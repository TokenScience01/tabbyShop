#!/usr/bin/env python3
"""Unified desktop host for the game console and the existing local shop."""
from __future__ import annotations

import json
import math
import os
import sys
import threading
import time
from pathlib import Path
from http.server import ThreadingHTTPServer
import tempfile

from github_updater import (APP_VERSION, RELEASES_PAGE, download_asset,
                            fetch_latest_release, is_frozen_windows,
                            launch_update_script, prepare_windows_update)

os.environ['TABBY_SAFE_START'] = '1'
BASE_DIR = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))
sys.path.insert(0, str(BASE_DIR / 'game_client'))

from PySide6.QtCore import QUrl, Qt, QObject, Signal, Slot, QFile, QTimer, QPointF, QRectF
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                              QHBoxLayout, QGridLayout, QLabel, QPushButton,
                              QStackedWidget, QButtonGroup, QDialog, QMessageBox,
                              QFrame, QPlainTextEdit, QInputDialog, QLineEdit,
                              QScrollArea, QCheckBox, QComboBox, QSpinBox, QSizePolicy)
from PySide6.QtGui import QDesktopServices, QIcon, QPixmap, QPainter, QColor, QPen, QPainterPath
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineScript
from PySide6.QtWebChannel import QWebChannel
from wss_tester import (MAP_NAMES, MAP_ROUTES, PORTAL_CENTERS,
                        localized_monster_name, MainWindow as GameWindow)
from game_client.minimap import peer_map_position
import server as shop
from ui_watchdog import UiWatchdog


class UpdateSignals(QObject):
    checked = Signal(object)
    downloaded = Signal(str)
    failed = Signal(str)


class WalletImportSignals(QObject):
    completed = Signal(object)


class DesktopClipboard(QObject):
    @Slot(str)
    def copyText(self, text):
        QApplication.clipboard().setText(text)


class BatchMapCanvas(QWidget):
    """Large shared map for dispatching connected game sessions."""

    def __init__(self, get_games, map_id=2, parent=None):
        super().__init__(parent)
        self.get_games = get_games
        self.map_id = map_id
        self.target = None
        self.terrain = {}
        self.zoom = 1.0
        self.view_center = None
        self._drag_pos = None
        self.animation_phase = 0.0
        self.monster_icon = QPixmap(str(BASE_DIR / 'game_client' / 'assets' / 'monster.webp'))
        self.setMinimumSize(560, 430)
        self.setMouseTracking(True)
        for key, filename in ((1, 'town_navigation.json'), (2, 'snowfield_navigation.json'),
                              (7, 'treasure_navigation.json'), (8, 'cave_navigation.json'),
                              (9, 'oasis_navigation.json'), (10, 'frozen_navigation.json')):
            try:
                payload = json.loads((BASE_DIR / 'game_client' / filename).read_text())
                cells = payload.get('cells', [])
                if cells:
                    self.terrain[key] = cells
            except (OSError, ValueError):
                pass

    def set_map(self, map_id):
        self.map_id = int(map_id)
        self.zoom = 1.0
        self.view_center = None
        self.update()

    def _bounds(self):
        cells = self.terrain.get(self.map_id, [])
        if cells:
            xs, ys = zip(*cells)
            return QRectF(min(xs) * 64, min(ys) * 64,
                          (max(xs) - min(xs) + 1) * 64, (max(ys) - min(ys) + 1) * 64)
        points = [coord for (source, _destination), coord in PORTAL_CENTERS.items()
                  if source == self.map_id]
        for game in self.get_games():
            if getattr(game, 'current_map', None) == self.map_id:
                if game.world_x is not None and game.world_y is not None:
                    points.append((float(game.world_x), float(game.world_y)))
                for monster in getattr(game, 'monsters', {}).values():
                    if monster.get('x') is not None and monster.get('y') is not None:
                        points.append((float(monster['x']), float(monster['y'])))
        # Maps without recovered navigation data still use the game's common
        # 0–7680 world coordinate space; include live markers if they fall
        # outside it, without collapsing the view around a single portal.
        bounds = QRectF(0, 0, 7680, 7680)
        for x, y in points:
            bounds = bounds.united(QRectF(x - 350, y - 300, 700, 600))
        return bounds

    def _transform(self):
        bounds = self._bounds()
        pad = 18
        scale = min((self.width() - 2 * pad) / max(1, bounds.width()),
                    (self.height() - 2 * pad) / max(1, bounds.height()))
        scale *= self.zoom
        center = self.view_center or bounds.center()
        dx = self.width() / 2 - (center.x() - bounds.left()) * scale
        dy = self.height() / 2 - (center.y() - bounds.top()) * scale
        def point(x, y):
            return QPointF(dx + (x - bounds.left()) * scale,
                           dy + (y - bounds.top()) * scale)
        def world(pos):
            return (bounds.left() + (pos.x() - dx) / scale,
                    bounds.top() + (pos.y() - dy) / scale)
        return bounds, scale, point, world

    def wheelEvent(self, event):
        factor = 1.2 if event.angleDelta().y() > 0 else 1 / 1.2
        _, _, _, world = self._transform()
        anchor_x, anchor_y = world(event.position())
        self.zoom = min(5.0, max(0.65, self.zoom * factor))
        _, scale, _, _ = self._transform()
        offset = event.position() - QPointF(self.width() / 2, self.height() / 2)
        self.view_center = QPointF(anchor_x - offset.x() / scale,
                                   anchor_y - offset.y() / scale)
        self.update()
        event.accept()

    @staticmethod
    def monster_map_label(monster):
        rank = str(monster.get('monsterRank', '')).upper()
        rank_label = {'ELITE': '精英', 'BOSS': '首领', 'NORMAL': '普通'}.get(rank, '怪物')
        level = next((monster.get(key) for key in ('level', 'monsterLevel', 'requiredLevel', 'lv')
                      if monster.get(key) is not None), None)
        level_text = f'{level}级 ' if level is not None else ''
        name = localized_monster_name(monster)
        rank_text = '' if rank_label in name else f' · {rank_label}'
        return f'{level_text}{name}{rank_text}'

    def draw_badge(self, painter, x, y, text, foreground, background, border,
                   occupied=None, placement='above'):
        metrics = painter.fontMetrics()
        width = metrics.horizontalAdvance(text) + 12
        height = max(18, metrics.height() + 6)
        candidates = {
            'above': [QRectF(x - width / 2, y - height - 11, width, height),
                      QRectF(x - width / 2, y - height * 2 - 15, width, height),
                      QRectF(x - width / 2, y + 11, width, height),
                      QRectF(x + 13, y - height / 2, width, height),
                      QRectF(x - width - 13, y - height / 2, width, height)],
            'right': [QRectF(x + 12, y - height / 2, width, height),
                      QRectF(x + 12, y - height - 5, width, height),
                      QRectF(x - width - 12, y - height / 2, width, height),
                      QRectF(x - width / 2, y + 12, width, height),
                      QRectF(x - width / 2, y - height - 12, width, height)],
        }[placement]
        occupied = occupied if occupied is not None else []
        rect = None
        for candidate in candidates:
            candidate.moveLeft(min(max(2, candidate.left()), self.width() - width - 2))
            candidate.moveTop(min(max(2, candidate.top()), self.height() - height - 22))
            if not any(candidate.adjusted(-2, -2, 2, 2).intersects(previous) for previous in occupied):
                rect = candidate
                break
        if rect is None:
            rect = candidates[0]
            rect.moveLeft(min(max(2, rect.left()), self.width() - width - 2))
            rect.moveTop(min(max(2, rect.top()), self.height() - height - 22))
        occupied.append(rect.adjusted(-2, -2, 2, 2))
        painter.setPen(QPen(QColor(border), 1))
        painter.setBrush(QColor(background))
        painter.drawRoundedRect(rect, 6, 6)
        painter.setPen(QColor(foreground))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, text)
        return rect

    def mouseMoveEvent(self, event):
        if self._drag_pos is not None:
            delta = event.position() - self._drag_pos
            _, scale, _, _ = self._transform()
            center = self.view_center or self._bounds().center()
            self.view_center = QPointF(center.x() - delta.x() / scale,
                                       center.y() - delta.y() / scale)
            self._drag_pos = event.position()
            self.update()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.MiddleButton:
            self._drag_pos = None
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.MiddleButton:
            self._drag_pos = event.position()
            event.accept()
            return
        if event.button() != Qt.MouseButton.LeftButton:
            return super().mousePressEvent(event)
        _, _, point, world = self._transform()
        games = self.get_games()
        best = None
        best_distance = 20.0
        for game in games:
            if getattr(game, 'current_map', None) != self.map_id:
                continue
            for encounter_id, monster in getattr(game, 'monsters', {}).items():
                if monster.get('x') is None or monster.get('y') is None or int(monster.get('health', 1) or 0) <= 0:
                    continue
                screen = point(float(monster['x']), float(monster['y']))
                distance = ((screen.x() - event.position().x()) ** 2 +
                            (screen.y() - event.position().y()) ** 2) ** 0.5
                if distance < best_distance:
                    best_distance = distance
                    best = {'x': float(monster['x']), 'y': float(monster['y']),
                            'encounterId': str(encounter_id),
                            'elite': str(monster.get('monsterRank', '')).upper() == 'ELITE',
                            'name': str(monster.get('name') or monster.get('monsterName') or '怪物')}
        if best is None:
            x, y = world(event.position())
            self.target = {'x': x, 'y': y, 'encounterId': None, 'elite': False, 'name': '坐标点'}
        else:
            self.target = best
        self.update()
        self.targetChanged.emit(self.target)

    targetChanged = Signal(object)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor('#F5F1E7'))
        bounds, scale, point, _ = self._transform()
        cells = self.terrain.get(self.map_id, [])
        # Snowfield's recovered navigation data is a complete 120×120 walkable
        # grid. Drawing every tile makes the map look like graph paper, so use
        # a calm field with a sparse tactical grid there. Town keeps its
        # irregular walkable-cell silhouette.
        if cells and self.map_id == 1:
            p.setPen(QPen(QColor('#E0D9C9'), 0.7))
            p.setBrush(QColor('#E9E5D8'))
            for x, y in cells:
                top = point(x * 64, y * 64)
                p.drawRect(QRectF(top.x(), top.y(), max(1, 64 * scale), max(1, 64 * scale)))
        elif cells:
            top_left = point(bounds.left(), bounds.top())
            bottom_right = point(bounds.right(), bounds.bottom())
            map_frame = QRectF(top_left, bottom_right)
            p.fillRect(map_frame, QColor('#EDF0E4'))
            p.save()
            p.setClipRect(map_frame)
            p.setPen(QPen(QColor('#D7DDCE'), 1))
            step = 512 * scale
            start_x = (self.width() / 2) % step
            while start_x < self.width():
                p.drawLine(round(start_x), 18, round(start_x), self.height() - 18)
                start_x += step
            start_y = (self.height() / 2) % step
            while start_y < self.height():
                p.drawLine(18, round(start_y), self.width() - 18, round(start_y))
                start_y += step
            p.restore()
            p.setPen(QPen(QColor('#C7CEBC'), 1.4))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawRoundedRect(QRectF(top_left, bottom_right), 12, 12)
        for (source, destination), coord in PORTAL_CENTERS.items():
            if source != self.map_id:
                continue
            pos = point(*coord)
            p.setPen(QPen(QColor('#A77933'), 2))
            p.setBrush(QColor('#FFF9EC'))
            p.drawRoundedRect(QRectF(pos.x() - 6, pos.y() - 6, 12, 12), 3, 3)
            p.setPen(QColor('#72552D'))
            p.drawText(pos + QPointF(8, -6), f'入口 {destination}')
        games = [game for game in self.get_games()
                 if getattr(game, 'current_map', None) == self.map_id]
        occupied_labels = [QRectF(8, 6, 280, 38)]
        seen_monsters = set()
        monster_count = 0
        for game in games:
            for encounter_id, monster in getattr(game, 'monsters', {}).items():
                if (int(monster.get('mapId', self.map_id) or self.map_id) != self.map_id
                        or encounter_id in seen_monsters or monster.get('x') is None or monster.get('y') is None
                        or int(monster.get('health', 1) or 0) <= 0):
                    continue
                seen_monsters.add(encounter_id)
                monster_count += 1
                pos = point(float(monster['x']), float(monster['y']))
                rank = str(monster.get('monsterRank', '')).upper()
                elite = rank == 'ELITE'
                boss = rank == 'BOSS'
                marker = '#9B4E56' if boss else '#B66A35' if elite else '#B66A70'
                fill = '#E9A2A1' if boss else '#E7A45A' if elite else '#D68A8D'
                radius = 8 if elite or boss else 4.5
                p.setPen(QPen(QColor(marker), 2.2 if elite or boss else 1.2))
                p.setBrush(QColor('#FFFDF7'))
                p.drawEllipse(pos, radius + 2, radius + 2)
                if not self.monster_icon.isNull():
                    p.drawPixmap(QRectF(pos.x() - radius, pos.y() - radius,
                                        radius * 2, radius * 2), self.monster_icon,
                                 QRectF(self.monster_icon.rect()))
                else:
                    p.setPen(QPen(QColor(marker), 1.4))
                    p.setBrush(QColor(fill))
                    p.drawEllipse(pos, radius, radius)
                label = self.monster_map_label(monster)
                colors = (('#6B3036', '#FCE6E1', '#B95E57') if boss else
                          ('#654817', '#FFF1CF', '#D4A339') if elite else
                          ('#613D42', '#FFF1F0', '#E1B7B4'))
                self.draw_badge(p, pos.x(), pos.y() - radius,
                                label, *colors, occupied=occupied_labels)

        local_player_ids = {str(getattr(game, 'player_id', '')) for game in games
                            if getattr(game, 'player_id', None) is not None}
        seen_peers = set()
        peer_count = 0
        for game in games:
            for peer in getattr(game, 'last_peers', []):
                location = peer_map_position(peer, self.map_id)
                if location is None or location[0] != self.map_id:
                    continue
                peer_id = peer.get('id', peer.get('playerId'))
                if peer_id is not None and str(peer_id) in local_player_ids:
                    continue
                identity = str(peer_id) if peer_id is not None else (
                    str(peer.get('playerName', peer.get('name', '玩家'))),
                    round(location[1]), round(location[2]))
                if identity in seen_peers:
                    continue
                seen_peers.add(identity)
                peer_count += 1
                pos = point(location[1], location[2])
                p.setPen(QPen(QColor('#FFFFFF'), 1.5))
                p.setBrush(QColor('#188A9D'))
                p.drawEllipse(pos, 6.5, 6.5)
                p.setPen(QPen(QColor('#116779'), 1.2))
                p.setBrush(QColor('#55C5D0'))
                p.drawEllipse(pos, 4.5, 4.5)
                name = str(peer.get('playerName', peer.get('name', '玩家'))).strip() or '玩家'
                if len(name) > 12:
                    name = name[:11] + '…'
                self.draw_badge(p, pos.x(), pos.y(), name,
                                '#145664', '#E3F6F5', '#91CFD0',
                                occupied=occupied_labels, placement='right')

        controller = self.parent()
        if not hasattr(controller, 'batch_map_account_checks') and controller is not None:
            controller = controller.parent()
        selected_addresses = {address.lower() for address, check in
                              getattr(controller, 'batch_map_account_checks', {}).items()
                              if check.isChecked()}
        character_count = 0
        character_positions = []
        for game in games:
            if game.world_x is None or game.world_y is None:
                continue
            character_count += 1
            pos = point(float(game.world_x), float(game.world_y))
            overlap_index = sum(math.hypot(pos.x() - previous.x(), pos.y() - previous.y()) < 18
                                for previous in character_positions)
            character_positions.append(pos)
            marker_pos = pos
            if overlap_index:
                angle = (overlap_index - 1) * (2 * math.pi / 3)
                marker_pos = pos + QPointF(math.cos(angle) * 15, math.sin(angle) * 15)
            address = getattr(game, '_desktop_wallet_address', '')
            selected = address.lower() in selected_addresses if address else False
            moving = any(getattr(game, timer_name, None) is not None and
                         getattr(game, timer_name).isActive()
                         for timer_name in ('move_timer', 'chase_timer', 'patrol_timer'))
            trace = list(getattr(game, 'movement_trace', ()))
            if moving and trace:
                now_since_welcome = None
                welcome_at = getattr(game, 'welcome_at', None)
                if welcome_at is not None:
                    now_since_welcome = time.monotonic() - welcome_at
                trace = [sample for sample in trace
                         if len(sample) >= 3 and sample[1] is not None and sample[2] is not None
                         and (now_since_welcome is None or sample[0] is None
                              or now_since_welcome - float(sample[0]) <= 8)]
                if len(trace) > 1:
                    trail = QPainterPath(point(float(trace[0][1]), float(trace[0][2])))
                    for sample in trace[1:]:
                        trail.lineTo(point(float(sample[1]), float(sample[2])))
                    trail.lineTo(pos)
                    p.setPen(QPen(QColor(79, 150, 94, 170), 2.2, Qt.PenStyle.DashLine))
                    p.setBrush(Qt.BrushStyle.NoBrush)
                    p.drawPath(trail)
            route = (getattr(game, 'chase_route', None) or
                     getattr(game, 'route_points', None) or [])
            if moving and route:
                next_point = point(float(route[0][0]), float(route[0][1]))
                vx, vy = next_point.x() - pos.x(), next_point.y() - pos.y()
                length = math.hypot(vx, vy)
                if length > 0.1:
                    ux, uy = vx / length, vy / length
                    tip = QPointF(pos.x() + ux * 19, pos.y() + uy * 19)
                    wing_a = QPointF(tip.x() - ux * 6 - uy * 4,
                                     tip.y() - uy * 6 + ux * 4)
                    wing_b = QPointF(tip.x() - ux * 6 + uy * 4,
                                     tip.y() - uy * 6 - ux * 4)
                    color = QColor('#398447' if selected else '#66766A')
                    p.setPen(QPen(color, 2.3, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
                    p.drawLine(pos, tip)
                    p.drawLine(tip, wing_a)
                    p.drawLine(tip, wing_b)
            p.setPen(QPen(QColor('#FFFFFF'), 2))
            p.setBrush(QColor('#398447' if selected else '#829183'))
            pulse = 2.5 * (0.5 + 0.5 * math.sin(self.animation_phase)) if moving else 0
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.setPen(QPen(QColor(57, 132, 71, 90 if selected else 45), 1.5))
            p.drawEllipse(marker_pos, 12 + pulse, 12 + pulse)
            p.setPen(QPen(QColor('#FFFFFF'), 2))
            p.setBrush(QColor('#398447' if selected else '#829183'))
            p.drawEllipse(marker_pos, 9, 9)
            p.setPen(QPen(QColor('#285D31' if selected else '#58645A'), 1.4))
            p.setBrush(QColor('#83D68D' if selected else '#C4CEC3'))
            p.drawEllipse(marker_pos, 5.5, 5.5)
            profile = getattr(game, 'api_profile', {})
            name = (profile.get('playerName') or profile.get('name')) if isinstance(profile, dict) else None
            name = str(name or (address[-3:] if address else getattr(game, 'player_id', '账号')))
            label = f'{"✓ " if selected else ""}{name} · {address[-3:]}' if address else name
            self.draw_badge(p, marker_pos.x(), marker_pos.y(), label,
                            '#24532C' if selected else '#4B574B',
                            '#E7F5E5' if selected else '#F1F2ED',
                            '#78B27D' if selected else '#C7CEC3',
                            occupied=occupied_labels, placement='right')
        if self.target:
            pos = point(self.target['x'], self.target['y'])
            p.setPen(QPen(QColor('#CF6B2C'), 2.2))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawEllipse(pos, 12, 12)
        p.setPen(QColor('#64695F'))
        p.drawText(12, self.height() - 10, f"{MAP_NAMES.get(self.map_id, f'地图 {self.map_id}')}  ·  缩放 {scale:.2f} px/单位")
        counts = f'角色 {character_count}　·　附近玩家 {peer_count}　·　怪物 {monster_count}'
        metrics = p.fontMetrics()
        badge = QRectF(12, 10, metrics.horizontalAdvance(counts) + 20, 28)
        p.setPen(QPen(QColor('#D8D2C4'), 1))
        p.setBrush(QColor(255, 253, 247, 230))
        p.drawRoundedRect(badge, 8, 8)
        p.setPen(QColor('#464A40'))
        p.drawText(badge, Qt.AlignmentFlag.AlignCenter, counts)


class DesktopWalletStore:
    """Read the active, passphrase-encrypted wallet for the shop signer."""

    class Errors:
        class PasswordDeleteError(Exception):
            pass

    errors = Errors()

    def __init__(self, window):
        self.window = window

    def get_password(self, service, username):
        if service != 'tabby-shop-bsc' or username != 'private-key':
            return None
        address = self.window.active_address
        phrase = self.window.game._vault_passphrase
        if not address or not phrase:
            return None
        if self.window._active_private_key:
            return self.window._active_private_key
        try:
            self.window._active_private_key = self.window.game.credential_vault.load_wallet(phrase, address)
            return self.window._active_private_key
        except (OSError, ValueError):
            return None

    def set_password(self, *_args):
        raise RuntimeError('请通过账号管理页导入并加密保存钱包')

    def delete_password(self, *_args):
        raise RuntimeError('请通过账号管理页管理保存的钱包')


class LocalShopPage(QWebEnginePage):
    def __init__(self, origin, parent):
        super().__init__(parent)
        self.origin = origin

    def acceptNavigationRequest(self, url, navigation_type, is_main_frame):
        # Keep the shop in its local application origin.
        return (url.scheme() == 'http' and url.host() == '127.0.0.1'
                and url.port() == self.origin.port()) or url.toString() == 'about:blank'


class DesktopWindow(QMainWindow):
    SESSION_BUSY_STATES = frozenset({
        '已连接', '连接中', '连接中…', '本机签名登录中…', '正在读取角色资料…',
    })

    def __init__(self):
        super().__init__()
        self.setWindowTitle('Tabby · 游戏与商城')
        app_icon = QIcon(str(BASE_DIR / 'assets' / 'tabby-logo.png'))
        self.setWindowIcon(app_icon)
        self.resize(1360, 920)
        self.setMinimumSize(980, 740)
        self._token = ''
        self.active_address = ''
        self._active_private_key = ''
        self._master_passphrase = None
        self._pending_address = ''
        self._shop_profiles = {}
        self._profile_path = None
        self._profile_lock = threading.RLock()
        self._game_sessions = {}
        self._account_last_maps = {}
        self._game_session_widgets = {}
        self._game_address_by_bridge = {}
        self._closing = False
        self._account_refresh_timer = QTimer(self)
        self._account_refresh_timer.setSingleShot(True)
        self._account_refresh_timer.setInterval(500)
        self._account_refresh_timer.timeout.connect(self.refresh_account_rows)
        self._session_tokens = {}
        self._batch_login_queue = []
        self._batch_login_inflight = set()
        self._batch_login_results = {}
        self._batch_login_needs_character = set()
        self._batch_login_timeouts = {}
        self._batch_login_active = False
        self._batch_login_launch_pending = False
        self._account_refresh_pending = False
        self._batch_login_max_concurrency = 3
        self._batch_login_attempted = 0
        self._batch_login_failed = 0
        self._batch_login_return_tab = 0
        self._loaded = False
        self._shop_started = False
        self.httpd = None
        self.web = None
        self.game = GameWindow()
        # Keep the game controller alive while hosting its existing widget.
        content = self.game.takeCentralWidget()
        self.setStyleSheet(self.game.styleSheet() + """
            QLabel#appBrand { color: #292C26; font-size: 15px; font-weight: 700; }
            QLabel#shellStatus { color: #6F7168; font-size: 12px; }
            QLabel#connectionDot { border-radius: 5px; }
            QPushButton#shellNav { min-height: 40px; padding: 4px 16px; border-radius: 0;
                                   color: #6F7168; background: transparent; border: 0;
                                   border-bottom: 2px solid transparent; }
            QPushButton#shellNav:hover { color: #292C26; background: #F3EFE6; border-bottom: 2px solid #D6C8AD; }
            QPushButton#shellNav:checked { color: #292C26; background: transparent; border: 0;
                                           border-bottom: 2px solid #63815E; }
            QLabel#accountManagerTitle { color: #292C26; font-size: 28px; font-weight: 700; }
            QLabel#accountManagerSubtitle { color: #6F7168; font-size: 13px; }
            QLabel#accountManagerCount { color: #8A642F; font-size: 12px; font-weight: 700; }
            QLabel#accountManagerNote, QLabel#accountEmpty { color: #77776E; font-size: 11px; }
            QFrame#walletAccountRow { background: #FBF9F4; border: 1px solid #DED7CA; border-radius: 12px; }
            QFrame#walletAccountRow:hover { border-color: #A7B49B; background: #FFFFFF; }
            QLabel#walletAddress { color: #292C26; font-family: Consolas; font-size: 12px; }
            QLabel#walletAccountState { color: #73766D; font-size: 10px; background:#F1EEE7;
                border:1px solid #E4DFD5; border-radius:9px; padding:2px 7px; }
            QPushButton#walletCopyAddress { min-height:40px; padding:0 12px; color:#4E654C;
                background:#F8F5EE; border:1px solid #CDD5C8; border-radius:8px; font-size:12px; font-weight:600; }
            QPushButton#walletCopyAddress:hover { color:#38553C; background:#EDF3E9; border-color:#89A184; }
            QPushButton#walletCopyAddress:pressed { background:#DFE9D9; }
            QPushButton#primaryButton { background:#5B7C55; color:#FFFFFF; border:1px solid #52734D; border-radius:8px; }
            QPushButton#primaryButton:hover { background:#496B47; border-color:#496B47; }
            QPushButton#secondaryButton { background:#F3EFE6; color:#514630; border:1px solid #CDBD9F; border-radius:8px; }
            QPushButton#secondaryButton:hover { background:#ECE4D4; border-color:#B99B67; }
            QLabel#walletAccountDetails { color: #555A51; font-size: 11px; }
            QLabel#walletStatusDot { border-radius: 5px; }
            QFrame#multiAccountPlanner { background:#FBF9F4; border:1px solid #DED7CA; border-radius:12px; }
            QLabel#plannerTitle { color:#292C26; font-size:14px; font-weight:700; }
            QLabel#plannerHint { color:#77776E; font-size:11px; }
            QWidget#plannerAccountsContent { background:transparent; }
            QScrollArea#plannerAccountsScroll, QScrollArea#plannerAccountsScroll > QWidget#qt_scrollarea_viewport {
                background:transparent; border:0;
            }
            QFrame#multiAccountPlanner QCheckBox { color:#454940; font-size:12px; spacing:8px; padding:2px 4px; }
            QFrame#multiAccountPlanner QCheckBox:hover { color:#292C26; }
            QFrame#multiAccountPlanner QCheckBox::indicator { width:15px; height:15px; border:1px solid #B8B5AA;
                                                                border-radius:4px; background:#FFFFFF; }
            QFrame#multiAccountPlanner QCheckBox::indicator:hover { border-color:#63815E; }
            QFrame#multiAccountPlanner QCheckBox::indicator:checked { background:#63815E; border-color:#63815E; }
            QCheckBox#plannerAccountCheck { color:#454940; font-size:12px; spacing:7px; padding:2px 7px;
                background:#FFFFFF; border:1px solid #DED7CA; border-radius:8px; }
            QCheckBox#plannerAccountCheck:hover { color:#292C26; border-color:#A7B49B; }
            QCheckBox#plannerAccountCheck::indicator { width:15px; height:15px; border:1px solid #B8B5AA;
                                                        border-radius:4px; background:#FFFFFF; }
            QCheckBox#plannerAccountCheck::indicator:hover { border-color:#63815E; }
            QCheckBox#plannerAccountCheck::indicator:checked { background:#63815E; border-color:#63815E; }
            QCheckBox#plannerAccountCheck::indicator:disabled { background:#EEEAE1; border-color:#D7D0C4; }
            QComboBox#plannerMode, QSpinBox#plannerLevelSpin {
                color:#373A33; background:#FFFFFF; border:1px solid #D5CEBF; border-radius:8px;
                min-height:40px; padding:0 10px;
            }
            QComboBox#plannerMode:hover, QSpinBox#plannerLevelSpin:hover { border-color:#8A9E80; }
            QComboBox#plannerMode::drop-down { width:28px; border:0; }
            QComboBox#plannerMode QAbstractItemView {
                color:#373A33; background:#FFFFFF; selection-background-color:#E4EBDC;
                border:1px solid #D5CEBF; outline:0;
            }
            QSpinBox#plannerLevelSpin:disabled { color:#92938B; background:#F0EDE6; border-color:#DED7CA; }
            QSpinBox#plannerLevelSpin::up-button, QSpinBox#plannerLevelSpin::down-button {
                width:18px; background:#F3EFE6; border:0;
            }
            QSpinBox#plannerLevelSpin::up-button:hover, QSpinBox#plannerLevelSpin::down-button:hover {
                background:#E8E3D8;
            }
        """)
        root = QWidget()
        root.setObjectName('root')
        layout = QVBoxLayout(root)
        layout.setContentsMargins(20, 8, 20, 12)
        layout.setSpacing(8)
        top = QGridLayout()
        top.setContentsMargins(2, 0, 2, 6)
        top.setHorizontalSpacing(12)
        brand = QWidget()
        brand_layout = QHBoxLayout(brand)
        brand_layout.setContentsMargins(0, 0, 0, 0)
        brand_layout.setSpacing(8)
        brand_icon = QLabel()
        brand_icon.setPixmap(QPixmap(str(BASE_DIR / 'assets' / 'tabby-logo.png')).scaled(
            30, 30, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        brand_layout.addWidget(brand_icon)
        brand_label = QLabel('TABBY  /  游戏与商城')
        brand_label.setObjectName('appBrand')
        brand_layout.addWidget(brand_label)
        top.addWidget(brand, 0, 0, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        top.setColumnStretch(0, 1)

        nav = QWidget()
        nav_layout = QHBoxLayout(nav)
        nav_layout.setContentsMargins(0, 0, 0, 0)
        nav_layout.setSpacing(6)
        self.tabs = QStackedWidget()
        self.tabs.setObjectName('appPages')
        self.account_nav = QPushButton('账号管理')
        self.game_nav = QPushButton('游戏控制台')
        self.batch_map_nav = QPushButton('批量地图')
        self.shop_nav = QPushButton('商城与监控')
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        for button in (self.account_nav, self.game_nav, self.shop_nav):
            button.setObjectName('shellNav')
            button.setCheckable(True)
            self.nav_group.addButton(button)
            nav_layout.addWidget(button)
        self.batch_map_nav.setObjectName('shellNav')
        self.batch_map_nav.setToolTip('打开独立大地图，统一调度多个在线账号')
        self.batch_map_nav.clicked.connect(self.open_batch_map)
        nav_layout.insertWidget(2, self.batch_map_nav)
        self.account_nav.setChecked(True)
        self.account_nav.clicked.connect(lambda: self.tabs.setCurrentIndex(0))
        self.game_nav.clicked.connect(lambda: self.tabs.setCurrentIndex(1))
        self.shop_nav.clicked.connect(lambda: self.tabs.setCurrentIndex(2))
        top.addWidget(nav, 0, 1, Qt.AlignmentFlag.AlignCenter)
        top.setColumnStretch(2, 1)

        actions = QWidget()
        actions_layout = QHBoxLayout(actions)
        actions_layout.setContentsMargins(0, 0, 0, 0)
        actions_layout.setSpacing(12)
        self.connection_dot = QLabel()
        self.connection_dot.setObjectName('connectionDot')
        self.connection_dot.setFixedSize(10, 10)
        actions_layout.addWidget(self.connection_dot)
        self.account_status = QLabel('未连接 · 未设置 Token')
        self.account_status.setObjectName('shellStatus')
        actions_layout.addWidget(self.account_status)
        self.update_button = QPushButton('检查更新')
        self.update_button.setObjectName('secondaryButton')
        self.update_button.clicked.connect(self.check_for_updates)
        actions_layout.addWidget(self.update_button)
        account = QPushButton('手动 Token 登录')
        account.setObjectName('secondaryButton')
        account.clicked.connect(self.show_account)
        actions_layout.addWidget(account)
        top.addWidget(actions, 0, 2, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        layout.addLayout(top)
        self.account_page = self.build_account_page()
        self.tabs.addWidget(self.account_page)
        self.game_stack = QStackedWidget()
        self.game_stack.setObjectName('accountGameSessions')
        self.game_stack.addWidget(content)
        self.tabs.addWidget(self.game_stack)
        self.shop_container = QWidget()
        self.shop_layout = QVBoxLayout(self.shop_container)
        self.shop_layout.setContentsMargins(0, 0, 0, 0)
        self.tabs.addWidget(self.shop_container)
        self.tabs.currentChanged.connect(self.activate_tab)
        self.tabs.currentChanged.connect(self.update_navigation)
        layout.addWidget(self.tabs, 1)
        self.setCentralWidget(root)
        self.game.account_toggle.hide()
        # The desktop shell owns the title and connection summary; don't stack
        # another dashboard title row inside the game page.
        self.game.dashboard_header.hide()
        self.game.on_state_change = lambda state, game=self.game: self.on_game_state(game, state)
        self.game.on_latency_change = lambda game=self.game: self.on_game_latency(game)
        self.game.on_account_metadata_change = lambda game=self.game: self.on_game_metadata(game)
        self.game.can_prompt_character_creation = lambda game=self.game: self.game is game
        self.game.on_vault_unlocked = self.cache_shared_passphrase
        self.game.token.textChanged.connect(self.set_token)
        # Private-key login obtains a short-lived game session without ever
        # populating the manual Token field. Share that in-memory session with
        # the embedded shop just like a pasted Token; never persist it.
        self.game.bridge.signed_login.connect(self.on_signed_login)
        self.account_dialog = QDialog(self)
        self.account_dialog.setWindowTitle('统一账号连接')
        self.account_dialog.setMinimumWidth(520)
        account_layout = QVBoxLayout(self.account_dialog)
        account_layout.setSpacing(10)
        account_layout.addWidget(QLabel('默认使用 BSC 私钥签名。Token 登录只接受游戏会话 Token，请勿粘贴钱包私钥。'))
        account_layout.addWidget(QLabel('登录方式'))
        account_layout.addWidget(self.game.auth_method)
        self.account_token_label = QLabel('游戏会话 Token')
        account_layout.addWidget(self.account_token_label)
        account_layout.addWidget(self.game.token)
        # Retain the familiar desktop account field reference for tests and
        # integrations while sharing the actual game login widget.
        self.account_token = self.game.token
        self.account_wallet_label = self.game.saved_wallet_label
        account_layout.addWidget(self.account_wallet_label)
        account_layout.addWidget(self.game.saved_wallet)
        self.account_private_key_label = self.game.private_key_label
        self.account_private_key_label.setText('BSC 钱包私钥（仅本机签名；记住时使用主密码加密分片）')
        account_layout.addWidget(self.account_private_key_label)
        account_layout.addWidget(self.game.private_key)
        self.account_sign_help = QLabel(
            '签名流程：POST /membership/challenge → /membership/verify → /membership/enter'
        )
        account_layout.addWidget(self.account_sign_help)
        account_layout.addWidget(self.game.remember_private_key)
        self.game.remember_private_key.hide()
        initial_vault_status = ('保存状态：检测到加密分片，使用时输入主密码'
                                if self.game.credential_vault.exists()
                                else '保存状态：尚未保存；勾选后首次成功登录时设置主密码')
        self.account_keyring_status = QLabel(initial_vault_status)
        self.account_keyring_status.setObjectName('accountHint')
        account_layout.addWidget(self.account_keyring_status)
        self.game.bridge.keyring_status.connect(self.account_keyring_status.setText)
        account_layout.addWidget(self.game.auto_reconnect)
        self.game.auth_method.currentIndexChanged.connect(self.update_account_auth_fields)
        self.update_account_auth_fields()
        row = QHBoxLayout()
        row.setSpacing(10)
        connect = QPushButton('连接游戏')
        connect.setObjectName('primaryButton')
        connect.clicked.connect(self.connect_active_game)
        disconnect = QPushButton('断开游戏')
        disconnect.setObjectName('secondaryButton')
        disconnect.clicked.connect(self.disconnect_active_game)
        done = QPushButton('完成')
        done.setObjectName('primaryButton')
        done.clicked.connect(self.account_dialog.accept)
        for button in (connect, disconnect, done):
            button.setMinimumHeight(38)
            row.addWidget(button, 1)
        account_layout.addLayout(row)
        self.game.connect_button.hide()
        self.game.disconnect_button.hide()
        self.game.set_state('未连接')
        self._last_game_state = '未连接'
        self.update_signals = UpdateSignals(self)
        self.update_signals.checked.connect(self.on_update_checked)
        self.update_signals.downloaded.connect(self.on_update_downloaded)
        self.update_signals.failed.connect(self.on_update_failed)
        self.wallet_import_signals = WalletImportSignals(self)
        self.wallet_import_signals.completed.connect(self.on_wallet_import_completed)
        self._wallet_import_thread = None
        self._update_release = None
        self._update_archive = None
        self._update_thread = None
        # The desktop monitor reads the same in-memory token used by the game.
        shop.read_token = lambda: ('Bearer ' + self._token) if self._token else ''
        shop.save_token = lambda value: None
        # Monitor work runs in a background thread; use a Qt signal to deliver
        # shop events onto the GUI thread before reading the saved webhook.
        shop.MONITOR.event_callback = self.game.bridge.shop_notification.emit
        self._profile_path = self.game.credential_vault.directory.parent / 'shop-profiles.json'
        self._shop_profiles = self.load_shop_profiles()
        # The embedded dashboard uses the selected account's encrypted vault
        # for signing; it never imports a second plaintext/keyring copy.
        shop.secure_keyring = lambda: DesktopWalletStore(self)
        shop.wallet_address = self.active_shop_wallet_address
        self.refresh_account_rows()
        self._ui_watchdog = UiWatchdog(self)

    def build_account_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 22, 28, 22)
        layout.setSpacing(12)
        heading = QLabel('账号中心')
        heading.setObjectName('accountManagerTitle')
        layout.addWidget(heading)
        subtitle = QLabel('导入多个 BSC 钱包并加密保存。切换控制台只改变当前显示账号，不会断开其他账号；每个账号的在线状态会单独显示。')
        subtitle.setObjectName('accountManagerSubtitle')
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)
        self.account_count = QLabel('0 个账号')
        self.account_count.setObjectName('accountManagerCount')
        layout.addWidget(self.account_count)
        self.build_multi_account_planner(layout)
        self.account_rows = QVBoxLayout()
        self.account_rows.setContentsMargins(0, 0, 0, 0)
        self.account_rows.setSpacing(9)
        self.account_list = QWidget()
        self.account_list.setStyleSheet('background: transparent;')
        self.account_list.setLayout(self.account_rows)
        account_scroll = QScrollArea()
        account_scroll.setWidgetResizable(True)
        account_scroll.setFrameShape(QFrame.Shape.NoFrame)
        account_scroll.setStyleSheet('QScrollArea { background: transparent; border: 0; } QWidget { background: transparent; }')
        account_scroll.setViewportMargins(8, 4, 8, 4)
        account_scroll.setWidget(self.account_list)
        layout.addWidget(account_scroll, 1)
        self.account_empty = QLabel('还没有保存的钱包。点击“导入钱包”，可以一次添加多个私钥。')
        self.account_empty.setObjectName('accountEmpty')
        self.account_empty.setWordWrap(True)
        layout.addWidget(self.account_empty)
        actions = QHBoxLayout()
        actions.addStretch(1)
        refresh = QPushButton('刷新列表')
        refresh.setObjectName('secondaryButton')
        refresh.clicked.connect(self.refresh_account_rows)
        add = QPushButton('导入钱包')
        add.setObjectName('primaryButton')
        add.clicked.connect(self.import_wallets)
        self.import_wallet_button = add
        actions.addWidget(refresh)
        actions.addWidget(add)
        layout.addLayout(actions)
        note = QLabel('私钥保存在本机加密保险库；主密码只在本次运行期间留在内存。切换控制台不会断开其他账号的游戏连接；商城扫描仅绑定当前选择的账号。')
        note.setObjectName('accountManagerNote')
        note.setWordWrap(True)
        layout.addWidget(note)
        return page

    def build_multi_account_planner(self, parent_layout):
        """Add a small coordinator for applying one play mode to many accounts."""
        card = QFrame()
        card.setObjectName('multiAccountPlanner')
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 11, 14, 11)
        layout.setSpacing(8)
        heading = QHBoxLayout()
        title = QLabel('多账号任务编排')
        title.setObjectName('plannerTitle')
        heading.addWidget(title)
        self.planner_select_all = QCheckBox('全选账号')
        self.planner_select_all.setObjectName('plannerSelectAll')
        self.planner_select_all.toggled.connect(self.set_all_planner_accounts)
        heading.addWidget(self.planner_select_all)
        heading.addStretch(1)
        layout.addLayout(heading)

        self.planner_account_checks = {}
        self.planner_accounts_content = QWidget()
        self.planner_accounts_content.setObjectName('plannerAccountsContent')
        self.planner_accounts_content.setStyleSheet('background:transparent;')
        self.planner_accounts_layout = QGridLayout(self.planner_accounts_content)
        self.planner_accounts_layout.setContentsMargins(2, 0, 2, 0)
        self.planner_accounts_layout.setHorizontalSpacing(9)
        self.planner_accounts_layout.setVerticalSpacing(2)
        account_scroll = QScrollArea()
        account_scroll.setObjectName('plannerAccountsScroll')
        account_scroll.setWidgetResizable(True)
        account_scroll.setFrameShape(QFrame.Shape.NoFrame)
        account_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        account_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        account_scroll.setMinimumHeight(32)
        self.planner_accounts_scroll = account_scroll
        account_scroll.setWidget(self.planner_accounts_content)
        account_scroll.viewport().setAutoFillBackground(False)
        account_scroll.viewport().setStyleSheet('background:transparent; border:0;')
        account_scroll.setStyleSheet('QScrollArea { background:transparent; border:0; }')
        self.planner_accounts_content.setAutoFillBackground(False)
        layout.addWidget(account_scroll)

        controls = QHBoxLayout()
        self.planner_mode = QComboBox()
        self.planner_mode.setObjectName('plannerMode')
        self.planner_mode.addItem('自动任务：接任务并按任务地图战斗', 'quests')
        self.planner_mode.addItem('自由刷怪：留在各账号当前地图', 'farm')
        self.planner_mode.addItem('精英狩猎：只攻击精英怪', 'elite')
        self.planner_mode.setMinimumWidth(260)
        controls.addWidget(self.planner_mode)
        self.planner_use_potion = QCheckBox('允许自动用药')
        self.planner_use_potion.setChecked(False)
        controls.addWidget(self.planner_use_potion)
        self.planner_limit_level = QCheckBox('等级范围')
        controls.addWidget(self.planner_limit_level)
        self.planner_level_min = QSpinBox()
        self.planner_level_min.setObjectName('plannerLevelSpin')
        self.planner_level_min.setFixedWidth(142)
        self.planner_level_min.setRange(1, 9999)
        self.planner_level_min.setPrefix('最低 ')
        self.planner_level_min.setValue(1)
        controls.addWidget(self.planner_level_min)
        self.planner_level_max = QSpinBox()
        self.planner_level_max.setObjectName('plannerLevelSpin')
        self.planner_level_max.setFixedWidth(142)
        self.planner_level_max.setRange(1, 9999)
        self.planner_level_max.setPrefix('最高 ')
        self.planner_level_max.setValue(9999)
        controls.addWidget(self.planner_level_max)
        self.planner_limit_level.toggled.connect(self.planner_level_min.setEnabled)
        self.planner_limit_level.toggled.connect(self.planner_level_max.setEnabled)
        self.planner_level_min.setEnabled(False)
        self.planner_level_max.setEnabled(False)
        layout.addLayout(controls)

        post_quest_controls = QHBoxLayout()
        self.planner_farm_after_quests = QCheckBox('任务做完后继续刷图')
        self.planner_farm_after_quests.setToolTip('自动任务没有下一项可接时，前往指定地图继续刷怪；复活后也会返回。')
        post_quest_controls.addWidget(self.planner_farm_after_quests)
        self.planner_farm_map = QComboBox()
        self.planner_farm_map.setObjectName('plannerFarmMap')
        for map_id, name in MAP_NAMES.items():
            if map_id not in (1, 7):
                self.planner_farm_map.addItem(name, map_id)
        saved_map_index = self.planner_farm_map.findData(2)
        if saved_map_index >= 0:
            self.planner_farm_map.setCurrentIndex(saved_map_index)
        self.planner_farm_map.setMinimumWidth(185)
        post_quest_controls.addWidget(self.planner_farm_map)
        self.planner_avoid_contested = QCheckBox('避开附近有玩家的怪')
        self.planner_avoid_contested.setToolTip('跳过服务端最近上报的位置中，180 游戏单位范围内有其他玩家的怪物。')
        post_quest_controls.addWidget(self.planner_avoid_contested)
        post_quest_controls.addStretch(1)
        layout.addLayout(post_quest_controls)

        actions = QHBoxLayout()
        self.planner_start = QPushButton('启动所选账号')
        self.planner_start.setObjectName('primaryButton')
        self.planner_start.clicked.connect(self.start_multi_account_plan)
        self.planner_batch_connect = QPushButton('批量上线所选')
        self.planner_batch_connect.setObjectName('secondaryButton')
        self.planner_batch_connect.clicked.connect(self.batch_connect_accounts)
        self.planner_pause = QPushButton('暂停方案')
        self.planner_pause.setObjectName('secondaryButton')
        self.planner_pause.clicked.connect(self.pause_multi_account_plan)
        self.planner_stop = QPushButton('停止方案')
        self.planner_stop.setObjectName('secondaryButton')
        self.planner_stop.clicked.connect(self.stop_multi_account_plan)
        self.planner_open_map = QPushButton('大地图批量管理')
        self.planner_open_map.setObjectName('secondaryButton')
        self.planner_open_map.setToolTip('打开独立大地图，统一派遣在线账号进图、移动或追击精英怪。')
        self.planner_open_map.clicked.connect(self.open_batch_map)
        self.planner_batch_disconnect = QPushButton('批量下线所选')
        self.planner_batch_disconnect.setObjectName('secondaryButton')
        self.planner_batch_disconnect.clicked.connect(self.batch_disconnect_accounts)
        actions.addWidget(self.planner_start)
        actions.addWidget(self.planner_batch_connect)
        actions.addWidget(self.planner_batch_disconnect)
        actions.addWidget(self.planner_pause)
        actions.addWidget(self.planner_stop)
        actions.addWidget(self.planner_open_map)
        actions.addStretch(1)
        self.planner_status = QLabel('选择已连接账号后，可将同一玩法配置应用到多个角色。')
        self.planner_status.setObjectName('plannerHint')
        actions.addWidget(self.planner_status, 2)
        layout.addLayout(actions)
        parent_layout.addWidget(card)

    def open_batch_map(self):
        if not hasattr(self, 'batch_map_dialog'):
            dialog = QDialog(self)
            dialog.setWindowTitle('批量管理 · 大地图')
            dialog.resize(1180, 780)
            dialog.setMinimumSize(920, 620)
            dialog.setStyleSheet(self.game.styleSheet())
            outer = QVBoxLayout(dialog)
            outer.setContentsMargins(18, 16, 18, 16)
            heading = QHBoxLayout()
            title = QLabel('批量地图调度')
            title.setObjectName('title')
            heading.addWidget(title)
            heading.addStretch(1)
            heading.addWidget(QLabel('地图'))
            self.batch_map_selector = QComboBox()
            self.batch_map_selector.setObjectName('plannerMode')
            for map_id, name in MAP_NAMES.items():
                self.batch_map_selector.addItem(name, map_id)
            active_map = getattr(self.game, 'current_map', None) or 2
            index = self.batch_map_selector.findData(active_map)
            self.batch_map_selector.setCurrentIndex(index if index >= 0 else 0)
            heading.addWidget(self.batch_map_selector)
            outer.addLayout(heading)

            body = QHBoxLayout()
            side = QVBoxLayout()
            side.setSpacing(9)
            side_title = QLabel('在线账号')
            side_title.setObjectName('sectionTitle')
            side.addWidget(side_title)
            self.batch_map_select_all = QCheckBox('全选在线账号')
            self.batch_map_select_all.toggled.connect(self.set_all_batch_map_accounts)
            side.addWidget(self.batch_map_select_all)
            self.batch_map_account_checks = {}
            self.batch_map_accounts_content = QWidget()
            self.batch_map_accounts_layout = QVBoxLayout(self.batch_map_accounts_content)
            self.batch_map_accounts_layout.setContentsMargins(0, 0, 0, 0)
            self.batch_map_accounts_layout.setSpacing(5)
            account_scroll = QScrollArea()
            account_scroll.setWidgetResizable(True)
            account_scroll.setFrameShape(QFrame.Shape.NoFrame)
            account_scroll.setWidget(self.batch_map_accounts_content)
            side.addWidget(account_scroll, 1)
            self.batch_map_status = QLabel('点击地图标记或空白处选择目标；再让在线账号移动或追击精英。')
            self.batch_map_status.setObjectName('subtitle')
            self.batch_map_status.setWordWrap(True)
            side.addWidget(self.batch_map_status)
            body.addLayout(side, 0)

            self.batch_map_canvas = BatchMapCanvas(self.batch_map_games,
                                                   self.batch_map_selector.currentData(), dialog)
            self.batch_map_canvas.targetChanged.connect(self.on_batch_map_target_changed)
            self.batch_map_selector.currentIndexChanged.connect(
                lambda *_: self.batch_map_canvas.set_map(self.batch_map_selector.currentData()))
            body.addWidget(self.batch_map_canvas, 1)
            outer.addLayout(body, 1)

            legend = QLabel('绿点：账号　·　粉点：怪物　·　金点：精英　·　棕框：地图入口　·　点击选择目标　·　滚轮缩放 / 中键拖动')
            legend.setObjectName('subtitle')
            outer.addWidget(legend)

            actions = QHBoxLayout()
            self.batch_map_enter = QPushButton('让所选账号进图')
            self.batch_map_enter.setObjectName('primaryButton')
            self.batch_map_enter.clicked.connect(self.batch_map_enter_selected)
            self.batch_map_move = QPushButton('移动到所选坐标')
            self.batch_map_move.setObjectName('secondaryButton')
            self.batch_map_move.clicked.connect(self.batch_map_move_selected)
            self.batch_map_attack = QPushButton('追击所选位置附近精英')
            self.batch_map_attack.setObjectName('secondaryButton')
            self.batch_map_attack.clicked.connect(self.batch_map_attack_selected)
            refresh = QPushButton('刷新地图')
            refresh.setObjectName('secondaryButton')
            refresh.clicked.connect(self.refresh_batch_map_accounts)
            for button in (self.batch_map_enter, self.batch_map_move,
                           self.batch_map_attack, refresh):
                actions.addWidget(button)
            actions.addStretch(1)
            outer.addLayout(actions)
            self.batch_map_dialog = dialog
            self.batch_map_timer = QTimer(dialog)
            self.batch_map_timer.setInterval(1200)
            self.batch_map_timer.timeout.connect(self.refresh_batch_map_animation)
            dialog.finished.connect(lambda *_: self.batch_map_timer.stop())
        self.refresh_batch_map_accounts()
        self.batch_map_timer.start()
        self.batch_map_dialog.show()
        self.batch_map_dialog.raise_()
        self.batch_map_dialog.activateWindow()

    def batch_map_games(self):
        # A wallet must own its own GameWindow/WebSocket. Keep the canvas
        # resilient to legacy aliases in the registry so one socket is never
        # drawn twice as two different characters.
        games = []
        seen = set()
        for game in self._game_sessions.values():
            if id(game) not in seen:
                seen.add(id(game))
                games.append(game)
        return games

    def refresh_batch_map_animation(self):
        games = self.batch_map_games()
        moving = any(getattr(game, timer_name, None) is not None and
                     getattr(game, timer_name).isActive()
                     for game in games
                     for timer_name in ('move_timer', 'chase_timer', 'patrol_timer'))
        interval = 100 if moving else 1200
        if self.batch_map_timer.interval() != interval:
            self.batch_map_timer.setInterval(interval)
        if moving:
            self.batch_map_canvas.animation_phase = (self.batch_map_canvas.animation_phase + 0.55) % (2 * math.pi)
        self.batch_map_canvas.update()

    def refresh_batch_map_accounts(self):
        if not hasattr(self, 'batch_map_accounts_layout'):
            return
        selected = {address: box.isChecked() for address, box in self.batch_map_account_checks.items()}
        while self.batch_map_accounts_layout.count():
            entry = self.batch_map_accounts_layout.takeAt(0)
            if entry.widget():
                entry.widget().deleteLater()
        self.batch_map_account_checks = {}
        seen_sessions = set()
        for address in self.sorted_wallet_addresses(self.game.credential_vault.list_wallets()):
            normalized = address.lower()
            game = self._game_sessions.get(normalized)
            duplicate_session = bool(game and id(game) in seen_sessions)
            if game and not duplicate_session:
                seen_sessions.add(id(game))
            online = bool(game and not duplicate_session
                          and game.status.text() == '已连接' and game.world_ready)
            if duplicate_session:
                location = '会话重复绑定，请重新登录'
            else:
                location = MAP_NAMES.get(game.current_map, '在线待定位') if online else '离线'
            label = f"尾号 {address[-3:]}  ·  {location}"
            check = QCheckBox(label)
            check.setToolTip(address)
            check.setEnabled(online)
            check.setChecked(online and selected.get(address, selected.get(normalized, False)))
            check.toggled.connect(self.update_batch_map_select_all)
            check.toggled.connect(lambda *_: self.batch_map_canvas.update())
            self.batch_map_account_checks[address] = check
            self.batch_map_accounts_layout.addWidget(check)
            if game and not duplicate_session:
                game._desktop_wallet_address = address
        self.batch_map_accounts_layout.addStretch(1)
        self.update_batch_map_select_all()
        self.batch_map_canvas.update()

    def set_all_batch_map_accounts(self, checked):
        for check in self.batch_map_account_checks.values():
            if check.isEnabled():
                check.setChecked(checked)

    def update_batch_map_select_all(self, *_args):
        boxes = [box for box in self.batch_map_account_checks.values() if box.isEnabled()]
        self.batch_map_select_all.blockSignals(True)
        self.batch_map_select_all.setChecked(bool(boxes) and all(box.isChecked() for box in boxes))
        self.batch_map_select_all.blockSignals(False)

    def selected_batch_map_games(self):
        selected = {address.lower() for address, box in self.batch_map_account_checks.items()
                    if box.isChecked() and box.isEnabled()}
        games = []
        seen = set()
        for address, game in self._game_sessions.items():
            if address in selected and id(game) not in seen:
                seen.add(id(game))
                games.append(game)
        return games

    def on_batch_map_target_changed(self, target):
        name = target.get('name', '目标')
        if target.get('encounterId'):
            name += ' · 精英' if target.get('elite') else ' · 怪物'
        self.batch_map_status.setText(
            f"已选 {name}：({target['x']:.0f}, {target['y']:.0f})。"
            "坐标移动仅对当前已在此地图的账号执行。")

    def batch_map_enter_selected(self):
        games = self.selected_batch_map_games()
        if not games:
            self.batch_map_status.setText('请先选择已在线的账号。')
            return
        destination = int(self.batch_map_selector.currentData())
        routed = 0
        for game in games:
            if game.current_map == destination:
                routed += 1
                continue
            game.start_manual_map_travel(destination)
            if game.manual_map_target is not None or game.current_map == destination:
                routed += 1
        self.batch_map_status.setText(
            f"已向 {routed}/{len(games)} 个账号发出前往 {MAP_NAMES.get(destination, destination)} 的路线指令。")
        self.batch_map_canvas.update()

    def batch_map_move_selected(self):
        target = self.batch_map_canvas.target
        if not target:
            self.batch_map_status.setText('先在地图上点选一个坐标或怪物。')
            return
        map_id = int(self.batch_map_selector.currentData())
        games = self.selected_batch_map_games()
        if not games:
            self.batch_map_status.setText('请先选择已在线的账号。')
            return
        accepted = []
        skipped = []
        coordinate = (target['x'], target['y'])
        for game in games:
            address = getattr(game, '_desktop_wallet_address', '')
            label = f"尾号 {address[-3:]}" if address else '账号'
            if game.current_map == map_id:
                ok = game.move_to_coordinate(*coordinate)
            else:
                # Keep the clicked destination with this session while it travels
                # through portals; otherwise only accounts already on this map move.
                game.start_manual_map_travel(map_id, coordinate_target=coordinate)
                ok = game.manual_map_target is not None or game.current_map == map_id
            if ok:
                accepted.append(label)
            else:
                reason = getattr(getattr(game, 'travel_status', None), 'text', lambda: '')()
                skipped.append(f"{label}（{reason or '角色未就绪'}）")
        summary = f"已向 {len(accepted)}/{len(games)} 个所选账号派发移动。"
        if accepted:
            summary += ' 正在移动：' + '、'.join(accepted[:4])
            if len(accepted) > 4:
                summary += f" 等 {len(accepted)} 个"
        if skipped:
            summary += '；未派发：' + '、'.join(skipped[:2])
            if len(skipped) > 3:
                summary += f" 等 {len(skipped)} 个"
            summary += '（请检查角色是否已进图、是否正在复活或服务端路线是否可达）'
        self.batch_map_status.setText(summary)
        self.batch_map_canvas.update()

    def batch_map_attack_selected(self):
        target = self.batch_map_canvas.target
        if not target:
            self.batch_map_status.setText('先在地图上点选一个精英怪标记。')
            return
        if not target.get('encounterId') or not target.get('elite'):
            self.batch_map_status.setText('所选位置不是精英怪标记；请点击地图上的金色精英标记。')
            return
        map_id = int(self.batch_map_selector.currentData())
        games = [game for game in self.selected_batch_map_games() if game.current_map == map_id]
        started = 0
        for game in games:
            candidates = [(encounter_id, monster) for encounter_id, monster in game.monsters.items()
                          if str(monster.get('monsterRank', '')).upper() == 'ELITE'
                          and monster.get('x') is not None and monster.get('y') is not None
                          and int(monster.get('health', 1) or 0) > 0]
            nearest = min(candidates,
                          key=lambda row: ((float(row[1]['x']) - target['x']) ** 2 +
                                           (float(row[1]['y']) - target['y']) ** 2), default=None)
            if nearest and ((float(nearest[1]['x']) - target['x']) ** 2 +
                            (float(nearest[1]['y']) - target['y']) ** 2) ** 0.5 <= 180:
                game.auto_attack.setChecked(True)
                game.start_chase(nearest[0])
                if game.chase_target == nearest[0]:
                    started += 1
        self.batch_map_status.setText(
            f"已对 {started}/{len(games)} 个同地图账号发出精英追击指令；等级范围、附近玩家保护和服务端目标校验仍会生效。")
        self.batch_map_canvas.update()

    def refresh_planner_accounts(self):
        selected = {address: box.isChecked()
                    for address, box in self.planner_account_checks.items()}
        while self.planner_accounts_layout.count():
            item = self.planner_accounts_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        self.planner_account_checks = {}
        addresses = self.sorted_wallet_addresses(self.game.credential_vault.list_wallets())
        # Balanced rows avoid a single stretched gray band on Windows and
        # keep a small account set from looking like an empty spreadsheet.
        columns = min(6, max(1, len(addresses)))
        for index, address in enumerate(addresses):
            suffix = address[-3:]
            box = QCheckBox(f'尾号 {suffix}')
            box.setObjectName('plannerAccountCheck')
            box.setMinimumHeight(26)
            box.setFixedWidth(136)
            box.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            box.setToolTip(address)
            box.setChecked(selected.get(address, selected.get(address.lower(), False)))
            box.toggled.connect(self.update_planner_select_all)
            self.planner_account_checks[address] = box
            self.planner_accounts_layout.addWidget(box, index // columns, index % columns)
        if not addresses:
            empty = QLabel('请先导入钱包')
            empty.setObjectName('plannerHint')
            self.planner_accounts_layout.addWidget(empty, 0, 0)
        rows = max(1, (len(addresses) + columns - 1) // columns)
        row_height = 28
        scroll_height = rows * row_height + 8
        self.planner_accounts_scroll.setFixedHeight(scroll_height)
        self.planner_select_all.blockSignals(True)
        self.planner_select_all.setChecked(bool(addresses) and all(
            box.isChecked() for box in self.planner_account_checks.values()))
        self.planner_select_all.blockSignals(False)

    @staticmethod
    def sorted_wallet_addresses(addresses):
        """Sort account listings by the wallet address's final three characters."""
        return sorted(addresses, key=lambda address: (str(address)[-3:].casefold(),
                                                       str(address).casefold()))

    def set_all_planner_accounts(self, checked):
        for box in self.planner_account_checks.values():
            box.blockSignals(True)
            box.setChecked(checked)
            box.blockSignals(False)

    def batch_connect_accounts(self):
        """Start up to three selected wallet logins concurrently in background workers."""
        if self._batch_login_active:
            self.planner_status.setText('批量上线正在进行中，请等待当前账号完成签名登录。')
            return
        if shop.MONITOR.buy_lock.locked():
            self.planner_status.setText('商城购买正在提交，完成后再批量上线。')
            return
        selected = [address for address, box in self.planner_account_checks.items()
                    if box.isChecked()]
        if not selected:
            self.planner_status.setText('请先选择要批量上线的账号。')
            return
        queue = []
        for address in selected:
            session = self._game_sessions.get(address.lower())
            state = session.status.text() if session else ''
            if state not in self.SESSION_BUSY_STATES:
                queue.append(address)
        if not queue:
            self.planner_status.setText('所选账号都已在线或正在连接。')
            return

        phrase = self._master_passphrase or self.game._vault_passphrase
        if not phrase:
            phrase = self.ask_shared_passphrase(confirm=False)
        if phrase is None:
            self.planner_status.setText('已取消批量上线；需要先解锁钱包保险库。')
            return
        self.cache_shared_passphrase(phrase)
        self._batch_login_queue = queue
        self._batch_login_inflight.clear()
        self._batch_login_results.clear()
        self._batch_login_needs_character.clear()
        self._batch_login_timeouts.clear()
        self._batch_login_active = True
        self._batch_login_attempted = 0
        self._batch_login_failed = 0
        self._batch_login_return_tab = self.tabs.currentIndex()
        self.planner_batch_connect.setEnabled(False)
        self.planner_status.setText(
            f'正在后台并发上线 {len(queue)} 个账号（最多同时 {self._batch_login_max_concurrency} 个）；'
            '界面仍可继续操作。')
        self._continue_batch_login()

    def _continue_batch_login(self):
        if not self._batch_login_active:
            return
        if self._batch_login_launch_pending:
            return
        if self._batch_login_queue and len(self._batch_login_inflight) < self._batch_login_max_concurrency:
            address = self._batch_login_queue.pop(0)
            session = self._game_sessions.get(address.lower())
            state = session.status.text() if session else ''
            if state in self.SESSION_BUSY_STATES:
                self._batch_login_attempted += 1
                QTimer.singleShot(0, self._continue_batch_login)
                return
            self._batch_login_inflight.add(address.lower())
            timeout_id = object()
            self._batch_login_timeouts[address.lower()] = timeout_id
            self.planner_status.setText(
                f'后台批量上线：已启动 {self._batch_login_attempted + len(self._batch_login_inflight)} / '
                f'{self._batch_login_attempted + len(self._batch_login_inflight) + len(self._batch_login_queue)} '
                f'个账号（尾号 {address[-3:]}）')
            self._batch_login_launch_pending = True
            try:
                self.connect_account(address, background=True)
            except Exception as exc:
                self._batch_login_inflight.discard(address.lower())
                self._batch_login_timeouts.pop(address.lower(), None)
                self._batch_login_attempted += 1
                self._batch_login_failed += 1
                self.planner_status.setText(f'账号尾号 {address[-3:]} 启动失败：{type(exc).__name__}')
            else:
                QTimer.singleShot(240000, lambda expected=address.lower(), run=timeout_id:
                                  self._batch_login_timeout(expected, run))
            finally:
                self._batch_login_launch_pending = False
            if self._batch_login_queue and len(self._batch_login_inflight) < self._batch_login_max_concurrency:
                self._batch_login_launch_pending = True

                def launch_next():
                    self._batch_login_launch_pending = False
                    self._continue_batch_login()

                QTimer.singleShot(0, launch_next)
            if self._batch_login_queue:
                return
        if self._batch_login_inflight:
            return
        if not self._batch_login_attempted:
            self._batch_login_active = False
            self.planner_batch_connect.setEnabled(True)
            self.planner_status.setText('所选账号都已上线或正在连接。')
            return
        message = (f'批量上线已完成 {self._batch_login_attempted} 个账号；'
                   f'登录失败 {self._batch_login_failed} 个。')
        if self._batch_login_needs_character:
            message += f' {len(self._batch_login_needs_character)} 个待创建角色，请点击对应账号的“创建角色”。'
        self.planner_status.setText(message)
        self._batch_login_active = False
        self.request_account_refresh()
        self.planner_batch_connect.setEnabled(True)
        self.tabs.setCurrentIndex(self._batch_login_return_tab)

    def _batch_login_timeout(self, expected_address, run=None):
        if expected_address not in self._batch_login_inflight:
            return
        if run is not None and self._batch_login_timeouts.get(expected_address) is not run:
            return
        self._batch_login_timeouts.pop(expected_address, None)
        self._batch_login_results.pop(expected_address, None)
        self._batch_login_inflight.discard(expected_address)
        self._batch_login_attempted += 1
        self._batch_login_failed += 1
        game = self._game_sessions.get(expected_address)
        if game is not None:
            game.disconnect_ws()
            game._batch_login_silent = False
        self.planner_status.setText(f'账号尾号 {expected_address[-3:]} 登录等待超时；其他账号继续登录。')
        self._continue_batch_login()

    def _finish_batch_login_result(self, address, result):
        normalized = str(address).lower()
        if normalized not in self._batch_login_inflight:
            return
        self._batch_login_results.pop(normalized, None)
        self._batch_login_timeouts.pop(normalized, None)
        self._batch_login_attempted += 1
        if isinstance(result, dict) and result.get('needs_character'):
            self._batch_login_needs_character.add(normalized)
        elif not (isinstance(result, dict) and result.get('ok') and result.get('token')):
            self._batch_login_failed += 1
        self._batch_login_inflight.discard(normalized)
        self._continue_batch_login()

    def update_planner_select_all(self, *_args):
        boxes = list(self.planner_account_checks.values())
        self.planner_select_all.blockSignals(True)
        self.planner_select_all.setChecked(bool(boxes) and all(box.isChecked() for box in boxes))
        self.planner_select_all.blockSignals(False)

    def selected_planner_games(self):
        selected = {address.lower() for address, box in self.planner_account_checks.items()
                    if box.isChecked()}
        return [(address, game) for address, game in self._game_sessions.items()
                if address.lower() in selected]

    def start_multi_account_plan(self):
        selected = [address for address, box in self.planner_account_checks.items() if box.isChecked()]
        if not selected:
            self.planner_status.setText('请先选择至少一个账号。')
            return
        mode = self.planner_mode.currentData()
        started, offline, busy = 0, 0, 0
        for address in selected:
            game = self._game_sessions.get(address.lower())
            if game is None or game.status.text() != '已连接':
                offline += 1
                continue
            if game.fishing_busy():
                busy += 1
                continue
            game.auto_potion.setChecked(self.planner_use_potion.isChecked())
            limited = self.planner_limit_level.isChecked()
            low, high = self.planner_level_min.value(), self.planner_level_max.value()
            if low > high:
                low, high = high, low
            game.monster_level_limited.setChecked(limited)
            game.monster_level_min.setValue(low)
            game.monster_level_max.setValue(high)
            game.auto_quest.setChecked(mode == 'quests')
            game.quest_map_auto.setChecked(mode == 'quests')
            game.elite_only.setChecked(mode == 'elite')
            game.task_limited_mode.setChecked(False)
            farm_map = self.planner_farm_map.currentData()
            if farm_map is not None:
                farm_map_index = game.no_quest_farm_map.findData(farm_map)
                if farm_map_index >= 0:
                    game.no_quest_farm_map.setCurrentIndex(farm_map_index)
            game.no_quest_farm.setChecked(self.planner_farm_after_quests.isChecked())
            game.avoid_contested_monsters.setChecked(self.planner_avoid_contested.isChecked())
            game.auto_attack.setChecked(True)
            if mode == 'quests':
                game.accept_next_monster_quest()
            started += 1
        self.planner_status.setText(
            f'已启动 {started} 个账号' + (f'；跳过离线账号 {offline} 个' if offline else '') +
            (f'；跳过钓鱼或库存核对中的账号 {busy} 个' if busy else '') + '。')

    def pause_multi_account_plan(self):
        games = self.selected_planner_games()
        for _address, game in games:
            game.auto_attack.setChecked(False)
            game.auto_quest.setChecked(False)
            game.quest_map_auto.setChecked(False)
            game.move_timer.stop()
            game.pending_destination = None
            game.pending_portal = None
            game.route_points = []
            game.update_map_buttons()
        self.planner_status.setText(f'已暂停 {len(games)} 个所选账号的自动任务、移动与战斗。')

    def stop_multi_account_plan(self):
        games = self.selected_planner_games()
        for _address, game in games:
            game.auto_attack.setChecked(False)
            game.auto_quest.setChecked(False)
            game.quest_map_auto.setChecked(False)
            game.move_timer.stop()
            game.pending_destination = None
            game.pending_portal = None
            game.route_points = []
            game.update_map_buttons()
        self.planner_status.setText(f'已停止 {len(games)} 个所选账号的自动任务与战斗。')

    def batch_disconnect_accounts(self):
        """Stop automation and close the game socket for every selected online account."""
        selected = [address for address, box in self.planner_account_checks.items()
                    if box.isChecked()]
        if not selected:
            self.planner_status.setText('请先选择要批量下线的账号。')
            return

        selected_ids = {address.lower() for address in selected}
        disconnected = 0
        already_offline = 0
        # Cancel any not-yet-started batch logins so the offline action remains final.
        if self._batch_login_active:
            self._batch_login_queue = [address for address in self._batch_login_queue
                                       if address.lower() not in selected_ids]
            for address in selected_ids:
                if address in self._batch_login_inflight:
                    game = self._game_sessions.get(address)
                    if game is not None:
                        game._batch_login_silent = False
                    self._batch_login_results.pop(address, None)
                    self._batch_login_timeouts.pop(address, None)
                    self._batch_login_inflight.discard(address)
                    self._batch_login_attempted += 1
                    self._batch_login_failed += 1
            self.planner_batch_connect.setEnabled(not self._batch_login_active)

        for address in selected:
            game = self._game_sessions.get(address.lower())
            if game is None:
                already_offline += 1
                continue
            game.auto_attack.setChecked(False)
            game.auto_quest.setChecked(False)
            game.quest_map_auto.setChecked(False)
            game.move_timer.stop()
            game.pending_destination = None
            game.pending_portal = None
            game.route_points = []
            game.update_map_buttons()
            if game.ws is not None or game.status.text() in self.SESSION_BUSY_STATES:
                if address.lower() == self.active_address.lower():
                    shop.MONITOR.stop()
                game.disconnect_ws()
                disconnected += 1
            else:
                already_offline += 1

        self.refresh_account_rows()
        self.planner_status.setText(
            f'已批量下线 {disconnected} 个账号' +
            (f'；{already_offline} 个本来就离线' if already_offline else '') + '。')
        if self._batch_login_active:
            self._continue_batch_login()

    def load_shop_profiles(self):
        try:
            payload = json.loads(self._profile_path.read_text(encoding='utf-8'))
            profiles = payload.get('profiles', {}) if isinstance(payload, dict) else {}
            return profiles if isinstance(profiles, dict) else {}
        except (OSError, ValueError, AttributeError):
            return {}

    def persist_shop_profiles(self):
        if not self._profile_path:
            return
        self._profile_path.parent.mkdir(parents=True, exist_ok=True)
        temp = self._profile_path.with_suffix('.tmp')
        with self._profile_lock:
            temp.write_text(json.dumps({'profiles': self._shop_profiles}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            if os.name != 'nt':
                temp.chmod(0o600)
            temp.replace(self._profile_path)

    def save_active_shop_profile(self):
        if not self.active_address or not self._profile_path:
            return
        try:
            with shop.MONITOR.lock:
                config = dict(shop.MONITOR.config)
            with self._profile_lock:
                self._shop_profiles[self.active_address.lower()] = config
            self.persist_shop_profiles()
        except (OSError, TypeError, ValueError):
            pass

    def active_shop_wallet_address(self):
        return self.active_address if DesktopWalletStore(self).get_password('tabby-shop-bsc', 'private-key') else ''

    def refresh_account_rows(self):
        self._account_refresh_timer.stop()
        while self.account_rows.count():
            item = self.account_rows.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        addresses = self.sorted_wallet_addresses(self.game.credential_vault.list_wallets())
        self.refresh_planner_accounts()
        self.account_count.setText(f'{len(addresses)} 个账号')
        self.account_empty.setVisible(not addresses)
        for address in addresses:
            row = QFrame()
            row.setObjectName('walletAccountRow')
            row.setMinimumHeight(72)
            row.setMaximumHeight(104)
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(14, 9, 14, 9)
            row_layout.setSpacing(12)
            identity = QVBoxLayout()
            identity.setSpacing(3)
            address_row = QHBoxLayout()
            address_row.setSpacing(8)
            dot = QLabel()
            dot.setObjectName('walletStatusDot')
            dot.setFixedSize(10, 10)
            address_label = QLabel(self.compact_wallet_address(address))
            address_label.setObjectName('walletAddress')
            address_label.setToolTip(address)
            address_label.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
            address_row.addWidget(dot, 0, Qt.AlignmentFlag.AlignVCenter)
            address_row.addWidget(address_label)
            copy_address = QPushButton('复制地址')
            copy_address.setObjectName('walletCopyAddress')
            copy_address.setFixedSize(112, 40)
            copy_address.setToolTip('复制完整钱包地址')
            copy_address.clicked.connect(
                lambda _checked=False, wallet=address, button=copy_address:
                self.copy_wallet_address(wallet, button))
            identity.addLayout(address_row)
            is_active = address.lower() == self.active_address.lower()
            session = self._game_sessions.get(address.lower())
            session_state = session.status.text() if session else ''
            needs_character = bool(session and session.character_creation_required)
            if needs_character:
                dot_color = '#E6BF55'
                state_text = '待创建角色'
            elif session_state == '已连接':
                dot_color = '#43C98B'
                state_text = '在线' + (' · 当前显示' if is_active else ' · 后台保持连接')
            elif session_state in self.SESSION_BUSY_STATES:
                dot_color = '#E6BF55'
                state_text = '连接中' + (' · 当前显示' if is_active else ' · 后台连接中')
            else:
                dot_color = '#E05E5A'
                state_text = '离线' + (' · 当前显示' if is_active else ' · 已加密保存')
            dot.setStyleSheet(f'background:{dot_color}; border-radius:5px;')
            dot.setToolTip(state_text)
            state_label = QLabel(state_text)
            state_label.setObjectName('walletAccountState')
            state_label.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
            state_label.setFixedWidth(state_label.sizeHint().width())
            address_row.addWidget(state_label)
            address_row.addStretch(1)
            details = self.account_summary(session, self._account_last_maps.get(address.lower()))
            details_label = QLabel(details or ('角色资料将在登录后显示' if session else '尚未登录'))
            details_label.setObjectName('walletAccountDetails')
            details_label.setWordWrap(True)
            identity.addWidget(details_label)
            row_layout.addLayout(identity, 1)
            row_layout.setAlignment(identity, Qt.AlignmentFlag.AlignVCenter)
            if needs_character:
                action_text = '创建角色'
            elif session_state in self.SESSION_BUSY_STATES - {'已连接'}:
                action_text = '连接中…'
            elif is_active and session_state == '已连接':
                action_text = '查看控制台'
            elif is_active:
                action_text = '重新连接'
            elif session_state == '已连接':
                action_text = '切换显示（不断线）'
            else:
                action_text = '切换并连接'
            action = QPushButton(action_text)
            action.setObjectName('secondaryButton' if is_active else 'primaryButton')
            action.setMinimumHeight(40)
            if is_active:
                action.setStyleSheet("QPushButton { background:#F3EFE6; color:#514630; border:1px solid #CDBD9F; border-radius:8px; font-weight:600; } QPushButton:hover { background:#ECE4D4; border-color:#B99B67; }")
            else:
                action.setStyleSheet("QPushButton { background:#5B7C55; color:#FFFFFF; border:1px solid #52734D; border-radius:8px; font-weight:600; } QPushButton:hover { background:#496B47; border-color:#496B47; }")
            action.setEnabled(needs_character or session_state not in self.SESSION_BUSY_STATES - {'已连接'})
            if needs_character:
                action.setToolTip('打开该账号，选择职业与名称后创建角色；其他账号继续在线。')
            elif not is_active and session_state == '已连接':
                action.setToolTip('只切换当前控制台；这个账号和其他账号的游戏连接都会保持在线。')
            elif not is_active:
                action.setToolTip('切换到这个账号并连接；其他在线账号不会断开。')
            elif session_state == '已连接':
                action.setToolTip('打开当前账号控制台。')
            else:
                action.setToolTip('重新连接当前账号；其他账号连接保持不变。')
            action.clicked.connect(lambda _checked=False, wallet=address: self.connect_account(wallet))
            action.setFixedSize(176, 40)
            actions = QHBoxLayout()
            actions.setContentsMargins(0, 0, 0, 0)
            actions.setSpacing(10)
            actions.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight)
            actions.addWidget(copy_address)
            actions.addWidget(action)
            row_layout.addLayout(actions)
            self.account_rows.addWidget(row)
        self.account_rows.addStretch(1)

    @staticmethod
    def compact_wallet_address(address):
        address = str(address or '')
        if len(address) <= 10:
            return address
        return f'{address[:3]}…{address[-4:]}'

    @staticmethod
    def copy_wallet_address(address, button=None):
        QApplication.clipboard().setText(str(address))
        if button is not None:
            button.setText('已复制')
            def restore_label(target=button):
                try:
                    target.setText('复制地址')
                except RuntimeError:
                    # The account list may have been refreshed meanwhile.
                    pass
            QTimer.singleShot(1200, restore_label)

    @staticmethod
    def account_summary(game, last_known_map=None):
        if game is None:
            return ''
        profile = getattr(game, 'api_profile', {})
        profile = profile if isinstance(profile, dict) else {}
        progress = getattr(game, 'last_progress_state', {})
        progress = progress if isinstance(progress, dict) else {}
        equipment = getattr(game, 'api_equipment', {})
        equipment = equipment if isinstance(equipment, dict) else {}
        totals = equipment.get('totals', {})
        totals = totals if isinstance(totals, dict) else {}
        self_state = getattr(game, 'last_self_state', {})
        self_state = self_state if isinstance(self_state, dict) else {}
        character_facts = getattr(game, 'character_facts', {})
        fact_value = lambda key: character_facts.get(key).text() if isinstance(character_facts, dict) and character_facts.get(key) else ''
        name = profile.get('playerName') or profile.get('name') or fact_value('角色')
        level = progress.get('level', profile.get('level')) or fact_value('等级')
        combat_power = next((source.get(key) for source in (profile, progress, totals)
                             for key in ('combatPower', 'battlePower', 'power')
                             if source.get(key) is not None), None)
        attack = totals.get('attack', totals.get('attackPower'))
        defense = totals.get('defense')
        luck = next((source.get(key) for source in (totals, self_state, profile, progress)
                     for key in ('luck', 'luckPercent', 'luckValue') if source.get(key) is not None), None)
        if attack is None:
            attack = self_state.get('attack')
        if defense is None:
            defense = self_state.get('defense')
        parts = []
        current_map = getattr(game, 'current_map', None)
        if current_map is None:
            current_map = last_known_map
        if current_map is not None:
            try:
                map_id = int(current_map)
            except (TypeError, ValueError):
                map_id = current_map
            map_name = MAP_NAMES.get(map_id, f'地图 {map_id}')
            parts.append(f'地图 {map_name.split(" · ")[-1]}')
        if name and str(name) != '—':
            parts.append(str(name))
        if level and str(level) != '—':
            parts.append(f'等级 {level}')
        if combat_power is not None:
            parts.append(f'战斗力 {combat_power}')
        elif attack is not None or defense is not None:
            combat = ' / '.join(f'{label} {value}' for label, value in (('攻击', attack), ('防御', defense)) if value is not None)
            parts.append(combat)
        if luck is not None:
            parts.append(f'幸运 {DesktopWindow.format_summary_decimal(luck)}%')
        profession = fact_value('职业') or profile.get('characterClass') or profile.get('class')
        if profession and str(profession) != '—':
            parts.append(str(profession))
        health = self_state.get('health')
        maximum_health = self_state.get('maxHealth', self_state.get('maximumHealth'))
        if health is not None:
            parts.append(f'生命 {health}' + (f'/{maximum_health}' if maximum_health is not None else ''))
        farming = self_state.get('farming', {})
        stamina = farming.get('staminaPercent') if isinstance(farming, dict) else None
        if stamina is not None:
            parts.append(f'疲劳 {DesktopWindow.format_summary_decimal(stamina)}%')
        experience = progress.get('experience', profile.get('experience'))
        experience_needed = progress.get('experienceNeeded', profile.get('experienceNeeded'))
        if experience is not None:
            shown_experience = DesktopWindow.format_summary_integer(experience)
            if experience_needed is not None:
                shown_experience += '/' + DesktopWindow.format_summary_integer(experience_needed)
            parts.append(f'经验 {shown_experience}')
        gold = profile.get('gold', self_state.get('gold'))
        if gold is not None:
            parts.append(f'金币 {DesktopWindow.format_summary_decimal(gold)}')
        balance = getattr(game, 'tabby_balance_display', '')
        if balance:
            parts.append(f'TABBY {balance}')
        return ' · '.join(parts)

    @staticmethod
    def format_summary_decimal(value):
        try:
            return f'{float(value):,.2f}'
        except (TypeError, ValueError):
            return str(value)

    @staticmethod
    def format_summary_integer(value):
        try:
            number = float(value)
            return f'{int(number):,}' if number.is_integer() else f'{number:,.2f}'
        except (TypeError, ValueError):
            return str(value)

    def ask_shared_passphrase(self, confirm):
        prompt = '设置所有钱包共用的主密码（至少 6 位）：' if confirm else '输入现有钱包保险库的主密码：'
        phrase, accepted = QInputDialog.getText(self, '统一主密码', prompt, QLineEdit.EchoMode.Password)
        if not accepted:
            return None
        if len(phrase) < 6:
            QMessageBox.warning(self, '主密码太短', '主密码至少需要 6 位。')
            return None
        if confirm:
            repeated, accepted = QInputDialog.getText(self, '确认主密码', '请再次输入主密码：', QLineEdit.EchoMode.Password)
            if not accepted:
                return None
            if phrase != repeated:
                QMessageBox.warning(self, '主密码不一致', '两次输入不一致，没有导入钱包。')
                return None
        return phrase

    def cache_shared_passphrase(self, phrase):
        """Keep the verified vault password in memory for this app session."""
        if not phrase:
            return
        self._master_passphrase = phrase
        sessions = [self.game, *self._game_sessions.values()]
        for game in {id(item): item for item in sessions}.values():
            game._vault_passphrase = phrase

    def import_wallets(self):
        dialog = QDialog(self)
        dialog.setWindowTitle('导入多个钱包')
        dialog.setMinimumSize(580, 430)
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel('每行粘贴一个 BSC 私钥，可一次导入多个。私钥只在本机校验并加密保存。'))
        editor = QPlainTextEdit()
        editor.setPlaceholderText('0x…\n0x…')
        editor.setTabChangesFocus(True)
        editor.setMinimumHeight(235)
        layout.addWidget(editor, 1)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        cancel = QPushButton('取消')
        cancel.setObjectName('secondaryButton')
        save = QPushButton('加密导入')
        save.setObjectName('primaryButton')
        cancel.clicked.connect(dialog.reject)
        save.clicked.connect(dialog.accept)
        buttons.addWidget(cancel)
        buttons.addWidget(save)
        layout.addLayout(buttons)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        raw_values = [line.strip() for line in editor.toPlainText().splitlines() if line.strip()]
        editor.clear()
        if not raw_values:
            return
        try:
            from eth_account import Account
            existing = {item.lower() for item in self.game.credential_vault.list_wallets()}
            validated, seen = [], set()
            for value in raw_values:
                private_key = value[2:] if value.lower().startswith('0x') else value
                address = Account.from_key(private_key).address
                if address.lower() in existing or address.lower() in seen:
                    continue
                seen.add(address.lower())
                validated.append((address, private_key))
        except Exception:
            QMessageBox.warning(self, '私钥格式无效', '至少一行不是有效的 EVM 私钥，没有保存本次导入内容。')
            return
        if not validated:
            QMessageBox.information(self, '没有新账号', '这些地址已经导入过了。')
            return
        existing_wallets = self.game.credential_vault.list_wallets()
        phrase = self._master_passphrase
        if not phrase:
            phrase = self.ask_shared_passphrase(confirm=not bool(existing_wallets))
        if phrase is None:
            return
        vault = self.game.credential_vault
        self._wallet_import_phrase = phrase
        self.import_wallet_button.setEnabled(False)
        self.import_wallet_button.setText('正在后台加密…')

        def encrypt_wallets():
            result = {'imported': 0, 'count': len(existing_wallets), 'error': None,
                      'wrong_passphrase': False}
            try:
                if existing_wallets:
                    vault.load_wallet(phrase, existing_wallets[0])
                for address, private_key in validated:
                    vault.store_wallet(private_key, phrase, address)
                    result['imported'] += 1
            except ValueError as exc:
                if existing_wallets and result['imported'] == 0:
                    result['wrong_passphrase'] = True
                else:
                    result['error'] = str(exc)
            except Exception as exc:
                result['error'] = f'{type(exc).__name__}: {exc}'
            result['count'] = len(vault.list_wallets())
            self.wallet_import_signals.completed.emit(result)

        self._wallet_import_thread = threading.Thread(
            target=encrypt_wallets, name='wallet-vault-import', daemon=True)
        self._wallet_import_thread.start()

    def on_wallet_import_completed(self, result):
        self.import_wallet_button.setEnabled(True)
        self.import_wallet_button.setText('导入钱包')
        if result.get('wrong_passphrase'):
            self._wallet_import_phrase = None
            QMessageBox.warning(self, '主密码错误', '无法用这个主密码解锁已保存的钱包，本次没有导入。')
            return
        imported = int(result.get('imported', 0))
        self.refresh_account_rows()
        if imported:
            self._master_passphrase = self._wallet_import_phrase
            self._wallet_import_phrase = None
            self.game._vault_passphrase = self._master_passphrase
            self.game.remember_private_key.setChecked(True)
            self.game.refresh_saved_wallets()
        else:
            self._wallet_import_phrase = None
        error = result.get('error')
        if error:
            QMessageBox.warning(
                self, '导入未完成',
                f"已加密保存 {result.get('count', 0)} 个钱包；本次导入 {imported} 个，其余失败：{error}")
        elif imported:
            QMessageBox.information(self, '导入完成', f'已加密保存 {imported} 个新钱包，可在列表中逐个连接。')

    def connect_account(self, address, background=False):
        normalized = address.lower()
        same_active = normalized == self.active_address.lower()
        if shop.MONITOR.buy_lock.locked():
            QMessageBox.warning(self, '购买正在提交', '当前账号有一笔购买正在提交。请等待交易完成后再切换商城账号；游戏连接会继续保持。')
            self.tabs.setCurrentIndex(2)
            return
        switching = bool(self.active_address and not same_active)
        if switching and not background:
            self.save_active_shop_profile()
            # The game socket remains alive in its own GameWindow. The shop
            # monitor is a singleton and must be rebound to the selected
            # account before it can continue safely.
            shop.MONITOR.stop()
            with shop.MONITOR.lock:
                shop.MONITOR.events = []
                shop.MONITOR.products = []
                shop.MONITOR.candidate = None
                shop.MONITOR.product_count = 0
                shop.MONITOR.last_scan = None
                shop.MONITOR.scan_count = 0
                shop.MONITOR.revision += 1
        wallets = self.game.credential_vault.list_wallets()
        if normalized not in {item.lower() for item in wallets}:
            QMessageBox.warning(self, '找不到钱包', '请刷新账号列表后重试。')
            self.request_account_refresh()
            return
        game = self._game_sessions.get(normalized)
        if game is None:
            # Background batch sign-ins do not set active_address. Reusing
            # that field to detect the first session made every background
            # wallet after the first point at the same GameWindow and socket.
            if not self._game_sessions:
                game = self.game
                widget = self.game_stack.widget(0)
            else:
                game = GameWindow()
                game.setStyleSheet(self.game.styleSheet())
                widget = game.takeCentralWidget()
                game.account_toggle.hide()
                game.dashboard_header.hide()
                game.connect_button.hide()
                game.disconnect_button.hide()
                game.remember_private_key.hide()
                self.game_stack.addWidget(widget)
                game.on_state_change = lambda state, instance=game: self.on_game_state(instance, state)
                game.on_latency_change = lambda instance=game: self.on_game_latency(instance)
                game.on_account_metadata_change = lambda instance=game: self.on_game_metadata(instance)
                game.can_prompt_character_creation = lambda instance=game: self.game is instance
                game.on_vault_unlocked = self.cache_shared_passphrase
                game.token.textChanged.connect(lambda value, instance=game: self.on_session_token_changed(instance, value))
                game.bridge.signed_login.connect(self.on_signed_login)
                game.bridge.keyring_status.connect(
                    lambda message, instance=game: self.account_keyring_status.setText(message)
                    if self.game is instance else None)
                game.auth_method.currentIndexChanged.connect(
                    lambda *_args, instance=game: self.update_account_auth_fields()
                    if self.game is instance else None)
            self._game_sessions[normalized] = game
            self._game_session_widgets[normalized] = widget
            game.on_map_change = lambda map_id, wallet=address: self.on_account_map_change(wallet, map_id)
            self._game_address_by_bridge[id(game.bridge)] = address
        else:
            widget = self._game_session_widgets.get(normalized)
        if game is None or widget is None:
            QMessageBox.warning(self, '账号控制台错误', '无法打开这个账号的游戏控制台。')
            return
        game._background_login = background
        if not background:
            self.game = game
            self.game_stack.setCurrentWidget(widget)
            self.active_address = address
            self._pending_address = address
        else:
            # Background batch sign-ins must not open a character-creation
            # dialog over the account manager; it can be handled when shown.
            game.can_prompt_character_creation = (
                lambda instance=game, wallet=address:
                self.game is instance and self.active_address.lower() == wallet.lower())
        game._batch_login_silent = background or normalized in self._batch_login_inflight
        game._vault_passphrase = self._master_passphrase or game._vault_passphrase
        if background and game.character_creation_required and game.get_session_token():
            game.bridge.state.emit('账号尚未创建角色；请先创建角色。')
            self.request_account_refresh()
            return
        index = game.saved_wallet.findData(address)
        if index >= 0:
            game.saved_wallet.setCurrentIndex(index)
        game.auth_method.setCurrentIndex(game.auth_method.findData('private_key'))
        if not game.remember_private_key.isChecked():
            game.remember_private_key.setChecked(True)
        if background:
            if game.status.text() not in self.SESSION_BUSY_STATES:
                game.connect_ws()
            self.request_account_refresh()
            return
        if not same_active:
            shop.MONITOR.stop()
            shop.MONITOR.configure(self._shop_profiles.get(address.lower(), shop.DEFAULT_CONFIG))
        shop.MONITOR.event_callback = game.bridge.shop_notification.emit
        self._token = self._session_tokens.get(normalized, '')
        self._active_private_key = ''
        self.prepare_shop_account_context(address)
        self.tabs.setCurrentIndex(1)
        if game.character_creation_required and game.get_session_token():
            game.pending_world_entry = True
            game._batch_login_silent = False
            game.character_creation_prompted = False
            game.maybe_prompt_character_creation()
        elif game.status.text() not in self.SESSION_BUSY_STATES:
            game.connect_ws()
        self.refresh_account_rows()

    def on_session_token_changed(self, game, value):
        if game is self.game:
            self.set_token(value)

    def on_game_state(self, game, state):
        if game is self.game:
            self.update_shell_status(state)
        bridge_key = id(game.bridge)
        address = self._game_address_by_bridge.get(bridge_key, '').lower()
        if address in self._batch_login_inflight and self._batch_login_active:
            if game.character_creation_required and state == '账号尚未创建角色；请先创建角色。':
                self._finish_batch_login_result(address, {'needs_character': True})
            elif state == '已连接':
                result = self._batch_login_results.get(address) or {'ok': True, 'token': 'connected'}
                game._batch_login_silent = False
                self._finish_batch_login_result(address, result)
            elif (state in {'签名登录失败', '连接失败', '读取角色资料失败；点击连接重试。',
                            '账号尚未创建角色；请先创建角色。', '已主动断开'}
                  or state.startswith(('对端关闭', '连接异常关闭', '心跳超时'))):
                game._batch_login_silent = False
                self._finish_batch_login_result(address, {'ok': False, 'error': state})
        self.request_account_refresh()

    def on_game_latency(self, game):
        if game is self.game:
            self.update_shell_latency()

    def on_game_metadata(self, game):
        if game in self._game_sessions.values():
            self.request_account_refresh()

    def on_account_map_change(self, address, map_id):
        if map_id is not None:
            self._account_last_maps[str(address).lower()] = map_id
        self.request_account_refresh()

    def request_account_refresh(self):
        """Coalesce background account updates without postponing forever."""
        if self._closing:
            return
        if self._batch_login_active:
            self._account_refresh_pending = True
            return
        if not self._account_refresh_timer.isActive():
            self._account_refresh_timer.start()

    def prepare_shop_account_context(self, address):
        if not self.web:
            return
        self._loaded = False
        page = self.web.page()
        scripts = page.scripts()
        for existing in scripts.find('tabby-account-context'):
            scripts.remove(existing)
        script = QWebEngineScript()
        script.setName('tabby-account-context')
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        script.setSourceCode('window.__TABBY_ACCOUNT__ = ' + json.dumps(address.lower()) + ';')
        scripts.insert(script)
        try:
            page.loadFinished.disconnect(self.shop_loaded)
        except (TypeError, RuntimeError):
            pass
        page.loadFinished.connect(self.shop_loaded)
        self.web.reload()

    def check_for_updates(self):
        if self._update_thread and self._update_thread.is_alive():
            return
        self.update_button.setEnabled(False)
        self.update_button.setText('正在检查…')

        def run_check():
            try:
                self.update_signals.checked.emit(fetch_latest_release())
            except Exception as exc:
                self.update_signals.failed.emit(f'{type(exc).__name__}: {exc}')

        self._update_thread = threading.Thread(target=run_check, daemon=True,
                                               name='tabby-update-check')
        self._update_thread.start()

    def on_update_checked(self, release):
        self.update_button.setEnabled(True)
        self.update_button.setText('检查更新')
        self._update_release = release
        if release.get('repository_unavailable'):
            QMessageBox.warning(
                self, '无法访问更新仓库',
                'GitHub 返回 404：仓库可能是私有的，当前设备没有可用的 GitHub 登录。\n'
                '请安装 GitHub CLI 并运行 gh auth login 后重试，或使用公开 Release。',
            )
            return
        if release.get('no_release'):
            QMessageBox.information(
                self, '暂无可用更新',
                'GitHub 仓库目前还没有公开的正式 Release。\n'
                '发布新版桌面程序后，这里就能检查并安装更新。',
            )
            return
        if not release.get('is_newer'):
            QMessageBox.information(self, '检查更新', f'当前已是最新版本（{APP_VERSION}）。')
            return
        version = release.get('version', '未知')
        asset = release.get('asset')
        if not is_frozen_windows() or not asset:
            QMessageBox.information(
                self, '发现新版本',
                f'GitHub 上有新版本 {version}。当前运行方式无法自动替换安装文件，\n'
                '将打开 Release 页面供你获取对应平台版本。',
            )
            QDesktopServices.openUrl(QUrl(RELEASES_PAGE))
            return
        answer = QMessageBox.question(
            self, '发现新版本', f'发现 Tabby Desktop {version}，是否下载并安装？\n'
            '安装完成后应用会自动重启。',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.download_update(asset)

    def download_update(self, asset):
        if self._update_thread and self._update_thread.is_alive():
            return
        self.update_button.setEnabled(False)
        self.update_button.setText('正在下载…')

        def run_download():
            try:
                temp_dir = Path(tempfile.mkdtemp(prefix='tabby-release-'))
                archive = download_asset(asset,
                                         temp_dir / 'TabbyDesktop-windows-x64.zip')
                self.update_signals.downloaded.emit(str(archive))
            except Exception as exc:
                self.update_signals.failed.emit(f'{type(exc).__name__}: {exc}')

        self._update_thread = threading.Thread(target=run_download, daemon=True,
                                               name='tabby-update-download')
        self._update_thread.start()

    def on_update_downloaded(self, archive_path):
        self.update_button.setEnabled(True)
        self.update_button.setText('检查更新')
        try:
            app_dir = Path(sys.executable).resolve().parent
            script = prepare_windows_update(Path(archive_path), app_dir)
            dialog = QMessageBox(self)
            dialog.setWindowTitle('更新已下载')
            dialog.setText('更新包已下载并校验。点击“立即重启安装”后，应用会关闭、替换程序文件并重新启动。')
            dialog.setInformativeText('安装器会等待当前程序退出后替换文件。若安装失败，会尝试恢复旧版本并显示错误；详细记录保存在 %LOCALAPPDATA%\\TabbyDesktop\\update.log。')
            dialog.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            dialog.button(QMessageBox.StandardButton.Yes).setText('立即重启安装')
            dialog.button(QMessageBox.StandardButton.No).setText('稍后')
            answer = dialog.exec()
            if answer == QMessageBox.StandardButton.Yes:
                launch_update_script(script)
                # close() performs the normal websocket, monitor and HTTP
                # cleanup. Explicitly quit the Qt event loop as well so a
                # modeless child window/WebEngine view cannot keep the old
                # process alive while the detached installer waits on it.
                self.close()
                app = QApplication.instance()
                if app is not None:
                    app.quit()
        except PermissionError:
            self.on_update_failed(
                '无法写入当前程序目录。请将 TabbyDesktop 文件夹移动到当前 Windows 用户可写入的位置后重试，'
                '或以管理员身份运行应用。')
        except Exception as exc:
            self.on_update_failed(f'{type(exc).__name__}: {exc}')

    def on_update_failed(self, message):
        self.update_button.setEnabled(True)
        self.update_button.setText('检查更新')
        if 'HTTP Error 403' in message:
            message += '\nGitHub 暂时限制了匿名 API 请求，请稍后再试。'
        QMessageBox.warning(self, '更新失败', f'无法完成 GitHub 更新：\n{message}')

    def show_account(self):
        self.account_dialog.show()
        self.account_dialog.raise_()
        if self.game.auth_method.currentData() == 'private_key':
            self.game.private_key.setFocus()
        else:
            self.game.token.setFocus()

    def connect_active_game(self):
        self.game.connect_ws()

    def disconnect_active_game(self):
        self.game.disconnect_ws()
        self._token = ''
        if self.active_address:
            self._session_tokens[self.active_address.lower()] = ''
        self.sync_shop_token()
        self.refresh_account_rows()

    def update_account_auth_fields(self, *_args):
        private_mode = self.game.auth_method.currentData() == 'private_key'
        self.account_token_label.setVisible(not private_mode)
        self.account_wallet_label.setVisible(private_mode)
        self.game.saved_wallet.setVisible(private_mode)
        self.account_private_key_label.setVisible(private_mode)
        self.account_sign_help.setVisible(private_mode)

    def set_token(self, value, guard_private_key=True):
        value = value.strip()
        probe = value[7:].strip() if value.lower().startswith('bearer ') else value
        candidate = probe[2:] if probe.lower().startswith('0x') else ''
        has_wallet_prefix = len(candidate) == 64 and all(
            ch in '0123456789abcdefABCDEF' for ch in candidate)
        is_unprefixed_hex = len(probe) == 64 and all(
            ch in '0123456789abcdefABCDEF' for ch in probe)
        if guard_private_key and (has_wallet_prefix or is_unprefixed_hex):
            # Common wallet private-key form. Stop it before it reaches the
            # shared shop token or any network request.
            if has_wallet_prefix:
                use_as_token = False
            else:
                answer = QMessageBox.warning(
                    self, '确认凭证类型',
                    '检测到 64 位十六进制内容，可能是钱包私钥，也可能是游戏 Token。\n'
                    '确认它是游戏 Token 才继续；否则清除并切换到私钥登录。',
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                use_as_token = answer == QMessageBox.StandardButton.Yes
            if not use_as_token:
                self.game.token.blockSignals(True)
                self.game.token.clear()
                self.game.token.blockSignals(False)
                self._token = ''
                if self.active_address:
                    self._session_tokens[self.active_address.lower()] = ''
                self.sync_shop_token()
                self.game.auth_method.setCurrentIndex(
                    self.game.auth_method.findData('private_key'))
                self.update_account_auth_fields()
                self.game.private_key.setFocus()
                QMessageBox.information(
                    self, '已阻止误用凭证',
                    '内容已从 Token 框清除，没有同步到商城或发送网络。请确认登录方式后再粘贴。'
                )
                return
        self._token = value[7:].strip() if value.lower().startswith('bearer ') else value
        if self.active_address:
            self._session_tokens[self.active_address.lower()] = self._token
        self.update_shell_status(self.game.status.text())
        self.sync_shop_token()

    def on_signed_login(self, result):
        bridge = self.sender()
        bridge_key = id(bridge) if bridge is not None else id(self.game.bridge)
        address = self._game_address_by_bridge.get(bridge_key, self._pending_address or self.active_address)
        game = next((item for item in self._game_sessions.values() if id(item.bridge) == bridge_key), self.game)
        if isinstance(result, dict) and result.get('ok') and result.get('token'):
            wallet_key = str(address or '').lower()
            token_value = str(result['token'])
            if wallet_key:
                self._session_tokens[wallet_key] = token_value
            # The server-issued game session is trusted application data; it
            # may itself be a 64-character hex token and must bypass the
            # paste-safety prompt used only for the editable Token field.
            if not wallet_key or wallet_key == self.active_address.lower():
                self.set_token(token_value, guard_private_key=False)
            self._master_passphrase = game._vault_passphrase or self._master_passphrase
            if wallet_key == self.active_address.lower():
                self._active_private_key = ''
            if address and address.lower() == self._pending_address.lower():
                self._pending_address = ''
            self.request_account_refresh()
            if result.get('remembered'):
                self.account_keyring_status.setText('保存状态：AES-GCM 已验证；三片已保存，主密码未保存')
            elif result.get('remember_error'):
                self.account_keyring_status.setText('保存状态：加密分片保存/校验失败；请重试')
            elif not self.game.remember_private_key.isChecked():
                self.account_keyring_status.setText('保存状态：本次未保存私钥')
        normalized = str(address or '').lower()
        if normalized in self._batch_login_inflight and self._batch_login_active:
            if isinstance(result, dict) and result.get('ok') and result.get('token'):
                self._batch_login_results[normalized] = result
            else:
                game._batch_login_silent = False
                self._finish_batch_login_result(address, result)
        else:
            game._batch_login_silent = False

    def update_shell_status(self, connection_state=None):
        state = connection_state or self.game.status.text()
        if state != getattr(self, '_last_game_state', None):
            self._last_game_state = state
            self.request_account_refresh()
        token_state = 'Token 已设置' if self._token else '未设置 Token'
        latency = self.game.last_rtt_ms
        if state == '已连接' and latency is not None:
            self.account_status.setText(f'{state} · {latency} ms · {token_state}')
            if latency <= 120:
                color, quality = '#43c98b', '延迟低'
            elif latency <= 250:
                color, quality = '#e6bf55', '延迟偏高'
            else:
                color, quality = '#ef8d43', '延迟高'
        elif state in ('连接中…', '连接中'):
            color, quality = '#e6bf55', '正在连接'
            self.account_status.setText(f'{state} · {token_state}')
        elif state == '已连接':
            color, quality = '#e6bf55', '等待延迟数据'
            self.account_status.setText(f'{state} · 等待延迟 · {token_state}')
        else:
            color, quality = '#e05e5a', '已掉线'
            self.account_status.setText(f'{state} · {token_state}')
        self.connection_dot.setStyleSheet(f'background:{color}; border-radius:5px;')
        self.connection_dot.setToolTip(f'{quality}' + (f'：{latency} ms' if state == '已连接' and latency is not None else ''))

    def update_shell_latency(self):
        self.update_shell_status(self.game.status.text())

    def update_navigation(self, index):
        self.account_nav.setChecked(index == 0)
        self.game_nav.setChecked(index == 1)
        self.shop_nav.setChecked(index == 2)

    def sync_shop_token(self):
        if self.web is None or not self._loaded:
            return
        # Pass as a JSON string literal; never construct executable token text.
        self.web.page().runJavaScript(
            "(() => {const e=document.getElementById('token');if(e){e.value="
            + json.dumps(self._token) + ";e.readOnly=true;"
            "e.placeholder='请通过桌面右上角账号连接设置 Token';}})();")

    def activate_tab(self, index):
        if index != 2 or self._shop_started:
            return
        try:
            self.httpd = ThreadingHTTPServer(('127.0.0.1', 0), self.make_handler())
            self.httpd.daemon_threads = True
            threading.Thread(target=self.httpd.serve_forever, daemon=True,
                             name='tabby-local-shop').start()
            url = QUrl(f'http://127.0.0.1:{self.httpd.server_port}/')
            self.web = QWebEngineView()
            page = LocalShopPage(url, self.web)
            self.web.setPage(page)
            self.clipboard_bridge = DesktopClipboard(self)
            self.web_channel = QWebChannel(page)
            self.web_channel.registerObject('desktopClipboard', self.clipboard_bridge)
            page.setWebChannel(self.web_channel)
            channel_file = QFile(':/qtwebchannel/qwebchannel.js')
            if channel_file.open(QFile.OpenModeFlag.ReadOnly):
                channel_source = bytes(channel_file.readAll()).decode('utf-8')
                channel_file.close()
                channel_script = QWebEngineScript()
                channel_script.setName('tabby-desktop-clipboard-channel')
                channel_script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
                channel_script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
                channel_script.setSourceCode(channel_source + "\nnew QWebChannel(qt.webChannelTransport, channel => { window.__tabbyClipboard = channel.objects.desktopClipboard; });")
                page.scripts().insert(channel_script)
            script = QWebEngineScript()
            script.setName('tabby-desktop-mode')
            script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
            script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
            script.setSourceCode('window.__TABBY_DESKTOP__ = true;')
            page.scripts().insert(script)
            account_script = QWebEngineScript()
            account_script.setName('tabby-account-context')
            account_script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
            account_script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
            account_script.setSourceCode('window.__TABBY_ACCOUNT__ = ' + json.dumps(self.active_address.lower()) + ';')
            page.scripts().insert(account_script)
            self.web.loadFinished.connect(self.shop_loaded)
            self.shop_layout.addWidget(self.web)
            self.web.load(url)
            self._shop_started = True
        except Exception as exc:
            self.shop_layout.addWidget(QLabel(f'商城启动失败：{type(exc).__name__}: {exc}'))

    def make_handler(self):
        window = self
        class DesktopHandler(shop.Handler):
            def do_GET(self):
                # Expose only UI and known API routes, never desktop sources,
                # local credential files, or the game package over HTTP.
                allowed = {'/', '/index.html', '/api/shop', '/api/monitor/state',
                           '/api/monitor/products', '/api/wallet/status'}
                if self.path == '/config.local.json':
                    self._send_json(200, {})
                elif self.path in allowed:
                    super().do_GET()
                else:
                    self.send_error(404)
            def do_POST(self):
                if self.path in {'/api/wallet/import', '/api/wallet/clear'}:
                    self.send_error(404)
                    return
                watched = self.path in {'/api/monitor/config', '/api/monitor/start', '/api/monitor/stop'}
                super().do_POST()
                if watched:
                    window.save_active_shop_profile()
        return DesktopHandler

    def shop_loaded(self, ok):
        self._loaded = ok
        if ok:
            self.sync_shop_token()

    def closeEvent(self, event):
        self._closing = True
        self._ui_watchdog.stop()
        self._account_refresh_timer.stop()
        sessions = list({id(game): game for game in self._game_sessions.values()}.values())
        if not sessions:
            sessions = [self.game]
        for game in sessions:
            game.minimap_timer.stop()
            game.disconnect_ws()
        # Do not leave a monitor operating after the application window closes.
        shop.MONITOR.stop()
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.web:
            self.web.stop()
        for game in sessions:
            game.close()
            game._vault_passphrase = None
        self._master_passphrase = None
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName('Tabby Desktop')
    app.setWindowIcon(QIcon(str(BASE_DIR / 'assets' / 'tabby-logo.png')))
    window = DesktopWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    import multiprocessing
    multiprocessing.freeze_support()
    main()
