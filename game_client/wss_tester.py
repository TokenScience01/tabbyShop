from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections import deque
import math
import os
from pathlib import Path
import re
import socket
import ssl
import struct
import threading
import time
import urllib.parse
import urllib.error
import urllib.request
from datetime import datetime, timezone

from town_navigation import find_map_path, find_town_path
from minimap import TacticalMap

from PySide6.QtCore import QObject, Signal, Qt, QTimer, QSettings, QSize
from PySide6.QtGui import QColor, QIcon, QPixmap
from credential_vault import CredentialVault
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QProgressBar,
    QTabWidget,
    QAbstractItemView,
    QHeaderView,
    QSpinBox,
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QInputDialog,
    QPushButton,
    QPlainTextEdit,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QSizePolicy,
)


class WsError(Exception):
    pass


class MiniWebSocket:
    """Small diagnostic WebSocket client; sends masked client frames per RFC 6455."""

    def __init__(self, url: str, headers: dict[str, str], subprotocols: list[str]):
        self.url = url
        self.headers = headers
        self.subprotocols = subprotocols
        self.sock: socket.socket | ssl.SSLSocket | None = None
        self._send_lock = threading.Lock()
        self.close_code: int | None = None
        self.close_reason = ""
        self.status_line = ""
        self.response_headers: dict[str, str] = {}
        self.selected_protocol = ""

    def connect(self) -> None:
        parsed = urllib.parse.urlsplit(self.url)
        if parsed.scheme not in ("ws", "wss") or not parsed.hostname:
            raise WsError("地址必须是 ws:// 或 wss://，并包含主机名。")
        if parsed.username or parsed.password:
            raise WsError("请勿把凭证放在 URL 用户名或密码中。")
        port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        host = parsed.hostname
        raw = socket.create_connection((host, port), timeout=12)
        if parsed.scheme == "wss":
            ctx = ssl.create_default_context()
            self.sock = ctx.wrap_socket(raw, server_hostname=host)
        else:
            self.sock = raw
        self.sock.settimeout(12)

        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        host_header = host if port in (80, 443) else f"{host}:{port}"
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host_header}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
        ]
        if self.subprotocols:
            lines.append("Sec-WebSocket-Protocol: " + ", ".join(self.subprotocols))
        for name, value in self.headers.items():
            if "\r" in name + value or "\n" in name + value:
                raise WsError("请求头中不能包含换行符。")
            lines.append(f"{name}: {value}")
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("utf-8"))

        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = self.sock.recv(1)
            if not chunk:
                raise WsError("服务端在返回 HTTP 握手响应前关闭了 TCP/TLS 连接。")
            response += chunk
            if len(response) > 65536:
                raise WsError("握手响应头超过 64 KB。")
        head = bytes(response).split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", "replace")
        rows = head.split("\r\n")
        self.status_line = rows[0]
        for row in rows[1:]:
            if ":" in row:
                k, v = row.split(":", 1)
                self.response_headers[k.strip().lower()] = v.strip()
        if not rows[0].startswith("HTTP/1.1 101") and not rows[0].startswith("HTTP/1.0 101"):
            raise WsError("WebSocket 握手被拒绝：" + rows[0])
        expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        if self.response_headers.get("sec-websocket-accept") != expected:
            raise WsError("握手返回 101，但 Sec-WebSocket-Accept 校验失败。")
        self.selected_protocol = self.response_headers.get("sec-websocket-protocol", "")
        self.sock.settimeout(None)

    def _read_exact(self, n: int) -> bytes:
        assert self.sock is not None
        out = bytearray()
        while len(out) < n:
            part = self.sock.recv(n - len(out))
            if not part:
                raise EOFError("对端关闭了底层连接（未收到 WebSocket close 帧）。")
            out.extend(part)
        return bytes(out)

    def _send_frame(self, opcode: int, payload: bytes = b"") -> None:
        if self.sock is None:
            raise WsError("尚未连接。")
        first = 0x80 | (opcode & 0x0F)
        n = len(payload)
        if n < 126:
            header = bytes([first, 0x80 | n])
        elif n < 65536:
            header = bytes([first, 0x80 | 126]) + struct.pack("!H", n)
        else:
            header = bytes([first, 0x80 | 127]) + struct.pack("!Q", n)
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        with self._send_lock:
            self.sock.sendall(header + mask + masked)

    def send_text(self, text: str) -> None:
        self._send_frame(1, text.encode("utf-8"))

    def recv_message(self) -> tuple[int, bytes]:
        fragments = bytearray()
        message_opcode = 0
        while True:
            first, second = self._read_exact(2)
            fin = bool(first & 0x80)
            opcode = first & 0x0F
            masked = bool(second & 0x80)
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read_exact(8))[0]
            mask = self._read_exact(4) if masked else b""
            payload = self._read_exact(length) if length else b""
            if masked:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == 8:
                if len(payload) >= 2:
                    self.close_code = struct.unpack("!H", payload[:2])[0]
                    self.close_reason = payload[2:].decode("utf-8", "replace")
                else:
                    self.close_code = 1005
                try:
                    self._send_frame(8, payload)
                except OSError:
                    pass
                raise EOFError("对端发送 WebSocket close 帧。")
            if opcode == 9:
                self._send_frame(10, payload)
                continue
            if opcode == 10:
                continue
            if opcode in (1, 2):
                message_opcode = opcode
                fragments.extend(payload)
            elif opcode == 0:
                fragments.extend(payload)
            else:
                continue
            if fin:
                return message_opcode, bytes(fragments)

    def close(self) -> None:
        if self.sock is not None:
            try:
                self._send_frame(8, struct.pack("!H", 1000))
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


class Bridge(QObject):
    log = Signal(str)
    state = Signal(str)
    connected = Signal(object)
    connect_failed = Signal()
    packet = Signal(object)
    profile = Signal(object)
    signed_login = Signal(object)
    sign_challenge = Signal(object)
    keyring_status = Signal(str)
    notification_result = Signal(str, bool, str)
    shop_notification = Signal(str, str, str)


MAP_NAMES = {1: "Tabby Island · 主城", 2: "Northern Snowfield · 北部雪地",
             3: "Stone Valley · 石谷", 4: "Western Wilds · 西部荒野",
             5: "Abandoned Ruins · 废弃遗迹", 6: "Southern Forest · 南部森林"}
MAP_ROUTES = {1: (2, 4, 5, 6), 2: (1,), 3: (6,),
              4: (1,), 5: (1,), 6: (1, 3)}
CHARACTER_NAMES_ZH = {"WARRIOR": "战士", "GUARD": "守卫", "LANCER": "枪兵", "ARCHER": "弓手"}
# Names mirrored from the game's bundled resources/localization/names_zh.gd.
MONSTER_NAMES_ZH = {
    "skeleton": "骷髅怪", "elite_skeleton": "精英骷髅怪",
    "neiro_pump": "南瓜首领",
}
SLOT_NAMES_ZH = {"WEAPON": "武器", "HAT": "头盔", "ARMOR": "护甲", "SHOES": "鞋子",
                 "RING": "戒指", "AMULET": "护符", "OTHER": "消耗品"}
QUALITY_NAMES_ZH = {"COMMON": "普通", "NORMAL": "普通", "UNCOMMON": "优秀", "RARE": "稀有",
                    "EPIC": "史诗", "LEGENDARY": "传说",
                    "L1": "普通", "L2": "稀有", "L3": "史诗", "L4": "传说"}
QUALITY_COLORS = {"L1": "#f2f2ef", "L2": "#69b3ff", "L3": "#c994ff", "L4": "#ffcf72",
                  "COMMON": "#f2f2ef", "NORMAL": "#f2f2ef", "UNCOMMON": "#69b3ff",
                  "RARE": "#69b3ff", "EPIC": "#c994ff", "LEGENDARY": "#ffcf72"}
NEARBY_PLAYER_TTL_SECONDS = 8.0


def equipment_icon(item: dict) -> QIcon:
    """Return the matching extracted game sprite for an equipment item."""
    code = str(item.get("itemCode", "")).lower()
    slot = str(item.get("slotType", "")).upper()
    stem = next((candidate for candidate in ("sword", "helmet", "armor", "boots", "shoes", "ring", "amulet")
                 if candidate in code), "")
    if not stem:
        stem = {"WEAPON": "sword", "HAT": "helmet", "ARMOR": "armor", "SHOES": "boots",
                "RING": "ring", "AMULET": "amulet"}.get(slot, "")
    if stem == "shoes":
        stem = "boots"
    if "spear" in code:
        stem = "sword"  # The extracted game pack has no separate spear icon.
    try:
        level = item.get("equipmentLevel")
        if level is None:
            match = re.search(r"P([1-6])$", code.upper())
            level = match.group(1) if match else 1
        level = min(2, max(1, int(level or 1)))
    except (TypeError, ValueError):
        level = 1
    path = Path(__file__).with_name("assets") / f"{stem}_p{level}.webp" if stem else None
    return QIcon(str(path)) if path and path.is_file() else QIcon()


def quality_color(value: object) -> str:
    return QUALITY_COLORS.get(str(value or "").upper(), "#d5dccd")
try:
    _item_name_rows = json.loads((Path(__file__).with_name("assets") / "item_names_zh.json").read_text(encoding="utf-8"))
except (OSError, ValueError):
    _item_name_rows = []
ITEM_NAMES_ZH = {str(row.get("itemCode", "")).upper(): row.get("nameZh", "")
                 for row in _item_name_rows if isinstance(row, dict)}
ITEM_NAMES_ZH.update({str(row.get("nameEn", "")).casefold(): row.get("nameZh", "")
                      for row in _item_name_rows if isinstance(row, dict)})
_COMPACT_EN_ITEM_NAMES_ZH = {
    re.sub(r"[^A-Z0-9]", "", str(row.get("nameEn", "")).upper()): row.get("nameZh", "")
    for row in _item_name_rows if isinstance(row, dict) and row.get("nameEn")
}
def localized_item_name(item: dict) -> str:
    for key in ("nameZh", "displayNameZh"):
        value = item.get(key)
        if value:
            return str(value)
    code = str(item.get("itemCode", "")).strip().upper()
    name = str(item.get("name") or item.get("displayName") or item.get("nameEn") or "")
    normalized_name = re.sub(r"\s+", " ", name).strip().casefold()
    code_key = re.sub(r"[^A-Z0-9]", "", code)
    name_key = re.sub(r"[^A-Z0-9]", "", name.strip().upper())
    mapped = (ITEM_NAMES_ZH.get(code) or ITEM_NAMES_ZH.get(code_key)
              or ITEM_NAMES_ZH.get(normalized_name)
              or ITEM_NAMES_ZH.get(name.strip().casefold())
              or ITEM_NAMES_ZH.get(name_key)
              or _COMPACT_EN_ITEM_NAMES_ZH.get(name_key))
    if mapped:
        return str(mapped)
    aliases = {"HEALTH_POTION": "生命药水", "HEALTHPOTION": "生命药水", "POTION": "生命药水",
               "BOSS_ENTRY_TICKET": "遗迹入场券", "BOSSENTRYTICKET": "遗迹入场券",
               "TOWN_STONE": "回城石", "TOWNSTONE": "回城石",
               "ATONEMENT_STONE": "赎罪石", "ATONEMENTSTONE": "赎罪石"}
    compact_code = re.sub(r"[^A-Z0-9]", "", code)
    if code in aliases or compact_code in aliases:
        return aliases.get(code) or aliases[compact_code]
    mapped = ITEM_NAMES_ZH.get(compact_code)
    if mapped:
        return str(mapped)
    # Do not leak raw database keys like STARTER_AMULET into the UI. Keep the
    # original record available in the row tooltip for diagnosis instead.
    raw_label = name or code
    if re.search(r"[A-Za-z]", raw_label.strip()):
        slot = SLOT_NAMES_ZH.get(str(item.get("slotType", "")).upper())
        return f"未收录{slot}" if slot and slot != "消耗品" else "未收录物品"
    return str(raw_label or "物品")


_ITEM_ATTRIBUTE_NAMES_ZH = {
    "ATTACK": "攻击", "DEFENSE": "防御", "HEALTH": "生命", "MAX_HEALTH": "生命",
    "HEALTH_REGEN": "生命恢复", "ATTACK_SPEED": "攻击速度", "ATTACK_SPEED_PERCENT": "攻击速度",
    "MOVE_SPEED": "移动速度", "MOVE_SPEED_PERCENT": "移动速度", "CRITICAL": "暴击",
    "CRITICAL_CHANCE": "暴击率", "CRITICAL_CHANCE_PERCENT": "暴击率", "LUCK": "幸运",
}


def equipment_attribute_lines(item: dict) -> list[str]:
    """Format the stat fields used by the game's equipment panel."""
    lines: list[str] = []
    attributes = item.get("attributes", [])
    if isinstance(attributes, list):
        for attribute in attributes:
            if not isinstance(attribute, dict):
                continue
            code = str(attribute.get("code", "")).upper()
            name = str(attribute.get("displayNameZh") or _ITEM_ATTRIBUTE_NAMES_ZH.get(code)
                       or attribute.get("displayName") or code or "属性")
            value = attribute.get("value", 0)
            suffix = "/秒" if code == "HEALTH_REGEN" else (
                "%" if attribute.get("percentage") or code in {"LUCK", "CRITICAL_CHANCE", "CRITICAL_CHANCE_PERCENT",
                                                                  "ATTACK_SPEED", "ATTACK_SPEED_PERCENT",
                                                                  "MOVE_SPEED", "MOVE_SPEED_PERCENT"} else "")
            try:
                number = float(value)
                shown = str(int(number)) if number.is_integer() else f"{number:g}"
            except (TypeError, ValueError):
                shown = str(value)
            lines.append(f"{name} +{shown}{suffix}")
    # Some API payloads expose rolled stats only as top-level fields, or mix
    # top-level values with the rolled-attribute array.
    if not lines:
        for key, name, suffix in (
            ("attack", "攻击", ""), ("defense", "防御", ""), ("maxHealth", "生命", ""),
            ("healthRegen", "生命恢复", "/秒"), ("attackSpeedPercent", "攻击速度", "%"),
            ("moveSpeedPercent", "移动速度", "%"), ("criticalChancePercent", "暴击率", "%"),
            ("luck", "幸运", "%"),
        ):
            try:
                value = float(item.get(key, 0) or 0)
            except (TypeError, ValueError):
                continue
            if value:
                shown = str(int(value)) if value.is_integer() else f"{value:g}"
                lines.append(f"{name} +{shown}{suffix}")
    return lines or ["暂无额外属性"]


def localized_monster_name(monster: dict) -> str:
    for key in ("nameZh", "monsterNameZh", "displayNameZh"):
        value = monster.get(key)
        if value:
            return str(value)
    candidates = (monster.get("monsterKey"), monster.get("name"), monster.get("displayName"))
    for candidate in candidates:
        if not candidate:
            continue
        normalized = str(candidate).strip().casefold().replace(" ", "_").replace("-", "_")
        normalized = normalized.removeprefix("monster.")
        if normalized == "skeleton" and str(monster.get("monsterRank", "")).upper() == "ELITE":
            normalized = "elite_skeleton"
        if normalized in MONSTER_NAMES_ZH:
            return MONSTER_NAMES_ZH[normalized]
    return str(monster.get("name") or monster.get("displayName") or monster.get("monsterKey") or "怪物")


PORTAL_CENTERS = {
    (1, 2): (928, -224), (1, 4): (-544, 928),
    (1, 5): (2464, 928), (1, 6): (928, 1952),
    (2, 1): (3872, 7616), (3, 6): (608, 608),
    (4, 1): (9136, 1568), (5, 1): (48, 2528),
    (6, 1): (3872, 96), (6, 3): (7264, 4320),
}

KEYRING_SERVICE = "Tabby Desktop"
KEYRING_ACCOUNT = "game-wallet-private-key"


def secure_keyring():
    """Return an OS credential-store backend; refuse plaintext keyrings."""
    import keyring

    backend = keyring.get_keyring()
    module = type(backend).__module__
    secure_modules = (
        "keyring.backends.macOS", "keyring.backends.Windows",
        "keyring.backends.SecretService", "keyring.backends.kwallet",
    )
    if backend.priority <= 0 or not module.startswith(secure_modules):
        raise RuntimeError("系统安全钥匙串不可用，拒绝将私钥保存到普通文件")
    return keyring


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Tabby · 探索控制台")
        self.resize(1100, 1040)
        self.setMinimumSize(720, 850)
        self.bridge = Bridge()
        self.bridge.log.connect(self.append_log)
        self.bridge.state.connect(self.set_state)
        self.bridge.connected.connect(self.on_connected)
        self.bridge.connect_failed.connect(self.on_connect_failed)
        self.bridge.packet.connect(self.accept_packet)
        self.bridge.profile.connect(self.accept_profile_data)
        self.bridge.signed_login.connect(self.finish_signed_login)
        self.bridge.sign_challenge.connect(self.confirm_sign_challenge)
        self.bridge.notification_result.connect(self.on_notification_result)
        self.bridge.shop_notification.connect(self.on_shop_notification)
        self.ws: MiniWebSocket | None = None
        self.reader: threading.Thread | None = None
        self.session_token = ""
        self.signed_session_token = ""
        self._resolved_token = ""
        self.credential_vault = CredentialVault()
        self._vault_passphrase: str | None = None
        self.manual_disconnect = False
        self._auto_reconnect_login = False
        self._reconnect_attempt = 0
        self.last_pong_received_at = 0.0
        self.auth_rejected = False
        self._auth_retry_attempted = False
        self.settings = QSettings("Tabby", "TabbyDesktop")
        self._fatigue_exhaustion_handled = False
        self._quest_notification_state = None
        self._known_equipment_ids = None
        self.reset_world_state()
        self.keepalive = QTimer(self)
        self.keepalive.setInterval(2000)
        self.keepalive.timeout.connect(self.send_keepalive)
        self.position_sync_timer = QTimer(self)
        self.position_sync_timer.setInterval(250)
        self.position_sync_timer.timeout.connect(self.send_stationary_sync)
        self.move_timer = QTimer(self)
        self.move_timer.setInterval(66)
        self.move_timer.setTimerType(Qt.TimerType.PreciseTimer)
        self.move_timer.timeout.connect(self.advance_to_portal)
        self.combat_timer = QTimer(self)
        self.combat_timer.setInterval(350)
        self.combat_timer.timeout.connect(self.auto_attack_tick)
        self.potion_timer = QTimer(self)
        self.potion_timer.setInterval(1000)
        self.potion_timer.timeout.connect(self.try_auto_use_potion)
        self.chase_timer = QTimer(self)
        self.chase_timer.setInterval(66)
        self.chase_timer.setTimerType(Qt.TimerType.PreciseTimer)
        self.chase_timer.timeout.connect(self.advance_chase)
        self.patrol_timer = QTimer(self)
        self.patrol_timer.setInterval(66)
        self.patrol_timer.setTimerType(Qt.TimerType.PreciseTimer)
        self.patrol_timer.timeout.connect(self.advance_patrol)
        self.reconnect_timer = QTimer(self)
        self.reconnect_timer.setSingleShot(True)
        self.reconnect_timer.timeout.connect(self.retry_connection)
        self.connection_stable_timer = QTimer(self)
        self.connection_stable_timer.setSingleShot(True)
        self.connection_stable_timer.setInterval(30000)
        self.connection_stable_timer.timeout.connect(self.reset_reconnect_backoff)
        self.telemetry_timer = QTimer(self)
        self.telemetry_timer.setInterval(300)
        self.telemetry_timer.timeout.connect(self.update_live_telemetry)

        root = QWidget()
        root.setObjectName("root")
        root.setMinimumHeight(930)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(24, 22, 24, 22)
        outer.setSpacing(16)

        heading = QVBoxLayout()
        heading.setSpacing(4)
        title = QLabel("TABBY  /  探索控制台")
        title.setObjectName("title")
        subtitle = QLabel("实时地图 · 角色状态 · 任务与战斗")
        subtitle.setObjectName("subtitle")
        heading.addWidget(title)
        heading.addWidget(subtitle)
        outer.addLayout(heading)

        connection_card = QFrame()
        connection_card.setObjectName("card")
        card_layout = QVBoxLayout(connection_card)
        card_layout.setContentsMargins(20, 18, 20, 18)
        card_layout.setSpacing(12)
        card_title = QLabel("开始探索")
        card_title.setObjectName("sectionTitle")
        card_layout.addWidget(card_title)
        url_label = QLabel("WebSocket URL")
        url_label.setObjectName("fieldLabel")
        card_layout.addWidget(url_label)
        self.url = QLineEdit("wss://game.tabby.meme/api/realtime")
        self.url.setObjectName("urlInput")
        self.url.setMinimumHeight(40)
        self.url.setToolTip(self.url.text())
        self.url.textChanged.connect(self.url.setToolTip)
        card_layout.addWidget(self.url)

        fields = QGridLayout()
        fields.setContentsMargins(0, 0, 0, 0)
        fields.setHorizontalSpacing(14)
        fields.setVerticalSpacing(7)
        self.origin = QLineEdit("https://game.tabby.meme")
        self.origin.setMinimumHeight(38)
        self.token = QLineEdit()
        self.token.setMinimumHeight(38)
        self.token.setEchoMode(QLineEdit.EchoMode.Password)
        self.token.setPlaceholderText("仅粘贴游戏会话 Token；钱包私钥请用私钥登录方式")
        self.auth_method = QComboBox()
        self.auth_method.addItem("BSC 私钥签名", "private_key")
        self.auth_method.addItem("Token 登录", "token")
        self.auth_method.setToolTip("私钥仅在本机用于签名，不会发送给服务器；记住时会用独立主密码加密分片保存。")
        self.private_key = QLineEdit()
        self.private_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.private_key.setPlaceholderText("输入 EVM 私钥（BSC / chainId 56）；记住时用主密码加密分片")
        self.private_key.textEdited.connect(self.on_private_key_edited)
        self.saved_wallet_label = QLabel("已保存钱包地址")
        self.saved_wallet_label.setObjectName("fieldLabel")
        self.saved_wallet = QComboBox()
        self.saved_wallet.setMinimumHeight(38)
        self.saved_wallet.addItem("输入新的私钥", "")
        self.saved_wallet.currentIndexChanged.connect(self.on_saved_wallet_selected)
        self.private_key_label = QLabel("钱包私钥（本机签名）")
        self.private_key_label.setObjectName("fieldLabel")
        origin_label = QLabel("Origin")
        token_label = QLabel("游戏会话 Token（不要粘贴钱包私钥）")
        for label in (origin_label, token_label):
            label.setObjectName("fieldLabel")
        fields.addWidget(origin_label, 0, 0)
        fields.addWidget(token_label, 0, 1)
        fields.addWidget(self.origin, 1, 0)
        fields.addWidget(self.token, 1, 1)
        fields.addWidget(self.saved_wallet_label, 2, 0, 1, 2)
        fields.addWidget(self.saved_wallet, 3, 0, 1, 2)
        fields.addWidget(self.private_key_label, 4, 0, 1, 2)
        fields.addWidget(self.private_key, 5, 0, 1, 2)
        self.refresh_saved_wallets()
        fields.setColumnStretch(0, 1)
        fields.setColumnStretch(1, 1)
        card_layout.addLayout(fields)
        card_layout.addWidget(self.auth_method)
        self.auto_auth = QCheckBox("连接成功后发送客户端登录帧")
        self.auto_auth.setChecked(True)
        self.auto_auth.setToolTip("按发布客户端的 pvp_client.gd 发送完整位置认证帧。")
        card_layout.addWidget(self.auto_auth)
        self.auto_reconnect = QCheckBox("断线后自动重连")
        self.auto_reconnect.setChecked(self.settings.value("autoReconnect", True, type=bool))
        self.auto_reconnect.setToolTip("手动断开除外。启用钱包记忆后，重连时可自动刷新签名会话。")
        self.auto_reconnect.toggled.connect(lambda checked: self.settings.setValue("autoReconnect", checked))
        card_layout.addWidget(self.auto_reconnect)
        self.remember_private_key = QCheckBox("记住私钥（主密码加密 + 三片分开保存）")
        self.remember_private_key.setChecked(self.settings.value("rememberPrivateKey", False, type=bool))
        self.remember_private_key.setToolTip(
            "登录成功后用你设置的主密码进行 AES-GCM 加密，并将密文拆成三片保存。"
            "主密码不会保存；读取时需要输入。取消勾选会删除三片数据。"
        )
        self.remember_private_key.toggled.connect(self.on_remember_private_key_toggled)
        card_layout.addWidget(self.remember_private_key)

        self.advanced_button = QPushButton("高级设置")
        self.advanced_button.setObjectName("quietButton")
        self.advanced_button.setAccessibleName("打开高级握手选项")
        card_layout.addWidget(self.advanced_button, 0, Qt.AlignmentFlag.AlignLeft)

        self.advanced_dialog = QDialog(self)
        self.advanced_dialog.setWindowTitle("高级握手选项")
        self.advanced_dialog.setMinimumWidth(480)
        advanced_layout = QVBoxLayout(self.advanced_dialog)
        advanced_layout.setContentsMargins(22, 20, 22, 20)
        advanced_layout.setSpacing(10)
        # Keep endpoint configuration available without crowding the main UI.
        advanced_layout.addWidget(url_label)
        advanced_layout.addWidget(self.url)
        advanced_layout.addWidget(origin_label)
        advanced_layout.addWidget(self.origin)
        advanced_layout.addWidget(self.auto_auth)
        fields.removeWidget(token_label)
        fields.removeWidget(self.token)
        fields.addWidget(token_label, 0, 0, 1, 2)
        fields.addWidget(self.token, 1, 0, 1, 2)
        protocols_label = QLabel("子协议")
        protocols_label.setObjectName("fieldLabel")
        advanced_layout.addWidget(protocols_label)
        self.protocols = QLineEdit()
        self.protocols.setPlaceholderText("可留空；多个值用逗号分隔")
        advanced_layout.addWidget(self.protocols)
        headers_label = QLabel("附加请求头")
        headers_label.setObjectName("fieldLabel")
        advanced_layout.addWidget(headers_label)
        self.extra_headers = QPlainTextEdit()
        self.extra_headers.setPlaceholderText("每行一个请求头，例如 X-Debug: 1")
        self.extra_headers.setFixedHeight(70)
        advanced_layout.addWidget(self.extra_headers)
        self.send_auth_header = QCheckBox("握手时附加 Authorization: Bearer")
        self.send_auth_header.setChecked(False)
        advanced_layout.addWidget(self.send_auth_header)
        auth_template_label = QLabel("客户端登录帧（token 自动注入）")
        auth_template_label.setObjectName("fieldLabel")
        advanced_layout.addWidget(auth_template_label)
        self.auth_template = QPlainTextEdit()
        self.auth_template.setObjectName("messageInput")
        self.auth_template.setFixedHeight(200)
        self.auth_template.setPlainText(json.dumps({
            "action": "auth",
            "movementRevision": 0,
            "map": 1,
            "x": 544.0,
            "y": 352.0,
            "animation": "idle",
            "attackCritical": False,
            "flip": False,
            "loginReset": True,
            "snapshotDelta": 2,
        }, ensure_ascii=False, indent=2))
        advanced_layout.addWidget(self.auth_template)
        advanced_hint = QLabel("位置是客户端初始出生点之一；如需模拟当前角色位置，请修改 map、x、y。原客户端不在握手头附加 Bearer。")
        advanced_hint.setObjectName("subtitle")
        advanced_hint.setWordWrap(True)
        advanced_layout.addWidget(advanced_hint)
        advanced_close = QPushButton("完成")
        advanced_close.setObjectName("primaryButton")
        advanced_close.clicked.connect(self.advanced_dialog.accept)
        advanced_layout.addWidget(advanced_close, 0, Qt.AlignmentFlag.AlignRight)
        self.advanced_button.clicked.connect(self.advanced_dialog.open)
        self.auth_method.currentIndexChanged.connect(self.update_auth_fields)
        self.update_auth_fields()

        controls = QHBoxLayout()
        controls.setContentsMargins(0, 4, 0, 0)
        controls.setSpacing(10)
        self.connect_button = QPushButton("连接")
        self.connect_button.setObjectName("primaryButton")
        self.disconnect_button = QPushButton("断开")
        self.disconnect_button.setObjectName("secondaryButton")
        self.disconnect_button.setEnabled(False)
        controls.addWidget(self.connect_button)
        controls.addWidget(self.disconnect_button)
        controls.addWidget(self.advanced_button)
        controls.addStretch(1)
        card_layout.addLayout(controls)
        outer.addWidget(connection_card)

        session_card = QFrame()
        session_card.setObjectName("sessionCard")
        session_layout = QVBoxLayout(session_card)
        session_layout.setContentsMargins(17, 12, 17, 12)
        session_layout.setSpacing(4)
        session_top = QHBoxLayout()
        session_title = QLabel("最近连接")
        session_title.setObjectName("fieldLabel")
        session_top.addWidget(session_title)
        session_top.addStretch(1)
        self.status = QLabel("未连接")
        self.status.setObjectName("status")
        self.status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        session_top.addWidget(self.status)
        session_layout.addLayout(session_top)
        self.active_url = QLabel("尚无活动连接")
        self.active_url.setObjectName("sessionUrl")
        self.active_url.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.active_url.setToolTip("当前或最近一次连接使用的完整 WebSocket URL")
        self.active_url.setWordWrap(True)
        self.active_url.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        session_layout.addWidget(self.active_url)
        outer.addWidget(session_card)
        session_card.hide()
        controls.addWidget(self.status)

        character_card = QFrame()
        character_card.setObjectName("card")
        character_layout = QVBoxLayout(character_card)
        character_layout.setContentsMargins(20, 15, 20, 16)
        character_layout.setSpacing(8)
        character_title = QLabel("角色信息")
        character_title.setObjectName("sectionTitle")
        character_layout.addWidget(character_title)
        self.character_status = QLabel("等待服务端角色快照…")
        self.character_status.setObjectName("subtitle")
        self.character_status.setWordWrap(True)
        character_layout.addWidget(self.character_status)
        outer.addWidget(character_card)
        map_card = QFrame()
        map_card.setObjectName("card")
        map_layout = QVBoxLayout(map_card)
        map_layout.setContentsMargins(18, 16, 18, 16)
        map_heading = QHBoxLayout()
        map_title = QLabel("实时小地图")
        map_title.setObjectName("sectionTitle")
        map_heading.addWidget(map_title)
        map_heading.addStretch()
        legend = QLabel("青色 · 角色    浅蓝 · 玩家    粉色 · 怪物    金色 · 精英    蓝色 · 入口")
        legend.setObjectName("subtitle")
        legend.setWordWrap(True)
        legend.setMinimumWidth(360)
        map_heading.addWidget(legend)
        map_layout.addLayout(map_heading)
        self.minimap = TacticalMap(self, PORTAL_CENTERS)
        map_layout.addWidget(self.minimap)
        self.map_activity = QLabel("等待连接")
        self.map_activity.setObjectName("subtitle")
        self.map_activity.setWordWrap(True)
        map_layout.addWidget(self.map_activity)
        outer.addWidget(map_card)
        self.minimap_timer = QTimer(self)
        self.minimap_timer.setInterval(200)
        self.minimap_timer.timeout.connect(self.refresh_minimap)
        self.minimap_timer.start()
        self.api_profile = {}
        self.api_equipment = {}
        self.last_progress_state = {}
        self.last_self_state = {}
        self.latest_quests = []
        self.quest_map_target = None
        self.quest_map_quest_id = None
        self.last_quest_map = None
        self.questless_farm_mode = False
        self.questless_farm_target = None
        self.quest_accept_blocked_date = None
        self.quest_accept_inflight = False
        self.quest_accept_checked_at = 0.0
        self.profile_refresh_inflight = False
        self.profile_refreshed_at = 0.0
        self.profile_refresh_queued = False
        self.last_world_status_render_at = 0.0
        self.last_world_status_map = None
        self.balance_refreshed_at = 0.0

        travel_card = QFrame()
        travel_card.setObjectName("card")
        travel_layout = QVBoxLayout(travel_card)
        travel_layout.setContentsMargins(20, 16, 20, 18)
        travel_layout.setSpacing(10)
        travel_title = QLabel("地图切换")
        travel_title.setObjectName("sectionTitle")
        travel_layout.addWidget(travel_title)
        self.current_map_label = QLabel("等待进入地图")
        self.current_map_label.setObjectName("currentMapBadge")
        self.current_map_label.setTextFormat(Qt.TextFormat.PlainText)
        self.current_map_label.setWordWrap(True)
        travel_layout.addWidget(self.current_map_label)
        self.world_status = QLabel("等待登录游戏世界…")
        self.world_status.setObjectName("subtitle")
        travel_layout.addWidget(self.world_status)
        self.respawn_button = QPushButton("回到城镇")
        self.respawn_button.setObjectName("primaryButton")
        self.respawn_button.setVisible(False)
        self.respawn_button.clicked.connect(self.request_respawn)
        travel_layout.addWidget(self.respawn_button, 0, Qt.AlignmentFlag.AlignLeft)
        map_grid = QGridLayout()
        map_grid.setHorizontalSpacing(10)
        map_grid.setVerticalSpacing(10)
        self.map_buttons = {}
        for map_id, name in MAP_NAMES.items():
            button = QPushButton(f"{map_id}  {name}")
            button.setObjectName("secondaryButton")
            button.setMinimumHeight(42)
            button.clicked.connect(lambda checked=False, destination=map_id: self.travel_to(destination))
            map_grid.addWidget(button, (map_id - 1) // 2, (map_id - 1) % 2)
            self.map_buttons[map_id] = button
        travel_layout.addLayout(map_grid)
        options = QHBoxLayout()
        self.quest_id = QSpinBox()
        self.quest_id.setRange(0, 999999)
        self.quest_id.setValue(0)
        self.quest_id.setPrefix("任务 ID  ")
        self.quest_id.setToolTip("客户端 travel 帧的 questId；普通入图使用 0。")
        self.use_ticket = QCheckBox("使用入场券（遗迹）")
        self.stop_move_button = QPushButton("停止移动")
        self.stop_move_button.setObjectName("quietButton")
        self.stop_move_button.setEnabled(False)
        self.stop_move_button.clicked.connect(self.cancel_travel)
        options.addWidget(self.quest_id)
        options.addStretch(1)
        options.addWidget(self.stop_move_button)
        travel_layout.addLayout(options)
        entry_options = QHBoxLayout()
        entry_options.addWidget(self.use_ticket)
        ticket_hint = QLabel("仅进入废弃遗迹时需要")
        ticket_hint.setObjectName("subtitle")
        entry_options.addWidget(ticket_hint)
        entry_options.addStretch(1)
        travel_layout.addLayout(entry_options)
        return_options = QHBoxLayout()
        self.auto_return_map = QCheckBox("复活后自动进入")
        self.return_map = QComboBox()
        for map_id, name in MAP_NAMES.items():
            if map_id != 1:
                self.return_map.addItem(name, map_id)
        return_options.addWidget(self.auto_return_map)
        return_options.addWidget(self.return_map, 1)
        travel_layout.addLayout(return_options)
        self.auto_return_map.toggled.connect(self.on_return_map_changed)
        self.return_map.currentIndexChanged.connect(self.on_return_map_changed)
        self.travel_status = QLabel("点击地图会先同步到对应入口，再请求切图；服务端仍会校验移动和入口距离。")
        self.travel_status.setObjectName("subtitle")
        self.travel_status.setWordWrap(True)
        travel_layout.addWidget(self.travel_status)
        self.update_map_buttons()

        quest_card = QFrame()
        quest_card.setObjectName("card")
        quest_layout = QVBoxLayout(quest_card)
        quest_layout.setContentsMargins(20, 16, 20, 18)
        quest_layout.setSpacing(10)
        quest_title = QLabel("任务")
        quest_title.setObjectName("sectionTitle")
        quest_title_row = QHBoxLayout()
        quest_title_row.addWidget(quest_title)
        quest_title_row.addStretch(1)
        self.refresh_profile_button = QPushButton("刷新角色与任务")
        self.refresh_profile_button.setObjectName("quietButton")
        self.refresh_profile_button.clicked.connect(lambda: self.refresh_profile_data(force=True))
        self.auto_quest = QCheckBox("完成后自动接打怪任务")
        self.auto_quest.setChecked(True)
        self.auto_quest.setProperty("taskOption", True)
        self.auto_quest.setToolTip("当前打怪任务完成后领取下一项；是否自动攻击由左侧战斗开关控制。")
        self.task_limited_mode = QCheckBox("任务有限模式")
        self.task_limited_mode.setProperty("taskOption", True)
        self.task_limited_mode.setToolTip("与自动接任务配合使用：只打当前任务目标；暂时没有任务时暂停攻击，不转为自由刷怪。")
        self.task_limited_mode.toggled.connect(self.on_task_limited_mode_changed)
        self.quest_map_auto = QCheckBox("按任务地图自动进图")
        self.quest_map_auto.setProperty("taskOption", True)
        self.quest_map_auto.setToolTip("自动接取新任务后，沿地图入口路线前往该任务对应地图。遗迹仍需入场券。")
        self.quest_map_auto.stateChanged.connect(self.on_quest_map_auto_changed)
        self.use_ticket.stateChanged.connect(lambda *_: QTimer.singleShot(0, self.continue_quest_map_travel))
        quest_title_row.addWidget(self.refresh_profile_button)
        quest_layout.addLayout(quest_title_row)
        quest_mode_row = QHBoxLayout()
        quest_mode_row.setSpacing(20)
        quest_mode_row.addWidget(self.auto_quest)
        quest_mode_row.addWidget(self.task_limited_mode)
        quest_mode_row.addStretch(1)
        quest_layout.addLayout(quest_mode_row)
        quest_travel_row = QHBoxLayout()
        quest_travel_row.addWidget(self.quest_map_auto)
        quest_travel_row.addStretch(1)
        quest_layout.addLayout(quest_travel_row)
        self.quest_status = QLabel("等待服务端任务数据…")
        self.quest_status.setObjectName("subtitle")
        quest_layout.addWidget(self.quest_status)
        self.quest_table = QTableWidget(0, 5)
        self.quest_table.setHorizontalHeaderLabels(["ID", "任务", "地图", "进度", "状态"])
        self.quest_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.quest_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.quest_table.setAlternatingRowColors(True)
        self.quest_table.verticalHeader().setVisible(False)
        self.quest_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.quest_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.quest_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.quest_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.quest_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.quest_table.setMinimumHeight(145)
        self.quest_table.setMaximumHeight(260)
        quest_layout.addWidget(self.quest_table)

        combat_card = QFrame()
        combat_card.setObjectName("card")
        combat_layout = QVBoxLayout(combat_card)
        combat_layout.setContentsMargins(20, 16, 20, 18)
        combat_layout.setSpacing(10)
        combat_title = QLabel("怪物与战斗")
        combat_title.setObjectName("sectionTitle")
        combat_layout.addWidget(combat_title)
        self.combat_status = QLabel("等待服务端怪物快照和攻击票据…")
        self.combat_status.setObjectName("subtitle")
        self.combat_status.setWordWrap(True)
        combat_layout.addWidget(self.combat_status)
        combat_stats = QHBoxLayout()
        self.combat_stats_layout = combat_stats
        combat_stats.setSpacing(8)
        self.combat_stat_labels = {}
        self.combat_stat_cards = {}
        for key, title, asset in (("kills", "击败", "monster.webp"),
                                  ("damage", "伤害", "warrior-idle.webp"),
                                  ("hits", "命中", "quest.webp"),
                                  ("potions", "药水", "location.webp")):
            stat = QFrame()
            stat.setObjectName("statChip")
            stat_row = QHBoxLayout(stat)
            stat_row.setContentsMargins(8, 5, 8, 5)
            art = QLabel()
            art.setFixedSize(22, 22)
            pix = QPixmap(str(Path(__file__).with_name("assets") / asset))
            if not pix.isNull():
                art.setPixmap(pix.scaled(20, 20, Qt.AspectRatioMode.KeepAspectRatio,
                                         Qt.TransformationMode.SmoothTransformation))
            stat_row.addWidget(art)
            label = QLabel(f"{title} 0")
            label.setObjectName("subtitle")
            stat_row.addWidget(label)
            combat_stats.addWidget(stat, 1)
            self.combat_stat_labels[key] = label
            self.combat_stat_cards[key] = stat
        combat_layout.addLayout(combat_stats)
        self.monster_table = QTableWidget(0, 7)
        self.monster_table.setHorizontalHeaderLabels(["encounterId", "怪物", "等级", "品级", "生命", "坐标", "距离"])
        self.monster_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.monster_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.monster_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.monster_table.setAlternatingRowColors(True)
        self.monster_table.verticalHeader().setVisible(False)
        self.monster_table.setColumnHidden(0, True)
        for col in (1, 2, 3, 4, 5, 6):
            self.monster_table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        self.monster_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.monster_table.setMinimumHeight(145)
        self.monster_table.setMaximumHeight(245)
        self.monster_table.itemSelectionChanged.connect(self.update_attack_button)
        combat_layout.addWidget(self.monster_table)
        combat_controls = QHBoxLayout()
        self.attack_button = QPushButton("攻击选中怪物")
        self.attack_button.setObjectName("primaryButton")
        self.attack_button.clicked.connect(self.attack_selected_monster)
        self.auto_attack = QCheckBox("自动追击并攻击附近怪物")
        self.auto_attack.toggled.connect(self.toggle_auto_attack)
        self.auto_potion = QCheckBox("自动使用生命药水")
        self.auto_potion.setChecked(False)
        self.auto_potion.setToolTip("默认关闭。开启后仅在生命低于 50%、有药水且冷却结束时请求使用。")
        self.auto_potion.toggled.connect(self.on_auto_potion_changed)
        self.elite_only = QCheckBox("只打精英怪")
        self.elite_only.toggled.connect(self.on_elite_filter_changed)
        combat_controls.addWidget(self.attack_button)
        combat_controls.addWidget(self.auto_attack)
        combat_controls.addWidget(self.auto_potion)
        combat_controls.addWidget(self.elite_only)
        self.encounter_id_toggle = QPushButton("查看 encounterId")
        self.encounter_id_toggle.setCheckable(True)
        self.encounter_id_toggle.setToolTip("默认隐藏技术 ID；点击后显示怪物 encounterId 列。")
        self.encounter_id_toggle.toggled.connect(self.toggle_encounter_id_column)
        combat_controls.addWidget(self.encounter_id_toggle)
        combat_controls.addStretch(1)
        combat_layout.addLayout(combat_controls)
        level_controls = QHBoxLayout()
        self.monster_level_limited = QCheckBox("限制怪物等级")
        self.monster_level_limited.setToolTip("开启后，自动搜怪、追击和攻击都会仅选择等级范围内的怪物。")
        self.monster_level_min = QSpinBox()
        self.monster_level_min.setRange(1, 9999)
        self.monster_level_min.setPrefix("最低 ")
        self.monster_level_min.setToolTip("怪物等级下限（包含该等级）")
        self.monster_level_max = QSpinBox()
        self.monster_level_max.setRange(1, 9999)
        self.monster_level_max.setPrefix("最高 ")
        self.monster_level_max.setToolTip("怪物等级上限（包含该等级）")
        self.monster_level_limited.setChecked(
            self.settings.value("monsterLevelLimited", False, type=bool))
        self.monster_level_min.setValue(self.settings.value("monsterLevelMin", 1, type=int))
        self.monster_level_max.setValue(self.settings.value("monsterLevelMax", 9999, type=int))
        self.monster_level_min.setEnabled(self.monster_level_limited.isChecked())
        self.monster_level_max.setEnabled(self.monster_level_limited.isChecked())
        self.monster_level_limited.toggled.connect(self.on_monster_level_filter_changed)
        self.monster_level_min.valueChanged.connect(self.on_monster_level_bound_changed)
        self.monster_level_max.valueChanged.connect(self.on_monster_level_bound_changed)
        level_controls.addWidget(self.monster_level_limited)
        level_controls.addWidget(self.monster_level_min)
        level_controls.addWidget(self.monster_level_max)
        level_controls.addStretch(1)
        combat_layout.addLayout(level_controls)
        combat_hint = QLabel("自动模式会搜索并追击当前地图怪物；北部雪地暂无怪物时会沿已验证路线巡逻搜索。")
        combat_hint.setObjectName("subtitle")
        combat_layout.addWidget(combat_hint)
        outer.addWidget(combat_card)
        outer.addWidget(travel_card)
        outer.addWidget(quest_card)
        self.update_attack_button()

        content_layout = QVBoxLayout()
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(10)
        log_card = QFrame()
        log_card.setObjectName("card")
        log_layout = QVBoxLayout(log_card)
        log_layout.setContentsMargins(16, 14, 16, 16)
        log_layout.setSpacing(10)
        log_top = QHBoxLayout()
        log_title = QLabel("连接日志")
        log_title.setObjectName("sectionTitle")
        log_top.addWidget(log_title)
        log_top.addStretch(1)
        self.clear_button = QPushButton("清空日志")
        self.clear_button.setObjectName("quietButton")
        self.clear_button.clicked.connect(self.log_clear)
        log_top.addWidget(self.clear_button)
        log_layout.addLayout(log_top)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMinimumHeight(140)
        self.log.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.log.setObjectName("logView")
        self.log.setPlaceholderText("连接结果、握手响应、收发消息和关闭原因会显示在这里。Bearer token 会被隐藏。")
        log_layout.addWidget(self.log, 1)
        compose = QFrame()
        compose.setObjectName("card")
        compose.setMinimumHeight(175)
        compose.setMaximumHeight(190)
        compose_layout = QVBoxLayout(compose)
        compose_layout.setContentsMargins(16, 14, 16, 16)
        compose_layout.setSpacing(10)
        compose_title = QLabel("发送文本帧")
        compose_title.setObjectName("sectionTitle")
        compose_layout.addWidget(compose_title)
        self.message = QPlainTextEdit()
        self.message.setPlaceholderText('{"type":"ping"}')
        self.message.setObjectName("messageInput")
        self.message.setMinimumHeight(65)
        compose_layout.addWidget(self.message)
        send_row = QHBoxLayout()
        send_hint = QLabel("手动发送，不会自动重放")
        send_hint.setObjectName("subtitle")
        send_row.addWidget(send_hint)
        send_row.addStretch(1)
        self.send_button = QPushButton("发送文本帧")
        self.send_button.setObjectName("primaryButton")
        self.send_button.setEnabled(False)
        send_row.addWidget(self.send_button)
        compose_layout.addLayout(send_row)
        content_layout.addWidget(log_card, 1)
        content_layout.addWidget(compose, 0)
        diagnostics = QPushButton("查看连接日志与手动协议工具")
        diagnostics.setObjectName("quietButton")
        diagnostics.setCheckable(True)
        diagnostics.toggled.connect(log_card.setVisible)
        diagnostics.toggled.connect(compose.setVisible)
        outer.addWidget(diagnostics)
        log_card.hide()
        compose.hide()
        outer.addLayout(content_layout, 1)
        scroll = QScrollArea()
        scroll.setObjectName("mainScroll")
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidgetResizable(True)
        scroll.setWidget(root)
        self.setCentralWidget(scroll)
        self.apply_theme()
        self.advanced_dialog.setStyleSheet(self.styleSheet())

        self.connect_button.clicked.connect(self.connect_ws)
        self.disconnect_button.clicked.connect(self.disconnect_ws)
        self.send_button.clicked.connect(self.send_message)
        self.redesign_dashboard(root)

    def redesign_dashboard(self, old_root) -> None:
        """Arrange live game controls in a compact, three-zone workspace."""
        root = QWidget()
        root.setObjectName("root")
        layout = QVBoxLayout(root)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(14)

        def place(box, widget, stretch=0):
            widget.setParent(root)
            box.addWidget(widget, stretch)
            widget.show()

        def card(title):
            frame = QFrame(root)
            frame.setObjectName("card")
            box = QVBoxLayout(frame)
            box.setContentsMargins(16, 14, 16, 14)
            box.setSpacing(10)
            box.setAlignment(Qt.AlignmentFlag.AlignTop)
            label = QLabel(title)
            label.setObjectName("sectionTitle")
            box.addWidget(label)
            return frame, box

        header_widget = QWidget(root)
        self.dashboard_header = header_widget
        header = QHBoxLayout(header_widget)
        header.setContentsMargins(0, 0, 0, 0)
        brand = QLabel("探索控制台")
        brand.setObjectName("title")
        self.dashboard_title = brand
        header.addWidget(brand)
        header.addStretch()
        self.account_toggle = QPushButton("账号连接")
        self.account_toggle.setObjectName("quietButton")
        self.account_toggle.setCheckable(True)
        header.addWidget(self.account_toggle)
        self.connection_dot = QLabel()
        self.connection_dot.setFixedSize(10, 10)
        self.connection_dot.setStyleSheet("background:#dc5b57;border-radius:5px;")
        self.connection_dot.setToolTip("连接状态与网络延迟")
        header.addWidget(self.connection_dot)
        place(header, self.status)
        layout.addWidget(header_widget)
        connection = QFrame(root)
        connection.setObjectName("card")
        connect_row = QHBoxLayout(connection)
        connect_row.setContentsMargins(14, 12, 14, 12)
        connect_row.addWidget(QLabel("登录方式"))
        place(connect_row, self.auth_method)
        place(connect_row, self.token, 1)
        place(connect_row, self.private_key, 1)
        for widget in (self.connect_button, self.disconnect_button, self.advanced_button):
            place(connect_row, widget)
        layout.addWidget(connection)
        connection.hide()
        self.account_toggle.toggled.connect(connection.setVisible)
        self.update_auth_fields()

        columns = QHBoxLayout()
        columns.setSpacing(14)
        left = QVBoxLayout()
        left.setContentsMargins(0, 0, 0, 0)
        left.setSpacing(14)
        left_panel = QWidget(root)
        left_panel.setLayout(left)
        left_panel.setFixedWidth(345)
        left_panel.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)
        columns.addWidget(left_panel, 0, Qt.AlignmentFlag.AlignTop)
        right = QVBoxLayout()
        right.setSpacing(14)
        columns.addLayout(right, 1)
        layout.addLayout(columns, 1)

        character, box = card("角色概览")
        self.character_card = character
        character_row = QHBoxLayout()
        portrait = QLabel()
        self.character_portrait = portrait
        portrait.setFixedSize(82, 108)
        portrait.setAlignment(Qt.AlignmentFlag.AlignCenter)
        portrait.setText("连接后\n加载角色")
        portrait.setStyleSheet("background:#292E2D;border:1px solid #414846;border-radius:10px;color:#AAB4B1;font-size:10px;")
        character_row.addWidget(portrait)
        self.character_status.setParent(root)
        self.character_status.hide()
        facts = QGridLayout()
        facts.setHorizontalSpacing(10)
        facts.setVerticalSpacing(4)
        facts.setColumnMinimumWidth(0, 48)
        facts.setColumnMinimumWidth(2, 48)
        facts.setColumnStretch(1, 1)
        facts.setColumnStretch(3, 1)
        self.character_facts = {}
        fact_keys = ("角色", "职业", "等级", "状态", "经验", "攻击", "防御", "金币", "移速加成")
        for index, key in enumerate(fact_keys):
            label = QLabel(key)
            label.setObjectName("subtitle")
            value = QLabel("—")
            value.setTextFormat(Qt.TextFormat.PlainText)
            value.setMinimumWidth(0)
            value.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            self.character_facts[key] = value
            row, col = index // 2, (index % 2) * 2
            facts.addWidget(label, row, col)
            facts.addWidget(value, row, col + 1)
        self.health_bar = QProgressBar()
        self.fatigue_bar = QProgressBar()
        character_bars = QVBoxLayout()
        character_bars.setSpacing(4)
        self.experience_bar = QProgressBar()
        for title, bar in (("生命", self.health_bar), ("疲劳余量", self.fatigue_bar), ("经验进度", self.experience_bar)):
            bar.setRange(0, 100)
            bar.setValue(0)
            bar.setFormat("等待数据")
            bar.setFixedHeight(18)
            fill = "#648c50" if bar is self.health_bar else "#B69460" if bar is self.fatigue_bar else "#5798A8"
            bar.setStyleSheet("QProgressBar {background:#191D1E;border:1px solid #444C4A;border-radius:5px;text-align:center;color:#F1F4F2;font-size:11px;} QProgressBar::chunk {background:" + fill + ";border-radius:4px;}")
            bar_row = QHBoxLayout()
            label = QLabel(title)
            label.setObjectName("subtitle")
            label.setFixedWidth(58)
            bar_row.addWidget(label)
            bar_row.addWidget(bar, 1)
            character_bars.addLayout(bar_row)
        facts.addLayout(character_bars, (len(fact_keys) + 1) // 2, 0, 1, 4)
        character_row.addLayout(facts, 1)
        box.addLayout(character_row)
        self.resource_chips = {}
        resource_row = QHBoxLayout()
        resource_row.setSpacing(6)
        for key, title in (("healthPotions", "药水"), ("bossTickets", "遗迹券"),
                            ("atonementStones", "赎罪石"), ("townStones", "回城石"),
                            ("evil", "恶名")):
            chip = QLabel(f"{title}  —")
            chip.setObjectName("resourceChip")
            chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
            chip.setToolTip("等待实时角色快照")
            self.resource_chips[key] = chip
            resource_row.addWidget(chip, 1)
        box.addLayout(resource_row)
        gear_title = QLabel("已穿戴装备")
        gear_title.setObjectName("fieldLabel")
        gear_header = QHBoxLayout()
        gear_header.addWidget(gear_title)
        gear_header.addStretch()
        self.backpack_button = QPushButton("背包")
        self.backpack_button.setObjectName("quietButton")
        self.backpack_button.clicked.connect(self.open_backpack)
        gear_header.addWidget(self.backpack_button)
        box.addLayout(gear_header)
        gear = QGridLayout()
        gear.setSpacing(6)
        self.gear_slots = {}
        self.gear_icons = {}
        for index, (slot, name) in enumerate((("WEAPON", "武器"), ("HAT", "头盔"),
                                             ("ARMOR", "护甲"), ("SHOES", "鞋子"),
                                             ("RING", "戒指"), ("AMULET", "项链"))):
            label = QLabel(f"{name}  ·  未穿戴")
            label.setTextFormat(Qt.TextFormat.PlainText)
            label.setMinimumWidth(0)
            label.setWordWrap(True)
            label.setStyleSheet("background:#191D1E;border:1px solid #363D3C;border-radius:6px;padding:6px;")
            self.gear_slots[slot] = (name, label)
            cell = QWidget()
            cell_row = QHBoxLayout(cell)
            cell_row.setContentsMargins(0, 0, 0, 0)
            cell_row.setSpacing(5)
            icon = QLabel()
            icon.setFixedSize(24, 24)
            self.gear_icons[slot] = icon
            cell_row.addWidget(icon)
            cell_row.addWidget(label, 1)
            gear.addWidget(cell, index // 2, index % 2)
        box.addLayout(gear)
        battle, box = card("战斗策略")
        self.auto_attack.setText("自动追击与攻击")
        for widget in (self.auto_attack, self.auto_potion, self.elite_only, self.attack_button):
            place(box, widget)
        left.addWidget(battle)
        travel, box = card("地图与复活")
        place(box, self.current_map_label)
        self.world_status.setWordWrap(True)
        place(box, self.world_status)
        grid = QGridLayout()
        grid.setSpacing(8)
        for index, (map_id, button) in enumerate(self.map_buttons.items()):
            button.setParent(root)
            button.setMinimumWidth(0)
            button.setMinimumHeight(34)
            button.show()
            grid.addWidget(button, index//2, index%2)
        box.addLayout(grid)
        place(box, self.respawn_button)
        self.respawn_button.setVisible(self.server_dead)
        place(box, self.auto_return_map)
        place(box, self.return_map)
        ticket_row = QHBoxLayout()
        place(ticket_row, self.use_ticket)
        ticket_hint = QLabel("仅进入废弃遗迹时需要")
        ticket_hint.setObjectName("subtitle")
        ticket_row.addWidget(ticket_hint)
        ticket_row.addStretch(1)
        box.addLayout(ticket_row)
        place(box, self.stop_move_button)
        place(box, self.travel_status)
        left.addWidget(travel)
        left.addStretch()

        map_card, box = card("实时小地图")
        map_card.setFixedWidth(260)
        self.minimap.setMinimumHeight(0)
        self.minimap.setFixedHeight(210)
        place(box, self.minimap)
        legend = QLabel("<span style='color:#afc69e'>●</span> 角色　"
                        "<span style='color:#45B9D0'>●</span> 玩家　"
                        "<span style='color:#c78f86'>●</span> 怪物　"
                        "<span style='color:#cfb77b'>◆</span> 精英　"
                        "<span style='color:#9cacae'>□</span> 入口　┄ 路线")
        legend.setObjectName("subtitle")
        legend.setWordWrap(True)
        legend.setMaximumHeight(34)
        place(box, self.map_activity)
        self.map_activity.setMaximumHeight(30)
        place(box, legend)
        overview = QHBoxLayout()
        overview.setSpacing(14)
        character.setMinimumHeight(0)
        map_card.setFixedHeight(340)
        self.minimap.setFixedHeight(190)
        character.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        overview.addWidget(character, 1)
        map_column = QWidget(root)
        map_column.setFixedWidth(260)
        map_column_layout = QVBoxLayout(map_column)
        map_column_layout.setContentsMargins(0, 0, 0, 0)
        map_column_layout.setSpacing(12)
        map_column_layout.addWidget(map_card)
        battle_feed, feed_box = card("战斗动态")
        self.combat_status.setParent(root)
        self.combat_status.setMinimumHeight(44)
        feed_box.addWidget(self.combat_status)
        stats_grid = QGridLayout()
        stats_grid.setContentsMargins(0, 0, 0, 0)
        stats_grid.setHorizontalSpacing(6)
        stats_grid.setVerticalSpacing(6)
        for index, stat in enumerate(self.combat_stat_cards.values()):
            stat.setParent(root)
            self.combat_stats_layout.removeWidget(stat)
            stats_grid.addWidget(stat, index // 2, index % 2)
        feed_box.addLayout(stats_grid)
        map_column_layout.addWidget(battle_feed)
        map_column_layout.addStretch(1)
        overview.addWidget(map_column, 0, Qt.AlignmentFlag.AlignTop)
        right.addLayout(overview)
        tabs = QTabWidget(root)
        tabs.setDocumentMode(True)
        tabs.tabBar().setDrawBase(False)
        quest_page = QWidget()
        quest_box = QVBoxLayout(quest_page)
        quest_box.setContentsMargins(10, 12, 10, 10)
        quest_box.setSpacing(10)
        quest_row = QHBoxLayout()
        task_heading = QLabel("任务管理")
        task_heading.setObjectName("fieldLabel")
        quest_row.addWidget(task_heading)
        quest_row.addStretch(1)
        self.refresh_profile_button.setFixedWidth(132)
        place(quest_row, self.refresh_profile_button)
        quest_box.addLayout(quest_row)
        task_options = QFrame()
        task_options.setObjectName("taskOptions")
        task_options_layout = QVBoxLayout(task_options)
        task_options_layout.setContentsMargins(12, 10, 12, 10)
        task_options_layout.setSpacing(8)
        task_options_heading = QHBoxLayout()
        task_options_title = QLabel("任务自动化")
        task_options_title.setObjectName("fieldLabel")
        task_options_heading.addWidget(task_options_title)
        task_options_hint = QLabel("自动接取、目标限制与按任务地图移动可组合使用")
        task_options_hint.setObjectName("subtitle")
        task_options_heading.addWidget(task_options_hint)
        task_options_heading.addStretch(1)
        task_options_layout.addLayout(task_options_heading)
        quest_options_row = QHBoxLayout()
        quest_options_row.setSpacing(8)
        for option in (self.auto_quest, self.task_limited_mode, self.quest_map_auto):
            option.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            option.setMinimumHeight(40)
            quest_options_row.addWidget(option, 1)
        task_options_layout.addLayout(quest_options_row)
        quest_box.addWidget(task_options)
        self.quest_status.setFixedHeight(24)
        place(quest_box, self.quest_status)
        self.quest_table.verticalHeader().setDefaultSectionSize(44)
        self.quest_table.horizontalHeader().setMinimumHeight(44)
        self.quest_table.setStyleSheet("font-size: 13px;")
        self.quest_table.setMinimumHeight(250)
        self.quest_table.setMaximumHeight(16777215)
        self.quest_table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        place(quest_box, self.quest_table, 1)
        tabs.addTab(quest_page, "任务")
        monsters_page = QWidget()
        monsters_box = QVBoxLayout(monsters_page)
        monsters_box.setContentsMargins(10, 12, 10, 10)
        monsters_box.setSpacing(8)
        monsters_box.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.monster_empty_state = QFrame()
        self.monster_empty_state.setObjectName("emptyState")
        self.monster_empty_state.setMaximumHeight(88)
        monster_empty_layout = QHBoxLayout(self.monster_empty_state)
        monster_empty_layout.setContentsMargins(14, 10, 14, 10)
        monster_empty_layout.setSpacing(12)
        monster_art = QLabel()
        monster_art.setFixedSize(38, 38)
        monster_pixmap = QPixmap(str(Path(__file__).with_name("assets") / "monster.webp"))
        if not monster_pixmap.isNull():
            monster_art.setPixmap(monster_pixmap.scaled(34, 34, Qt.AspectRatioMode.KeepAspectRatio,
                                                       Qt.TransformationMode.SmoothTransformation))
        monster_art.setAlignment(Qt.AlignmentFlag.AlignCenter)
        monster_empty_layout.addWidget(monster_art)
        monster_empty_copy = QVBoxLayout()
        monster_empty_copy.setSpacing(2)
        self.monster_empty_title = QLabel("等待怪物数据")
        self.monster_empty_title.setObjectName("sectionTitle")
        monster_empty_copy.addWidget(self.monster_empty_title)
        self.monster_empty_detail = QLabel("连接游戏后会列出当前地图发现的存活怪物。")
        self.monster_empty_detail.setObjectName("subtitle")
        self.monster_empty_detail.setWordWrap(True)
        monster_empty_copy.addWidget(self.monster_empty_detail)
        monster_empty_layout.addLayout(monster_empty_copy, 1)
        monsters_box.addWidget(self.monster_empty_state)
        self.encounter_id_toggle.setParent(root)
        self.encounter_id_toggle.hide()
        self.monster_table.setColumnHidden(0, False)
        self.monster_table.horizontalHeader().moveSection(0, 6)
        self.monster_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.monster_table.setColumnWidth(0, 285)
        self.monster_table.setMinimumHeight(120)
        self.monster_table.setMaximumHeight(260)
        place(monsters_box, self.monster_table)
        self.monster_table.hide()
        self.monster_empty_state.show()
        tabs.addTab(monsters_page, "怪物")
        log_page = QWidget()
        log_box = QVBoxLayout(log_page)
        log_box.setContentsMargins(10, 12, 10, 10)
        log_tools = QHBoxLayout()
        log_tools.addStretch(1)
        self.clear_button.setFixedSize(108, 32)
        place(log_tools, self.clear_button)
        log_box.addLayout(log_tools)
        place(log_box, self.log, 1)
        tabs.addTab(log_page, "运行日志")
        tools_page = QWidget()
        tools_box = QVBoxLayout(tools_page)
        tools_box.addWidget(QLabel("手动协议调试"))
        place(tools_box, self.quest_id)
        place(tools_box, self.message, 1)
        place(tools_box, self.send_button)
        tabs.addTab(tools_page, "调试")
        social_page = QWidget()
        social_box = QVBoxLayout(social_page)
        social_box.setContentsMargins(10, 12, 10, 10)
        social_box.setSpacing(12)
        social_header = QHBoxLayout()
        self.balance_label = QLabel("TABBY 余额：等待读取")
        self.balance_label.setObjectName("sectionTitle")
        social_header.addWidget(self.balance_label)
        self.mail_unread_label = QLabel("未读邮件：—")
        self.mail_unread_label.setObjectName("subtitle")
        social_header.addWidget(self.mail_unread_label)
        social_header.addStretch(1)
        balance_refresh = QPushButton("刷新余额与背包")
        balance_refresh.setObjectName("quietButton")
        balance_refresh.clicked.connect(self.refresh_social_data)
        social_header.addWidget(balance_refresh)
        social_box.addLayout(social_header)
        social_tabs = QTabWidget()
        social_tabs.setDocumentMode(True)
        social_tabs.tabBar().setDrawBase(False)
        inventory_card = QFrame()
        inventory_card.setObjectName("card")
        inventory_box = QVBoxLayout(inventory_card)
        inventory_box.setContentsMargins(14, 12, 14, 14)
        inventory_box.addWidget(QLabel("背包与装备"))
        self.social_inventory_table = QTableWidget(0, 6)
        self.social_inventory_table.setHorizontalHeaderLabels(["物品", "部位", "品质", "等级", "属性", "状态"])
        self.social_inventory_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.social_inventory_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.social_inventory_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.social_inventory_table.itemSelectionChanged.connect(self.update_inventory_action_button)
        self.social_inventory_table.verticalHeader().setVisible(False)
        self.social_inventory_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in range(1, 6):
            self.social_inventory_table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        self.social_inventory_table.setMinimumHeight(220)
        self.social_inventory_table.setMaximumHeight(440)
        inventory_box.addWidget(self.social_inventory_table, 1)
        selected_preview = QFrame()
        selected_preview.setObjectName("emptyState")
        preview_layout = QHBoxLayout(selected_preview)
        preview_layout.setContentsMargins(10, 8, 10, 8)
        self.selected_item_icon = QLabel()
        self.selected_item_icon.setFixedSize(36, 36)
        preview_layout.addWidget(self.selected_item_icon)
        preview_copy = QVBoxLayout()
        preview_copy.setSpacing(2)
        self.selected_item_name = QLabel("未选择物品")
        self.selected_item_name.setObjectName("sectionTitle")
        preview_copy.addWidget(self.selected_item_name)
        self.selected_item_detail = QLabel("点击背包中的一行查看物品详情，再执行装备操作。")
        self.selected_item_detail.setObjectName("subtitle")
        self.selected_item_detail.setWordWrap(True)
        preview_copy.addWidget(self.selected_item_detail)
        self.selected_item_attributes = QLabel("属性：选择装备查看")
        self.selected_item_attributes.setObjectName("subtitle")
        self.selected_item_attributes.setWordWrap(True)
        preview_copy.addWidget(self.selected_item_attributes)
        preview_layout.addLayout(preview_copy, 1)
        inventory_box.addWidget(selected_preview)
        inventory_actions = QHBoxLayout()
        self.equip_item_button = QPushButton("装备所选")
        self.equip_item_button.setObjectName("primaryButton")
        self.equip_item_button.clicked.connect(self.equip_selected_item)
        self.sell_item_button = QPushButton("上架出售")
        self.sell_item_button.setObjectName("secondaryButton")
        self.sell_item_button.setToolTip("当前游戏客户端没有可核实的装备上架接口；点击查看状态，不会发送猜测的交易请求。")
        self.sell_item_button.clicked.connect(self.explain_item_listing_status)
        inventory_actions.addWidget(self.equip_item_button)
        inventory_actions.addWidget(self.sell_item_button)
        inventory_box.addLayout(inventory_actions)
        self.inventory_action_status = QLabel("装备可直接操作；上架按钮会说明当前服务端协议状态。")
        self.inventory_action_status.setObjectName("subtitle")
        self.inventory_action_status.setWordWrap(True)
        inventory_box.addWidget(self.inventory_action_status)
        inventory_page = QWidget()
        inventory_page_layout = QVBoxLayout(inventory_page)
        inventory_page_layout.setContentsMargins(8, 8, 8, 8)
        inventory_page_layout.addWidget(inventory_card, 1)
        social_tabs.addTab(inventory_page, "背包与装备")
        mode_card = QFrame()
        mode_card.setObjectName("card")
        mode_box = QVBoxLayout(mode_card)
        mode_box.setContentsMargins(14, 12, 14, 14)
        mode_box.addWidget(QLabel("角色状态与仇杀"))
        mode_row = QHBoxLayout()
        self.combat_mode = QComboBox()
        for label, value in (("和平", 0), ("战斗", 1), ("仇杀", 2)):
            self.combat_mode.addItem(label, value)
        mode_row.addWidget(self.combat_mode, 1)
        self.set_mode_button = QPushButton("应用")
        self.set_mode_button.setObjectName("primaryButton")
        self.set_mode_button.clicked.connect(self.set_combat_mode)
        mode_row.addWidget(self.set_mode_button)
        mode_box.addLayout(mode_row)
        self.mode_status = QLabel("等待实时角色状态")
        self.mode_status.setObjectName("subtitle")
        self.mode_status.setWordWrap(True)
        mode_box.addWidget(self.mode_status)
        self.live_telemetry = QLabel("战斗票据、延迟与最近目标将在连接后显示。")
        self.live_telemetry.setObjectName("subtitle")
        self.live_telemetry.setWordWrap(True)
        mode_box.addWidget(self.live_telemetry)
        self.enemy_table = QTableWidget(0, 3)
        self.enemy_table.setHorizontalHeaderLabels(["附近玩家", "状态", "生命"])
        self.enemy_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.enemy_table.verticalHeader().setVisible(False)
        self.enemy_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.enemy_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.enemy_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.enemy_table.setMinimumHeight(120)
        self.enemy_table.setMinimumHeight(180)
        self.enemy_table.setMaximumHeight(420)
        mode_box.addWidget(self.enemy_table, 1)
        self.enemy_hint = QLabel("名单来自实时地图快照；服务端没有提供持久化仇人名单接口。")
        self.enemy_hint.setObjectName("subtitle")
        self.enemy_hint.setWordWrap(True)
        mode_box.addWidget(self.enemy_hint)
        players_page = QWidget()
        players_layout = QVBoxLayout(players_page)
        players_layout.setContentsMargins(8, 8, 8, 8)
        players_layout.addWidget(mode_card, 1)
        social_tabs.addTab(players_page, "状态与玩家")
        chat_card = QFrame()
        chat_card.setObjectName("card")
        chat_box = QVBoxLayout(chat_card)
        chat_box.setContentsMargins(14, 12, 14, 14)
        chat_box.addWidget(QLabel("世界聊天"))
        self.social_chat_log = QPlainTextEdit()
        self.social_chat_log.setReadOnly(True)
        self.social_chat_log.setMaximumBlockCount(200)
        self.social_chat_log.setPlaceholderText("连接后显示收到的世界聊天消息。")
        chat_box.addWidget(self.social_chat_log, 1)
        chat_row = QHBoxLayout()
        self.social_chat_input = QLineEdit()
        self.social_chat_input.setPlaceholderText("输入世界消息")
        self.social_chat_input.returnPressed.connect(self.send_chat_message)
        chat_row.addWidget(self.social_chat_input, 1)
        chat_send = QPushButton("发送")
        chat_send.setObjectName("secondaryButton")
        chat_send.clicked.connect(self.send_chat_message)
        chat_row.addWidget(chat_send)
        chat_box.addLayout(chat_row)
        chat_page = QWidget()
        chat_page_layout = QVBoxLayout(chat_page)
        chat_page_layout.setContentsMargins(8, 8, 8, 8)
        chat_page_layout.addWidget(chat_card, 1)
        social_tabs.addTab(chat_page, "世界聊天")
        social_box.addWidget(social_tabs, 1)
        tabs.addTab(social_page, "角色与社交")
        tabs.currentChanged.connect(lambda index: self.refresh_social_data() if tabs.widget(index) is social_page else None)
        notification_page = QWidget()
        notification_layout = QVBoxLayout(notification_page)
        notification_layout.setContentsMargins(10, 12, 10, 10)
        notification_layout.setSpacing(12)
        notification_card = QFrame()
        notification_card.setObjectName("card")
        notification_card_layout = QVBoxLayout(notification_card)
        notification_card_layout.setContentsMargins(18, 16, 18, 18)
        notification_card_layout.setSpacing(12)
        notification_heading = QLabel("推送与自动退出")
        notification_heading.setObjectName("sectionTitle")
        notification_card_layout.addWidget(notification_heading)
        notification_intro = QLabel("选择需要发送到 Lark 的事件。Webhook 会保存在本机应用设置中，输入框默认隐藏内容。")
        notification_intro.setObjectName("subtitle")
        notification_intro.setWordWrap(True)
        notification_card_layout.addWidget(notification_intro)

        webhook_label = QLabel("Lark 自定义机器人 Webhook")
        webhook_label.setObjectName("fieldLabel")
        notification_card_layout.addWidget(webhook_label)
        webhook_row = QHBoxLayout()
        self.lark_webhook = QLineEdit()
        self.lark_webhook.setEchoMode(QLineEdit.EchoMode.Password)
        self.lark_webhook.setPlaceholderText("粘贴 Lark 自定义机器人 Webhook")
        self.lark_webhook.setClearButtonEnabled(True)
        self.lark_webhook.setText(str(self.settings.value("larkWebhook", "")))
        self.lark_webhook.textChanged.connect(self.save_lark_webhook)
        webhook_row.addWidget(self.lark_webhook, 1)
        self.lark_status = QLabel("未配置")
        self.lark_status.setObjectName("subtitle")
        webhook_row.addWidget(self.lark_status)
        notification_card_layout.addLayout(webhook_row)
        self.update_lark_status(self.lark_webhook.text())

        notification_options = QFrame()
        notification_options.setObjectName("taskOptions")
        notification_options_layout = QVBoxLayout(notification_options)
        notification_options_layout.setContentsMargins(12, 10, 12, 10)
        notification_options_layout.setSpacing(8)
        notification_options_title = QLabel("通知事件")
        notification_options_title.setObjectName("fieldLabel")
        notification_options_layout.addWidget(notification_options_title)
        self.notification_preferences = {}
        preferences = (
            ("equipment", "装备掉落", "notifyEquipmentDrop"),
            ("quest", "任务完成（包含任务名称）", "notifyQuestComplete"),
            ("fatigue", "疲劳耗尽", "notifyFatigueExhausted"),
            ("purchase", "商城抢购交易已提交", "notifyPurchaseSuccess"),
            ("sale", "商城出售成功", "notifySaleSuccess"),
        )
        options_grid = QGridLayout()
        options_grid.setHorizontalSpacing(12)
        options_grid.setVerticalSpacing(6)
        for index, (event_key, label_text, setting_key) in enumerate(preferences):
            checkbox = QCheckBox(label_text)
            checkbox.setMinimumHeight(38)
            checkbox.setChecked(self.settings.value(setting_key, True, type=bool))
            checkbox.toggled.connect(
                lambda checked, key=setting_key: self.settings.setValue(key, checked))
            self.notification_preferences[event_key] = checkbox
            options_grid.addWidget(checkbox, index // 2, index % 2)
        notification_options_layout.addLayout(options_grid)
        notification_card_layout.addWidget(notification_options)

        self.logout_on_fatigue = QCheckBox("疲劳耗尽后断开并退出当前登录")
        self.logout_on_fatigue.setChecked(self.settings.value("logoutOnFatigue", False, type=bool))
        self.logout_on_fatigue.toggled.connect(
            lambda checked: self.settings.setValue("logoutOnFatigue", checked))
        self.logout_on_fatigue.setToolTip("只在收到服务端确认疲劳为 0% 时触发；下次需手动重新登录。")
        notification_card_layout.addWidget(self.logout_on_fatigue)
        notification_hint = QLabel("抢购提示表示交易已提交到 BSC 网络；出售成功推送会在应用获得出售成功事件后触发。")
        notification_hint.setObjectName("subtitle")
        notification_hint.setWordWrap(True)
        notification_card_layout.addWidget(notification_hint)
        notification_layout.addWidget(notification_card)
        notification_layout.addStretch(1)
        tabs.addTab(notification_page, "推送设置")
        right.addWidget(tabs, 1)
        scroll = QScrollArea()
        scroll.setObjectName("mainScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(root)
        old_root.setParent(root)
        old_root.hide()
        self.setCentralWidget(scroll)
        self.setMinimumSize(900, 700)
        self.resize(1180, 850)
        self.setStyleSheet(self.styleSheet() + """
            QFrame#taskOptions { background:#1B1E1F; border:1px solid #363D3C; border-radius:10px; }
            QLabel { color: #E8ECEB; }
            QTabWidget::pane { border: 0; background: transparent; }
            QTabBar::tab { background: transparent; color: #AAB4B1; padding: 9px 13px; min-height: 26px; border: 0; border-bottom: 2px solid transparent; margin-right: 8px; }
            QTabBar::tab:selected { color: #E5EBE4; background: transparent; border-bottom: 2px solid #78936B; }
            QTabBar::tab:hover { color: #FFFFFF; background: #222627; border-bottom: 2px solid #535A56; }
            QTabBar::tab:selected:hover { border-bottom-color: #91AD80; }
            QComboBox { color: #E8ECEB; background: #191D1E; border: 1px solid #535A56; border-radius: 7px; padding: 8px; }
            QComboBox QAbstractItemView { color: #E8ECEB; background: #292E2D; selection-background-color: #38533A; }
            QHeaderView { background: #292E2D; }
            QPushButton:focus, QCheckBox:focus, QComboBox:focus { border: 1px solid #9D875C; }
            QLabel#resourceChip { background:#292E2D; color:#D1D8D5; border:1px solid #414846; border-radius:7px; padding:7px 4px; font-size:11px; }
        """)
        for button in root.findChildren(QPushButton):
            button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.update_map_buttons()
        self.update_mode_control()

    def log_clear(self) -> None:
        self.log.clear()

    def refresh_minimap(self) -> None:
        self.minimap.update()
        if self.current_map is None:
            self.map_activity.setText("等待连接 · 输入 Token 开始探索")
            return
        action = ("等待复活确认" if self.respawn_pending else "角色阵亡" if self.server_dead else
                  "前往地图入口" if self.pending_destination is not None else
                  "追击怪物" if self.chase_target else
                  "自动战斗 · 搜索目标" if self.auto_attack.isChecked() else "待命")
        self.map_activity.setText(f"{MAP_NAMES.get(self.current_map, self.current_map)}  ·  {action}  ·  "
                                  f"坐标 {self.world_x}, {self.world_y}")

    def apply_theme(self) -> None:
        check_icon = Path(__file__).with_name("assets") / "checkmark.svg"
        self.setStyleSheet("""
            QMainWindow, QDialog, QScrollArea#mainScroll, QWidget#root { background: #17191A; color: #E8ECEB; }
            QFrame#card { background: #222627; border: 1px solid #363D3C; border-radius: 12px; }
            QFrame#emptyState { background: #1B1E1F; border: 1px dashed #4A514E; border-radius: 10px; }
            QFrame#statChip { background:#292E2D; border:1px solid #414846; border-radius:7px; }
            QFrame#sessionCard { background: #252A29; border: 1px solid #66583E; border-radius: 10px; }
            QLabel#title { color: #F3F5F3; font-size: 23px; font-weight: 700; }
            QLabel#subtitle { color: #AAB4B1; font-size: 12px; }
            QLabel#sectionTitle { color: #E8ECEB; font-size: 15px; font-weight: 700; }
            QLabel#fieldLabel { color: #B7C0BD; font-size: 12px; font-weight: 600; }
            QLabel#currentMapBadge { color: #E8ECEB; background: #29392C; border: 1px solid #58744C; border-radius: 7px; padding: 8px 10px; font-size: 13px; font-weight: 700; }
            QLabel#sessionUrl { color: #D9E0DE; font-family: Menlo, monospace; font-size: 13px; }
            QLabel#status { color: #AAB4B1; font-size: 12px; font-weight: 700; }
            QLineEdit, QPlainTextEdit, QSpinBox { background: #191D1E; color: #E8ECEB; border: 1px solid #444C4A; border-radius: 8px; padding: 8px 10px; selection-background-color: #38533A; }
            QLineEdit:focus, QPlainTextEdit:focus { border: 1px solid #9D875C; }
            QLineEdit::placeholder, QPlainTextEdit::placeholder { color: #818B88; }
            QLineEdit#urlInput, QPlainTextEdit#messageInput, QPlainTextEdit#logView { font-family: Menlo, monospace; font-size: 12px; }
            QPlainTextEdit#logView { background: #191D1E; color: #D5DDDA; border: 1px solid #363D3C; }
            QTableWidget { background: #1B1F20; alternate-background-color: #232829; color: #E8ECEB; border: 1px solid #444C4A; border-radius: 8px; gridline-color: #363D3C; selection-background-color: #354735; }
            QHeaderView::section { background: #292E2D; color: #C6CFCC; border: 0; border-bottom: 1px solid #444C4A; padding: 8px; font-weight: 600; }
            QPushButton { min-height: 32px; padding: 3px 15px; border-radius: 8px; font-weight: 600; }
            QPushButton#primaryButton { background: #3C7951; color: #F4F7F4; border: 1px solid #579166; }
            QPushButton#primaryButton:hover { background: #498D5D; border-color: #70A877; }
            QPushButton#secondaryButton { background: #302A25; color: #E6E8E5; border: 1px solid #766448; }
            QPushButton#secondaryButton:hover { background: #494036; border-color: #B69460; }
            QPushButton#secondaryButton[currentMap="true"] { background: #304333; color: #F1F5EF; border: 2px solid #81966B; }
            QPushButton#quietButton { background: #292E2D; color: #D5DDDA; border: 1px solid #535A56; padding-left: 12px; padding-right: 12px; }
            QPushButton#quietButton:hover { color: #FFFFFF; background: #343A37; border-color: #9D875C; }
            QPushButton:disabled { background: #242827; color: #78817E; border: 1px solid #363D3C; }
            QCheckBox { color: #D2D9D6; spacing: 10px; }
            QCheckBox::indicator { width: 18px; height: 18px; border-radius: 5px; border: 1px solid #59615D; background: #191D1E; }
            QCheckBox::indicator:hover { border-color: #9D875C; background: #292E2D; }
            QCheckBox::indicator:checked { background: #3C7951; border: 1px solid #70A877; image: url("@CHECK_ICON@"); }
            QCheckBox[taskOption="true"] { color: #E1E6E3; spacing: 10px; padding: 5px 11px; min-height: 30px; background: #292E2D; border: 1px solid #414846; border-radius: 8px; }
            QCheckBox[taskOption="true"]:hover { background: #343A37; border-color: #766448; }
            QCheckBox[taskOption="true"]:checked { border-color: #648468; }
            QScrollBar:vertical { background: #17191A; width: 10px; }
            QScrollBar::handle:vertical { background: #4A514E; border-radius: 5px; min-height: 25px; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        """.replace("@CHECK_ICON@", str(check_icon).replace("\\", "/")))

    def append_log(self, message: str) -> None:
        self.log.appendPlainText(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {message}")

    def set_state(self, state: str) -> None:
        self.status.setText(state)
        if state == "连接中…":
            color = "#a16207"
        elif state == "已连接":
            color = "#16803c"
        elif state in ("连接失败", "连接异常关闭") or state.startswith("对端关闭"):
            color = "#c2413b"
        else:
            color = "#536273"
        self.status.setStyleSheet(f"color: {color}; font-weight: 700; background: transparent; border: 0;")
        callback = getattr(self, "on_state_change", None)
        if callable(callback):
            callback(state)

    def set_combat_feedback(self, message: str, tone: str = "default", duration_ms: int = 2600) -> None:
        """Briefly color combat feedback while preserving the normal subtitle style."""
        if not hasattr(self, "combat_status"):
            return
        colors = {"attack": "#66C7D8", "hit": "#74C878", "critical": "#E7B85E", "error": "#E47782"}
        self._combat_feedback_revision = getattr(self, "_combat_feedback_revision", 0) + 1
        revision = self._combat_feedback_revision
        self.combat_status.setText(message)
        color = colors.get(tone)
        self.combat_status.setStyleSheet(f"color: {color}; font-weight: 700;" if color else "")

        def restore_default() -> None:
            if revision == self._combat_feedback_revision and hasattr(self, "combat_status"):
                self.combat_status.setStyleSheet("")

        if color:
            QTimer.singleShot(duration_ms, restore_default)

    def on_connected(self, ws: MiniWebSocket) -> None:
        if ws is None:
            return
        self.ws = ws
        self.send_button.setEnabled(True)
        self.disconnect_button.setEnabled(True)
        self.connect_button.setEnabled(False)
        self.manual_disconnect = False
        self._auto_reconnect_login = False
        self.last_pong_received_at = time.monotonic()
        self.connection_stable_timer.start()
        self.reconnect_timer.stop()
        self.active_url.setText(ws.url)
        self.active_url.setToolTip(ws.url)
        self.bridge.state.emit("已连接")
        safe = {k: v for k, v in ws.response_headers.items() if k not in ("set-cookie", "authorization")}
        self.append_log("响应头：" + json.dumps(safe, ensure_ascii=False))
        if ws.selected_protocol:
            self.append_log("服务端选择的子协议：" + ws.selected_protocol)
        self.reader = threading.Thread(target=self.read_loop, args=(ws,), daemon=True)
        self.reader.start()

    def on_connect_failed(self) -> None:
        self.connection_stable_timer.stop()
        self.keepalive.stop()
        self.reset_world_state()
        self.update_map_buttons()
        self.connect_button.setEnabled(True)
        self.disconnect_button.setEnabled(False)
        self.send_button.setEnabled(False)
        if self.auth_rejected:
            self.auth_rejected = False
            can_refresh_signed_session = (
                self.auth_method.currentData() == "private_key"
                and self.remember_private_key.isChecked()
                and not self._auth_retry_attempted
            )
            if can_refresh_signed_session:
                self._auth_retry_attempted = True
                self._auto_reconnect_login = True
                self.append_log("服务端拒绝当前会话；使用已记住的私钥重新签名登录一次。")
                QTimer.singleShot(0, self.retry_connection)
                return
            self._auto_reconnect_login = False
            self.reconnect_timer.stop()
            message = "登录凭证已失效 · 请重新签名或更新 Token"
            self.append_log("服务端返回 login_required；已停止重复使用同一 Token 重连。")
            self.bridge.state.emit(message)
            return
        self.schedule_auto_reconnect()

    def schedule_auto_reconnect(self) -> None:
        if self.manual_disconnect or not self.auto_reconnect.isChecked():
            self._auto_reconnect_login = False
            return
        # Keep retrying through transient outages. Backoff tops out at one
        # minute instead of permanently giving up after a small fixed count.
        delay = min(60, 2 ** min(self._reconnect_attempt, 6))
        self._reconnect_attempt += 1
        self.append_log(f"{delay} 秒后自动重连（第 {self._reconnect_attempt} 次）。")
        self.bridge.state.emit(f"{delay} 秒后自动重连…")
        self.reconnect_timer.start(delay * 1000)

    def reset_reconnect_backoff(self) -> None:
        if self.ws is not None:
            self._reconnect_attempt = 0

    def retry_connection(self) -> None:
        if self.manual_disconnect or not self.auto_reconnect.isChecked():
            return
        self._auto_reconnect_login = True
        self._resolved_token = ""
        if self.auth_method.currentData() == "private_key":
            self.signed_session_token = ""
        self.connect_ws()

    def on_remember_private_key_toggled(self, checked: bool) -> None:
        self.settings.setValue("rememberPrivateKey", checked)
        if checked:
            if self.credential_vault.exists():
                self.bridge.keyring_status.emit("检测到加密分片；登录时需要输入主密码。")
            else:
                self.bridge.keyring_status.emit("已开启；首次保存时会要求设置独立主密码。")
            return
        self._vault_passphrase = None
        self.credential_vault.delete()
        self.refresh_saved_wallets()
        try:
            secure_keyring().delete_password(KEYRING_SERVICE, KEYRING_ACCOUNT)
        except Exception:
            # Remove legacy credentials from older releases when possible.
            pass
        self.append_log("已请求删除本机保存的私钥分片。")
        self.bridge.keyring_status.emit("已删除本机保存的私钥分片。")

    def ask_vault_passphrase(self, confirm: bool) -> str | None:
        phrase, accepted = QInputDialog.getText(
            self, "私钥保险库主密码", "请输入独立主密码（至少 6 位，不会保存）：",
            QLineEdit.EchoMode.Password,
        )
        if not accepted:
            return None
        if len(phrase) < 6:
            QMessageBox.warning(self, "主密码太短", "请设置至少 6 位的独立主密码。")
            return None
        if confirm:
            repeated, accepted = QInputDialog.getText(
                self, "确认主密码", "请再次输入主密码：", QLineEdit.EchoMode.Password,
            )
            if not accepted:
                return None
            if phrase != repeated:
                QMessageBox.warning(self, "主密码不一致", "两次输入的主密码不一致；没有保存私钥。")
                return None
        return phrase

    def connect_ws(self) -> None:
        if not self._auto_reconnect_login:
            self.reconnect_timer.stop()
            self._reconnect_attempt = 0
            self._auth_retry_attempted = False
        self.auth_rejected = False
        if self.auth_method.currentData() == "private_key" and not self._resolved_token:
            if self.signed_session_token:
                self._resolved_token = self.signed_session_token
            else:
                self.start_signed_login()
                return
        self.keepalive.stop()
        self.reset_world_state()
        self.update_map_buttons()
        url = self.url.text().strip()
        self.active_url.setText(url or "(URL 为空)")
        self.active_url.setToolTip(url)
        self.manual_disconnect = False
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "wss":
            answer = QMessageBox.question(self, "非加密连接", "当前不是 wss:// 安全连接，仍要继续吗？")
            if answer != QMessageBox.StandardButton.Yes:
                return
        headers: dict[str, str] = {}
        origin = self.origin.text().strip()
        if origin:
            headers["Origin"] = origin
        token = self._resolved_token or self.get_session_token()
        self._resolved_token = ""
        self.session_token = token
        token_info = "未填写"
        if token:
            fingerprint = hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
            token_info = f"长度={len(token)}, SHA256前12位={fingerprint}"
            try:
                encoded_payload = token.split(".")[1]
                padded = encoded_payload + "=" * (-len(encoded_payload) % 4)
                claims = json.loads(base64.urlsafe_b64decode(padded))
                if not isinstance(claims, dict):
                    raise ValueError("JWT 载荷不是对象")
                if "playerId" in claims:
                    self.player_id = int(claims["playerId"])
                    token_info += f", playerId={claims['playerId']}"
                if "exp" in claims:
                    expires = datetime.fromtimestamp(int(claims["exp"]), timezone.utc)
                    token_info += f", 到期(UTC)={expires:%Y-%m-%d %H:%M:%S}"
                    if expires.timestamp() <= datetime.now(timezone.utc).timestamp():
                        token_info += " [已过期]"
            except (IndexError, ValueError, TypeError, OverflowError, OSError, binascii.Error):
                token_info += ", JWT载荷无法解析"
        if token and self.send_auth_header.isChecked():
            headers["Authorization"] = "Bearer " + token
        auth_message = None
        auth_fields = []
        if token and self.auto_auth.isChecked():
            try:
                auth_packet = json.loads(self.auth_template.toPlainText())
                if not isinstance(auth_packet, dict) or auth_packet.get("action") != "auth":
                    raise ValueError("首帧必须是包含 action=auth 的 JSON 对象")
                required = {"movementRevision", "map", "x", "y", "animation", "attackCritical", "flip", "loginReset", "snapshotDelta"}
                missing = sorted(required - auth_packet.keys())
                if missing:
                    raise ValueError("客户端登录帧缺少字段：" + ", ".join(missing))
                login_reset = auth_packet.pop("loginReset")
                snapshot_delta = auth_packet.pop("snapshotDelta")
                auth_packet["token"] = token
                auth_packet["loginReset"] = login_reset
                auth_packet["snapshotDelta"] = snapshot_delta
                auth_fields = list(auth_packet)
                auth_message = json.dumps(auth_packet, separators=(",", ":"))
            except (ValueError, TypeError) as exc:
                QMessageBox.warning(self, "客户端登录帧格式错误", str(exc))
                return
        for line in self.extra_headers.toPlainText().splitlines():
            if not line.strip():
                continue
            if ":" not in line:
                QMessageBox.warning(self, "请求头格式错误", f"无法解析：{line}")
                return
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
        protocols = [p.strip() for p in self.protocols.text().split(",") if p.strip()]
        self.connect_button.setEnabled(False)
        self.bridge.state.emit("连接中…")
        self.append_log(f"连接 {url}")
        self.append_log(f"请求头名称：{', '.join(headers.keys()) or '(无)'}；凭证值不会写入日志")
        self.append_log("token 摘要：" + token_info)

        def worker() -> None:
            client = MiniWebSocket(url, headers, protocols)
            try:
                client.connect()
                self.bridge.log.emit(f"握手成功：{client.status_line}")
                if auth_message is not None:
                    client.send_text(auth_message)
                    self.bridge.log.emit("已发送客户端登录帧：" + ", ".join(auth_fields) + "；token=<hidden>")
            except Exception as exc:
                self.bridge.log.emit(f"连接失败：{type(exc).__name__}: {exc}")
                if client.status_line:
                    self.bridge.log.emit("握手状态：" + client.status_line)
                    safe = {k: v for k, v in client.response_headers.items() if k not in ("set-cookie", "authorization")}
                    self.bridge.log.emit("响应头（已过滤敏感字段）：" + json.dumps(safe, ensure_ascii=False))
                client.close()
                self.bridge.state.emit("连接失败")
                self.bridge.log.emit("排查点：HTTP 状态/Origin/认证方式/代理；浏览器 1006 本身不说明具体原因。")
                self.bridge.connect_failed.emit()
                return
            self.bridge.connected.emit(client)

        threading.Thread(target=worker, daemon=True).start()

    def update_auth_fields(self, *_args) -> None:
        private_mode = self.auth_method.currentData() == "private_key"
        self.token.setVisible(not private_mode)
        self.saved_wallet_label.setVisible(private_mode)
        self.saved_wallet.setVisible(private_mode)
        self.private_key_label.setVisible(private_mode)
        self.private_key.setVisible(private_mode)
        if not private_mode:
            self.private_key.clear()
            self._vault_passphrase = None

    def refresh_saved_wallets(self) -> None:
        if not hasattr(self, "saved_wallet"):
            return
        selected = str(self.saved_wallet.currentData() or self.settings.value("lastWalletAddress", ""))
        addresses = self.credential_vault.list_wallets()
        self.saved_wallet.blockSignals(True)
        self.saved_wallet.clear()
        self.saved_wallet.addItem("输入新的私钥", "")
        for address in addresses:
            self.saved_wallet.addItem(address, address)
        index = self.saved_wallet.findData(selected) if selected else -1
        if index < 0 and len(addresses) == 1:
            index = self.saved_wallet.findData(addresses[0])
        self.saved_wallet.setCurrentIndex(max(0, index))
        self.saved_wallet.blockSignals(False)

    def on_saved_wallet_selected(self, index: int) -> None:
        address = str(self.saved_wallet.itemData(index) or "") if index >= 0 else ""
        if address:
            self.settings.setValue("lastWalletAddress", address)
            self.private_key.clear()
        self.invalidate_signed_session()

    def on_private_key_edited(self, *_args) -> None:
        if self.saved_wallet.currentData():
            self.saved_wallet.blockSignals(True)
            self.saved_wallet.setCurrentIndex(0)
            self.saved_wallet.blockSignals(False)
        self.invalidate_signed_session()

    def invalidate_signed_session(self, *_args) -> None:
        self.signed_session_token = ""
        if self.auth_method.currentData() == "private_key":
            self.session_token = ""

    def get_session_token(self) -> str:
        if self.auth_method.currentData() == "private_key":
            return self.signed_session_token.strip()
        token = self.token.text().strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        return token

    def start_signed_login(self) -> None:
        url = self.url.text().strip()
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "wss" or not parsed.netloc:
            QMessageBox.warning(self, "需要安全连接", "私钥签名登录只允许通过 wss:// 地址发起。")
            return
        private_key = self.private_key.text().strip()
        selected_wallet_address = str(self.saved_wallet.currentData() or "") if not private_key else ""
        remember_private_key = self.remember_private_key.isChecked()
        vault_passphrase = None
        if not private_key and selected_wallet_address:
            vault_passphrase = self._vault_passphrase
            if not vault_passphrase:
                vault_passphrase = self.ask_vault_passphrase(confirm=False)
                if vault_passphrase is None:
                    return
            try:
                private_key = self.credential_vault.load_wallet(vault_passphrase, selected_wallet_address)
                self.bridge.keyring_status.emit(f"主密码验证成功；已解锁 {selected_wallet_address[:8]}…{selected_wallet_address[-6:]}。")
            except (OSError, ValueError) as exc:
                self._vault_passphrase = None
                QMessageBox.warning(self, "无法解锁私钥", str(exc))
                self.bridge.keyring_status.emit("解锁失败；请确认主密码或检查分片文件。")
                return
        elif not private_key and self.credential_vault.list_wallets():
            QMessageBox.information(self, "选择钱包地址", "本机保存了多个钱包，请先选择要登录的钱包地址；也可以输入新的私钥。")
            return
        elif not private_key and remember_private_key and self.credential_vault.exists():
            # One-time migration from releases that kept the credential in
            # the OS keyring. New writes always go to the passphrase vault.
            try:
                legacy_key = secure_keyring().get_password(KEYRING_SERVICE, KEYRING_ACCOUNT) or ""
            except Exception:
                legacy_key = ""
                self.bridge.keyring_status.emit("旧版系统凭据不可读取；请输入私钥以迁移到加密分片。")
            if legacy_key:
                vault_passphrase = self.ask_vault_passphrase(confirm=True)
                if vault_passphrase is None:
                    return
                private_key = legacy_key
                legacy_key = ""
                self.bridge.keyring_status.emit("发现旧版保存项；成功登录后会迁移为主密码加密分片。")
        if not private_key:
            if self._auto_reconnect_login:
                self._auto_reconnect_login = False
                self.reconnect_timer.stop()
                self.bridge.state.emit("自动重连需要先选择钱包并解锁")
                self.append_log("自动重连已暂停：本次运行中没有已解锁的钱包私钥。")
                return
            QMessageBox.information(self, "需要私钥", "请输入用于本机签名的钱包私钥。")
            return
        if remember_private_key:
            if vault_passphrase is None:
                vault_passphrase = self.ask_vault_passphrase(confirm=True)
                if vault_passphrase is None:
                    return
            self._vault_passphrase = vault_passphrase
        else:
            self._vault_passphrase = None
        self.private_key.clear()
        automatic_reauth = self._auto_reconnect_login and remember_private_key
        api_path = parsed.path.rstrip("/")
        if api_path.endswith("/realtime"):
            api_path = api_path[:-len("/realtime")]
        api_base = urllib.parse.urlunsplit(("https", parsed.netloc, api_path, "", ""))
        api_origin = urllib.parse.urlunsplit(("https", parsed.netloc, "", "", ""))
        self.keepalive.stop()
        self.reset_world_state()
        self.update_map_buttons()
        self.connect_button.setEnabled(False)
        self.bridge.state.emit("本机签名登录中…")
        self.append_log("正在通过钱包签名获取游戏会话；私钥与签名不会写入日志。")

        def worker() -> None:
            key_material = private_key
            try:
                from eth_account import Account
                from eth_account.messages import encode_defunct

                account = Account.from_key(key_material)
                if selected_wallet_address and account.address.lower() != selected_wallet_address.lower():
                    raise RuntimeError("解锁出的私钥与所选钱包地址不匹配")

                def request(path: str, body: dict, bearer: str | None = None) -> dict:
                    # The membership API applies browser-origin validation.
                    # The game client itself does not need these headers for
                    # the WebSocket, but the HTTP signature endpoints do.
                    headers = {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Origin": api_origin,
                        "Referer": api_origin + "/",
                    }
                    if bearer:
                        headers["Authorization"] = "Bearer " + bearer
                    request_body = json.dumps(body).encode("utf-8")
                    result = None
                    for attempt in range(3):
                        req = urllib.request.Request(api_base + path, data=request_body,
                                                     headers=headers, method="POST")
                        try:
                            with urllib.request.urlopen(req, timeout=15) as response:
                                result = json.loads(response.read().decode("utf-8"))
                            break
                        except urllib.error.HTTPError as exc:
                            # A challenge is safe to request again. Avoid
                            # replaying verify/enter: a gateway may have lost
                            # its response after consuming their one-time data.
                            if path == "/membership/challenge" and exc.code in (502, 503, 504) and attempt < 2:
                                exc.close()
                                time.sleep(0.5 * (attempt + 1))
                                continue
                            raw = exc.read().decode("utf-8", errors="replace")
                            try:
                                error_data = json.loads(raw)
                            except (TypeError, ValueError):
                                if "html" in str(exc.headers.get("Content-Type", "")).lower():
                                    title = re.search(r"<title[^>]*>(.*?)</title>", raw, re.IGNORECASE | re.DOTALL)
                                    detail = re.sub(r"\s+", " ", title.group(1)).strip() if title else "服务器返回了 HTML 错误页"
                                    error_data = {"message": detail[:180]}
                                else:
                                    error_data = {"message": re.sub(r"\s+", " ", raw).strip()[:180]}
                            code = error_data.get("code", "") if isinstance(error_data, dict) else ""
                            message = error_data.get("message", "") if isinstance(error_data, dict) else ""
                            detail = str(code or message or f"HTTP {exc.code}")
                            raise RuntimeError(f"{path}: {detail}") from None
                    if not isinstance(result, dict):
                        raise RuntimeError("服务端返回格式无效")
                    if result.get("code") and not result.get("walletToken") and not result.get("token"):
                        raise RuntimeError(str(result["code"]))
                    return result

                challenge = request("/membership/challenge", {"address": account.address, "chainId": 56})
                challenge_id = challenge.get("challengeId")
                message = challenge.get("message")
                if not challenge_id or not isinstance(message, str) or not message:
                    raise RuntimeError("签名挑战缺少 challengeId 或 message")
                approval = threading.Event()
                approval_data = {"message": message, "approved": False, "event": approval,
                                 "automatic": automatic_reauth}
                self.bridge.sign_challenge.emit(approval_data)
                if not approval.wait(timeout=180) or not approval_data["approved"]:
                    raise RuntimeError("已取消签名登录")
                signed = Account.sign_message(encode_defunct(text=message), key_material)
                # eth-account's HexBytes.hex() may omit the 0x marker, while
                # the membership verifier expects an RPC-style hex signature.
                signature = "0x" + bytes(signed.signature).hex()
                verification = request("/membership/verify", {
                    "challengeId": challenge_id, "signature": signature, "chainId": 56
                })
                wallet_token = verification.get("walletToken")
                if not wallet_token:
                    raise RuntimeError("签名验证未返回 walletToken")
                entered = request("/membership/enter", {}, str(wallet_token))
                game_token = entered.get("token")
                if not game_token:
                    raise RuntimeError("入场验证未返回游戏会话 token；请确认钱包具备测试服资格")
                remember_error = ""
                remembered = False
                if remember_private_key:
                    try:
                        self.credential_vault.store_wallet(key_material, vault_passphrase, account.address)
                        remembered = self.credential_vault.load_wallet(vault_passphrase, account.address) == key_material
                        if not remembered:
                            raise RuntimeError("加密分片写入后校验失败")
                        try:
                            # Clean up the legacy system-keyring copy created by
                            # older versions; the new vault no longer depends on it.
                            secure_keyring().delete_password(KEYRING_SERVICE, KEYRING_ACCOUNT)
                        except Exception:
                            pass
                    except Exception:
                        remember_error = "登录成功，但加密分片保存或校验失败；私钥未被记住。"
                self.bridge.signed_login.emit({"ok": True, "token": str(game_token),
                                               "address": account.address,
                                               "remember_error": remember_error,
                                               "remembered": remembered})
            except Exception as exc:
                self.bridge.signed_login.emit({"ok": False,
                                               "error": f"{type(exc).__name__}: {exc}"})
            finally:
                key_material = ""

        threading.Thread(target=worker, daemon=True).start()

    def confirm_sign_challenge(self, approval_data: dict) -> None:
        try:
            if approval_data.get("automatic"):
                approval_data["approved"] = True
                return
            dialog = QMessageBox(self)
            dialog.setWindowTitle("确认钱包签名")
            dialog.setIcon(QMessageBox.Icon.Warning)
            dialog.setText("服务端请求对下方消息进行 EIP-191 签名。确认这是本次游戏登录挑战后再继续。")
            dialog.setTextFormat(Qt.TextFormat.PlainText)
            dialog.setDetailedText(str(approval_data.get("message", "")))
            dialog.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            dialog.setDefaultButton(QMessageBox.StandardButton.No)
            approval_data["approved"] = dialog.exec() == QMessageBox.StandardButton.Yes
        finally:
            approval_data["event"].set()

    def finish_signed_login(self, result: dict) -> None:
        self.connect_button.setEnabled(True)
        if not isinstance(result, dict) or not result.get("ok"):
            self._vault_passphrase = None
            self.bridge.keyring_status.emit("登录未完成；本次私钥不会写入加密分片。")
            error = result.get("error", "签名登录失败") if isinstance(result, dict) else "签名登录失败"
            self.bridge.state.emit("签名登录失败")
            self.append_log("签名登录失败：" + str(error))
            was_auto_reconnect = self._auto_reconnect_login
            self._auto_reconnect_login = False
            if was_auto_reconnect:
                self.schedule_auto_reconnect()
                return
            QMessageBox.warning(self, "签名登录失败", str(error))
            return
        self.session_token = str(result["token"])
        self.signed_session_token = self.session_token
        address = str(result.get("address", ""))
        if result.get("remember_error"):
            self.append_log(str(result["remember_error"]))
            self.bridge.keyring_status.emit("保存失败；请确认磁盘权限后重试。")
        elif result.get("remembered"):
            self.refresh_saved_wallets()
            index = self.saved_wallet.findData(address)
            if index >= 0:
                self.saved_wallet.setCurrentIndex(index)
                self.settings.setValue("lastWalletAddress", address)
            self.append_log("钱包私钥已加密分片保存并完成解密校验；主密码未写入磁盘。")
            self.bridge.keyring_status.emit("AES-GCM 校验成功；三片密文已保存。")
        self.append_log(f"钱包签名验证成功：{address[:8]}…{address[-6:]}；游戏 token 已留在内存中。")
        self._resolved_token = self.session_token
        self.connect_ws()

    def read_loop(self, ws: MiniWebSocket) -> None:
        try:
            while self.ws is ws:
                opcode, payload = ws.recv_message()
                if opcode == 1:
                    text = payload.decode("utf-8", "replace")
                    try:
                        packet = json.loads(text)
                    except ValueError:
                        packet = None
                    if isinstance(packet, dict):
                        # The server commonly follows login_required with a
                        # policy-close immediately. Record this on the socket
                        # reader thread before queueing Qt signals so the
                        # close handler cannot mistake it for a transient drop
                        # and retry the exact same rejected credential.
                        if packet.get("type") == "error" and packet.get("code") == "login_required":
                            self.auth_rejected = True
                        self.bridge.packet.emit(packet)
                    if not isinstance(packet, dict) or packet.get("type") not in ("snapshot", "pong"):
                        self.bridge.log.emit("RECV text: " + text)
                else:
                    self.bridge.log.emit(f"RECV binary: {len(payload)} bytes (hex {payload[:96].hex()})")
        except Exception as exc:
            if self.ws is not ws:
                return
            if ws.close_code is not None:
                self.bridge.log.emit(f"收到 Close 帧：code={ws.close_code}, reason={ws.close_reason!r}")
                state = f"对端关闭 ({ws.close_code})" + (f" · {ws.close_reason}" if ws.close_reason else "")
                self.bridge.state.emit(state)
            else:
                if self.manual_disconnect:
                    state = "已主动断开"
                else:
                    state = "连接异常关闭 (1006/无 Close 帧)"
                    self.bridge.log.emit(f"连接读循环结束：{type(exc).__name__}: {exc}；未收到 WebSocket Close 帧")
                self.bridge.state.emit(state)
            self.ws = None
            self.bridge.connect_failed.emit()

    def send_message(self) -> None:
        ws = self.ws
        if ws is None:
            return
        text = self.message.toPlainText()
        if not text:
            return
        try:
            ws.send_text(text)
            self.append_log("SEND text: " + text)
        except Exception as exc:
            self.append_log(f"发送失败：{type(exc).__name__}: {exc}")

    def disconnect_ws(self) -> None:
        self.manual_disconnect = True
        self._auto_reconnect_login = False
        self._vault_passphrase = None
        self.reconnect_timer.stop()
        self.connection_stable_timer.stop()
        self.keepalive.stop()
        self.position_sync_timer.stop()
        ws, self.ws = self.ws, None
        if ws:
            ws.close()
        self.send_button.setEnabled(False)
        self.disconnect_button.setEnabled(False)
        self.connect_button.setEnabled(True)
        self.bridge.state.emit("已主动断开")
        self.reset_world_state()
        self.update_map_buttons()

    def reset_world_state(self) -> None:
        if hasattr(self, "telemetry_timer"):
            self.telemetry_timer.stop()
        if hasattr(self, "move_timer"):
            self.move_timer.stop()
        if hasattr(self, "combat_timer"):
            self.combat_timer.stop()
        if hasattr(self, "potion_timer"):
            self.potion_timer.stop()
        if hasattr(self, "chase_timer"):
            self.chase_timer.stop()
        if hasattr(self, "patrol_timer"):
            self.patrol_timer.stop()
        if hasattr(self, "position_sync_timer"):
            self.position_sync_timer.stop()
        self.world_ready = False
        self.server_dead = False
        self.respawn_pending = False
        self.return_map_target = None
        self.quest_map_target = None
        self.quest_map_quest_id = None
        self.respawn_attempts = 0
        self.respawn_request_generation = getattr(self, "respawn_request_generation", 0) + 1
        self.current_map = None
        self.world_x = None
        self.world_y = None
        self.movement_revision = 0
        self.life = 0
        self.sequence = 0
        self.pending_destination = None
        self.pending_portal = None
        self.route_points = []
        self.position_estimated = False
        self.movement_trace = deque(maxlen=12)
        # Recovered client base: 105 * 1.15 * 1.15 * ACTION_SPEED_BOOST(1.2).
        self.movement_speed = 105.0 * 1.15 * 1.15 * 1.2
        self.welcome_at = None
        self.last_position_sync_at = None
        self.movement_sent_count = 0
        self.movement_corrections = 0
        self.last_move_at = None
        self.player_id = None
        self.monsters = {}
        self.last_self_state = {}
        self.last_progress_state = {}
        self._fatigue_exhaustion_handled = False
        self._quest_notification_state = None
        self._known_equipment_ids = None
        self.last_peers = []
        self.peer_cache = {}
        self.peer_last_seen = {}
        self.api_profile = {}
        self.api_equipment = {}
        self.profile_refresh_inflight = False
        self.profile_refreshed_at = 0.0
        self.profile_refresh_queued = False
        self.seen_monsters = set()
        self.next_attack = {}
        self.used_attack_tickets = set()
        self.claimed_encounters = set()
        self.last_attacked_monster = None
        self.last_attack_ticket = None
        self.attack_busy_until = 0.0
        self.pending_pings = {}
        self.last_rtt_ms = None
        self.combat_generation = getattr(self, "combat_generation", 0) + 1
        self.chase_target = None
        self.chase_route = []
        self.last_chase_at = None
        self.chase_retry_after = 0.0
        self.patrol_route = []
        self.patrol_anchor = None
        self.patrol_direction_index = 0
        self.patrol_ring = 320.0
        self.auto_route_retry_count = 0
        self.auto_potion_pending = False
        self.combat_stats = {"kills": 0, "damage": 0, "hits": 0, "potions": 0}
        self.patrol_last_at = None
        self.patrol_retry_after = 0.0
        self.invalid_target_until = {}
        if hasattr(self, "monster_table"):
            self.monster_table.setRowCount(0)
            self.combat_status.setText("等待服务端怪物快照和攻击票据…")
            self.update_attack_button()
        self.update_combat_stats()
        self.travel_attempt = getattr(self, "travel_attempt", 0) + 1
        if hasattr(self, "quest_table"):
            self.quest_table.setRowCount(0)
            self.quest_status.setText("等待服务端任务数据…")
        if hasattr(self, "resource_chips"):
            for key, label in self.resource_chips.items():
                title = {"healthPotions": "生命药水", "bossTickets": "遗迹入场券",
                         "atonementStones": "赎罪石", "townStones": "回城石", "evil": "恶名值"}[key]
                label.setText(f"{title}  —")
        if hasattr(self, "live_telemetry"):
            self.update_live_telemetry()

    def update_map_buttons(self) -> None:
        ready = self.ws is not None and self.world_ready and not self.server_dead and self.pending_destination is None
        if hasattr(self, "respawn_button"):
            self.respawn_button.setVisible(self.server_dead)
            self.respawn_button.setEnabled(self.ws is not None and self.server_dead and not self.respawn_pending)
            if self.respawn_pending:
                self.respawn_button.setText("正在回到城镇…")
            else:
                self.respawn_button.setText("回到城镇")
        self.stop_move_button.setEnabled(self.pending_destination is not None)
        for map_id, button in self.map_buttons.items():
            button.setEnabled(ready and map_id != self.current_map)
            route = map_id in MAP_ROUTES.get(self.current_map, ())
            button.setText(f"{map_id}  {MAP_NAMES[map_id].split(' · ')[-1]}")
            button.setProperty("currentMap", map_id == self.current_map)
            style = QApplication.style()
            style.unpolish(button)
            style.polish(button)
            button.setToolTip(MAP_NAMES[map_id] + (" · 相邻入口" if route else ""))
        if self.current_map is None:
            self.current_map_label.setText("等待进入地图")
            self.current_map_label.setToolTip("")
            self.world_status.setText("等待登录游戏世界…")
        else:
            map_name = MAP_NAMES.get(self.current_map, str(self.current_map))
            self.current_map_label.setText(f"当前所在地图  ·  {map_name.split(' · ')[-1]}")
            self.current_map_label.setToolTip(map_name)
            now = time.monotonic()
            # Keep predicted coordinates useful during travel without repainting
            # protocol counters on every movement tick.
            if (self.current_map != self.last_world_status_map
                    or now - self.last_world_status_render_at >= 2.0
                    or self.world_status.text().startswith("等待")):
                prefix = "预计坐标" if self.position_estimated else "坐标"
                self.world_status.setText(f"{prefix}：({self.world_x}, {self.world_y})")
                self.last_world_status_render_at = now
                self.last_world_status_map = self.current_map

    def accept_packet(self, packet: dict) -> None:
        kind = packet.get("type")
        if kind == "pong":
            self.last_pong_received_at = time.monotonic()
            try:
                sent_at = int(packet.get("sentAt"))
                started = self.pending_pings.pop(sent_at, None)
                if started is not None:
                    self.last_rtt_ms = max(0, round((time.monotonic() - started) * 1000))
            except (TypeError, ValueError):
                pass
            self.update_live_telemetry()
            latency_callback = getattr(self, "on_latency_change", None)
            if callable(latency_callback):
                latency_callback()
        elif kind == "error" and packet.get("code") == "login_required":
            self.auth_rejected = True
            self.bridge.state.emit("服务器拒绝登录凭证…")
            self.append_log("服务端拒绝游戏会话 Token：login_required。")
        elif kind == "welcome" and isinstance(packet.get("position"), dict):
            self.welcome_at = time.monotonic()
            position = packet["position"]
            self.current_map = int(position.get("map", 1))
            self.world_x = position.get("x")
            self.world_y = position.get("y")
            self.position_estimated = False
            self.movement_revision = int(position.get("revision", 0))
            self.update_map_buttons()
        elif kind == "snapshot" and self.current_map is not None:
            operation = str(packet.get("action", "snapshot"))
            progress = packet.get("progress")
            if isinstance(progress, dict):
                self.last_progress_state = dict(progress)
            if isinstance(progress, dict) and isinstance(progress.get("quests"), list):
                self.update_quests(progress["quests"])
            self_state = packet.get("self")
            detected_death = False
            if isinstance(self_state, dict):
                # Match accept_snapshot in pvp_client.gd: self is a partial
                # object in delta snapshots, including the common empty {}.
                previous_potions = self.last_self_state.get("healthPotions")
                if not bool(packet.get("delta", False)):
                    self.last_self_state.clear()
                self.last_self_state.update(self_state)
                self_state = self.last_self_state
                current_potions = self_state.get("healthPotions")
                if isinstance(previous_potions, (int, float)) and isinstance(current_potions, (int, float)):
                    used = max(0, int(previous_potions) - int(current_potions))
                    if used:
                        self.combat_stats["potions"] += used
                        self.update_combat_stats()
                        self.auto_potion_pending = False
                try:
                    if int(self_state.get("potionCooldownMs", 0) or 0) > 0:
                        self.auto_potion_pending = False
                except (TypeError, ValueError):
                    pass
                # A respawn acknowledgement carries the authoritative spawn
                # position; a delta may omit dead=False from its self object.
                if operation == "respawn" and isinstance(packet.get("position"), dict):
                    self_state["dead"] = False
                self.server_dead = bool(self_state.get("dead", False))
                if hasattr(self, "combat_mode") and "combatMode" in self_state:
                    try:
                        mode_index = max(0, min(2, int(self_state.get("combatMode", 0))))
                    except (TypeError, ValueError):
                        mode_index = 0
                    self.combat_mode.blockSignals(True)
                    self.combat_mode.setCurrentIndex(mode_index)
                    self.combat_mode.blockSignals(False)
                    try:
                        unlock = int(self_state.get("modeRemaining", 0) or 0)
                    except (TypeError, ValueError):
                        unlock = 0
                    self.mode_status.setText(f"当前：{('和平', '战斗', '仇杀')[mode_index]}" +
                                             (f" · 冷却 {unlock} 秒" if unlock > 0 else "") +
                                             (f" · 公会 #{self_state['guildId']}" if self_state.get("guildId") else ""))
                    self.update_mode_control(unlock)
                self.refresh_character_status()
                self.handle_fatigue_state(self_state)
                if self.manual_disconnect:
                    return
                if self.server_dead:
                    detected_death = not self.respawn_pending and self.respawn_attempts < 3
                    self.move_timer.stop()
                    self.stop_chase()
                    self.stop_patrol(reset_anchor=True)
                    self.position_sync_timer.stop()
                    self.combat_timer.stop()
                elif operation == "respawn":
                    self.respawn_pending = False
                    self.respawn_attempts = 0
                    self.respawn_request_generation += 1
                    self.pending_destination = None
                    self.pending_portal = None
                    self.route_points = []
                    self.travel_attempt += 1
                    self.combat_generation += 1
                    self.used_attack_tickets.clear()
                    self.attack_busy_until = 0.0
                    position = packet.get("position")
                    if isinstance(position, dict):
                        self.current_map = int(position.get("map", 1))
                        self.world_x = position.get("x", self.world_x)
                        self.world_y = position.get("y", self.world_y)
                        self.movement_revision = int(position.get("revision", self.movement_revision))
                    self.movement_corrections = 0
                    self.position_estimated = False
                    self.position_sync_timer.start()
                    self.travel_status.setText("已回到城镇，服务端确认复活位置。")
                    if self.auto_attack.isChecked():
                        self.combat_timer.start()
                    self.refresh_profile_data()
                    if self.auto_return_map.isChecked():
                        self.return_map_target = self.return_map.currentData()
                        QTimer.singleShot(500, self.continue_return_map)
                    elif self.questless_farm_mode:
                        QTimer.singleShot(500, self.continue_quest_map_travel)
            if isinstance(self_state, dict) and "life" in self_state:
                self.life = int(self_state["life"])
            if isinstance(self_state, dict) and isinstance(self_state.get("nextAttack"), dict):
                self.accept_attack_ticket(self_state["nextAttack"])
            self.update_monsters(packet)
            for reward in packet.get("rewards", []):
                if isinstance(reward, dict) and reward.get("EncounterID"):
                    encounter_id = str(reward["EncounterID"])
                    if encounter_id == self.last_attacked_monster:
                        self.combat_status.setText(f"收到击败奖励事件：{encounter_id}；正在同步经验与任务进度…")
                    if encounter_id not in self.claimed_encounters:
                        self.claimed_encounters.add(encounter_id)
                        self.combat_stats["kills"] += 1
                        self.update_combat_stats()
                        self.claim_encounter_reward(encounter_id)
            if not self.world_ready:
                self.world_ready = True
                self._auth_retry_attempted = False
                self.append_log("游戏世界已就绪；后续高频 snapshot 已折叠。")
                self.keepalive.start()
                self.telemetry_timer.start()
                self.send_stationary_sync(force=True)
                self.position_sync_timer.start()
                if self.auto_attack.isChecked() and not self.server_dead:
                    self.combat_timer.start()
                if self.auto_potion.isChecked():
                    self.potion_timer.start()
                if self.questless_farm_mode:
                    QTimer.singleShot(500, self.continue_quest_map_travel)
                self.refresh_social_data()
            self.update_map_buttons()
            if detected_death:
                self.travel_status.setText("检测到角色阵亡，正在自动请求回到城镇…")
                QTimer.singleShot(0, self.request_respawn)
            peers = packet.get("peers")
            if isinstance(peers, list):
                self.merge_nearby_players(peers)
            else:
                self.expire_nearby_players()
            self.update_nearby_players(self.last_peers)
            self.minimap.update()
            self.update_live_telemetry()
        elif kind == "travel_result":
            self.move_timer.stop()
            self.stop_chase()
            self.stop_patrol(reset_anchor=True)
            destination = self.pending_destination
            self.pending_destination = None
            self.pending_portal = None
            self.route_points = []
            if packet.get("ok"):
                self.auto_route_retry_count = 0
                if destination is not None:
                    self.current_map = destination
                self.world_x = packet.get("x", self.world_x)
                self.world_y = packet.get("y", self.world_y)
                self.movement_revision = int(packet.get("revision", self.movement_revision))
                self.position_estimated = False
                self.refresh_monster_table()
                self.travel_status.setText(f"已进入 {MAP_NAMES.get(self.current_map, str(self.current_map))}；服务端已确认。")
            else:
                reason = packet.get("reason", "未知原因")
                retry = packet.get("retryAfter")
                position = packet.get("position")
                if isinstance(position, dict) and int(position.get("map", self.current_map or 1)) == self.current_map:
                    self.world_x = position.get("x", self.world_x)
                    self.world_y = position.get("y", self.world_y)
                    self.movement_revision = int(position.get("revision", self.movement_revision))
                    self.position_estimated = False
                self.travel_status.setText(f"入图被拒绝：{reason}" + (f"；{retry} 秒后可重试" if retry else ""))
            self.update_map_buttons()
            if packet.get("ok") and self.return_map_target is not None:
                QTimer.singleShot(500, self.continue_return_map)
            elif packet.get("ok") and (self.quest_map_target is not None or self.questless_farm_mode):
                QTimer.singleShot(500, self.continue_quest_map_travel)
            elif not packet.get("ok"):
                self.schedule_auto_travel_retry()
            if not packet.get("ok") and not self.has_auto_travel_intent():
                self.return_map_target = None
                self.quest_map_target = None
                self.quest_map_quest_id = None
        elif kind == "chat":
            self.append_social_chat(packet.get("messages", []))
        elif kind == "scoped_chat":
            self.append_social_chat(packet.get("message", {}), str(packet.get("channel", "附近")))
        elif kind == "chat_ack":
            code = str(packet.get("code", ""))
            if code:
                self.social_chat_log.appendPlainText(f"[系统] 消息状态：{code}")
        elif kind == "attack_ready" and isinstance(packet.get("nextAttack"), dict):
            self.accept_attack_ticket(packet["nextAttack"])
        elif kind == "hit" and isinstance(packet.get("hit"), dict):
            hit = packet["hit"]
            encounter_id = str(hit.get("monster", ""))
            if encounter_id and self.player_id is not None:
                try:
                    if int(packet.get("attacker", -1)) == self.player_id:
                        self.combat_stats["hits"] += 1
                        try:
                            self.combat_stats["damage"] += max(0, int(hit.get("damage", 0)))
                        except (TypeError, ValueError):
                            pass
                        self.update_combat_stats()
                        monster = self.monsters.get(encounter_id)
                        if monster and "health" in monster:
                            monster["health"] = max(0, int(monster["health"]) - int(hit.get("damage", 0)))
                            self.refresh_monster_table()
                except (TypeError, ValueError):
                    pass
            if hit.get("monster") == self.last_attacked_monster:
                self.set_combat_feedback(
                    f"命中 {hit['monster']}：伤害 {hit.get('damage', '?')}"
                    + (" · 暴击" if hit.get("critical") else ""),
                    "critical" if hit.get("critical") else "hit",
                )
            self.update_live_telemetry()
            self.refresh_profile_data()
        elif kind == "error" and self.is_quest_limit_response(packet):
            self.handle_quest_limit_reached(self.quest_error_text(packet))
        elif kind == "error" and packet.get("action") == "monsterAttack":
            code = str(packet.get("code", "未知错误"))
            rejected_id = self.last_attacked_monster
            # invalid_target does not consume the ticket. The server may return
            # the same nextAttack id, so release the local reservation first.
            if self.last_attack_ticket:
                self.used_attack_tickets.discard(self.last_attack_ticket)
                self.last_attack_ticket = None
            if code == "invalid_target" and rejected_id:
                self.invalid_target_until[rejected_id] = time.monotonic() + 15.0
                monster = self.monsters.get(rejected_id, {})
                distance = self.monster_distance(monster) if monster else math.inf
                # Do not invent a death locally. Compact snapshots may not
                # resend an unchanged living monster, so setting health=0
                # here could hide it forever. Skip it temporarily instead.
                self.set_combat_feedback(
                    f"目标 {rejected_id[:8]} 已不被服务端接受（可能刚被击败或离开攻击范围）；"
                    f"暂时跳过 15 秒。当前记录距离 {distance:.0f}。", "error"
                )
                self.append_log(f"攻击目标诊断：invalid_target；id={rejected_id}；距离={distance:.1f}；"
                                f"地图={self.current_map}；本地血量={monster.get('health', '?')}")
            elif code == "attack_cooldown":
                # The server returns the same unconsumed ticket while its
                # cooldown is active. Avoid immediately restarting another
                # attack animation with that ticket.
                self.attack_busy_until = max(self.attack_busy_until, time.monotonic() + 0.62)
                self.combat_status.setText("服务端仍在攻击冷却；保留票据，稍后再试。")
            else:
                self.set_combat_feedback(f"攻击被拒绝：{code}", "error")
            if isinstance(packet.get("nextAttack"), dict):
                self.accept_attack_ticket(packet["nextAttack"])
        elif kind == "error" and packet.get("code") in ("movement_too_fast", "invalid_position", "combat_locked"):
            position = packet.get("position")
            if isinstance(position, dict):
                try:
                    server_revision = int(position.get("revision", self.movement_revision))
                except (TypeError, ValueError):
                    server_revision = self.movement_revision
                # Delayed movement errors can arrive after a newer correction.
                # Never roll the local revision and coordinates backwards.
                if server_revision < self.movement_revision:
                    self.append_log(
                        f"忽略过期移动纠正：服务端修订 {server_revision}，当前修订 {self.movement_revision}。"
                    )
                    return
            predicted = (self.world_x, self.world_y)
            revision_before = self.movement_revision
            trace = list(self.movement_trace)
            destination = self.pending_destination
            chase_target = self.chase_target
            self.move_timer.stop()
            self.stop_chase()
            position = packet.get("position")
            if isinstance(position, dict):
                self.current_map = int(position.get("map", self.current_map or 1))
                self.world_x = position.get("x", self.world_x)
                self.world_y = position.get("y", self.world_y)
                self.movement_revision = int(position.get("revision", self.movement_revision))
                self.position_estimated = False
                try:
                    gap = math.dist((float(predicted[0]), float(predicted[1])),
                                    (float(self.world_x), float(self.world_y)))
                    correction = f"预计 {predicted} → 服务端 ({self.world_x}, {self.world_y})，偏差 {gap:.2f}"
                except (TypeError, ValueError):
                    correction = f"预计 {predicted} → 服务端 ({self.world_x}, {self.world_y})"
                self.append_log(f"移动纠正诊断：{packet.get('code')}；{correction}；修订 {revision_before} → {self.movement_revision}")
                if trace:
                    self.append_log("最近移动帧（距 welcome 秒/坐标/修订/seq/life）：" + json.dumps(trace, ensure_ascii=False))
                self.movement_trace.clear()
            was_patrolling = self.patrol_timer.isActive()
            retry_movement = (packet.get("code") == "movement_too_fast"
                              and isinstance(position, dict)
                              and (destination is not None or chase_target is not None))
            if retry_movement:
                self.movement_corrections += 1
            can_retry = retry_movement and self.movement_corrections <= 3
            if destination is not None:
                reason = packet.get("code")
                self.pending_destination = None
                self.pending_portal = None
                self.route_points = []
                self.travel_attempt += 1
                if reason == "invalid_position":
                    message = "移动路径遇到不可走区域；已停止并恢复服务端坐标。"
                elif can_retry:
                    message = f"服务端纠正位置；将从 ({self.world_x}, {self.world_y}) 重新寻路（{self.movement_corrections}/3）。"
                elif reason == "movement_too_fast":
                    message = "连续 4 次被服务端纠正；已停止。当前会话的位置同步仍未被接受。"
                else:
                    message = "当前处于战斗移动限制；已停止并恢复服务端坐标。"
                self.travel_status.setText(message)
            if chase_target is not None:
                reason = str(packet.get("code", ""))
                if reason == "invalid_position":
                    self.invalid_target_until[chase_target] = time.monotonic() + 15.0
                    self.movement_corrections = 0
                    self.chase_retry_after = time.monotonic() + 0.25
                    self.combat_status.setText(
                        f"去往 {chase_target[:8]} 的路线被服务端判为不可通行；已恢复服务端坐标并暂时跳过，继续找其他怪物。"
                    )
                else:
                    # Don't race an immediate auto_attack_tick against a
                    # separate recovery timer. Let the combat timer resume
                    # after the in-flight sync frames have drained.
                    self.invalid_target_until[chase_target] = time.monotonic() + 6.0
                    self.chase_retry_after = time.monotonic() + 2.0
                    self.movement_corrections = 0
                    self.combat_status.setText(
                        f"追击位置被服务端纠正；已恢复服务端坐标并暂时跳过 {chase_target[:8]}，继续搜索。"
                    )
            if was_patrolling:
                # Keep the search anchor/direction cursor so the next pass
                # tries a different waypoint after the server rejects one.
                self.stop_patrol()
                self.patrol_retry_after = time.monotonic() + 1.5
                self.combat_status.setText("巡逻路线被服务端拒绝；已恢复服务器坐标，稍后换方向继续搜索。")
            self.update_map_buttons()
            if destination is None and chase_target is None and packet.get("code") == "movement_too_fast":
                self.travel_status.setText("原地位置同步也被服务端拒绝；当前没有移动目标。请查看纠正诊断日志。")
            if can_retry and destination is not None:
                QTimer.singleShot(500, lambda target=destination: self.travel_to(target, recovery=True))
            elif destination is not None:
                self.schedule_auto_travel_retry()

    def update_quests(self, quests: list) -> None:
        rows = [quest for quest in quests if isinstance(quest, dict)]
        current_states = {}
        for quest in rows:
            quest_id = str(quest.get("id", quest.get("questId", "")))
            if quest_id:
                current_states[quest_id] = bool(quest.get("completed"))
        previous_states = self._quest_notification_state
        if previous_states is not None:
            for quest in rows:
                quest_id = str(quest.get("id", quest.get("questId", "")))
                if (quest_id and quest.get("completed") and
                        not previous_states.get(quest_id, False)):
                    title = str(quest.get("titleZh") or quest.get("title") or f"任务 {quest_id}")
                    map_id = quest.get("mapId")
                    try:
                        map_name = MAP_NAMES.get(int(map_id), str(map_id)) if map_id is not None else "未指定地图"
                    except (TypeError, ValueError):
                        map_name = str(map_id)
                    self.send_lark_notification("任务完成", f"**{title}**\n\n完成地图：{map_name}\n任务编号：{quest_id}", "green", "quest")
        if previous_states is None:
            self._quest_notification_state = current_states
        else:
            previous_states.update(current_states)
        self.latest_quests = rows
        for quest in rows:
            if (quest.get("mapId") is not None and
                    (quest.get("accepted") or quest.get("completed"))):
                try:
                    map_id = int(quest["mapId"])
                    if map_id in MAP_NAMES:
                        self.last_quest_map = map_id
                except (TypeError, ValueError):
                    pass
        self.quest_table.setRowCount(len(rows))
        self.quest_table.setVisible(True)
        for index, quest in enumerate(rows):
            done = bool(quest.get("completed"))
            accepted = bool(quest.get("accepted"))
            available = bool(quest.get("available"))
            state = "已完成" if done else "进行中" if accepted else "可接取" if available else "未解锁"
            map_id = quest.get("mapId")
            try:
                map_name = MAP_NAMES.get(int(map_id), str(map_id)) if map_id is not None else "—"
            except (TypeError, ValueError):
                map_name = str(map_id) if map_id is not None else "—"
            values = [str(quest.get("id", "—")), str(quest.get("titleZh") or quest.get("title") or "未命名任务"),
                      map_name, f"{quest.get('progress', 0)}/{quest.get('target', '—')}", state]
            rewards = (f"经验 {quest.get('rewardExperience', 0)} · 金币 {quest.get('rewardGold', 0)}"
                       f" · 药水 {quest.get('rewardPotions', 0)}")
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(rewards)
                self.quest_table.setItem(index, col, item)
        active = sum(bool(q.get("accepted")) and not bool(q.get("completed")) for q in rows)
        self.quest_status.setText(f"服务端任务 {len(rows)} 条 · 进行中 {active} 条 · 悬停可看奖励" if rows else "服务端暂未下发任务。")
        self.refresh_quest_map_target()
        if self.task_limited_mode.isChecked():
            if self.has_active_monster_quest():
                self.questless_farm_mode = False
                self.questless_farm_target = None
                if self.auto_attack.isChecked() and self.world_ready and not self.server_dead:
                    self.combat_timer.start()
                self.combat_status.setText("任务有限模式：只攻击当前任务所需怪物。")
            else:
                self.combat_timer.stop()
                self.stop_chase()
                self.combat_generation += 1
                self.questless_farm_mode = False
                self.questless_farm_target = None
                self.combat_status.setText("任务有限模式：没有进行中的怪物任务，自动攻击已暂停。")
        if not active and hasattr(self, "auto_quest") and self.auto_quest.isChecked():
            self.accept_next_monster_quest()

    def save_lark_webhook(self, value: str) -> None:
        webhook = value.strip()
        if webhook:
            self.settings.setValue("larkWebhook", webhook)
        else:
            self.settings.remove("larkWebhook")
        self.settings.sync()
        self.update_lark_status(webhook)

    def update_lark_status(self, value: str) -> None:
        configured = bool(value.strip())
        self.lark_status.setText("已保存 · 本机" if configured else "未配置")
        self.lark_status.setStyleSheet("color:#75D5A6;" if configured else "")

    def on_shop_notification(self, event_key: str, title: str, detail: str) -> None:
        self.send_lark_notification(title, detail, "green", event_key)

    def send_lark_notification(self, title: str, detail: str, color: str = "blue",
                               event_key: str | None = None) -> None:
        if event_key:
            checkbox = getattr(self, "notification_preferences", {}).get(event_key)
            if checkbox is None or not checkbox.isChecked():
                return
        webhook = self.lark_webhook.text().strip() if hasattr(self, "lark_webhook") else ""
        if not webhook:
            return
        try:
            parsed = urllib.parse.urlsplit(webhook)
        except ValueError:
            self.bridge.notification_result.emit(title, False, "Webhook 地址格式无效，请检查 Lark 地址。")
            return
        if (parsed.scheme != "https" or parsed.hostname != "open.larksuite.com"
                or not parsed.path.startswith("/open-apis/bot/v2/hook/") or parsed.query or parsed.fragment):
            self.bridge.notification_result.emit(title, False, "Webhook 地址格式无效，请检查 Lark 地址。")
            return
        safe_color = color if color in {"blue", "green", "orange", "red"} else "blue"
        character_name = self.character_facts.get("角色") if hasattr(self, "character_facts") else None
        character_name = character_name.text() if character_name else "Tabby 角色"
        timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        card = {
            "msg_type": "interactive",
            "card": {
                "config": {"wide_screen_mode": True},
                "header": {
                    "template": safe_color,
                    "title": {"tag": "plain_text", "content": f"🎮 {title}"},
                },
                "elements": [
                    {"tag": "div", "text": {"tag": "lark_md", "content": detail}},
                    {"tag": "hr"},
                    {"tag": "note", "elements": [
                        {"tag": "plain_text", "content": f"{character_name}  ·  Tabby Desktop  ·  {timestamp}"}
                    ]},
                ],
            },
        }

        def worker() -> None:
            try:
                request = urllib.request.Request(
                    webhook, data=json.dumps(card, ensure_ascii=False).encode("utf-8"),
                    headers={"Content-Type": "application/json; charset=utf-8"}, method="POST")
                with urllib.request.urlopen(request, timeout=8) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                if isinstance(payload, dict) and payload.get("code", 0) not in (0, None):
                    self.bridge.notification_result.emit(title, False, "Lark 接收通知失败，请检查机器人配置。")
                else:
                    self.bridge.notification_result.emit(title, True, "")
            except urllib.error.HTTPError as exc:
                self.bridge.notification_result.emit(title, False, f"Lark 请求失败（HTTP {exc.code}）。")
            except Exception as exc:
                # Never include exception text: urllib errors can contain the full webhook URL.
                self.bridge.notification_result.emit(title, False, f"Lark 通知发送失败（{type(exc).__name__}）。")

        threading.Thread(target=worker, daemon=True).start()

    def on_notification_result(self, title: str, success: bool, error: str) -> None:
        if success:
            self.lark_status.setText(f"已发送：{title}")
            self.lark_status.setStyleSheet("color:#75D5A6;")
        else:
            self.lark_status.setText(error or "发送失败")
            self.lark_status.setStyleSheet("color:#E78178;")

    def handle_fatigue_state(self, self_state: dict) -> None:
        farming = self_state.get("farming") if isinstance(self_state, dict) else None
        if not isinstance(farming, dict) or "staminaPercent" not in farming:
            return
        try:
            stamina = float(farming["staminaPercent"])
        except (TypeError, ValueError):
            return
        if stamina > 0 or self._fatigue_exhaustion_handled:
            return
        self._fatigue_exhaustion_handled = True
        self.send_lark_notification(
            "疲劳值已耗尽", "当前角色疲劳已降至 **0%**。" +
            ("\n\n已按设置断开连接并退出当前登录。" if self.logout_on_fatigue.isChecked() else "\n\n游戏连接保持开启。"),
            "orange", "fatigue")
        if self.logout_on_fatigue.isChecked():
            self.logout_for_fatigue()

    def logout_for_fatigue(self) -> None:
        self.session_token = ""
        self.signed_session_token = ""
        self._resolved_token = ""
        self.token.clear()
        self.disconnect_ws()
        self.status.setText("疲劳耗尽 · 已退出登录")
        self.travel_status.setText("疲劳已耗尽，已断开游戏并退出当前登录；请手动重新登录。")

    @staticmethod
    def equipment_identity(item: dict) -> str:
        for key in ("playerItemId", "playerEquipmentId", "inventoryItemId", "id"):
            value = item.get(key)
            if value is not None and str(value):
                return f"{key}:{value}"
        return hashlib.sha256(json.dumps(item, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")).hexdigest()

    def notify_new_equipment(self, equipment: dict) -> None:
        items = equipment.get("items", [])
        if not isinstance(items, list):
            return
        current = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("itemKind", item.get("kind", ""))).upper()
            slot = str(item.get("slotType", item.get("equipmentType", ""))).upper()
            if "EQUIP" not in kind and slot not in SLOT_NAMES_ZH:
                continue
            current[self.equipment_identity(item)] = item
        if self._known_equipment_ids is not None:
            for identity, item in current.items():
                if identity in self._known_equipment_ids:
                    continue
                name = str(item.get("itemNameZh") or item.get("itemName") or item.get("name") or item.get("itemCode") or "新装备")
                slot = str(item.get("slotType") or item.get("equipmentType") or "装备")
                quality = str(item.get("qualityNameZh") or item.get("quality") or item.get("equipmentLevel") or "")
                attributes = " · ".join(equipment_attribute_lines(item))
                detail = f"获得新装备：**{name}**\n\n部位：{SLOT_NAMES_ZH.get(slot.upper(), slot)}"
                if quality:
                    detail += f"\n品质：{quality}"
                if attributes:
                    detail += f"\n属性：{attributes}"
                self.send_lark_notification("装备掉落", detail, "green", "equipment")
        self._known_equipment_ids = set(current)

    def has_active_monster_quest(self) -> bool:
        for quest in self.latest_quests:
            if not isinstance(quest, dict) or not quest.get("accepted") or quest.get("completed"):
                continue
            if quest.get("objectiveType") != "MONSTER":
                continue
            try:
                progress = float(quest.get("progress", 0))
                target = float(quest.get("target", math.inf))
            except (TypeError, ValueError):
                progress, target = 0, math.inf
            if progress < target:
                return True
        return False

    def monster_matches_active_quest(self, monster: dict) -> bool:
        if not self.task_limited_mode.isChecked():
            return True
        for quest in self.latest_quests:
            if (not isinstance(quest, dict) or not quest.get("accepted") or quest.get("completed")
                    or quest.get("objectiveType") != "MONSTER"):
                continue
            try:
                if float(quest.get("progress", 0)) >= float(quest.get("target", math.inf)):
                    continue
                quest_map = quest.get("mapId")
                if quest_map is None or int(quest_map) == int(monster.get("mapId", -1)):
                    return True
            except (TypeError, ValueError):
                continue
        return False

    def on_task_limited_mode_changed(self, enabled: bool) -> None:
        if enabled:
            was_free_farming = self.questless_farm_mode
            self.questless_farm_mode = False
            self.questless_farm_target = None
            self.quest_map_target = None
            self.quest_map_quest_id = None
            if was_free_farming and (self.pending_destination is not None or self.move_timer.isActive()):
                self.cancel_travel()
            if not self.has_active_monster_quest():
                self.combat_timer.stop()
                self.stop_chase()
                self.combat_generation += 1
                self.combat_status.setText("任务有限模式：等待当前怪物任务或自动接取下一项。")
            elif self.auto_attack.isChecked() and self.world_ready and not self.server_dead:
                self.combat_timer.start()
                self.combat_status.setText("任务有限模式：只攻击当前任务所需怪物。")
        elif self.auto_attack.isChecked() and self.world_ready and not self.server_dead:
            self.combat_timer.start()

    def on_quest_map_auto_changed(self, *_args) -> None:
        self.refresh_quest_map_target()

    def refresh_quest_map_target(self) -> None:
        if self.questless_farm_mode:
            self.quest_map_target = None
            self.quest_map_quest_id = None
            return
        if not getattr(self, "quest_map_auto", None) or not self.quest_map_auto.isChecked():
            self.quest_map_target = None
            self.quest_map_quest_id = None
            return
        active = [q for q in self.latest_quests
                  if q.get("accepted") and not q.get("completed") and q.get("mapId") is not None]
        if not active:
            self.quest_map_target = None
            self.quest_map_quest_id = None
            return
        quest = sorted(active, key=lambda q: q.get("objectiveType") != "MONSTER")[0]
        try:
            target = int(quest["mapId"])
        except (TypeError, ValueError):
            return
        if target not in MAP_NAMES:
            return
        self.quest_map_target = target
        try:
            self.quest_map_quest_id = int(quest.get("id"))
        except (TypeError, ValueError):
            self.quest_map_quest_id = None
        if self.world_ready and self.current_map != target:
            QTimer.singleShot(0, self.continue_quest_map_travel)
        elif self.current_map == target:
            self.quest_map_target = None
            self.quest_map_quest_id = None

    def continue_quest_map_travel(self) -> None:
        farm_fallback = self.questless_farm_mode and self.questless_farm_target is not None
        if ((not self.quest_map_auto.isChecked() and not farm_fallback)
                or (self.quest_map_target is None and not farm_fallback)
                or self.world_ready is False or self.current_map is None
                or self.server_dead or self.respawn_pending or self.pending_destination is not None
                or self.return_map_target is not None):
            return
        target = self.quest_map_target if self.quest_map_target is not None else self.questless_farm_target
        if self.current_map == target:
            self.quest_map_target = None
            self.quest_map_quest_id = None
            return
        queue = deque([(self.current_map, [])])
        visited = {self.current_map}
        route = None
        while queue:
            current, hops = queue.popleft()
            for neighbor in MAP_ROUTES.get(current, ()):
                if neighbor in visited:
                    continue
                next_hops = hops + [neighbor]
                if neighbor == target:
                    route = next_hops
                    queue.clear()
                    break
                visited.add(neighbor)
                queue.append((neighbor, next_hops))
        if not route:
            self.travel_status.setText(f"找不到通往任务地图 {MAP_NAMES[target]} 的入口路线。")
            self.quest_map_target = None
            self.quest_map_quest_id = None
            return
        if 5 in route and not self.use_ticket.isChecked():
            self.travel_status.setText("任务目标在废弃遗迹；请先勾选使用入场券。")
            return
        if farm_fallback:
            self.travel_status.setText(f"今日任务已领满，自动前往 {MAP_NAMES[target]} 巡图刷怪；下一站 {MAP_NAMES[route[0]]}。")
        else:
            self.travel_status.setText(f"按当前任务前往 {MAP_NAMES[target]}，下一站 {MAP_NAMES[route[0]]}。")
        self.travel_to(route[0])

    def has_auto_travel_intent(self) -> bool:
        return (self.return_map_target is not None
                or self.quest_map_target is not None
                or (self.questless_farm_mode and self.questless_farm_target is not None))

    def schedule_auto_travel_retry(self) -> None:
        if not self.has_auto_travel_intent() or self.auto_route_retry_count >= 2:
            if self.has_auto_travel_intent():
                self.travel_status.setText(self.travel_status.text() + "；自动重规划已达上限，请手动选择地图或重新点一次")
            return
        self.auto_route_retry_count += 1
        retry_number = self.auto_route_retry_count
        self.travel_status.setText(self.travel_status.text() + f"；{2 * retry_number} 秒后重新规划（{retry_number}/2）")

        def retry() -> None:
            if self.pending_destination is not None or not self.world_ready:
                return
            if self.return_map_target is not None:
                self.continue_return_map()
            elif self.has_auto_travel_intent():
                self.continue_quest_map_travel()

        QTimer.singleShot(2000 * retry_number, retry)

    def accept_next_monster_quest(self) -> None:
        today = datetime.now().date()
        if self.quest_accept_blocked_date is not None and self.quest_accept_blocked_date != today:
            self.quest_accept_blocked_date = None
            self.questless_farm_mode = False
            self.questless_farm_target = None
        if self.quest_accept_blocked_date == today:
            return
        if (not self.world_ready or self.quest_accept_inflight or
                time.monotonic() - self.quest_accept_checked_at < 15.0):
            return
        token = self.get_session_token()
        parsed = urllib.parse.urlsplit(self.url.text().strip())
        if not token or not parsed.netloc:
            return
        path = parsed.path.rstrip("/")
        if path.endswith("/realtime"):
            path = path[:-len("/realtime")]
        root = urllib.parse.urlunsplit(("https" if parsed.scheme == "wss" else "http",
                                       parsed.netloc, path + "/progression", "", ""))
        current_map = self.current_map
        self.quest_accept_inflight = True
        self.quest_accept_checked_at = time.monotonic()

        def worker() -> None:
            result = {"questRefresh": True}
            def request(endpoint: str, body=None):
                headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
                raw = None
                if body is not None:
                    raw = json.dumps(body).encode("utf-8")
                    headers["Content-Type"] = "application/json"
                req = urllib.request.Request(root + endpoint, data=raw, headers=headers,
                                             method="POST" if body is not None else "GET")
                with urllib.request.urlopen(req, timeout=8) as response:
                    return json.loads(response.read().decode("utf-8"))
            try:
                payload = request("/quests")
                quests = payload.get("quests", []) if isinstance(payload, dict) else []
                active = any(q.get("accepted") and not q.get("completed")
                             for q in quests if isinstance(q, dict))
                candidates = [q for q in quests if isinstance(q, dict) and q.get("available")
                              and not q.get("accepted") and not q.get("completed")
                              and q.get("objectiveType") == "MONSTER"]
                if not active and candidates:
                    candidates.sort(key=lambda q: q.get("mapId") != current_map)
                    chosen = candidates[0]
                    try:
                        accepted = request("/quests/accept", {"questId": chosen["id"]})
                    except urllib.error.HTTPError as exc:
                        body = exc.read().decode("utf-8", errors="replace")
                        try:
                            error_payload = json.loads(body)
                        except (TypeError, ValueError):
                            error_payload = body
                        if self.is_quest_limit_response(error_payload):
                            result["questLimitReached"] = True
                            result["questError"] = self.quest_error_text(error_payload) or str(exc)
                        else:
                            raise
                    else:
                        if self.is_quest_limit_response(accepted):
                            result["questLimitReached"] = True
                            result["questError"] = self.quest_error_text(accepted)
                        else:
                            result["acceptedQuestId"] = chosen["id"]
                        payload = request("/quests")
                result["questData"] = payload
            except Exception as exc:
                result["questError"] = f"{type(exc).__name__}: {exc}"
            self.bridge.profile.emit(result)
        threading.Thread(target=worker, daemon=True).start()

    @staticmethod
    def quest_error_text(value) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            for key in ("message", "error", "reason", "code", "detail"):
                item = value.get(key)
                if isinstance(item, (str, int, float)) and str(item).strip():
                    return str(item)
            return json.dumps(value, ensure_ascii=False)
        return str(value) if value is not None else ""

    @classmethod
    def is_quest_limit_response(cls, value) -> bool:
        if isinstance(value, dict):
            text = " ".join(str(item) for item in value.values()).casefold()
        elif isinstance(value, (list, tuple)):
            text = " ".join(str(item) for item in value).casefold()
        else:
            text = cls.quest_error_text(value).casefold()
        markers = (
            "任务领取已满", "领取已满", "每日任务上限", "任务领取上限",
            "今日任务已达上限", "今日可领取任务已达上限",
            "daily quest limit", "quest limit reached", "daily limit reached",
            "quest_accept_limit", "quest_acceptance_limit", "daily_quest_limit",
            "quest_daily_limit", "daily_task_limit", "daily_quest_cap",
        )
        return any(marker.casefold() in text for marker in markers)

    def handle_quest_limit_reached(self, detail: str = "") -> None:
        self.quest_accept_blocked_date = datetime.now().date()
        if self.task_limited_mode.isChecked():
            if self.questless_farm_mode and (self.pending_destination is not None or self.move_timer.isActive()):
                self.cancel_travel()
            self.questless_farm_mode = False
            self.questless_farm_target = None
            self.quest_map_target = None
            self.quest_map_quest_id = None
            self.combat_timer.stop()
            self.stop_chase()
            self.combat_generation += 1
            explanation = "今日任务领取已满；任务有限模式已暂停自动战斗，不会切换为自由刷怪。"
            if detail:
                explanation += f" 服务端：{detail}"
            self.quest_status.setText(explanation)
            self.combat_status.setText("任务有限模式：今日任务额度已用完，自动攻击已暂停。")
            self.append_log(explanation)
            return
        self.questless_farm_mode = True
        self.quest_map_target = None
        self.quest_map_quest_id = None
        # Keep farming in the last quest zone when known; otherwise use the
        # selected post-respawn map (Northern Snowfield by default).
        target = self.last_quest_map
        if target is None:
            try:
                target = int(self.return_map.currentData())
            except (TypeError, ValueError):
                target = 2
        if target not in MAP_NAMES or target == 1 or (target == 5 and not self.use_ticket.isChecked()):
            target = 2
        self.questless_farm_target = target
        self.auto_attack.setChecked(True)
        explanation = "今日任务领取已满，已切换为无任务刷怪模式。"
        if detail:
            explanation += f" 服务端：{detail}"
        explanation += f" 刷怪地图：{MAP_NAMES[target]}。"
        self.quest_status.setText(explanation)
        self.append_log(explanation)
        if (self.world_ready and not self.server_dead and not self.respawn_pending
                and self.current_map is not None and self.current_map != target):
            QTimer.singleShot(0, self.continue_quest_map_travel)
        elif self.current_map == target:
            self.travel_status.setText(f"今日任务已领满，留在 {MAP_NAMES[target]} 自动巡图打怪。")

    def refresh_profile_data(self, force: bool = False) -> None:
        if self.profile_refresh_inflight:
            if force:
                self.profile_refresh_queued = True
                self.refresh_profile_button.setText("刷新已排队")
            return
        # Background updates (for example, after a hit) are throttled. A click
        # is always honored, including immediately after an automatic refresh.
        throttle = 8.0 if not force else 0.0
        if time.monotonic() - self.profile_refreshed_at < throttle:
            return
        token = self.get_session_token()
        if not token:
            return
        parsed = urllib.parse.urlsplit(self.url.text().strip())
        scheme = "https" if parsed.scheme == "wss" else "http"
        api_path = parsed.path.rstrip("/")
        if api_path.endswith("/realtime"):
            api_path = api_path[:-len("/realtime")]
        api_root = urllib.parse.urlunsplit((scheme, parsed.netloc, api_path, "", ""))
        if not api_root or not parsed.netloc:
            return
        self.profile_refresh_inflight = True
        self.profile_refreshed_at = time.monotonic()
        self.refresh_profile_queued = False
        self.refresh_profile_button.setEnabled(True)
        self.refresh_profile_button.setText("刷新中…")

        threading.Thread(target=self.refresh_mail_unread, args=(api_root, token), daemon=True).start()

        def worker() -> None:
            result = {}
            try:
                for key, endpoint in (("player", "/player"), ("equipment", "/equipment"),
                                      ("progression", "/progression")):
                    try:
                        request = urllib.request.Request(
                            api_root + endpoint,
                            headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
                            method="GET",
                        )
                        with urllib.request.urlopen(request, timeout=8) as response:
                            if response.status == 200:
                                payload = json.loads(response.read().decode("utf-8"))
                                if isinstance(payload, (dict, list, int, float)):
                                    result[key] = payload
                    except Exception as exc:
                        result[key + "Error"] = f"{type(exc).__name__}: {exc}"
            except Exception as exc:
                result["error"] = f"{type(exc).__name__}: {exc}"
            self.bridge.profile.emit(result)

        threading.Thread(target=worker, daemon=True).start()

    def refresh_mail_unread(self, api_root: str, token: str) -> None:
        result = {}
        try:
            request = urllib.request.Request(
                api_root + "/progression/mail/unread",
                headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
                method="GET",
            )
            with urllib.request.urlopen(request, timeout=8) as response:
                if response.status == 200:
                    result["mailUnread"] = json.loads(response.read().decode("utf-8"))
                else:
                    result["mailUnreadError"] = f"HTTP {response.status}"
        except Exception as exc:
            result["mailUnreadError"] = f"{type(exc).__name__}: {exc}"
        self.bridge.profile.emit(result)

    def claim_encounter_reward(self, encounter_id: str) -> None:
        token = self.get_session_token()
        parsed = urllib.parse.urlsplit(self.url.text().strip())
        scheme = "https" if parsed.scheme == "wss" else "http"
        api_path = parsed.path.rstrip("/")
        if api_path.endswith("/realtime"):
            api_path = api_path[:-len("/realtime")]
        endpoint = urllib.parse.urlunsplit((scheme, parsed.netloc, api_path + "/progression/defeat", "", ""))
        if not token or not parsed.netloc:
            return

        def worker() -> None:
            result = {}
            try:
                body = json.dumps({"encounterId": encounter_id}).encode("utf-8")
                request = urllib.request.Request(
                    endpoint, data=body,
                    headers={"Authorization": "Bearer " + token,
                             "Content-Type": "application/json", "Accept": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=8) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                    if isinstance(payload, dict):
                        result["progression"] = payload
                        result["claimEncounterId"] = encounter_id
            except Exception as exc:
                result["claimError"] = f"{type(exc).__name__}: {exc}"
                result["claimEncounterId"] = encounter_id
            self.bridge.profile.emit(result)

        threading.Thread(target=worker, daemon=True).start()

    def accept_profile_data(self, data: dict) -> None:
        if isinstance(data, dict) and data.get("socialApiKey"):
            key = str(data["socialApiKey"])
            if data.get("socialApiError"):
                if key == "balance":
                    self.balance_label.setText("TABBY 余额：暂不可用")
                    self.balance_label.setToolTip(str(data["socialApiError"]))
                elif key in {"equip", "unequip"}:
                    self.inventory_action_status.setText("装备操作失败：" + str(data["socialApiError"]))
            elif key == "balance":
                payload = data.get("socialApiResult", {})
                nested = payload.get("balance", payload) if isinstance(payload, dict) else payload
                if isinstance(nested, dict):
                    amount = next((nested[k] for k in ("balance", "amount", "available", "tabby", "TABBY") if k in nested), None)
                    try:
                        display_amount = f"{float(amount):,.2f}"
                    except (TypeError, ValueError):
                        display_amount = str(amount) if amount is not None else "已读取"
                    self.balance_label.setText(f"TABBY 余额：{display_amount}")
                    self.balance_label.setToolTip(json.dumps(nested, ensure_ascii=False, indent=2))
                else:
                    self.balance_label.setText(f"TABBY 余额：{nested}")
            elif key in {"equip", "unequip"}:
                self.inventory_action_status.setText("装备状态已更新，正在刷新背包…")
                self.refresh_profile_data(force=True)
            return
        if isinstance(data, dict) and ("mailUnread" in data or "mailUnreadError" in data):
            payload = data.get("mailUnread")
            if isinstance(payload, (dict, list, int, float)):
                unread = self.find_unread_count(payload)
                self.mail_unread_label.setText(f"邮件未读：{unread}" if unread is not None else "邮件：已读取")
                self.mail_unread_label.setToolTip(json.dumps(payload, ensure_ascii=False, indent=2))
            else:
                self.mail_unread_label.setText("邮件：暂不可用")
                self.mail_unread_label.setToolTip(str(data["mailUnreadError"]))
            return
        if isinstance(data, dict) and data.get("questRefresh"):
            self.quest_accept_inflight = False
            if data.get("questError"):
                self.append_log("自动接取任务未完成：" + data["questError"])
            if data.get("questLimitReached"):
                self.quest_accept_blocked_date = datetime.now().date()
            payload = data.get("questData")
            if isinstance(payload, dict) and isinstance(payload.get("quests"), list):
                self.update_quests(payload["quests"])
            if data.get("questLimitReached"):
                self.handle_quest_limit_reached(str(data.get("questError", "")))
            if data.get("acceptedQuestId"):
                self.append_log(f"已自动接取打怪任务：{data['acceptedQuestId']}")
            return
        self.profile_refresh_inflight = False
        if hasattr(self, "refresh_profile_button"):
            self.refresh_profile_button.setEnabled(True)
            self.refresh_profile_button.setText("刷新角色与任务")
        if not isinstance(data, dict):
            return
        player = data.get("player", {})
        equipment = data.get("equipment", {})
        progression = data.get("progression", {})
        if isinstance(player, dict) and player:
            self.api_profile = player.get("player", player)
        if isinstance(equipment, dict) and equipment:
            self.notify_new_equipment(equipment)
            self.api_equipment = equipment
        progression_data = progression.get("progression", progression) if isinstance(progression, dict) else {}
        if isinstance(progression_data, dict):
            self.last_progress_state.update(progression_data)
            quests = progression_data.get("quests")
            if isinstance(quests, list):
                self.update_quests(quests)
        self.refresh_character_status()
        self.update_social_inventory()
        if data.get("error"):
            self.append_log("角色/任务刷新未完成：" + str(data["error"]))
        if data.get("claimEncounterId"):
            if data.get("claimError"):
                self.claimed_encounters.discard(str(data["claimEncounterId"]))
                self.append_log(f"击败结算未完成 {data['claimEncounterId']}：{data['claimError']}")
            else:
                self.append_log(f"击败结算已同步：{data['claimEncounterId']}；任务进度已刷新。")
                self.refresh_profile_data(force=True)

    @staticmethod
    def find_unread_count(payload: object) -> int | None:
        """Read a known unread count without treating arbitrary totals as unread."""
        if isinstance(payload, dict):
            for key in ("unreadCount", "unread_count", "unread", "unreadMessages"):
                value = payload.get(key)
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    return int(value)
                if isinstance(value, list):
                    return len(value)
            for key in ("data", "result", "mail", "messages"):
                if key in payload:
                    found = MainWindow.find_unread_count(payload[key])
                    if found is not None:
                        return found
        elif isinstance(payload, list):
            return len(payload)
        return None
        if self.profile_refresh_queued:
            self.profile_refresh_queued = False
            QTimer.singleShot(0, lambda: self.refresh_profile_data(force=True))

    def refresh_character_status(self) -> None:
        if not hasattr(self, "character_status"):
            return
        profile = self.api_profile if isinstance(self.api_profile, dict) else {}
        progress = self.last_progress_state if isinstance(self.last_progress_state, dict) else {}
        self_state = self.last_self_state if isinstance(self.last_self_state, dict) else {}
        equipment = self.api_equipment if isinstance(self.api_equipment, dict) else {}
        totals = equipment.get("totals", {}) if isinstance(equipment.get("totals", {}), dict) else {}
        name = profile.get("playerName") or profile.get("name") or "—"
        character_class = profile.get("characterClass") or profile.get("class") or "—"
        character_class = self_state.get("characterClass", character_class)
        class_display = CHARACTER_NAMES_ZH.get(str(character_class).upper(), character_class)
        if hasattr(self, "character_portrait"):
            class_code = str(character_class).upper()
            kind = {"GUARD": "guard", "WARRIOR": "warrior"}.get(class_code)
            sprite = (QPixmap(str(Path(__file__).with_name("assets") / (kind + "-idle.webp")))
                      if kind else QPixmap())
            if not sprite.isNull():
                # Guard idle is a horizontal strip; the warrior asset is one frame.
                frame = sprite.copy(0, 0, min(sprite.width(), sprite.height()), sprite.height())
                self.character_portrait.setText("")
                self.character_portrait.setStyleSheet("background:transparent;border:0;")
                self.character_portrait.setPixmap(frame.scaled(82, 108, Qt.AspectRatioMode.KeepAspectRatio,
                                                               Qt.TransformationMode.SmoothTransformation))
                self.character_portrait.setToolTip(f"{class_display} · 游戏原始待机素材")
            else:
                self.character_portrait.clear()
                self.character_portrait.setText("连接后\n加载角色")
                self.character_portrait.setStyleSheet("background:#292E2D;border:1px solid #414846;border-radius:10px;color:#AAB4B1;font-size:10px;")
        level = progress.get("level", profile.get("level", "—"))
        experience = progress.get("experience", profile.get("experience", "—"))
        experience_needed = progress.get("experienceNeeded", "—")
        health = self_state.get("health", "—")
        max_health = self_state.get("maxHealth", self_state.get("maximumHealth", totals.get("maxHealth", "—")))
        attack = totals.get("attack", totals.get("attackPower", self_state.get("attack", "—")))
        defense = totals.get("defense", self_state.get("defense", "—"))
        gold = profile.get("gold", self_state.get("gold", "—"))
        status = "阵亡" if self.server_dead else "存活"
        if hasattr(self, "health_bar"):
            try:
                maximum = max(1, int(max_health))
                self.health_bar.setRange(0, maximum)
                self.health_bar.setValue(max(0, min(maximum, int(health))))
                self.health_bar.setFormat(f"{health}/{maximum}")
            except (TypeError, ValueError):
                self.health_bar.setFormat("等待生命数据")
        if hasattr(self, "experience_bar"):
            try:
                current_xp = max(0, int(experience))
                needed_xp = max(1, int(experience_needed))
                self.experience_bar.setValue(round(min(100, current_xp / needed_xp * 100)))
                self.experience_bar.setFormat(f"{current_xp}/{needed_xp}")
            except (TypeError, ValueError):
                self.experience_bar.setFormat("等待经验数据")
            farming = self_state.get("farming", {})
            try:
                stamina = float(farming["staminaPercent"])
                self.fatigue_bar.setValue(round(max(0, min(100, stamina))))
                self.fatigue_bar.setFormat(f"剩余 {stamina:.0f}%")
            except (KeyError, TypeError, ValueError):
                self.fatigue_bar.setFormat("等待疲劳数据")
        if hasattr(self, "resource_chips"):
            resource_names = {
                "healthPotions": "生命药水", "bossTickets": "遗迹入场券",
                "atonementStones": "赎罪石", "townStones": "回城石",
                "evil": "恶名值",
            }
            for key, chip in self.resource_chips.items():
                count = self_state.get(key)
                if key == "townStones" and isinstance(count, list):
                    display = str(len(count))
                elif key == "evil" and isinstance(count, (int, float)):
                    display = f"{int(count)}/10"
                else:
                    display = str(int(count)) if isinstance(count, (int, float)) else "—"
                chip.setText(f"{resource_names[key]}  {display}")
                chip.setToolTip(f"实时角色快照字段：{key}" if count is not None else "等待服务端提供该资源数量")
        self.update_backpack()
        self.update_social_inventory()
        if hasattr(self, "character_facts"):
            values = {"角色": name, "职业": class_display,
                      "等级": level, "状态": status,
                      "经验": f"{experience}/{experience_needed}", "攻击": attack, "防御": defense,
                      "金币": gold, "移速加成": f"{totals.get('moveSpeedPercent', 0)}%"}
            for key, value in values.items():
                if key in self.character_facts:
                    self.character_facts[key].setText(str(value))
            items = equipment.get("items", [])
            equipped = {str(item.get("slotType")): item for item in items
                        if isinstance(item, dict) and item.get("equipped")} if isinstance(items, list) else {}
            for slot, (caption, label) in self.gear_slots.items():
                item = equipped.get(slot)
                if item:
                    title = localized_item_name(item)
                    rarity = str(item.get("qualityCode", "L1"))
                    color = quality_color(rarity)
                    label.setText(f"{caption} · {title}")
                    label.setToolTip(json.dumps(item, ensure_ascii=False, indent=2))
                    label.setStyleSheet(f"background:#191D1E;border:1px solid #363D3C;border-radius:6px;padding:6px;color:{color};font-weight:600;")
                    stem = {"WEAPON": "sword", "HAT": "helmet", "ARMOR": "armor", "SHOES": "boots",
                            "RING": "ring", "AMULET": "amulet"}[slot]
                    level = item.get("equipmentLevel", 1)
                    icon_path = Path(__file__).with_name("assets") / f"{stem}_p{level}.webp"
                    pix = QPixmap(str(icon_path))
                    self.gear_icons[slot].setPixmap(pix.scaled(24, 24, Qt.AspectRatioMode.KeepAspectRatio,
                                                                             Qt.TransformationMode.SmoothTransformation))
                else:
                    self.gear_icons[slot].clear()
                    label.setText(f"{caption} · 未穿戴" if "items" in equipment else f"{caption} · 等待装备数据")
                    label.setToolTip("")
                    label.setStyleSheet("background:#191D1E;border:1px solid #363D3C;border-radius:6px;padding:6px;color:#958976;")
        self.character_status.setText(
            f"{name} · {class_display}  |  等级 {level}  |  经验 {experience}/{experience_needed}  |  "
            f"生命 {health}/{max_health}  |  攻击 {attack}  |  防御 {defense}  |  金币 {gold}  |  {status}"
        )

    def accept_attack_ticket(self, ticket: dict) -> None:
        if ticket.get("id"):
            self.next_attack = ticket
            self.update_attack_button()
            self.update_live_telemetry()

    def update_live_telemetry(self) -> None:
        """Show only server-backed combat and connection state."""
        if not hasattr(self, "live_telemetry"):
            return
        rtt = f"{self.last_rtt_ms} ms" if self.last_rtt_ms is not None else "等待 pong"
        ticket = self.next_attack.get("id") if isinstance(self.next_attack, dict) else None
        remaining = max(0.0, self.attack_busy_until - time.monotonic())
        if not ticket:
            ticket_text = "等待攻击票据"
        elif ticket in self.used_attack_tickets:
            ticket_text = "等待新票据"
        elif remaining > 0:
            ticket_text = f"冷却 {remaining:.1f}s"
        else:
            ticket_text = "可攻击"
        nearest = None
        if self.world_x is not None and self.world_y is not None:
            candidates = []
            for encounter_id, monster in self.monsters.items():
                if not isinstance(monster, dict):
                    continue
                try:
                    if int(monster.get("health", 1)) <= 0:
                        continue
                except (TypeError, ValueError):
                    continue
                distance = self.monster_distance(monster)
                if math.isfinite(distance):
                    candidates.append((distance, encounter_id, monster))
            if candidates:
                nearest = min(candidates, key=lambda row: row[0])
        if nearest:
            distance, encounter_id, monster = nearest
            target_text = f"最近目标 {localized_monster_name(monster)} · {distance:.0f} 单位 · {str(encounter_id)[:8]}"
        else:
            target_text = "当前地图未见存活怪物"
        map_text = MAP_NAMES.get(self.current_map, "未进入地图").split(" · ")[-1] if self.current_map else "未进入地图"
        self.live_telemetry.setText(f"连接延迟 {rtt}  ·  攻击 {ticket_text}\n地图 {map_text}  ·  {target_text}")

    def open_backpack(self) -> None:
        if not hasattr(self, "backpack_dialog"):
            self.backpack_dialog = QDialog(self)
            self.backpack_dialog.setWindowTitle("背包")
            self.backpack_dialog.resize(720, 500)
            self.backpack_dialog.setMinimumSize(640, 440)
            layout = QVBoxLayout(self.backpack_dialog)
            heading = QHBoxLayout()
            self.backpack_status = QLabel("等待数据")
            heading.addWidget(self.backpack_status, 1)
            refresh = QPushButton("刷新背包")
            refresh.setObjectName("primaryButton")
            refresh.setMinimumWidth(132)
            refresh.setMinimumHeight(38)
            refresh.clicked.connect(lambda: self.refresh_profile_data(force=True))
            heading.addWidget(refresh)
            layout.addLayout(heading)
            self.backpack_table = QTableWidget(0, 5)
            self.backpack_table.setHorizontalHeaderLabels(["物品", "类型", "品质", "数量", "属性"])
            self.backpack_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            self.backpack_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            self.backpack_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
            self.backpack_table.setToolTip("按住 Ctrl（macOS 上按 ⌘）可多选；只能比较同一部位的装备。")
            self.backpack_table.itemSelectionChanged.connect(self.update_backpack_action)
            self.backpack_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            self.backpack_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
            self.backpack_table.verticalHeader().setDefaultSectionSize(48)
            self.backpack_table.horizontalHeader().setMinimumHeight(38)
            layout.addWidget(self.backpack_table)
            actions = QHBoxLayout()
            self.backpack_equip_button = QPushButton("装备所选")
            self.backpack_equip_button.setObjectName("primaryButton")
            self.backpack_equip_button.setEnabled(False)
            self.backpack_equip_button.clicked.connect(self.equip_backpack_selection)
            self.backpack_compare_button = QPushButton("对比所选 (0)")
            self.backpack_compare_button.setObjectName("quietButton")
            self.backpack_compare_button.setEnabled(False)
            self.backpack_compare_button.clicked.connect(self.compare_backpack_selection)
            self.backpack_sell_button = QPushButton("上架出售")
            self.backpack_sell_button.setObjectName("secondaryButton")
            self.backpack_sell_button.setToolTip("当前游戏客户端没有可核实的装备上架接口；点击查看状态。")
            self.backpack_sell_button.clicked.connect(self.explain_item_listing_status)
            actions.addWidget(self.backpack_equip_button)
            actions.addWidget(self.backpack_compare_button)
            actions.addWidget(self.backpack_sell_button)
            layout.addLayout(actions)
        self.update_backpack()
        self.backpack_dialog.show()
        self.backpack_dialog.raise_()
        self.refresh_profile_data(force=True)

    def _api_root(self) -> str:
        parsed = urllib.parse.urlsplit(self.url.text().strip())
        scheme = "https" if parsed.scheme == "wss" else "http"
        api_path = parsed.path.rstrip("/")
        if api_path.endswith("/realtime"):
            api_path = api_path[:-len("/realtime")]
        return urllib.parse.urlunsplit((scheme, parsed.netloc, api_path, "", ""))

    def request_social_api(self, key: str, path: str, method: str = "GET", body: dict | None = None) -> None:
        token = self.get_session_token()
        root = self._api_root()
        if not token or not root:
            if key == "balance":
                self.balance_label.setText("TABBY 余额：请先连接账号")
            return

        def worker() -> None:
            result = {"socialApiKey": key}
            try:
                encoded = json.dumps(body).encode("utf-8") if body is not None else None
                headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
                if encoded is not None:
                    headers["Content-Type"] = "application/json"
                request = urllib.request.Request(root + path, data=encoded, headers=headers, method=method)
                with urllib.request.urlopen(request, timeout=10) as response:
                    raw = response.read().decode("utf-8")
                    result["socialApiResult"] = json.loads(raw) if raw else {}
            except Exception as exc:
                result["socialApiError"] = f"{type(exc).__name__}: {exc}"
            self.bridge.profile.emit(result)

        threading.Thread(target=worker, daemon=True).start()

    def refresh_social_data(self) -> None:
        self.refresh_profile_data(force=True)
        if time.monotonic() - self.balance_refreshed_at >= 15.0:
            self.balance_refreshed_at = time.monotonic()
            self.request_social_api("balance", "/tabby-balance")

    def update_social_inventory(self) -> None:
        if not hasattr(self, "social_inventory_table"):
            return
        items = self.api_equipment.get("items", []) if isinstance(self.api_equipment, dict) else []
        items = [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []
        self.social_inventory_table.setRowCount(len(items))
        for row, item in enumerate(items):
            name = localized_item_name(item)
            slot = str(item.get("slotType", "—"))
            quality = str(item.get("qualityCode", "L1"))
            level = str(item.get("equipmentLevel", "—"))
            equipped = bool(item.get("equipped", False))
            values = (name, SLOT_NAMES_ZH.get(slot.upper(), slot),
                      QUALITY_NAMES_ZH.get(quality.upper(), quality), level,
                      " · ".join(equipment_attribute_lines(item)),
                      "已装备" if equipped else "背包")
            for col, value in enumerate(values):
                cell = QTableWidgetItem(value)
                cell.setForeground(QColor(quality_color(quality)))
                if col == 0:
                    cell.setData(Qt.ItemDataRole.UserRole, item)
                    cell.setToolTip(json.dumps(item, ensure_ascii=False, indent=2))
                    item_code = str(item.get("itemCode", "")).lower()
                    icon_stem = next((stem for stem in ("sword", "helmet", "armor", "boots", "shoes", "ring", "amulet")
                                      if stem in item_code), "")
                    if not icon_stem and "spear" in item_code:
                        icon_stem = "sword"  # The extracted game pack has no separate spear icon.
                    if icon_stem == "shoes":
                        icon_stem = "boots"
                    try:
                        level_source = item.get("equipmentLevel")
                        if level_source is None:
                            match = re.search(r"P([1-6])$", item_code.upper())
                            level_source = match.group(1) if match else 1
                        level_no = int(level_source or 1)
                    except (TypeError, ValueError):
                        level_no = 1
                    # The game bundle exposes tier-one/tier-two equipment icons;
                    # retain a source-matched icon for higher-tier items too.
                    icon_level = min(2, max(1, level_no))
                    icon_path = Path(__file__).with_name("assets") / f"{icon_stem}_p{icon_level}.webp" if icon_stem else None
                    if icon_path and icon_path.is_file():
                        cell.setIcon(QIcon(str(icon_path)))
                self.social_inventory_table.setItem(row, col, cell)
        if hasattr(self, "inventory_action_status"):
            self.inventory_action_status.setText(f"共 {len(items)} 件装备；品质颜色与商城统一：白、蓝、紫、金。")
        self.update_inventory_action_button()

    def update_inventory_action_button(self) -> None:
        if not hasattr(self, "equip_item_button"):
            return
        row = self.social_inventory_table.currentRow()
        item_cell = self.social_inventory_table.item(row, 0) if row >= 0 else None
        item = item_cell.data(Qt.ItemDataRole.UserRole) if item_cell else None
        self.equip_item_button.setEnabled(isinstance(item, dict))
        self.equip_item_button.setText(
            ("卸下 " if item.get("equipped") else "装备 ") + localized_item_name(item)
            if isinstance(item, dict) else "选择物品后装备"
        )
        if isinstance(item, dict):
            quality = str(item.get("qualityCode", "L1"))
            self.selected_item_name.setText(localized_item_name(item))
            self.selected_item_name.setStyleSheet(f"color: {quality_color(quality)}; font-weight: 700;")
            slot = SLOT_NAMES_ZH.get(str(item.get("slotType", "")).upper(), str(item.get("slotType", "物品")))
            level = item.get("equipmentLevel", "—")
            self.selected_item_detail.setText(
                f"{slot}  ·  {QUALITY_NAMES_ZH.get(quality.upper(), quality)}  ·  等级 {level}  ·  "
                f"{'已装备' if item.get('equipped') else '背包'}"
            )
            self.selected_item_attributes.setText("属性：" + "  ·  ".join(equipment_attribute_lines(item)))
            icon = item_cell.icon() if item_cell else QIcon()
            self.selected_item_icon.setPixmap(icon.pixmap(32, 32) if not icon.isNull() else QPixmap())
        else:
            self.selected_item_name.setText("未选择物品")
            self.selected_item_name.setStyleSheet("")
            self.selected_item_detail.setText("点击背包中的一行查看物品详情，再执行装备操作。")
            self.selected_item_attributes.setText("属性：选择装备查看")
            self.selected_item_icon.clear()

    def equip_selected_item(self) -> None:
        row = self.social_inventory_table.currentRow()
        cell = self.social_inventory_table.item(row, 0) if row >= 0 else None
        item = cell.data(Qt.ItemDataRole.UserRole) if cell else None
        if not isinstance(item, dict):
            self.inventory_action_status.setText("先从背包列表选择一件装备。")
            return
        if item.get("equipped"):
            self.request_social_api("unequip", "/equipment/unequip", "POST",
                                    {"slotType": item.get("slotType", "")})
        else:
            player_item_id = item.get("playerItemId")
            if player_item_id is None:
                self.inventory_action_status.setText("物品记录缺少 playerItemId，不能安全提交装备操作。")
                return
            self.request_social_api("equip", "/equipment/equip", "POST",
                                    {"playerItemId": player_item_id})

    def set_combat_mode(self) -> None:
        if self.ws is None or not self.world_ready or self.server_dead:
            self.mode_status.setText("请先连接并进入游戏世界。")
            return
        value = int(self.combat_mode.currentData())
        if self.current_map == 1:
            self.mode_status.setText("需要先离开主城，服务端才允许切换和平/战斗/仇杀模式。")
            return
        try:
            self.send_game_packet({"action": "mode", "mode": value})
            self.mode_status.setText("模式请求已发送；以服务端下一次角色快照为准。主城或冷却期间可能被拒绝。")
        except Exception as exc:
            self.mode_status.setText(f"模式请求失败：{type(exc).__name__}: {exc}")

    def update_mode_control(self, cooldown: int = 0) -> None:
        if not hasattr(self, "set_mode_button"):
            return
        ready = (self.ws is not None and self.world_ready and not self.server_dead
                 and self.current_map not in (None, 1) and cooldown <= 0)
        self.set_mode_button.setEnabled(ready)
        if self.current_map == 1:
            self.set_mode_button.setToolTip("离开主城后可更改模式")
        elif cooldown > 0:
            self.set_mode_button.setToolTip(f"模式冷却中：{cooldown} 秒")
        else:
            self.set_mode_button.setToolTip("向服务端请求切换角色模式")

    def update_nearby_players(self, peers: object) -> None:
        if not hasattr(self, "enemy_table"):
            return
        rows = peers if isinstance(peers, list) else []
        self.enemy_table.setRowCount(len(rows))
        mode_names = {0: "和平", 1: "战斗", 2: "仇杀"}
        for row, peer in enumerate(rows):
            if not isinstance(peer, dict):
                continue
            name = str(peer.get("playerName", peer.get("name", f"玩家 {peer.get('id', '?')}")))
            mode = int(peer.get("combatMode", 2 if peer.get("mode") else 0) or 0)
            health = peer.get("health", "—")
            maximum = peer.get("maxHealth", peer.get("maximumHealth", "—"))
            for col, value in enumerate((name, mode_names.get(mode, "未知"), f"{health}/{maximum}")):
                self.enemy_table.setItem(row, col, QTableWidgetItem(value))

    def merge_nearby_players(self, peers: list) -> None:
        """Keep nearby players visible across sparse/partial server snapshots."""
        now = time.monotonic()
        for index, raw_peer in enumerate(peers):
            if not isinstance(raw_peer, dict):
                continue
            peer = dict(raw_peer)
            peer_id = peer.get("id", peer.get("playerId"))
            if peer_id is not None:
                key = f"id:{peer_id}"
            else:
                name = str(peer.get("playerName", peer.get("name", ""))).strip()
                position = peer.get("position") if isinstance(peer.get("position"), dict) else peer
                key = f"name:{name}" if name else f"position:{position.get('x')}:{position.get('y')}:{index}"

            old = self.peer_cache.get(key, {})
            merged = dict(old)
            merged.update(peer)
            old_position = old.get("position") if isinstance(old.get("position"), dict) else {}
            new_position = peer.get("position") if isinstance(peer.get("position"), dict) else None
            if new_position is not None:
                merged["position"] = {**old_position, **new_position}
            if ("mapId" not in merged and "map" not in merged
                    and not (isinstance(merged.get("position"), dict)
                             and ("mapId" in merged["position"] or "map" in merged["position"]))
                    and self.current_map is not None):
                merged["mapId"] = self.current_map
            self.peer_cache[key] = merged
            self.peer_last_seen[key] = now
        self.expire_nearby_players(now)

    def expire_nearby_players(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        stale = [key for key, seen_at in self.peer_last_seen.items()
                 if now - seen_at > NEARBY_PLAYER_TTL_SECONDS]
        for key in stale:
            self.peer_last_seen.pop(key, None)
            self.peer_cache.pop(key, None)
        self.last_peers = list(self.peer_cache.values())

    def append_social_chat(self, messages: object, channel: str = "世界") -> None:
        if not hasattr(self, "social_chat_log"):
            return
        if isinstance(messages, dict):
            messages = [messages]
        if not isinstance(messages, list):
            return
        for message in messages:
            if not isinstance(message, dict):
                continue
            sender = message.get("Sender", message.get("sender", "系统"))
            body = message.get("Body", message.get("message", message.get("body", "")))
            if body:
                self.social_chat_log.appendPlainText(f"[{channel}] {sender}：{body}")

    def send_chat_message(self) -> None:
        message = self.social_chat_input.text().strip()
        if not message:
            return
        if self.ws is None or not self.world_ready:
            self.mode_status.setText("聊天发送失败：请先连接游戏。")
            return
        try:
            self.send_game_packet({"action": "chat", "channel": "world", "message": message})
            self.social_chat_input.clear()
            self.social_chat_log.appendPlainText(f"[我] {message}")
        except Exception as exc:
            self.mode_status.setText(f"聊天发送失败：{type(exc).__name__}: {exc}")

    def update_backpack(self) -> None:
        if not hasattr(self, "backpack_table"):
            return
        rows = []
        items = self.api_equipment.get("items", [])
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict) and not item.get("equipped"):
                slot = str(item.get("slotType", "—"))
                quality = str(item.get("qualityCode", "—"))
                rows.append([localized_item_name(item), SLOT_NAMES_ZH.get(slot.upper(), slot),
                             QUALITY_NAMES_ZH.get(quality.upper(), quality), str(item.get("quantity", 1)), quality, item])
        for key, name in (("healthPotions", "生命药水"), ("bossTickets", "遗迹入场券"), ("atonementStones", "赎罪石")):
            count = self.last_self_state.get(key)
            if isinstance(count, (int, float)) and count > 0:
                rows.append([name, "消耗品", "—", str(int(count)), "", None])
        self.backpack_table.setRowCount(len(rows))
        for row, values in enumerate(rows):
            quality = values[4]
            color = QColor(quality_color(quality))
            item_record = values[5]
            properties = " · ".join(equipment_attribute_lines(item_record)) if isinstance(item_record, dict) else "—"
            shown = (*values[:4], properties)
            for col, value in enumerate(shown):
                cell = QTableWidgetItem(value)
                if col in (0, 2) and quality:
                    cell.setForeground(color)
                if col == 0 and isinstance(item_record, dict):
                    cell.setData(Qt.ItemDataRole.UserRole, item_record)
                    cell.setToolTip(json.dumps(item_record, ensure_ascii=False, indent=2))
                    icon = equipment_icon(item_record)
                    if not icon.isNull():
                        cell.setIcon(icon)
                        cell.setSizeHint(QSize(0, 48))
                elif col == 0:
                    cell.setSizeHint(QSize(0, 48))
                self.backpack_table.setItem(row, col, cell)
        self.backpack_status.setText(
            f"背包 {len(rows)} 类物品 · 按住 Ctrl/⌘ 多选同部位装备可比较" if "items" in self.api_equipment
            else "等待服务端背包数据…"
        )
        self.update_backpack_action()

    def update_backpack_action(self) -> None:
        if not hasattr(self, "backpack_equip_button"):
            return
        row = self.backpack_table.currentRow()
        cell = self.backpack_table.item(row, 0) if row >= 0 else None
        item = cell.data(Qt.ItemDataRole.UserRole) if cell else None
        self.backpack_equip_button.setEnabled(isinstance(item, dict))
        selected_rows = sorted({index.row() for index in self.backpack_table.selectionModel().selectedRows()})
        selected_items = []
        for selected_row in selected_rows:
            selected_cell = self.backpack_table.item(selected_row, 0)
            selected_item = selected_cell.data(Qt.ItemDataRole.UserRole) if selected_cell else None
            if isinstance(selected_item, dict) and selected_item.get("slotType"):
                selected_items.append(selected_item)
        slots = {str(selected.get("slotType", "")).upper() for selected in selected_items}
        equipped_match = self.equipped_item_for_slot(next(iter(slots))) if len(slots) == 1 else None
        can_compare = (len(selected_items) == 1 and equipped_match is not None) or (len(selected_items) >= 2 and len(slots) == 1)
        if hasattr(self, "backpack_compare_button"):
            self.backpack_compare_button.setEnabled(can_compare)
            self.backpack_compare_button.setText("对比已装备" if len(selected_items) == 1 and can_compare
                                                else f"对比所选 ({len(selected_items)})")
            self.backpack_compare_button.setToolTip("将所选装备与当前已装备的同部位装备对比。" if len(selected_items) == 1 and can_compare else
                                                    "选择至少两件同部位装备进行属性对比。" if can_compare else
                                                    "请选择同部位装备；单选时需要角色当前已装备该部位。")

    def equipped_item_for_slot(self, slot: str) -> dict | None:
        items = self.api_equipment.get("items", [])
        if not isinstance(items, list):
            return None
        slot = str(slot or "").upper()
        return next((item for item in items if isinstance(item, dict) and item.get("equipped")
                     and str(item.get("slotType", "")).upper() == slot), None)

    def explain_item_listing_status(self) -> None:
        message = (
            "当前客户端已确认的装备接口只有读取、穿戴、卸下和丢弃；未发现可核实的装备上架接口。\n\n"
            "为避免误请求或误操作，这里不会伪造上架成功。上架功能需要服务端提供正式的商品创建/挂牌接口和参数后才能接通。"
        )
        if hasattr(self, "backpack_status") and self.sender() is getattr(self, "backpack_sell_button", None):
            self.backpack_status.setText("暂不可上架：游戏服务端接口尚未核实。")
        elif hasattr(self, "inventory_action_status"):
            self.inventory_action_status.setText("暂不可上架：游戏服务端接口尚未核实。")
        QMessageBox.information(self, "上架出售", message)

    def compare_backpack_selection(self) -> None:
        selected_rows = sorted({index.row() for index in self.backpack_table.selectionModel().selectedRows()})
        items = []
        for row in selected_rows:
            cell = self.backpack_table.item(row, 0)
            item = cell.data(Qt.ItemDataRole.UserRole) if cell else None
            if isinstance(item, dict) and item.get("slotType"):
                items.append(item)
        slots = {str(item.get("slotType", "")).upper() for item in items}
        if not items or len(slots) != 1:
            self.backpack_status.setText("请选择同一部位的装备后再对比。")
            return
        if len(items) == 1:
            equipped = self.equipped_item_for_slot(next(iter(slots)))
            if equipped is None:
                self.backpack_status.setText("角色当前没有已装备的同部位装备，无法进行单件对比。")
                return
            items.insert(0, equipped)
        self.open_equipment_comparison(items)

    def open_equipment_comparison(self, items: list[dict]) -> None:
        dialog = QDialog(self.backpack_dialog if hasattr(self, "backpack_dialog") else self)
        dialog.setWindowTitle("装备属性对比")
        dialog.resize(max(620, 240 * len(items)), 440)
        layout = QVBoxLayout(dialog)
        slot = SLOT_NAMES_ZH.get(str(items[0].get("slotType", "")).upper(), "装备")
        equipped_ids = {str(item.get("playerItemId")) for item in items
                        if item.get("equipped") and item.get("playerItemId") is not None}
        heading = QLabel(f"{slot}属性对比 · {len(items)} 件")
        heading.setObjectName("sectionTitle")
        layout.addWidget(heading)
        stat_keys = [
            ("攻击", "attack", "ATTACK"), ("防御", "defense", "DEFENSE"),
            ("生命", "maxHealth", "HEALTH"), ("生命恢复", "healthRegen", "HEALTH_REGEN"),
            ("攻击速度", "attackSpeedPercent", "ATTACK_SPEED_PERCENT"),
            ("移动速度", "moveSpeedPercent", "MOVE_SPEED_PERCENT"),
            ("暴击率", "criticalChancePercent", "CRITICAL_CHANCE_PERCENT"), ("幸运", "luck", "LUCK"),
        ]
        known_codes = {code for _, _, code in stat_keys}
        code_aliases = {"ATTACK_SPEED": "ATTACK_SPEED_PERCENT", "MOVE_SPEED": "MOVE_SPEED_PERCENT",
                        "CRITICAL": "CRITICAL_CHANCE_PERCENT", "CRITICAL_CHANCE": "CRITICAL_CHANCE_PERCENT",
                        "MAX_HEALTH": "HEALTH"}
        extra_codes = []
        for item in items:
            attributes = item.get("attributes", [])
            if not isinstance(attributes, list):
                continue
            for attr in attributes:
                if not isinstance(attr, dict):
                    continue
                raw_code = str(attr.get("code", "")).upper()
                code = code_aliases.get(raw_code, raw_code)
                if code and code not in known_codes:
                    known_codes.add(code)
                    extra_codes.append((str(attr.get("displayNameZh") or _ITEM_ATTRIBUTE_NAMES_ZH.get(raw_code)
                                           or attr.get("displayName") or raw_code), None, code))
        stat_keys.extend(extra_codes)
        table = QTableWidget(len(stat_keys) + 2, len(items) + 1)
        header_labels = []
        for item in items:
            label = localized_item_name(item)
            if item.get("equipped"):
                label += " · 已装备"
            header_labels.append(label)
        table.setHorizontalHeaderLabels(["属性", *header_labels])
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        for col in range(1, len(items) + 1):
            table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.Stretch)

        def stat_map(item: dict) -> dict[str, str]:
            result: dict[str, str] = {}
            attributes = item.get("attributes", [])
            if isinstance(attributes, list):
                for attr in attributes:
                    if isinstance(attr, dict):
                        raw_code = str(attr.get("code", "")).upper()
                        code = code_aliases.get(raw_code, raw_code)
                        result[code] = equipment_attribute_lines({"attributes": [attr]})[0]
            for _, key, code in stat_keys:
                if code not in result and item.get(key) not in (None, 0, "0", ""):
                    result[code] = " ".join(equipment_attribute_lines({key: item[key]}))
            return result

        values_by_item = [stat_map(item) for item in items]
        row_labels = ["等级", "品质", *[label for label, _, _ in stat_keys]]
        row_values: list[list[str]] = []
        for row, label in enumerate(row_labels):
            table.setItem(row, 0, QTableWidgetItem(label))
            current_row = []
            for col, item in enumerate(items, start=1):
                if row == 0:
                    value = str(item.get("equipmentLevel", "—"))
                elif row == 1:
                    quality = str(item.get("qualityCode", "L1"))
                    value = QUALITY_NAMES_ZH.get(quality.upper(), quality)
                else:
                    code = stat_keys[row - 2][2]
                    value = values_by_item[col - 1].get(code, "—")
                cell = QTableWidgetItem(value)
                cell.setForeground(QColor(quality_color(item.get("qualityCode", "L1"))))
                table.setItem(row, col, cell)
                current_row.append(value)
            row_values.append(current_row)
        for row, values in enumerate(row_values):
            if len(set(values)) > 1:
                for col, value in enumerate(values, start=1):
                    cell = table.item(row, col)
                    cell.setBackground(QColor("#35472f" if str(items[col - 1].get("playerItemId")) in equipped_ids else "#254e43"))
                    font = cell.font()
                    font.setBold(True)
                    cell.setFont(font)
        for col, item in enumerate(items, start=1):
            if item.get("equipped"):
                table.horizontalHeaderItem(col).setForeground(QColor("#a9d38f"))
                table.horizontalHeaderItem(col).setToolTip("角色当前穿戴的装备")
        layout.addWidget(table, 1)
        help_text = QLabel("绿色高亮表示该项属性与对比装备不同；“已装备”标记为角色当前穿戴物。选择其他装备后可直接穿戴。")
        help_text.setObjectName("subtitle")
        layout.addWidget(help_text)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        for item in items:
            equipped = bool(item.get("equipped"))
            equip_button = QPushButton(f"{'当前已装备' if equipped else '装备「' + localized_item_name(item) + '」'}")
            equip_button.setObjectName("quietButton" if equipped else "primaryButton")
            equip_button.setEnabled(not equipped and item.get("playerItemId") is not None)
            equip_button.clicked.connect(lambda _checked=False, selected=item: self.equip_item_from_comparison(selected, dialog))
            buttons.addWidget(equip_button)
        close_button = QPushButton("关闭")
        close_button.setObjectName("secondaryButton")
        close_button.clicked.connect(dialog.accept)
        buttons.addWidget(close_button)
        layout.addLayout(buttons)
        dialog.exec()

    def equip_item_from_comparison(self, item: dict, dialog: QDialog) -> None:
        player_item_id = item.get("playerItemId")
        if player_item_id is None:
            return
        self.request_social_api("equip", "/equipment/equip", "POST", {"playerItemId": player_item_id})
        if hasattr(self, "backpack_status"):
            self.backpack_status.setText(f"正在装备 {localized_item_name(item)}，等待服务端确认…")
        dialog.accept()

    def equip_backpack_selection(self) -> None:
        row = self.backpack_table.currentRow()
        cell = self.backpack_table.item(row, 0) if row >= 0 else None
        item = cell.data(Qt.ItemDataRole.UserRole) if cell else None
        if not isinstance(item, dict) or item.get("equipped"):
            return
        player_item_id = item.get("playerItemId")
        if player_item_id is None:
            self.backpack_status.setText("物品记录缺少 playerItemId，无法安全装备。")
            return
        self.request_social_api("equip", "/equipment/equip", "POST", {"playerItemId": player_item_id})
        self.backpack_status.setText("装备请求已发送，等待服务端确认…")

    def update_monsters(self, packet: dict) -> None:
        rows = packet.get("monsters", [])
        if not isinstance(rows, list):
            return
        # Mirror pvp_client.gd's expand_snapshot_rows: a non-delta snapshot
        # starts a fresh cache, while delta frames merge into the existing
        # cache. v2 returns the complete expanded cache; older formats prune
        # rows absent from the frame.
        compact = int(packet.get("deltaVersion", 0)) == 2
        is_delta = bool(packet.get("delta", False))
        cache = dict(self.monsters) if is_delta else {}
        for removed in packet.get("removedMonsters", []):
            cache.pop(str(removed), None)
        present_ids = set()
        for row in rows:
            if not isinstance(row, dict) or not row.get("encounterId"):
                continue
            encounter_id = str(row["encounterId"])
            present_ids.add(encounter_id)
            merged = dict(cache.get(encounter_id, {}))
            merged.update(row)
            cache[encounter_id] = merged
            if encounter_id not in self.seen_monsters and int(merged.get("health", 0)) > 0:
                self.seen_monsters.add(encounter_id)
                self.append_log(f"发现怪物：{localized_monster_name(merged)} · {encounter_id[:8]} · 地图 {merged.get('mapId', '?')}")
        if not compact:
            cache = {key: value for key, value in cache.items() if key in present_ids}
        self.monsters = cache
        self.refresh_monster_table()
        self.update_live_telemetry()

    def refresh_monster_table(self) -> None:
        selected = self.selected_monster_id()
        visible = [(encounter_id, monster) for encounter_id, monster in self.monsters.items()
                   if int(monster.get("mapId", self.current_map or -1)) == self.current_map
                   and int(monster.get("health", 0)) > 0]
        visible.sort(key=lambda item: self.monster_distance(item[1]))
        self.monster_table.blockSignals(True)
        self.monster_table.setRowCount(len(visible))
        if hasattr(self, "monster_empty_state"):
            has_monsters = bool(visible)
            self.monster_empty_state.setVisible(not has_monsters)
            self.monster_table.setVisible(has_monsters)
            if not has_monsters:
                if not self.world_ready:
                    self.monster_empty_title.setText("等待怪物数据")
                    self.monster_empty_detail.setText("连接游戏后会列出当前地图发现的存活怪物。")
                else:
                    self.monster_empty_title.setText("当前地图暂未发现存活怪物")
                    self.monster_empty_detail.setText("怪物出现后会自动显示在这里；自动战斗开启时会继续搜索。")
        selected_row = None
        for index, (encounter_id, monster) in enumerate(visible):
            hp = monster.get("health", "?")
            max_hp = monster.get("maxHealth")
            x, y = monster.get("x", "?"), monster.get("y", "?")
            x = f"{x:.1f}" if isinstance(x, (float, int)) else str(x)
            y = f"{y:.1f}" if isinstance(y, (float, int)) else str(y)
            distance = self.monster_distance(monster)
            rank = str(monster.get("monsterRank", "")).upper()
            rank_label = {"NORMAL": "普通", "ELITE": "精英", "BOSS": "首领"}.get(rank, "未知")
            level = next((monster.get(key) for key in ("level", "monsterLevel", "requiredLevel", "lv")
                          if monster.get(key) is not None), "—")
            values = [encounter_id, localized_monster_name(monster), str(level), rank_label,
                      f"{hp}/{max_hp}" if max_hp is not None else str(hp),
                      f"({x}, {y})", f"{distance:.0f}" if math.isfinite(distance) else "—"]
            for col, value in enumerate(values):
                self.monster_table.setItem(index, col, QTableWidgetItem(value))
            if encounter_id == selected:
                selected_row = index
        if selected_row is not None:
            self.monster_table.selectRow(selected_row)
        self.monster_table.blockSignals(False)
        if not visible and self.world_ready and not self.auto_attack.isChecked() and self.last_attacked_monster is None:
            self.combat_status.setText("当前地图尚未检测到存活怪物。")
        self.update_attack_button()

    def selected_monster_id(self) -> str | None:
        row = self.monster_table.currentRow()
        item = self.monster_table.item(row, 0) if row >= 0 else None
        return item.text() if item else None

    def toggle_encounter_id_column(self, visible: bool) -> None:
        self.monster_table.setColumnHidden(0, not visible)
        self.encounter_id_toggle.setText("隐藏 encounterId" if visible else "查看 encounterId")

    def monster_distance(self, monster: dict) -> float:
        if self.world_x is None or self.world_y is None:
            return math.inf
        try:
            return math.dist((float(self.world_x), float(self.world_y)),
                             (float(monster["x"]), float(monster["y"])))
        except (KeyError, TypeError, ValueError):
            return math.inf

    def update_attack_button(self) -> None:
        if not hasattr(self, "attack_button"):
            return
        encounter_id = self.selected_monster_id()
        monster = self.monsters.get(encounter_id) if encounter_id else None
        self.attack_button.setEnabled(self.ws is not None and self.world_ready
                                      and self.pending_destination is None
                                      and monster is not None
                                      and self.monster_matches_level_range(monster))

    @staticmethod
    def monster_level(monster: dict) -> int | None:
        for key in ("level", "monsterLevel", "requiredLevel", "lv"):
            value = monster.get(key)
            if value is None or value == "":
                continue
            try:
                return int(float(value))
            except (TypeError, ValueError, OverflowError):
                return None
        return None

    def monster_matches_level_range(self, monster: dict) -> bool:
        if not self.monster_level_limited.isChecked():
            return True
        level = self.monster_level(monster)
        return (level is not None
                and self.monster_level_min.value() <= level <= self.monster_level_max.value())

    def on_monster_level_filter_changed(self, enabled: bool) -> None:
        self.monster_level_min.setEnabled(enabled)
        self.monster_level_max.setEnabled(enabled)
        self.settings.setValue("monsterLevelLimited", enabled)
        self._discard_out_of_range_chase()
        self.update_attack_button()
        if self.auto_attack.isChecked():
            self.combat_status.setText(
                f"怪物等级限制已开启：{self.monster_level_min.value()}–{self.monster_level_max.value()} 级。"
                if enabled else "怪物等级限制已关闭：可攻击所有等级。")

    def on_monster_level_bound_changed(self, *_args) -> None:
        if self.monster_level_min.value() > self.monster_level_max.value():
            changed = self.sender()
            if changed is self.monster_level_min:
                self.monster_level_max.setValue(self.monster_level_min.value())
            else:
                self.monster_level_min.setValue(self.monster_level_max.value())
        self.settings.setValue("monsterLevelMin", self.monster_level_min.value())
        self.settings.setValue("monsterLevelMax", self.monster_level_max.value())
        self._discard_out_of_range_chase()
        self.update_attack_button()

    def _discard_out_of_range_chase(self) -> None:
        if self.chase_target is None:
            return
        target = self.monsters.get(self.chase_target)
        if target is None or not self.monster_matches_level_range(target):
            self.stop_chase()

    def attack_selected_monster(self) -> None:
        encounter_id = self.selected_monster_id()
        if encounter_id:
            self.attack_monster(encounter_id)

    def attack_monster(self, encounter_id: str) -> bool:
        monster = self.monsters.get(encounter_id)
        if monster is not None and not self.monster_matches_level_range(monster):
            self.combat_status.setText("该怪物不在设定的等级范围内，已跳过。")
            return False
        if self.task_limited_mode.isChecked() and not self.has_active_monster_quest():
            self.combat_status.setText("任务有限模式：当前没有未完成的怪物任务，不会攻击。")
            return False
        if self.task_limited_mode.isChecked() and monster is not None and not self.monster_matches_active_quest(monster):
            self.combat_status.setText("任务有限模式：该怪物不属于当前任务地图，已跳过。")
            return False
        if self.ws is None or not self.world_ready or self.server_dead or self.respawn_pending or self.pending_destination is not None or monster is None:
            self.combat_status.setText("目标已消失或游戏会话尚未就绪。")
            return False
        distance = self.monster_distance(monster)
        if distance > 55:
            self.combat_status.setText(f"目标距离 {distance:.0f}，需先靠近到 55 单位以内以留出位置同步余量。")
            return False
        ticket = str(self.next_attack.get("id", ""))
        if not ticket or ticket in self.used_attack_tickets:
            self.combat_status.setText("等待服务端下发新的攻击票据。")
            return False
        if time.monotonic() < self.attack_busy_until:
            return False
        critical = bool(self.next_attack.get("critical", False))
        sync = {"action": "sync", "movementRevision": self.movement_revision,
                "map": self.current_map, "x": self.world_x, "y": self.world_y,
                "animation": "attack", "attackCritical": critical,
                "flip": float(monster.get("x", self.world_x)) < float(self.world_x)}
        try:
            self.send_game_packet(sync)
        except Exception as exc:
            self.combat_status.setText(f"攻击准备失败：{type(exc).__name__}: {exc}")
            return False
        self.used_attack_tickets.add(ticket)
        self.last_attack_ticket = ticket
        impact_delay, animation_duration, speed_multiplier = self.attack_timing(critical)
        self.attack_busy_until = time.monotonic() + max(0.62 / speed_multiplier, animation_duration) + 0.06
        self.last_attacked_monster = encounter_id
        self.set_combat_feedback(
            f"攻击动画进行中：{encounter_id[:8]} · 命中帧约 {impact_delay} ms · 票据 {ticket[:8]}…",
            "attack", 1200,
        )
        generation = self.combat_generation
        QTimer.singleShot(impact_delay, lambda: self.send_monster_attack(encounter_id, ticket, generation))
        return True

    def attack_timing(self, critical: bool) -> tuple[int, float, float]:
        """Match the recovered client attack impact frame and equipment speed."""
        equipment = self.api_equipment if isinstance(self.api_equipment, dict) else {}
        totals = equipment.get("totals", {}) if isinstance(equipment.get("totals", {}), dict) else {}
        try:
            speed_percent = float(totals.get("attackSpeedPercent", 0))
        except (TypeError, ValueError):
            speed_percent = 0.0
        speed_multiplier = 1.2 * min(2.0, max(1.0, 1.0 + speed_percent / 100.0))
        # Mirror Wanderer.update_attack(): the default warrior uses the
        # 0.11-second normal strip (impact frame 4) and warrior_attack2 for
        # criticals (0.88/12-second frames, impact frame 5).
        frame_duration = ((0.88 / 12.0) if critical else 0.11) / speed_multiplier
        impact_frame = 5 if critical else 4
        impact_delay_ms = round(frame_duration * impact_frame * 1000)
        animation_duration = frame_duration * 7
        return impact_delay_ms, animation_duration, speed_multiplier

    def send_monster_attack(self, encounter_id: str, ticket: str, generation: int | None = None) -> None:
        if self.ws is None or (generation is not None and generation != self.combat_generation):
            return
        monster = self.monsters.get(encounter_id)
        if (monster is None or int(monster.get("health", 0)) <= 0
                or int(monster.get("mapId", self.current_map or -1)) != self.current_map
                or not self.monster_matches_level_range(monster)
                or self.monster_distance(monster) > 60):
            self.invalid_target_until[encounter_id] = time.monotonic() + 3.0
            self.used_attack_tickets.discard(ticket)
            if self.last_attack_ticket == ticket:
                self.last_attack_ticket = None
            self.combat_status.setText(f"目标 {encounter_id[:8]} 在攻击帧发出前已失效或超出范围，已跳过。")
            return
        try:
            self.send_game_packet({"action": "monsterAttack", "encounterId": encounter_id,
                                   "attackTicket": ticket, "queuedAt": int(time.monotonic() * 1000)})
            session = self.combat_generation
            QTimer.singleShot(550, lambda: self.send_idle_after_attack(session))
        except Exception as exc:
            self.used_attack_tickets.discard(ticket)
            if self.last_attack_ticket == ticket:
                self.last_attack_ticket = None
            self.combat_status.setText(f"攻击帧发送失败：{type(exc).__name__}: {exc}")

    def send_idle_after_attack(self, generation: int | None = None) -> None:
        if self.ws is None or not self.world_ready or self.pending_destination is not None or (generation is not None and generation != self.combat_generation):
            return
        try:
            self.send_game_packet({"action": "sync", "movementRevision": self.movement_revision,
                                   "map": self.current_map, "x": self.world_x, "y": self.world_y,
                                   "animation": "idle", "attackCritical": False, "flip": False}, log=False)
        except Exception:
            pass

    def toggle_auto_attack(self, enabled: bool) -> None:
        if enabled and (self.server_dead or self.respawn_pending):
            self.combat_timer.stop()
            self.combat_status.setText("自动战斗已保留；等待服务端确认复活后恢复。")
            return
        if enabled and self.task_limited_mode.isChecked() and not self.has_active_monster_quest():
            self.combat_timer.stop()
            self.combat_status.setText("任务有限模式：没有未完成的怪物任务，自动攻击保持暂停。")
            return
        if enabled and self.world_ready:
            self.combat_timer.start()
            self.combat_status.setText("自动战斗已开启：" + ("搜索当前地图的精英怪。" if self.elite_only.isChecked() else "搜索当前地图全部怪物。"))
        else:
            self.combat_timer.stop()
            self.stop_chase()
            self.stop_patrol(reset_anchor=True)
            if not enabled:
                self.combat_status.setText("自动攻击已关闭。")

    def on_elite_filter_changed(self, enabled: bool) -> None:
        if enabled and self.chase_target is not None:
            target = self.monsters.get(self.chase_target, {})
            if str(target.get("monsterRank", "")).upper() != "ELITE":
                self.stop_chase()
        if self.auto_attack.isChecked():
            self.combat_status.setText("只打精英怪：等待服务端标记为 ELITE 的怪物。" if enabled
                                       else "自动战斗：追击附近怪物。")


    def auto_attack_tick(self) -> None:
        if self.task_limited_mode.isChecked() and not self.has_active_monster_quest():
            self.combat_timer.stop()
            self.stop_chase()
            self.stop_patrol(reset_anchor=True)
            self.combat_status.setText("任务有限模式：当前没有未完成的怪物任务，自动攻击已暂停。")
            return
        if self.return_map_target is not None:
            self.stop_patrol()
            return
        if self.ws is None or not self.world_ready or self.server_dead or self.respawn_pending or self.pending_destination is not None:
            return
        candidates = [(self.monster_distance(monster), encounter_id)
                      for encounter_id, monster in self.monsters.items()
                      if int(monster.get("mapId", -1)) == self.current_map
                      and int(monster.get("health", 0)) > 0
                      and self.monster_matches_active_quest(monster)
                      and self.monster_matches_level_range(monster)
                      and time.monotonic() >= self.invalid_target_until.get(encounter_id, 0.0)
                      and (not self.elite_only.isChecked() or
                           str(monster.get("monsterRank", "")).upper() == "ELITE")]
        if not candidates:
            if self.chase_target is not None:
                self.stop_chase()
            if not self.patrol_timer.isActive() and time.monotonic() >= self.patrol_retry_after:
                self.start_patrol()
            return

        # A newly observed target always interrupts the search route.
        self.stop_patrol(reset_anchor=True)
        nearby = [(distance, encounter_id) for distance, encounter_id in candidates if distance <= 55]
        if nearby:
            self.stop_chase()
            _, encounter_id = min(nearby)
            ticket = str(self.next_attack.get("id", ""))
            if ticket and ticket not in self.used_attack_tickets and time.monotonic() >= self.attack_busy_until:
                self.attack_monster(encounter_id)
            elif time.monotonic() >= self.attack_busy_until:
                self.combat_status.setText(f"已发现附近怪物 {encounter_id[:8]}，等待服务端攻击票据…")
        elif self.chase_target is None and candidates and time.monotonic() >= self.chase_retry_after:
            distance, encounter_id = min(candidates)
            self.start_chase(encounter_id)

    def on_auto_potion_changed(self, enabled: bool) -> None:
        if not enabled:
            self.auto_potion_pending = False
            self.potion_timer.stop()
        elif self.world_ready and self.ws is not None:
            self.potion_timer.start()
        if hasattr(self, "combat_status"):
            self.combat_status.setText("自动药水已开启：生命低于 50% 且冷却结束时使用。" if enabled
                                       else "自动药水已关闭；不会自动消耗生命药水。")

    def try_auto_use_potion(self) -> None:
        if (not hasattr(self, "auto_potion") or not self.auto_potion.isChecked()
                or not self.world_ready or self.ws is None or self.server_dead
                or self.auto_potion_pending):
            return
        state = self.last_self_state if isinstance(self.last_self_state, dict) else {}
        try:
            health = float(state.get("health", 0))
            maximum = float(state.get("maxHealth", 0))
            quantity = int(state.get("healthPotions", 0))
            cooldown = int(state.get("potionCooldownMs", 0) or 0)
        except (TypeError, ValueError):
            return
        if maximum <= 0 or health / maximum > 0.5 or quantity <= 0 or cooldown > 0:
            return
        try:
            self.send_game_packet({"action": "useHealthPotion"})
            self.auto_potion_pending = True
            self.combat_status.setText(f"生命 {health:.0f}/{maximum:.0f}；已请求使用生命药水。")
            QTimer.singleShot(2500, self.release_auto_potion_request)
        except Exception as exc:
            self.combat_status.setText(f"药水请求发送失败：{type(exc).__name__}: {exc}")

    def release_auto_potion_request(self) -> None:
        self.auto_potion_pending = False

    def update_combat_stats(self) -> None:
        labels = getattr(self, "combat_stat_labels", {})
        stats = getattr(self, "combat_stats", {})
        titles = {"kills": "击败", "damage": "伤害", "hits": "命中", "potions": "药水"}
        for key, label in labels.items():
            label.setText(f"{titles[key]} {int(stats.get(key, 0))}")

    def start_patrol(self) -> None:
        """Search the current map while waiting for server-reported spawns."""
        if (self.current_map not in MAP_NAMES or self.world_x is None or self.world_y is None
                or self.ws is None or not self.world_ready or not self.auto_attack.isChecked()
                or self.server_dead or self.respawn_pending or self.pending_destination is not None):
            return
        if self.patrol_anchor is None:
            self.patrol_anchor = (float(self.world_x), float(self.world_y))
        start = (float(self.world_x), float(self.world_y))
        directions = ((0, -1), (1, -1), (1, 0), (1, 1),
                      (0, 1), (-1, 1), (-1, 0), (-1, -1))
        for _ in range(len(directions)):
            dx, dy = directions[self.patrol_direction_index]
            goal = (self.patrol_anchor[0] + dx * self.patrol_ring,
                    self.patrol_anchor[1] + dy * self.patrol_ring)
            # Stone Valley is a compact arena. Keep search waypoints inside
            # the walkable rectangle recovered from its world scene.
            if self.current_map == 3:
                goal = (min(1100.0, max(52.0, goal[0])),
                        min(620.0, max(32.0, goal[1])))
            self.patrol_direction_index += 1
            if self.patrol_direction_index == len(directions):
                self.patrol_direction_index = 0
                if self.patrol_ring >= 3200:
                    self.patrol_ring = 320.0
                    self.patrol_anchor = start
                else:
                    self.patrol_ring += 320.0
            if self.current_map in (1, 2):
                path = find_map_path(self.current_map, start, goal, max_distance=self.patrol_ring + 400)
            else:
                # Detailed collision grids are only available for maps 1/2.
                # On other maps, probe a short local waypoint and let the
                # authoritative server accept or correct it before continuing.
                path = [goal] if math.dist(start, goal) >= 24 else []
                for _, portal in ((destination, point) for (source, destination), point in PORTAL_CENTERS.items()
                                  if source == self.current_map):
                    if math.dist(goal, portal) < 220:
                        path = []
                        break
            if path:
                self.patrol_route = list(path)
                self.patrol_last_at = time.monotonic()
                self.patrol_timer.start()
                note = ("已验证路线，逐圈扩大至 3200 单位" if self.current_map in (1, 2)
                        else "逐圈扩大搜索路线")
                self.combat_status.setText(f"当前暂未发现怪物，正在沿{note}搜索；发现目标后会立即追击。")
                self.append_log(f"当前地图暂无可攻击怪物，开始搜索（地图 {self.current_map}，{note}）。")
                return
        self.patrol_retry_after = time.monotonic() + 3.0
        self.combat_status.setText("附近巡逻路线暂不可达，3 秒后重新规划搜索路线。")

    def advance_patrol(self) -> None:
        if (self.ws is None or not self.world_ready or self.current_map not in MAP_NAMES
                or not self.auto_attack.isChecked()
                or self.server_dead or self.respawn_pending or self.pending_destination is not None
                or self.chase_target is not None):
            self.stop_patrol()
            return
        if not self.patrol_route:
            self.stop_patrol()
            return
        while self.patrol_route and math.dist((float(self.world_x), float(self.world_y)), self.patrol_route[0]) <= 12:
            self.patrol_route.pop(0)
        if not self.patrol_route:
            self.stop_patrol()
            return
        now = time.monotonic()
        elapsed = max(0.0, now - (self.patrol_last_at or now))
        self.patrol_last_at = now
        target_x, target_y = self.patrol_route[0]
        dx, dy = target_x - float(self.world_x), target_y - float(self.world_y)
        distance = math.hypot(dx, dy)
        if distance <= 0:
            return
        # Keep patrol movement conservative to avoid movement_too_fast rejects.
        step = min(distance, self.movement_speed * elapsed * 0.4, 7.0)
        if step <= 0:
            return
        next_x = round(float(self.world_x) + dx / distance * step, 2)
        next_y = round(float(self.world_y) + dy / distance * step, 2)
        try:
            self.send_game_packet({"action": "sync", "movementRevision": self.movement_revision,
                                   "map": self.current_map, "x": next_x, "y": next_y,
                                   "animation": "run", "attackCritical": False,
                                   "flip": dx < 0}, log=False)
        except Exception as exc:
            self.stop_patrol()
            self.patrol_retry_after = time.monotonic() + 3.0
            self.combat_status.setText(f"巡逻移动失败，稍后重试：{type(exc).__name__}: {exc}")
            return
        self.world_x, self.world_y = next_x, next_y
        self.position_estimated = True

    def stop_patrol(self, *, reset_anchor: bool = False) -> None:
        if hasattr(self, "patrol_timer"):
            self.patrol_timer.stop()
        self.patrol_route = []
        self.patrol_last_at = None
        if reset_anchor:
            self.patrol_anchor = None
            self.patrol_direction_index = 0
            self.patrol_ring = 320.0

    def start_chase(self, encounter_id: str, *, recovery: bool = False) -> None:
        if not recovery:
            self.movement_corrections = 0
        monster = self.monsters.get(encounter_id)
        if (not monster or not self.monster_matches_level_range(monster)
                or self.world_x is None or self.world_y is None):
            return
        start = float(self.world_x), float(self.world_y)
        goal = float(monster["x"]), float(monster["y"])
        # Detailed collision maps are currently available for maps 1 and 2.
        # Other maps still chase every server-reported monster by approaching
        # it directly; the server remains authoritative and may correct an
        # invalid position if an obstacle blocks the straight route.
        path = find_map_path(self.current_map, start, goal) if self.current_map in (1, 2) else [goal]
        if not path:
            self.combat_status.setText(f"找到怪物 {encounter_id[:8]}，但当前地图缺少可验证的追击路线。")
            self.chase_retry_after = time.monotonic() + 3.0
            return
        points = [start, *path]
        remaining = 35.0
        approach = []
        for index in range(len(points) - 1, 0, -1):
            segment = math.dist(points[index - 1], points[index])
            if segment >= remaining:
                ratio = remaining / segment
                stop = (points[index][0] + (points[index - 1][0] - points[index][0]) * ratio,
                        points[index][1] + (points[index - 1][1] - points[index][1]) * ratio)
                approach = [*points[1:index], stop]
                break
            remaining -= segment
        if not approach:
            return
        self.chase_target = encounter_id
        self.chase_route = approach
        self.last_chase_at = time.monotonic()
        route_note = "估算直线路径" if self.current_map not in (1, 2) else f"{len(approach)} 段路线"
        self.combat_status.setText(f"正在沿{route_note}接近怪物 {encounter_id[:8]}…")
        self.chase_timer.start()

    def advance_chase(self) -> None:
        if self.server_dead or self.respawn_pending:
            self.stop_chase()
            return
        monster = self.monsters.get(self.chase_target)
        if not monster or int(monster.get("health", 0)) <= 0 or self.pending_destination is not None:
            self.stop_chase()
            return
        if self.monster_distance(monster) <= 45:
            self.stop_chase()
            return
        while self.chase_route and math.dist((float(self.world_x), float(self.world_y)), self.chase_route[0]) <= 1:
            self.chase_route.pop(0)
        if not self.chase_route:
            self.stop_chase()
            return
        now = time.monotonic()
        elapsed = min(0.1, max(0.0, now - (self.last_chase_at or now)))
        self.last_chase_at = now
        target_x, target_y = self.chase_route[0]
        dx, dy = target_x - float(self.world_x), target_y - float(self.world_y)
        distance = math.hypot(dx, dy)
        step = min(distance, self.movement_speed * elapsed, self.movement_speed / 10.0)
        if step <= 0:
            return
        next_x = round(float(self.world_x) + dx / distance * step, 2)
        next_y = round(float(self.world_y) + dy / distance * step, 2)
        try:
            self.send_game_packet({"action": "sync", "movementRevision": self.movement_revision,
                                   "map": self.current_map, "x": next_x, "y": next_y,
                                   "animation": "run", "attackCritical": False,
                                   "flip": dx < 0}, log=False)
        except Exception as exc:
            self.stop_chase()
            self.combat_status.setText(f"追击移动失败：{type(exc).__name__}: {exc}")
            return
        self.world_x, self.world_y = next_x, next_y
        self.position_estimated = True

    def stop_chase(self) -> None:
        self.chase_timer.stop()
        self.chase_target = None
        self.chase_route = []

    def send_game_packet(self, packet: dict, *, log: bool = True) -> None:
        if self.ws is None:
            raise WsError("连接已断开")
        self.sequence += 1
        payload = dict(packet, seq=self.sequence, life=self.life)
        self.ws.send_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
        if packet.get("action") == "sync":
            self.last_position_sync_at = time.monotonic()
        if packet.get("action") == "sync" and packet.get("animation") == "run":
            self.movement_sent_count += 1
            since_welcome = round(time.monotonic() - self.welcome_at, 3) if self.welcome_at is not None else None
            self.movement_trace.append((since_welcome, packet.get("x"), packet.get("y"),
                                        packet.get("movementRevision"), payload["seq"], payload["life"]))
        if log:
            self.append_log("SEND game: " + json.dumps(payload, ensure_ascii=False))

    def send_stationary_sync(self, *, force: bool = False) -> None:
        if (self.ws is None or not self.world_ready or self.server_dead or self.current_map is None or
                self.world_x is None or self.world_y is None or self.pending_destination is not None or
                self.chase_target is not None or self.patrol_timer.isActive()):
            return
        if not force and self.last_position_sync_at is not None and time.monotonic() - self.last_position_sync_at < 1.0:
            return
        try:
            self.send_game_packet({"action": "sync", "movementRevision": self.movement_revision,
                                   "map": self.current_map, "x": self.world_x, "y": self.world_y,
                                   "animation": "idle", "attackCritical": False, "flip": False}, log=False)
            if force:
                self.append_log(f"进入世界后原地同步：map={self.current_map}, x={self.world_x}, y={self.world_y}, revision={self.movement_revision}")
        except Exception as exc:
            self.append_log(f"原地位置同步失败：{type(exc).__name__}: {exc}")

    def request_respawn(self) -> None:
        if self.ws is None or not self.world_ready or not self.server_dead or self.respawn_pending:
            return
        self.move_timer.stop()
        self.stop_chase()
        self.combat_timer.stop()
        self.position_sync_timer.stop()
        self.respawn_pending = True
        self.respawn_attempts += 1
        self.respawn_request_generation += 1
        request_generation = self.respawn_request_generation
        self.update_map_buttons()
        try:
            self.send_game_packet({"action": "respawn"})
            self.append_log("检测到角色阵亡，已自动发送 respawn 请求；等待服务端确认。")
            self.travel_status.setText("已请求回到城镇，等待服务端复活确认…")
            QTimer.singleShot(8000, lambda: self.respawn_timeout(request_generation))
        except Exception as exc:
            self.respawn_pending = False
            self.update_map_buttons()
            self.travel_status.setText(f"复活请求发送失败：{type(exc).__name__}: {exc}")

    def respawn_timeout(self, request_generation: int) -> None:
        if request_generation != self.respawn_request_generation or not self.respawn_pending:
            return
        self.respawn_pending = False
        self.update_map_buttons()
        self.append_log(f"复活确认等待超过 8 秒；尝试次数 {self.respawn_attempts}/3。")
        if self.ws is not None and self.server_dead and self.respawn_attempts < 3:
            self.request_respawn()
        else:
            self.travel_status.setText("未收到复活确认，自动重试已停止。可点击回到城镇重试；请查看 respawn 响应日志。")

    def send_keepalive(self) -> None:
        if self.ws is None or not self.world_ready:
            self.keepalive.stop()
            return
        if (self.last_pong_received_at
                and time.monotonic() - self.last_pong_received_at > 12):
            self.append_log("12 秒未收到服务端 pong，判定连接失活并触发自动重连。")
            ws, self.ws = self.ws, None
            self.keepalive.stop()
            ws.close()
            self.bridge.state.emit("心跳超时，正在重连…")
            self.bridge.connect_failed.emit()
            return
        try:
            sent_at = int(time.monotonic() * 1000)
            self.pending_pings[sent_at] = time.monotonic()
            # Bound stale entries if a server or proxy does not answer pings.
            if len(self.pending_pings) > 8:
                self.pending_pings.pop(next(iter(self.pending_pings)), None)
            self.send_game_packet({"action": "ping", "sentAt": sent_at}, log=False)
        except Exception as exc:
            self.append_log(f"心跳发送失败：{type(exc).__name__}: {exc}")
            self.keepalive.stop()

    def travel_to(self, destination: int, *, recovery: bool = False) -> None:
        if not self.world_ready or self.current_map is None or self.pending_destination is not None:
            return
        if not recovery:
            self.movement_corrections = 0
            if not self.has_auto_travel_intent():
                self.auto_route_retry_count = 0
        if self.chase_target is not None:
            self.stop_chase()
        if self.world_x is None or self.world_y is None:
            self.travel_status.setText("没有服务端位置，无法构造同步帧。")
            return
        portal = PORTAL_CENTERS.get((self.current_map, destination))
        if portal and self.current_map == 1:
            route = find_town_path((float(self.world_x), float(self.world_y)), portal)
            if not route:
                self.travel_status.setText("无法从当前坐标找到主城可通行路径；已取消切图。")
                return
            self.route_points = list(route)
        else:
            self.route_points = [portal] if portal else []
        self.pending_destination = destination
        self.pending_portal = portal
        self.travel_attempt += 1
        attempt = self.travel_attempt
        if portal:
            self.last_move_at = time.monotonic()
            self.travel_status.setText(f"正沿 {len(self.route_points)} 段可通行路线前往入口 ({portal[0]}, {portal[1]})。")
            self.move_timer.start()
        else:
            self.travel_status.setText("当前地图没有通往该地图的入口；按当前位置请求切图。")
            self.send_travel(destination, attempt)
        self.update_map_buttons()

    def advance_to_portal(self) -> None:
        if self.server_dead or self.respawn_pending:
            self.move_timer.stop()
            return
        if self.pending_destination is None or self.pending_portal is None:
            self.move_timer.stop()
            return
        now = time.monotonic()
        elapsed = min(0.1, max(0.0, now - (self.last_move_at or now)))
        self.last_move_at = now
        while self.route_points and math.dist((float(self.world_x), float(self.world_y)), self.route_points[0]) <= 1.0:
            self.route_points.pop(0)
        if not self.route_points:
            self.move_timer.stop()
            attempt = self.travel_attempt
            self.travel_status.setText("已到入口坐标，补发位置同步并等待服务端确认…")
            try:
                self.send_game_packet({"action": "sync", "movementRevision": self.movement_revision,
                                       "map": self.current_map, "x": round(float(self.world_x), 2),
                                       "y": round(float(self.world_y), 2), "animation": "idle",
                                       "attackCritical": False, "flip": False}, log=False)
            except Exception as exc:
                self.travel_status.setText(f"入口位置确认帧发送失败：{type(exc).__name__}: {exc}")
                return
            QTimer.singleShot(900, lambda: self.send_travel(self.pending_destination, attempt)
                              if self.pending_destination is not None else None)
            return
        target_x, target_y = self.route_points[0]
        dx, dy = target_x - float(self.world_x), target_y - float(self.world_y)
        remaining = math.hypot(dx, dy)
        step = min(remaining, self.movement_speed * elapsed, self.movement_speed / 10.0)
        if step <= 0:
            return
        next_x = round(float(self.world_x) + dx / remaining * step, 2)
        next_y = round(float(self.world_y) + dy / remaining * step, 2)
        position = {"action": "sync", "movementRevision": self.movement_revision,
                    "map": self.current_map, "x": next_x, "y": next_y,
                    "animation": "run", "attackCritical": False, "flip": False}
        try:
            self.send_game_packet(position, log=False)
        except Exception as exc:
            self.cancel_travel()
            self.travel_status.setText(f"移动帧发送失败：{type(exc).__name__}: {exc}")
            return
        self.world_x, self.world_y = next_x, next_y
        self.position_estimated = True
        now = time.monotonic()
        if now - self.last_world_status_render_at >= 2.0:
            self.world_status.setText(f"正在前往入口 · 距离约 {round(remaining - step)}")
            self.last_world_status_render_at = now

    def cancel_travel(self) -> None:
        self.return_map_target = None
        self.move_timer.stop()
        self.pending_destination = None
        self.pending_portal = None
        self.route_points = []
        self.travel_attempt += 1
        self.travel_status.setText("已停止自动移动；当前坐标是客户端预计值，重连可取得服务端位置。")
        self.update_map_buttons()

    def continue_return_map(self) -> None:
        if not self.auto_return_map.isChecked() or self.server_dead or self.respawn_pending:
            self.return_map_target = None
            return
        target = self.return_map_target
        if target is None or self.ws is None or not self.world_ready:
            return
        if self.current_map == target:
            self.return_map_target = None
            self.travel_status.setText(f"已自动返回 {MAP_NAMES[target]}，按自动战斗选项继续。")
            QTimer.singleShot(0, self.continue_quest_map_travel)
            return
        if self.pending_destination is not None:
            return
        queue = deque([(self.current_map, [])])
        visited = {self.current_map}
        while queue:
            current, route = queue.popleft()
            for neighbor in MAP_ROUTES.get(current, ()):
                if neighbor in visited:
                    continue
                next_route = route + [neighbor]
                if neighbor == target:
                    if 5 in next_route and not self.use_ticket.isChecked():
                        self.return_map_target = None
                        self.travel_status.setText("自动返回遗迹需要先勾选使用入场券。")
                        return
                    self.append_log(f"复活后自动返回：目标地图 {target}，下一站 {next_route[0]}。")
                    self.travel_to(next_route[0])
                    if self.pending_destination is None:
                        self.return_map_target = None
                    return
                visited.add(neighbor)
                queue.append((neighbor, next_route))
        self.return_map_target = None
        self.travel_status.setText("找不到通往自动返回地图的相邻地图路线。")

    def on_return_map_changed(self, *args) -> None:
        self.return_map_target = None
        if not self.auto_return_map.isChecked():
            return
        if self.server_dead or self.respawn_pending or not self.world_ready or self.ws is None:
            self.travel_status.setText("自动进图已开启，等待登录或复活确认。")
            return
        self.return_map_target = self.return_map.currentData()
        self.continue_return_map()

    def send_travel(self, destination: int, attempt: int) -> None:
        if self.pending_destination != destination or self.travel_attempt != attempt:
            return
        quest_id = (self.quest_map_quest_id if self.quest_map_target is not None
                    else 0 if self.questless_farm_mode else self.quest_id.value())
        travel = {"action": "travel", "map": destination,
                  "questId": quest_id or 0, "useTicket": self.use_ticket.isChecked(),
                  "movementRevision": self.movement_revision}
        try:
            self.send_game_packet(travel)
            self.travel_status.setText(f"正在请求进入 {MAP_NAMES[destination]}…")
            QTimer.singleShot(6500, lambda: self.travel_timeout(destination, attempt))
        except Exception as exc:
            self.pending_destination = None
            self.pending_portal = None
            self.route_points = []
            self.travel_status.setText(f"切图请求发送失败：{type(exc).__name__}: {exc}")
            self.update_map_buttons()

    def travel_timeout(self, destination: int, attempt: int) -> None:
        if self.pending_destination == destination and self.travel_attempt == attempt:
            self.pending_destination = None
            self.pending_portal = None
            self.route_points = []
            self.travel_status.setText("6 秒内没有收到 travel_result；已释放进图状态，防止一直卡住。")
            self.update_map_buttons()
            self.schedule_auto_travel_retry()

    def closeEvent(self, event) -> None:  # noqa: N802
        self.minimap_timer.stop()
        self.disconnect_ws()
        event.accept()


def main() -> None:
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()


if __name__ == "__main__":
    main()
