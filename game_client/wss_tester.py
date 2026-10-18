from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections import deque
import math
import os
from pathlib import Path
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

from PySide6.QtCore import QObject, Signal, Qt, QTimer, QSettings
from PySide6.QtGui import QPixmap
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
                    "EPIC": "史诗", "LEGENDARY": "传说"}
try:
    _item_name_rows = json.loads((Path(__file__).with_name("assets") / "item_names_zh.json").read_text(encoding="utf-8"))
except (OSError, ValueError):
    _item_name_rows = []
ITEM_NAMES_ZH = {str(row.get("itemCode", "")).upper(): row.get("nameZh", "")
                 for row in _item_name_rows if isinstance(row, dict)}
ITEM_NAMES_ZH.update({str(row.get("nameEn", "")).casefold(): row.get("nameZh", "")
                      for row in _item_name_rows if isinstance(row, dict)})


def localized_item_name(item: dict) -> str:
    for key in ("nameZh", "displayNameZh"):
        value = item.get(key)
        if value:
            return str(value)
    code = str(item.get("itemCode", "")).upper()
    name = str(item.get("name") or item.get("displayName") or item.get("nameEn") or "")
    return str(ITEM_NAMES_ZH.get(code) or ITEM_NAMES_ZH.get(name.casefold()) or name or code or "物品")


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
        self.ws: MiniWebSocket | None = None
        self.reader: threading.Thread | None = None
        self.session_token = ""
        self.signed_session_token = ""
        self._resolved_token = ""
        self.manual_disconnect = False
        self._auto_reconnect_login = False
        self._reconnect_attempt = 0
        self.settings = QSettings("Tabby", "TabbyDesktop")
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
        self.chase_timer = QTimer(self)
        self.chase_timer.setInterval(66)
        self.chase_timer.setTimerType(Qt.TimerType.PreciseTimer)
        self.chase_timer.timeout.connect(self.advance_chase)
        self.reconnect_timer = QTimer(self)
        self.reconnect_timer.setSingleShot(True)
        self.reconnect_timer.timeout.connect(self.retry_connection)

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
        self.token.setPlaceholderText("粘贴游戏 Token，点击连接；仅保存在当前进程")
        self.auth_method = QComboBox()
        self.auth_method.addItem("Token 登录", "token")
        self.auth_method.addItem("BSC 私钥签名", "private_key")
        self.auth_method.setToolTip("私钥仅在本机用于签名，不会发送给服务器或保存到磁盘。")
        self.private_key = QLineEdit()
        self.private_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.private_key.setPlaceholderText("输入 EVM 私钥（BSC / chainId 56），仅用于本次签名")
        self.private_key.textEdited.connect(self.invalidate_signed_session)
        private_key_label = QLabel("钱包私钥（本机签名）")
        private_key_label.setObjectName("fieldLabel")
        origin_label = QLabel("Origin")
        token_label = QLabel("游戏会话 token")
        for label in (origin_label, token_label):
            label.setObjectName("fieldLabel")
        fields.addWidget(origin_label, 0, 0)
        fields.addWidget(token_label, 0, 1)
        fields.addWidget(self.origin, 1, 0)
        fields.addWidget(self.token, 1, 1)
        fields.addWidget(private_key_label, 2, 0, 1, 2)
        fields.addWidget(self.private_key, 3, 0, 1, 2)
        private_key_label.hide()
        self.private_key.hide()
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
        self.remember_private_key = QCheckBox("记住钱包私钥（系统钥匙串）")
        self.remember_private_key.setChecked(self.settings.value("rememberPrivateKey", False, type=bool))
        self.remember_private_key.setToolTip("仅保存到系统钥匙串/凭据管理器；不会写入应用配置文件。")
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
        legend = QLabel("青色 · 角色    粉色 · 怪物    金色 · 精英    蓝色 · 入口")
        legend.setObjectName("subtitle")
        legend.setMinimumWidth(360)
        legend.setWordWrap(True)
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

        travel_card = QFrame()
        travel_card.setObjectName("card")
        travel_layout = QVBoxLayout(travel_card)
        travel_layout.setContentsMargins(20, 16, 20, 18)
        travel_layout.setSpacing(10)
        travel_title = QLabel("地图切换")
        travel_title.setObjectName("sectionTitle")
        travel_layout.addWidget(travel_title)
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
        options.addWidget(self.use_ticket)
        options.addStretch(1)
        options.addWidget(self.stop_move_button)
        travel_layout.addLayout(options)
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
        quest_title_row.addWidget(self.auto_quest)
        self.quest_map_auto = QCheckBox("按任务地图自动进图")
        self.quest_map_auto.setToolTip("自动接取新任务后，沿地图入口路线前往该任务对应地图。遗迹仍需入场券。")
        self.quest_map_auto.stateChanged.connect(self.on_quest_map_auto_changed)
        self.use_ticket.stateChanged.connect(lambda *_: QTimer.singleShot(0, self.continue_quest_map_travel))
        quest_title_row.addWidget(self.quest_map_auto)
        quest_title_row.addWidget(self.refresh_profile_button)
        quest_layout.addLayout(quest_title_row)
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
        self.monster_table = QTableWidget(0, 6)
        self.monster_table.setHorizontalHeaderLabels(["encounterId", "怪物", "品级", "生命", "坐标", "距离"])
        self.monster_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.monster_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.monster_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.monster_table.setAlternatingRowColors(True)
        self.monster_table.verticalHeader().setVisible(False)
        self.monster_table.setColumnHidden(0, True)
        for col in (1, 2, 3, 4, 5):
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
        self.elite_only = QCheckBox("只打精英怪")
        self.elite_only.toggled.connect(self.on_elite_filter_changed)
        combat_controls.addWidget(self.attack_button)
        combat_controls.addWidget(self.auto_attack)
        combat_controls.addWidget(self.elite_only)
        self.encounter_id_toggle = QPushButton("查看 encounterId")
        self.encounter_id_toggle.setCheckable(True)
        self.encounter_id_toggle.setToolTip("默认隐藏技术 ID；点击后显示怪物 encounterId 列。")
        self.encounter_id_toggle.toggled.connect(self.toggle_encounter_id_column)
        combat_controls.addWidget(self.encounter_id_toggle)
        combat_controls.addStretch(1)
        combat_layout.addLayout(combat_controls)
        combat_hint = QLabel("自动模式会搜索当前地图收到的全部怪物；进入 70 单位后使用服务端票据攻击。无可用怪物时暂不巡逻。")
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
        """Present existing controls in a compact two-column workspace."""
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

        header = QHBoxLayout()
        brand = QLabel("TABBY  <span style='color:#9da794;font-weight:400'> / 探索控制台</span>")
        brand.setObjectName("title")
        header.addWidget(brand)
        header.addStretch()
        self.account_toggle = QPushButton("账号连接")
        self.account_toggle.setObjectName("quietButton")
        self.account_toggle.setCheckable(True)
        header.addWidget(self.account_toggle)
        place(header, self.status)
        layout.addLayout(header)
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
        left.setSpacing(14)
        left_panel = QWidget(root)
        left_panel.setLayout(left)
        left_panel.setFixedWidth(345)
        columns.addWidget(left_panel)
        right = QVBoxLayout()
        right.setSpacing(14)
        columns.addLayout(right, 1)
        layout.addLayout(columns, 1)

        character, box = card("角色概览")
        character_row = QHBoxLayout()
        portrait = QLabel()
        self.character_portrait = portrait
        portrait.setFixedSize(68, 92)
        portrait.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pixmap = QPixmap(str(Path(__file__).with_name("assets") / "portrait.webp"))
        portrait.setPixmap(pixmap.scaled(60, 60, Qt.AspectRatioMode.KeepAspectRatio,
                                       Qt.TransformationMode.SmoothTransformation))
        character_row.addWidget(portrait)
        self.character_status.setParent(root)
        self.character_status.hide()
        facts = QGridLayout()
        facts.setHorizontalSpacing(12)
        facts.setVerticalSpacing(5)
        self.character_facts = {}
        for index, key in enumerate(("角色", "职业", "等级", "状态", "生命", "经验", "攻击", "防御", "金币", "移速加成")):
            label = QLabel(key)
            label.setObjectName("subtitle")
            value = QLabel("—")
            value.setTextFormat(Qt.TextFormat.PlainText)
            self.character_facts[key] = value
            row, col = index // 2, (index % 2) * 2
            facts.addWidget(label, row, col)
            facts.addWidget(value, row, col + 1)
        self.health_bar = QProgressBar()
        self.fatigue_bar = QProgressBar()
        for row, (title, bar) in enumerate((("生命", self.health_bar), ("疲劳余量", self.fatigue_bar)), 5):
            bar.setRange(0, 100)
            bar.setValue(0)
            bar.setFormat("等待数据")
            bar.setFixedHeight(18)
            bar.setStyleSheet("QProgressBar {background:#171c16;border:1px solid #46523f;border-radius:4px;text-align:center;color:#edf0e6;font-size:11px;} QProgressBar::chunk {background:" + ("#809e73" if row == 5 else "#b59e6e") + ";border-radius:3px;}")
            facts.addWidget(QLabel(title), row, 0)
            facts.addWidget(bar, row, 1, 1, 3)
        character_row.addLayout(facts, 1)
        box.addLayout(character_row)
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
            label.setStyleSheet("background:#1b1e1b;border:1px solid #363d33;border-radius:5px;padding:5px;")
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
        for widget in (self.auto_attack, self.elite_only, self.attack_button, self.combat_status):
            place(box, widget)
        left.addWidget(battle)
        travel, box = card("地图与复活")
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
        place(box, self.use_ticket)
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
                        "<span style='color:#c78f86'>●</span> 怪物　"
                        "<span style='color:#cfb77b'>◆</span> 精英　"
                        "<span style='color:#9cacae'>□</span> 入口　┄ 路线")
        legend.setObjectName("subtitle")
        legend.hide()
        place(box, self.map_activity)
        self.map_activity.setMaximumHeight(30)
        overview = QHBoxLayout()
        overview.setSpacing(14)
        character.setFixedHeight(340)
        map_card.setFixedHeight(300)
        overview.addWidget(character, 1, Qt.AlignmentFlag.AlignTop)
        overview.addWidget(map_card, 0, Qt.AlignmentFlag.AlignTop)
        right.addLayout(overview)
        tabs = QTabWidget(root)
        tabs.setDocumentMode(True)
        tabs.tabBar().setDrawBase(False)
        quest_page = QWidget()
        quest_box = QVBoxLayout(quest_page)
        quest_box.setContentsMargins(10, 12, 10, 10)
        quest_box.setSpacing(10)
        quest_row = QHBoxLayout()
        place(quest_row, self.auto_quest)
        quest_row.addStretch()
        place(quest_row, self.refresh_profile_button)
        quest_box.addLayout(quest_row)
        place(quest_box, self.quest_status)
        self.quest_table.setMinimumHeight(160)
        self.quest_table.setMaximumHeight(16777215)
        place(quest_box, self.quest_table, 1)
        tabs.addTab(quest_page, "任务")
        monsters_page = QWidget()
        monsters_box = QVBoxLayout(monsters_page)
        self.encounter_id_toggle.setParent(root)
        self.encounter_id_toggle.hide()
        self.monster_table.setColumnHidden(0, False)
        self.monster_table.horizontalHeader().moveSection(0, 5)
        self.monster_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.monster_table.setColumnWidth(0, 285)
        self.monster_table.setMaximumHeight(16777215)
        place(monsters_box, self.monster_table, 1)
        tabs.addTab(monsters_page, "怪物")
        log_page = QWidget()
        log_box = QVBoxLayout(log_page)
        place(log_box, self.clear_button)
        place(log_box, self.log, 1)
        tabs.addTab(log_page, "运行日志")
        tools_page = QWidget()
        tools_box = QVBoxLayout(tools_page)
        tools_box.addWidget(QLabel("手动协议调试"))
        place(tools_box, self.quest_id)
        place(tools_box, self.message, 1)
        place(tools_box, self.send_button)
        tabs.addTab(tools_page, "调试")
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
            QLabel { color: #d5dccd; }
            QTabWidget::pane { border: 1px solid #363d33; background: #222522; border-radius: 10px; }
            QTabBar::tab { background: transparent; color: #a8afa3; padding: 10px 18px; border-bottom: 2px solid transparent; }
            QTabBar::tab:selected { color: #afc69e; border-bottom: 2px solid #afc69e; }
            QTabBar::tab:hover { background: #30382c; }
            QComboBox { color: #e3edf7; background: #1b1e1b; border: 1px solid #424a3e; border-radius: 7px; padding: 8px; }
            QComboBox QAbstractItemView { color: #e3edf7; background: #293025; selection-background-color: #285b50; }
            QHeaderView { background: #30352f; }
            QCheckBox::indicator { width: 15px; height: 15px; border-radius: 4px; border: 1px solid #50657c; background: #1b1e1b; }
            QCheckBox::indicator:checked { background: #9bb490; border: 3px solid #52664a; }
            QCheckBox::indicator:hover { border-color: #afc69e; }
            QPushButton:focus, QCheckBox:focus, QComboBox:focus { border: 1px solid #afc69e; }
        """)
        for button in root.findChildren(QPushButton):
            button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.update_map_buttons()

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
        self.setStyleSheet("""
            QMainWindow, QDialog, QScrollArea#mainScroll, QWidget#root { background: #181a19; color: #e6e8df; }
            QFrame#card { background: #222522; border: 1px solid #363d33; border-radius: 12px; }
            QFrame#sessionCard { background: #152132; border: 1px solid #30425a; border-radius: 10px; }
            QLabel#title { color: #f7faff; font-size: 23px; font-weight: 700; }
            QLabel#subtitle { color: #a8afa3; font-size: 12px; }
            QLabel#sectionTitle { color: #e6e8df; font-size: 15px; font-weight: 700; }
            QLabel#fieldLabel { color: #afbed2; font-size: 12px; font-weight: 600; }
            QLabel#sessionUrl { color: #dce8f7; font-family: Menlo, monospace; font-size: 13px; }
            QLabel#status { color: #a8bad0; font-size: 12px; font-weight: 700; }
            QLineEdit, QPlainTextEdit, QSpinBox { background: #1b1e1b; color: #e1e6da; border: 1px solid #424a3e; border-radius: 8px; padding: 8px 10px; selection-background-color: #2c6e5a; }
            QLineEdit:focus, QPlainTextEdit:focus { border: 1px solid #4cc48b; }
            QLineEdit::placeholder, QPlainTextEdit::placeholder { color: #788ba3; }
            QLineEdit#urlInput, QPlainTextEdit#messageInput, QPlainTextEdit#logView { font-family: Menlo, monospace; font-size: 12px; }
            QPlainTextEdit#logView { background: #1b1e1a; color: #d3e1ef; border: 1px solid #243248; }
            QTableWidget { background: #1b1e1b; alternate-background-color: #272c26; color: #e1e6da; border: 1px solid #424a3e; border-radius: 8px; gridline-color: #363d33; selection-background-color: #275f4b; }
            QHeaderView::section { background: #30352f; color: #b9cbe0; border: 0; border-bottom: 1px solid #424a3e; padding: 7px; font-weight: 600; }
            QPushButton { min-height: 30px; padding: 2px 15px; border-radius: 7px; font-weight: 600; }
            QPushButton#primaryButton { background: #9bb490; color: #182017; border: 1px solid #9bb490; }
            QPushButton#primaryButton:hover { background: #aec4a4; border-color: #aec4a4; }
            QPushButton#secondaryButton { background: #30362e; color: #dce2d5; border: 1px solid #4a5545; }
            QPushButton#secondaryButton:hover { background: #3c4637; }
            QPushButton#quietButton { background: transparent; color: #aab5a4; border: 1px solid transparent; padding-left: 5px; padding-right: 5px; }
            QPushButton#quietButton:hover { color: #e7f3ff; background: #343e2f; }
            QPushButton:disabled { background: #253245; color: #77889b; border: 1px solid #34445b; }
            QCheckBox { color: #cbd9e8; spacing: 8px; }
            QScrollBar:vertical { background: #181a19; width: 10px; }
            QScrollBar::handle:vertical { background: #32445b; border-radius: 5px; min-height: 25px; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        """)

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

    def on_connected(self, ws: MiniWebSocket) -> None:
        if ws is None:
            return
        self.ws = ws
        self.send_button.setEnabled(True)
        self.disconnect_button.setEnabled(True)
        self.connect_button.setEnabled(False)
        self.manual_disconnect = False
        self._auto_reconnect_login = False
        self._reconnect_attempt = 0
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
        self.keepalive.stop()
        self.reset_world_state()
        self.update_map_buttons()
        self.connect_button.setEnabled(True)
        self.disconnect_button.setEnabled(False)
        self.send_button.setEnabled(False)
        self.schedule_auto_reconnect()

    def schedule_auto_reconnect(self) -> None:
        if self.manual_disconnect or not self.auto_reconnect.isChecked():
            self._auto_reconnect_login = False
            return
        if self._reconnect_attempt >= 8:
            self.append_log("自动重连连续失败 8 次，已暂停；请检查网络或手动重试。")
            self._auto_reconnect_login = False
            return
        delay = min(30, 2 ** self._reconnect_attempt)
        self._reconnect_attempt += 1
        self.append_log(f"{delay} 秒后自动重连（第 {self._reconnect_attempt} 次）。")
        self.bridge.state.emit(f"{delay} 秒后自动重连…")
        self.reconnect_timer.start(delay * 1000)

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
            return
        try:
            secure_keyring().delete_password(KEYRING_SERVICE, KEYRING_ACCOUNT)
            self.append_log("已从系统钥匙串删除已记住的钱包私钥。")
        except Exception:
            # No saved entry is the common case; avoid leaking backend details.
            pass

    def connect_ws(self) -> None:
        if not self._auto_reconnect_login:
            self.reconnect_timer.stop()
            self._reconnect_attempt = 0
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
        self.private_key.setVisible(private_mode)

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
        if not private_key and self.remember_private_key.isChecked():
            try:
                private_key = secure_keyring().get_password(KEYRING_SERVICE, KEYRING_ACCOUNT) or ""
            except Exception:
                QMessageBox.warning(self, "系统钥匙串不可用", "无法读取已记住的私钥。请检查系统钥匙串，或重新输入私钥。")
                return
        if not private_key:
            QMessageBox.information(self, "需要私钥", "请输入用于本机签名的钱包私钥。")
            return
        self.private_key.clear()
        remember_private_key = self.remember_private_key.isChecked()
        automatic_reauth = self._auto_reconnect_login and remember_private_key
        api_path = parsed.path.rstrip("/")
        if api_path.endswith("/realtime"):
            api_path = api_path[:-len("/realtime")]
        api_base = urllib.parse.urlunsplit(("https", parsed.netloc, api_path, "", ""))
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

                def request(path: str, body: dict, bearer: str | None = None) -> dict:
                    headers = {"Accept": "application/json", "Content-Type": "application/json"}
                    if bearer:
                        headers["Authorization"] = "Bearer " + bearer
                    request_body = json.dumps(body).encode("utf-8")
                    req = urllib.request.Request(api_base + path, data=request_body,
                                                 headers=headers, method="POST")
                    try:
                        with urllib.request.urlopen(req, timeout=15) as response:
                            result = json.loads(response.read().decode("utf-8"))
                    except urllib.error.HTTPError as exc:
                        raw = exc.read().decode("utf-8", errors="replace")
                        try:
                            error_data = json.loads(raw)
                        except (TypeError, ValueError):
                            error_data = {"message": raw[:300]}
                        code = error_data.get("code", "") if isinstance(error_data, dict) else ""
                        message = error_data.get("message", "") if isinstance(error_data, dict) else ""
                        raise RuntimeError(str(code or message or f"HTTP {exc.code}")) from None
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
                signature = signed.signature.hex()
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
                if remember_private_key:
                    try:
                        secure_keyring().set_password(KEYRING_SERVICE, KEYRING_ACCOUNT, key_material)
                    except Exception:
                        remember_error = "登录成功，但系统钥匙串保存失败；私钥未被记住。"
                self.bridge.signed_login.emit({"ok": True, "token": str(game_token),
                                               "address": account.address,
                                               "remember_error": remember_error})
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
        self.reconnect_timer.stop()
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
        if hasattr(self, "move_timer"):
            self.move_timer.stop()
        if hasattr(self, "combat_timer"):
            self.combat_timer.stop()
        if hasattr(self, "chase_timer"):
            self.chase_timer.stop()
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
        self.combat_generation = getattr(self, "combat_generation", 0) + 1
        self.chase_target = None
        self.chase_route = []
        self.last_chase_at = None
        self.chase_retry_after = 0.0
        self.invalid_target_until = {}
        if hasattr(self, "monster_table"):
            self.monster_table.setRowCount(0)
            self.combat_status.setText("等待服务端怪物快照和攻击票据…")
            self.update_attack_button()
        self.travel_attempt = getattr(self, "travel_attempt", 0) + 1
        if hasattr(self, "quest_table"):
            self.quest_table.setRowCount(0)
            self.quest_status.setText("等待服务端任务数据…")

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
            button.setToolTip(MAP_NAMES[map_id] + (" · 相邻入口" if route else ""))
        if self.current_map is None:
            self.world_status.setText("等待登录游戏世界…")
        else:
            self.world_status.setText(
                f"当前：{MAP_NAMES.get(self.current_map, str(self.current_map))}"
                f"    {'预计坐标' if self.position_estimated else '坐标'}：({self.world_x}, {self.world_y})"
                f"    修订：{self.movement_revision}    生命序号：{self.life}"
            )

    def accept_packet(self, packet: dict) -> None:
        kind = packet.get("type")
        if kind == "welcome" and isinstance(packet.get("position"), dict):
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
                if not bool(packet.get("delta", False)):
                    self.last_self_state.clear()
                self.last_self_state.update(self_state)
                self_state = self.last_self_state
                # A respawn acknowledgement carries the authoritative spawn
                # position; a delta may omit dead=False from its self object.
                if operation == "respawn" and isinstance(packet.get("position"), dict):
                    self_state["dead"] = False
                self.server_dead = bool(self_state.get("dead", False))
                self.refresh_character_status()
                if self.server_dead:
                    detected_death = not self.respawn_pending and self.respawn_attempts < 3
                    self.move_timer.stop()
                    self.stop_chase()
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
                    self.monsters.clear()
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
                        self.claim_encounter_reward(encounter_id)
            if not self.world_ready:
                self.world_ready = True
                self.append_log("游戏世界已就绪；后续高频 snapshot 已折叠。")
                self.keepalive.start()
                self.send_stationary_sync(force=True)
                self.position_sync_timer.start()
                if not self.server_dead and not self.auto_attack.isChecked():
                    self.auto_attack.setChecked(True)
                elif self.auto_attack.isChecked() and not self.server_dead:
                    self.combat_timer.start()
                if self.questless_farm_mode:
                    QTimer.singleShot(500, self.continue_quest_map_travel)
                self.refresh_profile_data()
            self.update_map_buttons()
            if detected_death:
                self.travel_status.setText("检测到角色阵亡，正在自动请求回到城镇…")
                QTimer.singleShot(0, self.request_respawn)
        elif kind == "travel_result":
            self.move_timer.stop()
            self.stop_chase()
            destination = self.pending_destination
            self.pending_destination = None
            self.pending_portal = None
            self.route_points = []
            if packet.get("ok"):
                if destination is not None:
                    self.current_map = destination
                self.world_x = packet.get("x", self.world_x)
                self.world_y = packet.get("y", self.world_y)
                self.movement_revision = int(packet.get("revision", self.movement_revision))
                self.position_estimated = False
                self.monsters.clear()
                self.refresh_monster_table()
                self.travel_status.setText(f"已进入 {MAP_NAMES.get(self.current_map, str(self.current_map))}；服务端已确认。")
            else:
                reason = packet.get("reason", "未知原因")
                retry = packet.get("retryAfter")
                self.travel_status.setText(f"入图被拒绝：{reason}" + (f"；{retry} 秒后可重试" if retry else ""))
            self.update_map_buttons()
            if packet.get("ok") and self.return_map_target is not None:
                QTimer.singleShot(500, self.continue_return_map)
            elif packet.get("ok") and (self.quest_map_target is not None or self.questless_farm_mode):
                QTimer.singleShot(500, self.continue_quest_map_travel)
            elif not packet.get("ok"):
                self.return_map_target = None
                self.quest_map_target = None
                self.quest_map_quest_id = None
        elif kind == "attack_ready" and isinstance(packet.get("nextAttack"), dict):
            self.accept_attack_ticket(packet["nextAttack"])
        elif kind == "hit" and isinstance(packet.get("hit"), dict):
            hit = packet["hit"]
            encounter_id = str(hit.get("monster", ""))
            if encounter_id and self.player_id is not None:
                try:
                    if int(packet.get("attacker", -1)) == self.player_id and encounter_id in self.monsters:
                        monster = self.monsters[encounter_id]
                        if "health" in monster:
                            monster["health"] = max(0, int(monster["health"]) - int(hit.get("damage", 0)))
                            self.refresh_monster_table()
                except (TypeError, ValueError):
                    pass
            if hit.get("monster") == self.last_attacked_monster:
                self.combat_status.setText(
                    f"命中 {hit['monster']}：伤害 {hit.get('damage', '?')}"
                    + (" · 暴击" if hit.get("critical") else "")
                )
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
                # A rejected encounter can remain in a delta-snapshot cache
                # with stale positive health. Don't select it again from that
                # stale row; a later authoritative snapshot can replace it.
                if monster:
                    monster["health"] = 0
                    self.refresh_monster_table()
                self.combat_status.setText(
                    f"目标 {rejected_id[:8]} 已不被服务端接受（可能刚被击败或离开攻击范围）；"
                    f"暂时跳过并等待新快照。当前记录距离 {distance:.0f}。"
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
                self.combat_status.setText(f"攻击被拒绝：{code}")
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
            self.update_map_buttons()
            if destination is None and chase_target is None and packet.get("code") == "movement_too_fast":
                self.travel_status.setText("原地位置同步也被服务端拒绝；当前没有移动目标。请查看纠正诊断日志。")
            if can_retry and destination is not None:
                QTimer.singleShot(500, lambda target=destination: self.travel_to(target, recovery=True))

    def update_quests(self, quests: list) -> None:
        rows = [quest for quest in quests if isinstance(quest, dict)]
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
        if not active and hasattr(self, "auto_quest") and self.auto_quest.isChecked():
            self.accept_next_monster_quest()

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

        def worker() -> None:
            result = {}
            try:
                for key, endpoint in (("player", "/player"), ("equipment", "/equipment"),
                                      ("progression", "/progression")):
                    request = urllib.request.Request(
                        api_root + endpoint,
                        headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
                        method="GET",
                    )
                    with urllib.request.urlopen(request, timeout=8) as response:
                        if response.status == 200:
                            payload = json.loads(response.read().decode("utf-8"))
                            if isinstance(payload, dict):
                                result[key] = payload
            except Exception as exc:
                result["error"] = f"{type(exc).__name__}: {exc}"
            self.bridge.profile.emit(result)

        threading.Thread(target=worker, daemon=True).start()

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
            self.api_equipment = equipment
        progression_data = progression.get("progression", progression) if isinstance(progression, dict) else {}
        if isinstance(progression_data, dict):
            self.last_progress_state.update(progression_data)
            quests = progression_data.get("quests")
            if isinstance(quests, list):
                self.update_quests(quests)
        self.refresh_character_status()
        if data.get("error"):
            self.append_log("角色/任务刷新未完成：" + str(data["error"]))
        if data.get("claimEncounterId"):
            if data.get("claimError"):
                self.claimed_encounters.discard(str(data["claimEncounterId"]))
                self.append_log(f"击败结算未完成 {data['claimEncounterId']}：{data['claimError']}")
            else:
                self.append_log(f"击败结算已同步：{data['claimEncounterId']}；任务进度已刷新。")
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
        name = profile.get("playerName") or profile.get("name") or "角色"
        character_class = profile.get("characterClass") or profile.get("class") or "—"
        character_class = self_state.get("characterClass", character_class)
        class_display = CHARACTER_NAMES_ZH.get(str(character_class).upper(), character_class)
        if hasattr(self, "character_portrait"):
            kind = "guard" if str(character_class).upper() == "GUARD" else "warrior"
            sprite = QPixmap(str(Path(__file__).with_name("assets") / (kind + "-idle.webp")))
            if not sprite.isNull():
                # Guard idle is a horizontal strip; the warrior asset is one frame.
                frame = sprite.copy(0, 0, min(sprite.width(), sprite.height()), sprite.height())
                self.character_portrait.setPixmap(frame.scaled(68, 92, Qt.AspectRatioMode.KeepAspectRatio,
                                                               Qt.TransformationMode.SmoothTransformation))
                self.character_portrait.setToolTip(f"{kind.upper()} · 项目原始待机素材")
        level = progress.get("level", profile.get("level", "—"))
        experience = progress.get("experience", profile.get("experience", "—"))
        experience_needed = progress.get("experienceNeeded", "—")
        health = self_state.get("health", "—")
        max_health = self_state.get("maxHealth", self_state.get("maximumHealth", totals.get("maxHealth", "—")))
        attack = totals.get("attack", totals.get("attackPower", "—"))
        defense = totals.get("defense", "—")
        gold = profile.get("gold", "—")
        status = "阵亡" if self.server_dead else "存活"
        if hasattr(self, "health_bar"):
            try:
                maximum = max(1, int(max_health))
                self.health_bar.setRange(0, maximum)
                self.health_bar.setValue(max(0, min(maximum, int(health))))
                self.health_bar.setFormat(f"{health}/{maximum}")
            except (TypeError, ValueError):
                self.health_bar.setFormat("等待生命数据")
            farming = self_state.get("farming", {})
            try:
                stamina = float(farming["staminaPercent"])
                self.fatigue_bar.setValue(round(max(0, min(100, stamina))))
                self.fatigue_bar.setFormat(f"剩余 {stamina:.0f}%")
            except (KeyError, TypeError, ValueError):
                self.fatigue_bar.setFormat("等待疲劳数据")
        self.update_backpack()
        if hasattr(self, "character_facts"):
            values = {"角色": name, "职业": class_display,
                      "等级": level, "状态": status, "生命": f"{health}/{max_health}",
                      "经验": f"{experience}/{experience_needed}", "攻击": attack, "防御": defense,
                      "金币": gold, "移速加成": f"{totals.get('moveSpeedPercent', 0)}%"}
            for key, value in values.items():
                self.character_facts[key].setText(str(value))
            items = equipment.get("items", [])
            equipped = {str(item.get("slotType")): item for item in items
                        if isinstance(item, dict) and item.get("equipped")} if isinstance(items, list) else {}
            for slot, (caption, label) in self.gear_slots.items():
                item = equipped.get(slot)
                if item:
                    title = localized_item_name(item)
                    label.setText(f"{caption} · {title}")
                    label.setToolTip(json.dumps(item, ensure_ascii=False, indent=2))
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
        self.character_status.setText(
            f"{name} · {class_display}  |  等级 {level}  |  经验 {experience}/{experience_needed}  |  "
            f"生命 {health}/{max_health}  |  攻击 {attack}  |  防御 {defense}  |  金币 {gold}  |  {status}"
        )

    def accept_attack_ticket(self, ticket: dict) -> None:
        if ticket.get("id"):
            self.next_attack = ticket
            self.update_attack_button()

    def open_backpack(self) -> None:
        if not hasattr(self, "backpack_dialog"):
            self.backpack_dialog = QDialog(self)
            self.backpack_dialog.setWindowTitle("背包")
            self.backpack_dialog.resize(640, 420)
            layout = QVBoxLayout(self.backpack_dialog)
            self.backpack_status = QLabel("等待数据")
            layout.addWidget(self.backpack_status)
            refresh = QPushButton("刷新背包")
            refresh.clicked.connect(lambda: self.refresh_profile_data(force=True))
            layout.addWidget(refresh)
            self.backpack_table = QTableWidget(0, 4)
            self.backpack_table.setHorizontalHeaderLabels(["物品", "类型", "品质", "数量"])
            self.backpack_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            self.backpack_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            layout.addWidget(self.backpack_table)
        self.update_backpack()
        self.backpack_dialog.show()
        self.backpack_dialog.raise_()
        self.refresh_profile_data(force=True)

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
                             QUALITY_NAMES_ZH.get(quality.upper(), quality), str(item.get("quantity", 1))])
        for key, name in (("healthPotions", "生命药水"), ("bossTickets", "遗迹入场券"), ("atonementStones", "赎罪石")):
            count = self.last_self_state.get(key)
            if isinstance(count, (int, float)) and count > 0:
                rows.append([name, "消耗品", "—", str(int(count))])
        self.backpack_table.setRowCount(len(rows))
        for row, values in enumerate(rows):
            for col, value in enumerate(values):
                self.backpack_table.setItem(row, col, QTableWidgetItem(value))
        self.backpack_status.setText(f"背包 {len(rows)} 类物品 · 已穿戴装备见角色面板" if "items" in self.api_equipment else "等待服务端背包数据…")

    def update_monsters(self, packet: dict) -> None:
        rows = packet.get("monsters", [])
        if not isinstance(rows, list):
            return
        compact = bool(packet.get("delta")) and int(packet.get("deltaVersion", 0)) == 2
        cache = dict(self.monsters) if compact else {}
        for removed in packet.get("removedMonsters", []):
            cache.pop(str(removed), None)
        for row in rows:
            if not isinstance(row, dict) or not row.get("encounterId"):
                continue
            encounter_id = str(row["encounterId"])
            merged = dict(cache.get(encounter_id, {}))
            merged.update(row)
            cache[encounter_id] = merged
            if encounter_id not in self.seen_monsters and int(merged.get("health", 0)) > 0:
                self.seen_monsters.add(encounter_id)
                self.append_log(f"发现怪物：{localized_monster_name(merged)} · {encounter_id[:8]} · 地图 {merged.get('mapId', '?')}")
        self.monsters = cache
        self.refresh_monster_table()

    def refresh_monster_table(self) -> None:
        selected = self.selected_monster_id()
        visible = [(encounter_id, monster) for encounter_id, monster in self.monsters.items()
                   if int(monster.get("mapId", self.current_map or -1)) == self.current_map
                   and int(monster.get("health", 0)) > 0]
        visible.sort(key=lambda item: self.monster_distance(item[1]))
        self.monster_table.blockSignals(True)
        self.monster_table.setRowCount(len(visible))
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
            values = [encounter_id, localized_monster_name(monster), rank_label,
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
        self.attack_button.setEnabled(self.ws is not None and self.world_ready
                                      and self.pending_destination is None
                                      and self.selected_monster_id() is not None)

    def attack_selected_monster(self) -> None:
        encounter_id = self.selected_monster_id()
        if encounter_id:
            self.attack_monster(encounter_id)

    def attack_monster(self, encounter_id: str) -> bool:
        monster = self.monsters.get(encounter_id)
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
        self.combat_status.setText(f"攻击动画进行中：{encounter_id[:8]} · 命中帧约 {impact_delay} ms · 票据 {ticket[:8]}…")
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
        if enabled and self.world_ready:
            self.combat_timer.start()
            self.combat_status.setText("自动战斗已开启：" + ("搜索当前地图的精英怪。" if self.elite_only.isChecked() else "搜索当前地图全部怪物。"))
        else:
            self.combat_timer.stop()
            self.stop_chase()
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
        if self.return_map_target is not None:
            return
        if self.ws is None or not self.world_ready or self.server_dead or self.respawn_pending or self.pending_destination is not None:
            return
        ticket = str(self.next_attack.get("id", ""))
        if not ticket or ticket in self.used_attack_tickets or time.monotonic() < self.attack_busy_until:
            return
        candidates = [(self.monster_distance(monster), encounter_id)
                      for encounter_id, monster in self.monsters.items()
                      if int(monster.get("mapId", -1)) == self.current_map
                      and int(monster.get("health", 0)) > 0
                      and time.monotonic() >= self.invalid_target_until.get(encounter_id, 0.0)
                      and (not self.elite_only.isChecked() or
                           str(monster.get("monsterRank", "")).upper() == "ELITE")]
        nearby = [(distance, encounter_id) for distance, encounter_id in candidates if distance <= 55]
        if nearby:
            self.stop_chase()
            _, encounter_id = min(nearby)
            self.attack_monster(encounter_id)
        elif self.chase_target is None and candidates and time.monotonic() >= self.chase_retry_after:
            distance, encounter_id = min(candidates)
            self.start_chase(encounter_id)

    def start_chase(self, encounter_id: str, *, recovery: bool = False) -> None:
        if not recovery:
            self.movement_corrections = 0
        monster = self.monsters.get(encounter_id)
        if not monster or self.world_x is None or self.world_y is None:
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
                self.chase_target is not None):
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
        try:
            self.send_game_packet({"action": "ping", "sentAt": int(time.monotonic() * 1000)}, log=False)
        except Exception as exc:
            self.append_log(f"心跳发送失败：{type(exc).__name__}: {exc}")
            self.keepalive.stop()

    def travel_to(self, destination: int, *, recovery: bool = False) -> None:
        if not self.world_ready or self.current_map is None or self.pending_destination is not None:
            return
        if not recovery:
            self.movement_corrections = 0
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
            self.travel_status.setText("已到入口预计坐标，等待服务端移动校验后切图…")
            QTimer.singleShot(2500, lambda: self.send_travel(self.pending_destination, attempt)
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
        self.world_status.setText(
            f"当前：{MAP_NAMES.get(self.current_map, str(self.current_map))}    预计坐标：({next_x}, {next_y})"
            f"    距入口约 {round(remaining - step)}"
        )

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
            self.travel_status.setText("6 秒内没有收到 travel_result，请查看连接日志。")
            self.update_map_buttons()

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
