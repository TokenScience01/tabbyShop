#!/usr/bin/env python3
"""Unified desktop host for the game console and the existing local shop."""
from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path
from http.server import ThreadingHTTPServer
import tempfile

from github_updater import (APP_VERSION, RELEASES_PAGE, download_asset,
                            fetch_latest_release, is_frozen_windows,
                            launch_update_script, prepare_windows_update)

os.environ['TABBY_SAFE_START'] = '1'
BASE_DIR = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))
sys.path.insert(0, str(BASE_DIR / 'game_client'))

from PySide6.QtCore import QUrl, Qt, QObject, Signal, Slot, QFile, QTimer
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                              QHBoxLayout, QGridLayout, QLabel, QPushButton,
                              QStackedWidget, QButtonGroup, QDialog, QMessageBox,
                              QFrame, QPlainTextEdit, QInputDialog, QLineEdit,
                              QScrollArea)
from PySide6.QtGui import QDesktopServices, QIcon, QPixmap
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineScript
from PySide6.QtWebChannel import QWebChannel
from wss_tester import MainWindow as GameWindow
import server as shop


class UpdateSignals(QObject):
    checked = Signal(object)
    downloaded = Signal(str)
    failed = Signal(str)


class DesktopClipboard(QObject):
    @Slot(str)
    def copyText(self, text):
        QApplication.clipboard().setText(text)


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
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Tabby · 游戏与商城')
        app_icon = QIcon(str(BASE_DIR / 'assets' / 'tabby-logo.png'))
        self.setWindowIcon(app_icon)
        self.resize(1220, 900)
        self.setMinimumSize(920, 720)
        self._token = ''
        self.active_address = ''
        self._active_private_key = ''
        self._master_passphrase = None
        self._pending_address = ''
        self._shop_profiles = {}
        self._profile_path = None
        self._profile_lock = threading.RLock()
        self._game_sessions = {}
        self._game_session_widgets = {}
        self._game_address_by_bridge = {}
        self._session_tokens = {}
        self._loaded = False
        self._shop_started = False
        self.httpd = None
        self.web = None
        self.game = GameWindow()
        # Keep the game controller alive while hosting its existing widget.
        content = self.game.takeCentralWidget()
        self.setStyleSheet(self.game.styleSheet() + """
            QLabel#appBrand { color: #E8ECEB; font-size: 15px; font-weight: 700; }
            QLabel#shellStatus { color: #AAB4B1; font-size: 12px; }
            QLabel#connectionDot { border-radius: 5px; }
            QPushButton#shellNav { min-height: 40px; padding: 4px 16px; border-radius: 0;
                                   color: #AAB4B1; background: transparent; border: 0;
                                   border-bottom: 2px solid transparent; }
            QPushButton#shellNav:hover { color: #E8ECEB; background: #222627; border-bottom: 2px solid #535A56; }
            QPushButton#shellNav:checked { color: #DDE8D9; background: transparent; border: 0;
                                           border-bottom: 2px solid #78936B; }
            QLabel#accountManagerTitle { color: #E8ECEB; font-size: 28px; font-weight: 700; }
            QLabel#accountManagerSubtitle { color: #AAB4B1; font-size: 13px; }
            QLabel#accountManagerCount { color: #DDE8D9; font-size: 12px; font-weight: 700; }
            QLabel#accountManagerNote, QLabel#accountEmpty { color: #8E9994; font-size: 11px; }
            QFrame#walletAccountRow { background: #1B2020; border: 1px solid #343B39; border-radius: 10px; }
            QFrame#walletAccountRow:hover { border-color: #687B65; background: #202626; }
            QLabel#walletAddress { color: #E8ECEB; font-family: Consolas; font-size: 12px; }
            QLabel#walletAccountState { color: #8E9994; font-size: 10px; }
            QLabel#walletAccountDetails { color: #C5CECA; font-size: 11px; }
            QLabel#walletStatusDot { border-radius: 5px; }
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
        self.shop_nav = QPushButton('商城与监控')
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        for button in (self.account_nav, self.game_nav, self.shop_nav):
            button.setObjectName('shellNav')
            button.setCheckable(True)
            self.nav_group.addButton(button)
            nav_layout.addWidget(button)
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

    def build_account_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(34, 28, 34, 28)
        layout.setSpacing(16)
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
        actions.addWidget(refresh)
        actions.addWidget(add)
        layout.addLayout(actions)
        note = QLabel('私钥保存在本机加密保险库；主密码只在本次运行期间留在内存。切换控制台不会断开其他账号的游戏连接；商城扫描仅绑定当前选择的账号。')
        note.setObjectName('accountManagerNote')
        note.setWordWrap(True)
        layout.addWidget(note)
        return page

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
        while self.account_rows.count():
            item = self.account_rows.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        addresses = self.game.credential_vault.list_wallets()
        self.account_count.setText(f'{len(addresses)} 个账号')
        self.account_empty.setVisible(not addresses)
        for address in addresses:
            row = QFrame()
            row.setObjectName('walletAccountRow')
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(14, 11, 14, 11)
            row_layout.setSpacing(14)
            identity = QVBoxLayout()
            identity.setSpacing(4)
            address_row = QHBoxLayout()
            address_row.setSpacing(8)
            dot = QLabel()
            dot.setObjectName('walletStatusDot')
            dot.setFixedSize(10, 10)
            address_label = QLabel(address)
            address_label.setObjectName('walletAddress')
            address_row.addWidget(dot, 0, Qt.AlignmentFlag.AlignVCenter)
            address_row.addWidget(address_label, 1)
            identity.addLayout(address_row)
            is_active = address.lower() == self.active_address.lower()
            session = self._game_sessions.get(address.lower())
            session_state = session.status.text() if session else ''
            if session_state == '已连接':
                dot_color = '#43C98B'
                state_text = '在线' + (' · 当前显示' if is_active else ' · 后台保持连接')
            elif session_state in ('连接中…', '连接中'):
                dot_color = '#E6BF55'
                state_text = '连接中' + (' · 当前显示' if is_active else ' · 后台连接中')
            else:
                dot_color = '#E05E5A'
                state_text = '离线' + (' · 当前显示' if is_active else ' · 已加密保存')
            dot.setStyleSheet(f'background:{dot_color}; border-radius:5px;')
            dot.setToolTip(state_text)
            state_label = QLabel(state_text)
            state_label.setObjectName('walletAccountState')
            identity.addWidget(state_label)
            details = self.account_summary(session)
            details_label = QLabel(details or ('角色资料将在登录后显示' if session else '尚未登录'))
            details_label.setObjectName('walletAccountDetails')
            details_label.setWordWrap(True)
            identity.addWidget(details_label)
            row_layout.addLayout(identity, 1)
            if session_state in ('连接中…', '连接中'):
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
            action.setMinimumHeight(38)
            action.setEnabled(session_state not in ('连接中…', '连接中'))
            if not is_active and session_state == '已连接':
                action.setToolTip('只切换当前控制台；这个账号和其他账号的游戏连接都会保持在线。')
            elif not is_active:
                action.setToolTip('切换到这个账号并连接；其他在线账号不会断开。')
            elif session_state == '已连接':
                action.setToolTip('打开当前账号控制台。')
            else:
                action.setToolTip('重新连接当前账号；其他账号连接保持不变。')
            action.clicked.connect(lambda _checked=False, wallet=address: self.connect_account(wallet))
            row_layout.addWidget(action)
            self.account_rows.addWidget(row)
        self.account_rows.addStretch(1)

    @staticmethod
    def account_summary(game):
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
        if attack is None:
            attack = self_state.get('attack')
        if defense is None:
            defense = self_state.get('defense')
        parts = []
        if name and str(name) != '—':
            parts.append(str(name))
        if level and str(level) != '—':
            parts.append(f'等级 {level}')
        if combat_power is not None:
            parts.append(f'战斗力 {combat_power}')
        elif attack is not None or defense is not None:
            combat = ' / '.join(f'{label} {value}' for label, value in (('攻击', attack), ('防御', defense)) if value is not None)
            parts.append(combat)
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
            parts.append(f'疲劳 {stamina}%')
        gold = profile.get('gold', self_state.get('gold'))
        if gold is not None:
            parts.append(f'金币 {gold}')
        return ' · '.join(parts)

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
        if existing_wallets:
            try:
                self.game.credential_vault.load_wallet(phrase, existing_wallets[0])
            except (OSError, ValueError):
                QMessageBox.warning(self, '主密码错误', '无法用这个主密码解锁已保存的钱包，本次没有导入。')
                return
        try:
            for address, private_key in validated:
                self.game.credential_vault.store_wallet(private_key, phrase, address)
        except Exception as exc:
            self.refresh_account_rows()
            count = len(self.game.credential_vault.list_wallets())
            QMessageBox.warning(self, '导入未完成', f'目前已加密保存 {count} 个钱包；其余导入失败：{exc}')
            return
        self._master_passphrase = phrase
        self.game._vault_passphrase = phrase
        self.game.remember_private_key.setChecked(True)
        self.game.refresh_saved_wallets()
        self.refresh_account_rows()
        QMessageBox.information(self, '导入完成', f'已加密保存 {len(validated)} 个新钱包，可在列表中逐个连接。')

    def connect_account(self, address):
        normalized = address.lower()
        same_active = normalized == self.active_address.lower()
        if shop.MONITOR.buy_lock.locked():
            QMessageBox.warning(self, '购买正在提交', '当前账号有一笔购买正在提交。请等待交易完成后再切换商城账号；游戏连接会继续保持。')
            self.tabs.setCurrentIndex(2)
            return
        switching = bool(self.active_address and not same_active)
        if switching:
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
            self.refresh_account_rows()
            return
        game = self._game_sessions.get(normalized)
        if game is None:
            if not self.active_address:
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
            self._game_address_by_bridge[id(game.bridge)] = address
        else:
            widget = self._game_session_widgets.get(normalized)
        if game is None or widget is None:
            QMessageBox.warning(self, '账号控制台错误', '无法打开这个账号的游戏控制台。')
            return
        self.game = game
        self.game_stack.setCurrentWidget(widget)
        if self.game.character_creation_required:
            QTimer.singleShot(0, self.game.maybe_prompt_character_creation)
        self.active_address = address
        self._pending_address = address
        self.game._vault_passphrase = self._master_passphrase or self.game._vault_passphrase
        index = self.game.saved_wallet.findData(address)
        if index >= 0:
            self.game.saved_wallet.setCurrentIndex(index)
        self.game.auth_method.setCurrentIndex(self.game.auth_method.findData('private_key'))
        if not self.game.remember_private_key.isChecked():
            self.game.remember_private_key.setChecked(True)
        if not same_active:
            shop.MONITOR.stop()
            shop.MONITOR.configure(self._shop_profiles.get(address.lower(), shop.DEFAULT_CONFIG))
        shop.MONITOR.event_callback = self.game.bridge.shop_notification.emit
        self._token = self._session_tokens.get(normalized, '')
        self._active_private_key = ''
        self.prepare_shop_account_context(address)
        self.tabs.setCurrentIndex(1)
        if self.game.status.text() not in ('已连接', '连接中', '连接中…'):
            self.game.connect_ws()
        self.refresh_account_rows()

    def on_session_token_changed(self, game, value):
        if game is self.game:
            self.set_token(value)

    def on_game_state(self, game, state):
        if game is self.game:
            self.update_shell_status(state)
        self.refresh_account_rows()

    def on_game_latency(self, game):
        if game is self.game:
            self.update_shell_latency()

    def on_game_metadata(self, game):
        if game in self._game_sessions.values():
            self.refresh_account_rows()

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
            dialog.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            dialog.button(QMessageBox.StandardButton.Yes).setText('立即重启安装')
            dialog.button(QMessageBox.StandardButton.No).setText('稍后')
            answer = dialog.exec()
            if answer == QMessageBox.StandardButton.Yes:
                launch_update_script(script)
                self.close()
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
        if isinstance(result, dict) and result.get('ok') and result.get('token'):
            bridge = self.sender()
            bridge_key = id(bridge) if bridge is not None else id(self.game.bridge)
            address = self._game_address_by_bridge.get(bridge_key, self._pending_address or self.active_address)
            game = next((item for item in self._game_sessions.values() if id(item.bridge) == bridge_key), self.game)
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
            self.refresh_account_rows()
            if result.get('remembered'):
                self.account_keyring_status.setText('保存状态：AES-GCM 已验证；三片已保存，主密码未保存')
            elif result.get('remember_error'):
                self.account_keyring_status.setText('保存状态：加密分片保存/校验失败；请重试')
            elif not self.game.remember_private_key.isChecked():
                self.account_keyring_status.setText('保存状态：本次未保存私钥')

    def update_shell_status(self, connection_state=None):
        state = connection_state or self.game.status.text()
        if state != getattr(self, '_last_game_state', None):
            self._last_game_state = state
            self.refresh_account_rows()
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
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName('Tabby Desktop')
    app.setWindowIcon(QIcon(str(BASE_DIR / 'assets' / 'tabby-logo.png')))
    window = DesktopWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
