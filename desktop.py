#!/usr/bin/env python3
"""Unified desktop host for the game console and the existing local shop."""
from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path
from http.server import ThreadingHTTPServer

os.environ['TABBY_SAFE_START'] = '1'
BASE_DIR = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))
sys.path.insert(0, str(BASE_DIR / 'game_client'))

from PySide6.QtCore import QUrl, Qt
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                              QHBoxLayout, QGridLayout, QLabel, QPushButton,
                              QStackedWidget, QButtonGroup, QDialog)
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineScript
from wss_tester import MainWindow as GameWindow
import server as shop


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
        self.resize(1220, 900)
        self.setMinimumSize(920, 720)
        self._token = ''
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
        """)
        root = QWidget()
        root.setObjectName('root')
        layout = QVBoxLayout(root)
        layout.setContentsMargins(20, 8, 20, 12)
        layout.setSpacing(8)
        top = QGridLayout()
        top.setContentsMargins(2, 0, 2, 6)
        top.setHorizontalSpacing(12)
        brand = QLabel('TABBY  /  游戏与商城')
        brand.setObjectName('appBrand')
        top.addWidget(brand, 0, 0, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        top.setColumnStretch(0, 1)

        nav = QWidget()
        nav_layout = QHBoxLayout(nav)
        nav_layout.setContentsMargins(0, 0, 0, 0)
        nav_layout.setSpacing(6)
        self.tabs = QStackedWidget()
        self.tabs.setObjectName('appPages')
        self.game_nav = QPushButton('游戏控制台')
        self.shop_nav = QPushButton('商城与监控')
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        for button in (self.game_nav, self.shop_nav):
            button.setObjectName('shellNav')
            button.setCheckable(True)
            self.nav_group.addButton(button)
            nav_layout.addWidget(button)
        self.game_nav.setChecked(True)
        self.game_nav.clicked.connect(lambda: self.tabs.setCurrentIndex(0))
        self.shop_nav.clicked.connect(lambda: self.tabs.setCurrentIndex(1))
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
        account = QPushButton('账号连接')
        account.setObjectName('secondaryButton')
        account.clicked.connect(self.show_account)
        actions_layout.addWidget(account)
        top.addWidget(actions, 0, 2, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        layout.addLayout(top)
        self.tabs.addWidget(content)
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
        self.game.on_state_change = self.update_shell_status
        self.game.on_latency_change = self.update_shell_latency
        self.game.token.textChanged.connect(self.set_token)
        self.account_dialog = QDialog(self)
        self.account_dialog.setWindowTitle('统一账号连接')
        self.account_dialog.setMinimumWidth(520)
        account_layout = QVBoxLayout(self.account_dialog)
        account_layout.setSpacing(10)
        account_layout.addWidget(QLabel('选择 Token 登录，或用 BSC 私钥在本机签名登录。'))
        account_layout.addWidget(QLabel('登录方式'))
        account_layout.addWidget(self.game.auth_method)
        self.account_token_label = QLabel('游戏会话 Token')
        account_layout.addWidget(self.account_token_label)
        account_layout.addWidget(self.game.token)
        # Retain the familiar desktop account field reference for tests and
        # integrations while sharing the actual game login widget.
        self.account_token = self.game.token
        self.account_private_key_label = QLabel('BSC 钱包私钥（仅本机签名，不会保存）')
        account_layout.addWidget(self.account_private_key_label)
        account_layout.addWidget(self.game.private_key)
        self.account_sign_help = QLabel(
            '签名流程：POST /membership/challenge → /membership/verify → /membership/enter'
        )
        account_layout.addWidget(self.account_sign_help)
        account_layout.addWidget(self.game.remember_private_key)
        account_layout.addWidget(self.game.auto_reconnect)
        self.game.auth_method.currentIndexChanged.connect(self.update_account_auth_fields)
        self.update_account_auth_fields()
        row = QHBoxLayout()
        row.setSpacing(10)
        connect = QPushButton('连接游戏')
        connect.setObjectName('primaryButton')
        connect.clicked.connect(self.game.connect_ws)
        disconnect = QPushButton('断开游戏')
        disconnect.setObjectName('secondaryButton')
        disconnect.clicked.connect(self.game.disconnect_ws)
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
        # The desktop monitor reads the same in-memory token used by the game.
        shop.read_token = lambda: ('Bearer ' + self._token) if self._token else ''
        shop.save_token = lambda value: None

    def show_account(self):
        self.account_dialog.show()
        self.account_dialog.raise_()
        if self.game.auth_method.currentData() == 'private_key':
            self.game.private_key.setFocus()
        else:
            self.game.token.setFocus()

    def update_account_auth_fields(self, *_args):
        private_mode = self.game.auth_method.currentData() == 'private_key'
        self.account_token_label.setVisible(not private_mode)
        self.account_private_key_label.setVisible(private_mode)
        self.account_sign_help.setVisible(private_mode)

    def set_token(self, value):
        value = value.strip()
        self._token = value[7:].strip() if value.lower().startswith('bearer ') else value
        self.update_shell_status(self.game.status.text())
        self.sync_shop_token()

    def update_shell_status(self, connection_state=None):
        state = connection_state or self.game.status.text()
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
        self.game_nav.setChecked(index == 0)
        self.shop_nav.setChecked(index == 1)

    def sync_shop_token(self):
        if self.web is None or not self._loaded:
            return
        # Pass as a JSON string literal; never construct executable token text.
        self.web.page().runJavaScript(
            "(() => {const e=document.getElementById('token');if(e){e.value="
            + json.dumps(self._token) + ";e.readOnly=true;"
            "e.placeholder='请通过桌面右上角账号连接设置 Token';}})();")

    def activate_tab(self, index):
        if index != 1 or self._shop_started:
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
            script = QWebEngineScript()
            script.setName('tabby-desktop-mode')
            script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
            script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
            script.setSourceCode('window.__TABBY_DESKTOP__ = true;')
            page.scripts().insert(script)
            self.web.loadFinished.connect(self.shop_loaded)
            self.shop_layout.addWidget(self.web)
            self.web.load(url)
            self._shop_started = True
        except Exception as exc:
            self.shop_layout.addWidget(QLabel(f'商城启动失败：{type(exc).__name__}: {exc}'))

    @staticmethod
    def make_handler():
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
        return DesktopHandler

    def shop_loaded(self, ok):
        self._loaded = ok
        if ok:
            self.sync_shop_token()

    def closeEvent(self, event):
        self.game.minimap_timer.stop()
        self.game.disconnect_ws()
        # Do not leave a monitor operating after the application window closes.
        shop.MONITOR.stop()
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.web:
            self.web.stop()
        self.game.close()
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName('Tabby Desktop')
    window = DesktopWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
