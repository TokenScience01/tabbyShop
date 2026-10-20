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

from PySide6.QtCore import QUrl, Qt, QObject, Signal, Slot, QFile
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                              QHBoxLayout, QGridLayout, QLabel, QPushButton,
                              QStackedWidget, QButtonGroup, QDialog, QMessageBox)
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
        self.update_button = QPushButton('检查更新')
        self.update_button.setObjectName('secondaryButton')
        self.update_button.clicked.connect(self.check_for_updates)
        actions_layout.addWidget(self.update_button)
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
        self.update_shell_status(self.game.status.text())
        self.sync_shop_token()

    def on_signed_login(self, result):
        if isinstance(result, dict) and result.get('ok') and result.get('token'):
            # The server-issued game session is trusted application data; it
            # may itself be a 64-character hex token and must bypass the
            # paste-safety prompt used only for the editable Token field.
            self.set_token(str(result['token']), guard_private_key=False)
            if result.get('remembered'):
                self.account_keyring_status.setText('保存状态：AES-GCM 已验证；三片已保存，主密码未保存')
            elif result.get('remember_error'):
                self.account_keyring_status.setText('保存状态：加密分片保存/校验失败；请重试')
            elif not self.game.remember_private_key.isChecked():
                self.account_keyring_status.setText('保存状态：本次未保存私钥')

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
    app.setWindowIcon(QIcon(str(BASE_DIR / 'assets' / 'tabby-logo.png')))
    window = DesktopWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
