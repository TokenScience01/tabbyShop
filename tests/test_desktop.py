"""Local integration checks; no game/shop upstream calls or wallet access."""
import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
os.environ.setdefault('QTWEBENGINE_CHROMIUM_FLAGS', '--disable-gpu')
import json
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from unittest.mock import patch
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QDialog, QLabel, QMessageBox,
                               QPushButton, QTableWidget, QTabWidget)
from PySide6.QtCore import QEventLoop, QItemSelectionModel, QSettings, QTimer
from PySide6.QtGui import QImage
from desktop import DesktopWindow, shop
from credential_vault import CredentialVault
from game_client.wss_tester import (ITEM_NAMES_ZH, QUALITY_NAMES_ZH,
                                    equipment_attribute_lines, localized_item_name, quality_color)
from game_client.minimap import peer_map_position


class DesktopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.wallet_patch = patch.object(shop, 'wallet_address', return_value='')
        cls.wallet_patch.start()

    @classmethod
    def tearDownClass(cls):
        cls.wallet_patch.stop()

    def setUp(self):
        self.window = DesktopWindow()
        self.window.show()
        self.app.processEvents()

    def tearDown(self):
        self.window.close()
        self.app.processEvents()

    def test_shared_token_stays_in_memory(self):
        with patch.object(shop.TOKEN_FILE.__class__, 'write_text') as write:
            self.window.account_token.setText('Bearer test-session')
            self.assertEqual(self.window.game.token.text(), 'Bearer test-session')
            self.assertEqual(shop.read_token(), 'Bearer test-session')
            shop.save_token('test-session')
            write.assert_not_called()
        self.assertFalse(shop.MONITOR.enabled)
        self.assertFalse(shop.MONITOR.auto_buy_enabled)
        self.assertEqual(self.window.tabs.count(), 2)
        self.assertFalse(self.window.windowIcon().isNull())
        self.assertTrue(self.window.update_button.text().startswith('检查更新'))
        self.assertTrue(self.window.game_nav.isChecked())
        self.assertTrue(self.window.game.dashboard_header.isHidden())
        self.window.game.set_state('已连接')
        self.assertIn('已连接', self.window.account_status.text())

    def test_private_key_session_is_shared_with_shop_in_memory(self):
        self.window.game.auth_method.setCurrentIndex(
            self.window.game.auth_method.findData('private_key'))
        self.window.game.bridge.signed_login.emit({
            'ok': True, 'token': 'signed-game-session', 'address': '0x1234'
        })
        self.assertEqual(self.window._token, 'signed-game-session')
        self.assertEqual(shop.read_token(), 'Bearer signed-game-session')
        self.assertEqual(self.window.account_token.text(), '')
        self.assertIn('Token 已设置', self.window.account_status.text())

        # A rejected/failed signing attempt must not overwrite an existing
        # usable session with an empty value.
        self.window.on_signed_login({'ok': False, 'error': 'test'})
        self.assertEqual(shop.read_token(), 'Bearer signed-game-session')

    def test_saved_wallet_selector_lists_addresses_without_unlocking_private_keys(self):
        game = self.window.game
        with tempfile.TemporaryDirectory() as temporary:
            game.credential_vault = CredentialVault(Path(temporary) / 'vault')
            first = '0x' + '1' * 40
            second = '0x' + '2' * 40
            game.credential_vault.store_wallet('private-one', 'test-password', first)
            game.credential_vault.store_wallet('private-two', 'test-password', second)
            game.refresh_saved_wallets()
            addresses = {game.saved_wallet.itemData(index) for index in range(game.saved_wallet.count())}
            self.assertEqual(addresses, {'', first, second})
            self.assertNotIn('private-one', [game.saved_wallet.itemText(index)
                                             for index in range(game.saved_wallet.count())])
            game.saved_wallet.setCurrentIndex(game.saved_wallet.findData(second))
            self.assertEqual(game.saved_wallet.currentData(), second)
            self.assertEqual(game.settings.value('lastWalletAddress'), second)
            game.private_key.setText('temporary-key-entry')
            game.on_private_key_edited()
            self.assertEqual(game.saved_wallet.currentData(), '')

    def test_private_key_auth_is_default_and_token_field_rejects_wallet_key_format(self):
        game = self.window.game
        self.assertEqual(game.auth_method.currentData(), 'private_key')
        self.assertIs(game.saved_wallet.parentWidget(), self.window.account_dialog)
        self.assertFalse(self.window.account_wallet_label.isHidden())
        with patch.object(QMessageBox, 'warning') as warning, \
             patch.object(QMessageBox, 'information') as information:
            self.window.account_token.setText('0x' + 'a' * 64)
        self.assertEqual(self.window.account_token.text(), '')
        self.assertEqual(game.auth_method.currentData(), 'private_key')
        self.assertEqual(shop.read_token(), '')
        warning.assert_not_called()
        information.assert_called_once()

    def test_unprefixed_hex_token_requires_explicit_confirmation(self):
        with patch.object(QMessageBox, 'warning',
                          return_value=QMessageBox.StandardButton.No), \
             patch.object(QMessageBox, 'information'):
            self.window.account_token.setText('b' * 64)
        self.assertEqual(self.window.account_token.text(), '')
        self.assertEqual(shop.read_token(), '')

    def test_server_issued_hex_session_bypasses_paste_safety_prompt(self):
        server_token = 'c' * 64
        with patch.object(QMessageBox, 'warning') as warning:
            self.window.on_signed_login({'ok': True, 'token': server_token})
        warning.assert_not_called()
        self.assertEqual(shop.read_token(), 'Bearer ' + server_token)

    def test_local_handler_does_not_expose_files(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), self.window.make_handler())
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f'http://127.0.0.1:{server.server_port}'
        try:
            with urlopen(base + '/') as response:
                self.assertIn(b'Tabby', response.read())
            with urlopen(base + '/config.local.json') as response:
                self.assertEqual(json.load(response), {})
            with urlopen(base + '/api/monitor/state') as response:
                self.assertFalse(json.load(response)['enabled'])
            for path in ('/server.py', '/monitor.local.json', '/game_client/wss_tester.py'):
                with self.assertRaises(HTTPError) as error:
                    urlopen(base + path)
                self.assertEqual(error.exception.code, 404)
        finally:
            server.shutdown()
            server.server_close()

    def test_cancel_quote_is_proxied_to_the_matching_upstream_endpoint(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), self.window.make_handler())
        threading.Thread(target=server.serve_forever, daemon=True).start()
        class UpstreamResponse:
            status = 200
            headers = {'Content-Type': 'application/json'}
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def read(self): return b'{"ok":true}'
        try:
            request = Request(
                f'http://127.0.0.1:{server.server_port}/api/shop/cancel-quote',
                data=b'{"orderId":42}', method='POST',
                headers={'Content-Type': 'application/json', 'Authorization': 'Bearer session'},
            )
            with patch.object(shop, 'urlopen', return_value=UpstreamResponse()) as upstream:
                with urlopen(request) as response:
                    self.assertEqual(json.load(response), {'ok': True})
            forwarded = upstream.call_args.args[0]
            self.assertEqual(forwarded.full_url, shop.TARGET + '/cancel-quote')
            self.assertEqual(json.loads(forwarded.data), {'orderId': 42})
            self.assertEqual(forwarded.get_header('Authorization'), 'Bearer session')
            string_order = Request(
                f'http://127.0.0.1:{server.server_port}/api/shop/cancel-quote',
                data=json.dumps({'orderId': 'quote-7f38b9'}).encode(), method='POST',
                headers={'Content-Type': 'application/json', 'Authorization': 'Bearer session'},
            )
            with patch.object(shop, 'urlopen', return_value=UpstreamResponse()) as upstream:
                with urlopen(string_order) as response:
                    self.assertEqual(json.load(response), {'ok': True})
            self.assertEqual(json.loads(upstream.call_args.args[0].data), {'orderId': 'quote-7f38b9'})
            invalid = Request(
                f'http://127.0.0.1:{server.server_port}/api/shop/cancel-quote',
                data=b'{"orderId":true}', method='POST',
                headers={'Content-Type': 'application/json'},
            )
            with self.assertRaises(HTTPError) as error:
                urlopen(invalid)
            self.assertEqual(error.exception.code, 400)
        finally:
            server.shutdown()
            server.server_close()

    def test_embedded_shop_receives_shared_token(self):
        self.window.account_token.setText('test-embedded-session')
        self.window.tabs.setCurrentIndex(1)
        self.assertTrue(self.window.shop_nav.isChecked())
        loop = QEventLoop()
        QTimer.singleShot(10000, loop.quit)
        self.window.web.loadFinished.connect(loop.quit)
        loop.exec()
        self.assertTrue(self.window._loaded)
        result = []
        loop = QEventLoop()
        self.window.web.page().runJavaScript(
            "JSON.stringify({token:document.getElementById('token').value, readonly:document.getElementById('token').readOnly, desktop:window.__TABBY_DESKTOP__})",
            lambda value: (result.append(value), loop.quit()))
        QTimer.singleShot(3000, loop.quit)
        loop.exec()
        self.assertTrue(result)
        state = json.loads(result[0])
        self.assertEqual(state['token'], 'test-embedded-session')
        self.assertTrue(state['readonly'])
        self.assertTrue(state['desktop'])
        result.clear()
        self.window.web.page().runJavaScript(
            "typeof window.__tabbyClipboard?.copyText === 'function'",
            lambda value: (result.append(value), loop.quit()))
        QTimer.singleShot(3000, loop.quit)
        loop.exec()
        self.assertEqual(result, [True])
        self.window.web.page().runJavaScript(
            "window.__tabbyClipboard.copyText('clipboard-integration-test'); true")
        loop = QEventLoop()
        QTimer.singleShot(150, loop.quit)
        loop.exec()
        self.assertEqual(self.app.clipboard().text(), 'clipboard-integration-test')
        self.window.account_token.setText('changed-session')
        self.assertEqual(shop.read_token(), 'Bearer changed-session')

    def test_task_limited_mode_stops_at_objective_and_task_cap(self):
        game = self.window.game
        game.task_limited_mode.setChecked(True)
        game.latest_quests = [{
            'id': 1, 'objectiveType': 'MONSTER', 'accepted': True,
            'completed': False, 'progress': 2, 'target': 5, 'mapId': 2,
        }]
        self.assertTrue(game.has_active_monster_quest())
        self.assertTrue(game.monster_matches_active_quest({'mapId': 2}))
        self.assertFalse(game.monster_matches_active_quest({'mapId': 4}))
        game.latest_quests[0]['progress'] = 5
        self.assertFalse(game.has_active_monster_quest())

        game.handle_quest_limit_reached('daily cap')
        self.assertFalse(game.questless_farm_mode)
        self.assertIsNone(game.questless_farm_target)
        self.assertFalse(game.combat_timer.isActive())

    def test_rarity_colors_and_current_map_indicator(self):
        self.assertEqual([quality_color(f'L{level}') for level in range(1, 5)],
                         ['#f2f2ef', '#69b3ff', '#c994ff', '#ffcf72'])
        self.assertEqual(QUALITY_NAMES_ZH['L4'], '传说')
        self.assertEqual(localized_item_name({'itemCode': 'STARTER_SHOES'}), '新手鞋')

    def test_game_palette_and_action_buttons_are_visibly_clickable(self):
        game = self.window.game
        stylesheet = game.styleSheet()
        self.assertIn('background: #17191A', stylesheet)
        self.assertIn('QPushButton#quietButton { background: #292E2D', stylesheet)
        self.assertIn('border: 1px solid #535A56', stylesheet)
        self.assertIn('QTabBar::tab { background: transparent', stylesheet)
        self.assertIn('QTabWidget::pane { border: 0; background: transparent; }', stylesheet)
        self.assertIn('QPushButton#shellNav { min-height: 40px', self.window.styleSheet())
        self.assertEqual(game.refresh_profile_button.objectName(), 'quietButton')
        self.assertEqual(game.stop_move_button.objectName(), 'quietButton')
        account_button = next(button for button in self.window.findChildren(QPushButton)
                              if button.text() == '账号连接')
        self.assertEqual(account_button.objectName(), 'secondaryButton')

        game = self.window.game
        game.current_map = 4
        game.update_map_buttons()
        self.assertIn('西部荒野', game.current_map_label.text())
        self.assertTrue(game.map_buttons[4].property('currentMap'))

        game.api_equipment = {'items': [
            {'playerItemId': 31, 'itemCode': 'SWORDP1', 'slotType': 'WEAPON',
             'qualityCode': 'L3', 'equipmentLevel': 1, 'equipped': False},
        ]}
        game.backpack_table = QTableWidget(0, 5)
        game.backpack_status = QLabel()
        game.backpack_equip_button = QPushButton()
        game.backpack_compare_button = QPushButton()
        game.update_backpack()
        self.assertEqual(game.backpack_table.item(0, 0).foreground().color().name(), '#c994ff')
        self.assertEqual(game.backpack_table.item(0, 2).text(), '史诗')
        game.update_social_inventory()
        self.assertEqual(game.social_inventory_table.item(0, 0).foreground().color().name(), '#c994ff')
        self.assertEqual(game.social_inventory_table.item(0, 5).text(), '背包')

        game.api_equipment = {'items': [
            {'itemCode': 'STARTER_SHOES', 'slotType': 'SHOES',
             'qualityCode': 'L1', 'equipmentLevel': 1, 'equipped': False},
        ]}
        game.update_social_inventory()
        self.assertEqual(game.social_inventory_table.item(0, 0).text(), '新手鞋')

    def test_dashboard_labels_wait_for_real_profile_without_duplicate_placeholder(self):
        game = self.window.game
        game.api_profile = {}
        game.last_self_state = {}
        game.refresh_character_status()
        self.assertEqual(game.character_facts['角色'].text(), '—')
        self.assertNotEqual(game.character_facts['角色'].text(), '角色')
        self.assertIn('连接后', game.character_portrait.text())
        self.assertGreaterEqual(game.social_inventory_table.maximumHeight(), 220)
        game.auto_quest.setChecked(False)
        game.update_quests([])
        self.assertFalse(hasattr(game, 'quest_empty_state'))
        self.assertTrue(game.quest_table.isVisible())
        self.assertEqual(game.quest_status.height(), 24)
        game.update_quests([{'id': 1, 'titleZh': '测试任务', 'accepted': True,
                             'completed': False, 'progress': 0, 'target': 5}])
        self.assertTrue(game.quest_table.isVisible())

    def test_shell_connection_dot_tracks_latency_and_disconnect(self):
        game = self.window.game
        game.last_rtt_ms = 48
        self.window.update_shell_status('已连接')
        self.assertIn('#43c98b', self.window.connection_dot.styleSheet())
        self.assertIn('48 ms', self.window.account_status.text())
        game.status.setText('已连接')
        game.last_rtt_ms = 180
        self.window.update_shell_latency()
        self.assertIn('#e6bf55', self.window.connection_dot.styleSheet())
        game.last_rtt_ms = 320
        self.window.update_shell_latency()
        self.assertIn('#ef8d43', self.window.connection_dot.styleSheet())
        self.window.update_shell_status('已主动断开')
        self.assertIn('#e05e5a', self.window.connection_dot.styleSheet())

    def test_monster_empty_state_starts_at_top_and_replaces_empty_table(self):
        game = self.window.game
        tabs = next(tab for tab in self.window.findChildren(QTabWidget) if tab.count() == 5)
        tabs.setCurrentIndex(1)
        game.current_map = 1
        game.monsters = {}
        game.refresh_monster_table()
        self.app.processEvents()
        self.assertTrue(game.monster_empty_state.isVisible())
        self.assertFalse(game.monster_table.isVisible())
        self.assertLess(game.monster_empty_state.y(), 40)
        game.monsters = {'e1': {'mapId': 1, 'health': 10, 'maxHealth': 10, 'x': 1, 'y': 2}}
        game.refresh_monster_table()
        self.assertFalse(game.monster_empty_state.isVisible())
        self.assertTrue(game.monster_table.isVisible())

    def test_monster_level_column_and_selected_inventory_preview(self):
        game = self.window.game
        game.current_map = 2
        game.world_x, game.world_y = 0, 0
        game.monsters = {'e1': {'mapId': 2, 'health': 10, 'maxHealth': 10,
                                'x': 3, 'y': 4, 'level': 18, 'name': 'skeleton'}}
        game.refresh_monster_table()
        self.assertEqual(game.monster_table.horizontalHeaderItem(2).text(), '等级')
        self.assertEqual(game.monster_table.item(0, 2).text(), '18')
        game.api_equipment = {'items': [
            {'playerItemId': 31, 'itemCode': 'SWORDP1', 'slotType': 'WEAPON',
             'qualityCode': 'L2', 'equipmentLevel': 3, 'equipped': False},
        ]}
        game.update_social_inventory()
        game.social_inventory_table.selectRow(0)
        self.assertEqual(game.selected_item_name.text(), '铁短剑')
        self.assertIn('武器  ·  稀有  ·  等级 3', game.selected_item_detail.text())
        self.assertIn('铁短剑', game.equip_item_button.text())

    def test_auto_potion_is_opt_in_and_requires_health_inventory_and_ready_cooldown(self):
        game = self.window.game
        game.ws = object()
        game.world_ready = True
        game.last_self_state = {'health': 20, 'maxHealth': 100,
                                'healthPotions': 2, 'potionCooldownMs': 0}
        sent = []
        game.send_game_packet = lambda packet, **kwargs: sent.append(packet)
        game.auto_potion.setChecked(False)
        game.try_auto_use_potion()
        self.assertEqual(sent, [])
        game.auto_potion.setChecked(True)
        game.last_self_state['potionCooldownMs'] = 1000
        game.try_auto_use_potion()
        self.assertEqual(sent, [])
        game.last_self_state['potionCooldownMs'] = 0
        game.try_auto_use_potion()
        self.assertEqual(sent, [{'action': 'useHealthPotion'}])
        self.assertTrue(game.auto_potion_pending)
        game.auto_potion.setChecked(False)
        self.assertFalse(game.auto_potion_pending)
        game.ws = None

    def test_source_item_name_table_covers_all_bundled_equipment_codes(self):
        self.assertEqual(len(ITEM_NAMES_ZH), 90)  # 45 item codes and their English-name aliases
        self.assertEqual(localized_item_name({'itemCode': 'armor-p6'}), '王者战甲')
        self.assertEqual(localized_item_name({'itemCode': 'HEALTH_POTION'}), '生命药水')
        self.assertEqual(localized_item_name({'itemCode': 'STARTER_AMULET'}), '新手护符')
        self.assertEqual(localized_item_name({'nameEn': 'STARTER_ARMOR'}), '新手护甲')
        self.assertEqual(localized_item_name({'nameEn': 'Unmapped Blade', 'slotType': 'WEAPON'}), '未收录武器')

    def test_compact_dashboard_exposes_potion_toggle_and_combat_feed(self):
        game = self.window.game
        self.assertTrue(game.auto_potion.isVisible())
        self.assertTrue(game.combat_status.isVisible())
        self.assertTrue(all(card.isVisible() for card in game.combat_stat_cards.values()))

    def test_auto_attack_defaults_off_and_dashboard_panels_use_available_space(self):
        game = self.window.game
        self.assertFalse(game.auto_attack.isChecked())
        self.assertFalse(game.auto_potion.isChecked())
        self.assertEqual(game.quest_table.maximumHeight(), 16777215)
        self.assertEqual(game.character_card.sizePolicy().verticalPolicy().name, 'Preferred')

    def test_fatigue_logout_is_optional_and_triggers_once_at_zero(self):
        game = self.window.game
        previous_settings = game.settings
        temporary_settings = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_settings.cleanup)
        self.addCleanup(setattr, game, 'settings', previous_settings)
        game.settings = QSettings(str(Path(temporary_settings.name) / 'settings.ini'),
                                  QSettings.Format.IniFormat)
        game.logout_on_fatigue.setChecked(False)
        self.assertFalse(game.logout_on_fatigue.isChecked())
        with patch.object(game, 'send_lark_notification') as notify, \
             patch.object(game, 'disconnect_ws') as disconnect:
            game.handle_fatigue_state({'farming': {'staminaPercent': 2}})
            disconnect.assert_not_called()
            game.handle_fatigue_state({'farming': {'staminaPercent': 0}})
            game.handle_fatigue_state({'farming': {'staminaPercent': 0}})
            disconnect.assert_not_called()
            self.assertEqual(notify.call_count, 1)
            self.assertEqual(notify.call_args.args[0], '疲劳值已耗尽')

        game._fatigue_exhaustion_handled = False
        game.logout_on_fatigue.setChecked(True)
        game.session_token = 'session-to-clear'
        game.token.setText('session-to-clear')
        with patch.object(game, 'disconnect_ws') as disconnect:
            game.handle_fatigue_state({'farming': {'staminaPercent': 0}})
        disconnect.assert_called_once()
        self.assertEqual(game.session_token, '')
        self.assertEqual(game.token.text(), '')
        game.logout_on_fatigue.setChecked(False)

    def test_lark_webhook_is_masked_and_persisted_in_local_settings(self):
        game = self.window.game
        previous_settings = game.settings
        temporary_settings = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_settings.cleanup)
        self.addCleanup(setattr, game, 'settings', previous_settings)
        game.settings = QSettings(str(Path(temporary_settings.name) / 'settings.ini'),
                                  QSettings.Format.IniFormat)
        self.assertEqual(game.lark_webhook.echoMode().name, 'Password')
        game.lark_webhook.setText('https://open.larksuite.com/open-apis/bot/v2/hook/test-secret')
        self.assertEqual(game.settings.value('larkWebhook', ''),
                         'https://open.larksuite.com/open-apis/bot/v2/hook/test-secret')
        self.assertIn('已保存', game.lark_status.text())
        checkbox = game.notification_preferences['purchase']
        checkbox.setChecked(False)
        self.assertFalse(game.settings.value('notifyPurchaseSuccess', True, type=bool))
        checkbox.setChecked(True)
        self.assertTrue(game.settings.value('notifyPurchaseSuccess', False, type=bool))
        game.lark_webhook.clear()
        self.assertEqual(game.settings.value('larkWebhook', ''), '')

    def test_notification_preferences_are_available_in_the_new_top_level_tab(self):
        game = self.window.game
        top_tabs = next(tab for tab in self.window.findChildren(QTabWidget)
                        if tab.count() == 6 and tab.tabText(5) == '推送设置')
        self.assertEqual(top_tabs.tabText(5), '推送设置')
        self.assertEqual(set(game.notification_preferences),
                         {'equipment', 'quest', 'fatigue', 'purchase', 'sale'})
        self.assertTrue(all(option.isChecked()
                            for option in game.notification_preferences.values()))

    def test_shop_event_callback_forwards_purchase_and_sale_notifications(self):
        monitor = object.__new__(shop.ShopMonitor)
        events = []
        monitor.lock = threading.RLock()
        monitor.buy_lock = threading.Lock()
        monitor.attempted_products = set()
        monitor.auto_buy_enabled = True
        monitor.buy_count = 0
        monitor.buy_total = 0
        monitor.events = []
        monitor._persist = lambda: None
        monitor.event_callback = lambda *event: events.append(event)
        with patch.object(shop, 'execute_purchase', return_value={'amount': 12, 'txHash': '0xabc'}):
            monitor._process_candidate(
                {'id': 15, 'itemName': '冰霜长剑'}, {'maxCount': 1, 'budget': 100})
        monitor.emit_event('sale', '出售成功', '商品名称')
        self.assertEqual([event[0] for event in events], ['purchase', 'sale'])
        self.assertEqual(events[0][1], '秒购交易已提交')
        self.assertIn('0xabc', events[0][2])

    def test_task_and_equipment_notifications_only_report_new_events(self):
        game = self.window.game
        quest = {'id': 55, 'titleZh': '雪地讨伐', 'mapId': 2, 'accepted': True,
                 'completed': False, 'objectiveType': 'MONSTER', 'progress': 0, 'target': 10}
        with patch.object(game, 'send_lark_notification') as notify, \
             patch.object(game, 'accept_next_monster_quest'):
            game.update_quests([quest])
            game.update_quests([{**quest, 'completed': True, 'progress': 10}])
            game.update_quests([{**quest, 'completed': True, 'progress': 10}])
            self.assertEqual(notify.call_count, 1)
            self.assertEqual(notify.call_args.args[0], '任务完成')
            self.assertIn('雪地讨伐', notify.call_args.args[1])

            equipment = {'items': [{'playerItemId': 'drop-1', 'itemKind': 'EQUIPMENT',
                                    'itemName': '冰霜长剑', 'slotType': 'WEAPON',
                                    'attributes': []}]}
            game.notify_new_equipment(equipment)  # Initial inventory is only a baseline.
            self.assertEqual(notify.call_count, 1)
            game.notify_new_equipment({'items': [*equipment['items'], {
                'playerItemId': 'drop-2', 'itemKind': 'EQUIPMENT', 'itemName': '新护甲',
                'slotType': 'ARMOR', 'attributes': []}]})
            self.assertEqual(notify.call_count, 2)
            self.assertEqual(notify.call_args.args[0], '装备掉落')
            self.assertIn('新护甲', notify.call_args.args[1])

    def test_monster_level_range_is_opt_in_and_filters_combat_targets(self):
        game = self.window.game
        game.monster_level_limited.setChecked(False)
        game.monster_level_min.setValue(10)
        game.monster_level_max.setValue(20)
        self.assertTrue(game.monster_matches_level_range({'level': 3}))

        game.monster_level_limited.setChecked(True)
        self.assertTrue(game.monster_matches_level_range({'level': 10}))
        self.assertTrue(game.monster_matches_level_range({'monsterLevel': 20}))
        self.assertFalse(game.monster_matches_level_range({'level': 9}))
        self.assertFalse(game.monster_matches_level_range({'requiredLevel': 21}))
        self.assertFalse(game.monster_matches_level_range({'name': 'unknown level'}))

        game.monsters['outside-range'] = {'level': 9, 'mapId': 2, 'health': 10}
        with patch.object(game, 'send_game_packet') as send:
            self.assertFalse(game.attack_monster('outside-range'))
        send.assert_not_called()
        game.monsters.pop('outside-range', None)
        game.monster_level_limited.setChecked(False)

    def test_map_summary_hides_protocol_counters_and_throttles_predicted_position(self):
        game = self.window.game
        game.world_ready = True
        game.current_map = 2
        game.world_x, game.world_y = 100, 200
        game.position_estimated = False
        game.update_map_buttons()
        self.assertEqual(game.world_status.text(), '坐标：(100, 200)')
        self.assertNotIn('生命序号', game.world_status.text())
        game.position_estimated = True
        game.last_world_status_render_at = __import__('time').monotonic()
        game.world_status.setText('坐标：(100, 200)')
        game.world_x = 101
        game.update_map_buttons()
        self.assertEqual(game.world_status.text(), '坐标：(100, 200)')

    def test_auto_route_retry_is_bounded_instead_of_looping_forever(self):
        game = self.window.game
        game.quest_map_target = 2
        with patch('game_client.wss_tester.QTimer.singleShot') as schedule:
            game.schedule_auto_travel_retry()
            game.schedule_auto_travel_retry()
            game.schedule_auto_travel_retry()
        self.assertEqual(game.auto_route_retry_count, 2)
        self.assertEqual(schedule.call_count, 2)
        self.assertIn('已达上限', game.travel_status.text())

    def test_patrol_search_expands_beyond_previous_960_unit_limit(self):
        game = self.window.game
        class FakeSocket:
            def close(self):
                pass

        game.ws = FakeSocket()
        game.world_ready = True
        game.current_map = 2
        game.world_x, game.world_y = 3872, 7488
        game.auto_attack.blockSignals(True)
        game.auto_attack.setChecked(True)
        game.auto_attack.blockSignals(False)
        game.patrol_ring = 2880
        with patch('wss_tester.find_map_path', return_value=[(3872, 4608)]) as find_path:
            game.start_patrol()
        self.assertGreaterEqual(find_path.call_args.kwargs['max_distance'], 3200)
        game.stop_patrol(reset_anchor=True)
        game.auto_attack.setChecked(False)
        game.ws = None

    def test_equipment_actions_use_documented_game_endpoints(self):
        game = self.window.game
        game.api_equipment = {'items': [
            {'playerItemId': 31, 'itemCode': 'SWORDP1', 'slotType': 'WEAPON',
             'qualityCode': 'L2', 'attack': 5, 'equipped': False},
            {'playerItemId': 32, 'itemCode': 'ARMORP1', 'slotType': 'ARMOR',
             'qualityCode': 'L1', 'equipped': True},
        ]}
        game.update_social_inventory()
        game.social_inventory_table.selectRow(0)
        self.assertIn('攻击 +5', game.social_inventory_table.item(0, 4).text())
        self.assertIn('攻击 +5', game.selected_item_attributes.text())
        game.social_inventory_table.selectRow(0)
        calls = []
        game.request_social_api = lambda *args: calls.append(args)
        game.equip_selected_item()
        self.assertEqual(calls[-1], ('equip', '/equipment/equip', 'POST', {'playerItemId': 31}))
        game.social_inventory_table.selectRow(1)
        game.equip_selected_item()
        self.assertEqual(calls[-1], ('unequip', '/equipment/unequip', 'POST', {'slotType': 'ARMOR'}))
        self.assertTrue(game.sell_item_button.isEnabled())
        with patch.object(QMessageBox, 'information') as info:
            game.sell_item_button.click()
        info.assert_called_once()
        self.assertIn('暂不可上架', game.inventory_action_status.text())

    def test_backpack_shows_attributes_and_allows_same_slot_comparison_selection(self):
        game = self.window.game
        game.api_equipment = {'items': [
            {'playerItemId': 41, 'itemCode': 'SWORDP1', 'slotType': 'WEAPON', 'qualityCode': 'L1',
             'equipmentLevel': 1, 'attack': 4, 'equipped': False},
            {'playerItemId': 42, 'itemCode': 'SWORDP2', 'slotType': 'WEAPON', 'qualityCode': 'L2',
             'equipmentLevel': 2, 'attack': 9, 'attributes': [{'code': 'HEALTH', 'value': 12}], 'equipped': False},
            {'playerItemId': 43, 'itemCode': 'ARMORP1', 'slotType': 'ARMOR', 'qualityCode': 'L1',
             'defense': 3, 'equipped': False},
        ]}
        game.backpack_table = QTableWidget(0, 5)
        game.backpack_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        game.backpack_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        game.backpack_status = QLabel()
        game.backpack_equip_button = QPushButton()
        game.backpack_compare_button = QPushButton()
        game.backpack_sell_button = QPushButton()
        game.update_backpack()
        self.assertIn('攻击 +4', game.backpack_table.item(0, 4).text())
        self.assertIn('生命 +12', game.backpack_table.item(1, 4).text())
        selection = game.backpack_table.selectionModel()
        selection.select(game.backpack_table.model().index(0, 0),
                         QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows)
        selection.select(game.backpack_table.model().index(1, 0),
                         QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows)
        game.update_backpack_action()
        self.assertTrue(game.backpack_compare_button.isEnabled())
        compared = []
        game.open_equipment_comparison = lambda items: compared.extend(items)
        game.compare_backpack_selection()
        self.assertEqual([item['playerItemId'] for item in compared], [41, 42])
        compare_dialog = QDialog()
        calls = []
        game.request_social_api = lambda *args: calls.append(args)
        game.equip_item_from_comparison(game.api_equipment['items'][1], compare_dialog)
        self.assertEqual(calls[-1], ('equip', '/equipment/equip', 'POST', {'playerItemId': 42}))

    def test_single_backpack_item_compares_against_equipped_item_and_highlights_differences(self):
        game = self.window.game
        equipped = {'playerItemId': 30, 'itemCode': 'SWORDP1', 'slotType': 'WEAPON',
                    'qualityCode': 'L1', 'attack': 4, 'equipped': True}
        carried = {'playerItemId': 31, 'itemCode': 'SWORDP2', 'slotType': 'WEAPON',
                   'qualityCode': 'L2', 'attack': 9, 'equipped': False}
        game.api_equipment = {'items': [equipped, carried]}
        game.backpack_table = QTableWidget(0, 5)
        game.backpack_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        game.backpack_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        game.backpack_status = QLabel()
        game.backpack_equip_button = QPushButton()
        game.backpack_compare_button = QPushButton()
        game.backpack_sell_button = QPushButton()
        game.update_backpack()
        game.backpack_table.selectRow(0)
        game.update_backpack_action()
        self.assertTrue(game.backpack_compare_button.isEnabled())
        self.assertEqual(game.backpack_compare_button.text(), '对比已装备')
        captured = []
        with patch.object(QDialog, 'exec', lambda dialog: captured.append(dialog) or 0):
            game.compare_backpack_selection()
        table = captured[0].findChild(QTableWidget)
        self.assertIn('已装备', table.horizontalHeaderItem(1).text())
        self.assertIn('铁卫剑', table.horizontalHeaderItem(2).text())
        self.assertNotEqual(table.item(2, 1).background().color().name(),
                            table.item(2, 2).background().color().name())
        buttons = captured[0].findChildren(QPushButton)
        self.assertIn('当前已装备', [button.text() for button in buttons])

    def test_item_attribute_formatting_covers_game_stats(self):
        self.assertEqual(equipment_attribute_lines({'attributes': [
            {'code': 'ATTACK', 'value': 8}, {'code': 'LUCK', 'value': 3}
        ]}), ['攻击 +8', '幸运 +3%'])

    def test_mode_and_chat_use_live_realtime_actions(self):
        game = self.window.game
        game.ws = object()
        game.world_ready = True
        game.server_dead = False
        sent = []
        game.send_game_packet = lambda packet, **kwargs: sent.append(packet)
        game.combat_mode.setCurrentIndex(2)
        game.set_combat_mode()
        self.assertEqual(sent[-1], {'action': 'mode', 'mode': 2})
        game.social_chat_input.setText('hello')
        game.send_chat_message()
        self.assertEqual(sent[-1], {'action': 'chat', 'channel': 'world', 'message': 'hello'})
        self.assertEqual(game.social_chat_input.text(), '')
        game.ws = None

    def test_resource_counts_latency_and_live_target_are_visible(self):
        game = self.window.game
        game.last_self_state = {
            'healthPotions': 2, 'bossTickets': 1,
            'atonementStones': 0, 'townStones': ['one', 'two'], 'evil': 3,
            'health': 20, 'maxHealth': 30,
        }
        game.refresh_character_status()
        self.assertEqual(game.resource_chips['healthPotions'].text(), '生命药水  2')
        self.assertEqual(game.resource_chips['atonementStones'].text(), '赎罪石  0')
        self.assertEqual(game.resource_chips['townStones'].text(), '回城石  2')
        self.assertEqual(game.resource_chips['evil'].text(), '恶名值  3/10')
        self.assertEqual(game.find_unread_count({'data': {'unreadCount': 4}}), 4)
        self.assertEqual(game.find_unread_count([{'id': 1}, {'id': 2}]), 2)
        self.assertIsNone(game.find_unread_count({'total': 12}))

        game.world_x, game.world_y = 0, 0
        game.current_map = 2
        game.monsters = {
            'encounter-abc': {
                'encounterId': 'encounter-abc', 'name': 'skeleton',
                'mapId': 2, 'x': 3, 'y': 4, 'health': 10,
            }
        }
        game.next_attack = {'id': 'ticket-1'}
        game.pending_pings[12345] = __import__('time').monotonic() - 0.05
        game.accept_packet({'type': 'pong', 'sentAt': 12345})
        self.assertGreaterEqual(game.last_rtt_ms, 40)
        self.assertLess(game.last_rtt_ms, 500)
        self.assertIn('最近目标 骷髅怪', game.live_telemetry.text())
        self.assertIn('5 单位', game.live_telemetry.text())
        self.assertIn('可攻击', game.live_telemetry.text())

    def test_compact_monster_deltas_survive_travel_and_keep_unchanged_rows(self):
        game = self.window.game
        game.current_map = 1
        game.world_ready = True
        game.update_monsters({'monsters': [
            {'encounterId': 'map-1-monster', 'name': 'skeleton', 'mapId': 1,
             'x': 10, 'y': 20, 'health': 100, 'maxHealth': 100},
            {'encounterId': 'map-2-monster', 'name': 'skeleton', 'mapId': 2,
             'x': 30, 'y': 40, 'health': 100, 'maxHealth': 100},
        ]})

        # The live Godot client preserves its snapshot cache across travel;
        # v2 frames only carry changed monster rows.
        game.pending_destination = 2
        game.accept_packet({'type': 'travel_result', 'ok': True,
                            'x': 30, 'y': 40, 'revision': 2})
        self.assertEqual(game.current_map, 2)
        self.assertIn('map-2-monster', game.monsters)

        # deltaVersion=2 is the protocol's compact marker. An unchanged row
        # must remain available even when a later packet updates another row.
        game.update_monsters({'delta': True, 'deltaVersion': 2, 'monsters': [
            {'encounterId': 'map-2-monster', 'health': 75},
        ]})
        self.assertEqual(game.monsters['map-2-monster']['health'], 75)
        self.assertEqual(game.monsters['map-2-monster']['x'], 30)
        self.assertIn('map-1-monster', game.monsters)
        self.assertEqual(game.monster_table.rowCount(), 1)

    def test_full_monster_snapshot_replaces_delta_cache(self):
        game = self.window.game
        game.current_map = 2
        game.world_ready = True
        game.update_monsters({'delta': False, 'deltaVersion': 2, 'monsters': [
            {'encounterId': 'old-monster', 'name': 'skeleton', 'mapId': 2,
             'x': 10, 'y': 20, 'health': 100},
        ]})
        game.update_monsters({'delta': False, 'deltaVersion': 2, 'monsters': [
            {'encounterId': 'new-monster', 'name': 'skeleton', 'mapId': 2,
             'x': 30, 'y': 40, 'health': 100},
        ]})
        self.assertEqual(set(game.monsters), {'new-monster'})
        self.assertEqual(game.monster_table.rowCount(), 1)

    def test_auto_combat_patrols_when_snowfield_has_no_monsters(self):
        game = self.window.game
        game.ws = object()
        game.world_ready = True
        game.current_map = 2
        game.world_x, game.world_y = 3872, 7488
        game.auto_attack.blockSignals(True)
        game.auto_attack.setChecked(True)
        game.auto_attack.blockSignals(False)
        game.next_attack = {}

        with patch('game_client.wss_tester.find_map_path', return_value=[(3872, 7168)]):
            game.auto_attack_tick()
        self.assertTrue(game.patrol_timer.isActive())
        self.assertEqual(game.patrol_route, [(3872, 7168)])

        game.monsters = {'new-monster': {
            'encounterId': 'new-monster', 'mapId': 2, 'x': 3872,
            'y': 7488, 'health': 100, 'monsterRank': 'NORMAL',
        }}
        game.auto_attack_tick()
        self.assertFalse(game.patrol_timer.isActive())
        self.assertIn('等待服务端攻击票据', game.combat_status.text())
        game.stop_patrol(reset_anchor=True)
        game.combat_timer.stop()
        game.ws = None

    def test_auto_combat_patrols_all_other_maps_without_monsters(self):
        game = self.window.game
        game.ws = object()
        game.world_ready = True
        game.auto_attack.blockSignals(True)
        game.auto_attack.setChecked(True)
        game.auto_attack.blockSignals(False)
        game.next_attack = {}
        map_positions = {1: (416.0, 1504.0), 3: (608.0, 520.0),
                         4: (9024.0, 1568.0), 5: (192.0, 2528.0),
                         6: (3872.0, 160.0)}

        for map_id, (x, y) in map_positions.items():
            with self.subTest(map_id=map_id):
                game.stop_patrol(reset_anchor=True)
                game.current_map = map_id
                game.world_x, game.world_y = x, y
                game.auto_attack_tick()
                self.assertTrue(game.patrol_timer.isActive())
                self.assertTrue(game.patrol_route)

        game.stop_patrol(reset_anchor=True)
        game.combat_timer.stop()
        game.ws = None

    def test_auto_reconnect_continues_after_many_failures(self):
        game = self.window.game
        game.manual_disconnect = False
        game.auto_reconnect.setChecked(True)
        game._reconnect_attempt = 8
        game.schedule_auto_reconnect()
        self.assertTrue(game.reconnect_timer.isActive())
        self.assertEqual(game._reconnect_attempt, 9)
        self.assertEqual(game.reconnect_timer.interval(), 60000)
        game.reconnect_timer.stop()

    def test_rejected_token_stops_reconnecting_same_credential(self):
        game = self.window.game
        game.manual_disconnect = False
        game.auto_reconnect.setChecked(True)
        game.auth_method.setCurrentIndex(game.auth_method.findData('token'))
        game.auth_rejected = True

        game.on_connect_failed()

        self.assertFalse(game.reconnect_timer.isActive())
        self.assertFalse(game._auto_reconnect_login)
        self.assertIn('登录凭证已失效', game.status.text())

    def test_rejected_saved_wallet_reauthenticates_only_once(self):
        game = self.window.game
        game.manual_disconnect = False
        game.auto_reconnect.setChecked(True)
        game.auth_method.setCurrentIndex(game.auth_method.findData('private_key'))
        game.remember_private_key.setChecked(True)

        with patch('game_client.wss_tester.QTimer.singleShot') as single_shot:
            game.auth_rejected = True
            game.on_connect_failed()
            self.assertTrue(game._auth_retry_attempted)
            self.assertTrue(game._auto_reconnect_login)
            single_shot.assert_called_once_with(0, game.retry_connection)

            # If a freshly signed session is also rejected, stop instead of looping.
            game.auth_rejected = True
            game.on_connect_failed()

        self.assertFalse(game.reconnect_timer.isActive())
        self.assertFalse(game._auto_reconnect_login)
        self.assertEqual(single_shot.call_count, 1)
        self.assertIn('登录凭证已失效', game.status.text())

    def test_missing_pong_marks_connection_dead_and_reconnects(self):
        game = self.window.game

        class StalledSocket:
            closed = False

            def close(self):
                self.closed = True

        stalled = StalledSocket()
        game.ws = stalled
        game.world_ready = True
        game.last_pong_received_at = __import__('time').monotonic() - 13
        game.send_keepalive()
        self.assertTrue(stalled.closed)
        self.assertIsNone(game.ws)
        self.assertTrue(game.reconnect_timer.isActive())
        game.reconnect_timer.stop()

    def test_invalid_target_does_not_mark_cached_monster_as_dead(self):
        game = self.window.game
        encounter_id = 'still-alive'
        game.current_map = 1
        game.world_x, game.world_y = 10, 10
        game.monsters = {encounter_id: {
            'encounterId': encounter_id, 'name': 'skeleton', 'mapId': 1,
            'x': 20, 'y': 20, 'health': 80, 'maxHealth': 100,
        }}
        game.refresh_monster_table()
        game.last_attacked_monster = encounter_id
        game.last_attack_ticket = 'ticket-1'
        game.used_attack_tickets.add('ticket-1')
        game.accept_packet({'type': 'error', 'action': 'monsterAttack',
                            'code': 'invalid_target',
                            'nextAttack': {'id': 'ticket-1'}})
        self.assertEqual(game.monsters[encounter_id]['health'], 80)
        self.assertEqual(game.monster_table.rowCount(), 1)
        self.assertGreater(game.invalid_target_until[encounter_id], __import__('time').monotonic())
        self.assertNotIn('ticket-1', game.used_attack_tickets)

    def test_minimap_accepts_flat_and_nested_peer_positions(self):
        self.assertEqual(peer_map_position({'mapId': '2', 'x': '12.5', 'y': 8}), (2, 12.5, 8.0))
        self.assertEqual(peer_map_position({'map': 3, 'position': {'x': 10, 'y': -4}}), (3, 10.0, -4.0))
        self.assertEqual(peer_map_position({'id': 8, 'x': 10, 'y': 12}, 4), (4, 10.0, 12.0))
        self.assertIsNone(peer_map_position({'playerName': 'no coordinates'}))

    def test_minimap_keeps_grid_background_visible_inside_terrain(self):
        game = self.window.game
        game.current_map = 2
        game.world_x, game.world_y = 3840, 3840
        game.monsters = {}
        game.last_peers = []
        game.minimap.resize(320, 320)
        image = QImage(320, 320, QImage.Format.Format_ARGB32)
        image.fill(0)
        game.minimap.render(image)
        self.assertEqual(image.pixelColor(20, 20).name(), '#191d1e')

    def test_nearby_players_survive_empty_and_partial_snapshots_until_stale(self):
        game = self.window.game
        game.current_map = 2
        game.merge_nearby_players([{'id': 7, 'playerName': '附近玩家', 'x': 10, 'y': 20}])
        game.merge_nearby_players([])
        self.assertEqual(len(game.last_peers), 1)
        game.merge_nearby_players([{'id': 7, 'x': 12}])
        self.assertEqual(game.last_peers[0]['playerName'], '附近玩家')
        self.assertEqual(game.last_peers[0]['x'], 12)
        game.peer_last_seen['id:7'] = 100.0
        game.expire_nearby_players(109.0)
        self.assertEqual(game.last_peers, [])

    def test_combat_feedback_uses_tone_color_and_restores_default(self):
        game = self.window.game
        game.set_combat_feedback('命中：伤害 42 · 暴击', 'critical')
        self.assertIn('#E7B85E', game.combat_status.styleSheet())
        game.set_combat_feedback('攻击被拒绝：invalid_target', 'error')
        self.assertIn('#E47782', game.combat_status.styleSheet())


if __name__ == '__main__':
    unittest.main()
