"""Local integration checks; no game/shop upstream calls or wallet access."""
import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
os.environ.setdefault('QTWEBENGINE_CHROMIUM_FLAGS', '--disable-gpu')
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.request import urlopen
from urllib.error import HTTPError
from unittest.mock import patch
from PySide6.QtWidgets import QApplication, QLabel, QPushButton, QTableWidget, QTabWidget
from PySide6.QtCore import QEventLoop, QTimer
from desktop import DesktopWindow, shop
from game_client.wss_tester import QUALITY_NAMES_ZH, localized_item_name, quality_color


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
        self.assertTrue(self.window.game_nav.isChecked())
        self.assertTrue(self.window.game.dashboard_header.isHidden())
        self.window.game.set_state('已连接')
        self.assertIn('已连接', self.window.account_status.text())

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
        game.backpack_table = QTableWidget(0, 4)
        game.backpack_status = QLabel()
        game.update_backpack()
        self.assertEqual(game.backpack_table.item(0, 0).foreground().color().name(), '#c994ff')
        self.assertEqual(game.backpack_table.item(0, 2).text(), '史诗')
        game.update_social_inventory()
        self.assertEqual(game.social_inventory_table.item(0, 0).foreground().color().name(), '#c994ff')
        self.assertEqual(game.social_inventory_table.item(0, 4).text(), '背包')

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

    def test_equipment_actions_use_documented_game_endpoints(self):
        game = self.window.game
        game.api_equipment = {'items': [
            {'playerItemId': 31, 'itemCode': 'SWORDP1', 'slotType': 'WEAPON',
             'qualityCode': 'L2', 'equipped': False},
            {'playerItemId': 32, 'itemCode': 'ARMORP1', 'slotType': 'ARMOR',
             'qualityCode': 'L1', 'equipped': True},
        ]}
        game.update_social_inventory()
        game.social_inventory_table.selectRow(0)
        calls = []
        game.request_social_api = lambda *args: calls.append(args)
        game.equip_selected_item()
        self.assertEqual(calls[-1], ('equip', '/equipment/equip', 'POST', {'playerItemId': 31}))
        game.social_inventory_table.selectRow(1)
        game.equip_selected_item()
        self.assertEqual(calls[-1], ('unequip', '/equipment/unequip', 'POST', {'slotType': 'ARMOR'}))
        self.assertFalse(game.sell_item_button.isEnabled())

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


if __name__ == '__main__':
    unittest.main()
