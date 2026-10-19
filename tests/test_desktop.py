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
from PySide6.QtWidgets import (QApplication, QLabel, QMessageBox, QPushButton,
                               QTableWidget, QTabWidget)
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

    def test_private_key_auth_is_default_and_token_field_rejects_wallet_key_format(self):
        game = self.window.game
        self.assertEqual(game.auth_method.currentData(), 'private_key')
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


if __name__ == '__main__':
    unittest.main()
