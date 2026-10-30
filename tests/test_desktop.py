"""Local integration checks; no game/shop upstream calls or wallet access."""
import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
os.environ.setdefault('QTWEBENGINE_CHROMIUM_FLAGS', '--disable-gpu')
import json
import tempfile
import threading
import unittest
from concurrent.futures import Future
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from unittest.mock import patch, Mock
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QDialog, QLabel, QMessageBox,
                               QPushButton, QTableWidget, QTabWidget, QCheckBox, QFrame)
from PySide6.QtCore import QEventLoop, QItemSelectionModel, QSettings, QTimer
from PySide6.QtGui import QImage
from desktop import BatchMapCanvas, DesktopWindow, shop
from wss_tester import MainWindow as DesktopGameWindow
from credential_vault import CredentialVault
from game_client.wss_tester import (ITEM_NAMES_ZH, QUALITY_NAMES_ZH,
                                    character_creation_payload, equipment_attribute_lines,
                                    localized_item_name, profile_needs_character_creation, quality_color)
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
        self.assertEqual(self.window.tabs.count(), 3)
        self.assertFalse(self.window.windowIcon().isNull())
        self.assertTrue(self.window.update_button.text().startswith('检查更新'))
        self.assertTrue(self.window.account_nav.isChecked())
        self.assertTrue(self.window.game.dashboard_header.isHidden())
        self.window.game.set_state('已连接')
        self.assertIn('已连接', self.window.account_status.text())

    def test_account_metadata_bursts_only_rebuild_rows_once(self):
        game = self.window.game
        self.window._game_sessions['mock-wallet'] = game
        self.window._account_refresh_timer.stop()
        with patch.object(self.window, 'refresh_planner_accounts') as refresh:
            for _ in range(20):
                self.window.on_game_metadata(game)
            self.assertTrue(self.window._account_refresh_timer.isActive())
            refresh.assert_not_called()
            loop = QEventLoop()
            QTimer.singleShot(600, loop.quit)
            loop.exec()
            self.assertEqual(refresh.call_count, 1)
            self.assertFalse(self.window._account_refresh_timer.isActive())

    def test_world_snapshot_bursts_coalesce_expensive_ui_refresh(self):
        game = self.window.game
        game.current_map = 2
        game.world_ready = True
        with patch.object(game, 'refresh_snapshot_ui', wraps=game.refresh_snapshot_ui) as refresh:
            for _ in range(20):
                game.accept_packet({'type': 'snapshot', 'self': {}, 'monsters': [], 'peers': []})
            refresh.assert_not_called()
            loop = QEventLoop()
            QTimer.singleShot(260, loop.quit)
            loop.exec()
            self.assertEqual(refresh.call_count, 1)

    def test_hidden_account_dashboard_does_not_rebuild_snapshot_widgets(self):
        game = self.window.game
        game.world_ready = True
        self.assertFalse(game.minimap.isVisible())
        with (patch.object(game, 'refresh_character_status') as character,
              patch.object(game, 'refresh_monster_table') as monsters):
            game.refresh_snapshot_ui()
        character.assert_not_called()
        monsters.assert_not_called()

    def test_explicit_account_refresh_cancels_pending_duplicate(self):
        self.window.request_account_refresh()
        self.window.refresh_account_rows()
        self.assertFalse(self.window._account_refresh_timer.isActive())

    def test_closing_window_does_not_restart_account_refresh_timer(self):
        self.window.request_account_refresh()
        self.window.close()
        self.window.request_account_refresh()
        self.assertFalse(self.window._account_refresh_timer.isActive())

    def test_multi_account_planner_applies_mode_to_selected_connected_accounts(self):
        game = self.window.game
        address = '0x' + 'a' * 40
        game.status.setText('已连接')
        self.window._game_sessions[address.lower()] = game
        selected = QCheckBox()
        selected.setChecked(True)
        self.window.planner_account_checks = {address: selected}
        self.window.planner_mode.setCurrentIndex(self.window.planner_mode.findData('quests'))
        self.window.planner_use_potion.setChecked(True)
        self.window.planner_limit_level.setChecked(True)
        self.window.planner_level_min.setValue(10)
        self.window.planner_level_max.setValue(30)
        self.window.planner_farm_after_quests.setChecked(True)
        self.window.planner_farm_map.setCurrentIndex(self.window.planner_farm_map.findData(4))
        self.window.planner_avoid_contested.setChecked(True)

        self.window.start_multi_account_plan()

        self.assertTrue(game.auto_attack.isChecked())
        self.assertTrue(game.auto_quest.isChecked())
        self.assertTrue(game.quest_map_auto.isChecked())
        self.assertTrue(game.auto_potion.isChecked())
        self.assertTrue(game.monster_level_limited.isChecked())
        self.assertEqual((game.monster_level_min.value(), game.monster_level_max.value()), (10, 30))
        self.assertTrue(game.no_quest_farm.isChecked())
        self.assertEqual(game.no_quest_farm_map.currentData(), 4)
        self.assertTrue(game.avoid_contested_monsters.isChecked())
        self.assertIn('已启动 1 个账号', self.window.planner_status.text())

        self.window.pause_multi_account_plan()
        self.assertFalse(game.auto_attack.isChecked())
        self.window.stop_multi_account_plan()
        self.assertFalse(game.auto_quest.isChecked())
        self.assertFalse(game.quest_map_auto.isChecked())

    def test_wallet_accounts_sort_by_last_three_characters_and_show_compact_labels(self):
        addresses = [
            '0x' + 'a' * 37 + '333',
            '0x' + 'b' * 37 + '111',
            '0x' + 'c' * 37 + '222',
        ]
        self.assertEqual(self.window.sorted_wallet_addresses(addresses),
                         [addresses[1], addresses[2], addresses[0]])
        with patch.object(self.window.game.credential_vault, 'list_wallets', return_value=addresses):
            self.window.refresh_planner_accounts()
            self.window.refresh_account_rows()
        self.assertEqual(list(self.window.planner_account_checks),
                         [addresses[1], addresses[2], addresses[0]])
        self.assertEqual([box.text() for box in self.window.planner_account_checks.values()],
                         ['尾号 111', '尾号 222', '尾号 333'])
        self.assertTrue(all(box.toolTip() == address for address, box
                            in self.window.planner_account_checks.items()))

    def test_account_rows_compact_wallet_address_and_copy_full_address(self):
        address = '0x1234567890abcdef1234567890abcdef12345678'
        with patch.object(self.window.game.credential_vault, 'list_wallets', return_value=[address]):
            self.window.refresh_account_rows()

        row = self.window.account_rows.itemAt(0).widget()
        shown_address = row.findChild(QLabel, 'walletAddress')
        copy_button = row.findChild(QPushButton, 'walletCopyAddress')
        self.assertEqual(shown_address.text(), '0x1…5678')
        self.assertEqual(shown_address.toolTip(), address)
        copy_button.click()
        self.assertEqual(self.app.clipboard().text(), address)
        self.assertEqual(copy_button.text(), '已复制')

    def test_account_summary_shows_experience_and_two_decimal_resources(self):
        game = type('GameSummary', (), {})()
        game.api_profile = {'playerName': 'Hero', 'gold': 1234.5}
        game.last_progress_state = {'level': 12, 'experience': 1234, 'experienceNeeded': 5678}
        game.api_equipment = {'totals': {'attack': 8}}
        game.last_self_state = {'farming': {'staminaPercent': 98.5}}
        game.character_facts = {}
        game.tabby_balance_display = '6,305.93'
        summary = DesktopWindow.account_summary(game)
        self.assertIn('经验 1,234/5,678', summary)
        self.assertIn('疲劳 98.50%', summary)
        self.assertIn('金币 1,234.50', summary)
        self.assertIn('TABBY 6,305.93', summary)

    def test_account_summary_includes_luck_when_server_provides_it(self):
        game = type('GameSummary', (), {})()
        game.api_profile = {'playerName': 'Hero'}
        game.last_progress_state = {}
        game.api_equipment = {'totals': {'luck': 12.5}}
        game.last_self_state = {}
        game.character_facts = {}
        self.assertIn('幸运 12.50%', DesktopWindow.account_summary(game))

    def test_character_overview_includes_server_reported_luck(self):
        game = self.window.game
        game.api_profile = {'playerName': 'Hero', 'characterClass': 'WARRIOR'}
        game.last_progress_state = {'level': 8, 'experience': 20, 'experienceNeeded': 100}
        game.last_self_state = {'health': 10, 'maxHealth': 20, 'gold': 2}
        game.api_equipment = {'totals': {'luck': 7.5}, 'items': []}
        game.refresh_character_status()
        self.assertIn('幸运', game.character_facts)
        self.assertEqual(game.character_facts['幸运'].text(), '7.5%')

    def test_batch_map_window_is_a_separate_account_center_tool(self):
        self.assertEqual(self.window.batch_map_nav.text(), '批量地图')
        self.window.batch_map_nav.click()
        self.window.open_batch_map()
        self.app.processEvents()
        self.assertTrue(self.window.batch_map_dialog.isVisible())
        self.assertEqual(self.window.batch_map_canvas.minimumWidth(), 560)
        self.assertGreater(self.window.batch_map_selector.count(), 1)
        self.window.batch_map_dialog.close()

    def test_batch_map_labels_monster_level_name_and_rank(self):
        label = BatchMapCanvas.monster_map_label({
            'monsterKey': 'skeleton', 'level': 30, 'monsterRank': 'ELITE'
        })
        self.assertIn('30级', label)
        self.assertIn('精英', label)
        self.assertNotIn('None', label)

    def test_batch_manual_coordinate_move_uses_existing_path_planner(self):
        game = self.window.game
        class Socket:
            def send_text(self, _text):
                pass
        game.ws = Socket()
        game.world_ready = True
        game.server_dead = False
        game.respawn_pending = False
        game.current_map = 1
        game.world_x, game.world_y = 100.0, 100.0
        game.movement_revision = 1
        try:
            future = Future()
            future.set_result([(120.0, 130.0)])
            with patch('wss_tester.submit_map_path', return_value=future) as find_path:
                self.assertTrue(game.move_to_coordinate(120, 130))
            find_path.assert_called_once_with(1, (100.0, 100.0), (120.0, 130.0))
            self.assertTrue(game.manual_move_active)
            self.assertEqual(game.route_points, [(120.0, 130.0)])
        finally:
            game.move_timer.stop()
            game.manual_move_active = False
            game.route_points.clear()
            game.ws = None

    def test_batch_map_move_dispatches_to_selected_accounts_on_other_maps_too(self):
        self.window.open_batch_map()
        self.app.processEvents()
        map_id = int(self.window.batch_map_selector.currentData())
        class Session:
            def __init__(self, address, current_map):
                self._desktop_wallet_address = address
                self.current_map = current_map
                self.manual_map_target = None
                self.calls = []
            def move_to_coordinate(self, x, y):
                self.calls.append(('move', x, y))
                return True
            def start_manual_map_travel(self, destination, coordinate_target=None):
                self.calls.append(('travel', destination, coordinate_target))
                self.manual_map_target = destination

        first = Session('0x' + '1' * 37 + '111', map_id)
        second = Session('0x' + '2' * 37 + '222', 1 if map_id != 1 else 2)
        self.window.batch_map_canvas.target = {'x': 123.0, 'y': 456.0}
        with patch.object(self.window, 'selected_batch_map_games', return_value=[first, second]):
            self.window.batch_map_move_selected()

        self.assertEqual(first.calls, [('move', 123.0, 456.0)])
        self.assertEqual(second.calls, [('travel', map_id, (123.0, 456.0))])
        self.assertIn('已向 2/2 个所选账号派发移动', self.window.batch_map_status.text())
        self.window.batch_map_dialog.close()

    def test_manual_map_travel_starts_queued_coordinate_move_after_arrival(self):
        game = self.window.game
        game.world_ready = True
        game.server_dead = False
        game.respawn_pending = False
        game.current_map = 2
        with patch.object(game, 'move_to_coordinate', return_value=True) as move:
            game.start_manual_map_travel(2, coordinate_target=(321.0, 654.0))
        move.assert_called_once_with(321.0, 654.0)
        self.assertIsNone(game.manual_map_target)
        self.assertIsNone(game.manual_coordinate_target)

    def test_account_summary_shows_current_map(self):
        game = type('GameSummary', (), {})()
        game.api_profile = {'playerName': 'Hero'}
        game.last_progress_state = {}
        game.api_equipment = {}
        game.last_self_state = {}
        game.character_facts = {}
        game.current_map = 6
        self.assertIn('地图 南部森林', DesktopWindow.account_summary(game))
        game.current_map = None
        self.assertIn('地图 南部森林', DesktopWindow.account_summary(game, 6))

    def test_current_map_change_notifies_account_center(self):
        game = self.window.game
        changes = []
        game.on_map_change = changes.append
        game.set_current_map(6)
        game.set_current_map(6)
        self.assertEqual(changes, [6])

    def test_auto_equip_uses_weighted_total_for_mixed_stat_upgrades(self):
        game = self.window.game
        game.auto_equip_better.setChecked(True)
        game.api_equipment = {'items': [
            {'playerItemId': 'worn', 'slotType': 'WEAPON', 'equipped': True,
             'attributes': [{'code': 'ATTACK', 'value': 8}, {'code': 'DEFENSE', 'value': 5}]},
            {'playerItemId': 'attack', 'slotType': 'WEAPON', 'equipped': False,
             'attributes': [{'code': 'ATTACK', 'value': 10}]},
            {'playerItemId': 'balanced', 'slotType': 'WEAPON', 'equipped': False,
             'attributes': [{'code': 'ATTACK', 'value': 9}, {'code': 'DEFENSE', 'value': 9}]},
        ]}
        calls = []
        game.request_social_api = lambda *args: calls.append(args)
        game.auto_equip_best_inventory_item()
        self.assertEqual(calls[0][0:4], ('equip', '/equipment/equip', 'POST', {'playerItemId': 'balanced'}))

        game._auto_equip_pending_id = None
        game._auto_equip_attempted_ids.clear()
        # A 9 attack / 2 defense cross-trade is weaker than the currently equipped 8/5 set.
        game.api_equipment['items'][2]['attributes'][0]['value'] = 9
        game.api_equipment['items'][2]['attributes'][1]['value'] = 2
        game.api_equipment['items'] = game.api_equipment['items'][:2] + [game.api_equipment['items'][2]]
        calls.clear()
        game.auto_equip_best_inventory_item()
        self.assertEqual(calls, [])

    def test_planner_account_selector_expands_to_show_two_rows(self):
        addresses = ['0x' + 'a' * 37 + f'{index:03}' for index in range(11)]
        with patch.object(self.window.game.credential_vault, 'list_wallets', return_value=addresses):
            self.window.refresh_planner_accounts()
        self.assertEqual(len(self.window.planner_account_checks), 11)
        self.assertGreaterEqual(self.window.planner_accounts_scroll.height(), 60)
        self.assertEqual(self.window.planner_accounts_scroll.maximumHeight(), 64)

    def test_town_does_not_start_monster_search_patrol(self):
        game = self.window.game
        game.current_map = 1
        game.world_x, game.world_y = 100.0, 100.0
        game.ws = object()
        game.world_ready = True
        game.auto_attack.setChecked(True)
        game.start_patrol()
        self.assertFalse(game.patrol_timer.isActive())
        self.assertIn('主城没有怪物', game.combat_status.text())
        game.ws = None

    def test_wallet_login_challenge_is_approved_without_modal_prompt(self):
        approval = {'automatic': True, 'approved': False, 'event': threading.Event(),
                    'message': 'login challenge'}
        with patch.object(QMessageBox, 'exec') as show_dialog:
            self.window.game.confirm_sign_challenge(approval)
        show_dialog.assert_not_called()
        self.assertTrue(approval['approved'])
        self.assertTrue(approval['event'].is_set())

    def test_batch_online_starts_up_to_three_wallets_concurrently(self):
        addresses = ['0x' + 'a' * 37 + suffix for suffix in ('444', '222', '111', '333')]
        expected = [addresses[2], addresses[1], addresses[3], addresses[0]]
        vault = self.window.game.credential_vault
        queued_callbacks = []

        def queue_zero_delay_callback(delay, callback):
            if delay == 0:
                queued_callbacks.append(callback)

        with (patch.object(vault, 'list_wallets', return_value=addresses),
              patch.object(self.window, 'ask_shared_passphrase', return_value='shared123'),
              patch.object(self.window, 'connect_account') as connect,
              patch.object(QTimer, 'singleShot', side_effect=queue_zero_delay_callback)):
            self.window.refresh_planner_accounts()
            self.window.set_all_planner_accounts(True)
            self.window.batch_connect_accounts()
            self.assertEqual([call.args[0] for call in connect.call_args_list], expected[:1])
            while queued_callbacks:
                queued_callbacks.pop(0)()
            self.assertEqual([call.args[0] for call in connect.call_args_list],
                             expected[:3])
            self.assertTrue(all(call.kwargs.get('background') for call in connect.call_args_list))
            self.assertEqual(len(self.window._batch_login_inflight), 3)
            self.window._finish_batch_login_result(
                expected[0], {'ok': True, 'token': 'first-session'})
            while queued_callbacks:
                queued_callbacks.pop(0)()
            self.assertEqual(connect.call_args_list[-1].args[0], expected[3])
            self.window._finish_batch_login_result(
                expected[1], {'ok': True, 'token': 'second-session'})
            self.window._finish_batch_login_result(
                expected[2], {'ok': True, 'token': 'third-session'})
            self.window._finish_batch_login_result(
                expected[3], {'ok': True, 'token': 'fourth-session'})
        self.assertIn('批量上线已完成 4 个账号', self.window.planner_status.text())

    def test_background_wallets_get_distinct_game_sessions(self):
        addresses = ['0x' + '1' * 37 + '111', '0x' + '2' * 37 + '222']
        vault = self.window.game.credential_vault
        with (patch.object(vault, 'list_wallets', return_value=addresses),
              patch.object(DesktopGameWindow, 'connect_ws')):
            self.window.connect_account(addresses[0], background=True)
            self.window.connect_account(addresses[1], background=True)

        first, second = (self.window._game_sessions[address.lower()] for address in addresses)
        self.assertIsNot(first, second)
        self.assertIsNot(first.bridge, second.bridge)

    def test_batch_map_selection_deduplicates_aliased_game_sessions(self):
        game = self.window.game
        addresses = ['0x' + '1' * 37 + '111', '0x' + '2' * 37 + '222']
        self.window._game_sessions = {address.lower(): game for address in addresses}
        self.window.batch_map_account_checks = {}
        for address in addresses:
            check = QCheckBox()
            check.setChecked(True)
            self.window.batch_map_account_checks[address] = check

        self.assertEqual(self.window.selected_batch_map_games(), [game])
        self.assertEqual(self.window.batch_map_games(), [game])

    def test_batch_login_does_not_enable_combat_automatically(self):
        address = '0x' + 'a' * 37 + '111'
        game = self.window.game
        game.status.setText('离线')
        self.window._game_sessions[address.lower()] = game
        selected = QCheckBox()
        selected.setChecked(True)
        self.window.planner_account_checks = {address: selected}
        with (patch.object(game.credential_vault, 'list_wallets', return_value=[address]),
              patch.object(self.window, 'ask_shared_passphrase', return_value='shared123'),
              patch.object(self.window, 'connect_account'),
              patch.object(QTimer, 'singleShot')):
            self.window.batch_connect_accounts()
        self.assertFalse(game.auto_attack.isChecked())
        self.assertTrue(self.window._batch_login_active)

    def test_saved_wallet_decryption_is_started_in_background_worker(self):
        game = self.window.game
        address = '0x' + 'a' * 40
        game.saved_wallet.addItem(address, address)
        game.saved_wallet.setCurrentIndex(game.saved_wallet.findData(address))
        game._vault_passphrase = 'shared123'
        game.url.setText('wss://game.tabby.meme/api/realtime')
        game.remember_private_key.setChecked(True)
        with (patch.object(game.credential_vault, 'load_wallet') as load_wallet,
              patch('game_client.wss_tester.threading.Thread') as worker,
              patch.object(QMessageBox, 'warning') as warning):
            game.start_signed_login()
        load_wallet.assert_not_called()
        worker.assert_called_once()
        worker.return_value.start.assert_called_once_with()
        warning.assert_not_called()

    def test_batch_offline_disconnects_selected_online_accounts(self):
        address = '0x' + 'a' * 37 + '111'
        game = self.window.game
        game.status.setText('已连接')
        game.auto_attack.setChecked(True)
        self.window._game_sessions[address.lower()] = game
        selected = QCheckBox()
        selected.setChecked(True)
        self.window.planner_account_checks = {address: selected}
        with (patch.object(game, 'disconnect_ws') as disconnect,
              patch.object(self.window, 'refresh_account_rows')):
            self.window.batch_disconnect_accounts()
        disconnect.assert_called_once_with()
        self.assertFalse(game.auto_attack.isChecked())
        self.assertIn('已批量下线 1 个账号', self.window.planner_status.text())

    def test_vault_passphrase_is_cached_globally_and_kept_after_login_failure(self):
        phrase = 'shared-vault-passphrase'
        self.window.cache_shared_passphrase(phrase)
        game = self.window.game
        self.assertEqual(game._vault_passphrase, phrase)
        with patch.object(QMessageBox, 'warning'):
            game.finish_signed_login({
                'ok': False,
                'error': 'RuntimeError: /membership/challenge: try_again',
            })
        self.app.processEvents()
        self.assertEqual(self.window._master_passphrase, phrase)
        self.assertEqual(game._vault_passphrase, phrase)
        self.assertIn('try_again', self.window.account_keyring_status.text())

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

    def test_character_creation_only_uses_explicit_server_flag(self):
        self.assertTrue(profile_needs_character_creation({'characterCreated': False}))
        self.assertFalse(profile_needs_character_creation({'playerName': '已有角色'}))
        self.assertFalse(profile_needs_character_creation({'characterCreated': True}))
        self.assertFalse(profile_needs_character_creation(None))
        self.assertEqual(character_creation_payload(' 新角色_7 ', 'WARRIOR'),
                         {'name': '新角色_7', 'characterClass': 'WARRIOR'})
        self.assertEqual(character_creation_payload('Guard2', 'GUARD')['characterClass'], 'GUARD')
        self.assertEqual(character_creation_payload('Archer3', 'ARCHER')['characterClass'], 'ARCHER')
        for name, character_class in [('x', 'WARRIOR'), ('a name', 'WARRIOR'),
                                      ('valid', 'MAGE')]:
            with self.subTest(name=name, character_class=character_class):
                with self.assertRaises(ValueError):
                    character_creation_payload(name, character_class)

    def test_uncreated_character_shows_creation_action_without_prompting_background_account(self):
        game = self.window.game
        game.can_prompt_character_creation = lambda: False
        game.accept_profile_data({
            'player': {'characterCreated': False},
            'equipment': {},
            'progression': {},
        })
        self.assertTrue(game.character_creation_required)
        self.assertFalse(game.create_character_button.isHidden())
        self.assertFalse(game.character_creation_prompted)

    def test_batch_login_failure_does_not_open_modal_after_state_callback(self):
        game = self.window.game
        address = '0x' + '1' * 40
        self.window._game_sessions[address] = game
        self.window._game_address_by_bridge[id(game.bridge)] = address
        self.window._batch_login_active = True
        self.window._batch_login_inflight = {address}
        game._batch_login_silent = True
        with patch.object(QMessageBox, 'warning') as warning:
            game.finish_signed_login({'ok': False, 'error': 'test login error'})
        warning.assert_not_called()
        self.assertFalse(self.window._batch_login_inflight)

    def test_batch_uncreated_current_account_never_opens_creation_dialog(self):
        game = self.window.game
        address = '0x' + '1' * 40
        self.window._game_sessions[address] = game
        self.window._game_address_by_bridge[id(game.bridge)] = address
        self.window.active_address = address
        self.window._batch_login_active = True
        self.window._batch_login_inflight = {address}
        game._batch_login_silent = True
        game.pending_world_entry = True
        game.signed_session_token = 'test-session'
        with (patch.object(game, 'show_character_creation_dialog') as dialog,
              patch.object(game, 'connect_ws') as connect):
            game.accept_profile_data({'loginPreflight': True,
                                      'loginPreflightGeneration': game._login_generation,
                                      'player': {'characterCreated': False}})
            self.app.processEvents()
        dialog.assert_not_called()
        connect.assert_not_called()
        self.assertTrue(game.character_creation_required)
        self.assertFalse(self.window._batch_login_inflight)
        self.assertEqual(self.window._batch_login_failed, 0)
        self.assertEqual(self.window._batch_login_needs_character, {address})

    def test_mixed_batch_releases_uncreated_account_slot_and_can_open_creation_later(self):
        addresses = ['0x' + str(i) * 40 for i in range(1, 5)]
        vault = self.window.game.credential_vault
        self.window._master_passphrase = 'test-password'
        with (patch.object(vault, 'list_wallets', return_value=addresses),
              patch.object(DesktopGameWindow, 'connect_ws') as connect,
              patch.object(self.window, 'prepare_shop_account_context')):
            self.window.refresh_planner_accounts()
            self.window.set_all_planner_accounts(True)
            self.window.batch_connect_accounts()
            for _ in range(5):
                self.app.processEvents()
            self.assertEqual(len(self.window._batch_login_inflight), 3)
            waiting = self.window._game_sessions[addresses[0]]
            waiting.pending_world_entry = True
            waiting.signed_session_token = 'pending-character-session'
            with patch.object(waiting, 'show_character_creation_dialog') as dialog:
                waiting.accept_profile_data({'loginPreflight': True,
                    'loginPreflightGeneration': waiting._login_generation,
                    'player': {'characterCreated': False}})
                self.app.processEvents()
                dialog.assert_not_called()
                self.assertIn(addresses[3], self.window._game_sessions)
                self.assertNotIn(addresses[0], self.window._batch_login_inflight)
                for address in addresses[1:]:
                    self.window._game_sessions[address].bridge.state.emit('已连接')
                self.assertFalse(self.window._batch_login_active)
                self.assertEqual(self.window._batch_login_failed, 0)
                self.assertIn('1 个待创建角色', self.window.planner_status.text())
                self.window.refresh_account_rows()
                row = self.window.account_rows.itemAt(0).widget()
                self.assertIn('创建角色', [button.text() for button in row.findChildren(QPushButton)])
                connect.reset_mock()
                self.window.connect_account(addresses[0])
                self.app.processEvents()
                dialog.assert_called_once()
                connect.assert_not_called()
                self.assertFalse(waiting._background_login)
                self.window.connect_account(addresses[0])
                self.app.processEvents()
                self.assertEqual(dialog.call_count, 2)

    def test_previous_batch_timeout_cannot_disconnect_later_attempt(self):
        game = self.window.game
        address = '0x' + '1' * 40
        self.window._game_sessions[address] = game
        self.window._batch_login_active = True
        self.window._batch_login_inflight = {address}
        old_run, current_run = object(), object()
        self.window._batch_login_timeouts[address] = current_run
        with patch.object(game, 'disconnect_ws') as disconnect:
            self.window._batch_login_timeout(address, old_run)
            disconnect.assert_not_called()
            self.assertEqual(self.window._batch_login_inflight, {address})
            self.window._batch_login_timeout(address, current_run)
            disconnect.assert_called_once()
        self.assertEqual(self.window._batch_login_failed, 1)

    def test_archer_uses_ranged_attack_and_directional_impact_frames(self):
        game = self.window.game
        game.api_profile = {'characterClass': 'ARCHER'}
        self.assertEqual(game.attack_reach(), 295)
        self.assertEqual(game.attack_reach(impact=True), 310)
        game.attack_elevation = 0
        sideways, _, speed = game.attack_timing(False)
        game.attack_elevation = 1
        downward, _, _ = game.attack_timing(True)
        self.assertEqual(sideways, round(7 * (0.88 / 12) / speed * 1000))
        self.assertLess(downward, sideways)
        game.world_ready = True
        game.current_map = 2
        game.world_x = game.world_y = 0
        game.monster_level_limited.setChecked(False)
        game.monsters = {'target': {'mapId': 2, 'health': 10, 'x': 250, 'y': 0}}
        game.next_attack = {'id': 'archer-ticket'}
        game.ws = object()
        try:
            with patch.object(game, 'send_game_packet') as send, patch('wss_tester.QTimer.singleShot'):
                self.assertTrue(game.attack_monster('target'))
                self.assertEqual(send.call_args.args[0]['attackElevation'], 0)
                game.send_monster_attack('target', 'archer-ticket')
                self.assertEqual(send.call_args.args[0]['action'], 'monsterAttack')
            game.last_self_state['characterClass'] = 'GUARD'
            self.assertEqual(game.attack_reach(), 55)
        finally:
            game.ws = None

    def test_treasure_stone_requires_manual_action_and_server_position(self):
        game = self.window.game
        game.world_ready = True
        game.current_map = 1
        game.world_x = game.world_y = 100
        game.ws = object()
        game.last_self_state = {'treasureStones': 1}
        try:
            with patch.object(game, 'send_game_packet') as send:
                game.update_activity_controls()
                send.assert_not_called()
                self.assertTrue(game.request_activity('useTreasureStone'))
                self.assertEqual(send.call_args.args[0], {'action': 'useTreasureStone'})
                self.assertEqual(game.current_map, 1)
                self.assertFalse(game.request_activity('useTreasureStone'))
                game.accept_packet({'type': 'treasure_position', 'revision': 4, 'map': 7,
                                    'x': 3872, 'y': 7360, 'serverTime': 1000,
                                    'expiresAt': 3601000, 'treasureStones': 0})
                self.assertEqual(game.current_map, 7)
                self.assertEqual(game.movement_revision, 4)
                self.assertFalse(game.auto_attack.isChecked())
                self.assertFalse(game.activity_buttons['useTreasureStone'].isEnabled())
                game.accept_packet({'type': 'treasure_position', 'revision': 3, 'map': 1, 'x': 0, 'y': 0})
                self.assertEqual(game.current_map, 7)
                game.accept_packet({'type': 'treasure_position', 'revision': 5, 'map': 1,
                                    'x': 928, 'y': 928, 'serverTime': 3601000, 'expiresAt': 3601000,
                                    'expired': True})
                self.assertEqual(game.current_map, 1)
                self.assertFalse(game.activity_buttons['enterTreasureLand'].isEnabled())
        finally:
            game.ws = None

    def test_fishing_rod_sends_owned_item_id_without_equipping_or_consuming(self):
        game = self.window.game
        game.world_ready = True
        game.current_map = 1
        game.world_x = game.world_y = 100
        game.api_equipment = {'items': [{'playerItemId': 42, 'itemCode': 'WOODEN_FISHING_ROD', 'slotType': 'OTHER'}]}
        game.ws = object()
        try:
            with patch.object(game, 'send_game_packet') as send:
                self.assertTrue(game.request_activity('useFishingRod'))
                self.assertEqual(send.call_args.args[0], {'action': 'useFishingRod', 'playerItemId': 42})
                self.assertEqual(game.fishing_rod()['playerItemId'], 42)
                game.accept_packet({'type': 'fishing_rod_failed'})
                self.assertIsNone(game._activity_pending)
        finally:
            game.ws = None

    def test_stamina_potion_requires_resource_and_waits_for_confirmation(self):
        game = self.window.game
        game.world_ready = True
        game.current_map = 1
        game.last_self_state = {'staminaPotions': 1, 'farming': {'staminaPercent': 100}}
        game.ws = object()
        try:
            with patch.object(game, 'send_game_packet') as send:
                self.assertFalse(game.request_activity('useStaminaPotion'))
                send.assert_not_called()
                game.last_self_state['farming']['staminaPercent'] = 50
                self.assertTrue(game.request_activity('useStaminaPotion'))
                self.assertEqual(game.last_self_state['staminaPotions'], 1)
                game.accept_packet({'type': 'stamina_potion_used', 'quantity': 0})
                self.assertEqual(game.last_self_state['staminaPotions'], 0)
                self.assertEqual(game.last_self_state['farming']['staminaPercent'], 100)
        finally:
            game.ws = None

    def test_class_restriction_excludes_wrong_profession_from_auto_equipment(self):
        game = self.window.game
        game.api_profile = {'characterClass': 'ARCHER'}
        game.api_equipment = {'items': [{'playerItemId': 50, 'slotType': 'WEAPON',
                                        'requiredClass': 'WARRIOR', 'attack': 999}]}
        with patch.object(game, 'request_social_api') as request:
            game.auto_equip_best_inventory_item()
        request.assert_not_called()
        self.assertTrue(game.equipment_matches_class({'requiredClass': 'ARCHER'}))

    def test_delivery_requires_exact_manual_item_selection(self):
        game = self.window.game
        game._delivery_requested_id = 31
        game.show_quest_delivery({'quest': {'target': 2, 'runNumber': 7}, 'items': [
            {'playerItemId': 10, 'itemCode': 'SWORDP1'},
            {'playerItemId': 11, 'itemCode': 'SWORDP1'},
            {'playerItemId': 12, 'itemCode': 'SWORDP1', 'equipped': True}]})
        try:
            checks = game._delivery_dialog.findChildren(QCheckBox)
            self.assertEqual(len(checks), 2)
            with patch.object(game, 'request_social_api') as request:
                self.assertFalse(game._delivery_confirm.isEnabled())
                checks[0].setChecked(True)
                self.assertFalse(game._delivery_confirm.isEnabled())
                checks[1].setChecked(True)
                request.assert_not_called()
                game._delivery_confirm.click()
                self.assertEqual(request.call_args.args, ('questDeliver', '/quests/deliver', 'POST',
                                 {'questId': 31, 'runNumber': 7, 'itemIds': [10, 11]}))
                game._delivery_dialog.close()
                self.assertFalse(game.quest_delivery_button.isEnabled())
                self.assertTrue(game._delivery_submit_pending)
        finally:
            game._delivery_dialog.close()

    def test_old_attack_idle_callback_does_not_interrupt_next_attack(self):
        game = self.window.game
        game.last_attack_ticket = 'new-ticket'
        with patch.object(game, 'send_game_packet') as send:
            game.send_idle_after_attack(game.combat_generation, 'old-ticket')
        send.assert_not_called()

    def test_login_preflight_pauses_world_entry_for_new_character(self):
        game = self.window.game
        game.pending_world_entry = True
        game.can_prompt_character_creation = lambda: False
        with patch.object(game, 'connect_ws') as connect_ws:
            game.accept_profile_data({
                'loginPreflight': True,
                'loginPreflightGeneration': game._login_generation,
                'player': {'player': {'characterCreated': False}},
            })
        self.assertTrue(game.character_creation_required)
        self.assertTrue(game.pending_world_entry)
        self.assertFalse(game.create_character_button.isHidden())
        connect_ws.assert_not_called()

    def test_login_preflight_enters_world_for_existing_character(self):
        game = self.window.game
        game.pending_world_entry = True
        game.signed_session_token = 'test-session'
        with patch.object(game, 'connect_ws') as connect_ws:
            game.accept_profile_data({
                'loginPreflight': True,
                'loginPreflightGeneration': game._login_generation,
                'player': {'player': {'characterCreated': True, 'playerName': 'Hero'}},
            })
        self.assertFalse(game.pending_world_entry)
        connect_ws.assert_called_once()

    def test_login_preflight_error_does_not_attempt_websocket_login(self):
        game = self.window.game
        game.pending_world_entry = True
        with patch.object(game, 'connect_ws') as connect_ws:
            game.accept_profile_data({
                'loginPreflight': True,
                'loginPreflightGeneration': game._login_generation,
                'loginPreflightError': 'HTTP 502',
            })
        self.assertTrue(game.pending_world_entry)
        self.assertEqual(game.connect_button.text(), '重试读取角色')
        connect_ws.assert_not_called()

    def test_login_preflight_fetches_player_with_signed_bearer_token(self):
        received = {}

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                received['path'] = self.path
                received['authorization'] = self.headers.get('Authorization')
                payload = json.dumps({'player': {'characterCreated': False}}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        game = self.window.game
        game.url.setText(f'ws://127.0.0.1:{server.server_port}/api/realtime')
        game.signed_session_token = 'signed-test-session'
        game.pending_world_entry = True
        game.can_prompt_character_creation = lambda: False
        loop = QEventLoop()
        game.bridge.profile.connect(
            lambda payload: loop.quit() if isinstance(payload, dict)
            and payload.get('loginPreflight') else None)
        try:
            with patch.object(game, 'connect_ws') as connect_ws:
                game.preflight_character_then_enter()
                QTimer.singleShot(3000, loop.quit)
                loop.exec()
            self.assertEqual(received['path'], '/api/player')
            self.assertEqual(received['authorization'], 'Bearer signed-test-session')
            self.assertTrue(game.character_creation_required)
            self.assertTrue(game.pending_world_entry)
            connect_ws.assert_not_called()
        finally:
            server.shutdown()
            server.server_close()

    def test_character_creation_completes_pending_world_entry(self):
        game = self.window.game
        game.pending_world_entry = True
        game.character_creation_required = True
        game.signed_session_token = 'test-session'
        with patch.object(game, 'connect_ws') as connect_ws:
            game.accept_profile_data({'characterCreationResult': {
                'playerName': 'NewHero', 'characterClass': 'GUARD', 'characterCreated': True,
            }})
            self.app.processEvents()
        self.assertFalse(game.pending_world_entry)
        connect_ws.assert_called_once()

    def test_character_creation_posts_published_endpoint_payload(self):
        received = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received['path'] = self.path
                received['authorization'] = self.headers.get('Authorization')
                length = int(self.headers.get('Content-Length', '0'))
                received['body'] = json.loads(self.rfile.read(length))
                payload = json.dumps({'playerName': received['body']['name'],
                                      'characterClass': received['body']['characterClass'],
                                      'characterCreated': True}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        game = self.window.game
        game.get_session_token = lambda: 'test-session'
        game.url.setText(f'ws://127.0.0.1:{server.server_port}/api/realtime')
        loop = QEventLoop()
        game.bridge.profile.connect(
            lambda payload: loop.quit() if isinstance(payload, dict)
            and ('characterCreationResult' in payload or 'characterCreationError' in payload) else None)
        try:
            game.submit_character_creation({'name': 'NewHero', 'characterClass': 'GUARD'})
            QTimer.singleShot(3000, loop.quit)
            loop.exec()
            self.assertEqual(received['path'], '/api/player/character')
            self.assertEqual(received['authorization'], 'Bearer test-session')
            self.assertEqual(received['body'], {'name': 'NewHero', 'characterClass': 'GUARD'})
            game.accept_profile_data({'characterCreationResult': {
                'playerName': 'NewHero', 'characterClass': 'GUARD', 'characterCreated': True,
            }})
            self.assertFalse(game.character_creation_required)
            self.assertTrue(game.create_character_button.isHidden())
        finally:
            server.shutdown()
            server.server_close()

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
        self.window.tabs.setCurrentIndex(2)
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
        game.no_quest_farm.setChecked(False)
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

    def test_task_cap_uses_configured_farm_map_when_enabled(self):
        game = self.window.game
        game.task_limited_mode.setChecked(True)
        game.no_quest_farm_map.setCurrentIndex(game.no_quest_farm_map.findData(4))
        game.no_quest_farm.setChecked(True)

        game.handle_quest_limit_reached('daily cap')

        self.assertTrue(game.questless_farm_mode)
        self.assertEqual(game.questless_farm_target, 4)
        self.assertFalse(game.task_limited_mode.isChecked())
        self.assertTrue(game.auto_attack.isChecked())
        self.assertEqual(game.return_map.currentData(), 4)
        self.assertTrue(game.auto_return_map.isChecked())

    def test_no_available_followup_quest_starts_selected_free_farm(self):
        game = self.window.game
        game.no_quest_farm_map.setCurrentIndex(game.no_quest_farm_map.findData(6))
        game.no_quest_farm.setChecked(True)

        game.accept_profile_data({'questRefresh': True, 'questData': {'quests': []}})

        self.assertTrue(game.questless_farm_mode)
        self.assertEqual(game.questless_farm_target, 6)
        self.assertTrue(game.auto_attack.isChecked())

    def test_contested_monster_filter_skips_other_players_but_not_self(self):
        game = self.window.game
        game.player_id = 7
        game.current_map = 2
        game.avoid_contested_monsters.setChecked(True)
        monster = {'mapId': 2, 'x': 100, 'y': 100}
        game.last_peers = [
            {'id': 7, 'mapId': 2, 'x': 100, 'y': 100},
            {'id': 8, 'mapId': 2, 'x': 240, 'y': 100},
        ]
        self.assertTrue(game.monster_has_nearby_player(monster))
        self.assertFalse(game.monster_is_uncontested(monster))

        game.last_peers = [{'id': 7, 'mapId': 2, 'x': 100, 'y': 100}]
        self.assertFalse(game.monster_has_nearby_player(monster))
        self.assertTrue(game.monster_is_uncontested(monster))

    def test_rarity_colors_and_current_map_indicator(self):
        self.assertEqual([quality_color(f'L{level}') for level in range(1, 5)],
                         ['#667085', '#1976B2', '#7B3FA1', '#9A6500'])
        self.assertEqual(QUALITY_NAMES_ZH['L4'], '传说')
        self.assertEqual(localized_item_name({'itemCode': 'STARTER_SHOES'}), '皮革靴')

    def test_game_palette_and_action_buttons_are_visibly_clickable(self):
        game = self.window.game
        stylesheet = game.styleSheet()
        self.assertIn('background: #F1EEE7', stylesheet)
        self.assertIn('QPushButton#quietButton { background: #F7F4ED', stylesheet)
        self.assertIn('border: 1px solid #D5CEBF', stylesheet)
        self.assertIn('QTabBar::tab { background: transparent', stylesheet)
        self.assertIn('QTabWidget::pane { border: 0; background: transparent; }', stylesheet)
        self.assertIn('QPushButton#shellNav { min-height: 40px', self.window.styleSheet())
        self.assertEqual(game.refresh_profile_button.objectName(), 'quietButton')
        self.assertEqual(game.stop_move_button.objectName(), 'quietButton')
        account_button = next(button for button in self.window.findChildren(QPushButton)
                              if button.text() == '账号连接')
        self.assertEqual(account_button.objectName(), 'quietButton')

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
        self.assertEqual(game.backpack_table.item(0, 0).foreground().color().name(), '#7b3fa1')
        self.assertEqual(game.backpack_table.item(0, 2).text(), '史诗')
        game.update_social_inventory()
        self.assertEqual(game.social_inventory_table.item(0, 0).foreground().color().name(), '#7b3fa1')
        self.assertEqual(game.social_inventory_table.item(0, 5).text(), '背包')

        game.api_equipment = {'items': [
            {'itemCode': 'STARTER_SHOES', 'slotType': 'SHOES',
             'qualityCode': 'L1', 'equipmentLevel': 1, 'equipped': False},
        ]}
        game.update_social_inventory()
        self.assertEqual(game.social_inventory_table.item(0, 0).text(), '皮革靴')

    def test_dashboard_labels_wait_for_real_profile_without_duplicate_placeholder(self):
        self.window.tabs.setCurrentIndex(1)
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
        self.window.tabs.setCurrentIndex(1)
        game = self.window.game
        tabs = next(tab for tab in self.window.findChildren(QTabWidget)
                    if [tab.tabText(i) for i in range(tab.count())][:2] == ["任务", "怪物"])
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
        self.assertGreaterEqual(len(ITEM_NAMES_ZH), 98)
        self.assertEqual(localized_item_name({'itemCode': 'armor-p6'}), '王者战甲')
        self.assertEqual(localized_item_name({'itemCode': 'HEALTH_POTION'}), '生命药水')
        self.assertEqual(localized_item_name({'itemCode': 'STARTER_AMULET'}), '兽牙护符')
        self.assertEqual(localized_item_name({'nameEn': 'STARTER_ARMOR'}), '皮革衣')
        self.assertEqual(localized_item_name({'itemCode': 'BOWP1'}), '木弓')
        self.assertEqual(localized_item_name({'itemCode': 'TREASURE_STONE'}), '秘宝之石')
        self.assertNotIn('', ITEM_NAMES_ZH)
        self.assertEqual(localized_item_name({'nameEn': 'Unmapped Blade', 'slotType': 'WEAPON'}), '未收录武器')

    def test_compact_dashboard_exposes_potion_toggle_and_combat_feed(self):
        self.window.tabs.setCurrentIndex(1)
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

    def test_lark_card_includes_character_name_and_quality_color_template(self):
        game = self.window.game
        previous_settings = game.settings
        temporary_settings = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_settings.cleanup)
        self.addCleanup(setattr, game, 'settings', previous_settings)
        game.settings = QSettings(str(Path(temporary_settings.name) / 'settings.ini'),
                                  QSettings.Format.IniFormat)
        game.lark_webhook.setText('https://open.larksuite.com/open-apis/bot/v2/hook/test-secret')
        game.character_facts['角色'].setText('冰霜勇士')

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return b'{"code":0}'

        class ImmediateThread:
            def __init__(self, target, daemon=True):
                self.target = target

            def start(self):
                self.target()

        with patch('game_client.wss_tester.urllib.request.urlopen', return_value=Response()) as urlopen, \
             patch('game_client.wss_tester.threading.Thread', side_effect=ImmediateThread):
            game.send_lark_notification('装备掉落', '传说装备', 'red', 'equipment')

        payload = json.loads(urlopen.call_args.args[0].data)
        self.assertEqual(payload['card']['header']['template'], 'red')
        self.assertIn('冰霜勇士', payload['card']['header']['title']['content'])

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
                                    'qualityCode': 'L4', 'quality': 'COMMON',
                                    'equipmentLevel': 1, 'attributes': []}]}
            game.notify_new_equipment(equipment)  # Initial inventory is only a baseline.
            self.assertEqual(notify.call_count, 1)
            game.notify_new_equipment({'items': [*equipment['items'], {
                'playerItemId': 'drop-2', 'itemKind': 'EQUIPMENT', 'itemName': '新护甲',
                'slotType': 'ARMOR', 'attributes': []}]})
            self.assertEqual(notify.call_count, 2)
            self.assertEqual(notify.call_args.args[0], '装备掉落')
            self.assertIn('新护甲', notify.call_args.args[1])
            self.assertEqual(notify.call_args.args[2], 'green')

            game.notify_new_equipment({'items': [*equipment['items'], {
                'playerItemId': 'drop-3', 'itemKind': 'EQUIPMENT', 'itemName': '传说枪',
                'slotType': 'WEAPON', 'qualityCode': 'L4', 'quality': 'COMMON',
                'equipmentLevel': 1, 'attributes': [],
            }]})
            self.assertEqual(notify.call_args.args[2], 'red')
            self.assertIn('品质：传说', notify.call_args.args[1])

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
        with patch.object(game, 'request_map_path') as request_path:
            game.start_patrol()
        request_path.assert_called_once()
        self.assertEqual(request_path.call_args.args[0], 2)
        self.assertEqual(request_path.call_args.args[3], 'patrol')
        self.assertGreater(request_path.call_args.args[2][0], 7000)
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
        with patch.object(game, 'get_session_token', return_value='test-listing-session'):
            game.sell_item_button.click()
        self.assertEqual(calls[-1], ('marketListingSettings', '/shop/listing-settings'))
        self.assertTrue(game._listing_dialog.isVisible())
        game._listing_dialog.close()

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

    def test_backpack_selection_and_dialog_fit_windows_screens(self):
        game = self.window.game
        game.api_equipment = {'items': [
            {'playerItemId': 51, 'itemCode': 'SWORDP1', 'slotType': 'WEAPON',
             'qualityCode': 'L2', 'attack': 6, 'equipped': False},
        ]}
        game.refresh_profile_data = lambda **kwargs: None
        game.open_backpack()
        self.app.processEvents()
        style = game.backpack_table.styleSheet()
        self.assertIn('QTableWidget::item:selected', style)
        self.assertIn('#293C2B', style)
        self.assertGreaterEqual(game.backpack_table.rowHeight(0), 48)
        self.assertGreaterEqual(game.backpack_dialog.width(), game.backpack_dialog.minimumWidth())
        game.backpack_table.selectRow(0)
        self.assertEqual(game.backpack_table.currentRow(), 0)

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
        self.assertEqual(equipment_attribute_lines({
            'attributes': [{'code': 'ATTACK', 'value': 8}], 'luck': 2.5
        }), ['攻击 +8', '幸运 +2.5%'])

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
        self.assertEqual(set(game.monsters_on_current_map()), {'map-1-monster'})

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
        self.assertEqual(set(game.monsters_on_current_map()), {'map-2-monster'})
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
        game.monster_level_limited.setChecked(False)
        game.next_attack = {}

        with patch.object(game, 'request_map_path') as request_path:
            game.auto_attack_tick()
            request_path.assert_called_once()
        game._pending_path_request = {
            'id': 1, 'kind': 'patrol', 'context': {'map': 2, 'row': 1, 'row_count': 25}}
        game.on_map_path_ready(1, [(3872, 7168)], None)
        self.assertTrue(game.patrol_timer.isActive())
        self.assertEqual(game.patrol_route, [(3872, 7168)])

        game.monsters = {'new-monster': {
            'encounterId': 'new-monster', 'mapId': 2, 'x': 3872,
            'y': 7488, 'health': 100, 'level': 1, 'monsterRank': 'NORMAL',
        }}
        game.auto_attack_tick()
        self.assertFalse(game.patrol_timer.isActive())
        self.assertIn('等待服务端攻击票据', game.combat_status.text())
        game.stop_patrol(reset_anchor=True)
        game.combat_timer.stop()
        game.ws = None

    def test_auto_combat_patrols_outside_town_without_monsters(self):
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
                if map_id == 1:
                    self.assertFalse(game.patrol_timer.isActive())
                    self.assertFalse(game.patrol_route)
                else:
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

    def test_reconnect_world_ready_resumes_enabled_auto_combat(self):
        game = self.window.game
        game.auto_attack.setChecked(True)
        game.current_map = 2
        game.world_ready = False
        game.ws = object()
        with (patch.object(game, 'send_stationary_sync'),
              patch.object(game, 'refresh_social_data')):
            game.accept_packet({'type': 'snapshot', 'self': {}, 'monsters': []})
        self.assertTrue(game.auto_attack.isChecked())
        self.assertTrue(game.combat_timer.isActive())
        game.ws = None
        game.combat_timer.stop()
        game.keepalive.stop()
        game.telemetry_timer.stop()
        game.position_sync_timer.stop()

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
        self.assertEqual(image.pixelColor(20, 20).name(), '#faf8f3')

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

    def prepare_fishing_account(self):
        game = self.window.game
        game.world_ready = True
        game.current_map = 1
        game.world_x = game.world_y = 100
        game.ws = Mock()
        game.api_equipment = {'items': [{'playerItemId': 42, 'itemCode': 'WOODEN_FISHING_ROD'}]}
        self.addCleanup(lambda: setattr(game, 'ws', None))
        return game

    def test_fishing_waits_for_result_and_fresh_inventory(self):
        game = self.prepare_fishing_account()
        with patch.object(game, 'send_game_packet') as send, patch.object(game, 'request_social_api') as api, patch.object(game, 'refresh_profile_data'):
            self.assertTrue(game.request_activity('useFishingRod'))
            game.accept_packet({'type': 'welcome', 'position': {'map': 1, 'x': 200, 'y': 200}})
            self.assertTrue(game.fishing_busy())
            game.accept_packet({'type': 'fishing_started', 'durationMs': 3000})
            self.assertTrue(game._fishing_active)
            self.assertFalse(game.request_activity('useFishingRod'))
            send.reset_mock()
            game.attack_monster('anything')
            game.move_to_coordinate(500, 500)
            game.travel_to(2)
            game.auto_attack.setChecked(True)
            self.assertFalse(game.auto_attack.isChecked())
            send.assert_not_called()
            game.accept_packet({'type': 'fishing_result', 'outcome': 'EXPERIENCE', 'experience': 2500})
            self.assertIn('2500', game.activity_status.text())
            self.assertTrue(game.fishing_busy())
            api.assert_called_with('fishingInventory', '/equipment')
            game.accept_profile_data({'socialApiKey': 'fishingInventory', 'socialApiResult': {'items': []}})
            self.assertFalse(game.fishing_busy())
            self.assertIsNone(game.fishing_rod())
            self.assertFalse(game.activity_buttons['useFishingRod'].isEnabled())

    def test_fishing_timeout_does_not_unlock_or_resend_consumption(self):
        import time
        game = self.prepare_fishing_account()
        with patch.object(game, 'send_game_packet') as send:
            self.assertTrue(game.request_activity('useFishingRod'))
            game._activity_pending = ('useFishingRod', time.monotonic() - 20)
            game.update_activity_controls()
            self.assertTrue(game._activity_uncertain)
            self.assertFalse(game.request_activity('useFishingRod'))
            self.assertEqual(sum(call.args[0].get('action') == 'useFishingRod' for call in send.call_args_list), 1)

    def test_fishing_inventory_error_keeps_lock_and_stale_result_is_ignored(self):
        game = self.prepare_fishing_account()
        game._fishing_inventory_pending = True
        game._api_request_ids['fishingInventory'] = 2
        game.accept_profile_data({'socialApiKey': 'fishingInventory', 'socialApiRequestId': 1,
                                  'socialApiResult': {'items': []}})
        self.assertTrue(game.fishing_busy())
        game.accept_profile_data({'socialApiKey': 'fishingInventory', 'socialApiRequestId': 2,
                                  'socialApiError': 'timeout'})
        self.assertTrue(game.fishing_busy())

    def test_boss_pass_has_independent_expiry_and_no_ticket_consumption(self):
        import time
        game = self.prepare_fishing_account()
        game.use_ticket.setChecked(False)
        game.accept_activity_resources({'bossExpiresAt': 3601000, 'treasureExpiresAt': 1000}, 1000)
        self.assertTrue(game.boss_entry_allowed())
        self.assertGreater(game._boss_access_until, time.monotonic() + 3590)
        self.assertLessEqual(game._treasure_access_until, time.monotonic())
        with patch.object(game, 'send_game_packet') as send:
            self.assertTrue(game.request_activity('enterBossMap'))
            self.assertEqual(send.call_args.args[0], {'action': 'enterBossMap'})

    def test_boss_rewards_ignore_expired_and_duplicate_notifications(self):
        import time
        game = self.window.game
        packet = {'type': 'boss_token_reward', 'rewardKey': 'example-reward', 'monsterKey': 'troll',
                  'amount': '1.25', 'expiresAt': (time.time() + 60) * 1000}
        with patch.object(game, 'append_log') as log:
            game.accept_packet(packet)
            game.accept_packet(packet)
            game.accept_packet(dict(packet, rewardKey='expired', expiresAt=1))
            self.assertEqual(log.call_count, 1)

    def test_fishpond_redeem_requires_confirmation_and_blocks_duplicate_item(self):
        game = self.prepare_fishing_account()
        game.api_equipment = {'items': [{'playerItemId': 77, 'itemCode': 'FISHPOND_NFT'}]}
        with patch('wss_tester.QInputDialog.getItem', return_value=('FishPond NFT · 道具 ID 77', True)), patch('wss_tester.QMessageBox.question', return_value=QMessageBox.StandardButton.Yes), patch.object(game, 'request_social_api') as api, patch.object(game, 'refresh_profile_data'):
            game.redeem_fishpond()
            api.assert_called_once_with('fishpondRedeem', '/equipment/fishpond/redeem', 'POST',
                                       {'playerItemId': 77, 'confirmed': True})
            game.accept_profile_data({'socialApiKey': 'fishpondRedeem', 'socialApiError': 'timeout'})
            game.redeem_fishpond()
            self.assertEqual(api.call_count, 1)

    def test_new_maps_use_worker_navigation_and_have_routes(self):
        from wss_tester import MAP_ROUTES, PORTAL_CENTERS
        game = self.prepare_fishing_account()
        for source, target in ((6, 8), (4, 9), (2, 10)):
            self.assertIn(target, MAP_ROUTES[source])
            self.assertIn(source, MAP_ROUTES[target])
            self.assertEqual(PORTAL_CENTERS[(target, source)], (3232, 6240))
        game.current_map = 8
        with patch.object(game, 'request_map_path') as route:
            self.assertTrue(game.move_to_coordinate(3232, 5984))
            self.assertEqual(route.call_args.args[0], 8)

    def test_batch_start_skips_fishing_without_changing_automation(self):
        game = self.prepare_fishing_account()
        game._fishing_active = True
        game.status.setText('已连接')
        self.window._game_sessions = {'test-account': game}
        selected = QCheckBox()
        selected.setChecked(True)
        self.window.planner_account_checks = {'test-account': selected}
        game.auto_quest.setChecked(False)
        with patch.object(game, 'accept_next_monster_quest') as quest:
            self.window.start_multi_account_plan()
            quest.assert_not_called()
        self.assertFalse(game.auto_quest.isChecked())
        self.assertIn('钓鱼', self.window.planner_status.text())

    def prepare_listing(self):
        game = self.window.game
        game.token.setText('test-listing-session')
        game.signed_session_token = 'test-listing-session'
        item = {'playerItemId': 61, 'itemCode': 'SWORDP1', 'slotType': 'WEAPON', 'equipped': True}
        game.api_equipment = {'items': [item]}
        game.update_social_inventory()
        game.social_inventory_table.selectRow(0)
        return game

    def quote_listing(self, game):
        game.open_item_listing()
        dialog = game._listing_dialog
        game.accept_profile_data({'socialApiKey': 'marketListingSettings', 'socialApiResult': {'minimumPrice': '100'}})
        dialog.price.setText('100')
        dialog.delay.stop()
        dialog.fetch_quote()
        game.accept_profile_data({'socialApiKey': 'marketListingQuote', 'socialApiResult':
                                  {'price': '100', 'feePercent': '10', 'feeAmount': '10', 'sellerAmount': '90'}})
        return dialog

    def test_listing_quote_and_confirm_submit_owned_equipment_once(self):
        game = self.prepare_listing()
        with patch.object(game, 'request_social_api') as api, patch.object(game, 'refresh_profile_data'):
            dialog = self.quote_listing(game)
            self.assertTrue(dialog.confirm.isEnabled())
            self.assertIn('90', dialog.totals.text())
            dialog.submit()
            api.assert_called_with('marketListingSubmit', '/shop/list', 'POST',
                                   {'playerItemId': 61, 'price': '100', 'feePercent': '10'})
            count = api.call_count
            dialog.submit()
            dialog.close()
            self.assertTrue(dialog.isVisible())
            self.assertEqual(api.call_count, count)
            game.accept_profile_data({'socialApiKey': 'marketListingSubmit', 'socialApiStatus': 200,
                                      'socialApiResult': {'ok': True}})
            self.assertTrue(dialog.completed)
            self.assertEqual(game.api_equipment['items'], [])
            self.assertFalse(game._listing_submit_pending)
            dialog.close()

    def test_listing_price_change_invalidates_quote_and_ignores_old_response(self):
        game = self.prepare_listing()
        with patch.object(game, 'request_social_api') as api:
            dialog = self.quote_listing(game)
            dialog.price.setText('200')
            dialog.delay.stop()
            game.accept_profile_data({'socialApiKey': 'marketListingQuote', 'socialApiResult':
                                      {'price': '100', 'feePercent': '10', 'feeAmount': '10', 'sellerAmount': '90'}})
            self.assertFalse(dialog.confirm.isEnabled())
            api.reset_mock()
            dialog.submit()
            api.assert_not_called()
            dialog.close()

    def test_listing_timeout_stays_blocked_across_reopen(self):
        game = self.prepare_listing()
        with patch.object(game, 'request_social_api') as api, patch.object(game, 'refresh_profile_data'):
            dialog = self.quote_listing(game)
            dialog.submit()
            game.accept_profile_data({'socialApiKey': 'marketListingSubmit', 'socialApiError': 'timeout'})
            self.assertTrue(dialog.uncertain)
            self.assertIn(('item', '61'), game._listing_blocked)
            count = api.call_count
            dialog.submit()
            dialog.close()
            game.open_item_listing()
            self.assertEqual(api.call_count, count)

    def test_listing_checks_current_inventory_again_before_submit(self):
        game = self.prepare_listing()
        with patch.object(game, 'request_social_api') as api:
            dialog = self.quote_listing(game)
            game.api_equipment = {'items': []}
            api.reset_mock()
            dialog.submit()
            api.assert_not_called()
            self.assertIn('当前库存', dialog.message.text())
            dialog.close()

    def test_listing_does_not_submit_after_account_session_changes(self):
        game = self.prepare_listing()
        with patch.object(game, 'request_social_api') as api:
            dialog = self.quote_listing(game)
            game._login_generation += 1
            api.reset_mock()
            dialog.submit()
            api.assert_not_called()
            dialog.close()


if __name__ == '__main__':
    unittest.main()
