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
from PySide6.QtWidgets import QApplication, QLabel, QTableWidget
from PySide6.QtCore import QEventLoop, QTimer
from desktop import DesktopWindow, shop
from game_client.wss_tester import QUALITY_NAMES_ZH, quality_color


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
                         ['#f2f2ef', '#63adff', '#c487ff', '#f2c45f'])
        self.assertEqual(QUALITY_NAMES_ZH['L4'], '传说')

        game = self.window.game
        game.current_map = 4
        game.update_map_buttons()
        self.assertIn('西部荒野', game.current_map_label.text())
        self.assertTrue(game.map_buttons[4].property('currentMap'))

        game.api_equipment = {'items': [
            {'itemCode': 'SWORDP1', 'slotType': 'WEAPON', 'qualityCode': 'L3', 'equipped': False},
        ]}
        game.backpack_table = QTableWidget(0, 4)
        game.backpack_status = QLabel()
        game.update_backpack()
        self.assertEqual(game.backpack_table.item(0, 0).foreground().color().name(), '#c487ff')
        self.assertEqual(game.backpack_table.item(0, 2).text(), '史诗')


if __name__ == '__main__':
    unittest.main()
