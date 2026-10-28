"""Monitor scheduling and scan isolation checks with no upstream or wallet access."""
import json
import os
import threading
import unittest
from unittest.mock import Mock, call, patch
from urllib.error import URLError

os.environ.setdefault("TABBY_SAFE_START", "1")
import server


class StopRun(BaseException):
    """Exit the otherwise perpetual worker without changing its error handling."""


class Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def read(self):
        return json.dumps(self.payload).encode()


def product(item_id=1, price=12):
    return {"id": item_id, "price": price, "qualityCode": "L3", "state": "ACTIVE", "market": True}


class ShopMonitorTests(unittest.TestCase):
    def setUp(self):
        with patch.object(server.ShopMonitor, "_load", return_value={}), \
                patch.object(threading.Thread, "start"):
            self.monitor = server.ShopMonitor()
        self.monitor._persist = Mock()
        self.monitor.enabled = True
        self.wallet_patch = patch.object(server, "wallet_address", return_value="")
        self.token_patch = patch.object(server, "read_token", return_value="Bearer mock-session")
        self.wallet_patch.start()
        self.token_patch.start()
        self.addCleanup(self.wallet_patch.stop)
        self.addCleanup(self.token_patch.stop)

    def test_interval_timeout_keeps_scanning_without_another_start_click(self):
        self.monitor.wake = Mock()
        self.monitor._scan_once = Mock(side_effect=[None, None, StopRun()])
        with self.assertRaises(StopRun):
            self.monitor._run()
        self.assertEqual(self.monitor._scan_once.call_count, 3)
        self.assertEqual(self.monitor.wake.wait.call_args_list, [call(5), call(5)])

    def test_disabled_monitor_waits_for_start_instead_of_busy_looping(self):
        self.monitor.enabled = False
        self.monitor.wake = Mock()
        self.monitor.wake.wait.side_effect = StopRun()
        self.monitor._scan_once = Mock()
        with self.assertRaises(StopRun):
            self.monitor._run()
        self.monitor._scan_once.assert_not_called()
        self.monitor.wake.wait.assert_called_once_with()

    def test_stop_during_scan_does_not_publish_old_products_or_buy(self):
        generation = self.monitor.generation
        self.monitor.auto_buy_enabled = True
        self.monitor._process_candidate = Mock()

        def delayed_response(*_args, **_kwargs):
            self.monitor.stop()
            return Response({"products": [product()]})

        with patch.object(server, "urlopen", side_effect=delayed_response):
            self.monitor._scan_once(dict(server.DEFAULT_CONFIG, concurrency=1), generation)
        self.assertEqual(self.monitor.products, [])
        self.assertEqual(self.monitor.scan_count, 0)
        self.assertEqual(self.monitor.status, "stopped")
        self.monitor._process_candidate.assert_not_called()

    def test_reconfigure_during_scan_discards_old_filter_results(self):
        generation = self.monitor.generation

        def delayed_response(*_args, **_kwargs):
            self.monitor.configure(dict(server.DEFAULT_CONFIG, qualities=["L4"]))
            return Response({"products": [product()]})

        with patch.object(server, "urlopen", side_effect=delayed_response):
            self.monitor._scan_once(dict(server.DEFAULT_CONFIG, concurrency=1), generation)
        self.assertEqual(self.monitor.config["qualities"], ["L4"])
        self.assertIsNone(self.monitor.candidate)
        self.assertEqual(self.monitor.revision, 0)

    def test_old_scan_error_cannot_override_new_start_state(self):
        self.monitor.wake = Mock()

        def stale_error(*_args):
            self.monitor.start(server.DEFAULT_CONFIG)
            raise URLError("old request failed")

        scans = 0

        def scan(*args):
            nonlocal scans
            scans += 1
            if scans > 1:
                raise StopRun()
            stale_error(*args)

        self.monitor._scan_once = Mock(side_effect=scan)
        with self.assertRaises(StopRun):
            self.monitor._run()
        self.assertEqual(self.monitor.status, "running")
        self.assertEqual(self.monitor.error, "")
        self.assertEqual(self.monitor.events, [])
        self.monitor.wake.wait.assert_not_called()

    def test_one_failed_parallel_request_does_not_discard_successful_products(self):
        with patch.object(server, "urlopen", side_effect=[URLError("temporary failure"), Response({"products": [product()]})]):
            self.monitor._scan_once(dict(server.DEFAULT_CONFIG, concurrency=2), self.monitor.generation)
        self.assertEqual(self.monitor.candidate["id"], 1)
        self.assertEqual(self.monitor.scan_count, 1)

    def test_all_failed_parallel_requests_report_error(self):
        with patch.object(server, "urlopen", side_effect=URLError("offline")):
            with self.assertRaises(URLError):
                self.monitor._scan_once(dict(server.DEFAULT_CONFIG, concurrency=2), self.monitor.generation)
        self.assertEqual(self.monitor.scan_count, 0)

    def test_malformed_product_rows_do_not_break_other_candidates(self):
        rows = [None, [], product("bad-id"), product(False), product(-1), product(float("inf")), product(3)]
        with patch.object(server, "urlopen", return_value=Response({"products": rows})):
            self.monitor._scan_once(dict(server.DEFAULT_CONFIG, concurrency=1), self.monitor.generation)
        self.assertEqual(self.monitor.candidate["id"], 3)

    def test_non_object_payload_has_clear_error(self):
        with patch.object(server, "urlopen", return_value=Response([])):
            with self.assertRaisesRegex(RuntimeError, "JSON 对象"):
                self.monitor._scan_once(dict(server.DEFAULT_CONFIG, concurrency=1), self.monitor.generation)

    def test_stale_candidate_is_rejected_before_marking_attempted_or_purchasing(self):
        with patch.object(server, "execute_purchase") as purchase:
            self.monitor._process_candidate(product(), server.DEFAULT_CONFIG, self.monitor.generation - 1)
        purchase.assert_not_called()
        self.assertEqual(self.monitor.attempted_products, set())

    def test_auth_change_discards_inflight_scan(self):
        with patch.object(server, "read_token", side_effect=["Bearer old", "Bearer new"]), \
                patch.object(server, "urlopen", return_value=Response({"products": [product()]})):
            self.monitor._scan_once(dict(server.DEFAULT_CONFIG, concurrency=1), self.monitor.generation)
        self.assertEqual(self.monitor.products, [])


if __name__ == "__main__":
    unittest.main()
