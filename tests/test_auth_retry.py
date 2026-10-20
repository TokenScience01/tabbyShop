"""Focused tests for retry timing returned by the wallet-login API."""
import unittest
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "game_client"))
from wss_tester import challenge_retry_delay


class ChallengeRetryTests(unittest.TestCase):
    def test_uses_retry_after_seconds_and_bounds_excessive_values(self):
        self.assertEqual(challenge_retry_delay({}, 0, "3"), 3.0)
        self.assertEqual(challenge_retry_delay({}, 0, "120"), 15.0)

    def test_uses_retry_after_milliseconds_from_application_response(self):
        self.assertEqual(challenge_retry_delay({"retryAfterMs": 2400}, 3), 2.4)
        self.assertEqual(challenge_retry_delay({"retryAfter": 4}, 0), 4.0)

    def test_uses_http_date_when_retry_after_is_not_numeric(self):
        target = datetime.now(timezone.utc) + timedelta(seconds=5)
        delay = challenge_retry_delay({}, 0, format_datetime(target, usegmt=True))
        self.assertGreaterEqual(delay, 0.5)
        self.assertLessEqual(delay, 5.1)

    def test_falls_back_to_exponential_backoff_and_never_returns_zero(self):
        self.assertEqual(challenge_retry_delay({}, 0), 1.0)
        self.assertEqual(challenge_retry_delay({}, 3), 8.0)
        self.assertEqual(challenge_retry_delay({"retryAfterMs": 0}, 0), 0.5)


if __name__ == "__main__":
    unittest.main()
