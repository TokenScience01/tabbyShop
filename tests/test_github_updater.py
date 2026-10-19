import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import github_updater as updater


class GitHubUpdaterTests(unittest.TestCase):
    def test_version_comparison_handles_release_prefix(self):
        self.assertEqual(updater.version_tuple('v2.10.3'), (2, 10, 3, 0))
        self.assertGreater(updater.version_tuple('1.2.10'), updater.version_tuple('1.2.9'))
        self.assertEqual(updater.version_tuple('1.2'), updater.version_tuple('1.2.0'))

    def test_latest_release_identifies_newer_version_and_windows_asset(self):
        response = {
            'tag_name': 'v9.8.7',
            'assets': [
                {'name': updater.ASSET_NAME, 'browser_download_url': 'https://example.test/app.zip'},
                {'name': 'source.zip', 'browser_download_url': 'https://example.test/source.zip'},
            ],
        }

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        with patch.object(updater.urllib.request, 'urlopen', return_value=FakeResponse()), \
             patch.object(updater, 'json') as json_module:
            json_module.load.return_value = response
            latest = updater.fetch_latest_release()

        self.assertEqual(latest['version'], '9.8.7')
        self.assertTrue(latest['is_newer'])
        self.assertEqual(latest['asset']['name'], updater.ASSET_NAME)

    def test_missing_latest_release_returns_friendly_empty_state(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        not_found = HTTPError(updater.RELEASES_API, 404, 'Not Found', {}, None)
        with patch.object(updater.urllib.request, 'urlopen',
                          side_effect=[not_found, FakeResponse()]), \
             patch.object(updater, 'json') as json_module:
            json_module.load.return_value = []
            result = updater.fetch_latest_release()

        self.assertTrue(result['no_release'])
        self.assertFalse(result['is_newer'])

    def test_github_cli_token_is_only_added_to_request_headers(self):
        completed = type('Result', (), {'stdout': 'gh-secret-token\n'})()
        with patch.dict('os.environ', {}, clear=True), \
             patch.object(updater.shutil, 'which', return_value='/usr/bin/gh'), \
             patch.object(updater.subprocess, 'run', return_value=completed):
            headers = updater.github_headers()

        self.assertEqual(headers['Authorization'], 'Bearer gh-secret-token')
        self.assertNotIn('gh-secret-token', str(updater.__dict__))


if __name__ == '__main__':
    unittest.main()
