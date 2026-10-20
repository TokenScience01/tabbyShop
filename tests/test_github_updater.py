import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

import github_updater as updater


class GitHubUpdaterTests(unittest.TestCase):
    def test_version_comparison_handles_release_prefix(self):
        self.assertEqual(updater.version_tuple('v2.10.3'), (2, 10, 3, 0))
        self.assertGreater(updater.version_tuple('1.2.10'), updater.version_tuple('1.2.9'))
        self.assertEqual(updater.version_tuple('1.2'), updater.version_tuple('1.2.0'))
        self.assertEqual(updater.APP_VERSION, '1.2.16')

    def test_update_script_logs_failures_and_restores_previous_install(self):
        install_dir = Path('C:/Users/test/App/TabbyDesktop')
        stage = install_dir.parent / '.tabby-update-test'
        script = updater._windows_update_script(
            stage, stage / 'TabbyDesktop', install_dir,
            install_dir.with_name('TabbyDesktop.previous'), 1234)

        self.assertIn('move "%STAGED%" "%TARGET%"', script)
        self.assertIn('goto rollback', script)
        self.assertIn('move "%BACKUP%" "%TARGET%"', script)
        self.assertIn('update.log', script)
        self.assertIn('start "" "%EXE%"', script)
        self.assertIn('set "APP_PID=1234"', script)
        self.assertIn('set /a WAITED=0', script)
        self.assertIn('if %WAITED% GEQ 300 goto failed', script)
        self.assertIn('findstr /R /C:"[ ]%APP_PID%[ ]"', script)
        self.assertIn('Application exited; replacing files.', script)
        self.assertIn('Updated application launched successfully.', script)

    def test_update_launcher_quotes_script_paths_for_cmd_with_spaces(self):
        class WindowsScriptPath:
            def resolve(self):
                return Path(r'C:\Program Files\Tabby\.tabby-update\install-update.bat')

        with patch.object(updater.os, 'name', 'nt'), \
             patch.dict('os.environ', {'COMSPEC': r'C:\Windows\System32\cmd.exe'}), \
             patch.object(updater.subprocess, 'Popen') as popen:
            updater.launch_update_script(WindowsScriptPath())

        command = popen.call_args.args[0]
        self.assertEqual(command[:3], [r'C:\Windows\System32\cmd.exe', '/d', '/c'])
        self.assertEqual(command[3], r'"C:\Program Files\Tabby\.tabby-update\install-update.bat"')
        self.assertIsInstance(command, list)

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

    def test_private_release_download_uses_authenticated_asset_api(self):
        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, 'w') as archive:
            archive.writestr('TabbyDesktop/TabbyDesktop.exe', b'test')
        response = io.BytesIO(archive_buffer.getvalue())
        asset = {
            'url': 'https://api.github.com/repos/TokenScience01/tabbyShop/releases/assets/123',
            'browser_download_url': 'https://github.com/TokenScience01/tabbyShop/releases/download/v1/test.zip',
        }

        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(updater, 'github_headers', return_value={
                 'Authorization': 'Bearer test-read-token',
                 'Accept': 'application/vnd.github+json',
             }), \
             patch.object(updater.urllib.request, 'urlopen', return_value=response) as urlopen:
            destination = Path(temporary) / 'update.zip'
            updater.download_asset(asset, destination)
            request = urlopen.call_args.args[0]
            self.assertEqual(request.full_url, asset['url'])
            self.assertEqual(request.get_header('Accept'), 'application/octet-stream')
            self.assertEqual(request.get_header('Authorization'), 'Bearer test-read-token')
            self.assertTrue(zipfile.is_zipfile(destination))


if __name__ == '__main__':
    unittest.main()
