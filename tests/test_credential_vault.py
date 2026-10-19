import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'game_client'))
from credential_vault import CredentialVault


class CredentialVaultTests(unittest.TestCase):
    def test_three_encrypted_shards_reassemble_only_with_master_password(self):
        with tempfile.TemporaryDirectory() as temporary:
            vault = CredentialVault(Path(temporary) / 'vault')
            wallet_secret = '0x' + 'ab' * 32
            master_password = 'test-only-master-password-42'

            vault.store(wallet_secret, master_password)

            self.assertEqual(len(vault.shard_paths), 3)
            self.assertTrue(vault.exists())
            self.assertTrue(all(path.stat().st_size > 0 for path in vault.shard_paths))
            self.assertTrue(all(wallet_secret.encode() not in path.read_bytes()
                                for path in vault.shard_paths))
            self.assertEqual(vault.load(master_password), wallet_secret)
            with self.assertRaisesRegex(ValueError, '主密码错误'):
                vault.load('incorrect-master-password')

            vault.shard_paths[0].unlink()
            with self.assertRaisesRegex(FileNotFoundError, '分片不完整'):
                vault.load(master_password)

    def test_delete_removes_all_shards(self):
        with tempfile.TemporaryDirectory() as temporary:
            vault = CredentialVault(Path(temporary) / 'vault')
            vault.store('private-test-value', 'another-test-master-password')
            vault.delete()
            self.assertFalse(vault.exists())
            self.assertTrue(all(not path.exists() for path in vault.shard_paths))


if __name__ == '__main__':
    unittest.main()
