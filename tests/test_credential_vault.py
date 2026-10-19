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

    def test_multiple_wallets_are_saved_as_independent_encrypted_shard_sets(self):
        with tempfile.TemporaryDirectory() as temporary:
            vault = CredentialVault(Path(temporary) / 'vault')
            first = '0x' + '1' * 40
            second = '0x' + '2' * 40
            password = 'shared-test-master-password'
            vault.store_wallet('private-key-one', password, first)
            vault.store_wallet('private-key-two', password, second)
            self.assertEqual({address.lower() for address in vault.list_wallets()},
                             {first.lower(), second.lower()})
            self.assertEqual(vault.load_wallet(password, first), 'private-key-one')
            self.assertEqual(vault.load_wallet(password, second), 'private-key-two')
            self.assertFalse(any(b'private-key-' in path.read_bytes()
                                 for address in vault.list_wallets()
                                 for path in vault.wallet_vault(address).shard_paths))
            vault.delete_wallet(first)
            self.assertFalse(vault.exists(first))
            self.assertTrue(vault.exists(second))


if __name__ == '__main__':
    unittest.main()
