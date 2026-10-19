"""Passphrase-encrypted, three-part storage for a local wallet credential.

The XOR shares are a storage-fragmentation layer, not a substitute for the
passphrase. AES-GCM protects the credential if all fragments are copied.
"""
from __future__ import annotations

import base64
import os
import secrets
import shutil
import sys
import tempfile
import re
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


_MAGIC = b"TBYV1"
_AAD = b"Tabby Desktop wallet credential v1"
_SALT_SIZE = 16
_NONCE_SIZE = 12
_KEY_SIZE = 32
_KDF_ROUNDS = 900_000
_SHARD_COUNT = 3


def default_vault_directory() -> Path:
    """Return a per-user app-data directory; never use the install folder."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return base / "TabbyDesktop" / "credential-vault"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "TabbyDesktop" / "credential-vault"
    base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "tabby-desktop" / "credential-vault"


class CredentialVault:
    """Store one UTF-8 secret encrypted by a user-entered master passphrase."""

    def __init__(self, directory: Path | str | None = None) -> None:
        self.directory = Path(directory) if directory is not None else default_vault_directory()

    @property
    def shard_paths(self) -> tuple[Path, Path, Path]:
        return tuple(self.directory / f"wallet.part{index}" for index in range(1, 4))

    @staticmethod
    def _wallet_component(address: str) -> str:
        value = str(address or "").strip()
        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
            raise ValueError("钱包地址格式无效")
        return value.lower()

    def wallet_vault(self, address: str) -> "CredentialVault":
        return CredentialVault(self.directory / "wallets" / self._wallet_component(address))

    def exists(self, address: str | None = None) -> bool:
        if address:
            return all(path.is_file() for path in self.wallet_vault(address).shard_paths)
        if all(path.is_file() for path in self.shard_paths):
            return True
        return bool(self.list_wallets())

    def list_wallets(self) -> list[str]:
        wallet_root = self.directory / "wallets"
        if not wallet_root.is_dir():
            return []
        addresses = []
        for entry in wallet_root.iterdir():
            address_file = entry / "address.txt"
            if not entry.is_dir() or not address_file.is_file():
                continue
            try:
                address = address_file.read_text(encoding="ascii").strip()
                self._wallet_component(address)
                if entry.name.lower() != address.lower():
                    continue
                if all(path.is_file() for path in CredentialVault(entry).shard_paths):
                    addresses.append(address)
            except (OSError, ValueError, UnicodeError):
                continue
        return sorted(addresses, key=str.lower)

    def store_wallet(self, secret: str, passphrase: str, address: str) -> None:
        normalized = self._wallet_component(address)
        vault = self.wallet_vault(normalized)
        vault.store(secret, passphrase)
        address_file = vault.directory / "address.txt"
        address_file.write_text(address, encoding="ascii")
        if os.name != "nt":
            address_file.chmod(0o600)

    def load_wallet(self, passphrase: str, address: str) -> str:
        return self.wallet_vault(address).load(passphrase)

    def delete_wallet(self, address: str) -> None:
        shutil.rmtree(self.wallet_vault(address).directory, ignore_errors=True)

    @staticmethod
    def _derive_key(passphrase: str, salt: bytes) -> bytes:
        if not passphrase:
            raise ValueError("主密码不能为空")
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=_KEY_SIZE,
                         salt=salt, iterations=_KDF_ROUNDS)
        return kdf.derive(passphrase.encode("utf-8"))

    @staticmethod
    def _split(payload: bytes) -> tuple[bytes, bytes, bytes]:
        left = secrets.token_bytes(len(payload))
        middle = secrets.token_bytes(len(payload))
        right = bytes(a ^ b ^ c for a, b, c in zip(payload, left, middle))
        return left, middle, right

    @staticmethod
    def _join(shards: tuple[bytes, bytes, bytes]) -> bytes:
        if len({len(part) for part in shards}) != 1:
            raise ValueError("私钥分片长度不一致")
        return bytes(a ^ b ^ c for a, b, c in zip(*shards))

    def store(self, secret: str, passphrase: str) -> None:
        if not secret:
            raise ValueError("私钥不能为空")
        salt = secrets.token_bytes(_SALT_SIZE)
        nonce = secrets.token_bytes(_NONCE_SIZE)
        key = self._derive_key(passphrase, salt)
        ciphertext = AESGCM(key).encrypt(nonce, secret.encode("utf-8"), _AAD)
        payload = _MAGIC + salt + nonce + ciphertext
        shards = self._split(payload)

        parent = self.directory.parent
        parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=".vault-write-", dir=parent))
        if os.name != "nt":
            staging.chmod(0o700)
        backup = parent / f".vault-old-{secrets.token_hex(8)}"
        moved_old = False
        try:
            for path, shard in zip(self.shard_paths, shards):
                staged = staging / path.name
                staged.write_bytes(base64.b64encode(shard))
                if os.name != "nt":
                    staged.chmod(0o600)
            if self.directory.exists():
                os.replace(self.directory, backup)
                moved_old = True
            os.replace(staging, self.directory)
            # Read back and authenticate before reporting success.
            if self.load(passphrase) != secret:
                raise RuntimeError("分片保存后校验失败")
        except Exception:
            if self.directory.exists():
                shutil.rmtree(self.directory, ignore_errors=True)
            if moved_old and backup.exists():
                os.replace(backup, self.directory)
            raise
        finally:
            shutil.rmtree(staging, ignore_errors=True)
            shutil.rmtree(backup, ignore_errors=True)

    def load(self, passphrase: str) -> str:
        paths = self.shard_paths
        if not all(path.is_file() for path in paths):
            raise FileNotFoundError("私钥分片不完整")
        try:
            shards = tuple(base64.b64decode(path.read_bytes(), validate=True) for path in paths)
            payload = self._join(shards)
            header_size = len(_MAGIC) + _SALT_SIZE + _NONCE_SIZE
            if len(payload) <= header_size or not payload.startswith(_MAGIC):
                raise ValueError("私钥分片格式无效")
            offset = len(_MAGIC)
            salt = payload[offset:offset + _SALT_SIZE]
            offset += _SALT_SIZE
            nonce = payload[offset:offset + _NONCE_SIZE]
            offset += _NONCE_SIZE
            key = self._derive_key(passphrase, salt)
            plaintext = AESGCM(key).decrypt(nonce, payload[offset:], _AAD)
            return plaintext.decode("utf-8")
        except FileNotFoundError:
            raise
        except Exception as exc:
            raise ValueError("主密码错误或私钥分片损坏") from exc

    def delete(self) -> None:
        shutil.rmtree(self.directory / "wallets", ignore_errors=True)
        for path in self.shard_paths:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        try:
            self.directory.rmdir()
        except OSError:
            pass
