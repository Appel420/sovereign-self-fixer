import os
import json
import time
import logging
import asyncio
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .encryption import CodeCryptor
from .tpm import TPMManager

class TamperHardLock:
    def __init__(self, code_file: str = "state.code"):
        self.code_file = Path(code_file)
        self.chain_file = self.code_file.with_suffix(".chain")
        self.cryptor = CodeCryptor()
        self.tpm = TPMManager()
        self.private_key = self._load_or_create_key()
        self.public_key = self.private_key.public_key()

    def _load_or_create_key(self):
        key_path = Path(".sovereign_key")
        if key_path.exists():
            with open(key_path, "rb") as f:
                return serialization.load_pem_private_key(f.read(), password=None)
        key = Ed25519PrivateKey.generate()
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
        return key

    async def update_chain(self, content: str):
        timestamp = int(time.time())
        entry = {
            "timestamp": timestamp,
            "content_hash": self._hash(content),
            "signature": self._sign(content).hex()
        }
        with open(self.chain_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
        if self.tpm and await self.tpm.is_tpm_present():
            try:
                await self.tpm.store_hash_chain_in_nv(json.dumps(entry))
            except Exception as e:
                logging.warning(f"Failed to update TPM NV Index: {e}")

    def is_valid(self, content: str) -> bool:
        if not self.chain_file.exists():
            return True
        try:
            with open(self.chain_file, "r") as f:
                for line in f:
                    entry = json.loads(line.strip())
                    if entry["content_hash"] != self._hash(content):
                        return False
            return True
        except Exception:
            return False

    async def seal_state_to_tpm(self, content: str):
        if not self.tpm or not await self.tpm.is_tpm_present():
            return None
        return await self.tpm.seal_with_pcr_policy(content.encode())

    async def unseal_state_from_tpm(self, sealed_blob: bytes):
        if not self.tpm or not await self.tpm.is_tpm_present():
            return None
        result = await self.tpm.unseal_with_pcr_policy(sealed_blob)
        return result.decode() if result else None

    def _hash(self, data: str) -> str:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data.encode())
        return digest.finalize().hex()

    def _sign(self, data: str):
        return self.private_key.sign(data.encode())