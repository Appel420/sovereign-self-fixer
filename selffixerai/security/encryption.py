#!/usr/bin/env python3
"""Encryption Module — XChaCha20-Poly1305 + ML-KEM + ML-DSA-87"""

import os
import logging
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305

try:
    import oqs
    HAS_OQS = True
except ImportError:
    HAS_OQS = False
    logging.warning("python-oqs not installed. ML-KEM / ML-DSA-87 will be unavailable.")

class CodeCryptor:
    def __init__(self, key_file: str = "master.key"):
        self.key_file = key_file
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                key = f.read()
        else:
            key = XChaCha20Poly1305.generate_key()
            with open(key_file, "wb") as f:
                f.write(key)
        self.key = key
        self.cipher = XChaCha20Poly1305(self.key)

    def encrypt(self, content: str) -> bytes:
        nonce = os.urandom(24)
        ciphertext = self.cipher.encrypt(nonce, content.encode(), None)
        return nonce + ciphertext

    def decrypt(self, blob: bytes) -> str:
        nonce, ciphertext = blob[:24], blob[24:]
        return self.cipher.decrypt(nonce, ciphertext, None).decode()

class PQCHybrid:
    def __init__(self):
        self.ml_kem = None
        self.ml_dsa = None
        if HAS_OQS:
            try:
                self.ml_kem = oqs.KeyEncapsulation("ML-KEM-768")
                self.ml_dsa = oqs.Signature("ML-DSA-87")
            except Exception as e:
                logging.error(f"Failed to initialize PQC: {e}")

    def generate_kem_keypair(self) -> Optional[Tuple[bytes, bytes]]:
        if not self.ml_kem: return None
        public_key = self.ml_kem.generate_keypair()
        secret_key = self.ml_kem.export_secret_key()
        return public_key, secret_key

    def sign(self, message: bytes, secret_key: bytes) -> Optional[bytes]:
        if not self.ml_dsa: return None
        self.ml_dsa.import_secret_key(secret_key)
        return self.ml_dsa.sign(message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        if not self.ml_dsa: return False
        try:
            verifier = oqs.Signature("ML-DSA-87")
            return verifier.verify(message, signature, public_key)
        except Exception:
            return False