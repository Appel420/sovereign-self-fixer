import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

class CodeCryptor:
    def __init__(self, key: bytes = None):
        if key:
            self.key = key
        else:
            self.key = self._get_or_create_key()

    def _get_or_create_key(self):
        key_file = os.path.expanduser("~/.sovereign/master.key")
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                return f.read()
        key = os.urandom(32)
        os.makedirs(os.path.dirname(key_file), exist_ok=True)
        with open(key_file, "wb") as f:
            f.write(key)
        os.chmod(key_file, 0o600)
        return key

    def encrypt(self, plaintext: bytes):
        nonce = os.urandom(12)
        chacha = ChaCha20Poly1305(self.key)
        ciphertext = chacha.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes):
        nonce = data[:12]
        ciphertext = data[12:]
        chacha = ChaCha20Poly1305(self.key)
        return chacha.decrypt(nonce, ciphertext, None)