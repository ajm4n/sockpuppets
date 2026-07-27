"""AES-256-GCM wire crypto.

Protocol: base64(b'AES1' + nonce(12) + ciphertext+tag).
The AES key is HKDF-SHA256 of the agent key, not a raw SHA-256 digest.
A key embedded in an agent can still be recovered by reversing the binary.
"""

import os
import base64

SALT = b'sockpuppets-salt-v1'
INFO = b'sockpuppets-aes-256-gcm-v1'


def derive_aes_key(key: bytes) -> bytes:
    if isinstance(key, str):
        key = key.encode()
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=SALT, info=INFO).derive(key)


def aes_encrypt(data: str, key: bytes) -> str:
    if isinstance(key, str):
        key = key.encode()
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    ct = AESGCM(derive_aes_key(key)).encrypt(nonce, data.encode('utf-8'), None)
    return base64.b64encode(b'AES1' + nonce + ct).decode()


def aes_decrypt(encoded: str, key: bytes) -> str:
    if isinstance(key, str):
        key = key.encode()
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    raw = base64.b64decode(encoded.encode())
    if len(raw) < 16 or raw[:4] != b'AES1':
        raise ValueError('ciphertext rejected')
    pt = AESGCM(derive_aes_key(key)).decrypt(raw[4:16], raw[16:], None)
    return pt.decode('utf-8')


def seal_bytes(data: bytes) -> tuple:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = os.urandom(32)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, data, None)
    return key, nonce, ct


def open_bytes(key: bytes, nonce: bytes, ct: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).decrypt(nonce, ct, None)


def generate_unique_key() -> str:
    return os.urandom(32).hex()
