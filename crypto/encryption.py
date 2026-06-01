"""Shared AES-256-GCM encryption used by both server and agent templates.

Protocol format: base64(b'AES1' + nonce(12) + ciphertext)
Fallback: base64(XOR(data, key))
"""

import os
import base64
import hashlib


def derive_aes_key(key: bytes) -> bytes:
    if isinstance(key, str):
        key = key.encode()
    return hashlib.sha256(key).digest()


def aes_encrypt(data: str, key: bytes) -> str:
    if isinstance(key, str):
        key = key.encode()
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aes_key = derive_aes_key(key)
        nonce = os.urandom(12)
        ct = AESGCM(aes_key).encrypt(nonce, data.encode('utf-8'), None)
        return base64.b64encode(b'AES1' + nonce + ct).decode()
    except ImportError:
        return xor_encrypt(data, key)


def aes_decrypt(encoded: str, key: bytes) -> str:
    if isinstance(key, str):
        key = key.encode()
    raw = base64.b64decode(encoded.encode())
    if raw[:4] == b'AES1':
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aes_key = derive_aes_key(key)
            pt = AESGCM(aes_key).decrypt(raw[4:16], raw[16:], None)
            return pt.decode('utf-8')
        except Exception:
            pass
    return xor_decrypt_raw(raw, key)


def xor_encrypt(data: str, key: bytes) -> str:
    if isinstance(key, str):
        key = key.encode()
    encoded = data.encode('latin-1')
    encrypted = bytes(a ^ key[i % len(key)] for i, a in enumerate(encoded))
    return base64.b64encode(encrypted).decode()


def xor_decrypt_raw(raw: bytes, key: bytes) -> str:
    if isinstance(key, str):
        key = key.encode()
    decrypted = bytes(a ^ key[i % len(key)] for i, a in enumerate(raw))
    return decrypted.decode('latin-1')


def generate_unique_key() -> str:
    return hashlib.sha256(os.urandom(16)).hexdigest()[:24]
