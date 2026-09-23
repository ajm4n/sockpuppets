"""X25519 handshake and AES-256-GCM sessions.

The agent embeds only the server static public key. Each session uses a
fresh X25519 share. A stolen server key does not decrypt old session traffic.
A debugger on a live agent still can.
"""

import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SALT = b'sockpuppets-salt-v1'
INFO_HS = b'sockpuppets-handshake-v1'
INFO_SESSION = b'sockpuppets-session-v1'
IDENTITY_PATH = Path(__file__).resolve().parents[1] / 'keys' / 'server_x25519.bin'


def _hkdf(ikm: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=SALT, info=info).derive(ikm)


def _pub_bytes(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _seal(key: bytes, plaintext: str) -> bytes:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode('utf-8'), None)
    return nonce + ct


def _open(key: bytes, blob: bytes) -> str:
    return AESGCM(key).decrypt(blob[:12], blob[12:], None).decode('utf-8')


def session_encrypt(session_key: bytes, plaintext: str) -> str:
    return base64.b64encode(b'AES1' + _seal(session_key, plaintext)).decode()


def session_decrypt(session_key: bytes, encoded: str) -> str:
    raw = base64.b64decode(encoded.encode())
    if len(raw) < 16 or raw[:4] != b'AES1':
        raise ValueError('ciphertext rejected')
    return _open(session_key, raw[4:])


class ServerIdentity:
    def __init__(self, priv: X25519PrivateKey = None):
        self.priv = priv or X25519PrivateKey.generate()
        self.pub = _pub_bytes(self.priv)

    @classmethod
    def load(cls, path: Path = IDENTITY_PATH) -> 'ServerIdentity':
        if path.exists():
            return cls(X25519PrivateKey.from_private_bytes(path.read_bytes()))
        ident = cls()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(ident.priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ))
        return ident


def client_hello(server_pub: bytes, plaintext: str):
    eph = X25519PrivateKey.generate()
    eph_pub = _pub_bytes(eph)
    shared = eph.exchange(X25519PublicKey.from_public_bytes(server_pub))
    hs = _hkdf(shared, INFO_HS)
    blob = 'EPH1.' + base64.b64encode(eph_pub + _seal(hs, plaintext)).decode()
    return blob, eph, hs


def server_accept(identity: ServerIdentity, blob: str):
    if not blob.startswith('EPH1.'):
        raise ValueError('not a handshake')
    raw = base64.b64decode(blob[5:].encode())
    eph_pub, rest = raw[:32], raw[32:]
    shared = identity.priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    hs = _hkdf(shared, INFO_HS)
    return _open(hs, rest), eph_pub, hs


def server_welcome(hs: bytes, agent_eph_pub: bytes, plaintext: str):
    eph = X25519PrivateKey.generate()
    eph_pub = _pub_bytes(eph)
    shared2 = eph.exchange(X25519PublicKey.from_public_bytes(agent_eph_pub))
    session = _hkdf(shared2 + hs, INFO_SESSION)
    blob = 'EPH2.' + base64.b64encode(eph_pub + _seal(hs, plaintext)).decode()
    return blob, session


def client_finish(eph: X25519PrivateKey, hs: bytes, blob: str):
    if not blob.startswith('EPH2.'):
        raise ValueError('not a welcome')
    raw = base64.b64decode(blob[5:].encode())
    srv_pub, rest = raw[:32], raw[32:]
    pt = _open(hs, rest)
    shared2 = eph.exchange(X25519PublicKey.from_public_bytes(srv_pub))
    session = _hkdf(shared2 + hs, INFO_SESSION)
    return pt, session


def agent_wire_source(server_pub: bytes) -> str:
    return f'''
_SERVER_PUB = bytes.fromhex("{server_pub.hex()}")
_WIRE = {{"eph": None, "hs": None, "key": None}}

def _hkdf_wire(ikm, info):
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"sockpuppets-salt-v1", info=info).derive(ikm)

def _seal_wire(key, text):
    import os, base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, text.encode("utf-8"), None)

def _open_wire(key, blob):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).decrypt(blob[:12], blob[12:], None).decode("utf-8")

def wire_encrypt(data):
    import os, base64
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives import serialization
    if _WIRE["key"]:
        return base64.b64encode(b"AES1" + _seal_wire(_WIRE["key"], data)).decode()
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    shared = eph.exchange(X25519PublicKey.from_public_bytes(_SERVER_PUB))
    hs = _hkdf_wire(shared, b"sockpuppets-handshake-v1")
    _WIRE["eph"] = eph
    _WIRE["hs"] = hs
    return "EPH1." + base64.b64encode(eph_pub + _seal_wire(hs, data)).decode()

def wire_decrypt(data):
    import base64
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    if isinstance(data, bytes):
        data = data.decode()
    if data.startswith("EPH2."):
        raw = base64.b64decode(data[5:].encode())
        srv_pub, rest = raw[:32], raw[32:]
        pt = _open_wire(_WIRE["hs"], rest)
        shared2 = _WIRE["eph"].exchange(X25519PublicKey.from_public_bytes(srv_pub))
        _WIRE["key"] = _hkdf_wire(shared2 + _WIRE["hs"], b"sockpuppets-session-v1")
        _WIRE["eph"] = None
        return pt
    raw = base64.b64decode(data.encode())
    if raw[:4] != b"AES1":
        raise ValueError("ciphertext rejected")
    return _open_wire(_WIRE["key"], raw[4:])
'''


class Wire:
    def __init__(self, plaintext, seal, session_key=None):
        self.plaintext = plaintext
        self._seal = seal
        self.session_key = session_key

    def seal(self, plaintext: str) -> str:
        blob, session = self._seal(plaintext)
        if session is not None:
            self.session_key = session
        return blob


def open_wire(identity: ServerIdentity, body: str, session_keys: list) -> Wire:
    if body.startswith('EPH1.'):
        pt, eph_pub, hs = server_accept(identity, body)

        def seal(plaintext, hs=hs, eph_pub=eph_pub):
            return server_welcome(hs, eph_pub, plaintext)

        return Wire(pt, seal)
    for key in session_keys:
        try:
            pt = session_decrypt(key, body)
        except Exception:
            continue

        def seal(plaintext, key=key):
            return session_encrypt(key, plaintext), None

        return Wire(pt, seal, key)
    raise ValueError('ciphertext rejected')
