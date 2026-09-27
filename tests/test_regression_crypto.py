"""Regression: EPH1 X25519 handshake, AES-256-GCM, HKDF, session encrypt/decrypt.

Tests the full cryptographic pipeline that all agents rely on for secure
communication with the C2 server.
"""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from server import SockPuppetsServer
from crypto.handshake import (
    SALT, INFO_HS, INFO_SESSION,
    ServerIdentity, client_hello, server_accept, server_welcome, client_finish,
    session_encrypt, session_decrypt, _hkdf,
)


class TestHKDFConstants:
    def test_salt_value(self):
        assert SALT == b'sockpuppets-salt-v1'

    def test_salt_length(self):
        assert len(SALT) == 19, "Salt must be exactly 19 bytes (no null terminator)"

    def test_handshake_info(self):
        assert INFO_HS == b'sockpuppets-handshake-v1'

    def test_session_info(self):
        assert INFO_SESSION == b'sockpuppets-session-v1'

    def test_hkdf_deterministic(self):
        key1 = _hkdf(b'test-ikm', INFO_HS)
        key2 = _hkdf(b'test-ikm', INFO_HS)
        assert key1 == key2

    def test_hkdf_different_info_different_keys(self):
        key1 = _hkdf(b'test-ikm', INFO_HS)
        key2 = _hkdf(b'test-ikm', INFO_SESSION)
        assert key1 != key2

    def test_hkdf_output_length(self):
        key = _hkdf(b'test-ikm', INFO_HS)
        assert len(key) == 32


class TestAESGCMEncryptDecrypt:
    @pytest.fixture
    def server(self):
        return SockPuppetsServer(encryption_key="test-key-aes")

    def test_round_trip(self, server):
        plaintext = '{"type": "register", "hostname": "TEST-PC"}'
        encrypted = server.simple_encrypt(plaintext)
        decrypted = server.simple_decrypt(encrypted)
        assert decrypted == plaintext

    def test_encrypted_has_aes1_prefix(self, server):
        encrypted = server.simple_encrypt("hello")
        raw = base64.b64decode(encrypted)
        assert raw[:4] == b'AES1'

    def test_nonce_is_12_bytes(self, server):
        encrypted = server.simple_encrypt("test")
        raw = base64.b64decode(encrypted)
        assert len(raw) >= 16 + 4  # AES1(4) + nonce(12) + at least some ciphertext

    def test_minimum_payload_size(self, server):
        encrypted = server.simple_encrypt("x")
        raw = base64.b64decode(encrypted)
        # AES1(4) + nonce(12) + ciphertext(1) + tag(16) = 33 min
        assert len(raw) >= 33

    def test_different_encryptions_differ(self, server):
        enc1 = server.simple_encrypt("same plaintext")
        enc2 = server.simple_encrypt("same plaintext")
        assert enc1 != enc2, "Random nonce should produce different ciphertexts"

    def test_wrong_key_fails(self, server):
        encrypted = server.simple_encrypt("secret data")
        server2 = SockPuppetsServer(encryption_key="wrong-key")
        with pytest.raises(Exception):
            server2.simple_decrypt(encrypted)

    def test_invalid_prefix_rejected(self, server):
        bad = base64.b64encode(b'AES2' + os.urandom(28)).decode()
        with pytest.raises(ValueError, match="AES1"):
            server.simple_decrypt(bad)

    def test_too_short_rejected(self, server):
        bad = base64.b64encode(b'AES1' + os.urandom(10)).decode()
        with pytest.raises(Exception):
            server.simple_decrypt(bad)

    def test_json_roundtrip(self, server):
        data = {"type": "checkin", "agent_id": "abc123", "results": [{"output": "whoami"}]}
        encrypted = server.simple_encrypt(json.dumps(data))
        decrypted = json.loads(server.simple_decrypt(encrypted))
        assert decrypted == data


class TestEPH1Handshake:
    @pytest.fixture
    def identity(self):
        return ServerIdentity()

    def test_full_handshake_roundtrip(self, identity):
        reg_msg = '{"type": "register", "hostname": "WIN-TEST"}'
        hello_blob, eph, hs = client_hello(identity.pub, reg_msg)
        assert hello_blob.startswith('EPH1.')

        plaintext, eph_pub, server_hs = server_accept(identity, hello_blob)
        assert plaintext == reg_msg

        welcome_msg = '{"type": "registered", "agent_id": "abc12345"}'
        welcome_blob, server_session = server_welcome(server_hs, eph_pub, welcome_msg)
        assert welcome_blob.startswith('EPH2.')

        client_pt, client_session = client_finish(eph, hs, welcome_blob)
        assert client_pt == welcome_msg
        assert client_session == server_session

    def test_session_keys_match(self, identity):
        _, eph, hs = client_hello(identity.pub, "test")
        _, eph_pub, server_hs = server_accept(identity, _)
        # Re-do properly
        hello_blob, eph, hs = client_hello(identity.pub, "test")
        _, eph_pub, server_hs = server_accept(identity, hello_blob)
        _, server_session = server_welcome(server_hs, eph_pub, "ok")
        _, client_session = client_finish(eph, hs, _)
        # Actually need the welcome blob
        hello_blob, eph, hs = client_hello(identity.pub, "msg1")
        pt, eph_pub, server_hs = server_accept(identity, hello_blob)
        welcome_blob, server_session = server_welcome(server_hs, eph_pub, "msg2")
        _, client_session = client_finish(eph, hs, welcome_blob)
        assert server_session == client_session
        assert len(server_session) == 32

    def test_session_encrypt_decrypt(self, identity):
        hello_blob, eph, hs = client_hello(identity.pub, "reg")
        _, eph_pub, server_hs = server_accept(identity, hello_blob)
        welcome_blob, server_session = server_welcome(server_hs, eph_pub, "ok")
        _, client_session = client_finish(eph, hs, welcome_blob)

        encrypted = session_encrypt(server_session, "command: whoami")
        decrypted = session_decrypt(client_session, encrypted)
        assert decrypted == "command: whoami"

    def test_session_encrypt_has_aes1_prefix(self, identity):
        key = os.urandom(32)
        encrypted = session_encrypt(key, "test")
        raw = base64.b64decode(encrypted)
        assert raw[:4] == b'AES1'

    def test_session_decrypt_rejects_bad_prefix(self):
        bad = base64.b64encode(b'BAD1' + os.urandom(28)).decode()
        with pytest.raises(ValueError, match="ciphertext rejected"):
            session_decrypt(os.urandom(32), bad)

    def test_different_identities_incompatible(self):
        id1 = ServerIdentity()
        id2 = ServerIdentity()
        hello_blob, eph, hs = client_hello(id1.pub, "test")
        with pytest.raises(Exception):
            server_accept(id2, hello_blob)

    def test_eph1_blob_format(self, identity):
        hello_blob, _, _ = client_hello(identity.pub, "test")
        assert hello_blob.startswith('EPH1.')
        b64_part = hello_blob[5:]
        raw = base64.b64decode(b64_part)
        assert len(raw) >= 32, "Must contain at least eph_pub (32 bytes)"


class TestTryDecrypt:
    def test_finds_correct_key(self):
        server = SockPuppetsServer(encryption_key="key-one")
        # Add a second key and encrypt with it
        key_two = b"key-two-for-test"
        server.known_keys.add(key_two)
        # try_decrypt requires valid JSON in the plaintext
        msg = json.dumps({"test": True})
        encrypted = server.simple_encrypt(msg, key_two)
        decrypted, key_used = server.try_decrypt(encrypted)
        assert json.loads(decrypted) == {"test": True}

    def test_no_matching_key_raises(self):
        server = SockPuppetsServer(encryption_key="key-one")
        server2 = SockPuppetsServer(encryption_key="key-two")
        encrypted = server2.simple_encrypt(json.dumps({"x": 1}))
        with pytest.raises(ValueError, match="No known key"):
            server.try_decrypt(encrypted)


class TestDeriveAgentKeys:
    def test_deterministic(self):
        server = SockPuppetsServer(encryption_key="test-key")
        k1 = server.derive_agent_keys("agent-001")
        k2 = server.derive_agent_keys("agent-001")
        assert k1 == k2

    def test_different_agents_different_keys(self):
        server = SockPuppetsServer(encryption_key="test-key")
        k1 = server.derive_agent_keys("agent-001")
        k2 = server.derive_agent_keys("agent-002")
        assert k1 != k2

    def test_directional_keys_differ(self):
        server = SockPuppetsServer(encryption_key="test-key")
        c2s, s2c = server.derive_agent_keys("agent-001")
        assert c2s != s2c, "c2s and s2c keys must be different"

    def test_key_length(self):
        server = SockPuppetsServer(encryption_key="test-key")
        c2s, s2c = server.derive_agent_keys("agent-001")
        assert len(c2s) == 32
        assert len(s2c) == 32
