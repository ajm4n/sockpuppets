"""Regression: GUI API models, auth, and endpoint validation.

Tests Pydantic models, operator auth lifecycle, path traversal guard,
and API endpoint behavior.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

try:
    from fastapi.testclient import TestClient
    from pydantic import ValidationError
    from gui import create_app
    from gui.auth import OperatorStore, _hash_password, operators
    from gui.api import SleepRequest, CommandRequest, GenerateRequest, DowngradeRequest
    from server import SockPuppetsServer
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi not installed")


# ── Pydantic models ─────────────────────────────────────────


class TestSleepRequestModel:
    def test_interval_required(self):
        with pytest.raises(ValidationError):
            SleepRequest()

    def test_jitter_optional(self):
        req = SleepRequest(interval=30)
        assert req.jitter is None

    def test_jitter_accepted(self):
        req = SleepRequest(interval=10, jitter=25)
        assert req.interval == 10
        assert req.jitter == 25


class TestCommandRequestModel:
    def test_command_required(self):
        with pytest.raises(ValidationError):
            CommandRequest()

    def test_accepts_fs_commands(self):
        for cmd in ["__fs:ls:C:\\", "__fs:get:C:\\file.txt", "__fs:put:C:\\f\tdata"]:
            req = CommandRequest(command=cmd)
            assert req.command == cmd


class TestDowngradeRequestModel:
    def test_default_interval(self):
        req = DowngradeRequest()
        assert req.interval == 60


class TestGenerateRequestModel:
    def test_defaults(self):
        req = GenerateRequest(host="192.168.1.1", port=8443)
        assert req.key == "SOCKPUPPETS_KEY_2026"
        assert req.interval == 60
        assert req.jitter == 0
        assert req.lang == "go"
        assert req.beacon_mode is False
        assert req.amsi is False
        assert req.etw is False


# ── Operator auth ────────────────────────────────────────────


class TestOperatorStore:
    @pytest.fixture
    def store(self):
        return OperatorStore()

    def test_add_and_verify(self, store):
        store.add("op1", "pass1", must_change=False)
        name, mc = store.verify("op1", "pass1")
        assert name == "op1"
        assert mc is False

    def test_wrong_password(self, store):
        store.add("op1", "pass1")
        name, _ = store.verify("op1", "wrong")
        assert name is None

    def test_nonexistent_user(self, store):
        name, _ = store.verify("ghost", "pass")
        assert name is None

    def test_must_change_flag(self, store):
        store.add("op2", "temp", must_change=True)
        _, mc = store.verify("op2", "temp")
        assert mc is True

    def test_change_password_clears_must_change(self, store):
        store.add("op3", "old", must_change=True)
        store.change_password("op3", "new")
        assert store.requires_password_change("op3") is False
        name, mc = store.verify("op3", "new")
        assert name == "op3"
        assert mc is False

    def test_change_password_revokes_sessions(self, store):
        store.add("op4", "pass", must_change=False)
        token = store.create_session("op4")
        store.change_password("op4", "newpass")
        assert store.verify_session(token) is None

    def test_session_lifecycle(self, store):
        store.add("op5", "pass", must_change=False)
        token = store.create_session("op5")
        assert store.verify_session(token) == "op5"
        store.revoke_sessions("op5")
        assert store.verify_session(token) is None

    def test_remove_operator(self, store):
        store.add("op6", "pass")
        assert store.remove("op6") is True
        assert store.remove("op6") is False  # already removed
        name, _ = store.verify("op6", "pass")
        assert name is None

    def test_list_operators(self, store):
        store.add("a", "p")
        store.add("b", "p")
        assert sorted(store.list()) == ["a", "b"]

    def test_len(self, store):
        assert len(store) == 0
        store.add("x", "p")
        assert len(store) == 1


class TestPasswordHashing:
    def test_deterministic(self):
        h1 = _hash_password("test")
        h2 = _hash_password("test")
        assert h1 == h2

    def test_different_passwords_different_hashes(self):
        assert _hash_password("a") != _hash_password("b")

    def test_sha256_length(self):
        assert len(_hash_password("test")) == 64  # hex digest


# ── API endpoints ────────────────────────────────────────────


class TestAPIEndpoints:
    @pytest.fixture
    def client(self):
        server = SockPuppetsServer(encryption_key="test-gui")
        app = create_app(server)
        return TestClient(app)

    @pytest.fixture
    def auth_headers(self):
        operators.add("test-op", "test-pass", must_change=False)
        token = operators.create_session("test-op")
        yield {"Authorization": f"Bearer {token}"}
        operators.remove("test-op")

    def test_login_success(self, client):
        operators.add("login-test", "pass123", must_change=False)
        resp = client.post("/api/auth/login",
                           json={"username": "login-test", "password": "pass123"})
        assert resp.status_code == 200
        data = resp.json()
        assert "token" in data
        assert data["operator"] == "login-test"
        operators.remove("login-test")

    def test_login_failure(self, client):
        resp = client.post("/api/auth/login",
                           json={"username": "nobody", "password": "wrong"})
        assert resp.status_code == 401

    def test_agents_list_requires_auth(self, client):
        resp = client.get("/api/agents")
        assert resp.status_code == 401

    def test_agents_list_authorized(self, client, auth_headers):
        resp = client.get("/api/agents", headers=auth_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_command_agent_not_found(self, client, auth_headers):
        resp = client.post("/api/agents/nonexistent/command",
                           json={"command": "whoami"}, headers=auth_headers)
        assert resp.status_code == 404

    def test_sleep_agent_not_found(self, client, auth_headers):
        resp = client.post("/api/agents/nonexistent/sleep",
                           json={"interval": 10}, headers=auth_headers)
        assert resp.status_code == 404

    def test_kill_agent_not_found(self, client, auth_headers):
        resp = client.post("/api/agents/nonexistent/kill", headers=auth_headers)
        assert resp.status_code == 404

    def test_invalid_token_rejected(self, client):
        resp = client.get("/api/agents",
                          headers={"Authorization": "Bearer invalid-token"})
        assert resp.status_code == 401

    def test_must_change_password_blocks(self, client):
        operators.add("mustchange", "temp", must_change=True)
        token = operators.create_session("mustchange")
        resp = client.get("/api/agents",
                          headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403
        operators.remove("mustchange")


# ── Path traversal guard ─────────────────────────────────────


class TestPathTraversalGuard:
    def test_download_path_traversal_blocked(self):
        src = read_source("gui/api.py")
        assert "is_relative_to" in src, \
            "Download endpoint must check is_relative_to to prevent path traversal"

    def test_download_nonexistent_404(self):
        server = SockPuppetsServer(encryption_key="test")
        app = create_app(server)
        client = TestClient(app)
        operators.add("dl-test", "pass", must_change=False)
        token = operators.create_session("dl-test")
        resp = client.get("/api/download/../../etc/passwd",
                          headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 404
        operators.remove("dl-test")


def read_source(relative_path):
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        relative_path)
    with open(path) as f:
        return f.read()
