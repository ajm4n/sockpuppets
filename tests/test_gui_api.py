import asyncio
import pytest
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from fastapi.testclient import TestClient
    from gui import create_app
    from gui.auth import operators
    from server import SockPuppetsServer
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi not installed")

ENCRYPTION_KEY = b"test-key-for-gui"


@pytest.fixture
def server():
    return SockPuppetsServer(encryption_key=ENCRYPTION_KEY)


@pytest.fixture
def auth_token():
    token = operators.add("test-operator")
    yield token
    operators.remove("test-operator")


@pytest.fixture
def client(server):
    app = create_app(server)
    return TestClient(app)


@pytest.fixture
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}


def test_server_status_unauthorized(client):
    resp = client.get("/api/server/status")
    assert resp.status_code == 401


def test_server_status_authorized(client, auth_headers):
    resp = client.get("/api/server/status", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "running" in data


def test_agents_empty(client, auth_headers):
    resp = client.get("/api/agents", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() == []


def test_profiles_list(client, auth_headers):
    resp = client.get("/api/profiles", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


def test_redirectors_list(client, auth_headers):
    resp = client.get("/api/redirectors", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


def test_agent_not_found(client, auth_headers):
    resp = client.get("/api/agents/nonexistent", headers=auth_headers)
    assert resp.status_code == 404


def test_invalid_token_rejected(client):
    resp = client.get("/api/agents", headers={"Authorization": "Bearer bad-token"})
    assert resp.status_code == 401


def test_operator_store_lifecycle():
    from gui.auth import OperatorStore
    store = OperatorStore()
    token = store.add("alice")
    assert isinstance(token, str)
    assert len(token) == 64
    assert store.verify(token) == "alice"
    assert store.verify("wrong-token") is None
    assert "alice" in store.list()
    assert store.remove("alice")
    assert store.verify(token) is None
    assert not store.remove("alice")
