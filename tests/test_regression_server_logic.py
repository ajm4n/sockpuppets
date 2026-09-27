"""Regression: Server core logic — agent lifecycle, command dispatch, health checks.

Tests the server-side logic for agent management that doesn't require
live network connections.
"""
import asyncio
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from server import SockPuppetsServer, Agent, EventBus


# ── Agent class ──────────────────────────────────────────────


class TestAgentDefaults:
    @pytest.fixture
    def agent(self):
        return Agent("test-001", {"hostname": "WIN-PC", "username": "admin",
                                   "os": "windows", "mode": "beacon",
                                   "beacon_interval": 30, "beacon_jitter": 10}, "http")

    def test_initial_mode(self, agent):
        assert agent.mode == "beacon"

    def test_initial_interval(self, agent):
        assert agent.beacon_interval == 30

    def test_initial_jitter(self, agent):
        assert agent.beacon_jitter == 10

    def test_initial_interval_flag(self, agent):
        assert agent._interval_set_by_operator is False

    def test_initial_pending_kill(self, agent):
        assert agent.pending_kill is False

    def test_initial_pending_results(self, agent):
        assert agent.pending_results == []

    def test_initial_command_history(self, agent):
        assert agent.command_history == []

    def test_default_mode_when_missing(self):
        agent = Agent("test-002", {}, "websocket")
        assert agent.mode == "streaming"

    def test_default_interval_when_missing(self):
        agent = Agent("test-003", {}, "http")
        assert agent.beacon_interval == 60

    def test_default_jitter_when_missing(self):
        agent = Agent("test-004", {}, "http")
        assert agent.beacon_jitter == 0


class TestAgentGetInfo:
    def test_contains_required_fields(self):
        agent = Agent("test-info", {"hostname": "PC1", "username": "user1",
                                     "os": "linux", "ip": "10.0.0.5"}, "https")
        info = agent.get_info()
        required = {"id", "hostname", "username", "os", "ip", "connected_at",
                     "last_seen", "mode", "transport", "beacon_interval", "beacon_jitter"}
        assert required.issubset(info.keys())

    def test_id_matches(self):
        agent = Agent("abc123", {}, "http")
        assert agent.get_info()["id"] == "abc123"

    def test_transport_matches(self):
        for transport in ("http", "https", "websocket"):
            agent = Agent("t-" + transport, {}, transport)
            assert agent.get_info()["transport"] == transport

    def test_timestamps_are_iso(self):
        agent = Agent("ts-test", {}, "http")
        info = agent.get_info()
        datetime.fromisoformat(info["connected_at"])
        datetime.fromisoformat(info["last_seen"])


class TestAgentIsHttp:
    def test_http_true(self):
        assert Agent("a", {}, "http").is_http() is True

    def test_https_true(self):
        assert Agent("b", {}, "https").is_http() is True

    def test_websocket_false(self):
        assert Agent("c", {}, "websocket").is_http() is False


# ── Registration ─────────────────────────────────────────────


class TestRegistration:
    def test_register_agent_common(self):
        server = SockPuppetsServer(encryption_key="test")
        meta = {"hostname": "WIN-REG", "username": "user", "os": "windows"}
        agent = server.register_agent_common("reg-001", meta, "https")
        assert "reg-001" in server.agents
        assert agent.metadata["hostname"] == "WIN-REG"
        assert agent.transport_type == "https"

    def test_register_preserves_metadata(self):
        server = SockPuppetsServer(encryption_key="test")
        meta = {"hostname": "H", "username": "U", "os": "linux",
                "mode": "beacon", "beacon_interval": 15}
        agent = server.register_agent_common("reg-002", meta, "http")
        assert agent.mode == "beacon"
        assert agent.beacon_interval == 15

    def test_register_multiple_agents(self):
        server = SockPuppetsServer(encryption_key="test")
        server.register_agent_common("a1", {}, "http")
        server.register_agent_common("a2", {}, "https")
        server.register_agent_common("a3", {}, "websocket")
        assert len(server.agents) == 3


# ── Command dispatch ─────────────────────────────────────────


class TestCommandDispatch:
    @pytest.fixture
    def setup(self):
        server = SockPuppetsServer(encryption_key="test")
        agent = server.register_agent_common("cmd-001",
            {"mode": "beacon", "beacon_interval": 5}, "http")
        return server, agent

    def test_agent_not_found(self, setup):
        server, _ = setup
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(server.send_command_to_agent("nonexistent", "whoami"))
        assert result == "Agent not found"

    def test_beacon_queues_command(self, setup):
        server, agent = setup
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(server.send_command_to_agent("cmd-001", "whoami"))
        assert "queued" in result.lower()

    def test_command_history_appended(self, setup):
        server, agent = setup
        loop = asyncio.get_event_loop()
        loop.run_until_complete(server.send_command_to_agent("cmd-001", "hostname"))
        assert len(agent.command_history) == 1
        assert agent.command_history[0]["command"] == "hostname"

    def test_command_has_id_and_timestamp(self, setup):
        server, agent = setup
        loop = asyncio.get_event_loop()
        loop.run_until_complete(server.send_command_to_agent("cmd-001", "dir"))
        entry = agent.command_history[0]
        assert "command_id" in entry
        assert "queued_at" in entry


# ── Kill agent ───────────────────────────────────────────────


class TestKillAgent:
    def test_kill_not_found(self):
        server = SockPuppetsServer(encryption_key="test")
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(server.kill_agent("ghost"))
        assert result == "Agent not found"

    def test_kill_http_queues_command(self):
        server = SockPuppetsServer(encryption_key="test")
        server.register_agent_common("kill-http", {"mode": "beacon"}, "http")
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(server.kill_agent("kill-http"))
        assert "queued" in result.lower()
        agent = server.agents["kill-http"]
        assert agent.pending_kill is True

    def test_kill_http_sends_kill_command(self):
        server = SockPuppetsServer(encryption_key="test")
        server.register_agent_common("kill-cmd", {"mode": "beacon"}, "http")
        loop = asyncio.get_event_loop()
        loop.run_until_complete(server.kill_agent("kill-cmd"))
        agent = server.agents["kill-cmd"]
        cmd = loop.run_until_complete(agent.command_queue.get())
        assert cmd == "__kill"


# ── Agent results ────────────────────────────────────────────


class TestAgentResults:
    def test_empty_results(self):
        server = SockPuppetsServer(encryption_key="test")
        assert server.get_agent_results("nope") == []

    def test_results_returned(self):
        server = SockPuppetsServer(encryption_key="test")
        agent = server.register_agent_common("res-001", {}, "http")
        agent.pending_results.append({"command": "whoami", "output": "admin"})
        results = server.get_agent_results("res-001")
        assert len(results) == 1
        assert results[0]["output"] == "admin"

    def test_clear_removes_results(self):
        server = SockPuppetsServer(encryption_key="test")
        agent = server.register_agent_common("res-002", {}, "http")
        agent.pending_results.append({"command": "hostname", "output": "WIN-PC"})
        server.get_agent_results("res-002", clear=True)
        assert len(agent.pending_results) == 0

    def test_no_clear_keeps_results(self):
        server = SockPuppetsServer(encryption_key="test")
        agent = server.register_agent_common("res-003", {}, "http")
        agent.pending_results.append({"command": "dir", "output": "files"})
        server.get_agent_results("res-003", clear=False)
        assert len(agent.pending_results) == 1


# ── Agent list ───────────────────────────────────────────────


class TestAgentList:
    def test_empty_list(self):
        server = SockPuppetsServer(encryption_key="test")
        assert server.get_agent_list() == []

    def test_list_returns_all(self):
        server = SockPuppetsServer(encryption_key="test")
        server.register_agent_common("list-1", {"hostname": "A"}, "http")
        server.register_agent_common("list-2", {"hostname": "B"}, "https")
        result = server.get_agent_list()
        assert len(result) == 2


# ── Health check ─────────────────────────────────────────────


class TestHealthCheck:
    def test_nonexistent_agent(self):
        server = SockPuppetsServer(encryption_key="test")
        assert server.check_agent_health("ghost") == ""

    def test_non_beacon_always_healthy(self):
        server = SockPuppetsServer(encryption_key="test")
        agent = server.register_agent_common("hc-ws", {"mode": "streaming"}, "websocket")
        assert server.check_agent_health("hc-ws") == ""

    def test_fresh_beacon_healthy(self):
        server = SockPuppetsServer(encryption_key="test")
        server.register_agent_common("hc-fresh", {"mode": "beacon", "beacon_interval": 60}, "http")
        assert server.check_agent_health("hc-fresh") == ""

    def test_stale_beacon_warns(self):
        server = SockPuppetsServer(encryption_key="test")
        agent = server.register_agent_common("hc-stale",
            {"mode": "beacon", "beacon_interval": 10, "beacon_jitter": 0}, "http")
        agent.last_seen = datetime.now() - timedelta(minutes=10)
        result = server.check_agent_health("hc-stale")
        assert "may be dead" in result

    def test_health_accounts_for_jitter(self):
        server = SockPuppetsServer(encryption_key="test")
        agent = server.register_agent_common("hc-jit",
            {"mode": "beacon", "beacon_interval": 60, "beacon_jitter": 50}, "http")
        # interval(60) + jitter(50% = 30s) + grace(180s) = 270s
        # Set last_seen to 200s ago — should still be healthy
        agent.last_seen = datetime.now() - timedelta(seconds=200)
        assert server.check_agent_health("hc-jit") == ""


# ── EventBus ─────────────────────────────────────────────────


class TestEventBus:
    def test_subscribe_returns_queue(self):
        bus = EventBus()
        q = bus.subscribe()
        assert isinstance(q, asyncio.Queue)

    def test_unsubscribe(self):
        bus = EventBus()
        q = bus.subscribe()
        bus.unsubscribe(q)
        # Internal check: subscriber list should be empty
        assert len(bus._subscribers) == 0

    def test_emit_adds_timestamp(self):
        bus = EventBus()
        q = bus.subscribe()
        loop = asyncio.get_event_loop()
        bus.emit({"event": "test"})
        loop.run_until_complete(asyncio.sleep(0.05))
        if not q.empty():
            item = q.get_nowait()
            assert "timestamp" in item

    def test_emit_delivers_via_loop(self):
        bus = EventBus()
        q = bus.subscribe()
        loop = asyncio.get_event_loop()
        bus.emit({"event": "ping", "data": 42})
        loop.run_until_complete(asyncio.sleep(0.05))
        if not q.empty():
            item = q.get_nowait()
            assert item["event"] == "ping"
            assert item["data"] == 42


# ── Encryption key management ────────────────────────────────


class TestEncryptionKeyManagement:
    def test_known_keys_includes_default(self):
        server = SockPuppetsServer(encryption_key="default-key")
        assert b"default-key" in server.known_keys

    def test_add_encryption_key(self):
        server = SockPuppetsServer(encryption_key="default-key")
        initial_count = len(server.known_keys)
        server.known_keys.add(b"extra-key-unique-test")
        assert b"extra-key-unique-test" in server.known_keys
        assert len(server.known_keys) == initial_count + 1

    def test_duplicate_key_no_duplicates(self):
        server = SockPuppetsServer(encryption_key="default-key")
        initial_count = len(server.known_keys)
        server.known_keys.add(b"default-key")
        assert len(server.known_keys) == initial_count
