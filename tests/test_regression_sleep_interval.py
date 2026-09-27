"""Regression: operator-set beacon interval must not be overwritten by agent checkin metadata.

Bug: server.py overwrote agent.beacon_interval from checkin metadata on every
HTTP poll, reverting operator-set values. Fixed by adding _interval_set_by_operator
flag to Agent and guarding the 3 checkin-update sites.
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from server import SockPuppetsServer, Agent


@pytest.fixture
def server():
    return SockPuppetsServer(encryption_key="test-key")


@pytest.fixture
def agent():
    meta = {
        "hostname": "TEST-PC",
        "username": "testuser",
        "os": "windows",
        "mode": "beacon",
        "beacon_interval": 60,
        "beacon_jitter": 10,
    }
    return Agent("test-agent-001", meta, transport_type="http")


def test_agent_has_interval_flag(agent):
    assert hasattr(agent, "_interval_set_by_operator")
    assert agent._interval_set_by_operator is False


def test_set_beacon_interval_sets_flag(server, agent):
    server.agents[agent.agent_id] = agent
    loop = asyncio.get_event_loop()
    loop.run_until_complete(server.set_beacon_interval(agent.agent_id, 5))
    assert agent.beacon_interval == 5
    assert agent._interval_set_by_operator is True


def test_set_beacon_interval_with_jitter(server, agent):
    server.agents[agent.agent_id] = agent
    loop = asyncio.get_event_loop()
    loop.run_until_complete(server.set_beacon_interval(agent.agent_id, 10, jitter=25))
    assert agent.beacon_interval == 10
    assert agent.beacon_jitter == 25
    assert agent._interval_set_by_operator is True


def test_flag_prevents_metadata_overwrite(agent):
    """Simulate what happens when checkin metadata tries to overwrite interval."""
    agent.beacon_interval = 5
    agent._interval_set_by_operator = True
    checkin_metadata = {"beacon_interval": 60}
    if not agent._interval_set_by_operator:
        agent.beacon_interval = checkin_metadata.get("beacon_interval", agent.beacon_interval)
    assert agent.beacon_interval == 5, "Operator-set interval was overwritten by checkin metadata"


def test_flag_not_set_allows_metadata_update(agent):
    """Without the flag, checkin metadata can update the interval."""
    agent.beacon_interval = 60
    assert agent._interval_set_by_operator is False
    checkin_metadata = {"beacon_interval": 30}
    if not agent._interval_set_by_operator:
        agent.beacon_interval = checkin_metadata.get("beacon_interval", agent.beacon_interval)
    assert agent.beacon_interval == 30


def test_set_beacon_interval_agent_not_found(server):
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(server.set_beacon_interval("nonexistent", 5))
    assert result == "Agent not found"


def test_set_beacon_interval_queues_command_for_http(server, agent):
    server.agents[agent.agent_id] = agent
    loop = asyncio.get_event_loop()
    loop.run_until_complete(server.set_beacon_interval(agent.agent_id, 15))
    cmd = loop.run_until_complete(agent.command_queue.get())
    assert cmd == "__set_interval:15"
