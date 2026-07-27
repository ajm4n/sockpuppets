import asyncio
import pytest

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import EventBus


@pytest.fixture
def bus():
    return EventBus()


def test_subscribe_returns_queue(bus):
    q = bus.subscribe()
    assert isinstance(q, asyncio.Queue)


def test_emit_delivers_to_subscriber(bus):
    q = bus.subscribe()
    bus.emit({"event": "test", "data": 42})
    assert not q.empty()
    item = q.get_nowait()
    assert item["event"] == "test"
    assert item["data"] == 42


def test_emit_delivers_to_multiple_subscribers(bus):
    q1 = bus.subscribe()
    q2 = bus.subscribe()
    bus.emit({"event": "ping"})
    assert q1.get_nowait()["event"] == "ping"
    assert q2.get_nowait()["event"] == "ping"


def test_unsubscribe_stops_delivery(bus):
    q = bus.subscribe()
    bus.unsubscribe(q)
    bus.emit({"event": "after_unsub"})
    assert q.empty()


def test_emit_adds_timestamp(bus):
    q = bus.subscribe()
    bus.emit({"event": "test"})
    item = q.get_nowait()
    assert "timestamp" in item
