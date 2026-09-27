import asyncio
import pytest


@pytest.fixture(autouse=True)
def _event_loop():
    """Ensure an event loop exists for tests that use asyncio.Queue."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        yield
        loop.close()
    else:
        yield
