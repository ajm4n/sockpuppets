"""WebSocket event bus endpoint for real-time GUI updates."""

import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

from gui.auth import operators

router = APIRouter()

_server = None
_connected_operators: dict[str, set[WebSocket]] = {}


def init(server):
    global _server
    _server = server


@router.websocket("/api/ws")
async def websocket_endpoint(ws: WebSocket, name: str = Query("operator")):
    await ws.accept()

    try:
        auth_raw = await asyncio.wait_for(ws.receive_text(), timeout=10.0)
        auth_data = json.loads(auth_raw)
        token = auth_data.get('token', '')
    except (asyncio.TimeoutError, json.JSONDecodeError, Exception):
        await ws.close(code=4001, reason="Unauthorized")
        return

    verified_name = operators.verify_session(token)
    if verified_name is None:
        await ws.close(code=4001, reason="Unauthorized")
        return

    display_name = verified_name
    _connected_operators.setdefault(display_name, set()).add(ws)

    if _server:
        _server.events.emit({"event": "operator_connected", "operator": display_name})

    event_queue = _server.events.subscribe() if _server else asyncio.Queue()

    forward_task = None
    try:
        agents = _server.get_agent_list() if _server else []
        active_ids = {a['id'] for a in _server.get_active_agents()} if _server else set()
        for a in agents:
            a['active'] = a['id'] in active_ids
            a['health_warning'] = _server.check_agent_health(a['id']) if _server else ''
        await ws.send_json({"event": "snapshot", "agents": agents, "operators": list(_connected_operators.keys())})

        async def forward_events():
            while True:
                event = await event_queue.get()
                event = {**event, "operators": list(_connected_operators.keys())}
                await ws.send_json(event)

        forward_task = asyncio.create_task(forward_events())

        async for message in ws.iter_text():
            pass

    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        if forward_task is not None:
            forward_task.cancel()
        if display_name in _connected_operators:
            _connected_operators[display_name].discard(ws)
            if not _connected_operators[display_name]:
                del _connected_operators[display_name]
                if _server:
                    _server.events.emit({"event": "operator_disconnected", "operator": display_name})
        if _server:
            _server.events.unsubscribe(event_queue)
