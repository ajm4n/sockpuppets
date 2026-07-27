"""SockPuppets Web GUI — optional FastAPI-based operator dashboard."""

import threading
from pathlib import Path

_gui_thread = None
_uvicorn_server = None


def create_app(server):
    """Create the FastAPI app. Can be used standalone or via start_gui()."""
    from fastapi import FastAPI, Depends
    from fastapi.staticfiles import StaticFiles

    from gui.auth import AuthMiddleware
    from gui import api, ws

    app = FastAPI(title="SockPuppets", docs_url=None, redoc_url=None)

    auth = AuthMiddleware()
    api.init(server, auth)
    ws.init(server)

    app.include_router(api.auth_router)  # login/change-password — no auth required
    app.include_router(api.router, dependencies=[Depends(auth)])
    app.include_router(ws.router)

    static_dir = Path(__file__).parent / "static"
    if static_dir.is_dir():
        app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")

    return app


def start_gui(server, port: int = 13337):
    """Start the GUI server in a background thread."""
    global _gui_thread, _uvicorn_server

    try:
        import uvicorn
    except ImportError:
        raise ImportError("GUI requires fastapi and uvicorn: pip install -r requirements-gui.txt")

    app = create_app(server)

    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="warning")
    _uvicorn_server = uvicorn.Server(config)

    _gui_thread = threading.Thread(target=_uvicorn_server.run, daemon=True)
    _gui_thread.start()


def stop_gui():
    """Stop the GUI server."""
    global _uvicorn_server, _gui_thread
    if _uvicorn_server:
        _uvicorn_server.should_exit = True
        _gui_thread = None
        _uvicorn_server = None
