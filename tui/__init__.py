"""SockPuppets TUI — optional Textual-based terminal interface."""


def launch_tui(server):
    """Launch the Textual TUI. Blocks until quit."""
    try:
        from tui.app import SockPuppetsTUI
    except ImportError:
        raise ImportError("TUI requires textual: pip install -r requirements-tui.txt")
    app = SockPuppetsTUI(server)
    app.run()
