"""Custom Textual widgets for SockPuppets TUI."""

from textual.widgets import DataTable, RichLog, Input, Static, Footer, Header, TabbedContent, TabPane
from textual.containers import Vertical, Horizontal
from textual.screen import ModalScreen
from textual.widget import Widget
from rich.text import Text


class AgentTable(DataTable):
    """Live-updating agent table with health indicators."""

    def on_mount(self):
        self.add_columns("ID", "Hostname", "User", "OS", "IP", "Mode", "Sleep", "Health", "Last Seen")
        self.cursor_type = "row"

    @staticmethod
    def _format_sleep(agent: dict) -> Text:
        if agent.get("mode") != "beacon":
            return Text("—", style="dim")
        s = agent.get("beacon_interval", 60)
        j = agent.get("beacon_jitter", 0)
        label = f"{s}s"
        if j > 0:
            label += f" {j}% jitter"
        return Text(label, style="cyan")

    @staticmethod
    def _format_ago(iso_str: str) -> Text:
        if not iso_str:
            return Text("")
        from datetime import datetime
        try:
            then = datetime.fromisoformat(iso_str)
        except (ValueError, TypeError):
            return Text(iso_str)
        diff = int((datetime.now() - then).total_seconds())
        if diff < 0:
            diff = 0
        if diff < 60:
            return Text(f"{diff}s ago", style="green")
        if diff < 3600:
            m, s = divmod(diff, 60)
            return Text(f"{m}m {s}s ago", style="yellow" if diff > 120 else "green")
        h, rem = divmod(diff, 3600)
        m = rem // 60
        return Text(f"{h}h {m}m ago", style="red")

    def update_agents(self, agents: list, active_ids: set):
        self.clear()
        for agent in agents:
            health = Text("●", style="green") if agent["id"] in active_ids else Text("●", style="red")
            mode = Text("BEACON", style="yellow bold") if agent["mode"] == "beacon" else Text("STREAM", style="green bold")
            self.add_row(
                agent["id"],
                agent.get("hostname", "Unknown"),
                agent.get("username", "Unknown"),
                agent.get("os", "Unknown"),
                agent.get("ip", "Unknown"),
                mode,
                self._format_sleep(agent),
                health,
                self._format_ago(agent.get("last_seen", "")),
                key=agent["id"],
            )


class ConsolePanel(Vertical):
    """Terminal-style console for agent interaction."""

    def __init__(self, agent_id: str, **kwargs):
        super().__init__(**kwargs)
        self.agent_id = agent_id

    def compose(self):
        yield RichLog(id=f"console-log-{self.agent_id}", wrap=True, markup=True)
        yield Input(placeholder=f"agent[{self.agent_id}]> ", id=f"console-input-{self.agent_id}")

    def append(self, text: str, style: str = ""):
        log = self.query_one(f"#console-log-{self.agent_id}", RichLog)
        if style:
            log.write(Text(text, style=style))
        else:
            log.write(text)


class EventLogPanel(RichLog):
    """Scrolling event log."""

    def add_event(self, event_type: str, message: str):
        from datetime import datetime
        time_str = datetime.now().strftime("%H:%M:%S")
        style_map = {
            "agent_registered": "green",
            "agent_disconnected": "red",
            "command_sent": "cyan",
            "command_queued": "yellow",
            "error": "red bold",
        }
        style = style_map.get(event_type, "white")
        self.write(Text(f"[{time_str}] [{event_type}] {message}", style=style))


class GenerateDialog(ModalScreen):
    """Modal form for payload generation."""

    BINDINGS = [("escape", "dismiss", "Close")]

    def compose(self):
        yield Vertical(
            Static("Generate Payload", classes="dialog-title"),
            Horizontal(
                Static("Host: ", classes="label"),
                Input(placeholder="10.0.0.5", id="gen-host"),
                Static("Port: ", classes="label"),
                Input(placeholder="8443", id="gen-port"),
            ),
            Horizontal(
                Static("Profile: ", classes="label"),
                Input(placeholder="default", id="gen-profile", value="default"),
                Static("Patterns: ", classes="label"),
                Input(placeholder="default", id="gen-patterns", value="default"),
            ),
            Horizontal(
                Static("[Enter] Generate  [Esc] Cancel", classes="hint"),
            ),
            id="generate-dialog",
        )

    def on_input_submitted(self, event):
        if event.input.id == "gen-port":
            host = self.query_one("#gen-host", Input).value
            port = self.query_one("#gen-port", Input).value
            profile = self.query_one("#gen-profile", Input).value
            patterns = self.query_one("#gen-patterns", Input).value
            self.dismiss({"host": host, "port": port, "profile": profile, "patterns": patterns})


class StatusBar(Static):
    """Footer status bar showing server state and keybindings."""

    def update_status(self, server_running: bool, agent_count: int, operators: int = 1):
        status = "[green]●[/green] Running" if server_running else "[red]●[/red] Stopped"
        self.update(f" Server: {status}  |  Agents: {agent_count}  |  Operators: {operators}  |  [dim]F1:Help  F2:Generate  q:Quit[/dim]")
