"""Main Textual application for SockPuppets TUI."""

import asyncio
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, Horizontal
from textual.widgets import Header, Footer, TabbedContent, TabPane, Static, Input
from textual.timer import Timer

from tui.widgets import AgentTable, ConsolePanel, EventLogPanel, GenerateDialog, StatusBar


class SockPuppetsTUI(App):
    """SockPuppets Terminal UI — Cobalt Strike layout in the terminal."""

    TITLE = "SockPuppets"
    CSS = """
    #agent-panel { height: 1fr; }
    #bottom-panel { height: 1fr; }
    AgentTable { height: 100%; }
    EventLogPanel { height: 100%; }
    ConsolePanel { height: 100%; }
    #status-bar { dock: bottom; height: 1; background: $surface; }
    .dialog-title { text-align: center; text-style: bold; padding: 1; }
    .label { width: 10; padding: 1; }
    .hint { padding: 1; color: $text-muted; }
    #generate-dialog { width: 60; height: 20; border: solid $primary; background: $surface; padding: 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("f1", "help", "Help"),
        Binding("f2", "generate", "Generate"),
        Binding("f5", "refresh", "Refresh"),
        Binding("k", "kill_agent", "Kill"),
        Binding("s", "sleep_agent", "Sleep"),
        Binding("u", "upgrade_agent", "Upgrade"),
        Binding("d", "downgrade_agent", "Downgrade"),
        Binding("p", "socks_agent", "SOCKS"),
    ]

    def __init__(self, server, **kwargs):
        super().__init__(**kwargs)
        self.server = server
        self.event_queue = None
        self.console_tabs = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Vertical(
            AgentTable(id="agent-table"),
            id="agent-panel",
        )
        yield TabbedContent(
            TabPane("Event Log", EventLogPanel(id="event-log"), id="tab-event-log"),
            id="bottom-panel",
        )
        yield StatusBar(id="status-bar")
        yield Footer()

    def on_mount(self):
        self.event_queue = self.server.events.subscribe()
        self.set_interval(1.0, self.refresh_agents)
        self.set_interval(0.5, self.poll_events)
        self.refresh_agents()

    def refresh_agents(self):
        table = self.query_one("#agent-table", AgentTable)
        agents = self.server.get_agent_list()
        active_ids = {a["id"] for a in self.server.get_active_agents()}
        table.update_agents(agents, active_ids)

        running = hasattr(self.server, "ws_server") and self.server.ws_server is not None
        self.query_one("#status-bar", StatusBar).update_status(running, len(agents))

    def poll_events(self):
        if not self.event_queue:
            return
        event_log = self.query_one("#event-log", EventLogPanel)
        while not self.event_queue.empty():
            try:
                event = self.event_queue.get_nowait()
                event_log.add_event(event.get("event", "unknown"), str(event))

                if event.get("event") == "agent_result":
                    agent_id = event.get("agent_id")
                    if agent_id in self.console_tabs:
                        self.console_tabs[agent_id].append(event.get("output", ""), "white")
            except Exception:
                break

    def on_data_table_row_selected(self, event):
        agent_id = str(event.row_key.value)
        self.open_console(agent_id)

    def open_console(self, agent_id: str):
        if agent_id not in self.console_tabs:
            panel = ConsolePanel(agent_id, id=f"console-{agent_id}")
            pane = TabPane(f"Console: {agent_id}", panel, id=f"tab-console-{agent_id}")
            self.query_one("#bottom-panel", TabbedContent).add_pane(pane)
            self.console_tabs[agent_id] = panel

        self.query_one("#bottom-panel", TabbedContent).active = f"tab-console-{agent_id}"

    def on_input_submitted(self, event: Input.Submitted):
        input_id = event.input.id or ""
        if input_id.startswith("console-input-"):
            agent_id = input_id.replace("console-input-", "")
            command = event.value.strip()
            if not command:
                return
            event.input.value = ""

            if agent_id in self.console_tabs:
                self.console_tabs[agent_id].append(f"agent[{agent_id}]> {command}", "bold cyan")

            asyncio.ensure_future(self._send_command(agent_id, command))

    async def _send_command(self, agent_id: str, command: str):
        try:
            result = await self.server.send_command_to_agent(agent_id, command)
            if agent_id in self.console_tabs:
                self.console_tabs[agent_id].append(result, "white")
        except Exception as e:
            if agent_id in self.console_tabs:
                self.console_tabs[agent_id].append(f"Error: {e}", "red")

    def _get_selected_agent_id(self) -> str | None:
        table = self.query_one("#agent-table", AgentTable)
        if table.cursor_row is not None:
            try:
                row_key = table.get_row_at(table.cursor_row)
                return str(table.rows[table.cursor_row].key.value) if hasattr(table.rows[table.cursor_row], 'key') else None
            except Exception:
                return None
        return None

    async def action_kill_agent(self):
        agent_id = self._get_selected_agent_id()
        if agent_id:
            result = await self.server.kill_agent(agent_id)
            self.query_one("#event-log", EventLogPanel).add_event("kill", result)
            self.refresh_agents()

    async def action_sleep_agent(self):
        agent_id = self._get_selected_agent_id()
        if agent_id:
            result = await self.server.set_beacon_interval(agent_id, 60)
            self.query_one("#event-log", EventLogPanel).add_event("sleep", result)

    async def action_upgrade_agent(self):
        agent_id = self._get_selected_agent_id()
        if agent_id:
            result = await self.server.upgrade_to_streaming(agent_id)
            self.query_one("#event-log", EventLogPanel).add_event("upgrade", result)
            self.refresh_agents()

    async def action_downgrade_agent(self):
        agent_id = self._get_selected_agent_id()
        if agent_id:
            result = await self.server.downgrade_to_beacon(agent_id, 60)
            self.query_one("#event-log", EventLogPanel).add_event("downgrade", result)
            self.refresh_agents()

    async def action_generate(self):
        result = await self.push_screen_wait(GenerateDialog())
        if result:
            try:
                from agent import AgentGenerator
                gen = AgentGenerator(patterns=result.get("patterns", "default"))
                agents = gen.generate_all(
                    c2_host=result["host"],
                    c2_port=int(result["port"]),
                    profile=result.get("profile", "default"),
                )
                event_log = self.query_one("#event-log", EventLogPanel)
                for agent_type, path in agents.items():
                    event_log.add_event("generate", f"{agent_type}: {path}")
            except Exception as e:
                self.query_one("#event-log", EventLogPanel).add_event("error", str(e))

    def action_refresh(self):
        self.refresh_agents()
