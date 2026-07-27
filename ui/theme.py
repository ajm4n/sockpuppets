"""SockPuppets TUI theme and styled output."""

from rich.console import Console
from rich.theme import Theme
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich import box

THEME = Theme({
    "info": "cyan",
    "success": "bold green",
    "warning": "bold yellow",
    "error": "bold red",
    "highlight": "bold magenta",
    "dim": "dim white",
    "agent.active": "bold green",
    "agent.dead": "bold red",
    "agent.beacon": "yellow",
    "agent.stream": "cyan",
    "transport.ws": "blue",
    "transport.http": "yellow",
    "transport.https": "green",
})

console = Console(theme=THEME)

BANNER = r"""[bold cyan]
   ____             _    ____                         _
  / ___|  ___   ___| | _|  _ \ _   _ _ __  _ __   ___| |_ ___
  \___ \ / _ \ / __| |/ / |_) | | | | '_ \| '_ \ / _ \ __/ __|
   ___) | (_) | (__|   <|  __/| |_| | |_) | |_) |  __/ |_\__ \
  |____/ \___/ \___|_|\_\_|    \__,_| .__/| .__/ \___|\__|___/
                                    |_|   |_|
[/bold cyan][dim]                    C2 Framework v2.0
                    by AJ Hammond @ajm4n[/dim]
"""


def print_banner():
    console.print(BANNER)


def print_status(msg, style="info"):
    icons = {"info": "ℹ", "success": "✓", "warning": "⚠", "error": "✗"}
    icon = icons.get(style, "•")
    console.print(f"  [{style}]{icon}[/{style}] {msg}")


def print_agents_table(agents, active_ids):
    if not agents:
        print_status("No agents connected", "warning")
        return

    table = Table(
        title="Connected Agents",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold white",
        show_lines=True,
    )
    table.add_column("Status", width=3, justify="center")
    table.add_column("ID", style="bold")
    table.add_column("Hostname")
    table.add_column("Username")
    table.add_column("OS")
    table.add_column("Transport", justify="center")
    table.add_column("Mode", justify="center")
    table.add_column("Last Seen")

    for agent in agents:
        is_active = agent['id'] in active_ids
        status = "[agent.active]●[/]" if is_active else "[agent.dead]●[/]"
        transport = agent.get('transport', 'ws').upper()
        transport_style = {
            'WEBSOCKET': 'transport.ws', 'HTTP': 'transport.http', 'HTTPS': 'transport.https'
        }.get(transport, 'dim')
        mode = agent['mode'].upper()
        mode_style = 'agent.beacon' if mode == 'BEACON' else 'agent.stream'

        table.add_row(
            status,
            agent['id'],
            agent['hostname'],
            agent['username'],
            agent['os'],
            f"[{transport_style}]{transport}[/]",
            f"[{mode_style}]{mode}[/]",
            agent['last_seen'],
        )

    console.print(table)


def print_listeners_table(listeners):
    if not listeners:
        print_status("No active listeners", "warning")
        return

    table = Table(
        title="Active Listeners",
        box=box.ROUNDED,
        border_style="green",
        header_style="bold white",
    )
    table.add_column("Type", style="bold")
    table.add_column("Host")
    table.add_column("Port", justify="right")
    table.add_column("Started")

    for l in listeners:
        type_style = {
            'websocket': 'transport.ws', 'http': 'transport.http', 'https': 'transport.https'
        }.get(l['type'], 'dim')
        table.add_row(
            f"[{type_style}]{l['type'].upper()}[/]",
            l['host'],
            str(l['port']),
            l['started_at'],
        )

    console.print(table)


def print_help_panel():
    help_sections = {
        "Server": [
            ("start [type] [host] [port]", "Start listener (ws/http/https)"),
            ("listeners", "List active listeners"),
            ("stop [type]", "Stop listener(s)"),
        ],
        "Agents": [
            ("agents / puppets", "List connected agents"),
            ("interact <id>", "Interact with agent"),
            ("remove <id>", "Remove dead agent"),
        ],
        "Generate": [
            ("generate <host> <port> [opts]", "Generate agent payloads"),
            ("  --lang=go|rust|python|c|csharp", "Select language"),
            ("  --transport=http|https|ws", "Select transport"),
            ("  --beacon --interval=N", "Beacon mode"),
        ],
        "Other": [
            ("debug [on|off]", "Toggle debug logging"),
            ("clear", "Clear screen"),
            ("exit", "Exit"),
        ],
    }

    panels = []
    for title, commands in help_sections.items():
        lines = []
        for cmd, desc in commands:
            lines.append(f"  [bold]{cmd}[/bold]\n    [dim]{desc}[/dim]")
        panel = Panel(
            "\n".join(lines),
            title=f"[bold]{title}[/bold]",
            border_style="cyan",
            padding=(0, 1),
        )
        panels.append(panel)

    console.print(Columns(panels, equal=True, expand=True))


def print_generate_results(results):
    table = Table(
        title="Generated Agents",
        box=box.ROUNDED,
        border_style="green",
        header_style="bold white",
    )
    table.add_column("Type", style="bold")
    table.add_column("Path")
    table.add_column("Status", justify="center")

    for agent_type, path in results.items():
        if isinstance(path, str) and path.startswith('Error'):
            table.add_row(agent_type.upper(), path, "[error]✗[/]")
        else:
            table.add_row(agent_type.upper(), str(path), "[success]✓[/]")

    console.print(table)


def print_interact_banner(agent_id, agent_info):
    mode = agent_info['mode'].upper()
    transport = agent_info.get('transport', 'websocket').upper()

    info_text = (
        f"[bold]Agent:[/bold] {agent_id}\n"
        f"[bold]Host:[/bold]  {agent_info['hostname']}\n"
        f"[bold]User:[/bold]  {agent_info['username']}\n"
        f"[bold]OS:[/bold]    {agent_info['os']}\n"
        f"[bold]Mode:[/bold]  {mode} | [bold]Transport:[/bold] {transport}"
    )

    if mode == 'BEACON':
        info_text += f"\n[bold]Interval:[/bold] {agent_info.get('beacon_interval', 'N/A')}s"

    console.print(Panel(
        info_text,
        title=f"[bold cyan]Interacting with {agent_id}[/bold cyan]",
        border_style="cyan",
        padding=(0, 2),
    ))

    cmds = [
        "[bold]back[/bold] — return to menu",
        "[bold]kill[/bold] — terminate agent",
        "[bold]sleep N[/bold] — set interval",
        "[bold]upgrade[/bold] — switch to streaming",
        "[bold]socks PORT[/bold] — SOCKS proxy",
    ]
    console.print(f"  [dim]Commands: {' | '.join(cmds)}[/dim]")


def print_command_result(command, output):
    console.print(Panel(
        output,
        title=f"[bold green]{command}[/bold green]",
        border_style="green",
        padding=(0, 1),
    ))
