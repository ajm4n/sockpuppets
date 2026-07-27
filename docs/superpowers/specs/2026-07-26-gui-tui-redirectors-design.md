# SockPuppets GUI, TUI & Redirector Support

**Date:** 2026-07-26
**Status:** Approved

## Overview

Add three capabilities to sockpuppets:

1. **Web GUI** — a FastAPI-based operator dashboard served alongside the existing server, mirroring Cobalt Strike's layout with a Frutiger Aero visual aesthetic
2. **TUI** — a Textual-based terminal UI as an alternative to the `cmd.Cmd` CLI
3. **Redirector support** — infrastructure-layer traffic redirection with config generation

All three are optional. The CLI remains the default. Missing dependencies produce a helpful install message, not a crash.

## Architecture

### Optionality

Launch modes:

```
python main.py                  # CLI (default, no new deps)
python main.py --gui [port]     # Web GUI on :13337 (needs fastapi + uvicorn)
python main.py --tui            # TUI (needs textual)
```

Mid-session from the CLI:

```
sockpuppets> gui start [port]
sockpuppets> gui stop
```

Optional dependency groups:

```
# requirements-gui.txt
fastapi>=0.100.0
uvicorn>=0.23.0

# requirements-tui.txt
textual>=0.40.0
```

The core `requirements.txt` is unchanged. Lazy imports gate each feature.

### Shared API Layer

Both GUI and TUI consume the same `SockPuppetsServer` instance. The web GUI accesses it through a REST + WebSocket API. The TUI accesses it directly in-process.

### Event Bus

A lightweight pub/sub (`EventBus`) added to `SockPuppetsServer`. Existing methods fire events at key moments. Subscribers (GUI WebSocket clients, TUI widgets) receive them in real time.

```python
class EventBus:
    def __init__(self):
        self._subscribers: list[asyncio.Queue] = []

    def subscribe(self) -> asyncio.Queue:
        q = asyncio.Queue()
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        self._subscribers.remove(q)

    def emit(self, event: dict):
        for q in self._subscribers:
            q.put_nowait(event)
```

Event types:

| Event | Fired when |
|-------|-----------|
| `agent_registered` | New agent connects and registers |
| `agent_disconnected` | Agent WebSocket closes |
| `agent_result` | Command result received from agent |
| `agent_health_warning` | Beacon missed expected checkin window |
| `command_sent` | Operator sends command to agent |
| `command_queued` | Command queued for beacon agent |
| `server_started` | Server begins listening |
| `server_stopped` | Server shuts down |
| `operator_connected` | GUI/TUI operator joins |
| `operator_disconnected` | GUI/TUI operator leaves |

Each event includes a `timestamp` and `operator` field (who triggered it).

### Multi-Operator Auth

Token-based, derived from the existing encryption key. No user database.

- On GUI start, an operator token is derived: `HMAC-SHA256(encryption_key, "sockpuppets-gui-auth")`
- Operators authenticate via:
  - WebSocket: `GET /api/ws?token=<token>&name=<operator_name>`
  - REST: `Authorization: Bearer <token>` header
- The token is displayed in the CLI when the GUI starts so operators can copy it
- Every action is tagged with the operator name for the event log

## New File Structure

```
gui/
  __init__.py          # FastAPI app factory, mounts routes + static
  api.py               # REST endpoints
  ws.py                # WebSocket event bus endpoint
  auth.py              # Token derivation and middleware
  static/
    index.html         # Single-page app shell
    app.js             # All client-side logic (vanilla JS)
    style.css          # Frutiger Aero theme

tui/
  __init__.py          # Textual app factory, launch function
  app.py               # Main Textual App with screen composition
  widgets.py           # AgentTable, ConsolePanel, EventLog, GenerateDialog, StatusBar

redirectors/
  default.yaml         # Example: direct connection (no redirector)
  private/
    EXAMPLE.md         # Usage instructions for operator-specific redirector configs
```

## REST API

All endpoints under `/api/`. Static files served from `/`.

### Server Control

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| GET | `/api/server/status` | — | `{running, host, port, agent_count, uptime}` |
| POST | `/api/server/start` | `{host, port, key, ssl}` | `{status, message}` |
| POST | `/api/server/stop` | — | `{status, message}` |

### Agents

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| GET | `/api/agents` | — | `[{id, hostname, user, os, ip, mode, last_seen, health}]` |
| GET | `/api/agents/{id}` | — | `{...agent_info, health_warning, command_history}` |
| POST | `/api/agents/{id}/command` | `{command}` | `{output}` (streaming) or `{queued, message}` (beacon) |
| GET | `/api/agents/{id}/results` | `?clear=bool` | `[{command, output, timestamp}]` |
| POST | `/api/agents/{id}/kill` | — | `{status, message}` |
| POST | `/api/agents/{id}/sleep` | `{interval}` | `{status, message}` |
| POST | `/api/agents/{id}/upgrade` | — | `{status, message}` |
| POST | `/api/agents/{id}/downgrade` | `{interval}` | `{status, message}` |
| POST | `/api/agents/{id}/socks` | `{port}` | `{status, message}` |
| DELETE | `/api/agents/{id}` | — | `{status, message}` |

### Payload Generation

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| POST | `/api/generate` | `{host, port, key, beacon_mode, interval, jitter, amsi, etw, syscalls, inject, inject_target, sleep_obf, idle_encrypt, profile, patterns, redirector, compile, dll, shellcode, shellcode_format, target_os}` | `{agents: {type: filepath}}` |
| GET | `/api/profiles` | — | `[{name, description}]` |
| GET | `/api/patterns` | — | `[{name, description}]` |
| GET | `/api/download/{filename}` | — | File download from output/ |

### Redirectors

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| GET | `/api/redirectors` | — | `[{name, type, domain, backend, status}]` |
| GET | `/api/redirectors/{name}` | — | Full redirector config |
| POST | `/api/redirectors` | YAML config body | `{status, name}` |
| DELETE | `/api/redirectors/{name}` | — | `{status}` |
| POST | `/api/redirectors/{name}/deploy` | `{format}` | `{config_text}` where format is `apache`, `nginx`, `socat`, `iptables`, or `lambda` |

### Infrastructure

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| GET | `/api/infrastructure` | — | `{server: {...}, redirectors: [...], agents: [...], topology: [...]}` |

### WebSocket

| Endpoint | Protocol |
|----------|----------|
| `/api/ws?token=<token>&name=<operator>` | JSON event stream (see Event Bus above) |

## Web GUI Design

### Layout (Cobalt Strike mirror)

The web GUI is a single-page app with three horizontal zones:

1. **Top toolbar** — server controls, generate button, settings, operator list
2. **Main panel** — agent table (primary view, always dominant)
3. **Bottom tabbed panel** — console, event log, infrastructure view; resizable divider between main and bottom

```
┌──────────────────────────────────────────────────────────┐
│  [toolbar]  ● Server  │  + Generate  │  ⚙  │  Operators │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Agent Table (sortable, filterable)                      │
│  ID   Hostname   User   OS     Mode    Health  Last Seen │
│  ▸ a3f1 ...                                              │
│  ▸ c7d2 ...                                              │
│                                                          │
│  ══════════════ draggable divider ═══════════════════════ │
│  [Console: a3f1] [Event Log] [Infrastructure]            │
│                                                          │
│  agent[a3f1]> _                                          │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

Right-click on agent row opens a frosted-glass context menu: Interact, Sleep, Inject, SOCKS Proxy, Upgrade/Downgrade, Kill.

Interacting opens a console tab in the bottom panel. Multiple agent consoles can be open simultaneously as tabs.

Generate opens as a modal overlay.

### Visual Design — Frutiger Aero

**Core aesthetic:** Frosted glass panels, soft gradients, glossy interactive elements, rounded surfaces, depth through layering. Light mode primary.

**Surfaces:**
- Panel backgrounds: `rgba(255, 255, 255, 0.6)` with `backdrop-filter: blur(12px)`
- Dark mode variant: `rgba(20, 20, 30, 0.7)` with same blur
- Background: soft gradient wash (sky blue `#E3F2FD` → teal `#E0F7FA`)
- Dark mode background: deep navy `#0D1117` → dark teal `#0A1929`

**Colors:**
- Primary: sky blue `#4FC3F7` → teal `#00BCD4`
- Active/healthy: fresh green `#66BB6A`
- Warning/stale: warm amber `#FFA726`
- Dead/error: coral `#EF5350`
- Text: dark charcoal `#263238` (light mode), `#E0E0E0` (dark mode)

**Elements:**
- Buttons: subtle top-half highlight gradient (Vista-era glass), `border-radius: 8px`
- Panels: `border-radius: 12px`, soft shadow `0 8px 32px rgba(0,0,0,0.1)`
- Badges/pills: `border-radius: 20px`
- Status dots: glow effect via `box-shadow: 0 0 8px <color>`
- Context menus: frosted glass dropdown with rounded corners

**Typography:**
- UI text: `-apple-system, 'Segoe UI', sans-serif`
- Terminal/output: `'SF Mono', 'Cascadia Code', 'Fira Code', monospace`

**Motion:**
- Panel transitions: `ease-in-out 200ms`
- Agent health dots: gentle pulse animation
- New events: slide into log from top
- Modal overlays: fade + scale from 95% to 100%

**Dark mode:** Toggle in toolbar. Shifts frosted glass to dark translucent. Keeps the same color accents but on darker surfaces. Both modes respect `prefers-color-scheme` by default.

## TUI Design

### Layout

Mirrors the Cobalt Strike split-panel layout in the terminal:

```
┌─ SockPuppets ──────────────────── Server: ● 0.0.0.0:8443 ─┐
│  Agents (3)                                    [F1] Help    │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ ID     Hostname     User    OS      Mode     Last Seen ││
│  │ ▸a3f1  DESKTOP-1    admin   Win11   BEACON   12s ago   ││
│  │  c7d2  web-srv      root    Ubuntu  STREAM   now       ││
│  │  9e4a  LAPTOP-3     jdoe    Win10   BEACON   ⚠ 5m ago  ││
│  └─────────────────────────────────────────────────────────┘│
│ ─────────────────────────────────────────────────────────── │
│  [Console: a3f1] [Event Log] [Generate]                     │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ agent[a3f1]> whoami                                     ││
│  │ desktop-1\admin                                         ││
│  │ agent[a3f1]> _                                          ││
│  └─────────────────────────────────────────────────────────┘│
│  [k]ill [s]leep [u]pgrade [d]owngrade [p]roxy    q: quit   │
└─────────────────────────────────────────────────────────────┘
```

### Key Bindings

| Key | Action |
|-----|--------|
| `Tab` / arrows | Navigate agent table |
| `Enter` | Interact with selected agent (opens console tab) |
| `k` | Kill agent (with confirmation) |
| `s` | Set sleep interval |
| `u` | Upgrade to streaming |
| `d` | Downgrade to beacon |
| `p` | Start SOCKS proxy |
| `F1` | Help overlay |
| `F2` | Generate payload dialog |
| `F3` | Infrastructure view |
| `F5` | Refresh |
| `q` | Quit (with confirmation) |

### Textual Widgets

| Widget | Purpose |
|--------|---------|
| `AgentTable` | `DataTable` with live-updating rows, color-coded health indicators |
| `ConsolePanel` | `RichLog` + `Input` field, per-agent tabs, streaming output |
| `EventLog` | Scrolling `RichLog` with operator/event-type filtering |
| `GenerateDialog` | Modal form with radio buttons, text inputs, toggle switches |
| `InfrastructureView` | ASCII topology diagram of server → redirectors → agents |
| `StatusBar` | Footer showing server status, operator count, keybinding hints |

### Color Scheme

Textual default dark theme. Green/yellow/red for agent health. Cyan for active selections. No attempt to replicate Frutiger Aero — clean terminal aesthetics.

## Redirector Support

### Redirector Config Format

YAML files in `redirectors/`, with `redirectors/private/` gitignored for operator-specific configs.

```yaml
name: cdn-redir
type: https                       # https, dns, cloud-function
listen: 0.0.0.0:443
backend: 10.0.0.5:8443            # real team server
domain: cdn-assets.example.com
trusted: true                      # server trusts X-Forwarded-For

profile: cdn-cloudfront            # filter traffic against this C2 profile
allow_user_agents:
  - "Mozilla/5.0*"

decoy: redirect                    # redirect, serve-page, 404
decoy_target: https://www.example.com
```

### Integration Points

**Agent generation:** `generate host port --redirector=cdn-redir` makes the agent connect to the redirector's domain/port instead of the team server directly. Multiple redirectors supported — ties into the existing `HostRotator` in profiles for rotation.

**Server-side trust:** `SockPuppetsServer` accepts a `trusted_redirectors` list of IPs/CIDRs. Connections from trusted redirectors read `X-Forwarded-For` for the real agent source IP. Untrusted sources use the socket IP as-is.

**Config generation:** `POST /api/redirectors/{name}/deploy` with `{format: "apache"}` returns a ready-to-deploy config. Supported formats:

| Format | Output |
|--------|--------|
| `apache` | `.htaccess` with `mod_rewrite` rules matching C2 profile URIs and user-agents |
| `nginx` | `server {}` block with `proxy_pass`, URI filtering, user-agent checks |
| `socat` | One-liner for quick TCP forwarding |
| `iptables` | NAT rules for raw TCP redirection |
| `lambda` | AWS Lambda function stub with API Gateway config |

**Private directory:** `redirectors/private/` is added to `.gitignore`, same convention as profiles/patterns/transforms.

### CLI Integration

```
sockpuppets> generate 10.0.0.5 8443 --redirector=cdn-redir
[*] Agent will connect via: cdn-assets.example.com:443
[*] Generating agents...
```

New CLI command:

```
sockpuppets> redirectors                    # list configured redirectors
sockpuppets> redirector-deploy cdn-redir nginx   # print nginx config
```

## Modified Files

| File | Change |
|------|--------|
| `main.py` | Add `--gui`, `--tui` flags. Add `gui start/stop` and `redirectors` CLI commands. Lazy-import gui/tui packages. |
| `server.py` | Add `EventBus` to `SockPuppetsServer`. Add `trusted_redirectors` param. Fire events from `register_agent`, `handle_agent`, `send_command_to_agent`, `kill_agent`, etc. Add `X-Forwarded-For` parsing in agent handler. |
| `agent.py` | Add `redirector` param to `generate_all()` and `generate_python_agent()`. Resolve redirector config to get the connect-to address. |
| `requirements.txt` | Unchanged (core deps only — `pyyaml` already present from profiles work, used for redirector configs). |
| `.gitignore` | Add `redirectors/private/`. |

## New Files

| File | Purpose |
|------|---------|
| `gui/__init__.py` | FastAPI app factory, mounts API routes and static files |
| `gui/api.py` | REST endpoint handlers |
| `gui/ws.py` | WebSocket event bus endpoint |
| `gui/auth.py` | Token derivation, auth middleware |
| `gui/static/index.html` | SPA shell |
| `gui/static/app.js` | Client-side logic |
| `gui/static/style.css` | Frutiger Aero theme |
| `tui/__init__.py` | Launch function with dependency check |
| `tui/app.py` | Main Textual App |
| `tui/widgets.py` | Custom widgets |
| `redirectors/default.yaml` | Direct connection config (no redirector) |
| `redirectors/private/EXAMPLE.md` | Usage instructions |
| `requirements-gui.txt` | FastAPI + uvicorn |
| `requirements-tui.txt` | Textual |
