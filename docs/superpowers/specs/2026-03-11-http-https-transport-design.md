# HTTP/HTTPS Transport Support for SockPuppets C2

**Date:** 2026-03-11
**Status:** Approved
**Scope:** Add HTTP and HTTPS as first-class transport options alongside the existing WebSocket transport.

---

## 1. Goals

- Add HTTP and HTTPS listeners to SockPuppets so agents can callback over standard web traffic.
- Provide HTTP/HTTPS agent templates for all supported languages (Python, PowerShell, JavaScript, HTA).
- Disguise HTTP traffic as normal web activity by default, with architecture supporting malleable profiles later.
- Support long-polling for near-real-time interaction over HTTP, with optional upgrade to WebSocket for full streaming.
- Auto-generate self-signed TLS certificates for HTTPS, with option to supply custom certs.
- Maintain full backward compatibility with existing WebSocket functionality.

## 2. Non-Goals

- Malleable C2 profile engine (future work; architecture supports it but not implemented in this pass).
- HTTP/2 or HTTP/3 support.
- Domain fronting.

---

## 3. Architecture

### 3.1 Listener Model

Three listener types run as independent asyncio tasks sharing a single `SockPuppetsServer` instance:

| Listener | Library | Port | TLS |
|----------|---------|------|-----|
| WebSocket | `websockets` (existing) | Operator-chosen (default 8443) | No (existing behavior) |
| HTTP | `aiohttp` | Operator-chosen (e.g., 8080) | No |
| HTTPS | `aiohttp` | Operator-chosen (e.g., 443) | Yes |

All listeners share the same `self.agents` dict, command queues, response queues, and encryption infrastructure.

### 3.2 Agent Class Changes

```python
class Agent:
    def __init__(self, agent_id, metadata):
        self.transport = None          # WebSocket object or HTTP session ID
        self.transport_type = 'websocket'  # 'websocket', 'http', or 'https'
        self.http_response_queue = asyncio.Queue()  # Commands waiting for HTTP poll pickup
        # ... all existing fields unchanged
```

- `transport_type` tracks how the agent communicates.
- For HTTP agents, `transport` stores a session identifier string (not a connection object, since HTTP is stateless).
- `http_response_queue` holds commands waiting to be delivered in the next HTTP poll response.
- An HTTP agent is considered "active" if `last_seen` is within `2 * beacon_interval` (beacon) or 90 seconds (long-poll).

### 3.3 HTTP Routes (Disguised)

| Purpose | Route | Method | Description |
|---------|-------|--------|-------------|
| Register | `/submit-form` | POST | Agent registration, looks like form submission |
| Checkin/poll | `/api/v1/update` | POST | Beacon checkin or long-poll, looks like update check |
| Send results | `/upload` | POST | Command results, looks like file upload |
| Heartbeat | `/health` | GET | Keep-alive, looks like health check |
| WebSocket upgrade | `/ws` | GET (upgrade) | Optional WS upgrade endpoint on HTTP listener |

All POST bodies contain the XOR+Base64 encrypted JSON payload. Responses use `Content-Type: text/html` headers with encrypted data in the body.

---

## 4. HTTP Communication Protocol

### 4.1 Beacon Mode

```
1. Agent POST /submit-form → encrypted {type: 'register', metadata: {...}}
   Server responds → encrypted {type: 'registered', agent_id: 'abc12345'}

2. Agent sleeps for beacon_interval ± jitter

3. Agent POST /api/v1/update → encrypted {type: 'checkin', agent_id: '...', results: [...]}
   Server responds → encrypted {type: 'commands', commands: [...]}
   (or {type: 'no_commands'} if queue is empty)

4. Agent executes commands offline, stores results

5. Repeat from step 2
```

Single HTTP round-trip per beacon cycle. Results from the previous cycle are sent with each checkin.

### 4.2 Long-Polling (Streaming Equivalent)

```
1. Agent POST /submit-form → register (same as beacon)

2. Agent POST /api/v1/update → encrypted checkin
   Server HOLDS connection open for up to 30 seconds waiting for command_queue

3a. Command arrives → server responds with encrypted command
    Agent executes, POST /upload with result, immediately re-polls (goto 2)

3b. 30 second timeout → server responds with {type: 'no_commands'}
    Agent immediately re-polls (goto 2)
```

Effective latency: near-instant when commands are queued, 30s max idle.

### 4.3 WebSocket Upgrade

When operator runs `upgrade` on an HTTP/HTTPS agent:

1. Server queues `{type: 'upgrade_websocket', ws_host: '...', ws_port: ...}` command.
2. Agent receives it in next poll response.
3. Agent opens WebSocket connection to `ws://host:port/ws`, sends checkin with existing `agent_id`.
4. Server recognizes agent ID, updates `transport_type` to `'websocket'`.
5. Agent is now fully streaming over WebSocket.

If WebSocket connection fails (firewall, etc.), agent sends `{type: 'upgrade_failed'}` via HTTP and continues polling.

---

## 5. TLS Certificate Handling

- On `start https <port>`, server checks for `certs/server.pem` and `certs/server.key`.
- If found, uses them.
- If not found, auto-generates a self-signed certificate and writes it to `certs/`.
- Operator can specify custom certs: `start https <host> <port> --cert=path/to/cert.pem --certkey=path/to/key.pem`.
- Agent templates have `{{VERIFY_SSL}}` placeholder, defaulting to `False` for self-signed certs.

---

## 6. Agent Templates

### 6.1 New Template Files

| Template | File | Transport Library |
|----------|------|-------------------|
| Python HTTP full | `templates/agent_http_template.py` | `urllib.request` (stdlib) |
| Python HTTP beacon minimal | `templates/agent_http_beacon_minimal.py` | `urllib.request` (stdlib) |
| PowerShell HTTP | `templates/agent_http_template.ps1` | `Invoke-WebRequest` / `System.Net.WebClient` |
| JavaScript HTTP | `templates/agent_http_template.js` | `http`/`https` Node.js stdlib |
| HTA HTTP | `templates/agent_http_template.hta` | `MSXML2.ServerXMLHTTP` |

### 6.2 Template Placeholders

Existing: `{{C2_HOST}}`, `{{C2_PORT}}`, `{{ENCRYPTION_KEY}}`, `{{BEACON_MODE}}`, `{{BEACON_INTERVAL}}`, `{{BEACON_JITTER}}`

New: `{{C2_SCHEME}}` (http/https), `{{VERIFY_SSL}}` (True/False)

### 6.3 Python HTTP Agent

- Zero external dependencies — uses only `urllib.request` from stdlib. Major operational advantage over WebSocket agents that require `websockets` pip package.
- Supports beacon mode, long-poll mode, and WebSocket upgrade.
- Same `execute_command()`, `get_metadata()`, `simple_encrypt()`/`simple_decrypt()` as WS agent.
- Full polymorphic obfuscation pipeline applies identically.

### 6.4 PowerShell HTTP Agent

- Uses `Invoke-WebRequest` (PS 3.0+) with `-SkipCertificateCheck` for self-signed HTTPS.
- Beacon mode only (long-polling adds complexity in PS for minimal benefit).
- WebSocket upgrade supported via `System.Net.WebSockets.ClientWebSocket`.

### 6.5 JavaScript HTTP Agent

- Uses Node.js `http`/`https` built-in modules — no `ws` dependency needed.
- Supports beacon and long-poll modes.

### 6.6 HTA HTTP Agent

- Extends the existing partial HTA implementation.
- Beacon mode only (HTA can't do long-poll or WebSocket).
- Full register → checkin → execute → respond cycle.

---

## 7. Agent Generator Updates (`agent.py`)

### 7.1 New Parameter

`transport` parameter added to `generate_python_agent()`, `generate_all()`, and all per-language generators. Values: `'websocket'` (default), `'http'`, `'https'`.

### 7.2 Template Selection

When `transport='http'` or `'https'`, generators load from `agent_http_*.py/ps1/js/hta` templates instead of the WebSocket versions.

### 7.3 Placeholder Substitution

- `{{C2_SCHEME}}` → `'http'` or `'https'`
- `{{VERIFY_SSL}}` → `'True'` or `'False'`

### 7.4 Output Naming

Output files include transport: `agent_<hash>_https_beacon60s_windows.py`

### 7.5 Obfuscation

Same polymorphic pipeline. Obfuscator updated to also randomize HTTP-specific function names (`http_request`, `poll_for_commands`, `send_results`, etc.).

### 7.6 Compilation, DLL, Shellcode

All work unchanged — they compile whatever Python agent was generated (HTTP or WS).

### 7.7 One-liners

Already work with HTTP URLs. No changes needed to `generate_oneliners()`.

---

## 8. CLI Updates (`main.py`)

### 8.1 Listener Management

```
start [host] [port] [--key=K]                                    # WebSocket (default, backward compatible)
start http [host] [port] [--key=K]                               # HTTP listener
start https [host] [port] [--key=K] [--cert=PATH] [--certkey=PATH]  # HTTPS listener
```

Multiple listeners can run simultaneously on different ports.

### 8.2 New Commands

- `listeners` — show all active listeners (type, host, port, status)
- `stop <type>` — stop specific listener (`stop http`, `stop https`, `stop ws`). `stop` alone stops all.

### 8.3 Generate Command

```
generate <host> <port> --transport https [other existing options]
```

`--transport` defaults to `websocket` if omitted (backward compatible).

### 8.4 Agent Display

Agent info shows transport type: `[STREAM/WS]`, `[STREAM/HTTPS]`, `[BEACON/HTTP]`, `[BEACON/WS]`, etc.

### 8.5 Interact

Works identically regardless of transport. Commands go through the same queue system. `upgrade` on an HTTP agent queues the WebSocket upgrade command.

### 8.6 Help

- New `help transport` topic.
- Updated `help generate` with `--transport` flag.
- Updated main help with new `start` syntax and `listeners` command.

---

## 9. Error Handling

- **Upgrade failure:** HTTP agent that can't connect to WS port retries once, then sends `upgrade_failed` and continues HTTP polling.
- **HTTP agent liveness:** Agent considered active if `last_seen` within `2 * beacon_interval` (beacon) or 90 seconds (long-poll). `check_agent_health()` works as-is.
- **Concurrent listeners:** Each runs as separate asyncio task. `stop` without args stops all. `stop http`/`stop https`/`stop ws` stops specific ones.
- **Self-signed cert:** Auto-generated once, persisted in `certs/`, reused on subsequent starts.
- **Backward compatibility:** All defaults remain WebSocket. Existing commands without `--transport` work identically. Existing templates untouched.

---

## 10. Dependencies

- **New:** `aiohttp` — async HTTP server framework. Well-maintained, async-native, supports TLS, routing.
- **Existing unchanged:** `websockets`, `asyncio`, standard library.

---

## 11. File Changes Summary

| File | Change |
|------|--------|
| `server.py` | Add HTTP/HTTPS listener handlers, route definitions, long-poll logic, TLS cert management, listener tracking |
| `agent.py` | Add `transport` parameter, HTTP template loading, updated placeholder substitution, filename updates |
| `main.py` | New `start http/https` syntax, `listeners` command, `--transport` flag on generate, updated help |
| `templates/agent_http_template.py` | **New** — Python HTTP/HTTPS agent (full) |
| `templates/agent_http_beacon_minimal.py` | **New** — Python HTTP/HTTPS beacon (staged) |
| `templates/agent_http_template.ps1` | **New** — PowerShell HTTP/HTTPS agent |
| `templates/agent_http_template.js` | **New** — JavaScript HTTP/HTTPS agent |
| `templates/agent_http_template.hta` | **New** — HTA HTTP agent (complete version) |
| `certs/` | **New directory** — auto-generated or user-provided TLS certs |
| `requirements.txt` | Add `aiohttp` |
