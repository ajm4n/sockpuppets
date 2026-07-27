# Evasion Hardening Design Spec

**Date:** 2026-07-26
**Status:** Draft
**Scope:** 7 evasion features + streaming-mode sleep obfuscation

---

## Overview

Add production-grade evasion capabilities to sockpuppets: real encryption, AMSI/ETW bypasses, syscall-based injection, sleep obfuscation (both beacon and streaming modes), and full malleable C2 profiles. All Windows-specific features are delivered as pure ctypes (Python) or inline C#/.NET (PowerShell) — no external binaries dropped to disk.

## Architecture

New `evasion/` package alongside existing `agent.py`, `server.py`, and `templates/`.

```
evasion/
  __init__.py          # EvasionConfig dataclass, feature registry
  crypto.py            # AES-256-GCM for all languages
  amsi.py              # AMSI bypass techniques
  etw.py               # ETW patching
  syscalls.py          # Direct/indirect syscall stub generation
  injection.py         # Process injection techniques
  sleep_obf.py         # Sleep obfuscation (beacon + streaming)
  profiles.py          # Malleable C2 profile engine + parser
profiles/
  default.yaml         # Plain WebSocket (current behavior)
  slack-api.yaml       # Slack API masquerade
  cdn-cloudfront.yaml  # CloudFront domain fronting
  microsoft-graph.yaml # MS Graph API masquerade
  generic-cdn.yaml     # Generic static asset requests
```

Each evasion module exposes a `generate_code(lang, config)` function returning language-specific code snippets. `agent.py`'s generator calls these and injects output into templates via `{{EVASION_*}}` placeholders.

The generator gains new CLI flags:
```
generate python --amsi --etw --syscalls=indirect --inject=hollowing \
  --sleep-obf=ekko --profile=slack-api --host=10.0.0.1 --port=443
```

All evasion flags are optional and composable. Omitting a flag means that feature is not included in the generated agent.

---

## Feature 1: AES-256-GCM Encryption

**Replaces:** XOR "encryption" across all agents and the server.

**Breaking change:** Old XOR agents are incompatible with the new server. The `generate` command prints a deprecation warning.

### Wire Format

```
[4 bytes]  payload length (big-endian, network order)
[12 bytes] nonce (os.urandom, unique per message)
[16 bytes] GCM authentication tag
[N bytes]  AES-256-GCM ciphertext
```

### Key Derivation

HKDF-SHA256 from the shared secret (`--key` flag):
- Input key material: the raw `--key` value
- Salt: agent_id (assigned at registration)
- Info context: `b"sockpuppets-c2s"` or `b"sockpuppets-s2c"`
- Output: two 256-bit subkeys (client→server, server→client)

During registration (before agent_id is assigned), a bootstrap key derived with a static salt is used for the initial register/ack exchange. Once the agent receives its ID, both sides derive the session keys.

### Per-Language Implementation

| Language | Library / API | Notes |
|---|---|---|
| Python | `cryptography` (preferred) or `PyCryptodome` | Generator detects availability, templates accordingly |
| PowerShell | `.NET System.Security.Cryptography.AesGcm` | .NET Core 3.0+ / .NET 5+. Fallback: AES-CBC + HMAC-SHA256 for older targets |
| JavaScript | Built-in `crypto.createCipheriv('aes-256-gcm')` | Zero dependencies |
| HTA (VBScript) | COM `System.Security.Cryptography.AesManaged` | AES-CBC + HMAC via COM objects, no child process |

### Server Changes

- `server.py`: Replace `simple_encrypt`/`simple_decrypt` with AES-GCM methods
- `cryptography` becomes a hard dependency in `requirements.txt`
- Bootstrap key handling for pre-registration messages

---

## Feature 2: AMSI Bypass

**Applies to:** Python agents (via ctypes), PowerShell agents (via .NET reflection / inline C#).
**Windows only.** Gated by `sys.platform == 'win32'` check.

### Techniques (randomly selected at generation time)

**A. Patch `AmsiScanBuffer`:**
Overwrite the first 6 bytes of `amsi.dll!AmsiScanBuffer` with `mov eax, 0x80070057; ret` — forces `AMSI_RESULT_CLEAN` on every scan.

```
VirtualProtect(addr, 6, PAGE_EXECUTE_READWRITE, &old)
memcpy(addr, "\xb8\x57\x00\x07\x80\xc3", 6)
```

**B. `amsiInitFailed` flag:**
Set the `amsiInitFailed` field in the PowerShell `AmsiContext` via reflection. Causes all subsequent scans to be skipped without modifying code pages.

### Execution Order

First call after imports, before any C2 communication. Sequence: AMSI patch → ETW patch → connect.

### Polymorphism

Patch bytes, variable names, function names, and strings are randomized per generation. The existing obfuscation layer in `agent.py` handles renaming; `amsi.py` emits code with standard names that the obfuscator can process.

---

## Feature 3: ETW Patching

**Applies to:** Python agents (ctypes), PowerShell agents (inline C#).
**Windows only.**

### What Gets Patched

- `ntdll!EtwEventWrite` — primary ETW logging. Prologue overwritten with `xor rax, rax; ret` (4 bytes: `\x48\x33\xc0\xc3`).
- `ntdll!EtwEventWriteEx` — extended variant, same treatment.

### Implementation

Same VirtualProtect + memmove pattern as AMSI. Uses the syscall wrappers from Feature 4 when `--syscalls` is enabled; falls back to direct API calls otherwise.

### Execution Order

Runs immediately after AMSI bypass, before C2 registration.

---

## Feature 4: Direct/Indirect Syscalls

**Applies to:** Python agents (ctypes), PowerShell agents (inline C#).
**Windows only.** Foundation for Features 5 and 6.

### SSN Resolution (one selected at generation time)

- **Hell's Gate:** Parse target function prologue for `mov r10, rcx; mov eax, <SSN>` pattern. Fast, fails if hooked.
- **Halo's Gate:** Read SSN from neighboring unhooked syscall stub, walk up/down to find target's SSN by offset. Works through hooks.
- **Tartarus' Gate (default):** Hell's Gate first, fall back to Halo's Gate on failure. Most resilient.

### Execution Mode

- **Indirect (default, `--syscalls=indirect`):** Find a clean `syscall; ret` gadget inside ntdll. Build a stub that sets registers and jumps to the gadget. The `syscall` instruction executes from ntdll's address range — passes stack-based return address checks.
- **Direct (`--syscalls=direct`):** Build a complete syscall stub in RWX memory: `mov r10, rcx; mov eax, <SSN>; syscall; ret`. No ntdll touch. RWX allocation is a signal.

### Wrapped Syscalls

```
NtAllocateVirtualMemory    NtProtectVirtualMemory
NtWriteVirtualMemory       NtCreateThreadEx
NtOpenProcess              NtCreateSection
NtMapViewOfSection         NtQueueApcThread
NtSetContextThread         NtResumeThread
NtWaitForSingleObject
```

### Python Implementation

`SyscallResolver` class using ctypes:
1. Read ntdll from disk (or from PEB `InMemoryOrderModuleList`) to get clean SSNs
2. Build per-function stubs in allocated memory
3. Expose as callable `ctypes.CFUNCTYPE` pointers

### PowerShell Implementation

Inline C# via `Add-Type` — same logic, compiled at runtime. String-obfuscated by the PS obfuscation layer.

### Scope

JS and HTA agents do not get syscalls — they lack the low-level memory access.

---

## Feature 5: Process Injection

**Applies to:** Python agents, PowerShell agents. **Windows only.**
**Depends on:** Feature 4 (syscalls) when `--syscalls` is enabled.

### Techniques (`--inject=<technique>`)

**A. `createthread` (default) — Classic CreateRemoteThread:**
`OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread`

**B. `apc` — QueueUserAPC:**
Allocate + write into target, queue APC to an alertable thread. No `CreateRemoteThread` call. Requires finding an alertable thread in the target.

**C. `hollowing` — Process Hollowing:**
`CreateProcess(SUSPENDED) → NtUnmapViewOfSection → VirtualAllocEx → WriteProcessMemory → SetThreadContext → ResumeThread`. Spawns legitimate process, hollows its image, replaces with payload.

**D. `stomp` — Module Stomping:**
Load a legitimate DLL into target, overwrite its `.text` section. Memory region is file-backed — treated as more trustworthy by some EDRs.

### Target Process Selection

Default prioritized list embedded at generation time:
- **Windows 10/11:** `RuntimeBroker.exe`, `smartscreen.exe`, `SearchHost.exe`
- **Server:** `WmiPrvSE.exe`, `msdtc.exe`
- **Fallback:** `explorer.exe`

Overridable via `--inject-target=<process>`.

### API Routing

All memory/thread operations go through syscall wrappers (Feature 4) when enabled. Otherwise fall back to direct Win32 API calls.

---

## Feature 6: Sleep Obfuscation

**Applies to:** Python agents, PowerShell agents. **Windows only.**
**Depends on:** Feature 4 (syscalls) when enabled.

### Beacon Mode Techniques (`--sleep-obf=<technique>`)

**A. `ekko` (default) — ROP-based timer queue:**

Uses `CreateTimerQueueTimer` with a ROP chain:
1. `VirtualProtect` — mark agent memory RW
2. `SystemFunction032` (advapi32) — RC4-encrypt the region with a random key
3. `WaitForSingleObject` — sleep for beacon interval
4. `SystemFunction032` — decrypt (RC4 is symmetric)
5. `VirtualProtect` — restore RX

No agent code executes during sleep. Memory scanners see encrypted noise.

**B. `foliage` — APC-based:**

Same encrypt/sleep/decrypt chain, but queued as APCs to the current thread via `NtQueueApcThread`, then enters alertable wait via `NtTestAlert`. Useful when timer queue APIs are hooked.

### Streaming Mode: Idle-Window Encryption

When `--sleep-obf` is enabled for streaming agents, a `StreamingSleepObfuscator` wraps the WebSocket receive loop:

**Architecture:**
```
[main thread]    encrypts self → waits on wake_event
[watcher thread] recv() on websocket → fires wake_event when data arrives
```

**Flow:**
1. Agent maintains an idle timer (default 30s, configurable via `--idle-encrypt=<seconds>`)
2. Each received message resets the timer
3. When the timer expires (no activity for N seconds):
   a. Main thread spawns a lightweight watcher thread
   b. Watcher thread takes over the socket `recv()` loop
   c. Main thread encrypts its own memory (same Ekko/Foliage technique)
   d. Main thread waits on a threading `Event`
4. When watcher receives data:
   a. Fires the wake `Event`
   b. Main thread wakes, decrypts, processes the message
   c. Watcher thread exits
   d. Idle timer resets

**Watcher thread design:** The watcher is intentionally minimal — a bare `recv()` + `event.set()` loop. It does not contain encryption keys, C2 URLs, or agent logic. Its memory footprint is negligible for signature-based scanners.

**Heartbeat integration:** The heartbeat (every 10s) counts as activity and resets the idle timer. With the default 30s idle threshold, encryption kicks in after 3 missed heartbeat opportunities — meaning the operator has disconnected or the agent is truly idle.

### Memory Region Discovery

At startup, the agent resolves its own image base from the PEB (`Ldr->InMemoryOrderModuleList`), parses PE section headers (`.text`, `.data`, `.rdata`), and stores boundaries for the sleep cycle.

### Fallback

If sleep obfuscation setup fails (PEB resolution failure, wrong architecture, missing APIs), silently fall back to regular `asyncio.sleep` / `Start-Sleep`. No crash, no error output.

---

## Feature 7: Malleable C2 Profiles

**Applies to:** All agent types + server.

### Profile Format (YAML)

```yaml
name: slack-api
description: Masquerade as Slack API traffic

http-get:
  uri:
    - /api/conversations.history
    - /api/users.list
    - /api/team.info
  headers:
    Host: slack.com
    Authorization: "Bearer xoxb-{{AGENT_ID}}-{{RAND}}"
    Content-Type: application/json; charset=utf-8
    Accept: application/json
  body:
    prepend: '{"ok":true,"messages":['
    append: ']}'
    transform: base64

http-post:
  uri:
    - /api/chat.postMessage
    - /api/chat.update
  headers:
    Host: slack.com
    Authorization: "Bearer xoxb-{{AGENT_ID}}-{{RAND}}"
    Content-Type: application/x-www-form-urlencoded
  body:
    prepend: "channel=C0GENERAL&text="
    append: "&as_user=true"
    transform: base64url

https-certificate:
  CN: "*.slack.com"
  O: "Slack Technologies"

host-rotation:
  strategy: round-robin  # round-robin | random | failover
  hosts:
    - d1234.cloudfront.net
    - d5678.cloudfront.net
  domain-fronting:
    sni: d1234.cloudfront.net
    host: slack.com

sleep:
  default: 60
  jitter: 25

user-agent:
  - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  - "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)"
```

### Data Transform Pipeline

Each message passes through an ordered transform chain:

```
Raw payload (AES-GCM encrypted bytes)
  → transform: base64 | base64url | hex | netbios | mask
  → prepend / append: wrap in context framing
  → Final HTTP body (looks like legitimate API traffic)
```

Server reverses: strip prepend/append → decode transform → AES-GCM decrypt.

### Profile Engine Components

| Component | Responsibility |
|---|---|
| `ProfileParser` | Load YAML, validate schema, resolve `{{RAND}}` / `{{AGENT_ID}}` placeholders at runtime |
| `ProfileTransformer` | Apply / reverse data transform pipeline |
| `HostRotator` | Manage host list with strategy (round-robin, random, failover + health checks) |
| `URIRotator` | Cycle through URIs per-request |

### Domain Fronting

Agent connects to CDN edge IP (from `hosts` list), sends TLS SNI matching the CDN domain, but sets HTTP `Host` header to the fronted domain. CDN routes based on `Host` to the C2 origin. Compatible with CloudFront, Azure CDN, Fastly.

### Transport Abstraction

The current WebSocket transport gets abstracted behind a `Transport` interface:
- `WebSocketTransport` — current behavior, used with `default.yaml`
- `HTTPTransport` — profile-driven HTTP GET/POST, used with all custom profiles
- Both support streaming and beacon modes

WebSocket remains available as `transport: websocket` in profile YAML.

### Agent Template Changes

Templates gain a `{{TRANSPORT_BLOCK}}` placeholder. The generator injects the appropriate transport code based on the selected profile. The transport exposes a uniform `send(data)` / `recv()` interface that the rest of the agent code calls.

### Server Changes

`server.py` gains a profile-aware HTTP handler that:
1. Loads the same profile YAML as the agents
2. Matches incoming requests by URI pattern and headers
3. Reverses the transform pipeline to extract the real payload
4. Responds with the appropriate profile-formatted output

The existing HTTP handler (for HTA agents) is refactored into this system.

### Built-in Profiles

| Profile | Description |
|---|---|
| `default.yaml` | Plain WebSocket, current behavior |
| `slack-api.yaml` | Slack API masquerade |
| `cdn-cloudfront.yaml` | CloudFront domain fronting |
| `microsoft-graph.yaml` | Microsoft Graph API masquerade |
| `generic-cdn.yaml` | Static asset requests (.js, .css, .png) |

---

## Feature Applicability Matrix

| Feature | Python | PowerShell | JavaScript | HTA | Mode |
|---|---|---|---|---|---|
| AES-256-GCM | Yes | Yes | Yes | Yes (CBC+HMAC) | Both |
| AMSI bypass | Yes (ctypes) | Yes (.NET) | No | No | N/A (startup) |
| ETW patching | Yes (ctypes) | Yes (C#) | No | No | N/A (startup) |
| Syscalls | Yes (ctypes) | Yes (C#) | No | No | N/A (foundation) |
| Process injection | Yes | Yes | No | No | Both |
| Sleep obfuscation | Yes | Yes | No | No | Beacon + Streaming |
| Malleable profiles | Yes | Yes | Yes | Yes | Both |

## CLI Interface

```
generate python <host> <port> [options]

Evasion options:
  --amsi                    Enable AMSI bypass (Windows, Python/PS)
  --etw                     Enable ETW patching (Windows, Python/PS)
  --syscalls=MODE           Enable syscall wrappers: indirect (default), direct
  --inject=TECHNIQUE        Process injection: createthread, apc, hollowing, stomp
  --inject-target=PROCESS   Target process for injection (default: auto-select)
  --sleep-obf=TECHNIQUE     Sleep obfuscation: ekko (default), foliage
  --idle-encrypt=SECONDS    Streaming mode idle threshold (default: 30)
  --profile=NAME            Malleable C2 profile (default: default)
  --evasion-all             Enable all applicable evasion features with defaults:
                            amsi + etw + syscalls=indirect + inject=hollowing +
                            sleep-obf=ekko + idle-encrypt=30

Existing options (unchanged):
  --beacon=SECONDS          Beacon mode with interval
  --jitter=PERCENT          Beacon jitter (0-100)
  --key=KEY                 Encryption key
  --os=TARGET               Target OS: windows, linux, macos, auto
  --no-obfuscate            Disable polymorphic obfuscation
```

## Dependencies

New entries in `requirements.txt`:
```
cryptography>=41.0.0
pyyaml>=6.0
```

## File Changes Summary

| File | Change |
|---|---|
| `evasion/__init__.py` | New — EvasionConfig, feature registry |
| `evasion/crypto.py` | New — AES-256-GCM implementation |
| `evasion/amsi.py` | New — AMSI bypass code generation |
| `evasion/etw.py` | New — ETW patching code generation |
| `evasion/syscalls.py` | New — Syscall resolver + stub generation |
| `evasion/injection.py` | New — 4 injection techniques |
| `evasion/sleep_obf.py` | New — Ekko/Foliage + streaming idle-window |
| `evasion/profiles.py` | New — Profile engine, transforms, rotation |
| `profiles/*.yaml` | New — 5 built-in profile definitions |
| `agent.py` | Modified — integrate evasion module calls, new CLI flags, replace XOR with AES-GCM |
| `server.py` | Modified — AES-GCM, profile-aware HTTP handler |
| `templates/agent_template.py` | Modified — AES-GCM, evasion placeholders, transport abstraction |
| `templates/agent_beacon_minimal.py` | Modified — AES-GCM, evasion placeholders |
| `templates/agent_template.ps1` | Modified — AES-GCM, AMSI/ETW/syscall blocks |
| `templates/agent_template.js` | Modified — AES-GCM, transport abstraction |
| `templates/agent_template.hta` | Modified — AES-CBC+HMAC, transport abstraction |
| `templates/streaming_module.py` | Modified — AES-GCM, idle-window sleep obfuscation |
| `requirements.txt` | Modified — add cryptography, pyyaml |
