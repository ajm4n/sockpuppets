# SockPuppets BOF Loader

**Date:** 2026-07-26
**Status:** Approved

## Overview

Add in-memory Beacon Object File (BOF) execution to Windows agents. BOFs are compiled COFF object files that run inside the agent process, providing extensibility without dropping new executables to disk.

The loader is a pure Python/ctypes module following the existing `evasion/<feature>.py` pattern. Memory operations route through the existing `SyscallResolver` when syscalls are enabled.

## Scope

- Native x64 COFF object files only (machine type `0x8664`)
- Full Cobalt Strike BeaconAPI compatibility (output, data parsing, format, process/token)
- Win32 API resolution via `__imp_LIBRARY$Function` convention
- No .NET/BOF.NET support
- No x86 (i386) support

## COFF Loader Architecture

### Parsing

Standard COFF header: 20-byte file header → section table → symbol table → string table. Validate `Machine == 0x8664` on load, reject anything else.

### Section Loading

Single contiguous allocation via `syscall_alloc` (or `VirtualAlloc` without syscalls). All sections packed sequentially with 16-byte alignment between them. Initial protection: `PAGE_READWRITE`.

Track each section's offset within the allocation so relocations can compute absolute addresses.

### Symbol Resolution

Two categories:

**BeaconAPI functions** — matched by name against a lookup table of Python ctypes callback wrappers. Functions like `BeaconPrintf`, `BeaconOutput`, `BeaconDataParse`, etc.

**Win32 imports** — follow the `__imp_LIBRARY$FunctionName` convention. Split on `$`, call `LoadLibraryA(LIBRARY)` then `GetProcAddress(handle, FunctionName)`. Cache resolved addresses for the duration of the BOF execution.

Unresolved symbols are fatal — abort load with an error listing the missing symbol.

### Relocation Processing

Three relocation types for AMD64:

| Type | Value | Behavior |
|------|-------|----------|
| `IMAGE_REL_AMD64_ADDR64` | 0x0001 | 64-bit absolute address |
| `IMAGE_REL_AMD64_ADDR32NB` | 0x0003 | 32-bit RVA (no base) |
| `IMAGE_REL_AMD64_REL32` | 0x0004 | 32-bit PC-relative |

Each relocation patches the loaded section data using the resolved symbol address and the section's base in the contiguous allocation.

### Execution

1. Flip entire allocation `RW → RX` via `syscall_protect` (or `VirtualProtect`)
2. Find the `go` symbol in the symbol table, compute its absolute address
3. Call `go(args_ptr, args_len)` via ctypes `CFUNCTYPE`
4. Flip back `RX → RW`
5. Zero-fill the allocation
6. Free the allocation

No `RWX` at any point in the lifecycle.

## BeaconAPI Implementation

All functions implemented as Python ctypes callbacks (`CFUNCTYPE`/`WINFUNCTYPE`) that the COFF loader maps into the BOF's import table.

### Output Functions

| Function | Signature | Behavior |
|----------|-----------|----------|
| `BeaconPrintf` | `(int type, char* fmt, ...)` | Printf-style output to shared buffer. Type 0 = regular, 1 = error |
| `BeaconOutput` | `(int type, char* data, int len)` | Raw byte output to shared buffer |

Output buffer is collected after `go()` returns and sent back as the command result.

### Data Parsing

| Function | Signature | Behavior |
|----------|-----------|----------|
| `BeaconDataParse` | `(datap* parser, char* buffer, int size)` | Initialize parser over argument buffer |
| `BeaconDataInt` | `(datap* parser)` | Extract 4-byte int (big-endian) |
| `BeaconDataShort` | `(datap* parser)` | Extract 2-byte short (big-endian) |
| `BeaconDataLength` | `(datap* parser, int* outlen)` | Extract length-prefixed blob |
| `BeaconDataExtract` | `(datap* parser, int* outlen)` | Extract null-terminated string |

### Format Functions

| Function | Signature | Behavior |
|----------|-----------|----------|
| `BeaconFormatAlloc` | `(formatp* fmt, int maxsz)` | Allocate format buffer |
| `BeaconFormatReset` | `(formatp* fmt)` | Reset position to 0 |
| `BeaconFormatFree` | `(formatp* fmt)` | Free format buffer |
| `BeaconFormatAppend` | `(formatp* fmt, char* data, int len)` | Append raw bytes |
| `BeaconFormatPrintf` | `(formatp* fmt, char* fmtstr, ...)` | Printf into buffer |
| `BeaconFormatToString` | `(formatp* fmt, int* size)` | Return pointer + size |
| `BeaconFormatInt` | `(formatp* fmt, int val)` | Append 4-byte int |

### Process/Token Functions

| Function | Signature | Behavior |
|----------|-----------|----------|
| `BeaconGetSpawnTo` | `(BOOL x86, char* buffer, int length)` | Return spawnto path (default `C:\Windows\System32\rundll32.exe`) |
| `BeaconInjectProcess` | `(HANDLE proc, int pid, char* payload, int len, int offset, char* arg, int arglen)` | Route through existing injection module |
| `BeaconInjectTemporaryProcess` | `(PROCESS_INFORMATION* pi, char* payload, int len, int offset)` | Inject into temporary process |
| `BeaconSpawnTemporaryProcess` | `(BOOL x86, BOOL ignoreToken, STARTUPINFO* si, PROCESS_INFORMATION* pi)` | Spawn sacrificial process |
| `BeaconUseToken` | `(HANDLE token)` | Impersonate token |
| `BeaconRevertToken` | `()` | Revert to original token |
| `BeaconCleanupProcess` | `(PROCESS_INFORMATION* pi)` | Terminate + close handles |
| `BeaconIsAdmin` | `()` | Check if elevated |

### Structs

Match Cobalt Strike layout for binary compatibility:

```c
typedef struct {
    char* original;   // start of buffer
    char* buffer;     // current position
    int length;       // bytes remaining
    int size;         // total size
} datap;

typedef struct {
    char* original;
    char* buffer;
    int length;
    int size;
} formatp;
```

### Win32 API Resolution

BOFs import Win32 functions via `__imp_LIBRARY$FunctionName`. The loader:

1. Splits symbol name on `$`
2. Calls `LoadLibraryA(LIBRARY)` to get module handle
3. Calls `GetProcAddress(handle, FunctionName)` to get address
4. Caches `(library, function) → address` for the BOF's lifetime
5. Patches the address into the BOF's GOT slot

## Argument Marshaling

### Server-Side Packing

`BOFPacker` class packs arguments into a binary buffer matching Cobalt Strike's format:

| Method | Wire format |
|--------|-------------|
| `add_int(val)` | 4 bytes big-endian |
| `add_short(val)` | 2 bytes big-endian |
| `add_str(val)` | 4-byte length prefix + UTF-8 + null terminator |
| `add_wstr(val)` | 4-byte length prefix + UTF-16LE + null terminator |
| `add_binary(val)` | 4-byte length prefix + raw bytes |

### CLI Syntax

```
agent[id]> bof /path/to/file.o [type:value ...]
```

Type prefixes: `str:`, `wstr:`, `int:`, `short:`, `bin:` (reads file as raw bytes). No prefix defaults to `str:`.

### Wire Format

Server sends to agent:

```json
{
  "command": "__bof__",
  "bof_data": "<base64 COFF bytes>",
  "bof_args": "<base64 packed args>",
  "bof_entry": "go"
}
```

Agent decodes both blobs, passes to the COFF loader.

## Server/CLI/GUI Integration

### CLI

New handler `do_bof` in the agent interaction loop (`main.py`):

1. Read `.o` file from disk
2. Parse args via type prefixes into `BOFPacker`
3. Base64-encode COFF bytes and packed args
4. Send as `__bof__` command
5. Display captured output

### GUI API

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| POST | `/api/agents/{id}/bof` | `{bof_data: base64, args: base64, entry: "go"}` | `{output}` or `{queued, message}` |

Console tab also accepts `bof` commands typed directly.

### Event Bus

Fires `bof_executed` event: agent ID, BOF filename, success/failure, output length.

### TUI

No TUI changes needed — existing command passthrough handles `bof` commands.

## Evasion Module Integration

### New File: `evasion/bof_loader.py`

Follows the `generate_code(lang, config)` pattern. Returns a string of Python code containing:

- `COFFLoader` class: `load()`, `_parse_coff()`, `_load_sections()`, `_resolve_symbols()`, `_apply_relocations()`, `_execute()`
- BeaconAPI callback implementations
- `datap`/`formatp` ctypes struct definitions
- `__bof__` command handler for the agent's command dispatcher

### Template Changes

New placeholder: `{{EVASION_BOF}}`

Added to `templates/agent_template.py` alongside existing evasion placeholders.

### EvasionConfig Changes

```python
@dataclass
class EvasionConfig:
    amsi: bool = False
    etw: bool = False
    syscalls: Optional[str] = None
    inject: Optional[str] = None
    inject_target: Optional[str] = None
    sleep_obf: Optional[str] = None
    idle_encrypt: int = 30
    profile: str = "default"
    bof: bool = False              # NEW
```

### `evasion/__init__.py` Changes

- Add `'bof': ['python', 'c']` to `FEATURE_LANG_SUPPORT`
- Add `'bof': '{{EVASION_BOF}}'` to `_PLACEHOLDER_MAP`
- Wire `bof_loader.generate_code()` into `get_evasion_code()`

### CLI Flag

```
sockpuppets> generate 10.0.0.5 8443 --bof
```

Single flag. Agent includes full COFF loader when enabled, stays smaller without it.

### Syscall Routing

When `config.syscalls` is set, the BOF loader uses `syscall_alloc`, `syscall_protect`, and `syscall_write` from `evasion/syscalls.py` instead of direct Win32 calls. This is automatic — the generated code checks for syscall wrapper availability.

## Modified Files

| File | Change |
|------|--------|
| `main.py` | Add `--bof` flag to `do_generate`. Add `bof` command to agent interaction loop. |
| `agent.py` | Add `bof: bool = False` param, pass through to EvasionConfig and template. |
| `evasion/__init__.py` | Add `bof` to EvasionConfig, FEATURE_LANG_SUPPORT, _PLACEHOLDER_MAP. |
| `templates/agent_template.py` | Add `{{EVASION_BOF}}` placeholder. |
| `gui/api.py` | Add `/api/agents/{id}/bof` endpoint. |

## New Files

| File | Purpose |
|------|---------|
| `evasion/bof_loader.py` | COFF loader + BeaconAPI implementation, `generate_code()` |
| `tests/test_bof_loader.py` | Unit tests for COFF parsing, argument packing, symbol resolution |
