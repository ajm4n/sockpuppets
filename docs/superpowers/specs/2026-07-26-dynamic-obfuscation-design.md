# SockPuppets Dynamic & BYO Obfuscation

**Date:** 2026-07-26
**Status:** Approved

## Overview

Add two obfuscation capabilities:

1. **BYO (Bring Your Own) Obfuscation** — a plugin system where operators drop custom obfuscation passes into `obfuscators/` or `obfuscators/private/`
2. **Dynamic Multi-Layer Obfuscation** — a `--obfuscation=dynamic` mode that randomly selects and combines obfuscation techniques per agent, ensuring no two agents share the same obfuscation fingerprint

## BYO Obfuscation

### Plugin System

Follows the same convention as `patterns/` and `transforms/`:

```
obfuscators/
  __init__.py          # ObfuscatorRegistry, discover(), chain()
  default.py           # The existing obfuscation logic, extracted
  private/
    EXAMPLE.md         # Usage instructions
```

Each `.py` file exports:

```python
OBFUSCATOR = {
    "name": "my-custom-obfuscator",
    "description": "What it does",
    "languages": ["python", "powershell"],  # which langs it supports
    "order": 50,  # execution order (lower = earlier)
}

def obfuscate(content: str, lang: str, config) -> str:
    """Transform the agent source code. Must return valid source."""
    ...
    return modified_content
```

The `order` field controls chaining: obfuscators run in ascending order. Default passes use order 10-90. Operator plugins typically use 50-80 to run in the middle or late.

### Registry

```python
class ObfuscatorRegistry:
    def discover(self) -> None
    def get(self, name: str) -> ObfuscatorPlugin | None
    def list_available(self) -> list[str]
    def chain(self, content: str, lang: str, config, names: list[str] | None = None) -> str
```

`chain()` runs all discovered obfuscators (or a specified subset) in order. Each pass receives the output of the previous one.

### CLI

```
sockpuppets> generate host port --obfuscators=default,my-custom
```

When `--obfuscators` is not specified, only `default` runs (preserving current behavior). When specified, only the named obfuscators run in order.

## Dynamic Multi-Layer Obfuscation

### Concept

`--obfuscation=dynamic` activates a meta-obfuscator that randomly composes techniques per agent. Each agent gets a unique seed derived from `os.urandom(16)`, making its obfuscation fingerprint unreproducible.

### Technique Pool

The dynamic obfuscator randomly selects 3-5 techniques from this pool per agent:

**String Encoding Diversity** — each string in the agent gets a different encoding method, randomly selected:
- Base64 decode
- Hex decode
- XOR with random key (1-255)
- Character code array (`[ord(c) for c in ...]`)
- Split-and-join (split string into random chunks, join at runtime)
- Reverse + decode
- Multi-layer (e.g., XOR then base64)

**Control Flow Obfuscation:**
- Opaque predicates (always-true/false conditions wrapping real code)
- Dead code branches (realistic-looking but unreachable code)
- Loop-based dispatch (replace sequential calls with a loop over a shuffled function list)
- Lambda wrapping (wrap function calls in lambda indirection)

**Name Mangling Strategies** — each agent uses a different naming scheme:
- Hash-based names (`_h4a8f2`)
- Word-combination names (`signal_matrix_7`)
- Single-letter sequences (`a, b, c, ...`)
- Underscore-heavy (`__internal_proc_12`)
- CamelCase mimicry (`processDataHandler`)

**Code Layout Randomization:**
- Random function definition order
- Nested function extraction (extract inner logic into standalone functions)
- Class wrapping (wrap standalone functions into a class)
- Module-level vs. function-level variable placement

**Dead Code Injection:**
- Decoy functions with plausible names and realistic bodies
- Unused import statements for common libraries
- Decoy class definitions with methods that reference each other
- Fake error handling blocks

**Encoding Diversity** — the obfuscation methods themselves vary:
- Different base64 alphabets
- Variable XOR key lengths (1, 2, 4 bytes)
- Nested encoding (encode the decoder)

### Seed System

```python
seed = os.urandom(16)
rng = random.Random(int.from_bytes(seed, 'big'))
```

The seed produces deterministic selections for one agent but is unique across agents. The seed is not stored or recoverable.

### CLI

```
sockpuppets> generate host port --obfuscation=dynamic
sockpuppets> generate host port --evasion-all    # includes dynamic
```

## Integration

### Modified Files

| File | Change |
|------|--------|
| `agent.py` | Add `obfuscation: str = None` param. When `'dynamic'`, use dynamic obfuscator instead of `obfuscate_strings()`. When custom names, use `ObfuscatorRegistry.chain()`. |
| `main.py` | Add `--obfuscation=MODE` flag. Add `--obfuscators=name,name` flag. Update help. |
| `gui/api.py` | Add `obfuscation` field to `GenerateRequest`. |

### New Files

| File | Purpose |
|------|---------|
| `obfuscators/__init__.py` | ObfuscatorRegistry with discover/chain |
| `obfuscators/default.py` | Existing obfuscation extracted as a plugin |
| `obfuscators/dynamic.py` | Dynamic multi-layer obfuscator |
| `obfuscators/private/EXAMPLE.md` | Instructions for writing custom obfuscators |
| `tests/test_obfuscators.py` | Tests for registry, default, dynamic |
