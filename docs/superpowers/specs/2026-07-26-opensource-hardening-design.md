# Open-Source Hardening Design Spec

**Date:** 2026-07-26
**Status:** Draft
**Scope:** 3 features for open-source readiness — custom transforms, pluggable obfuscation patterns, private directories

---

## Overview

Prepare sockpuppets for open-sourcing without burning operator evasion capability. Three additions: a plugin system for custom data transforms, a pluggable pattern system for polymorphic obfuscation, and a private directory convention that .gitignore separates operator-specific assets from the public repo.

## Feature 1: Custom Transform Plugins

### Directory Structure

```
transforms/
  __init__.py          # Auto-discovery loader + TransformRegistry
  private/             # .gitignore'd — operator drop-in transforms
    .gitkeep
```

### Plugin Contract

Each `.py` file in `transforms/` or `transforms/private/` exports two functions:

```python
def encode(data: bytes) -> str:
    """Encode raw bytes into a transport-safe string."""
    ...

def decode(encoded: str) -> bytes:
    """Reverse the encoding."""
    ...
```

The filename (minus `.py`) becomes the transform name usable in profile YAML:
```yaml
body:
  transform: my_custom_xor  # loads transforms/my_custom_xor.py or transforms/private/my_custom_xor.py
```

### TransformRegistry

`transforms/__init__.py` provides:

```python
class TransformRegistry:
    def __init__(self):
        self._builtins = {}   # base64, base64url, hex, netbios, mask
        self._plugins = {}    # discovered from transforms/ and transforms/private/
    
    def discover(self):
        """Scan transforms/ and transforms/private/ for .py files, import them."""
    
    def get(self, name: str) -> tuple[Callable, Callable]:
        """Return (encode, decode) for a transform name. Plugins override builtins."""
    
    def list_available(self) -> list[str]:
        """List all available transform names."""
```

### Integration with ProfileTransformer

`evasion/profiles.py` `ProfileTransformer` changes:
- On init, instantiate a `TransformRegistry` and call `discover()`
- In `encode()` and `decode()`, replace the hardcoded if/elif chain with `registry.get(transform)`
- Built-in transforms (base64, hex, netbios, mask, base64url) are registered as builtins in the registry init — they still live in profiles.py as functions, just registered instead of hardcoded
- Unknown transform name with no plugin raises a clear error: `"Unknown transform '{name}'. Available: {list}"`

### Code Generation

`generate_code()` in `profiles.py` must embed the custom transform logic in the generated agent. When a profile uses a custom transform:
1. Read the plugin `.py` file
2. Inline its `encode`/`decode` functions into the generated transport code
3. The agent carries its own copy — no runtime plugin loading on the target

---

## Feature 2: Pluggable Obfuscation Patterns

### Directory Structure

```
patterns/
  __init__.py          # PatternProvider loader
  default.py           # Ships with repo — current hardcoded patterns extracted
  private/             # .gitignore'd — operator patterns
    .gitkeep
```

### Pattern Contract

Each `.py` file in `patterns/` or `patterns/private/` exports a `PATTERNS` dict:

```python
PATTERNS = {
    # Variable name generation
    'var_prefixes': ['data', 'buf', 'cfg', 'temp', 'proc', 'handler', 'result'],
    
    # Junk code templates — {var}, {func}, {rand_int} are replaced at generation time
    'junk_templates': [
        '{var} = {rand_int}',
        'def {func}():\n    return {rand_int}',
        '{var} = lambda x: x * {rand_int}',
    ],
    
    # String encoding methods to randomly select from
    'string_encodings': ['base64', 'hex', 'reverse', 'xor'],
    
    # Padding/filler words for entropy reduction
    'padding_words': ['config', 'handler', 'process', 'service', 'manager',
                      'controller', 'adapter', 'factory', 'builder', 'context'],
    
    # Import alias prefixes
    'import_prefixes': ['_mod', '_lib', '_pkg'],
    
    # Function name prefixes for obfuscated names
    'func_prefixes': ['init', 'run', 'check', 'load', 'parse', 'handle'],
}
```

### PatternProvider

`patterns/__init__.py` provides:

```python
class PatternProvider:
    def __init__(self, name: str = 'default'):
        """Load patterns from patterns/<name>.py or patterns/private/<name>.py"""
    
    @property
    def var_prefixes(self) -> list[str]: ...
    @property
    def junk_templates(self) -> list[str]: ...
    @property
    def string_encodings(self) -> list[str]: ...
    @property
    def padding_words(self) -> list[str]: ...
    @property
    def import_prefixes(self) -> list[str]: ...
    @property
    def func_prefixes(self) -> list[str]: ...
    
    def random_var_name(self) -> str:
        """Generate a variable name using this pattern set."""
    
    def random_func_name(self) -> str:
        """Generate a function name using this pattern set."""
    
    def random_junk(self) -> str:
        """Generate a junk code snippet using this pattern set."""
```

### Integration with AgentGenerator

`agent.py` changes:
- `AgentGenerator.__init__()` accepts `patterns: str = 'default'` and creates a `PatternProvider`
- Replace all hardcoded `random.choice(prefixes)` calls with `self.patterns.random_var_name()` etc.
- Replace hardcoded `padding_words` lists in `reduce_entropy()` with `self.patterns.padding_words`
- Replace hardcoded junk code patterns in `generate_junk_code()` with `self.patterns.random_junk()`
- Replace hardcoded `string_encodings` choices with `self.patterns.string_encodings`

### Extracting default.py

Move the current hardcoded values from `agent.py` into `patterns/default.py`. This includes:
- Variable prefixes from `random_var_name()` (line 33): `['data', 'buf', 'cfg', 'temp', 'proc', 'handler', 'result']`
- Junk patterns from `generate_junk_code()` (lines 39-44)
- Padding words from `reduce_entropy()` (lines ~80-90)
- String encoding choices from `obfuscate_strings()` (line 278): `['base64', 'hex', 'reverse', 'xor']`

### CLI

New flag: `--patterns=<name>` (default: `default`)

`--evasion-all` does NOT set a pattern — it stays as `default`. Operators explicitly choose their custom pattern set.

---

## Feature 3: Private Directories

### Convention

Three private directories, all .gitignore'd:

```
profiles/private/     # Operator C2 profiles
patterns/private/     # Operator obfuscation patterns
transforms/private/   # Operator data transforms
```

### Loader Priority

All loaders (ProfileParser, PatternProvider, TransformRegistry) check private first:

1. `<dir>/private/<name>` — if found, use it
2. `<dir>/<name>` — fallback to public

This means an operator can override a public profile by placing a file with the same name in the private directory.

### .gitignore Additions

```
# Operator-specific assets (not for public repo)
profiles/private/
patterns/private/
transforms/private/
```

### Scaffolding

Each private directory ships with:
- `.gitkeep` — so the directory structure exists after clone
- `EXAMPLE.md` — brief instructions on the plugin contract and how to add custom assets

Example `profiles/private/EXAMPLE.md`:
```markdown
# Private Profiles

Drop engagement-specific YAML profiles here. They won't be committed to the repo.

See profiles/slack-api.yaml for the format. Use `generate --profile=<name>` to select.
```

---

## File Changes Summary

| File | Change |
|---|---|
| `transforms/__init__.py` | New — TransformRegistry with auto-discovery |
| `patterns/__init__.py` | New — PatternProvider loader |
| `patterns/default.py` | New — extracted current hardcoded patterns |
| `profiles/private/.gitkeep` | New — directory scaffold |
| `profiles/private/EXAMPLE.md` | New — usage instructions |
| `patterns/private/.gitkeep` | New — directory scaffold |
| `patterns/private/EXAMPLE.md` | New — usage instructions |
| `transforms/private/.gitkeep` | New — directory scaffold |
| `transforms/private/EXAMPLE.md` | New — usage instructions |
| `evasion/profiles.py` | Modified — ProfileTransformer uses TransformRegistry; ProfileParser checks private dir |
| `agent.py` | Modified — AgentGenerator uses PatternProvider; add --patterns flag |
| `main.py` | Modified — add --patterns CLI flag |
| `.gitignore` | Modified — add 3 private directory entries |

## CLI Changes

```
generate python <host> <port> [existing options...]
  --patterns=NAME           Obfuscation pattern set (default: default)
```

`--patterns` is independent of `--evasion-all`.
