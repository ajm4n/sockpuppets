"""Dynamic multi-layer obfuscation -- no two agents are the same.

Randomly selects and combines 3-5 techniques per agent using a unique
cryptographic seed, producing unique polymorphic output every time.
"""

import base64
import os
import random
import re
import string

OBFUSCATOR = {
    "name": "dynamic",
    "description": "Multi-layered dynamic obfuscation -- no two agents are the same",
    "languages": ["python"],
    "order": 20,
}


# ---------------------------------------------------------------------------
# Technique pool
# ---------------------------------------------------------------------------

def _string_encoding_diversity(content: str, rng: random.Random) -> str:
    """Encode suspicious string literals with randomly-varied encodings."""
    suspicious = [
        'register', 'checkin', 'command', 'response', 'heartbeat',
        'beacon', 'payload', 'shellcode', 'inject', 'execute',
        'socket', 'connect', 'callback', 'exfiltrate', 'upload',
        'download', 'tasklist', 'keylog', 'screenshot', 'persist',
    ]

    def _encode_string(s: str) -> str:
        method = rng.choice([
            'base64', 'hex', 'xor', 'charcode', 'split_join', 'reverse',
            'multi_layer',
        ])

        if method == 'base64':
            encoded = base64.b64encode(s.encode()).decode()
            return f"__import__('base64').b64decode('{encoded}').decode()"

        if method == 'hex':
            encoded = s.encode().hex()
            return f"bytes.fromhex('{encoded}').decode()"

        if method == 'xor':
            key = rng.randint(1, 255)
            xored = ''.join(chr(ord(c) ^ key) for c in s)
            encoded = base64.b64encode(xored.encode()).decode()
            return (
                f"''.join([chr(ord(c)^{key}) for c in "
                f"__import__('base64').b64decode('{encoded}').decode()])"
            )

        if method == 'charcode':
            codes = ', '.join(str(ord(c)) for c in s)
            return f"''.join(chr(c) for c in [{codes}])"

        if method == 'split_join':
            # Split into random-length chunks
            parts = []
            i = 0
            while i < len(s):
                chunk_len = rng.randint(1, max(1, len(s) // 3 + 1))
                parts.append(s[i:i + chunk_len])
                i += chunk_len
            return "''.join([" + ', '.join(f"'{p}'" for p in parts) + "])"

        if method == 'reverse':
            return f"'{s[::-1]}'[::-1]"

        # multi_layer: base64 of xor'd string
        key = rng.randint(1, 255)
        xored = ''.join(chr(ord(c) ^ key) for c in s)
        double_encoded = base64.b64encode(
            base64.b64encode(xored.encode())
        ).decode()
        return (
            f"''.join([chr(ord(c)^{key}) for c in "
            f"__import__('base64').b64decode("
            f"__import__('base64').b64decode('{double_encoded}')).decode()])"
        )

    for word in suspicious:
        if f"'{word}'" in content:
            replacement = _encode_string(word)
            content = content.replace(f"'{word}'", replacement, 1)
        if f'"{word}"' in content:
            replacement = _encode_string(word)
            content = content.replace(f'"{word}"', replacement, 1)

    return content


def _control_flow_obfuscation(content: str, rng: random.Random) -> str:
    """Insert opaque predicates and dead branches at safe module-level positions."""
    lines = content.split('\n')
    safe_positions = []

    for i, line in enumerate(lines):
        if i > 10 and i < len(lines) - 10:
            if line.startswith('def ') or line.startswith('async def '):
                safe_positions.append(i)

    if not safe_positions:
        return content

    num_insertions = min(rng.randint(2, 4), len(safe_positions))
    positions = rng.sample(safe_positions, num_insertions)

    predicates = [
        lambda: (
            f"if (lambda: True)():\n"
            f"    _opq_{rng.randint(1000,9999)} = {rng.randint(0, 500)}"
        ),
        lambda: (
            f"if ({rng.randint(2,99)} * {rng.randint(2,99)} + 1) > 0:\n"
            f"    _chk_{rng.randint(1000,9999)} = {rng.randint(0, 500)}"
        ),
        lambda: (
            f"_pred_{rng.randint(1000,9999)} = {rng.randint(100,999)}\n"
            f"if _pred_{rng.randint(1000,9999)} or True:\n"
            f"    pass"
        ),
        lambda: (
            f"if not ([] and False):\n"
            f"    _flg_{rng.randint(1000,9999)} = True"
        ),
    ]

    for pos in sorted(positions, reverse=True):
        predicate = rng.choice(predicates)()
        lines.insert(pos, predicate)

    return '\n'.join(lines)


def _name_mangling(content: str, rng: random.Random) -> str:
    """Apply a randomly-chosen naming strategy to function and variable names."""
    target_funcs = [
        'execute_command', 'get_metadata', 'simple_encrypt', 'simple_decrypt',
        'connect_to_server', 'heartbeat', 'calculate_sleep_time',
    ]
    target_vars = [
        'metadata', 'message', 'command', 'output', 'encrypted', 'decrypted',
    ]

    strategy = rng.choice([
        'hash_based', 'word_combo', 'single_letter', 'underscore_heavy',
        'camelCase',
    ])

    _counter = [0]

    def _gen_name(prefix: str = '') -> str:
        _counter[0] += 1
        n = _counter[0]

        if strategy == 'hash_based':
            h = format(rng.getrandbits(32), '08x')
            return f"_h{h[:8]}"

        if strategy == 'word_combo':
            words = [
                'signal', 'matrix', 'delta', 'vector', 'stream', 'kernel',
                'buffer', 'cache', 'queue', 'stack', 'frame', 'token',
                'cipher', 'digest', 'block', 'index', 'table', 'relay',
            ]
            return f"{rng.choice(words)}_{rng.choice(words)}_{n}"

        if strategy == 'single_letter':
            # a..z, then aa..az, etc.
            letters = string.ascii_lowercase
            if n <= 26:
                return letters[n - 1]
            return letters[(n - 1) // 26 - 1] + letters[(n - 1) % 26]

        if strategy == 'underscore_heavy':
            return f"__internal_proc_{n:02d}"

        # camelCase
        parts = ['process', 'data', 'handler', 'init', 'run', 'check',
                 'load', 'parse', 'resolve', 'compute', 'validate']
        p1 = rng.choice(parts)
        p2 = rng.choice(parts).capitalize()
        return f"{p1}{p2}{n}"

    func_mappings = {}
    for fname in target_funcs:
        if fname in content:
            func_mappings[fname] = _gen_name()

    if func_mappings:
        func_pattern = re.compile(
            r'\b(' + '|'.join(re.escape(k) for k in func_mappings) + r')\b'
        )
        content = func_pattern.sub(lambda m: func_mappings[m.group(0)], content)

    var_mappings = {}
    for vname in target_vars:
        if re.search(rf'\b{re.escape(vname)}\b(?=\s*[=:]|[\s\.])', content):
            var_mappings[vname] = _gen_name()

    if var_mappings:
        var_pattern = re.compile(
            r'\b(' + '|'.join(re.escape(k) for k in var_mappings) + r')\b(?=\s*[=:]|[\s\.])'
        )
        content = var_pattern.sub(lambda m: var_mappings[m.group(1)], content)

    return content


def _code_layout_randomization(content: str, rng: random.Random) -> str:
    """Randomly reorder module-level function definitions."""
    lines = content.split('\n')

    # Parse function boundaries at module level (no leading whitespace)
    functions = []  # list of (start, end, lines)
    preamble = []   # lines before the first function
    postamble = []  # lines after the last function (main block, etc.)
    i = 0

    # Collect preamble
    while i < len(lines):
        if lines[i].startswith('def ') or lines[i].startswith('async def '):
            break
        preamble.append(lines[i])
        i += 1

    # Collect functions
    while i < len(lines):
        if lines[i].startswith('def ') or lines[i].startswith('async def '):
            func_lines = [lines[i]]
            i += 1
            while i < len(lines):
                # Next module-level def or non-indented non-empty non-decorator
                if (lines[i].startswith('def ') or lines[i].startswith('async def ')
                        or lines[i].startswith('class ')
                        or (lines[i].strip() and not lines[i][0].isspace()
                            and not lines[i].startswith('#')
                            and not lines[i].startswith('@'))):
                    break
                func_lines.append(lines[i])
                i += 1
            functions.append(func_lines)
        else:
            # Non-function line after functions started -- likely main block
            postamble = lines[i:]
            break

    if len(functions) < 2:
        return content

    # Shuffle function order
    rng.shuffle(functions)

    result_lines = preamble[:]
    for func_lines in functions:
        result_lines.extend(func_lines)
    result_lines.extend(postamble)

    return '\n'.join(result_lines)


def _dead_code_injection(content: str, rng: random.Random) -> str:
    """Insert realistic-looking decoy functions and classes."""
    decoy_pool = [
        lambda: (
            f"def validate_checksum_{rng.randint(100,999)}(data):\n"
            f"    return sum(data) & 0xFF\n"
        ),
        lambda: (
            f"def init_entropy_pool_{rng.randint(100,999)}():\n"
            f"    import random as _rnd\n"
            f"    return [_rnd.randint(0, 255) for _ in range({rng.randint(8, 32)})]\n"
        ),
        lambda: (
            f"def rotate_buffer_{rng.randint(100,999)}(buf, n):\n"
            f"    return buf[n:] + buf[:n]\n"
        ),
        lambda: (
            f"def compute_hash_{rng.randint(100,999)}(payload):\n"
            f"    h = 0x{rng.randint(0x1000, 0xFFFF):04x}\n"
            f"    for b in payload:\n"
            f"        h = ((h << 5) + h + b) & 0xFFFFFFFF\n"
            f"    return h\n"
        ),
        lambda: (
            f"class ConfigValidator_{rng.randint(100,999)}:\n"
            f"    def __init__(self):\n"
            f"        self._state = {rng.randint(0, 255)}\n"
            f"    def validate(self, cfg):\n"
            f"        return isinstance(cfg, dict) and len(cfg) > 0\n"
        ),
        lambda: (
            f"def xor_bytes_{rng.randint(100,999)}(data, key):\n"
            f"    return bytes(b ^ key for b in data)\n"
        ),
        lambda: (
            f"def pad_payload_{rng.randint(100,999)}(data, block_size={rng.choice([8,16,32])}):\n"
            f"    pad_len = block_size - (len(data) % block_size)\n"
            f"    return data + bytes([pad_len] * pad_len)\n"
        ),
        lambda: (
            f"def decode_config_{rng.randint(100,999)}(raw):\n"
            f"    try:\n"
            f"        import json as _j\n"
            f"        return _j.loads(raw)\n"
            f"    except Exception:\n"
            f"        return {{}}\n"
        ),
    ]

    num_decoys = rng.randint(2, 5)
    selected = rng.sample(decoy_pool, min(num_decoys, len(decoy_pool)))

    lines = content.split('\n')

    # Find safe insertion points (before module-level defs)
    safe_positions = []
    for i, line in enumerate(lines):
        if i > 10 and i < len(lines) - 5:
            if line.startswith('def ') or line.startswith('async def '):
                safe_positions.append(i)

    if not safe_positions:
        # Fallback: append near end
        for decoy_fn in selected:
            lines.append('')
            lines.append(decoy_fn())
        return '\n'.join(lines)

    for decoy_fn in selected:
        pos = rng.choice(safe_positions)
        lines.insert(pos, decoy_fn())
        lines.insert(pos, '')
        # Shift remaining safe positions
        safe_positions = [p + 2 for p in safe_positions]

    return '\n'.join(lines)


def _encoding_diversity(content: str, rng: random.Random) -> str:
    """Apply meta-encoding layer: wrap already-encoded strings in another layer."""
    # Find base64.b64decode('...') patterns and optionally double-encode them
    b64_pattern = re.compile(
        r"__import__\('base64'\)\.b64decode\('([A-Za-z0-9+/=]+)'\)"
    )

    def _maybe_wrap(match):
        if rng.random() < 0.5:
            return match.group(0)

        original_b64 = match.group(1)
        method = rng.choice(['double_b64', 'variable_xor', 'substitution'])

        if method == 'double_b64':
            double = base64.b64encode(original_b64.encode()).decode()
            return (
                f"__import__('base64').b64decode("
                f"__import__('base64').b64decode('{double}'))"
            )

        if method == 'variable_xor':
            key = rng.randint(1, 255)
            xored_bytes = bytes(b ^ key for b in original_b64.encode())
            xored_b64 = base64.b64encode(xored_bytes).decode()
            return (
                f"__import__('base64').b64decode("
                f"bytes(b^{key} for b in "
                f"__import__('base64').b64decode('{xored_b64}')))"
            )

        # substitution: use a shifted alphabet for base64 chars
        shift = rng.randint(1, 25)
        shifted = ''.join(
            chr((ord(c) - 65 + shift) % 26 + 65) if c.isupper()
            else chr((ord(c) - 97 + shift) % 26 + 97) if c.islower()
            else c
            for c in original_b64
        )
        # Undo at runtime with negative shift
        return (
            f"__import__('base64').b64decode("
            f"''.join(chr((ord(c)-65-{shift})%26+65) if c.isupper() "
            f"else chr((ord(c)-97-{shift})%26+97) if c.islower() "
            f"else c for c in '{shifted}'))"
        )

    content = b64_pattern.sub(_maybe_wrap, content)
    return content


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def obfuscate(content: str, lang: str, config) -> str:
    """Apply dynamic multi-layer obfuscation with a unique random seed."""
    if lang != "python":
        return content

    seed = os.urandom(16)
    rng = random.Random(int.from_bytes(seed, 'big'))

    techniques = [
        _string_encoding_diversity,
        _control_flow_obfuscation,
        _name_mangling,
        _code_layout_randomization,
        _dead_code_injection,
        _encoding_diversity,
    ]

    num_techniques = rng.randint(3, 5)
    selected = rng.sample(techniques, num_techniques)
    rng.shuffle(selected)

    for technique in selected:
        content = technique(content, rng)

    return content
