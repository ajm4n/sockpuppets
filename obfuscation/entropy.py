"""Shannon entropy calculation and reduction for EDR evasion."""

import math
import random


def calculate_shannon_entropy(data: str) -> float:
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


def reduce_entropy(content: str, target: float = 6.5, max_passes: int = 5) -> str:
    """Iteratively reduce Shannon entropy below target using realistic code padding."""
    current = calculate_shannon_entropy(content)
    if current < target:
        return content

    padding_words = [
        'data', 'result', 'value', 'info', 'config', 'option', 'param', 'item',
        'handler', 'manager', 'service', 'process', 'buffer', 'context', 'state',
        'status', 'error', 'message', 'request', 'response', 'client', 'server',
        'connection', 'timeout', 'retry', 'interval', 'counter', 'length', 'index',
    ]

    realistic_stubs = [
        'def validate_{w1}({w2}):\n    if {w2} is None:\n        return False\n    return True',
        'def format_{w1}({w2}):\n    return str({w2}).strip()',
        'def get_{w1}_count({w2}):\n    return len({w2}) if {w2} else 0',
        '{w1}_{w2} = "{w3}"',
        '{w1}_list = ["{w2}", "{w3}", "{w4}"]',
        'DEFAULT_{w1} = {num}',
        '{w1}_enabled = True',
    ]

    lines = content.split('\n')
    iteration = 0
    while current >= target and iteration < max_passes:
        padding_vars = []
        for _ in range(random.randint(8, 15)):
            w1, w2, w3, w4 = [random.choice(padding_words) for _ in range(4)]
            num = random.randint(1, 10000)
            template = random.choice(realistic_stubs)
            padding_vars.append(template.format(w1=w1, w2=w2, w3=w3, w4=w4, num=num))

        safe_positions = [i for i, line in enumerate(lines)
                          if i > 10 and i < len(lines) - 5 and
                          (line.strip() == '' or line.strip().startswith('def '))]

        if safe_positions:
            insert_positions = random.sample(safe_positions, min(len(padding_vars), len(safe_positions)))
            for pos, padding in zip(sorted(insert_positions, reverse=True), padding_vars):
                lines.insert(pos, padding)
        else:
            for padding in padding_vars:
                lines.insert(5, padding)

        content = '\n'.join(lines)
        lines = content.split('\n')
        current = calculate_shannon_entropy(content)
        iteration += 1

    return content
