"""Shared utilities for all agent generators."""

import os
import random
import string
import hashlib
from pathlib import Path


def random_string(length: int = 8) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def random_var_name() -> str:
    prefixes = ['data', 'temp', 'buf', 'ctx', 'info', 'val', 'obj', 'result',
                'handler', 'proc', 'mgr', 'svc', 'cfg', 'opt', 'ref', 'item']
    return random.choice(prefixes) + '_' + random_string(6)


def generate_unique_key() -> str:
    return hashlib.sha256(os.urandom(16)).hexdigest()[:24]


def get_templates_dir() -> Path:
    return Path(__file__).parent.parent / 'templates'


def get_agent_go_dir() -> Path:
    return Path(__file__).parent.parent / 'agent_go'


def get_agent_rust_dir() -> Path:
    return Path(__file__).parent.parent / 'agent_rust'


def get_agent_c_dir() -> Path:
    return Path(__file__).parent.parent / 'agent_c'


def get_agent_csharp_dir() -> Path:
    return Path(__file__).parent.parent / 'agent_csharp'
