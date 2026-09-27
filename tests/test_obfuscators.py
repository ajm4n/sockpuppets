"""Tests for the obfuscator plugin system."""

import sys
from pathlib import Path

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from obfuscators import ObfuscatorRegistry

TEST_CONTENT = '''#!/usr/bin/env python3
import os
import json

def execute_command(command):
    return os.popen(command).read()

def get_metadata():
    return {'type': 'register', 'hostname': 'test'}

def simple_encrypt(data):
    return data

def simple_decrypt(data):
    return data

def connect_to_server():
    pass

def heartbeat():
    pass

def calculate_sleep_time(interval, jitter):
    return float(interval)
'''


def _fresh_registry():
    """Create a fresh registry that re-discovers plugins."""
    reg = ObfuscatorRegistry()
    reg.discover()
    return reg


# 1. ObfuscatorRegistry discovers plugins from the obfuscators directory
def test_registry_discovers_plugins():
    reg = _fresh_registry()
    assert len(reg._plugins) >= 2, f"Expected at least 2 plugins, found {len(reg._plugins)}"


# 2. registry.list_available() returns at least ['default', 'dynamic']
def test_list_available_contains_expected():
    reg = _fresh_registry()
    available = reg.list_available()
    assert 'default' in available, f"'default' not in {available}"
    assert 'dynamic' in available, f"'dynamic' not in {available}"


# 3. registry.get('default') returns a plugin with correct metadata
def test_get_default_metadata():
    reg = _fresh_registry()
    plugin = reg.get('default')
    assert plugin is not None
    assert plugin.name == 'default'
    assert 'python' in plugin.languages
    assert plugin.order == 10
    assert callable(plugin.obfuscate)


# 4. registry.get('dynamic') returns a plugin with correct metadata
def test_get_dynamic_metadata():
    reg = _fresh_registry()
    plugin = reg.get('dynamic')
    assert plugin is not None
    assert plugin.name == 'dynamic'
    assert 'python' in plugin.languages
    assert plugin.order == 20
    assert callable(plugin.obfuscate)


# 5. registry.chain(content, 'python', None) returns modified content
def test_chain_all_modifies_content():
    reg = _fresh_registry()
    result = reg.chain(TEST_CONTENT, 'python', None)
    assert result != TEST_CONTENT, "chain() should modify content"


# 6. registry.chain with names=['default'] runs only default
def test_chain_only_default():
    reg = _fresh_registry()
    result = reg.chain(TEST_CONTENT, 'python', None, names=['default'])
    assert result != TEST_CONTENT, "chain(names=['default']) should modify content"
    # Should still be valid-ish Python (has shebang)
    assert '#!/usr/bin/env python3' in result or 'python' in result.lower()


# 7. default obfuscator changes content (is not identity)
def test_default_modifies_content():
    reg = _fresh_registry()
    plugin = reg.get('default')
    result = plugin.obfuscate(TEST_CONTENT, 'python', None)
    assert result != TEST_CONTENT, "default obfuscator should modify content"
    # Key function names should be replaced
    assert 'execute_command' not in result or 'get_metadata' not in result


# 8. dynamic obfuscator changes content (is not identity)
def test_dynamic_modifies_content():
    reg = _fresh_registry()
    plugin = reg.get('dynamic')
    result = plugin.obfuscate(TEST_CONTENT, 'python', None)
    assert result != TEST_CONTENT, "dynamic obfuscator should modify content"


# 9. dynamic obfuscator produces different output on two calls (random seed)
def test_dynamic_produces_different_output():
    reg = _fresh_registry()
    plugin = reg.get('dynamic')
    result1 = plugin.obfuscate(TEST_CONTENT, 'python', None)
    result2 = plugin.obfuscate(TEST_CONTENT, 'python', None)
    assert result1 != result2, (
        "dynamic obfuscator should produce different output on each call"
    )


# 10. Obfuscators return content unchanged for unsupported languages
def test_unsupported_language_returns_unchanged():
    reg = _fresh_registry()
    for name in ['default', 'dynamic']:
        plugin = reg.get(name)
        result = plugin.obfuscate(TEST_CONTENT, 'ruby', None)
        assert result == TEST_CONTENT, (
            f"{name} should return content unchanged for unsupported language 'ruby'"
        )


if __name__ == '__main__':
    tests = [
        test_registry_discovers_plugins,
        test_list_available_contains_expected,
        test_get_default_metadata,
        test_get_dynamic_metadata,
        test_chain_all_modifies_content,
        test_chain_only_default,
        test_default_modifies_content,
        test_dynamic_modifies_content,
        test_dynamic_produces_different_output,
        test_unsupported_language_returns_unchanged,
    ]
    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            print(f"  PASS  {test.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {test.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed out of {len(tests)} tests")
    sys.exit(1 if failed else 0)
