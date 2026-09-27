"""Regression: AgentGenerator utility functions — entropy, key generation, obfuscation."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from agent import AgentGenerator


@pytest.fixture
def gen():
    return AgentGenerator(output_dir="/tmp/sockpuppets_test_output")


class TestShannonEntropy:
    def test_empty_string(self, gen):
        assert gen.calculate_shannon_entropy("") == 0.0

    def test_single_char(self, gen):
        assert gen.calculate_shannon_entropy("aaaa") == 0.0

    def test_two_chars_equal(self, gen):
        entropy = gen.calculate_shannon_entropy("ab" * 50)
        assert abs(entropy - 1.0) < 0.01

    def test_high_entropy(self, gen):
        import string
        high = string.ascii_letters + string.digits + string.punctuation
        entropy = gen.calculate_shannon_entropy(high * 3)
        assert entropy > 5.0

    def test_normal_code_range(self, gen):
        code = """
import os
import json

def execute_command(command):
    return os.popen(command).read()

def get_metadata():
    return {'type': 'register', 'hostname': 'test'}
"""
        entropy = gen.calculate_shannon_entropy(code)
        assert 3.5 < entropy < 6.5


class TestReduceEntropy:
    def test_low_entropy_unchanged(self, gen):
        code = "x = 1\ny = 2\nz = 3\n"
        result = gen.reduce_entropy(code)
        assert result == code

    def test_high_entropy_reduced(self, gen):
        import string, random
        high = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=2000))
        high_code = f'data = """{high}"""\n'
        result = gen.reduce_entropy(high_code)
        new_entropy = gen.calculate_shannon_entropy(result)
        assert new_entropy < gen.calculate_shannon_entropy(high_code) or new_entropy < 6.5


class TestRandomString:
    def test_default_length(self, gen):
        s = gen.random_string()
        assert len(s) == 8

    def test_custom_length(self, gen):
        s = gen.random_string(16)
        assert len(s) == 16

    def test_alphanumeric(self, gen):
        s = gen.random_string(100)
        assert s.isalnum()

    def test_uniqueness(self, gen):
        strings = {gen.random_string() for _ in range(10)}
        assert len(strings) >= 8, "random_string should produce mostly unique values"


class TestRandomVarName:
    def test_valid_python_identifier(self, gen):
        for _ in range(10):
            name = gen.random_var_name()
            assert name.isidentifier(), f"'{name}' is not a valid Python identifier"

    def test_not_empty(self, gen):
        assert len(gen.random_var_name()) > 0
