"""Pluggable obfuscation pattern system.

Drop .py files into patterns/ or patterns/private/ — each file must export a
PATTERNS dict. Use --patterns=<name> to select (default: default).
"""
from __future__ import annotations

import importlib.util
import random
import string
from pathlib import Path

_BASE_DIR = Path(__file__).parent
_PRIVATE_DIR = _BASE_DIR / "private"

_REQUIRED_KEYS = {
    "var_prefixes",
    "junk_templates",
    "string_encodings",
    "padding_words",
    "import_prefixes",
    "func_prefixes",
}


def _load_patterns(name: str) -> dict:
    for directory in (_PRIVATE_DIR, _BASE_DIR):
        path = directory / f"{name}.py"
        if path.is_file():
            spec = importlib.util.spec_from_file_location(
                f"patterns.{name}", path
            )
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            patterns = getattr(mod, "PATTERNS", None)
            if patterns and _REQUIRED_KEYS.issubset(patterns):
                return patterns
            raise ValueError(
                f"Pattern file {path} missing PATTERNS dict or required keys: "
                f"{_REQUIRED_KEYS - set(patterns or {})}"
            )
    raise FileNotFoundError(f"No pattern file found for '{name}'")


class PatternProvider:
    def __init__(self, name: str = "default"):
        self._patterns = _load_patterns(name)
        self.name = name

    @property
    def var_prefixes(self) -> list[str]:
        return self._patterns["var_prefixes"]

    @property
    def junk_templates(self) -> list[str]:
        return self._patterns["junk_templates"]

    @property
    def string_encodings(self) -> list[str]:
        return self._patterns["string_encodings"]

    @property
    def padding_words(self) -> list[str]:
        return self._patterns["padding_words"]

    @property
    def import_prefixes(self) -> list[str]:
        return self._patterns["import_prefixes"]

    @property
    def func_prefixes(self) -> list[str]:
        return self._patterns["func_prefixes"]

    def random_string(self, length: int = 6) -> str:
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))

    def random_var_name(self) -> str:
        return random.choice(self.var_prefixes) + "_" + self.random_string()

    def random_func_name(self) -> str:
        return random.choice(self.func_prefixes) + "_" + self.random_string()

    def random_junk(self) -> str:
        template = random.choice(self.junk_templates)
        return template.format(
            var=self.random_var_name(),
            func=self.random_func_name(),
            rand_int=random.randint(0, 1000),
        )
