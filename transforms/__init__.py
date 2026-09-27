"""Custom transform plugin system for malleable C2 profiles.

Drop .py files into transforms/ or transforms/private/ — each file must export
encode(data: bytes) -> str and decode(encoded: str) -> bytes. The filename
(minus .py) becomes the transform name usable in profile YAML.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import Callable

_BASE_DIR = Path(__file__).parent
_PRIVATE_DIR = _BASE_DIR / "private"


class TransformRegistry:
    def __init__(self):
        self._builtins: dict[str, tuple[Callable, Callable]] = {}
        self._plugins: dict[str, tuple[Callable, Callable]] = {}
        self._discovered = False

    def register_builtin(self, name: str, encode_fn: Callable, decode_fn: Callable):
        self._builtins[name] = (encode_fn, decode_fn)

    def discover(self):
        if self._discovered:
            return
        self._discovered = True
        for directory in (_BASE_DIR, _PRIVATE_DIR):
            if not directory.is_dir():
                continue
            for py_file in sorted(directory.glob("*.py")):
                if py_file.name.startswith("_"):
                    continue
                name = py_file.stem
                try:
                    spec = importlib.util.spec_from_file_location(
                        f"transforms.{name}", py_file
                    )
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    if hasattr(mod, "encode") and hasattr(mod, "decode"):
                        self._plugins[name] = (mod.encode, mod.decode)
                except Exception:
                    pass

    def get(self, name: str) -> tuple[Callable, Callable] | None:
        if not self._discovered:
            self.discover()
        if name in self._plugins:
            return self._plugins[name]
        return self._builtins.get(name)

    def list_available(self) -> list[str]:
        if not self._discovered:
            self.discover()
        names = set(self._builtins) | set(self._plugins)
        return sorted(names)


registry = TransformRegistry()
