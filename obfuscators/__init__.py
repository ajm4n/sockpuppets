"""Pluggable obfuscation pipeline.

Drop .py files into obfuscators/ or obfuscators/private/ — each file must export:
- OBFUSCATOR dict with: name, description, languages (list), order (int)
- obfuscate(content: str, lang: str, config) -> str
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_BASE_DIR = Path(__file__).parent
_PRIVATE_DIR = _BASE_DIR / "private"


class ObfuscatorPlugin:
    def __init__(self, name, description, languages, order, obfuscate_fn):
        self.name = name
        self.description = description
        self.languages = languages
        self.order = order
        self.obfuscate = obfuscate_fn


class ObfuscatorRegistry:
    def __init__(self):
        self._plugins: dict[str, ObfuscatorPlugin] = {}
        self._discovered = False

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
                        f"obfuscators.{name}", py_file
                    )
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    meta = getattr(mod, "OBFUSCATOR", None)
                    fn = getattr(mod, "obfuscate", None)
                    if meta and fn and callable(fn):
                        self._plugins[meta["name"]] = ObfuscatorPlugin(
                            name=meta["name"],
                            description=meta.get("description", ""),
                            languages=meta.get("languages", ["python"]),
                            order=meta.get("order", 50),
                            obfuscate_fn=fn,
                        )
                except Exception:
                    pass

    def get(self, name: str) -> ObfuscatorPlugin | None:
        if not self._discovered:
            self.discover()
        return self._plugins.get(name)

    def list_available(self) -> list[str]:
        if not self._discovered:
            self.discover()
        return sorted(self._plugins.keys())

    def chain(self, content: str, lang: str, config, names: list[str] | None = None) -> str:
        """Run obfuscators in order. If names is None, run all that support the language."""
        if not self._discovered:
            self.discover()
        if names is not None:
            plugins = [self._plugins[n] for n in names if n in self._plugins]
        else:
            plugins = list(self._plugins.values())
        plugins = [p for p in plugins if lang in p.languages]
        plugins.sort(key=lambda p: p.order)
        for plugin in plugins:
            content = plugin.obfuscate(content, lang, config)
        return content


registry = ObfuscatorRegistry()
