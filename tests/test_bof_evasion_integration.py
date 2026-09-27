"""Tests for BOF loader integration with the evasion system.

Validates that bof_loader is properly wired into EvasionConfig,
FEATURE_LANG_SUPPORT, _PLACEHOLDER_MAP, and get_all_evasion_code.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from evasion import (
    EvasionConfig,
    FEATURE_LANG_SUPPORT,
    _PLACEHOLDER_MAP,
    get_all_evasion_code,
)


# ---------------------------------------------------------------------------
# EvasionConfig.bof field
# ---------------------------------------------------------------------------

class TestEvasionConfigBofField:
    def test_bof_field_exists_default_false(self):
        cfg = EvasionConfig()
        assert hasattr(cfg, "bof")
        assert cfg.bof is False

    def test_bof_field_set_true(self):
        cfg = EvasionConfig(bof=True)
        assert cfg.bof is True


# ---------------------------------------------------------------------------
# FEATURE_LANG_SUPPORT and _PLACEHOLDER_MAP
# ---------------------------------------------------------------------------

class TestFeatureMaps:
    def test_bof_loader_in_feature_lang_support(self):
        assert "bof_loader" in FEATURE_LANG_SUPPORT
        assert "python" in FEATURE_LANG_SUPPORT["bof_loader"]

    def test_bof_loader_in_placeholder_map(self):
        assert "bof_loader" in _PLACEHOLDER_MAP
        assert _PLACEHOLDER_MAP["bof_loader"] == "EVASION_BOF"


# ---------------------------------------------------------------------------
# get_all_evasion_code integration
# ---------------------------------------------------------------------------

class TestGetAllEvasionCode:
    def test_bof_true_python_includes_evasion_bof(self):
        cfg = EvasionConfig(bof=True)
        result = get_all_evasion_code("python", cfg)
        assert "EVASION_BOF" in result

    def test_bof_false_python_excludes_evasion_bof(self):
        cfg = EvasionConfig(bof=False)
        result = get_all_evasion_code("python", cfg)
        assert "EVASION_BOF" not in result

    def test_bof_true_powershell_excludes_evasion_bof(self):
        cfg = EvasionConfig(bof=True)
        result = get_all_evasion_code("powershell", cfg)
        assert "EVASION_BOF" not in result
