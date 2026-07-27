"""Tests for evasion.bof_loader module.

Validates that the generated code string contains all expected elements:
COFFLoader class, BeaconAPI functions, handle_bof, correct memory constants,
struct definitions, and proper conditional behavior based on syscall config.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from evasion import EvasionConfig
from evasion.bof_loader import generate_code


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def config_no_syscalls():
    """EvasionConfig with no syscalls (direct Win32 API)."""
    return EvasionConfig()


@pytest.fixture
def config_with_syscalls():
    """EvasionConfig with indirect syscalls enabled."""
    return EvasionConfig(syscalls='indirect')


@pytest.fixture
def config_direct_syscalls():
    """EvasionConfig with direct syscalls enabled."""
    return EvasionConfig(syscalls='direct')


@pytest.fixture
def code_no_syscalls(config_no_syscalls):
    """Generated code without syscall wrappers."""
    return generate_code('python', config_no_syscalls)


@pytest.fixture
def code_with_syscalls(config_with_syscalls):
    """Generated code with syscall wrappers."""
    return generate_code('python', config_with_syscalls)


# ---------------------------------------------------------------------------
# Language gate
# ---------------------------------------------------------------------------

class TestLanguageGate:
    """generate_code returns empty string for non-python languages."""

    def test_returns_empty_for_powershell(self, config_no_syscalls):
        assert generate_code('powershell', config_no_syscalls) == ''

    def test_returns_empty_for_javascript(self, config_no_syscalls):
        assert generate_code('javascript', config_no_syscalls) == ''

    def test_returns_empty_for_vbscript(self, config_no_syscalls):
        assert generate_code('vbscript', config_no_syscalls) == ''

    def test_returns_empty_for_csharp(self, config_no_syscalls):
        assert generate_code('csharp', config_no_syscalls) == ''

    def test_returns_nonempty_for_python(self, code_no_syscalls):
        assert len(code_no_syscalls) > 0

    def test_returns_string_for_python(self, code_no_syscalls):
        assert isinstance(code_no_syscalls, str)


# ---------------------------------------------------------------------------
# BOF marker
# ---------------------------------------------------------------------------

class TestBofMarker:
    """The generated code must contain the __bof__ identifier string."""

    def test_bof_marker_present(self, code_no_syscalls):
        assert '__bof__' in code_no_syscalls

    def test_bof_marker_present_with_syscalls(self, code_with_syscalls):
        assert '__bof__' in code_with_syscalls


# ---------------------------------------------------------------------------
# COFFLoader class
# ---------------------------------------------------------------------------

class TestCOFFLoaderPresence:
    """The generated code must define the COFFLoader class with core methods."""

    def test_class_defined(self, code_no_syscalls):
        assert 'class COFFLoader' in code_no_syscalls

    def test_load_method(self, code_no_syscalls):
        assert 'def load(self' in code_no_syscalls

    def test_parse_coff_method(self, code_no_syscalls):
        assert 'def _parse_coff(self' in code_no_syscalls

    def test_load_sections_method(self, code_no_syscalls):
        assert 'def _load_sections(self' in code_no_syscalls

    def test_resolve_symbols_method(self, code_no_syscalls):
        assert 'def _resolve_symbols(self' in code_no_syscalls

    def test_apply_relocations_method(self, code_no_syscalls):
        assert 'def _apply_relocations(self' in code_no_syscalls

    def test_execute_method(self, code_no_syscalls):
        assert 'def _execute(self' in code_no_syscalls


# ---------------------------------------------------------------------------
# BeaconAPI functions
# ---------------------------------------------------------------------------

class TestBeaconAPIFunctions:
    """All required BeaconAPI functions must be present in generated code."""

    @pytest.mark.parametrize("func_name", [
        'BeaconPrintf',
        'BeaconOutput',
        'BeaconDataParse',
        'BeaconDataInt',
        'BeaconDataShort',
        'BeaconDataExtract',
        'BeaconDataLength',
        'BeaconFormatAlloc',
        'BeaconFormatFree',
        'BeaconFormatAppend',
        'BeaconFormatPrintf',
        'BeaconFormatToString',
        'BeaconFormatInt',
        'BeaconGetSpawnTo',
        'BeaconIsAdmin',
        'BeaconUseToken',
        'BeaconRevertToken',
    ])
    def test_beacon_function_defined(self, code_no_syscalls, func_name):
        assert f'def {func_name}(' in code_no_syscalls

    @pytest.mark.parametrize("func_name", [
        'BeaconInjectProcess',
        'BeaconInjectTemporaryProcess',
        'BeaconSpawnTemporaryProcess',
        'BeaconCleanupProcess',
        'BeaconFormatReset',
    ])
    def test_additional_beacon_functions(self, code_no_syscalls, func_name):
        assert f'def {func_name}(' in code_no_syscalls


# ---------------------------------------------------------------------------
# BEACON_API lookup table
# ---------------------------------------------------------------------------

class TestBeaconAPITable:
    """The BEACON_API dict must map all function names."""

    def test_beacon_api_dict_present(self, code_no_syscalls):
        assert 'BEACON_API' in code_no_syscalls

    @pytest.mark.parametrize("func_name", [
        'BeaconPrintf',
        'BeaconOutput',
        'BeaconDataParse',
        'BeaconDataInt',
        'BeaconDataShort',
        'BeaconDataLength',
        'BeaconDataExtract',
        'BeaconFormatAlloc',
        'BeaconFormatPrintf',
        'BeaconFormatToString',
        'BeaconFormatInt',
        'BeaconGetSpawnTo',
        'BeaconIsAdmin',
        'BeaconUseToken',
        'BeaconRevertToken',
    ])
    def test_function_in_api_table(self, code_no_syscalls, func_name):
        assert f"'{func_name}'" in code_no_syscalls


# ---------------------------------------------------------------------------
# Struct definitions
# ---------------------------------------------------------------------------

class TestStructDefinitions:
    """datap and formatp ctypes structures must be defined."""

    def test_datap_defined(self, code_no_syscalls):
        assert 'class datap(ctypes.Structure)' in code_no_syscalls

    def test_formatp_defined(self, code_no_syscalls):
        assert 'class formatp(ctypes.Structure)' in code_no_syscalls

    def test_datap_has_fields(self, code_no_syscalls):
        # Check that datap has the expected fields
        idx = code_no_syscalls.index('class datap')
        section = code_no_syscalls[idx:idx+300]
        assert 'original' in section
        assert 'buffer' in section
        assert 'length' in section
        assert 'size' in section

    def test_formatp_has_fields(self, code_no_syscalls):
        idx = code_no_syscalls.index('class formatp')
        section = code_no_syscalls[idx:idx+300]
        assert 'original' in section
        assert 'buffer' in section
        assert 'length' in section
        assert 'size' in section


# ---------------------------------------------------------------------------
# handle_bof function
# ---------------------------------------------------------------------------

class TestHandleBof:
    """The handle_bof entry point must be defined."""

    def test_handle_bof_defined(self, code_no_syscalls):
        assert 'def handle_bof(' in code_no_syscalls

    def test_handle_bof_uses_base64(self, code_no_syscalls):
        assert 'base64' in code_no_syscalls

    def test_handle_bof_creates_loader(self, code_no_syscalls):
        assert 'COFFLoader()' in code_no_syscalls

    def test_handle_bof_has_error_handling(self, code_no_syscalls):
        assert 'BOF execution failed' in code_no_syscalls

    def test_handle_bof_has_success_message(self, code_no_syscalls):
        assert 'BOF executed successfully' in code_no_syscalls


# ---------------------------------------------------------------------------
# Memory protection: no PAGE_EXECUTE_READWRITE
# ---------------------------------------------------------------------------

class TestMemoryProtection:
    """Code must never use PAGE_EXECUTE_READWRITE (0x40)."""

    def test_no_page_execute_readwrite_no_syscalls(self, code_no_syscalls):
        assert 'PAGE_EXECUTE_READWRITE' not in code_no_syscalls
        # 0x40 may appear in section characteristics (0x00000040, 0x40000000)
        # but must not appear as a standalone memory protection constant
        assert 'PAGE_EXECUTE_READWRITE' not in code_no_syscalls

    def test_no_page_execute_readwrite_with_syscalls(self, code_with_syscalls):
        assert 'PAGE_EXECUTE_READWRITE' not in code_with_syscalls

    def test_uses_page_readwrite(self, code_no_syscalls):
        assert 'PAGE_READWRITE' in code_no_syscalls

    def test_uses_page_execute_read(self, code_no_syscalls):
        assert 'PAGE_EXECUTE_READ' in code_no_syscalls


# ---------------------------------------------------------------------------
# COFF constants
# ---------------------------------------------------------------------------

class TestCOFFConstants:
    """Required COFF constants must be defined."""

    def test_machine_amd64(self, code_no_syscalls):
        assert 'IMAGE_FILE_MACHINE_AMD64' in code_no_syscalls
        assert '0x8664' in code_no_syscalls

    def test_reloc_addr64(self, code_no_syscalls):
        assert 'IMAGE_REL_AMD64_ADDR64' in code_no_syscalls

    def test_reloc_addr32nb(self, code_no_syscalls):
        assert 'IMAGE_REL_AMD64_ADDR32NB' in code_no_syscalls

    def test_reloc_rel32(self, code_no_syscalls):
        assert 'IMAGE_REL_AMD64_REL32' in code_no_syscalls

    def test_mem_commit(self, code_no_syscalls):
        assert 'MEM_COMMIT' in code_no_syscalls

    def test_mem_reserve(self, code_no_syscalls):
        assert 'MEM_RESERVE' in code_no_syscalls

    def test_mem_release(self, code_no_syscalls):
        assert 'MEM_RELEASE' in code_no_syscalls

    def test_sym_class_external(self, code_no_syscalls):
        assert 'IMAGE_SYM_CLASS_EXTERNAL' in code_no_syscalls

    def test_sym_class_static(self, code_no_syscalls):
        assert 'IMAGE_SYM_CLASS_STATIC' in code_no_syscalls


# ---------------------------------------------------------------------------
# Import resolution (__imp_ handling)
# ---------------------------------------------------------------------------

class TestImportResolution:
    """Symbol resolution must handle __imp_ prefixed imports."""

    def test_imp_prefix_handling(self, code_no_syscalls):
        assert '__imp_' in code_no_syscalls

    def test_load_library(self, code_no_syscalls):
        assert 'LoadLibraryA' in code_no_syscalls

    def test_get_proc_address(self, code_no_syscalls):
        assert 'GetProcAddress' in code_no_syscalls


# ---------------------------------------------------------------------------
# Syscall conditional behavior
# ---------------------------------------------------------------------------

class TestSyscallConditional:
    """Memory functions route through syscalls when configured."""

    def test_syscall_alloc_referenced_when_configured(self, code_with_syscalls):
        assert 'syscall_alloc' in code_with_syscalls

    def test_syscall_protect_referenced_when_configured(self, code_with_syscalls):
        assert 'syscall_protect' in code_with_syscalls

    def test_virtual_alloc_used_when_no_syscalls(self, code_no_syscalls):
        assert 'VirtualAlloc' in code_no_syscalls

    def test_virtual_protect_used_when_no_syscalls(self, code_no_syscalls):
        assert 'VirtualProtect' in code_no_syscalls

    def test_try_except_fallback_with_syscalls(self, code_with_syscalls):
        # When syscalls configured, should have try/except block for fallback
        assert 'try:' in code_with_syscalls
        assert 'except NameError' in code_with_syscalls

    def test_no_syscall_try_except_in_memory_section_without_syscalls(self, code_no_syscalls):
        # The _bof_alloc/protect section should NOT have the NameError fallback
        # (NameError fallback only appears in BeaconInjectProcess which is always present)
        bof_alloc_idx = code_no_syscalls.index('def _bof_alloc(')
        # Get the section between _bof_alloc and COFFLoader class
        coff_idx = code_no_syscalls.index('class COFFLoader')
        memory_section = code_no_syscalls[bof_alloc_idx:coff_idx]
        assert 'except NameError' not in memory_section

    def test_direct_syscalls_also_reference_wrappers(self, config_direct_syscalls):
        code = generate_code('python', config_direct_syscalls)
        assert 'syscall_alloc' in code
        assert 'syscall_protect' in code


# ---------------------------------------------------------------------------
# Relocation handling
# ---------------------------------------------------------------------------

class TestRelocationHandling:
    """Relocation application must handle all three AMD64 types."""

    def test_addr64_handling(self, code_no_syscalls):
        assert 'IMAGE_REL_AMD64_ADDR64' in code_no_syscalls

    def test_addr32nb_handling(self, code_no_syscalls):
        assert 'IMAGE_REL_AMD64_ADDR32NB' in code_no_syscalls

    def test_rel32_handling(self, code_no_syscalls):
        assert 'IMAGE_REL_AMD64_REL32' in code_no_syscalls


# ---------------------------------------------------------------------------
# Memory lifecycle
# ---------------------------------------------------------------------------

class TestMemoryLifecycle:
    """Code must handle RW->RX transitions and cleanup."""

    def test_virtual_free_present(self, code_no_syscalls):
        assert 'VirtualFree' in code_no_syscalls

    def test_memset_zeroing(self, code_no_syscalls):
        assert 'ctypes.memset' in code_no_syscalls

    def test_cfunctype_for_entry(self, code_no_syscalls):
        assert 'CFUNCTYPE' in code_no_syscalls


# ---------------------------------------------------------------------------
# Process/token API stubs
# ---------------------------------------------------------------------------

class TestProcessTokenAPIs:
    """BeaconAPI process and token functions must be present."""

    def test_impersonate_logged_on_user(self, code_no_syscalls):
        assert 'ImpersonateLoggedOnUser' in code_no_syscalls

    def test_revert_to_self(self, code_no_syscalls):
        assert 'RevertToSelf' in code_no_syscalls

    def test_is_user_an_admin(self, code_no_syscalls):
        assert 'IsUserAnAdmin' in code_no_syscalls

    def test_rundll32_spawn_path(self, code_no_syscalls):
        assert 'rundll32.exe' in code_no_syscalls
