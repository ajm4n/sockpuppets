using System;
using System.IO;
using System.Runtime.InteropServices;

class HdHop {
    static int Main() {
        int sid = 0;
        ProcessIdToSessionId(GetCurrentProcessId(), out sid);
        if (Environment.GetEnvironmentVariable("SP_HD_HOST") != "1" && sid == 0) {
            int active = WTSGetActiveConsoleSessionId();
            IntPtr tok, dup;
            if (!WTSQueryUserToken(active, out tok)) return 2;
            if (!DuplicateTokenEx(tok, 0x02000000, IntPtr.Zero, 2, 1, out dup)) return 3;
            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            si.lpDesktop = "winsta0\\default";
            PROCESS_INFORMATION pi;
            string cmd = "\"" + System.Reflection.Assembly.GetExecutingAssembly().Location + "\"";
            Environment.SetEnvironmentVariable("SP_HD_HOST", "1");
            bool ok = CreateProcessAsUserW(dup, null, cmd, IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref si, out pi);
            Environment.SetEnvironmentVariable("SP_HD_HOST", null);
            if (!ok) return 4;
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(tok); CloseHandle(dup);
            var deadline = DateTime.UtcNow.AddSeconds(15);
            while (DateTime.UtcNow < deadline && !File.Exists(@"C:\Users\Public\csframe.txt")) System.Threading.Thread.Sleep(300);
            Console.WriteLine(File.Exists(@"C:\Users\Public\cshost.txt") ? File.ReadAllText(@"C:\Users\Public\cshost.txt").Trim() : "no host");
            Console.WriteLine(File.Exists(@"C:\Users\Public\csframe.txt") ? "frame " + new FileInfo(@"C:\Users\Public\csframe.txt").Length : "no frame");
            return 0;
        }
        File.WriteAllText(@"C:\Users\Public\cshost.txt", Capture());
        return 0;
    }
    static string Capture() {
        int sid = 0;
        ProcessIdToSessionId(GetCurrentProcessId(), out sid);
        var wins = new System.Collections.Generic.List<IntPtr>();
        EnumWindows((hwnd, lp) => { if (IsWindowVisible(hwnd)) wins.Add(hwnd); return true; }, IntPtr.Zero);
        int dw = 320, dh = 200, stride = ((dw * 3 + 3) / 4) * 4, painted = 0;
        var titles = new System.Text.StringBuilder();
        IntPtr hdc = GetDC(IntPtr.Zero);
        IntPtr mem = CreateCompatibleDC(hdc);
        IntPtr bmp = CreateCompatibleBitmap(hdc, dw, dh);
        SelectObject(mem, bmp);
        foreach (var hwnd in wins) {
            RECT rc; GetWindowRect(hwnd, out rc);
            int ww = rc.r - rc.l, wh = rc.b - rc.t;
            if (ww < 40 || wh < 40) continue;
            IntPtr src = GetWindowDC(hwnd);
            IntPtr tmp = CreateCompatibleDC(src);
            IntPtr bits = CreateCompatibleBitmap(src, ww, wh);
            SelectObject(tmp, bits);
            if (!PrintWindow(hwnd, tmp, 2)) BitBlt(tmp, 0, 0, ww, wh, src, 0, 0, 0x00CC0020);
            StretchBlt(mem, 8, 8, dw - 16, dh - 16, tmp, 0, 0, ww, wh, 0x00CC0020);
            DeleteObject(bits); DeleteDC(tmp); ReleaseDC(hwnd, src);
            var tb = new System.Text.StringBuilder(64);
            GetWindowTextW(hwnd, tb, 64);
            titles.Append(tb).Append(' ');
            if (++painted >= 3) break;
        }
        var pixels = new byte[stride * dh];
        var bi = new BITMAPINFO { biSize = 40, biWidth = dw, biHeight = dh, biPlanes = 1, biBitCount = 24 };
        GetDIBits(mem, bmp, 0, dh, pixels, ref bi, 0);
        var file = new byte[54 + pixels.Length];
        file[0] = 66; file[1] = 77;
        BitConverter.GetBytes(file.Length).CopyTo(file, 2);
        BitConverter.GetBytes(54).CopyTo(file, 10);
        BitConverter.GetBytes(40).CopyTo(file, 14);
        BitConverter.GetBytes(dw).CopyTo(file, 18);
        BitConverter.GetBytes(dh).CopyTo(file, 22);
        file[26] = 1; file[28] = 24;
        Buffer.BlockCopy(pixels, 0, file, 54, pixels.Length);
        File.WriteAllText(@"C:\Users\Public\csframe.txt", "HDIMG:320,200:" + Convert.ToBase64String(file));
        return "host session=" + sid + " wins=" + painted + " " + titles;
    }
    delegate bool EnumProc(IntPtr hwnd, IntPtr lp);
    [StructLayout(LayoutKind.Sequential)] struct RECT { public int l, t, r, b; }
    [StructLayout(LayoutKind.Sequential)] struct BITMAPINFO { public int biSize, biWidth, biHeight; public short biPlanes, biBitCount; public int biCompression, biSizeImage, biXPelsPerMeter, biYPelsPerMeter, biClrUsed, biClrImportant; }
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr lp);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT rc);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowTextW(IntPtr h, System.Text.StringBuilder s, int n);
    [DllImport("user32.dll")] static extern IntPtr GetDC(IntPtr h);
    [DllImport("user32.dll")] static extern IntPtr GetWindowDC(IntPtr h);
    [DllImport("user32.dll")] static extern int ReleaseDC(IntPtr h, IntPtr hdc);
    [DllImport("user32.dll")] static extern bool PrintWindow(IntPtr hwnd, IntPtr hdc, uint flags);
    [DllImport("gdi32.dll")] static extern IntPtr CreateCompatibleDC(IntPtr hdc);
    [DllImport("gdi32.dll")] static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int w, int h);
    [DllImport("gdi32.dll")] static extern IntPtr SelectObject(IntPtr hdc, IntPtr o);
    [DllImport("gdi32.dll")] static extern bool BitBlt(IntPtr d, int x, int y, int w, int h, IntPtr s, int sx, int sy, int rop);
    [DllImport("gdi32.dll")] static extern bool StretchBlt(IntPtr d, int x, int y, int w, int h, IntPtr s, int sx, int sy, int sw, int sh, int rop);
    [DllImport("gdi32.dll")] static extern int GetDIBits(IntPtr hdc, IntPtr bmp, int start, int lines, byte[] bits, ref BITMAPINFO bi, int usage);
    [DllImport("gdi32.dll")] static extern bool DeleteObject(IntPtr o);
    [DllImport("gdi32.dll")] static extern bool DeleteDC(IntPtr hdc);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] static extern bool CreateProcessW(string app, string cmd, IntPtr pa, IntPtr ta, bool inherit, int flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll")] static extern int GetCurrentProcessId();
    [DllImport("kernel32.dll")] static extern bool ProcessIdToSessionId(int pid, out int sid);
    [DllImport("kernel32.dll")] static extern int WTSGetActiveConsoleSessionId();
    [DllImport("wtsapi32.dll")] static extern bool WTSQueryUserToken(int sid, out IntPtr tok);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr t, uint acc, IntPtr sa, int ilevel, int type, out IntPtr dup);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateProcessAsUserW(IntPtr tok, string app, string cmd, IntPtr pa, IntPtr ta, bool inherit, int flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct STARTUPINFO { public int cb; public string lpReserved, lpDesktop, lpTitle; public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError; }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
}
