$ErrorActionPreference = 'Stop'
if (-not ('Win32.HdHop' -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace Win32 {
  public static class HdHop {
    public static int Session() {
      int sid = 0;
      ProcessIdToSessionId(GetCurrentProcessId(), out sid);
      return sid;
    }
    public static string Launch(string cmd, string file) {
      int sid = WTSGetActiveConsoleSessionId();
      IntPtr tok, dup;
      if (!WTSQueryUserToken(sid, out tok)) return "token failed " + Marshal.GetLastWin32Error();
      if (!DuplicateTokenEx(tok, 0x02000000, IntPtr.Zero, 2, 1, out dup)) return "dup failed " + Marshal.GetLastWin32Error();
      var si = new STARTUPINFO();
      si.cb = Marshal.SizeOf(si);
      si.lpDesktop = "winsta0\\default";
      PROCESS_INFORMATION pi;
      if (!CreateProcessAsUserW(dup, null, cmd, IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref si, out pi))
        return "launch failed " + Marshal.GetLastWin32Error();
      CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(tok); CloseHandle(dup);
      return "host pid=" + pi.dwProcessId + " session=" + sid + " file=" + file;
    }
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
}
'@
}

$out = 'C:\Users\Public\psframe.txt'
if ($env:SP_HD_HOST -eq '1') {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
namespace Win32 {
  public static class HdCap {
    public static string Go(string path) {
      string name = "p" + DateTime.UtcNow.Ticks.ToString("x");
      int sidNow = SessionOf();
      SetLastError(0);
      IntPtr desk = CreateDesktopW(name, null, IntPtr.Zero, 0, 0x10000000, IntPtr.Zero);
      int openErr = Marshal.GetLastWin32Error();
      bool switched = desk != IntPtr.Zero && SetThreadDesktop(desk);
      if (!switched) name = "default err=" + (desk == IntPtr.Zero ? openErr : Marshal.GetLastWin32Error());
      var wins = new System.Collections.Generic.List<IntPtr>();
      EnumWindows((hwnd, lp) => { if (IsWindowVisible(hwnd)) wins.Add(hwnd); return true; }, IntPtr.Zero);
      int dw = 320, dh = 200, stride = ((dw * 3 + 3) / 4) * 4, painted = 0;
      var titles = new StringBuilder();
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
        var tb = new StringBuilder(64);
        GetWindowTextW(hwnd, tb, 64);
        titles.Append(tb.ToString()).Append(' ');
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
      System.IO.File.WriteAllText(path, "HDIMG:320,200:" + Convert.ToBase64String(file));
      return "host session=" + sidNow + " desk=" + name + " wins=" + painted + " " + titles;
    }
    static int SessionOf() { int sid = 0; ProcessIdToSessionId(GetCurrentProcessId(), out sid); return sid; }
    delegate bool EnumProc(IntPtr hwnd, IntPtr lp);
    [StructLayout(LayoutKind.Sequential)] struct RECT { public int l, t, r, b; }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct STARTUPINFO { public int cb; public string lpReserved, lpDesktop, lpTitle; public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError; }
    [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
    [StructLayout(LayoutKind.Sequential)] struct BITMAPINFO { public int biSize, biWidth, biHeight; public short biPlanes, biBitCount; public int biCompression, biSizeImage, biXPelsPerMeter, biYPelsPerMeter, biClrUsed, biClrImportant; }
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern IntPtr CreateDesktopW(string n, string d, IntPtr dm, int f, int acc, IntPtr sa);
    [DllImport("user32.dll")] static extern bool SetThreadDesktop(IntPtr h);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr lp);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT rc);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
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
    [DllImport("kernel32.dll")] static extern void SetLastError(uint err);
  }
}
'@
  try {
    $note = [Win32.HdCap]::Go($out)
  } catch {
    $note = $_.Exception.ToString()
  }
  Set-Content -Path 'C:\Users\Public\pshost.txt' -Value $note -Encoding ASCII
  exit 0
}

$sid = [Win32.HdHop]::Session()
if ($sid -eq 0) {
  $script = $MyInvocation.MyCommand.Path
  if (-not $script) { $script = 'C:\Users\Public\hd_hop.ps1' }
  $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$script`""
  $env:SP_HD_HOST = '1'
  $launched = [Win32.HdHop]::Launch($cmd, $out)
  Remove-Item Env:SP_HD_HOST -ErrorAction SilentlyContinue
  $deadline = (Get-Date).AddSeconds(20)
  while ((Get-Date) -lt $deadline -and -not (Test-Path $out)) { Start-Sleep -Milliseconds 400 }
  if (Test-Path 'C:\Users\Public\pshost.txt') { Get-Content 'C:\Users\Public\pshost.txt' } else { $launched }
  if (Test-Path $out) { 'frame ' + (Get-Item $out).Length }
  else { 'no frame' }
} else {
  Set-Content -Path 'C:\Users\Public\pshost.txt' -Value ("already session=" + $sid) -Encoding ASCII
  "already session=$sid"
}
