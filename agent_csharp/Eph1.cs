using System;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SvcHealth
{
    static class X25519
    {
        static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
        static readonly BigInteger A24 = 121665;

        static BigInteger Inv(BigInteger x) { return BigInteger.ModPow(x, P - 2, P); }

        public static byte[] ScalarMult(byte[] k, byte[] u)
        {
            var kc = (byte[])k.Clone();
            kc[0] &= 248; kc[31] &= 127; kc[31] |= 64;

            var ub = new byte[33];
            Buffer.BlockCopy(u, 0, ub, 0, 32);
            var uBI = new BigInteger(ub);

            BigInteger x1 = uBI, x2 = 1, z2 = 0, x3 = uBI, z3 = 1;
            int swap = 0;

            for (int t = 254; t >= 0; t--)
            {
                int kt = (kc[t >> 3] >> (t & 7)) & 1;
                swap ^= kt;
                CSwap(swap, ref x2, ref x3); CSwap(swap, ref z2, ref z3);
                swap = kt;

                var AA2 = Mod(x2 + z2); var AAA = Mod(AA2 * AA2);
                var BB2 = Mod(x2 - z2); var BBB = Mod(BB2 * BB2);
                var EE = Mod(AAA - BBB);
                var CC = Mod(x3 + z3); var DD = Mod(x3 - z3);
                var DA = Mod(DD * AA2); var CB = Mod(CC * BB2);
                x3 = Mod((DA + CB) * (DA + CB));
                z3 = Mod(x1 * Mod((DA - CB) * (DA - CB)));
                x2 = Mod(AAA * BBB);
                z2 = Mod(EE * (AAA + A24 * EE));
            }
            CSwap(swap, ref x2, ref x3); CSwap(swap, ref z2, ref z3);
            var result = Mod(x2 * Inv(z2));
            var rb = result.ToByteArray();
            var outb = new byte[32];
            int copyLen = Math.Min(rb.Length, 32);
            Buffer.BlockCopy(rb, 0, outb, 0, copyLen);
            return outb;
        }

        static BigInteger Mod(BigInteger v) { var r = v % P; return r < 0 ? r + P : r; }

        static void CSwap(int swap, ref BigInteger a, ref BigInteger b)
        {
            if (swap != 0) { var t = a; a = b; b = t; }
        }

        static readonly byte[] Basepoint = { 9, 0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0 };

        public static void GenerateKeypair(out byte[] priv, out byte[] pub)
        {
            priv = new byte[32];
            using (var rng = RandomNumberGenerator.Create()) { rng.GetBytes(priv); }
            pub = ScalarMult(priv, Basepoint);
        }

        public static byte[] ComputeShared(byte[] myPriv, byte[] theirPub) { return ScalarMult(myPriv, theirPub); }
    }

    static class AesGcmHelper
    {
        [StructLayout(LayoutKind.Sequential)]
        struct AUTH
        {
            public int cbSize, dwInfoVersion;
            public IntPtr pbNonce; public int cbNonce;
            public IntPtr pbAuthData; public int cbAuthData;
            public IntPtr pbTag; public int cbTag;
            public IntPtr pbMacContext; public int cbMacContext;
            public int cbAAD; public long cbData; public int dwFlags;
        }

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        static extern uint BCryptOpenAlgorithmProvider(out IntPtr h, string alg, string impl, uint flags);
        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        static extern uint BCryptSetProperty(IntPtr h, string prop, byte[] val, int len, uint flags);
        [DllImport("bcrypt.dll")]
        static extern uint BCryptGenerateSymmetricKey(IntPtr h, out IntPtr key, IntPtr obj, int objLen, byte[] secret, int secretLen, uint flags);
        [DllImport("bcrypt.dll")]
        static extern uint BCryptEncrypt(IntPtr key, byte[] input, int inLen, ref AUTH info, byte[] iv, int ivLen, byte[] output, int outLen, out int wrote, uint flags);
        [DllImport("bcrypt.dll")]
        static extern uint BCryptDecrypt(IntPtr key, byte[] input, int inLen, ref AUTH info, byte[] iv, int ivLen, byte[] output, int outLen, out int wrote, uint flags);
        [DllImport("bcrypt.dll")]
        static extern uint BCryptDestroyKey(IntPtr key);
        [DllImport("bcrypt.dll")]
        static extern uint BCryptCloseAlgorithmProvider(IntPtr h, uint flags);

        public static byte[] Encrypt(byte[] aesKey, byte[] nonce, byte[] plaintext, out byte[] tag)
        {
            IntPtr alg, bkey;
            BCryptOpenAlgorithmProvider(out alg, "AES", null, 0);
            var mode = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
            BCryptSetProperty(alg, "ChainingMode", mode, mode.Length, 0);
            BCryptGenerateSymmetricKey(alg, out bkey, IntPtr.Zero, 0, aesKey, aesKey.Length, 0);
            tag = new byte[16];
            var info = new AUTH();
            info.cbSize = Marshal.SizeOf(typeof(AUTH));
            info.dwInfoVersion = 1;
            info.cbNonce = nonce.Length;
            info.cbTag = 16;
            var nH = GCHandle.Alloc(nonce, GCHandleType.Pinned);
            var tH = GCHandle.Alloc(tag, GCHandleType.Pinned);
            info.pbNonce = nH.AddrOfPinnedObject();
            info.pbTag = tH.AddrOfPinnedObject();
            var ct = new byte[plaintext.Length];
            int wrote;
            BCryptEncrypt(bkey, plaintext, plaintext.Length, ref info, nonce, nonce.Length, ct, ct.Length, out wrote, 0);
            nH.Free(); tH.Free();
            BCryptDestroyKey(bkey); BCryptCloseAlgorithmProvider(alg, 0);
            return ct;
        }

        public static byte[] Decrypt(byte[] aesKey, byte[] nonce, byte[] ciphertext, byte[] tag)
        {
            IntPtr alg, bkey;
            BCryptOpenAlgorithmProvider(out alg, "AES", null, 0);
            var mode = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
            BCryptSetProperty(alg, "ChainingMode", mode, mode.Length, 0);
            BCryptGenerateSymmetricKey(alg, out bkey, IntPtr.Zero, 0, aesKey, aesKey.Length, 0);
            var info = new AUTH();
            info.cbSize = Marshal.SizeOf(typeof(AUTH));
            info.dwInfoVersion = 1;
            info.cbNonce = nonce.Length;
            info.cbTag = 16;
            var nH = GCHandle.Alloc(nonce, GCHandleType.Pinned);
            var tH = GCHandle.Alloc(tag, GCHandleType.Pinned);
            info.pbNonce = nH.AddrOfPinnedObject();
            info.pbTag = tH.AddrOfPinnedObject();
            var pt = new byte[ciphertext.Length];
            int wrote;
            BCryptDecrypt(bkey, ciphertext, ciphertext.Length, ref info, null, 0, pt, pt.Length, out wrote, 0);
            nH.Free(); tH.Free();
            BCryptDestroyKey(bkey); BCryptCloseAlgorithmProvider(alg, 0);
            return pt;
        }
    }

    static class Eph1
    {
        static readonly byte[] Salt = Encoding.UTF8.GetBytes("sockpuppets-salt-v1");
        static readonly byte[] InfoHs = Encoding.UTF8.GetBytes("sockpuppets-handshake-v1");
        static readonly byte[] InfoSession = Encoding.UTF8.GetBytes("sockpuppets-session-v1");

        static byte[] Hkdf(byte[] ikm, byte[] info)
        {
            byte[] prk;
            using (var hmacExtract = new HMACSHA256(Salt)) { prk = hmacExtract.ComputeHash(ikm); }
            byte[] okm;
            using (var hmacExpand = new HMACSHA256(prk))
            {
                var t = new byte[info.Length + 1];
                Buffer.BlockCopy(info, 0, t, 0, info.Length);
                t[info.Length] = 1;
                okm = hmacExpand.ComputeHash(t);
            }
            var result = new byte[32];
            Buffer.BlockCopy(okm, 0, result, 0, 32);
            return result;
        }

        static byte[] Seal(byte[] key, string plaintext)
        {
            var nonce = new byte[12];
            using (var rng = RandomNumberGenerator.Create()) { rng.GetBytes(nonce); }
            var pt = Encoding.UTF8.GetBytes(plaintext);
            byte[] tag;
            var ct = AesGcmHelper.Encrypt(key, nonce, pt, out tag);
            var result = new byte[12 + ct.Length + 16];
            Buffer.BlockCopy(nonce, 0, result, 0, 12);
            Buffer.BlockCopy(ct, 0, result, 12, ct.Length);
            Buffer.BlockCopy(tag, 0, result, 12 + ct.Length, 16);
            return result;
        }

        static string Open(byte[] key, byte[] blob)
        {
            var nonce = new byte[12];
            Buffer.BlockCopy(blob, 0, nonce, 0, 12);
            int ctLen = blob.Length - 12 - 16;
            var ct = new byte[ctLen];
            Buffer.BlockCopy(blob, 12, ct, 0, ctLen);
            var tag = new byte[16];
            Buffer.BlockCopy(blob, blob.Length - 16, tag, 0, 16);
            var pt = AesGcmHelper.Decrypt(key, nonce, ct, tag);
            return Encoding.UTF8.GetString(pt);
        }

        public static string SessionEncrypt(byte[] sessionKey, string plaintext)
        {
            var sealed_ = Seal(sessionKey, plaintext);
            var result = new byte[4 + sealed_.Length];
            Encoding.ASCII.GetBytes("AES1").CopyTo(result, 0);
            Buffer.BlockCopy(sealed_, 0, result, 4, sealed_.Length);
            return Convert.ToBase64String(result);
        }

        public static string SessionDecrypt(byte[] sessionKey, string encoded)
        {
            var raw = Convert.FromBase64String(encoded);
            if (raw.Length < 16 || Encoding.ASCII.GetString(raw, 0, 4) != "AES1")
                throw new Exception("ciphertext rejected");
            var payload = new byte[raw.Length - 4];
            Buffer.BlockCopy(raw, 4, payload, 0, payload.Length);
            return Open(sessionKey, payload);
        }

        public static byte[] EphPriv;
        public static byte[] HsKey;
        public static byte[] SessionKey;

        public static string ClientHello(byte[] serverPub, string plaintext)
        {
            byte[] priv, pub;
            X25519.GenerateKeypair(out priv, out pub);
            EphPriv = priv;
            var shared = X25519.ComputeShared(priv, serverPub);
            HsKey = Hkdf(shared, InfoHs);
            var sealed_ = Seal(HsKey, plaintext);
            var payload = new byte[32 + sealed_.Length];
            Buffer.BlockCopy(pub, 0, payload, 0, 32);
            Buffer.BlockCopy(sealed_, 0, payload, 32, sealed_.Length);
            return "EPH1." + Convert.ToBase64String(payload);
        }

        public static string ClientFinish(string blob)
        {
            if (!blob.StartsWith("EPH2.")) throw new Exception("not a welcome");
            var raw = Convert.FromBase64String(blob.Substring(5));
            var srvPub = new byte[32];
            Buffer.BlockCopy(raw, 0, srvPub, 0, 32);
            var rest = new byte[raw.Length - 32];
            Buffer.BlockCopy(raw, 32, rest, 0, rest.Length);
            var pt = Open(HsKey, rest);
            var shared2 = X25519.ComputeShared(EphPriv, srvPub);
            var combined = new byte[shared2.Length + HsKey.Length];
            Buffer.BlockCopy(shared2, 0, combined, 0, shared2.Length);
            Buffer.BlockCopy(HsKey, 0, combined, shared2.Length, HsKey.Length);
            SessionKey = Hkdf(combined, InfoSession);
            EphPriv = null;
            HsKey = null;
            return pt;
        }

        public static string Encrypt(string plaintext)
        {
            if (SessionKey != null) return SessionEncrypt(SessionKey, plaintext);
            return ClientHello(ServerPub, plaintext);
        }

        public static string Decrypt(string encoded)
        {
            if (encoded.StartsWith("EPH2.")) return ClientFinish(encoded);
            if (SessionKey != null) return SessionDecrypt(SessionKey, encoded);
            throw new Exception("no session key");
        }

        public static byte[] ServerPub;
    }
}
