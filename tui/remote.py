"""Remote server proxy for connecting TUI to a remote SockPuppets instance."""

import asyncio
import json
import getpass

import aiohttp


class RemoteEventBus:
    def __init__(self):
        self._subscribers = []

    def subscribe(self):
        q = asyncio.Queue()
        loop = asyncio.get_event_loop()
        self._subscribers.append((q, loop))
        return q

    def unsubscribe(self, q):
        self._subscribers = [(sq, sl) for sq, sl in self._subscribers if sq is not q]

    def emit(self, event):
        for q, loop in list(self._subscribers):
            try:
                loop.call_soon_threadsafe(q.put_nowait, event)
            except Exception:
                pass


class RemoteServer:
    """Proxy that exposes the same interface as SockPuppetsServer
    but forwards calls to a remote instance's HTTP API."""

    def __init__(self, host_port: str):
        if "://" not in host_port:
            host_port = "http://" + host_port
        self.base_url = host_port.rstrip("/")
        self.api_url = self.base_url + "/api"
        self.token = None
        self.events = RemoteEventBus()
        self.ws_server = True
        self._session = None
        self._agents_cache = []

        print(f"[*] Connecting to remote SockPuppets: {self.base_url}")
        username = input("    Username: ").strip() or "admin"
        password = getpass.getpass("    Password: ")
        self._username = username
        self._password = password

        self._login_sync()

    def _login_sync(self):
        import urllib.request
        import urllib.error

        url = self.api_url + "/auth/login"
        data = json.dumps({"username": self._username, "password": self._password}).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read())
                self.token = result.get("token")
                if not self.token:
                    raise ValueError("No token in login response")
                print(f"[+] Authenticated as {self._username}")
        except urllib.error.HTTPError as e:
            body = e.read().decode() if e.fp else ""
            raise ConnectionError(f"Login failed ({e.code}): {body}")
        except urllib.error.URLError as e:
            raise ConnectionError(f"Cannot reach {self.base_url}: {e.reason}")

    def _headers(self):
        h = {"Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    async def _ensure_session(self):
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(headers=self._headers())
        return self._session

    async def _get(self, path):
        session = await self._ensure_session()
        async with session.get(self.api_url + path) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def _post(self, path, data=None):
        session = await self._ensure_session()
        async with session.post(self.api_url + path, json=data or {}) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def _delete(self, path):
        session = await self._ensure_session()
        async with session.delete(self.api_url + path) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def start_ws_events(self):
        """Connect to the remote WebSocket for live events."""
        ws_url = self.base_url.replace("http://", "ws://").replace("https://", "wss://")
        ws_url += "/api/ws?name=tui-remote"
        session = await self._ensure_session()
        try:
            ws = await session.ws_connect(ws_url)
            await ws.send_json({"token": self.token})

            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    try:
                        event = json.loads(msg.data)
                        self.events.emit(event)
                    except json.JSONDecodeError:
                        pass
                elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                    break
        except Exception:
            pass

    def get_agent_list(self):
        try:
            result = self._sync_get("/agents")
            self._agents_cache = result
            return result
        except Exception:
            return self._agents_cache

    def _sync_get(self, path):
        import urllib.request
        req = urllib.request.Request(
            self.api_url + path,
            headers=self._headers(),
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())

    def get_active_agents(self):
        agents = self.get_agent_list()
        return [a for a in agents if a.get("active")]

    def get_listeners(self):
        try:
            return self._sync_get("/listeners")
        except Exception:
            return []

    def check_agent_health(self, agent_id):
        agents = self._agents_cache or self.get_agent_list()
        for a in agents:
            if a.get("id") == agent_id:
                return a.get("health_warning")
        return None

    async def send_command_to_agent(self, agent_id, command):
        result = await self._post(f"/agents/{agent_id}/command", {"command": command})
        return result.get("output") or result.get("message", str(result))

    async def send_bof_to_agent(self, agent_id, bof_data, bof_args="", entry="go"):
        result = await self._post(f"/agents/{agent_id}/bof", {
            "bof_data": bof_data,
            "args": bof_args,
            "entry": entry,
        })
        return result.get("output", str(result))

    async def kill_agent(self, agent_id):
        result = await self._post(f"/agents/{agent_id}/kill")
        return result.get("message", str(result))

    async def set_beacon_interval(self, agent_id, interval):
        result = await self._post(f"/agents/{agent_id}/sleep", {"interval": interval})
        return result.get("message", str(result))

    async def upgrade_to_streaming(self, agent_id):
        result = await self._post(f"/agents/{agent_id}/upgrade")
        return result.get("message", str(result))

    async def downgrade_to_beacon(self, agent_id, interval=60):
        result = await self._post(f"/agents/{agent_id}/downgrade", {"interval": interval})
        return result.get("message", str(result))

    async def start_http_listener(self, host, port):
        return await self._post("/listeners", {"type": "http", "host": host, "port": port})

    async def start_ws_listener(self, host, port):
        return await self._post("/listeners", {"type": "websocket", "host": host, "port": port})

    async def start_socks_proxy(self, agent_id, port):
        result = await self._post(f"/agents/{agent_id}/socks", {"port": port})
        return result.get("message", str(result))
