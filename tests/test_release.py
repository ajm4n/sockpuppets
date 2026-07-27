#!/usr/bin/env python3
"""Release checks: crypto, HTTP protocol, CLI, and UI rendering."""

import asyncio
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from crypto.encryption import aes_decrypt, aes_encrypt
from server import SockPuppetsServer
from ui.theme import (
    console,
    print_agents_table,
    print_banner,
    print_command_result,
    print_generate_results,
    print_help_panel,
    print_interact_banner,
    print_listeners_table,
    print_status,
)


class CryptoTests(unittest.TestCase):
    def test_roundtrip(self):
        key = b"release-key"
        blob = aes_encrypt('{"type":"register"}', key)
        self.assertTrue(blob)
        self.assertEqual(aes_decrypt(blob, key), '{"type":"register"}')
        self.assertTrue(blob.startswith("QUVTM"))  # base64("AES1")
        with self.assertRaises(Exception):
            aes_decrypt(blob, b"wrong-key")


class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server = SockPuppetsServer("SOCKPUPPETS_KEY_2026")
        self.port = 18765
        await self.server.start_http_listener("127.0.0.1", self.port)

    async def asyncTearDown(self):
        await self.server.stop_listener()

    def _post(self, payload, key=None):
        import urllib.request
        from crypto.handshake import client_finish, client_hello
        blob, eph, hs = client_hello(self.server.identity.pub, json.dumps(payload))
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/v1/update",
            data=blob.encode(),
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            pt, session = client_finish(eph, hs, resp.read().decode())
            self.session = session
            return json.loads(pt)

    async def test_register_checkin_command_result_kill(self):
        reg = await asyncio.to_thread(self._post, {"type": "register", "metadata": {
            "hostname": "lab", "username": "tester", "os": "Linux",
            "mode": "beacon", "beacon_interval": 5,
        }})
        self.assertEqual(reg["type"], "registered")
        agent_id = reg["agent_id"]

        await self.server.send_command_to_agent(agent_id, "echo hi")
        check = await asyncio.to_thread(self._post, {
            "type": "checkin", "agent_id": agent_id,
            "metadata": {"mode": "beacon", "beacon_interval": 5},
            "results": [],
        })
        self.assertEqual(check["type"], "commands")
        self.assertEqual(check["commands"][0]["command"], "echo hi")

        again = await asyncio.to_thread(self._post, {
            "type": "checkin", "agent_id": agent_id,
            "metadata": {"mode": "beacon"},
            "results": [{"command": "echo hi", "output": "hi", "timestamp": "t"}],
        })
        self.assertEqual(again["type"], "no_commands")
        results = self.server.get_agent_results(agent_id)
        self.assertEqual(results[0]["output"], "hi")

        await self.server.kill_agent(agent_id)
        self.assertIn(agent_id, self.server.agents)
        killed = await asyncio.to_thread(self._post, {
            "type": "checkin", "agent_id": agent_id,
            "metadata": {"mode": "beacon"}, "results": [],
        })
        self.assertEqual(killed["commands"][0]["command"], "__kill")
        self.assertNotIn(agent_id, self.server.agents)

    async def test_control_messages_use_agent_key(self):
        reg = await asyncio.to_thread(self._post, {"type": "register", "metadata": {
            "hostname": "lab", "username": "tester", "os": "Linux", "mode": "beacon",
        }})
        agent_id = reg["agent_id"]
        msg = self.server.encrypt_for_agent(agent_id, '{"type":"set_interval","interval":10}')
        from crypto.handshake import session_decrypt
        self.assertEqual(session_decrypt(self.session, msg), '{"type":"set_interval","interval":10}')

    async def test_upgrade_ws_rewrites_bind_all(self):
        self.assertNotEqual(self.server._callback_host("0.0.0.0"), "0.0.0.0")
        self.assertEqual(self.server._callback_host("10.1.2.3"), "10.1.2.3")


class UITests(unittest.TestCase):
    def _render(self, fn):
        buf = StringIO()
        old = console.file
        console.file = buf
        try:
            fn()
        finally:
            console.file = old
        return buf.getvalue()

    def test_panels_render(self):
        text = self._render(print_banner)
        self.assertIn("C2 Framework", text)
        text = self._render(lambda: print_status("listener up", "success"))
        self.assertIn("listener up", text)
        text = self._render(print_help_panel)
        self.assertIn("upgrade_ws", text)
        self.assertIn("beacons", text)
        text = self._render(lambda: print_listeners_table([{
            "type": "http", "host": "127.0.0.1", "port": 8080, "started_at": "now",
        }]))
        self.assertIn("HTTP", text)
        text = self._render(lambda: print_agents_table([{
            "id": "abc", "hostname": "lab", "username": "user", "ip": "10.0.0.5",
            "os": "Windows", "transport": "http", "mode": "beacon",
            "beacon_interval": 30, "last_seen": "now", "warning": "late",
        }], {"abc"}))
        self.assertIn("abc", text)
        self.assertIn("10.0.0", text.replace("\n", ""))
        self.assertIn("late", text)
        text = self._render(lambda: print_generate_results({"python": "/tmp/a.py", "c": "Error: missing"}))
        self.assertIn("/tmp/a.py", text)
        self.assertIn("missing", text)
        text = self._render(lambda: print_interact_banner("abc", {
            "hostname": "lab", "username": "user", "os": "Windows",
            "mode": "beacon", "transport": "http", "beacon_interval": 30,
        }))
        self.assertIn("upgrade_ws", text)
        self.assertNotIn("socks PORT", text)
        text = self._render(lambda: print_command_result("whoami [x]", "lab\\user"))
        self.assertIn("whoami", text)
        self.assertIn("lab", text)


class CLITests(unittest.TestCase):
    def test_c_generate_does_not_nameerror(self):
        from main import SockPuppetsCLI
        from agent import AgentGenerator

        cli = SockPuppetsCLI()
        called = {}

        def fake_c(self, host, port, encryption_key="SOCKPUPPETS_KEY_2026", transport="http",
                   beacon_interval=60, beacon_jitter=0, unique_key=True):
            called["args"] = (host, port, encryption_key, transport, beacon_interval, beacon_jitter)
            return "Error: MinGW not found"

        old = AgentGenerator.generate_c_agent
        AgentGenerator.generate_c_agent = fake_c
        try:
            cli.do_generate("127.0.0.1 8080 --lang=c --transport=http --beacon --interval=15")
        finally:
            AgentGenerator.generate_c_agent = old
        self.assertEqual(called["args"][0], "127.0.0.1")
        self.assertEqual(called["args"][4], 15)

    def test_generate_python_compiles(self):
        from agent import AgentGenerator
        gen = AgentGenerator(output_dir=tempfile.mkdtemp())
        path = gen.generate_python_agent(
            "127.0.0.1", 18766, encryption_key="test-key",
            beacon_mode=True, beacon_interval=1, target_os="windows",
            transport="http", obfuscate=False, unique_key=False,
        )
        compile(Path(path).read_text(), path, "exec")
        text = Path(path).read_text()
        self.assertIn("test-key", text)
        self.assertIn("stealth_sleep", text)
        self.assertIn("globals()['sleep_encrypt']", text)

    def test_every_beacon_template_sleeps_with_stealth(self):
        root = ROOT / "templates"
        checks = {
            "agent_http_template.py": "stealth_sleep(sleep_time)",
            "agent_http_beacon_minimal.py": "stealth_sleep(sleep_time)",
            "agent_template.py": "stealth_sleep(sleep_time)",
            "agent_beacon_minimal.py": "stealth_sleep(sleep_time)",
            "agent_dns_template.py": "stealth_sleep(BEACON_INTERVAL)",
            "agent_smb_template.py": "stealth_sleep(BEACON_INTERVAL)",
            "agent_http_template.ps1": "Invoke-SleepEncrypt",
            "agent_http_template.js": "stealthSleep(sleepTime)",
            "agent_http_template.hta": "StealthSleep sleepTime",
        }
        for name, needle in checks.items():
            self.assertIn(needle, (root / name).read_text(), name)
        self.assertIn("stealthSleep(", (ROOT / "agent_go" / "agent.go").read_text())
        self.assertIn("stealth_sleep_ms(", (ROOT / "agent_c" / "agent.c").read_text())
        self.assertIn("StealthSleep(", (ROOT / "agent_csharp" / "Program.cs").read_text())
        self.assertIn("stealth_sleep(", (ROOT / "agent_rust" / "src" / "main.rs").read_text())

    def test_sleep_encrypt_restores_buffer(self):
        import types
        src = (ROOT / "templates" / "evasion_windows.py").read_text()
        start = src.index("def sleep_encrypt")
        nxt = src.index("\ndef ", start + 1)
        ns = {"sys": types.SimpleNamespace(platform="win32"), "os": os}
        exec(src[start:nxt], ns)
        buf = bytearray(b"beacon-secret")
        ns["sleep_encrypt"](0, buf)
        self.assertEqual(bytes(buf), b"beacon-secret")


if __name__ == "__main__":
    unittest.main()
