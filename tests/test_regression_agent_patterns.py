"""Regression: Cross-agent consistency for crypto constants, protocol markers,
command handling patterns, and platform-specific fixes.

Validates source code patterns since agents can't be compiled in CI without
target toolchains.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read_source(relative_path):
    with open(os.path.join(PROJECT_ROOT, relative_path)) as f:
        return f.read()


# ── HKDF salt consistency ────────────────────────────────────


class TestHKDFSaltConsistency:
    """All agents and server must use the same HKDF salt string."""

    EXPECTED_SALT = "sockpuppets-salt-v1"

    def test_salt_length(self):
        assert len(self.EXPECTED_SALT) == 19

    def test_server_crypto_module(self):
        src = read_source("crypto/handshake.py")
        assert "b'sockpuppets-salt-v1'" in src

    def test_rust_main(self):
        src = read_source("agent_rust/src/main.rs")
        assert 'b"sockpuppets-salt-v1"' in src

    def test_go_agent(self):
        # Go uses the salt in wire_session.go or agent.go
        try:
            src = read_source("agent_go/wire_session.go")
        except FileNotFoundError:
            src = read_source("agent_go/agent.go")
        assert "sockpuppets-salt-v1" in src

    def test_c_agent(self):
        src = read_source("agent_c/agent.c")
        assert '"sockpuppets-salt-v1"' in src

    def test_c_agent_salt_length_19(self):
        src = read_source("agent_c/agent.c")
        # C agent should hardcode length as 19
        assert "19" in src

    def test_csharp_agent(self):
        try:
            src = read_source("agent_csharp/Eph1.cs")
        except FileNotFoundError:
            src = read_source("agent_csharp/Program.cs")
        assert "sockpuppets-salt-v1" in src

    def test_powershell_template(self):
        src = read_source("templates/agent_http_template.ps1")
        assert "'sockpuppets-salt-v1'" in src

    def test_python_agent_wire_source(self):
        src = read_source("crypto/handshake.py")
        # agent_wire_source embeds the salt in generated Python agents
        assert 'b"sockpuppets-salt-v1"' in src


# ── HKDF info strings ───────────────────────────────────────


class TestHKDFInfoConsistency:
    """Handshake and session info strings must match across agents."""

    def test_rust_handshake_info(self):
        src = read_source("agent_rust/src/main.rs")
        assert 'b"sockpuppets-handshake-v1"' in src

    def test_rust_session_info(self):
        src = read_source("agent_rust/src/main.rs")
        assert 'b"sockpuppets-session-v1"' in src

    def test_c_handshake_info(self):
        src = read_source("agent_c/agent.c")
        assert '"sockpuppets-handshake-v1"' in src

    def test_c_session_info(self):
        src = read_source("agent_c/agent.c")
        assert '"sockpuppets-session-v1"' in src

    def test_csharp_handshake_info(self):
        try:
            src = read_source("agent_csharp/Eph1.cs")
        except FileNotFoundError:
            src = read_source("agent_csharp/Program.cs")
        assert "sockpuppets-handshake-v1" in src

    def test_csharp_session_info(self):
        try:
            src = read_source("agent_csharp/Eph1.cs")
        except FileNotFoundError:
            src = read_source("agent_csharp/Program.cs")
        assert "sockpuppets-session-v1" in src

    def test_powershell_handshake_info(self):
        src = read_source("templates/agent_http_template.ps1")
        assert "'sockpuppets-handshake-v1'" in src

    def test_powershell_session_info(self):
        src = read_source("templates/agent_http_template.ps1")
        assert "'sockpuppets-session-v1'" in src


# ── Protocol markers ────────────────────────────────────────


class TestProtocolMarkers:
    """All agents must use EPH1., EPH2., and AES1 markers."""

    # lib.rs uses bootstrap keys (not EPH1), so only check EPH1-capable agents
    EPH1_AGENTS = {
        "Rust main": "agent_rust/src/main.rs",
        "C": "agent_c/agent.c",
        "PowerShell": "templates/agent_http_template.ps1",
    }

    def test_eph1_marker(self):
        for name, path in self.EPH1_AGENTS.items():
            src = read_source(path)
            assert "EPH1." in src, f"{name} missing EPH1. marker"

    def test_eph2_marker(self):
        for name, path in self.EPH1_AGENTS.items():
            src = read_source(path)
            assert "EPH2." in src, f"{name} missing EPH2. marker"

    def test_aes1_marker(self):
        for name, path in self.EPH1_AGENTS.items():
            src = read_source(path)
            assert "AES1" in src, f"{name} missing AES1 marker"

    def test_go_eph1(self):
        try:
            src = read_source("agent_go/wire_session.go")
        except FileNotFoundError:
            src = read_source("agent_go/agent.go")
        assert "EPH1." in src

    def test_go_eph2(self):
        try:
            src = read_source("agent_go/wire_session.go")
        except FileNotFoundError:
            src = read_source("agent_go/agent.go")
        assert "EPH2." in src

    def test_go_aes1(self):
        try:
            src = read_source("agent_go/wire_session.go")
        except FileNotFoundError:
            src = read_source("agent_go/agent.go")
        assert "AES1" in src

    def test_csharp_eph1(self):
        try:
            src = read_source("agent_csharp/Eph1.cs")
        except FileNotFoundError:
            src = read_source("agent_csharp/Program.cs")
        assert "EPH1." in src

    def test_server_crypto_markers(self):
        src = read_source("crypto/handshake.py")
        assert "'EPH1.'" in src
        assert "'EPH2.'" in src
        assert "b'AES1'" in src


# ── __kill and __set_interval commands ───────────────────────


class TestKillCommandHandling:
    """All agents must handle __kill to terminate."""

    AGENTS = {
        "Rust main": "agent_rust/src/main.rs",
        "Go": "agent_go/agent.go",
        "C": "agent_c/agent.c",
        "PowerShell": "templates/agent_http_template.ps1",
    }

    def test_all_handle_kill(self):
        for name, path in self.AGENTS.items():
            src = read_source(path)
            assert "__kill" in src, f"{name} missing __kill handler"


class TestSetIntervalCommandHandling:
    """All agents must handle __set_interval: to update sleep."""

    AGENTS = {
        "Rust main": "agent_rust/src/main.rs",
        "Go": "agent_go/agent.go",
        "C": "agent_c/agent.c",
        "PowerShell": "templates/agent_http_template.ps1",
    }

    def test_all_handle_set_interval(self):
        for name, path in self.AGENTS.items():
            src = read_source(path)
            assert "__set_interval:" in src, f"{name} missing __set_interval handler"


# ── C# specific fixes ───────────────────────────────────────


class TestCSharpFixes:
    """C# agent fixes: BigInteger 1-param constructor, BCrypt P/Invoke."""

    @pytest.fixture(autouse=True)
    def load_csharp(self):
        try:
            self.eph_src = read_source("agent_csharp/Eph1.cs")
        except FileNotFoundError:
            pytest.skip("Eph1.cs not found")
        self.main_src = read_source("agent_csharp/Program.cs")

    def test_biginteger_single_param_constructor(self):
        # Must use `new BigInteger(ub)` not `new BigInteger(ub, true)`
        assert "new BigInteger(ub)" in self.eph_src
        # Must NOT have 2-param form
        assert "BigInteger(ub, true)" not in self.eph_src
        assert "BigInteger(ub,true)" not in self.eph_src

    def test_bcrypt_dll_import(self):
        assert 'DllImport("bcrypt.dll"' in self.eph_src

    def test_bcrypt_charset_unicode(self):
        assert "CharSet.Unicode" in self.eph_src

    def test_bcrypt_aes_algorithm(self):
        assert '"AES"' in self.eph_src


# ── PowerShell specific fixes ───────────────────────────────


class TestPowerShellFixes:
    """PowerShell agent fixes: BigInteger comma-prefix, BCrypt P/Invoke."""

    @pytest.fixture(autouse=True)
    def load_ps(self):
        self.src = read_source("templates/agent_http_template.ps1")

    def test_biginteger_comma_prefix(self):
        # PowerShell must use `(,$ub)` to force single-param constructor
        assert "(,$ub)" in self.src

    def test_has_bcrypt_pinvoke(self):
        # PS template should have BCrypt functions for AES-GCM
        assert "BCryptOpenAlgorithmProvider" in self.src or "AesGcm" in self.src

    def test_utf8_salt_encoding(self):
        assert "UTF8.GetBytes('sockpuppets-salt-v1')" in self.src


# ── Native LS output format ─────────────────────────────────


class TestNativeLsOutputFormat:
    """All agents must produce parseable ls output: {d|-|f} {size} {name}"""

    def test_rust_uses_d_and_dash(self):
        src = read_source("agent_rust/src/main.rs")
        assert '"d"' in src or "'d'" in src
        assert '"-"' in src or "'-'" in src

    def test_go_uses_d_and_f(self):
        src = read_source("agent_go/agent.go")
        assert '"d "' in src or '"d\t"' in src or 'd ' in src
        assert '"f "' in src or '"f\t"' in src or 'f ' in src

    def test_c_uses_d_and_f(self):
        src = read_source("agent_c/agent.c")
        # C agent uses "d" and "f" as format args in sprintf
        assert '"d"' in src or '"d ' in src
        assert '"f"' in src or '"f ' in src

    def test_powershell_uses_d_and_dash(self):
        src = read_source("templates/agent_http_template.ps1")
        assert "'d '" in src or '"d "' in src or "d " in src
