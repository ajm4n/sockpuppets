"""Regression: __fs:ls:, __fs:get:, __fs:put: must be handled by native agents.

Bug: Rust and PowerShell agents passed __fs: commands to the system shell instead
of handling them internally, causing failures on paths like C:\\.  Go and C agents
already handled __fs:ls: but this test ensures all agent source files contain the
correct routing logic.

This test validates the source code patterns rather than compiling agents, since
cross-compilation requires target toolchains not available in CI.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read_source(relative_path):
    path = os.path.join(PROJECT_ROOT, relative_path)
    with open(path) as f:
        return f.read()


class TestRustAgentFsCommands:
    @pytest.fixture(autouse=True)
    def load_source(self):
        self.main_src = read_source("agent_rust/src/main.rs")
        self.lib_src = read_source("agent_rust/src/lib.rs")

    def test_main_routes_fs_ls(self):
        assert '__fs:ls:' in self.main_src, "main.rs must route __fs:ls: commands"

    def test_main_routes_fs_get(self):
        assert '__fs:get:' in self.main_src, "main.rs must route __fs:get: commands"

    def test_main_routes_fs_put(self):
        assert '__fs:put:' in self.main_src, "main.rs must route __fs:put: commands"

    def test_main_native_ls_handles_prefix(self):
        assert 'strip_prefix("__fs:ls:")' in self.main_src, \
            "native_ls must strip __fs:ls: prefix"

    def test_main_fs_get_returns_file_prefix(self):
        assert 'FILE:' in self.main_src, "fs_get must return FILE: prefix for downloads"

    def test_main_fs_put_splits_on_tab(self):
        assert "find('\\t')" in self.main_src, "fs_put must split on tab character"

    def test_lib_routes_fs_ls(self):
        assert '__fs:ls:' in self.lib_src, "lib.rs must route __fs:ls: commands"

    def test_lib_routes_fs_get(self):
        assert '__fs:get:' in self.lib_src, "lib.rs must route __fs:get: commands"

    def test_lib_routes_fs_put(self):
        assert '__fs:put:' in self.lib_src, "lib.rs must route __fs:put: commands"


class TestGoAgentFsCommands:
    @pytest.fixture(autouse=True)
    def load_source(self):
        self.src = read_source("agent_go/agent.go")

    def test_routes_fs_ls(self):
        assert '__fs:ls:' in self.src, "Go agent must route __fs:ls: commands"

    def test_native_ls_switch_case(self):
        assert 'HasPrefix(cmd, "__fs:ls:")' in self.src, \
            "Go agent must handle __fs:ls: in native ls switch"


class TestCAgentFsCommands:
    @pytest.fixture(autouse=True)
    def load_source(self):
        self.src = read_source("agent_c/agent.c")

    def test_routes_fs_prefix(self):
        assert '"__fs:"' in self.src, "C agent must check for __fs: prefix"

    def test_handles_ls(self):
        assert '__fs:ls:' in self.src, "C agent must handle __fs:ls:"


class TestPowerShellAgentFsCommands:
    @pytest.fixture(autouse=True)
    def load_source(self):
        self.src = read_source("templates/agent_http_template.ps1")

    def test_routes_fs_ls(self):
        assert "__fs:ls:" in self.src, "PS template must handle __fs:ls:"

    def test_routes_fs_get(self):
        assert "__fs:get:" in self.src, "PS template must handle __fs:get:"

    def test_routes_fs_put(self):
        assert "__fs:put:" in self.src, "PS template must handle __fs:put:"

    def test_fs_ls_calls_native(self):
        assert "Invoke-NativeLs" in self.src, \
            "PS __fs:ls: must call Invoke-NativeLs not shell out"

    def test_fs_get_returns_file_prefix(self):
        assert '"FILE:"' in self.src, "PS __fs:get: must return FILE: prefix"

    def test_fs_put_splits_on_tab(self):
        assert "IndexOf(\"`t\")" in self.src or 'IndexOf("`t")' in self.src, \
            "PS __fs:put: must split on tab character"


class TestFsCommandConsistency:
    """Verify all native agents handle the same set of __fs: commands."""

    def test_all_agents_have_fs_ls(self):
        agents = {
            "Rust main": "agent_rust/src/main.rs",
            "Rust lib": "agent_rust/src/lib.rs",
            "Go": "agent_go/agent.go",
            "C": "agent_c/agent.c",
            "PowerShell": "templates/agent_http_template.ps1",
        }
        for name, path in agents.items():
            src = read_source(path)
            assert "__fs:ls:" in src, f"{name} agent missing __fs:ls: handler"
