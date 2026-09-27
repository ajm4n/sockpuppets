"""Regression: GUI file browser must parse output from ALL agent types.

Bug: The file browser regex ^([d\\-]) didn't match 'f' (file indicator used by
Go and C agents). Fixed regex to ^([df\\-]) with normalization of 'f' to '-'.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_app_js():
    path = os.path.join(PROJECT_ROOT, "gui", "static", "app.js")
    with open(path) as f:
        return f.read()


JS_REGEX_PATTERN = re.compile(r"line\.match\(/\^(\([^)]+\))")


class TestFileBrowserRegex:
    @pytest.fixture(autouse=True)
    def load_source(self):
        self.src = get_app_js()

    def test_regex_matches_directory_indicator(self):
        assert "[df\\-]" in self.src or "[df-]" in self.src, \
            "File browser regex must match 'd' for directories"

    def test_regex_matches_file_indicator_f(self):
        assert "df" in self.src.split("line.match")[1][:50] if "line.match" in self.src else False, \
            "File browser regex must match 'f' (Go/C agent file indicator)"

    def test_f_normalized_to_dash(self):
        assert "=== 'f'" in self.src or "==='f'" in self.src, \
            "File browser must normalize 'f' to '-' for consistent display"


class TestFileBrowserParsing:
    """Test the parsing logic with sample agent outputs."""

    RUST_OUTPUT = """d            0  Windows
d            0  Users
d            0  Program Files
-   1234567890  pagefile.sys"""

    GO_OUTPUT = """d            0  Windows
d            0  Users
d            0  Program Files
f   1234567890  pagefile.sys"""

    C_OUTPUT = """d            0  Windows
d            0  Users
f   1234567890  pagefile.sys"""

    PYTHON_OUTPUT = """d            0  Windows
-   1234567890  pagefile.sys"""

    @pytest.fixture(autouse=True)
    def load_regex(self):
        src = get_app_js()
        match = re.search(r"line\.match\((/[^/]+/)\)", src)
        assert match, "Could not find file browser regex in app.js"
        raw = match.group(1)
        pattern = raw.strip("/")
        self.pattern = re.compile(pattern)

    def _parse_line(self, line):
        m = self.pattern.match(line.strip())
        if m:
            return {"kind": m.group(1), "size": m.group(2), "name": m.group(3)}
        return None

    def test_parses_directory_d(self):
        result = self._parse_line("d            0  Windows")
        assert result is not None, "Must parse 'd' directory entries"
        assert result["kind"] == "d"

    def test_parses_file_dash(self):
        result = self._parse_line("-   1234567890  pagefile.sys")
        assert result is not None, "Must parse '-' file entries (Rust/Python format)"
        assert result["kind"] == "-"

    def test_parses_file_f(self):
        result = self._parse_line("f   1234567890  pagefile.sys")
        assert result is not None, "Must parse 'f' file entries (Go/C format)"
        assert result["kind"] == "f"

    def test_all_rust_lines_parse(self):
        for line in self.RUST_OUTPUT.strip().split("\n"):
            assert self._parse_line(line) is not None, f"Rust line failed: {line}"

    def test_all_go_lines_parse(self):
        for line in self.GO_OUTPUT.strip().split("\n"):
            assert self._parse_line(line) is not None, f"Go line failed: {line}"

    def test_all_c_lines_parse(self):
        for line in self.C_OUTPUT.strip().split("\n"):
            assert self._parse_line(line) is not None, f"C line failed: {line}"
