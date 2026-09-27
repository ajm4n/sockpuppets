"""Redirector config system — parse YAML configs and generate deploy configs."""

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REDIRECTORS_DIR = os.path.join(_PROJECT_ROOT, "redirectors")
REDIRECTORS_PRIVATE_DIR = os.path.join(REDIRECTORS_DIR, "private")


@dataclass
class RedirectorConfig:
    name: str = "default"
    type: str = "direct"
    description: str = ""
    listen: str = ""
    backend: str = ""
    domain: str = ""
    trusted: bool = False
    profile: str = ""
    allow_user_agents: list[str] = field(default_factory=list)
    decoy: str = "404"
    decoy_target: str = ""


def load_redirector(name: str) -> RedirectorConfig:
    """Load a redirector config from redirectors/<name>.yaml.

    Checks private/ first, then the public directory.
    """
    if not _HAS_YAML:
        if name == "default":
            return RedirectorConfig()
        raise ImportError("pyyaml is required to load redirector configs: pip install pyyaml")

    # Check private dir first
    for directory in [REDIRECTORS_PRIVATE_DIR, REDIRECTORS_DIR]:
        path = os.path.join(directory, f"{name}.yaml")
        if os.path.exists(path):
            with open(path, "r") as f:
                raw = yaml.safe_load(f) or {}
            return RedirectorConfig(
                name=raw.get("name", name),
                type=raw.get("type", "direct"),
                description=raw.get("description", ""),
                listen=raw.get("listen", ""),
                backend=raw.get("backend", ""),
                domain=raw.get("domain", ""),
                trusted=bool(raw.get("trusted", False)),
                profile=raw.get("profile", ""),
                allow_user_agents=list(raw.get("allow_user_agents", [])),
                decoy=raw.get("decoy", "404"),
                decoy_target=raw.get("decoy_target", ""),
            )

    raise FileNotFoundError(f"Redirector config not found: {name}.yaml")


def list_redirectors() -> list[RedirectorConfig]:
    """List all available redirector configs (public + private)."""
    configs = []
    seen = set()
    for directory in [REDIRECTORS_PRIVATE_DIR, REDIRECTORS_DIR]:
        if not os.path.isdir(directory):
            continue
        for filename in sorted(os.listdir(directory)):
            if not filename.endswith(".yaml"):
                continue
            name = filename[:-5]
            if name in seen:
                continue
            seen.add(name)
            try:
                configs.append(load_redirector(name))
            except Exception:
                pass
    return configs


def generate_deploy_config(config: RedirectorConfig, fmt: str) -> str:
    """Generate a deploy config for the given redirector.

    Args:
        config: RedirectorConfig to generate for
        fmt: One of 'apache', 'nginx', 'socat', 'iptables', 'lambda'

    Returns:
        Ready-to-deploy config text
    """
    generators = {
        "apache": _gen_apache,
        "nginx": _gen_nginx,
        "socat": _gen_socat,
        "iptables": _gen_iptables,
        "lambda": _gen_lambda,
    }
    if fmt not in generators:
        raise ValueError(f"Unknown format: {fmt}. Supported: {', '.join(generators)}")
    return generators[fmt](config)


def _parse_backend(backend: str) -> tuple[str, str]:
    """Split 'host:port' into (host, port) strings."""
    if ":" in backend:
        host, port = backend.rsplit(":", 1)
        return host, port
    return backend, "443"


def _gen_apache(config: RedirectorConfig) -> str:
    host, port = _parse_backend(config.backend)
    ua_conditions = ""
    if config.allow_user_agents:
        ua_conditions = "\n".join(
            f'RewriteCond %{{HTTP_USER_AGENT}} "{ua}" [NC,OR]'
            for ua in config.allow_user_agents
        )
        # Remove trailing [OR] from last condition
        ua_conditions = ua_conditions.rsplit("[NC,OR]", 1)[0] + "[NC]"

    decoy_rule = ""
    if config.decoy == "redirect":
        decoy_rule = f"RewriteRule ^(.*)$ {config.decoy_target} [L,R=302]"
    elif config.decoy == "404":
        decoy_rule = "RewriteRule ^(.*)$ - [F,L]"

    return f"""# Apache .htaccess — redirector config for {config.name}
# Deploy to the web root of your redirector host: {config.domain}
#
# Requirements: mod_rewrite, mod_proxy, mod_ssl

RewriteEngine On

# Block requests that don't match expected User-Agent
{ua_conditions}
RewriteCond %{{HTTP_USER_AGENT}} !. [OR]
{decoy_rule}

# Forward matching traffic to team server
RewriteRule ^(.*)$ https://{host}:{port}$1 [P,L]

# Proxy settings
SSLProxyEngine On
ProxyPreserveHost Off
RequestHeader set X-Forwarded-For "%{{REMOTE_ADDR}}s"
"""


def _gen_nginx(config: RedirectorConfig) -> str:
    host, port = _parse_backend(config.backend)
    ua_block = ""
    if config.allow_user_agents:
        ua_conditions = " ".join(f'~*"{ua}"' for ua in config.allow_user_agents)
        ua_block = f"""
    # Block non-matching User-Agents
    if ($http_user_agent !{ua_conditions}) {{
        return 302 {config.decoy_target or 'https://www.google.com'};
    }}"""

    return f"""# Nginx config — redirector for {config.name}
# Deploy to /etc/nginx/sites-enabled/{config.name}.conf

server {{
    listen {config.listen or '443 ssl'};
    server_name {config.domain};
{ua_block}

    location / {{
        proxy_pass https://{host}:{port};
        proxy_ssl_verify off;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Host $host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }}
}}
"""


def _gen_socat(config: RedirectorConfig) -> str:
    host, port = _parse_backend(config.backend)
    listen_port = config.listen.split(":")[-1] if config.listen else "443"
    return f"""# socat redirector — {config.name}
# Quick TCP forwarding from {config.domain}:{listen_port} to team server

socat TCP-LISTEN:{listen_port},reuseaddr,fork TCP:{host}:{port}

# With TLS termination (requires cert):
# socat OPENSSL-LISTEN:{listen_port},reuseaddr,fork,cert=server.pem,verify=0 TCP:{host}:{port}
"""


def _gen_iptables(config: RedirectorConfig) -> str:
    host, port = _parse_backend(config.backend)
    listen_port = config.listen.split(":")[-1] if config.listen else "443"
    return f"""#!/bin/bash
# iptables redirector — {config.name}
# Raw TCP redirection from :{listen_port} to {host}:{port}

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# DNAT incoming traffic to team server
iptables -t nat -A PREROUTING -p tcp --dport {listen_port} -j DNAT --to-destination {host}:{port}

# Masquerade outgoing traffic
iptables -t nat -A POSTROUTING -j MASQUERADE

# Allow forwarding
iptables -A FORWARD -p tcp -d {host} --dport {port} -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# To remove:
# iptables -t nat -D PREROUTING -p tcp --dport {listen_port} -j DNAT --to-destination {host}:{port}
# iptables -t nat -D POSTROUTING -j MASQUERADE
"""


def _gen_lambda(config: RedirectorConfig) -> str:
    host, port = _parse_backend(config.backend)
    return f"""# AWS Lambda redirector — {config.name}
# Deploy as a Lambda function behind API Gateway
#
# API Gateway config:
#   - Type: HTTP API
#   - Route: ANY /{{proxy+}}
#   - Integration: Lambda
#   - Custom domain: {config.domain}

import json
import urllib.request
import urllib.parse
import ssl

BACKEND = "https://{host}:{port}"

def lambda_handler(event, context):
    path = event.get("rawPath", "/")
    method = event.get("requestContext", {{}}).get("http", {{}}).get("method", "GET")
    headers = event.get("headers", {{}})
    body = event.get("body", "")

    # Forward to team server
    url = BACKEND + path
    if event.get("rawQueryString"):
        url += "?" + event["rawQueryString"]

    req = urllib.request.Request(url, method=method)
    req.add_header("X-Forwarded-For", headers.get("x-forwarded-for", "unknown"))
    for k, v in headers.items():
        if k.lower() not in ("host", "content-length"):
            req.add_header(k, v)

    if body:
        req.data = body.encode() if isinstance(body, str) else body

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=30)
        return {{
            "statusCode": resp.status,
            "headers": dict(resp.headers),
            "body": resp.read().decode("utf-8", errors="replace"),
        }}
    except Exception as e:
        return {{
            "statusCode": 502,
            "body": json.dumps({{"error": str(e)}}),
        }}
"""
