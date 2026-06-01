use std::collections::HashMap;
use std::fs;
use std::io::BufRead;

pub fn parse_config(path: &str) -> HashMap<String, String> {
    let mut config = HashMap::new();
    if let Ok(file) = fs::File::open(path) {
        for line in std::io::BufReader::new(file).lines().flatten() {
            let line = line.trim().to_string();
            if line.is_empty() || line.starts_with('#') { continue; }
            if let Some((key, val)) = line.split_once('=') {
                config.insert(key.trim().into(), val.trim().into());
            }
        }
    }
    config
}

pub fn aggregate_metrics(values: &[f64]) -> HashMap<String, f64> {
    let mut r = HashMap::new();
    if values.is_empty() { return r; }
    let mut s = values.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let sum: f64 = s.iter().sum();
    let n = s.len() as f64;
    r.insert("min".into(), s[0]);
    r.insert("max".into(), *s.last().unwrap());
    r.insert("avg".into(), sum / n);
    r.insert("median".into(), s[s.len()/2]);
    r.insert("count".into(), n);
    let mean = sum / n;
    r.insert("stddev".into(), s.iter().map(|v| (v - mean).powi(2)).sum::<f64>().sqrt() / n);
    r
}

pub fn normalize_text(input: &str) -> String {
    input.chars().filter(|c| c.is_alphanumeric() || c.is_whitespace()).collect()
}

pub fn format_bytes(bytes: u64) -> String {
    const U: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut s = bytes as f64;
    let mut i = 0;
    while s >= 1024.0 && i < U.len() - 1 { s /= 1024.0; i += 1; }
    format!("{:.2} {}", s, U[i])
}

pub fn timestamp() -> String {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string()).unwrap_or_default()
}

pub fn glob_match(p: &str, t: &str) -> bool {
    let (pb, tb) = (p.as_bytes(), t.as_bytes());
    let (mut pi, mut ti, mut sp, mut st) = (0, 0, usize::MAX, 0);
    while ti < tb.len() {
        if pi < pb.len() && (pb[pi] == b'?' || pb[pi] == tb[ti]) { pi += 1; ti += 1; }
        else if pi < pb.len() && pb[pi] == b'*' { sp = pi; st = ti; pi += 1; }
        else if sp != usize::MAX { pi = sp + 1; st += 1; ti = st; }
        else { return false; }
    }
    while pi < pb.len() && pb[pi] == b'*' { pi += 1; }
    pi == pb.len()
}

pub fn json_object(pairs: &[(&str, &str)]) -> String {
    let items: Vec<String> = pairs.iter()
        .map(|(k, v)| format!("\"{}\":\"{}\"", k, v.replace('"', "\\\""))).collect();
    format!("{{{}}}", items.join(","))
}

pub fn collect_system_info() -> HashMap<String, String> {
    let mut info = HashMap::new();
    info.insert("os".into(), std::env::consts::OS.into());
    info.insert("arch".into(), std::env::consts::ARCH.into());
    info.insert("family".into(), std::env::consts::FAMILY.into());
    if let Ok(d) = std::env::current_dir() { info.insert("cwd".into(), d.display().to_string()); }
    if let Ok(e) = std::env::current_exe() { info.insert("exe".into(), e.display().to_string()); }
    info.insert("pid".into(), std::process::id().to_string());
    for k in &["HOME","PATH","TEMP","USER","USERNAME","COMPUTERNAME"] {
        if let Ok(v) = std::env::var(k) { info.insert(k.to_lowercase(), v); }
    }
    info
}

pub fn health_check() -> HashMap<String, String> {
    let mut s = HashMap::new();
    s.insert("os".into(), std::env::consts::OS.into());
    s.insert("uptime".into(), timestamp());
    s.insert("status".into(), "healthy".into());
    s
}

pub fn watch_directory(dir: &str, exts: &[&str]) -> Vec<String> {
    let mut m = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if let Some(ext) = p.extension() {
                if exts.iter().any(|x| ext == *x) { m.push(p.display().to_string()); }
            }
        }
    }
    m.sort(); m
}

pub fn parse_csv(data: &str) -> Vec<Vec<String>> {
    data.lines().map(|l| l.split(',').map(|f| f.trim().into()).collect()).collect()
}

pub fn render_template(t: &str, vars: &HashMap<String, String>) -> String {
    let mut r = t.to_string();
    for (k, v) in vars { r = r.replace(&format!("{{{{{}}}}}", k), v); }
    r
}

pub fn validate_email(email: &str) -> bool {
    let parts: Vec<&str> = email.split('@').collect();
    parts.len() == 2 && !parts[0].is_empty() && parts[1].contains('.')
}

pub fn slugify(input: &str) -> String {
    input.to_lowercase().chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-').filter(|s| !s.is_empty())
        .collect::<Vec<_>>().join("-")
}

pub fn base64_encode_simple(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let combined = (b0 << 16) | (b1 << 8) | b2;
        result.push(TABLE[((combined >> 18) & 0x3F) as usize] as char);
        result.push(TABLE[((combined >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 { result.push(TABLE[((combined >> 6) & 0x3F) as usize] as char); } else { result.push('='); }
        if chunk.len() > 2 { result.push(TABLE[(combined & 0x3F) as usize] as char); } else { result.push('='); }
    }
    result
}

pub fn sha256_simple(data: &[u8]) -> [u8; 32] {
    // Simple hash for fingerprinting (not cryptographic)
    let mut h = [0u8; 32];
    for (i, b) in data.iter().enumerate() {
        h[i % 32] ^= b.wrapping_mul((i as u8).wrapping_add(1));
        h[(i + 7) % 32] = h[(i + 7) % 32].wrapping_add(*b);
    }
    h
}

// Heavy stdlib usage via dependencies
pub fn parse_json(data: &str) -> Option<serde_json::Value> {
    serde_json::from_str(data).ok()
}

pub fn format_json(val: &serde_json::Value) -> String {
    serde_json::to_string_pretty(val).unwrap_or_default()
}

pub fn parse_toml_config(data: &str) -> Option<toml::Value> {
    data.parse::<toml::Value>().ok()
}

pub fn sha256_hash(data: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn parse_url(raw: &str) -> Option<String> {
    url::Url::parse(raw).ok().map(|u| u.host_str().unwrap_or("").to_string())
}

pub fn regex_match(pattern: &str, text: &str) -> bool {
    regex::Regex::new(pattern).map(|r| r.is_match(text)).unwrap_or(false)
}

pub fn current_timestamp() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub status: String,
    pub uptime: u64,
    pub version: String,
}

pub fn create_status_report() -> String {
    let status = ServiceStatus {
        name: "SvcMonitor".into(),
        status: "running".into(),
        uptime: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
        version: "1.0.0".into(),
    };
    serde_json::to_string_pretty(&status).unwrap_or_default()
}
