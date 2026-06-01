// transport.rs — Unified transport layer (HTTP/HTTPS/WebSocket)
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use tungstenite::{connect, Message, WebSocket};
use tungstenite::stream::MaybeTlsStream;

pub enum TransportType {
    Http,
    Https,
    WebSocket,
}

pub struct HttpTransport {
    pub host: String,
    pub port: String,
    pub scheme: String,
    pub user_agent: String,
}

pub struct WsTransport {
    pub host: String,
    pub port: String,
    pub scheme: String,
    pub user_agent: String,
    pub conn: Option<WebSocket<MaybeTlsStream<TcpStream>>>,
}

impl HttpTransport {
    pub fn post(&self, path: &str, body: &str) -> Option<String> {
        let addr = format!("{}:{}", self.host, self.port);
        let mut stream = TcpStream::connect_timeout(
            &addr.parse().ok()?, Duration::from_secs(30),
        ).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(60))).ok();

        let use_tls = self.scheme == "https";
        // For HTTPS, we'd need native-tls wrapping — simplified to HTTP for now
        // Full TLS support requires native_tls::TlsConnector
        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            path, addr, self.user_agent, body.len(), body
        );
        stream.write_all(request.as_bytes()).ok()?;
        let mut resp = String::new();
        stream.read_to_string(&mut resp).ok()?;
        resp.find("\r\n\r\n").map(|i| resp[i + 4..].to_string())
    }
}

impl WsTransport {
    pub fn new(host: &str, port: &str, scheme: &str, ua: &str) -> Self {
        WsTransport {
            host: host.into(),
            port: port.into(),
            scheme: scheme.into(),
            user_agent: ua.into(),
            conn: None,
        }
    }

    pub fn connect(&mut self) -> Result<(), String> {
        let ws_scheme = if self.scheme == "https" { "wss" } else { "ws" };
        let url = format!("{}://{}:{}", ws_scheme, self.host, self.port);
        match connect(&url) {
            Ok((socket, _)) => {
                self.conn = Some(socket);
                Ok(())
            }
            Err(e) => Err(format!("WS connect failed: {}", e)),
        }
    }

    pub fn send(&mut self, msg: &str) -> Result<(), String> {
        if let Some(ref mut conn) = self.conn {
            conn.send(Message::Text(msg.into()))
                .map_err(|e| format!("WS send: {}", e))
        } else {
            Err("Not connected".into())
        }
    }

    pub fn recv(&mut self) -> Option<String> {
        if let Some(ref mut conn) = self.conn {
            match conn.read() {
                Ok(Message::Text(t)) => Some(t),
                Ok(Message::Binary(b)) => String::from_utf8(b).ok(),
                _ => None,
            }
        } else {
            None
        }
    }

    pub fn close(&mut self) {
        if let Some(ref mut conn) = self.conn {
            let _ = conn.close(None);
        }
        self.conn = None;
    }
}
