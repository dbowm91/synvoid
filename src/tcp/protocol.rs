use std::io;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    Smtp,
    Imap,
    Pop3,
    Http,
    Https,
    Http2,
    Grpc,
    Mysql,
    Postgres,
    Ssh,
    Ftp,
    Redis,
    Memcached,
    Mongodb,
    Ldap,
    Rdp,
    Vnc,
    Xmpp,
    Amqp,
    Kafka,
    WebSocket,
    Rtsp,
    Dns,
    Unknown,
}

impl Protocol {
    pub fn as_str(&self) -> &str {
        match self {
            Protocol::Smtp => "smtp",
            Protocol::Imap => "imap",
            Protocol::Pop3 => "pop3",
            Protocol::Http => "http",
            Protocol::Https => "https",
            Protocol::Http2 => "http2",
            Protocol::Grpc => "grpc",
            Protocol::Mysql => "mysql",
            Protocol::Postgres => "postgres",
            Protocol::Ssh => "ssh",
            Protocol::Ftp => "ftp",
            Protocol::Redis => "redis",
            Protocol::Memcached => "memcached",
            Protocol::Mongodb => "mongodb",
            Protocol::Ldap => "ldap",
            Protocol::Rdp => "rdp",
            Protocol::Vnc => "vnc",
            Protocol::Xmpp => "xmpp",
            Protocol::Amqp => "amqp",
            Protocol::Kafka => "kafka",
            Protocol::WebSocket => "websocket",
            Protocol::Rtsp => "rtsp",
            Protocol::Dns => "dns",
            Protocol::Unknown => "unknown",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "smtp" => Protocol::Smtp,
            "imap" => Protocol::Imap,
            "pop3" => Protocol::Pop3,
            "http" => Protocol::Http,
            "https" => Protocol::Https,
            "http2" | "h2" => Protocol::Http2,
            "grpc" => Protocol::Grpc,
            "mysql" => Protocol::Mysql,
            "postgres" | "postgresql" => Protocol::Postgres,
            "ssh" => Protocol::Ssh,
            "ftp" => Protocol::Ftp,
            "redis" => Protocol::Redis,
            "memcached" => Protocol::Memcached,
            "mongodb" | "mongo" => Protocol::Mongodb,
            "ldap" => Protocol::Ldap,
            "rdp" => Protocol::Rdp,
            "vnc" => Protocol::Vnc,
            "xmpp" => Protocol::Xmpp,
            "amqp" => Protocol::Amqp,
            "kafka" => Protocol::Kafka,
            "websocket" | "ws" | "wss" => Protocol::WebSocket,
            "rtsp" => Protocol::Rtsp,
            "dns" => Protocol::Dns,
            _ => Protocol::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtocolResult {
    pub protocol: Protocol,
    pub confidence: f32,
    pub matched_pattern: String,
}

pub struct ProtocolDetector {
    read_buffer_size: usize,
    peek_timeout_ms: u64,
}

impl Default for ProtocolDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ProtocolDetector {
    fn clone(&self) -> Self {
        Self {
            read_buffer_size: self.read_buffer_size,
            peek_timeout_ms: self.peek_timeout_ms,
        }
    }
}

impl ProtocolDetector {
    pub fn new() -> Self {
        Self {
            read_buffer_size: 64,
            peek_timeout_ms: 1000,
        }
    }

    pub async fn detect_peek(&self, stream: &TcpStream) -> io::Result<ProtocolResult> {
        let mut buffer = vec![0u8; self.read_buffer_size];
        
        let n = tokio::time::timeout(
            std::time::Duration::from_millis(self.peek_timeout_ms),
            stream.peek(&mut buffer)
        ).await??;

        if n == 0 {
            return Ok(ProtocolResult {
                protocol: Protocol::Unknown,
                confidence: 0.0,
                matched_pattern: "empty".to_string(),
            });
        }

        let data = &buffer[..n];
        let protocol = self.detect_from_bytes(data);

        Ok(ProtocolResult {
            protocol,
            confidence: 1.0,
            matched_pattern: "peek_bytes".to_string(),
        })
    }

    pub async fn detect(&self, stream: &mut TcpStream) -> io::Result<ProtocolResult> {
        self.detect_peek(stream).await
    }

    fn detect_from_bytes(&self, data: &[u8]) -> Protocol {
        if data.len() < 4 {
            return Protocol::Unknown;
        }

        if data.len() >= 2 && data[0] == 0x16 && (data[1] == 0x03 || data[1] == 0x02) {
            if let Some(&_upgrade_byte) = data.get(5) {
                let first_line = self.extract_first_line(&data[5..]);
                if first_line.to_lowercase().contains("websocket") {
                    return Protocol::WebSocket;
                }
                if first_line.to_lowercase().contains("h2") {
                    return Protocol::Http2;
                }
            }
            return Protocol::Https;
        }

        if data.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
            tracing::debug!("HTTP/2 connection preface detected");
            if self.looks_like_grpc(&data) {
                return Protocol::Grpc;
            }
            return Protocol::Http2;
        }

        if self.looks_like_grpc(data) {
            tracing::debug!("gRPC framing detected");
            return Protocol::Grpc;
        }

        let first_line = self.extract_first_line(data);
        let upper_line = first_line.to_uppercase();

        if first_line.starts_with("HELO") || first_line.starts_with("EHLO") 
            || first_line.starts_with("MAIL FROM") || first_line.starts_with("RCPT TO") 
            || first_line.starts_with("QUIT") || first_line.starts_with("DATA") {
            return Protocol::Smtp;
        }

        if first_line.starts_with("OPTIONS ") && upper_line.contains("RTSP/") {
            return Protocol::Rtsp;
        }
        if first_line.starts_with("DESCRIBE ") || first_line.starts_with("SETUP ") 
            || first_line.starts_with("PLAY ") || first_line.starts_with("PAUSE ")
            || first_line.starts_with("TEARDOWN ") || first_line.starts_with("RTSP/") {
            return Protocol::Rtsp;
        }

        if first_line.starts_with("GET") || first_line.starts_with("POST") 
            || first_line.starts_with("HEAD") || first_line.starts_with("PUT") 
            || first_line.starts_with("DELETE") || first_line.starts_with("OPTIONS") 
            || first_line.starts_with("PATCH") || first_line.starts_with("CONNECT") {
            let data_upper = String::from_utf8_lossy(data).to_uppercase();
            if data_upper.contains("UPGRADE: WEBSOCKET") || data_upper.contains("SEC-WEBSOCKET") {
                return Protocol::WebSocket;
            }
            return Protocol::Http;
        }

        if first_line.starts_with("A") && first_line.chars().nth(4).map(|c| c.is_ascii_digit()).unwrap_or(false) {
            return Protocol::Imap;
        }

        if first_line.starts_with("USER") || first_line.starts_with("PASS") 
            || first_line.starts_with("LIST") || first_line.starts_with("RETR") 
            || first_line.starts_with("QUIT") {
            return Protocol::Ftp;
        }

        if data.starts_with(b"\x00\x14") || (data.len() >= 4 && u32::from_be_bytes([data[0], data[1], data[2], data[3]]) == 10) {
            return Protocol::Mysql;
        }

        if data.starts_with(b"\x00\x00\x00\x08") || (data.len() >= 8 && &data[..8] == b"\x00\x00\x00\x08pgsrc\x00\x00") {
            return Protocol::Postgres;
        }

        if first_line.starts_with("SSH-") {
            return Protocol::Ssh;
        }

        if first_line.starts_with("*") || first_line.starts_with("$") 
            || first_line.starts_with(":") {
            if self.looks_like_redis(data) {
                return Protocol::Redis;
            }
        }

        if first_line.starts_with("+OK") || first_line.starts_with("-ERR") {
            if self.looks_like_redis(data) {
                return Protocol::Redis;
            }
            return Protocol::Pop3;
        }

        if first_line.starts_with("get ") || first_line.starts_with("set ") 
            || first_line.starts_with("delete ") || first_line.starts_with("stats")
            || first_line.starts_with("incr ") || first_line.starts_with("decr ")
            || first_line.starts_with("add ") || first_line.starts_with("gets ") {
            return Protocol::Memcached;
        }

        if data[0] == 0x30 && data.len() >= 6 {
            if self.looks_like_ldap(data) {
                return Protocol::Ldap;
            }
        }

        if data.len() >= 18 && data[0] == 0x03 && data[1] == 0x00 {
            return Protocol::Rdp;
        }

        if first_line.starts_with("RFB ") {
            return Protocol::Vnc;
        }

        if data.starts_with(b"<?xml") || data.starts_with(b"<stream:stream") 
            || first_line.starts_with("<stream") {
            return Protocol::Xmpp;
        }

        if data.len() >= 8 && &data[..4] == b"AMQP" {
            return Protocol::Amqp;
        }

        if data.len() >= 4 {
            let msg_size = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
            if msg_size > 0 && msg_size < 100000000 && data.len() >= 4 + msg_size {
                if self.looks_like_mongodb(data) {
                    return Protocol::Mongodb;
                }
            }
        }

        if data.len() >= 5 {
            let api_key = u16::from_be_bytes([data[4], data[5]]);
            if self.looks_like_kafka(data, api_key) {
                return Protocol::Kafka;
            }
        }

        if data.len() >= 12 && data[2] == 0x01 && data[3] == 0x00 {
            let _flags = u16::from_be_bytes([data[2], data[3]]);
            if self.looks_like_dns(data) {
                return Protocol::Dns;
            }
        }

        Protocol::Unknown
    }

    fn looks_like_redis(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        let first_char = data[0] as char;
        let line = self.extract_first_line(data);
        
        if first_char == '*' {
            if line.len() > 1 {
                if let Ok(_) = line[1..].parse::<u32>() {
                    return true;
                }
            }
        }
        if first_char == '$' {
            if line.len() > 1 {
                if let Ok(_) = line[1..].parse::<i32>() {
                    return true;
                }
            }
        }
        if first_char == ':' {
            if line.len() > 1 {
                if line[1..].chars().all(|c| c.is_ascii_digit() || c == '-') {
                    return true;
                }
            }
        }
        false
    }

    fn looks_like_mongodb(&self, data: &[u8]) -> bool {
        if data.len() < 16 {
            return false;
        }
        let msg_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if msg_len > 0 && msg_len < 48000000 && data.len() >= msg_len {
            if data.len() >= 12 {
                let request_id = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                let response_to = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
                let opcode = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
                if opcode >= 1 && opcode <= 2010 {
                    return true;
                }
            }
        }
        false
    }

    fn looks_like_ldap(&self, data: &[u8]) -> bool {
        if data.len() < 6 {
            return false;
        }
        if data[0] != 0x30 {
            return false;
        }
        let length_byte = data[1];
        if length_byte < 0x80 {
            return true;
        }
        if length_byte == 0x82 && data.len() >= 4 {
            let _len = u16::from_be_bytes([data[2], data[3]]);
            return true;
        }
        false
    }

    fn looks_like_kafka(&self, data: &[u8], api_key: u16) -> bool {
        if api_key <= 64 {
            if data.len() >= 6 {
                let api_version = u16::from_be_bytes([data[6], data[7]]);
                if api_version <= 20 {
                    let correlation_id = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                    return correlation_id > 0 || api_key == 18;
                }
            }
        }
        false
    }

    fn looks_like_dns(&self, data: &[u8]) -> bool {
        if data.len() < 12 {
            return false;
        }
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let qr = (flags >> 15) & 1;
        let opcode = (flags >> 11) & 0xF;
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        if opcode <= 2 && qdcount > 0 && qdcount <= 100 {
            return true;
        }
        false
    }

    fn looks_like_grpc(&self, data: &[u8]) -> bool {
        if data.len() < 5 {
            return false;
        }

        let length = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;

        if length > 8 * 1024 * 1024 || length == 0 {
            return false;
        }

        if data.len() >= 5 + length && length > 2 {
            let payload = &data[5..5 + length];
            
            let compression = data[0] & 0x01;
            if compression == 0 && payload.len() >= 3 {
                if payload[0] == 0x00 || payload[0] == 0x01 {
                    let text_start = if payload[0] == 0x00 { 1 } else { 0 };
                    if payload.len() > text_start {
                        if let Ok(text) = std::str::from_utf8(&payload[text_start..]) {
                            if text.starts_with('/') && text.contains('.') {
                                return true;
                            }
                        }
                    }
                }
                
                if payload[0] == 0x0a && payload.len() > 2 {
                    let field_length = payload[1] as usize;
                    if payload.len() >= 2 + field_length && field_length > 0 {
                        if let Ok(text) = std::str::from_utf8(&payload[2..2 + field_length]) {
                            if text.starts_with('/') && text.contains('.') {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }

    fn extract_first_line(&self, data: &[u8]) -> String {
        let mut line = String::new();
        for &byte in data {
            if byte == b'\n' {
                break;
            }
            if byte != b'\r' {
                line.push(byte as char);
            }
        }
        line
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smtp_detection() {
        let detector = ProtocolDetector::new();
        assert_eq!(detector.detect_from_bytes(b"EHLO example.com\r\n"), Protocol::Smtp);
        assert_eq!(detector.detect_from_bytes(b"MAIL FROM:<test@example.com>\r\n"), Protocol::Smtp);
    }

    #[test]
    fn test_http_detection() {
        let detector = ProtocolDetector::new();
        assert_eq!(detector.detect_from_bytes(b"GET / HTTP/1.1\r\n"), Protocol::Http);
        assert_eq!(detector.detect_from_bytes(b"POST /api HTTP/1.1\r\n"), Protocol::Http);
    }

    #[test]
    fn test_imap_detection() {
        let detector = ProtocolDetector::new();
        assert_eq!(detector.detect_from_bytes(b"A0001 LOGIN user pass\r\n"), Protocol::Imap);
        assert_eq!(detector.detect_from_bytes(b"A0002 SELECT INBOX\r\n"), Protocol::Imap);
    }

    #[test]
    fn test_redis_detection() {
        let detector = ProtocolDetector::new();
        assert_eq!(detector.detect_from_bytes(b"*1\r\n$4\r\nPING\r\n"), Protocol::Redis);
        assert_eq!(detector.detect_from_bytes(b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n"), Protocol::Redis);
        assert_eq!(detector.detect_from_bytes(b"$5\r\nhello\r\n"), Protocol::Redis);
        assert_eq!(detector.detect_from_bytes(b":1000\r\n"), Protocol::Redis);
    }

    #[test]
    fn test_memcached_detection() {
        let detector = ProtocolDetector::new();
        assert_eq!(detector.detect_from_bytes(b"get mykey\r\n"), Protocol::Memcached);
        assert_eq!(detector.detect_from_bytes(b"set mykey 0 3600 5\r\nhello\r\n"), Protocol::Memcached);
    }

    #[test]
    fn test_ssh_detection() {
        let detector = ProtocolDetector::new();
        assert_eq!(detector.detect_from_bytes(b"SSH-2.0-OpenSSH_8.2p1\r\n"), Protocol::Ssh);
    }

    #[test]
    fn test_vnc_detection() {
        let detector = ProtocolDetector::new();
        assert_eq!(detector.detect_from_bytes(b"RFB 003.008\n"), Protocol::Vnc);
    }

    #[test]
    fn test_amqp_detection() {
        let detector = ProtocolDetector::new();
        assert_eq!(detector.detect_from_bytes(b"AMQP\x00\x00\x09\x01"), Protocol::Amqp);
    }

    #[test]
    fn test_rtsp_detection() {
        let detector = ProtocolDetector::new();
        assert_eq!(detector.detect_from_bytes(b"OPTIONS rtsp://example.com RTSP/1.0\r\n"), Protocol::Rtsp);
        assert_eq!(detector.detect_from_bytes(b"DESCRIBE rtsp://example.com RTSP/1.0\r\n"), Protocol::Rtsp);
    }

    #[test]
    fn test_websocket_detection() {
        let detector = ProtocolDetector::new();
        let ws_upgrade = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        assert_eq!(detector.detect_from_bytes(ws_upgrade), Protocol::WebSocket);
    }

    #[test]
    fn test_xmpp_detection() {
        let detector = ProtocolDetector::new();
        assert_eq!(detector.detect_from_bytes(b"<?xml version='1.0'?><stream:stream>"), Protocol::Xmpp);
        assert_eq!(detector.detect_from_bytes(b"<stream:stream to='example.com'>"), Protocol::Xmpp);
    }

    #[test]
    fn test_http2_detection() {
        let detector = ProtocolDetector::new();
        assert_eq!(detector.detect_from_bytes(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), Protocol::Http2);
    }

    #[test]
    fn test_grpc_detection() {
        let detector = ProtocolDetector::new();
        
        let h2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        assert_eq!(detector.detect_from_bytes(h2_preface), Protocol::Http2);
        
        let h2_preface_with_settings = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00";
        assert_eq!(detector.detect_from_bytes(h2_preface_with_settings), Protocol::Http2);
    }
}
