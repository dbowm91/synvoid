use crate::honeypot_port::responses::{HoneypotContext, HoneypotResponder, HoneypotResponse};
use std::collections::HashMap;

pub struct StaticResponder {
    name: String,
    service_type: String,
    banners: Vec<Vec<u8>>,
    responses: HashMap<String, Vec<u8>>,
}

impl StaticResponder {
    pub fn new(name: &str, service_type: &str) -> Self {
        Self {
            name: name.to_string(),
            service_type: service_type.to_string(),
            banners: Vec::new(),
            responses: HashMap::new(),
        }
    }

    pub fn with_banner(mut self, banner: Vec<u8>) -> Self {
        self.banners.push(banner);
        self
    }

    pub fn with_response(mut self, pattern: &str, response: Vec<u8>) -> Self {
        self.responses.insert(pattern.to_string(), response);
        self
    }

    pub fn http() -> Self {
        Self::new("http_static", "http")
            .with_banner(b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\nContent-Length: 426\r\nConnection: close\r\n\r\n".to_vec())
            .with_response("GET ", b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\nContent-Length: 426\r\nConnection: close\r\n\r\n".to_vec())
            .with_response("POST", b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Length: 0\r\n\r\n".to_vec())
    }

    pub fn ssh() -> Self {
        Self::new("ssh_static", "ssh")
            .with_banner(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n".to_vec())
    }

    pub fn ftp() -> Self {
        Self::new("ftp_static", "ftp")
            .with_banner(b"220 (vsFTPd 3.0.3)\r\n".to_vec())
            .with_response("USER ", b"331 Please specify the password.\r\n".to_vec())
            .with_response("PASS ", b"230 Login successful.\r\n".to_vec())
            .with_response(
                "LIST",
                b"150 Here comes the directory listing.\r\n226 Transfer complete.\r\n".to_vec(),
            )
    }

    pub fn mysql() -> Self {
        Self::new("mysql_static", "mysql").with_banner(vec![
            0x0a, 0x00, 0x00, 0x01, 0xff, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
    }

    pub fn redis() -> Self {
        Self::new("redis_static", "redis")
            .with_banner(b"+OK\r\n".to_vec())
            .with_response("PING", b"+PONG\r\n".to_vec())
            .with_response("GET ", b"$-1\r\n".to_vec())
            .with_response("SET ", b"+OK\r\n".to_vec())
    }

    pub fn tls() -> Self {
        Self::new("tls_static", "tls").with_banner(vec![
            0x16, 0x03, 0x01, 0x00, 0xc8, 0x01, 0x00, 0x00, 0xc4, 0x03, 0x03,
        ])
    }

    pub fn smtp() -> Self {
        Self::new("smtp_static", "smtp")
            .with_banner(b"220 mail.example.com ESMTP Postfix\r\n".to_vec())
            .with_response("EHLO", b"250-mail.example.com\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-ETRN\r\n250-STARTTLS\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250 SMTPUTF8\r\n".to_vec())
            .with_response("QUIT", b"221 2.0.0 Bye\r\n".to_vec())
    }

    pub fn pop3() -> Self {
        Self::new("pop3_static", "pop3")
            .with_banner(b"+OK POP3 server ready\r\n".to_vec())
            .with_response("USER ", b"+OK\r\n".to_vec())
            .with_response("PASS ", b"+OK Logged in.\r\n".to_vec())
    }

    pub fn imap() -> Self {
        Self::new("imap_static", "imap")
            .with_banner(b"* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE NAMESPACE LITERAL+ STARTTLS] Dovecot ready\r\n".to_vec())
    }

    pub fn telnet() -> Self {
        Self::new("telnet_static", "telnet")
            .with_banner(b"\r\nUbuntu 20.04.6 LTS\r\nlocalhost login: ".to_vec())
    }

    pub fn postgresql() -> Self {
        Self::new("postgresql_static", "postgresql")
            .with_banner(vec![0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f])
            .with_response("", vec![0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f])
    }

    pub fn smb() -> Self {
        Self::new("smb_static", "smb")
            .with_banner(b"\x00\x00\x00\x85 SMB2\x00\xff\xfeSMB 2.002\x00\x00\x00\x00\x00".to_vec())
    }

    pub fn rdp() -> Self {
        Self::new("rdp_static", "rdp").with_banner(vec![
            0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
    }

    pub fn vnc() -> Self {
        Self::new("vnc_static", "vnc")
            .with_banner(b"RFB 003.008\n".to_vec())
            .with_response("RFB 003.008", b"RFB 003.008\n".to_vec())
    }
}

impl HoneypotResponder for StaticResponder {
    fn name(&self) -> &str {
        &self.name
    }

    fn service_type(&self) -> &str {
        &self.service_type
    }

    fn respond(&self, payload: &[u8], _context: &HoneypotContext) -> HoneypotResponse {
        if payload.is_empty() {
            if let Some(banner) = self.banners.first() {
                return HoneypotResponse::static_response(banner.clone());
            }
            return HoneypotResponse::static_response(Vec::new());
        }

        if let Ok(text) = std::str::from_utf8(payload) {
            for (pattern, response) in &self.responses {
                if text.starts_with(pattern) || text.contains(pattern) {
                    return HoneypotResponse::static_response(response.clone());
                }
            }
        }

        if let Some(banner) = self.banners.first() {
            return HoneypotResponse::static_response(banner.clone());
        }

        HoneypotResponse::static_response(Vec::new())
    }

    fn clone_box(&self) -> Box<dyn HoneypotResponder> {
        Box::new(Self {
            name: self.name.clone(),
            service_type: self.service_type.clone(),
            banners: self.banners.clone(),
            responses: self.responses.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::honeypot_port::responses::HoneypotContext;

    fn make_context() -> HoneypotContext {
        HoneypotContext {
            remote_ip: "192.168.1.100".to_string(),
            remote_port: 12345,
            local_port: 22,
            service: "ssh".to_string(),
            protocol: "ssh".to_string(),
            payload: Vec::new(),
            payload_hex: String::new(),
            detected_pattern: None,
            bytes_received: 0,
            duration_ms: 0,
            connection_start: std::time::Instant::now(),
        }
    }

    #[test]
    fn test_ssh_banner() {
        let responder = StaticResponder::ssh();
        let context = make_context();

        let response = responder.respond(b"", &context);

        assert!(!response.data.is_empty());
        assert!(response.data.starts_with(b"SSH-"));
    }

    #[test]
    fn test_ftp_user_command() {
        let responder = StaticResponder::ftp();
        let context = make_context();

        let response = responder.respond(b"USER admin", &context);

        let response_str = String::from_utf8_lossy(&response.data);
        assert!(response_str.contains("331"));
    }

    #[test]
    fn test_ftp_pass_command() {
        let responder = StaticResponder::ftp();
        let context = make_context();

        let response = responder.respond(b"PASS password", &context);

        let response_str = String::from_utf8_lossy(&response.data);
        // Response should not be empty
        assert!(!response_str.is_empty());
    }

    #[test]
    fn test_http_get() {
        let responder = StaticResponder::http();
        let context = make_context();

        let response = responder.respond(b"GET / HTTP/1.1", &context);

        let response_str = String::from_utf8_lossy(&response.data);
        assert!(response_str.contains("200 OK"));
    }

    #[test]
    fn test_redis_ping() {
        let responder = StaticResponder::redis();
        let context = make_context();

        let response = responder.respond(b"PING", &context);

        let response_str = String::from_utf8_lossy(&response.data);
        assert!(response_str.contains("PONG"));
    }

    #[test]
    fn test_static_responder_name() {
        let responder = StaticResponder::new("test", "test");
        assert_eq!(responder.name(), "test");
        assert_eq!(responder.service_type(), "test");
    }
}
