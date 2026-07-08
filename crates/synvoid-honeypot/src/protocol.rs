use std::collections::HashMap;
use std::sync::LazyLock;

/// Detection confidence level.
///
/// - High: strong magic/prefix (SSH banner, TLS record header, SMB marker, HTTP method with request syntax)
/// - Medium: recognizable text command with common protocol token
/// - Low: weak shape-only binary checks
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::High => write!(f, "high"),
            Confidence::Medium => write!(f, "medium"),
            Confidence::Low => write!(f, "low"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProtocolMatch {
    /// Normalized protocol identifier: http, ssh, tls, mysql, redis, postgres, smb, dns, etc.
    pub protocol: String,
    /// Display/service label: HTTP, SSH, PostgreSQL, etc.
    pub service: String,
    pub confidence: Confidence,
    /// Short non-payload reason, e.g. "http_method", "tls_record_header"
    pub evidence: String,
}

#[derive(Clone)]
pub struct ServiceBanner {
    pub service: String,
    pub banner: Vec<u8>,
    pub response_for_payload: Option<Vec<u8>>,
}

pub struct ProtocolDetector;

impl ProtocolDetector {
    pub fn new() -> Self {
        Self
    }

    /// Detect protocol from raw bytes. Binary-safe: does not require valid UTF-8.
    /// Detection order:
    /// 1. Binary fixed-prefix and structural checks
    /// 2. ASCII/text protocol method checks on a lossy or bounded ASCII path
    /// 3. Fallback/unknown
    pub fn detect(&self, payload: &[u8]) -> Option<ProtocolMatch> {
        if payload.is_empty() {
            return None;
        }

        // Phase 1: Binary fixed-prefix checks (no UTF-8 required)
        if let Some(detection) = Self::detect_binary(payload) {
            return Some(detection);
        }

        // Phase 2: Text protocol checks (requires valid UTF-8 for text protocols)
        if let Ok(text) = std::str::from_utf8(payload) {
            if let Some(detection) = Self::detect_text(text) {
                return Some(detection);
            }
        }

        None
    }

    /// Binary protocol detection. Pure byte-level, no UTF-8 dependency.
    fn detect_binary(payload: &[u8]) -> Option<ProtocolMatch> {
        // TLS/SSL: record type 0x16 (handshake), version bytes 0x03 0x00..=0x04
        if payload.len() >= 5 && payload[0] == 0x16 && payload[1] == 0x03 {
            let version = payload[2];
            if version <= 0x04 {
                let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
                if record_len > 0 && record_len <= 16384 + 256 {
                    let version_name = match version {
                        0x00 => "SSLv3",
                        0x01 => "TLS 1.0",
                        0x02 => "TLS 1.1",
                        0x03 => "TLS 1.2",
                        0x04 => "TLS 1.3",
                        _ => "TLS",
                    };
                    return Some(ProtocolMatch {
                        protocol: "tls".to_string(),
                        service: format!("{} ClientHello", version_name),
                        confidence: Confidence::High,
                        evidence: "tls_record_header".to_string(),
                    });
                }
            }
        }

        // SSH: starts with "SSH-"
        if payload.len() >= 4 && &payload[..4] == b"SSH-" {
            return Some(ProtocolMatch {
                protocol: "ssh".to_string(),
                service: "SSH".to_string(),
                confidence: Confidence::High,
                evidence: "ssh_banner_prefix".to_string(),
            });
        }

        // VNC: starts with "RFB "
        if payload.len() >= 4 && &payload[..4] == b"RFB " {
            return Some(ProtocolMatch {
                protocol: "vnc".to_string(),
                service: "VNC".to_string(),
                confidence: Confidence::High,
                evidence: "vnc_banner_prefix".to_string(),
            });
        }

        // SMB1: \xffSMB or \xfeSMB
        if payload.len() >= 4
            && (payload[0] == 0xff || payload[0] == 0xfe)
            && payload[1] == 0x53
            && payload[2] == 0x4d
            && payload[3] == 0x42
        {
            return Some(ProtocolMatch {
                protocol: "smb".to_string(),
                service: "SMB".to_string(),
                confidence: Confidence::High,
                evidence: "smb_marker".to_string(),
            });
        }

        // MySQL: first packet starts with 0x0a (protocol version 10 greeting)
        if payload.len() >= 5 && payload[0] == 0x0a {
            return Some(ProtocolMatch {
                protocol: "mysql".to_string(),
                service: "MySQL".to_string(),
                confidence: Confidence::Medium,
                evidence: "mysql_handshake_v10".to_string(),
            });
        }

        // PostgreSQL SSLRequest: 8 bytes starting with 0x00 0x00 0x00 0x08 0x04 0xd2
        if payload.len() >= 8
            && payload[0] == 0x00
            && payload[1] == 0x00
            && payload[2] == 0x00
            && payload[3] == 0x08
            && payload[4] == 0x04
            && payload[5] == 0xd2
        {
            return Some(ProtocolMatch {
                protocol: "postgres".to_string(),
                service: "PostgreSQL".to_string(),
                confidence: Confidence::High,
                evidence: "postgresql_ssl_request".to_string(),
            });
        }

        // RDP TPKT: 0x03 0x00
        if payload.len() >= 4 && payload[0] == 0x03 && payload[1] == 0x00 {
            return Some(ProtocolMatch {
                protocol: "rdp".to_string(),
                service: "RDP".to_string(),
                confidence: Confidence::Low,
                evidence: "rdp_tpkt_header".to_string(),
            });
        }

        // Redis RESP: starts with * (array), + (simple string), - (error), : (integer), $ (bulk string)
        if payload.len() >= 2 {
            match payload[0] {
                b'*' => {
                    if let Some(d) = Self::try_detect_redis_resp(payload) {
                        return Some(d);
                    }
                }
                b'+' | b'-' | b':' | b'$' if Self::looks_like_redis_inline(payload) => {
                    return Some(ProtocolMatch {
                        protocol: "redis".to_string(),
                        service: "Redis".to_string(),
                        confidence: Confidence::Medium,
                        evidence: "redis_resp_prefix".to_string(),
                    });
                }
                _ => {}
            }
        }

        // MongoDB: starts with specific opmsg/opquery headers
        if payload.len() >= 5 && payload[0] == 0x3a && payload[1] == 0x00 {
            return Some(ProtocolMatch {
                protocol: "mongodb".to_string(),
                service: "MongoDB".to_string(),
                confidence: Confidence::Low,
                evidence: "mongodb_opmsg_header".to_string(),
            });
        }

        // DNS: minimal UDP header shape (12-byte header with reasonable flags)
        if payload.len() >= 12 {
            let flags = u16::from_be_bytes([payload[2], payload[3]]);
            let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
            let ancount = u16::from_be_bytes([payload[6], payload[7]]);
            // Standard query: QR=0, opcode=0, QDCOUNT=1, ANCOUNT=0
            if (flags & 0x8000) == 0 && (flags & 0x7800) == 0 && qdcount == 1 && ancount == 0 {
                return Some(ProtocolMatch {
                    protocol: "dns".to_string(),
                    service: "DNS".to_string(),
                    confidence: Confidence::Low,
                    evidence: "dns_udp_header".to_string(),
                });
            }
        }

        None
    }

    fn try_detect_redis_resp(payload: &[u8]) -> Option<ProtocolMatch> {
        // *N\r\n where N is a digit
        if payload[0] == b'*' {
            let mut i = 1;
            while i < payload.len() && payload[i].is_ascii_digit() {
                i += 1;
            }
            if i > 1 && i < payload.len() && payload[i] == b'\r' {
                return Some(ProtocolMatch {
                    protocol: "redis".to_string(),
                    service: "Redis".to_string(),
                    confidence: Confidence::High,
                    evidence: "redis_resp_array".to_string(),
                });
            }
        }
        None
    }

    fn looks_like_redis_inline(payload: &[u8]) -> bool {
        // Check for common inline commands: PING, AUTH, SET, GET, etc.
        let text = String::from_utf8_lossy(payload);
        let upper = text.to_uppercase();
        upper.starts_with("PING")
            || upper.starts_with("AUTH ")
            || upper.starts_with("SET ")
            || upper.starts_with("GET ")
            || upper.starts_with("DEL ")
            || upper.starts_with("INFO")
            || upper.starts_with("COMMAND")
    }

    /// Text protocol detection. Requires valid UTF-8 input.
    fn detect_text(text: &str) -> Option<ProtocolMatch> {
        // HTTP methods (high confidence with request-line syntax)
        if Self::detect_http(text) {
            return Some(ProtocolMatch {
                protocol: "http".to_string(),
                service: "HTTP".to_string(),
                confidence: Confidence::High,
                evidence: "http_method".to_string(),
            });
        }

        // HTTP response
        if text.starts_with("HTTP/") {
            return Some(ProtocolMatch {
                protocol: "http".to_string(),
                service: "HTTP".to_string(),
                confidence: Confidence::High,
                evidence: "http_response_status".to_string(),
            });
        }

        // SMTP
        if let Some(d) = Self::detect_smtp(text) {
            return Some(d);
        }

        // FTP
        if let Some(d) = Self::detect_ftp(text) {
            return Some(d);
        }

        // POP3
        if text.starts_with("+OK") {
            return Some(ProtocolMatch {
                protocol: "pop3".to_string(),
                service: "POP3".to_string(),
                confidence: Confidence::High,
                evidence: "pop3_positive_response".to_string(),
            });
        }

        // IMAP
        if text.starts_with("* OK") {
            return Some(ProtocolMatch {
                protocol: "imap".to_string(),
                service: "IMAP".to_string(),
                confidence: Confidence::Medium,
                evidence: "imap_greeting".to_string(),
            });
        }

        // Redis inline commands (text form)
        if Self::looks_like_redis_inline(text.as_bytes()) {
            return Some(ProtocolMatch {
                protocol: "redis".to_string(),
                service: "Redis".to_string(),
                confidence: Confidence::Medium,
                evidence: "redis_inline_command".to_string(),
            });
        }

        // MongoDB JSON wire protocol
        if text.starts_with('{') && text.contains("\"ismaster\"") {
            return Some(ProtocolMatch {
                protocol: "mongodb".to_string(),
                service: "MongoDB".to_string(),
                confidence: Confidence::Medium,
                evidence: "mongodb_json_ismaster".to_string(),
            });
        }

        None
    }

    fn detect_http(text: &str) -> bool {
        text.starts_with("GET ")
            || text.starts_with("POST ")
            || text.starts_with("PUT ")
            || text.starts_with("DELETE ")
            || text.starts_with("HEAD ")
            || text.starts_with("OPTIONS ")
            || text.starts_with("PATCH ")
            || text.starts_with("TRACE ")
            || text.starts_with("CONNECT ")
    }

    fn detect_smtp(text: &str) -> Option<ProtocolMatch> {
        let upper = text.to_uppercase();
        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            return Some(ProtocolMatch {
                protocol: "smtp".to_string(),
                service: "SMTP".to_string(),
                confidence: Confidence::High,
                evidence: "smtp_ehlo".to_string(),
            });
        }
        if upper.starts_with("MAIL FROM:")
            || upper.starts_with("RCPT TO:")
            || upper.starts_with("DATA")
        {
            return Some(ProtocolMatch {
                protocol: "smtp".to_string(),
                service: "SMTP".to_string(),
                confidence: Confidence::High,
                evidence: "smtp_command".to_string(),
            });
        }
        if text.starts_with("220 ") && (upper.contains("ESMTP") || upper.contains("SMTP")) {
            return Some(ProtocolMatch {
                protocol: "smtp".to_string(),
                service: "SMTP".to_string(),
                confidence: Confidence::High,
                evidence: "smtp_banner".to_string(),
            });
        }
        None
    }

    fn detect_ftp(text: &str) -> Option<ProtocolMatch> {
        let upper = text.to_uppercase();
        if upper.starts_with("USER ") {
            return Some(ProtocolMatch {
                protocol: "ftp".to_string(),
                service: "FTP".to_string(),
                confidence: Confidence::High,
                evidence: "ftp_user".to_string(),
            });
        }
        if upper.starts_with("PASS ") {
            return Some(ProtocolMatch {
                protocol: "ftp".to_string(),
                service: "FTP".to_string(),
                confidence: Confidence::High,
                evidence: "ftp_pass".to_string(),
            });
        }
        if upper.starts_with("QUIT") {
            return Some(ProtocolMatch {
                protocol: "ftp".to_string(),
                service: "FTP".to_string(),
                confidence: Confidence::Medium,
                evidence: "ftp_quit".to_string(),
            });
        }
        if text.starts_with("220 ") && upper.contains("FTP") {
            return Some(ProtocolMatch {
                protocol: "ftp".to_string(),
                service: "FTP".to_string(),
                confidence: Confidence::High,
                evidence: "ftp_banner".to_string(),
            });
        }
        None
    }

    pub fn get_banner_for_service(&self, service: &str, port: u16) -> Option<ServiceBanner> {
        let key = if service == "tls" && port == 443 {
            "https"
        } else {
            service
        };
        BANNER_MAP.get(key).cloned()
    }

    pub fn detect_and_get_banner(&self, payload: &[u8], port: u16) -> Option<ServiceBanner> {
        let detection = self.detect(payload)?;

        if detection.protocol == "http" && port == 80 {
            return self.get_banner_for_service("http", port);
        }
        if detection.protocol == "tls" || port == 443 {
            return self.get_banner_for_service("https", port);
        }

        self.get_banner_for_service(&detection.protocol, port)
    }
}

impl Default for ProtocolDetector {
    fn default() -> Self {
        Self::new()
    }
}

static BANNER_MAP: LazyLock<HashMap<&'static str, ServiceBanner>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert(
        "http",
        ServiceBanner {
            service: "HTTP".to_string(),
            banner: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\nContent-Length: 426\r\nConnection: close\r\n\r\n".to_vec(),
            response_for_payload: None,
        },
    );
    m.insert(
        "https",
        ServiceBanner {
            service: "TLS".to_string(),
            banner: vec![
                0x16, 0x03, 0x01, 0x00, 0xc8, 0x01, 0x00, 0x00, 0xc4, 0x03, 0x03,
            ],
            response_for_payload: None,
        },
    );
    m.insert(
        "ssh",
        ServiceBanner {
            service: "SSH".to_string(),
            banner: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n".to_vec(),
            response_for_payload: None,
        },
    );
    m.insert(
        "mysql",
        ServiceBanner {
            service: "MySQL".to_string(),
            banner: vec![
                0x0a, 0x00, 0x00, 0x01, 0xff, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            response_for_payload: Some(b"+OK\r\n".to_vec()),
        },
    );
    m.insert(
        "redis",
        ServiceBanner {
            service: "Redis".to_string(),
            banner: b"+OK\r\n".to_vec(),
            response_for_payload: Some(b"+PONG\r\n".to_vec()),
        },
    );
    m.insert(
        "ftp",
        ServiceBanner {
            service: "FTP".to_string(),
            banner: b"220 (vsFTPd 3.0.3)\r\n".to_vec(),
            response_for_payload: Some(b"530 Login authentication failed\r\n".to_vec()),
        },
    );
    m.insert(
        "smb",
        ServiceBanner {
            service: "SMB".to_string(),
            banner: vec![
                0x00, 0x00, 0x00, 0x7b, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00,
            ],
            response_for_payload: None,
        },
    );
    m.insert(
        "smtp",
        ServiceBanner {
            service: "SMTP".to_string(),
            banner: b"220 mail.example.com ESMTP Postfix\r\n".to_vec(),
            response_for_payload: Some(b"550 5.7.1 Service unavailable\r\n".to_vec()),
        },
    );
    m.insert(
        "pop3",
        ServiceBanner {
            service: "POP3".to_string(),
            banner: b"+OK POP3 server ready\r\n".to_vec(),
            response_for_payload: Some(b"+OK\r\n".to_vec()),
        },
    );
    m.insert(
        "imap",
        ServiceBanner {
            service: "IMAP".to_string(),
            banner: b"* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE NAMESPACE LITERAL+ STARTTLS] Dovecot ready\r\n".to_vec(),
            response_for_payload: Some(b"* BYE Logging out\r\n".to_vec()),
        },
    );
    m.insert(
        "postgres",
        ServiceBanner {
            service: "PostgreSQL".to_string(),
            banner: vec![0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00],
            response_for_payload: None,
        },
    );
    m.insert(
        "mongodb",
        ServiceBanner {
            service: "MongoDB".to_string(),
            banner: b"{\"ok\":1,\"ismaster\":true,\"maxWireVersion\":20,\"minWireVersion\":0}\0"
                .to_vec(),
            response_for_payload: None,
        },
    );
    m.insert(
        "vnc",
        ServiceBanner {
            service: "VNC".to_string(),
            banner: b"RFB 003.008\n".to_vec(),
            response_for_payload: None,
        },
    );
    m.insert(
        "rdp",
        ServiceBanner {
            service: "RDP".to_string(),
            banner: vec![
                0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            response_for_payload: None,
        },
    );
    m
});

#[cfg(test)]
mod tests {
    use super::*;

    fn detect_proto(payload: &[u8]) -> &'static str {
        let detector = ProtocolDetector::new();
        match detector.detect(payload) {
            Some(m) => leak_protocol(m.protocol),
            None => "none",
        }
    }

    fn detect_confidence(payload: &[u8]) -> Confidence {
        let detector = ProtocolDetector::new();
        detector
            .detect(payload)
            .map(|m| m.confidence)
            .unwrap_or(Confidence::Low)
    }

    fn leak_protocol(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    // --- TLS ---

    #[test]
    fn test_tls_10() {
        assert_eq!(detect_proto(&[0x16, 0x03, 0x01, 0x00, 0x2e, 0x01]), "tls");
    }

    #[test]
    fn test_tls_12() {
        assert_eq!(detect_proto(&[0x16, 0x03, 0x03, 0x00, 0xc8, 0x01]), "tls");
    }

    #[test]
    fn test_tls_13() {
        assert_eq!(detect_proto(&[0x16, 0x03, 0x04, 0x00, 0x2e, 0x01]), "tls");
    }

    #[test]
    fn test_tls_sslv3() {
        assert_eq!(detect_proto(&[0x16, 0x03, 0x00, 0x00, 0x2e, 0x01]), "tls");
    }

    #[test]
    fn test_tls_version_label() {
        let detector = ProtocolDetector::new();
        let m = detector.detect(&[0x16, 0x03, 0x03, 0x00, 0xc8]).unwrap();
        assert_eq!(m.service, "TLS 1.2 ClientHello");
    }

    #[test]
    fn test_tls_high_confidence() {
        assert_eq!(
            detect_confidence(&[0x16, 0x03, 0x01, 0x00, 0x2e]),
            Confidence::High
        );
    }

    #[test]
    fn test_random_binary_not_tls() {
        let detector = ProtocolDetector::new();
        assert!(detector.detect(&[0xDE, 0xAD, 0xBE, 0xEF]).is_none());
    }

    #[test]
    fn test_tls_record_too_short() {
        // 0x16 0x03 but only 2 bytes - too short for record header
        let detector = ProtocolDetector::new();
        assert!(detector.detect(&[0x16, 0x03]).is_none());
    }

    #[test]
    fn test_tls_invalid_version() {
        // 0x16 0x03 0x05 is out of range
        let detector = ProtocolDetector::new();
        assert!(detector.detect(&[0x16, 0x03, 0x05, 0x00, 0x01]).is_none());
    }

    // --- SSH ---

    #[test]
    fn test_ssh_banner() {
        assert_eq!(detect_proto(b"SSH-2.0-OpenSSH_8.9"), "ssh");
    }

    #[test]
    fn test_ssh_high_confidence() {
        assert_eq!(detect_confidence(b"SSH-2.0-OpenSSH_8.9"), Confidence::High);
    }

    // --- HTTP ---

    #[test]
    fn test_http_get() {
        assert_eq!(detect_proto(b"GET / HTTP/1.1"), "http");
    }

    #[test]
    fn test_http_post() {
        assert_eq!(detect_proto(b"POST /admin HTTP/1.1"), "http");
    }

    #[test]
    fn test_http_put() {
        assert_eq!(detect_proto(b"PUT /resource HTTP/1.1"), "http");
    }

    #[test]
    fn test_http_delete() {
        assert_eq!(detect_proto(b"DELETE /item HTTP/1.1"), "http");
    }

    #[test]
    fn test_http_head() {
        assert_eq!(detect_proto(b"HEAD / HTTP/1.1"), "http");
    }

    #[test]
    fn test_http_options() {
        assert_eq!(detect_proto(b"OPTIONS * HTTP/1.1"), "http");
    }

    #[test]
    fn test_http_patch() {
        assert_eq!(detect_proto(b"PATCH /item HTTP/1.1"), "http");
    }

    #[test]
    fn test_http_response() {
        assert_eq!(detect_proto(b"HTTP/1.1 200 OK"), "http");
    }

    #[test]
    fn test_http_high_confidence() {
        assert_eq!(detect_confidence(b"GET / HTTP/1.1"), Confidence::High);
    }

    // --- SMTP ---

    #[test]
    fn test_smtp_ehlo() {
        assert_eq!(detect_proto(b"EHLO example.com"), "smtp");
    }

    #[test]
    fn test_smtp_helo() {
        assert_eq!(detect_proto(b"HELO example.com"), "smtp");
    }

    #[test]
    fn test_smtp_mail_from() {
        assert_eq!(detect_proto(b"MAIL FROM:<user@example.com>"), "smtp");
    }

    #[test]
    fn test_smtp_banner() {
        assert_eq!(detect_proto(b"220 mail.example.com ESMTP Postfix"), "smtp");
    }

    // --- FTP ---

    #[test]
    fn test_ftp_user() {
        assert_eq!(detect_proto(b"USER admin"), "ftp");
    }

    #[test]
    fn test_ftp_pass() {
        assert_eq!(detect_proto(b"PASS password"), "ftp");
    }

    #[test]
    fn test_ftp_quit() {
        assert_eq!(detect_proto(b"QUIT"), "ftp");
    }

    #[test]
    fn test_ftp_banner() {
        assert_eq!(detect_proto(b"220 (vsFTPd 3.0.3)"), "ftp");
    }

    // --- POP3 ---

    #[test]
    fn test_pop3() {
        assert_eq!(detect_proto(b"+OK POP3 server ready"), "pop3");
    }

    // --- IMAP ---

    #[test]
    fn test_imap() {
        assert_eq!(detect_proto(b"* OK [CAPABILITY] Dovecot ready"), "imap");
    }

    // --- MySQL ---

    #[test]
    fn test_mysql_handshake() {
        assert_eq!(detect_proto(&[0x0a, 0x00, 0x00, 0x01, 0xff, 0x15]), "mysql");
    }

    // --- Redis ---

    #[test]
    fn test_redis_resp_array() {
        assert_eq!(detect_proto(b"*1\r\n$4\r\nPING\r\n"), "redis");
    }

    #[test]
    fn test_redis_inline_ping() {
        assert_eq!(detect_proto(b"PING"), "redis");
    }

    #[test]
    fn test_redis_inline_auth() {
        assert_eq!(detect_proto(b"AUTH password"), "redis");
    }

    // --- PostgreSQL ---

    #[test]
    fn test_postgres_ssl_request() {
        assert_eq!(
            detect_proto(&[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f]),
            "postgres"
        );
    }

    // --- SMB ---

    #[test]
    fn test_smb1() {
        assert_eq!(detect_proto(&[0xff, 0x53, 0x4d, 0x42, 0x72]), "smb");
    }

    #[test]
    fn test_smb2() {
        assert_eq!(detect_proto(&[0xfe, 0x53, 0x4d, 0x42]), "smb");
    }

    // --- RDP ---

    #[test]
    fn test_rdp() {
        assert_eq!(detect_proto(&[0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0]), "rdp");
    }

    // --- VNC ---

    #[test]
    fn test_vnc() {
        assert_eq!(detect_proto(b"RFB 003.008\n"), "vnc");
    }

    // --- DNS ---

    #[test]
    fn test_dns_query() {
        // Standard DNS query header: ID=0x0000, flags=0x0100 (standard query, recursion desired),
        // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        assert_eq!(
            detect_proto(&[0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            "dns"
        );
    }

    // --- Binary with invalid UTF-8 ---

    #[test]
    fn test_invalid_utf8_with_valid_binary_sig() {
        // TLS record with invalid UTF-8 bytes after header
        let payload = [0x16, 0x03, 0x01, 0x00, 0x05, 0xff, 0xfe, 0xfd];
        assert_eq!(detect_proto(&payload), "tls");
    }

    #[test]
    fn test_invalid_utf8_no_known_sig() {
        // Random binary with no known signature
        let payload = [0xc0, 0x80, 0xc1, 0xa0, 0xff, 0xfe];
        let detector = ProtocolDetector::new();
        assert!(detector.detect(&payload).is_none());
    }

    // --- Empty ---

    #[test]
    fn test_empty_payload() {
        let detector = ProtocolDetector::new();
        assert!(detector.detect(b"").is_none());
    }

    // --- Banner lookup ---

    #[test]
    fn test_banner_lookup_normalized() {
        let detector = ProtocolDetector::new();
        let banner = detector.get_banner_for_service("http", 80).unwrap();
        assert_eq!(banner.service, "HTTP");
    }

    #[test]
    fn test_banner_lookup_tls_443() {
        let detector = ProtocolDetector::new();
        let banner = detector.get_banner_for_service("tls", 443).unwrap();
        assert_eq!(banner.service, "TLS");
    }

    #[test]
    fn test_banner_lookup_unknown() {
        let detector = ProtocolDetector::new();
        assert!(detector.get_banner_for_service("nonexistent", 0).is_none());
    }

    #[test]
    fn test_detect_and_get_banner_http() {
        let detector = ProtocolDetector::new();
        let banner = detector
            .detect_and_get_banner(b"GET / HTTP/1.1", 80)
            .unwrap();
        assert_eq!(banner.service, "HTTP");
    }

    #[test]
    fn test_detect_and_get_banner_ssh() {
        let detector = ProtocolDetector::new();
        let banner = detector
            .detect_and_get_banner(b"SSH-2.0-OpenSSH_8.9", 22)
            .unwrap();
        assert_eq!(banner.service, "SSH");
    }

    // --- Evidence field ---

    #[test]
    fn test_evidence_field_populated() {
        let detector = ProtocolDetector::new();
        let m = detector.detect(b"GET / HTTP/1.1").unwrap();
        assert!(!m.evidence.is_empty());
    }

    // --- Confidence ordering ---

    #[test]
    fn test_confidence_ordering() {
        assert!(Confidence::High > Confidence::Medium);
        assert!(Confidence::Medium > Confidence::Low);
    }
}
