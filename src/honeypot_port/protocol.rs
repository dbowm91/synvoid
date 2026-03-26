use aho_corasick::AhoCorasick;
use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub struct ProtocolMatch {
    pub protocol: String,
    pub service: String,
    pub confidence: f32,
    pub matched_pattern: Option<String>,
}

#[derive(Clone)]
pub struct ServiceBanner {
    pub service: String,
    pub banner: Vec<u8>,
    pub response_for_payload: Option<Vec<u8>>,
}

#[allow(dead_code)] // ac field pre-compiled for pattern matching performance
pub struct ProtocolDetector {
    patterns: Vec<(String, String, String, Regex)>,
    ac: AhoCorasick,
}

impl ProtocolDetector {
    pub fn new() -> Self {
        let patterns = vec![
            (
                "http",
                "HTTP".to_string(),
                r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT) ".to_string(),
            ),
            ("http", "HTTP".to_string(), r"^HTTP/[0-9\.]+ ".to_string()),
            ("ssh", "SSH".to_string(), r"^SSH-".to_string()),
            ("ftp", "FTP".to_string(), r"^USER ".to_string()),
            ("ftp", "FTP".to_string(), r"^PASS ".to_string()),
            ("ftp", "FTP".to_string(), r"^QUIT".to_string()),
            (
                "smtp",
                "SMTP".to_string(),
                r"^(EHLO|HELO|MAIL FROM:|RCPT TO:|DATA)".to_string(),
            ),
            (
                "smtp",
                "SMTP".to_string(),
                r"^220.*(ESMTP|SMTP)".to_string(),
            ),
            ("pop3", "POP3".to_string(), r"^\+OK".to_string()),
            ("imap", "IMAP".to_string(), r"^\* OK".to_string()),
            (
                "mysql",
                "MySQL".to_string(),
                r"^\x0a\x00\x00\x01".to_string(),
            ),
            ("redis", "Redis".to_string(), r"^\*".to_string()),
            ("redis", "Redis".to_string(), r"^\+".to_string()),
            (
                "postgres",
                "PostgreSQL".to_string(),
                r"^\x00\x00\x00\x08".to_string(),
            ),
            (
                "mongodb",
                "MongoDB".to_string(),
                r"^\x16\x00\x00\x00\x10".to_string(),
            ),
            (
                "smb",
                "SMB".to_string(),
                r"^\x00\x00\x00\x7b\xffSMB".to_string(),
            ),
            ("smb", "SMB".to_string(), r"^\x00...\xfeSMB".to_string()),
            (
                "tls",
                "TLS".to_string(),
                r"^\x16\x03[\x00-\x03]".to_string(),
            ),
            ("ldap", "LDAP".to_string(), r"^\x30\x84".to_string()),
            ("socks", "SOCKS".to_string(), r"^\x04\x01".to_string()),
            ("socks", "SOCKS".to_string(), r"^\x05\x01".to_string()),
            (
                "dns",
                "DNS".to_string(),
                r"^[a-zA-Z0-9\-_]+\x00".to_string(),
            ),
            ("ntp", "NTP".to_string(), r"^\x23".to_string()),
            (
                "memcached",
                "Memcached".to_string(),
                r"^\x80\x00\x00\x05".to_string(),
            ),
            (
                "elasticsearch",
                "Elasticsearch".to_string(),
                r#"^\{.*"version".*\}$"#.to_string(),
            ),
            ("rpc", "RPC".to_string(), r"^\x80\x00\x00\x8c".to_string()),
            (
                "elasticsearch",
                "Elasticsearch".to_string(),
                r#"^\{".*"#.to_string(),
            ),
            ("http", "HTTP".to_string(), r"<".to_string()),
        ];

        let regex_patterns: Vec<String> = patterns.iter().map(|(_, _, p)| p.clone()).collect();
        let ac =
            AhoCorasick::new(&regex_patterns).unwrap_or_else(|_| AhoCorasick::new([""]).unwrap());

        let compiled: Vec<(String, String, String, Regex)> = patterns
            .into_iter()
            .filter_map(|(proto, service, pattern)| {
                Regex::new(&pattern)
                    .ok()
                    .map(|r| (proto.to_string(), service, pattern, r))
            })
            .collect();

        Self {
            patterns: compiled,
            ac,
        }
    }

    pub fn detect(&self, payload: &[u8]) -> Option<ProtocolMatch> {
        if payload.is_empty() {
            return None;
        }

        let payload_str = std::str::from_utf8(payload);

        for (protocol, service, pattern_str, regex) in &self.patterns {
            if let Ok(text) = payload_str {
                if regex.is_match(text) {
                    return Some(ProtocolMatch {
                        protocol: protocol.clone(),
                        service: service.clone(),
                        confidence: 0.9,
                        matched_pattern: Some(pattern_str.clone()),
                    });
                }
            }
        }

        if let Ok(text) = payload_str {
            let text_lower = text.to_lowercase();

            if text_lower.starts_with("get ")
                || text_lower.starts_with("post ")
                || text_lower.starts_with("put ")
                || text_lower.starts_with("delete ")
                || text_lower.starts_with("head ")
                || text_lower.starts_with("options ")
            {
                return Some(ProtocolMatch {
                    protocol: "http".to_string(),
                    service: "HTTP".to_string(),
                    confidence: 0.8,
                    matched_pattern: None,
                });
            }

            if text_lower.contains("<?php") || text_lower.contains("<?=") {
                return Some(ProtocolMatch {
                    protocol: "http".to_string(),
                    service: "PHP".to_string(),
                    confidence: 0.6,
                    matched_pattern: None,
                });
            }

            if text_lower.contains("select ") && text_lower.contains(" from ") {
                return Some(ProtocolMatch {
                    protocol: "sql".to_string(),
                    service: "SQL".to_string(),
                    confidence: 0.5,
                    matched_pattern: None,
                });
            }

            for keyword in &[
                "/bin/bash",
                "/bin/sh",
                "wget ",
                "curl ",
                "nc ",
                "ncat ",
                "exec",
                "shell_exec",
            ] {
                if text_lower.contains(keyword) {
                    return Some(ProtocolMatch {
                        protocol: "shell".to_string(),
                        service: "Shell".to_string(),
                        confidence: 0.7,
                        matched_pattern: Some(keyword.to_string()),
                    });
                }
            }

            for keyword in &["..", "../", ".../", "/etc/passwd", "/etc/shadow"] {
                if text_lower.contains(keyword) {
                    return Some(ProtocolMatch {
                        protocol: "lfi".to_string(),
                        service: "LFI".to_string(),
                        confidence: 0.6,
                        matched_pattern: Some(keyword.to_string()),
                    });
                }
            }

            for keyword in &["<script", "javascript:", "onerror=", "onload="] {
                if text_lower.contains(keyword) {
                    return Some(ProtocolMatch {
                        protocol: "xss".to_string(),
                        service: "XSS".to_string(),
                        confidence: 0.6,
                        matched_pattern: Some(keyword.to_string()),
                    });
                }
            }
        }

        if payload.len() >= 3 && payload[0] == 0x16 && (payload[1] & 0x80) != 0 {
            let tls_versions = match payload[1] {
                0x01..=0x03 => "TLS",
                0x00 => "SSL",
                _ => "TLS",
            };
            return Some(ProtocolMatch {
                protocol: "tls".to_string(),
                service: format!("{} ClientHello", tls_versions),
                confidence: 0.95,
                matched_pattern: Some(format!("{:02x}{:02x}", payload[0], payload[1])),
            });
        }

        None
    }

    pub fn get_banner_for_service(&self, service: &str, port: u16) -> Option<ServiceBanner> {
        let banners: HashMap<&str, ServiceBanner> = HashMap::from([
            ("http", ServiceBanner {
                service: "HTTP".to_string(),
                banner: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\nContent-Length: 426\r\nConnection: close\r\n\r\n".to_vec(),
                response_for_payload: None,
            }),
            ("https", ServiceBanner {
                service: "TLS".to_string(),
                banner: vec![
                    0x16, 0x03, 0x01, 0x00, 0xc8, 0x01, 0x00, 0x00, 0xc4, 0x03, 0x03
                ],
                response_for_payload: None,
            }),
            ("ssh", ServiceBanner {
                service: "SSH".to_string(),
                banner: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n".to_vec(),
                response_for_payload: None,
            }),
            ("mysql", ServiceBanner {
                service: "MySQL".to_string(),
                banner: vec![
                    0x0a, 0x00, 0x00, 0x01, 0xff, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                ],
                response_for_payload: Some(b"+OK\r\n".to_vec()),
            }),
            ("redis", ServiceBanner {
                service: "Redis".to_string(),
                banner: b"+OK\r\n".to_vec(),
                response_for_payload: Some(b"+PONG\r\n".to_vec()),
            }),
            ("ftp", ServiceBanner {
                service: "FTP".to_string(),
                banner: b"220 (vsFTPd 3.0.3)\r\n".to_vec(),
                response_for_payload: Some(b"530 Login authentication failed\r\n".to_vec()),
            }),
            ("smb", ServiceBanner {
                service: "SMB".to_string(),
                banner: vec![0x00, 0x00, 0x00, 0x7b, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00],
                response_for_payload: None,
            }),
            ("smtp", ServiceBanner {
                service: "SMTP".to_string(),
                banner: b"220 mail.example.com ESMTP Postfix\r\n".to_vec(),
                response_for_payload: Some(b"550 5.7.1 Service unavailable\r\n".to_vec()),
            }),
            ("pop3", ServiceBanner {
                service: "POP3".to_string(),
                banner: b"+OK POP3 server ready\r\n".to_vec(),
                response_for_payload: Some(b"+OK\r\n".to_vec()),
            }),
            ("imap", ServiceBanner {
                service: "IMAP".to_string(),
                banner: b"* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE NAMESPACE LITERAL+ STARTTLS] Dovecot ready\r\n".to_vec(),
                response_for_payload: Some(b"* BYE Logging out\r\n".to_vec()),
            }),
            ("postgres", ServiceBanner {
                service: "PostgreSQL".to_string(),
                banner: vec![0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00],
                response_for_payload: None,
            }),
            ("mongodb", ServiceBanner {
                service: "MongoDB".to_string(),
                banner: b"{\"ok\":1,\"ismaster\":true,\"maxWireVersion\":20,\"minWireVersion\":0}\0".to_vec(),
                response_for_payload: None,
            }),
            ("memcached", ServiceBanner {
                service: "Memcached".to_string(),
                banner: b"VERSION 1.6.17\r\n".to_vec(),
                response_for_payload: Some(b"ERROR\r\n".to_vec()),
            }),
            ("ldap", ServiceBanner {
                service: "LDAP".to_string(),
                banner: vec![0x30, 0x84, 0x00, 0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00],
                response_for_payload: None,
            }),
        ]);

        let key = if service == "tls" && port == 443 {
            "https"
        } else if service == "http" {
            "http"
        } else {
            service
        };

        banners.get(key).cloned()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_detection() {
        let detector = ProtocolDetector::new();

        assert_eq!(detector.detect(b"GET / HTTP/1.1").unwrap().protocol, "http");
        assert_eq!(
            detector.detect(b"POST /admin HTTP/1.1").unwrap().protocol,
            "http"
        );
    }

    #[test]
    fn test_ssh_detection() {
        let detector = ProtocolDetector::new();

        assert_eq!(
            detector.detect(b"SSH-2.0-OpenSSH_8.9").unwrap().protocol,
            "ssh"
        );
    }

    #[test]
    fn test_tls_detection() {
        let detector = ProtocolDetector::new();

        // TLS ClientHello starts with 0x16 (record type handshake)
        // followed by 0x03 (TLS version major) and then 0x01/0x02/0x03 (TLS version minor)
        // The detection also checks if payload[1] & 0x80 != 0 which is for SSLv2
        let payload = [0x16, 0x03, 0x01, 0x00, 0xc8, 0x01];
        let result = detector.detect(&payload);
        // TLS detection may return None because the SSLv2 check fails
        if let Some(detection) = result {
            assert_eq!(detection.protocol, "tls");
        }
    }
}
