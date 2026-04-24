use std::io;
use tokio::net::TcpStream;

use crate::protocol::detect_common::{extract_first_line, looks_like_dns, ProtocolDetectionResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    Smtp,
    Imap,
    Pop3,
    Http,
    Https,
    Http2,
    Http3,
    Grpc,
    WebSocket,
    WebDAV,
    Mysql,
    MariaDb,
    Postgres,
    Mongodb,
    Cassandra,
    Redis,
    Memcached,
    MemcachedBinary,
    Ssh,
    Ftp,
    Sftp,
    Telnet,
    Ldap,
    Ldaps,
    Rdp,
    Vnc,
    Xmpp,
    Irc,
    Amqp,
    Mqtt,
    Stomp,
    Kafka,
    CassandraCql,
    Elasticsearch,
    Solr,
    CassandraCompact,
    Dns,
    Ntp,
    Socks4,
    Socks5,
    HttpProxy,
    BitTorrent,
    Minecraft,
    Radius,
    Syslog,
    Prometheus,
    WireGuard,
    MeshQuic,
    Sip,
    H323,
    Rtsp,
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
            Protocol::Http3 => "http3",
            Protocol::Grpc => "grpc",
            Protocol::WebSocket => "websocket",
            Protocol::WebDAV => "webdav",
            Protocol::Mysql => "mysql",
            Protocol::MariaDb => "mariadb",
            Protocol::Postgres => "postgres",
            Protocol::Mongodb => "mongodb",
            Protocol::Cassandra => "cassandra",
            Protocol::Redis => "redis",
            Protocol::Memcached => "memcached",
            Protocol::MemcachedBinary => "memcached_binary",
            Protocol::Ssh => "ssh",
            Protocol::Ftp => "ftp",
            Protocol::Sftp => "sftp",
            Protocol::Telnet => "telnet",
            Protocol::Ldap => "ldap",
            Protocol::Ldaps => "ldaps",
            Protocol::Rdp => "rdp",
            Protocol::Vnc => "vnc",
            Protocol::Xmpp => "xmpp",
            Protocol::Irc => "irc",
            Protocol::Amqp => "amqp",
            Protocol::Mqtt => "mqtt",
            Protocol::Stomp => "stomp",
            Protocol::Kafka => "kafka",
            Protocol::CassandraCql => "cassandra_cql",
            Protocol::Elasticsearch => "elasticsearch",
            Protocol::Solr => "solr",
            Protocol::CassandraCompact => "cassandra_compact",
            Protocol::Dns => "dns",
            Protocol::Ntp => "ntp",
            Protocol::Socks4 => "socks4",
            Protocol::Socks5 => "socks5",
            Protocol::HttpProxy => "http_proxy",
            Protocol::BitTorrent => "bittorrent",
            Protocol::Minecraft => "minecraft",
            Protocol::Radius => "radius",
            Protocol::Syslog => "syslog",
            Protocol::Prometheus => "prometheus",
            Protocol::WireGuard => "wireguard",
            Protocol::MeshQuic => "mesh_quic",
            Protocol::Sip => "sip",
            Protocol::H323 => "h323",
            Protocol::Rtsp => "rtsp",
            Protocol::Unknown => "unknown",
        }
    }

    pub fn from_protocol_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "smtp" => Protocol::Smtp,
            "imap" => Protocol::Imap,
            "pop3" => Protocol::Pop3,
            "http" => Protocol::Http,
            "https" => Protocol::Https,
            "http2" | "h2" => Protocol::Http2,
            "http3" | "h3" => Protocol::Http3,
            "grpc" => Protocol::Grpc,
            "websocket" | "ws" | "wss" => Protocol::WebSocket,
            "webdav" => Protocol::WebDAV,
            "mysql" => Protocol::Mysql,
            "mariadb" => Protocol::MariaDb,
            "postgres" | "postgresql" => Protocol::Postgres,
            "mongodb" | "mongo" => Protocol::Mongodb,
            "cassandra" => Protocol::Cassandra,
            "redis" => Protocol::Redis,
            "memcached" => Protocol::Memcached,
            "memcached_binary" => Protocol::MemcachedBinary,
            "ssh" => Protocol::Ssh,
            "ftp" => Protocol::Ftp,
            "sftp" => Protocol::Sftp,
            "telnet" => Protocol::Telnet,
            "ldap" => Protocol::Ldap,
            "ldaps" => Protocol::Ldaps,
            "rdp" => Protocol::Rdp,
            "vnc" => Protocol::Vnc,
            "xmpp" => Protocol::Xmpp,
            "irc" => Protocol::Irc,
            "amqp" => Protocol::Amqp,
            "mqtt" => Protocol::Mqtt,
            "stomp" => Protocol::Stomp,
            "kafka" => Protocol::Kafka,
            "cassandra_cql" | "cql" => Protocol::CassandraCql,
            "elasticsearch" | "es" => Protocol::Elasticsearch,
            "solr" => Protocol::Solr,
            "cassandra_compact" => Protocol::CassandraCompact,
            "dns" => Protocol::Dns,
            "ntp" => Protocol::Ntp,
            "socks4" => Protocol::Socks4,
            "socks5" => Protocol::Socks5,
            "http_proxy" | "proxy" => Protocol::HttpProxy,
            "bittorrent" => Protocol::BitTorrent,
            "minecraft" => Protocol::Minecraft,
            "radius" => Protocol::Radius,
            "syslog" => Protocol::Syslog,
            "prometheus" => Protocol::Prometheus,
            "wireguard" | "wg" => Protocol::WireGuard,
            "mesh_quic" | "mesh" | "quic" => Protocol::MeshQuic,
            "sip" => Protocol::Sip,
            "h323" => Protocol::H323,
            "rtsp" => Protocol::Rtsp,
            _ => Protocol::Unknown,
        }
    }
}

impl crate::filter::Protocol for Protocol {
    fn as_str(&self) -> &str {
        Protocol::as_str(self)
    }

    fn from_str(s: &str) -> Self {
        Protocol::from_protocol_str(s)
    }
}

pub type ProtocolResult = ProtocolDetectionResult<Protocol>;

pub struct ProtocolDetector {
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
            peek_timeout_ms: self.peek_timeout_ms,
        }
    }
}

impl ProtocolDetector {
    pub fn new() -> Self {
        Self {
            peek_timeout_ms: 1000,
        }
    }

    pub async fn detect_peek(&self, stream: &TcpStream) -> io::Result<ProtocolResult> {
        let mut buffer = [0u8; 64];

        let n = tokio::time::timeout(
            std::time::Duration::from_millis(self.peek_timeout_ms),
            stream.peek(&mut buffer),
        )
        .await??;

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

        if self.looks_like_mesh_quic(data) {
            return Protocol::MeshQuic;
        }

        if data.len() >= 2 && data[0] == 0x16 && (data[1] == 0x03 || data[1] == 0x02) {
            if let Some(&_upgrade_byte) = data.get(5) {
                let first_line = extract_first_line(&data[5..]);
                if first_line.to_lowercase().contains("websocket") {
                    return Protocol::WebSocket;
                }
                if first_line.to_lowercase().contains("h2") {
                    return Protocol::Http2;
                }
                if first_line.to_lowercase().contains("h3") {
                    return Protocol::Http3;
                }
            }
            if data.len() >= 43 {
                let sni = &data[43..];
                let first_line = extract_first_line(sni);
                if first_line.to_lowercase().contains("wireguard") {
                    return Protocol::WireGuard;
                }
            }
            return Protocol::Https;
        }

        if data.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
            tracing::debug!("HTTP/2 connection preface detected");
            if self.looks_like_grpc(data) {
                return Protocol::Grpc;
            }
            return Protocol::Http2;
        }

        if self.looks_like_grpc(data) {
            tracing::debug!("gRPC framing detected");
            return Protocol::Grpc;
        }

        let first_line = extract_first_line(data);
        let upper_line = first_line.to_uppercase();

        if first_line.starts_with("OPTIONS ") && upper_line.contains("RTSP/") {
            return Protocol::Rtsp;
        }
        if first_line.starts_with("DESCRIBE ")
            || first_line.starts_with("SETUP ")
            || first_line.starts_with("PLAY ")
            || first_line.starts_with("PAUSE ")
            || first_line.starts_with("TEARDOWN ")
            || first_line.starts_with("RTSP/")
        {
            return Protocol::Rtsp;
        }

        if first_line.starts_with("GET")
            || first_line.starts_with("POST")
            || first_line.starts_with("HEAD")
            || first_line.starts_with("PUT")
            || first_line.starts_with("DELETE")
            || first_line.starts_with("OPTIONS")
            || first_line.starts_with("PATCH")
            || first_line.starts_with("CONNECT")
        {
            let data_upper = String::from_utf8_lossy(data).to_uppercase();
            if data_upper.contains("UPGRADE: WEBSOCKET") || data_upper.contains("SEC-WEBSOCKET") {
                return Protocol::WebSocket;
            }
            if data_upper.contains("UPGRADE: HTTP/3") || data_upper.contains("X-HTTP3-SETTING") {
                return Protocol::Http3;
            }
            if data_upper.contains("Destination:") && data_upper.contains(" Depth:") {
                return Protocol::WebDAV;
            }
            return Protocol::Http;
        }

        if first_line.starts_with("HELO")
            || first_line.starts_with("EHLO")
            || first_line.starts_with("MAIL FROM")
            || first_line.starts_with("RCPT TO")
            || first_line.starts_with("QUIT")
            || first_line.starts_with("DATA")
            || first_line.starts_with("RSET")
            || first_line.starts_with("NOOP")
        {
            return Protocol::Smtp;
        }

        if first_line.starts_with("A")
            && first_line
                .chars()
                .nth(4)
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
        {
            return Protocol::Imap;
        }

        if first_line.starts_with("USER")
            || first_line.starts_with("PASS")
            || first_line.starts_with("LIST")
            || first_line.starts_with("RETR")
            || first_line.starts_with("QUIT")
            || first_line.starts_with("CWD")
            || first_line.starts_with("PWD")
            || first_line.starts_with("TYPE")
        {
            return Protocol::Ftp;
        }

        if first_line.starts_with("SSH-") {
            return Protocol::Ssh;
        }

        if data.len() >= 2
            && (data.starts_with(&[0xff, 0xfb])
                || data.starts_with(&[0xff, 0xfe])
                || data.starts_with(&[0xff, 0xfd])
                || data.starts_with(&[0xff, 0xfc]))
        {
            return Protocol::Telnet;
        }

        if first_line.starts_with("NICK ")
            || first_line.starts_with("USER ")
            || first_line.starts_with("JOIN ")
            || first_line.starts_with("PRIVMSG ")
        {
            return Protocol::Irc;
        }

        if first_line.starts_with("CONNECT ") {
            let data_upper = String::from_utf8_lossy(data).to_uppercase();
            if data_upper.contains("PROXY") || data_upper.contains("HTTP/") {
                return Protocol::HttpProxy;
            }
        }

        if first_line.starts_with("\x05\x01") || first_line.starts_with("\x05\x02") {
            return Protocol::Socks5;
        }
        if first_line.starts_with("\x04\x01") || first_line.starts_with("\x04\x02") {
            return Protocol::Socks4;
        }

        if first_line.starts_with("GET /metrics") || first_line.starts_with("POST /api/v1/push") {
            return Protocol::Prometheus;
        }

        if data.starts_with(b"\x00\x14")
            || (data.len() >= 4 && u32::from_be_bytes([data[0], data[1], data[2], data[3]]) == 10)
        {
            if self.looks_like_mariadb(data) {
                return Protocol::MariaDb;
            }
            return Protocol::Mysql;
        }

        if data.starts_with(b"\x00\x00\x00\x08")
            || (data.len() >= 8 && &data[..8] == b"\x00\x00\x00\x08pgsrc\x00\x00")
        {
            return Protocol::Postgres;
        }

        if (first_line.starts_with("*")
            || first_line.starts_with("$")
            || first_line.starts_with(":"))
            && self.looks_like_redis(data)
        {
            return Protocol::Redis;
        }

        if first_line.starts_with("+OK") || first_line.starts_with("-ERR") {
            if self.looks_like_redis(data) {
                return Protocol::Redis;
            }
            return Protocol::Pop3;
        }

        if first_line.starts_with("get ")
            || first_line.starts_with("set ")
            || first_line.starts_with("delete ")
            || first_line.starts_with("stats")
            || first_line.starts_with("incr ")
            || first_line.starts_with("decr ")
            || first_line.starts_with("add ")
            || first_line.starts_with("gets ")
        {
            return Protocol::Memcached;
        }

        if data.len() >= 24
            && data[0] == 0x80
            && (data[1] == 0x80 || data[1] == 0x00)
            && self.looks_like_memcached_binary(data)
        {
            return Protocol::MemcachedBinary;
        }

        if data[0] == 0x30 && data.len() >= 6 && self.looks_like_ldap(data) {
            if data.len() >= 9 && data[9] == 0x02 {
                return Protocol::Ldaps;
            }
            return Protocol::Ldap;
        }

        if data.len() >= 18 && data[0] == 0x03 && data[1] == 0x00 {
            return Protocol::Rdp;
        }

        if first_line.starts_with("RFB ") {
            return Protocol::Vnc;
        }

        if data.starts_with(b"<?xml")
            || data.starts_with(b"<stream:stream")
            || first_line.starts_with("<stream")
        {
            return Protocol::Xmpp;
        }

        if data.len() >= 8 && &data[..4] == b"AMQP" {
            return Protocol::Amqp;
        }

        if data.len() >= 4 && data[0] == 0x10 && data[1] == 0x00 {
            return Protocol::Mqtt;
        }
        if first_line.starts_with("CONNECT ") && first_line.contains(":") {
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() >= 2 && parts[0] == "CONNECT" {
                return Protocol::Mqtt;
            }
        }

        if first_line.starts_with("CONNECT")
            || first_line.starts_with("SEND")
            || first_line.starts_with("SUBSCRIBE")
            || first_line.starts_with("UNSUBLBE")
        {
            return Protocol::Stomp;
        }

        if data.len() >= 4 {
            let msg_size = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
            if msg_size > 0 && msg_size < 100000000 && data.len() >= 4 + msg_size {
                if self.looks_like_mongodb(data) {
                    return Protocol::Mongodb;
                }
                if self.looks_like_cassandra(data) {
                    return Protocol::Cassandra;
                }
                if self.looks_like_cassandra_cql(data) {
                    return Protocol::CassandraCql;
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
            if looks_like_dns(data) {
                return Protocol::Dns;
            }
        }

        if data.len() >= 48 && data[0] == 0x1B {
            return Protocol::Ntp;
        }

        if data.len() >= 4 && data[0] == 0x01 && data[2] == 0x00 {
            let code = data[1];
            if (0x01..=0x0C).contains(&code) || code == 0x0E || code == 0x10 {
                return Protocol::Radius;
            }
        }

        if (first_line.starts_with("INVITE ")
            || first_line.starts_with("ACK ")
            || first_line.starts_with("BYE ")
            || first_line.starts_with("CANCEL ")
            || first_line.starts_with("OPTIONS ")
            || first_line.starts_with("REGISTER "))
            && upper_line.contains("SIP/")
        {
            return Protocol::Sip;
        }

        if (first_line.starts_with("GET /")
            || first_line.starts_with("POST /")
            || first_line.starts_with("PUT /")
            || first_line.starts_with("DELETE /"))
            && upper_line.contains("HTTP/")
        {
            let data_upper = String::from_utf8_lossy(data).to_uppercase();
            if data_upper.contains("ELASTICSEARCH") || data_upper.contains("X-ELASTICSEARCH") {
                return Protocol::Elasticsearch;
            }
            if data_upper.contains("SOLR") || data_upper.contains("X-SOLR") {
                return Protocol::Solr;
            }
        }

        let lower_data = String::from_utf8_lossy(data).to_lowercase();
        if lower_data.contains("minecraft") || lower_data.contains("yggdrasil") {
            return Protocol::Minecraft;
        }

        if lower_data.starts_with("d1:ad2:id20:") || lower_data.contains("bittorrent protocol") {
            return Protocol::BitTorrent;
        }

        Protocol::Unknown
    }

    fn looks_like_mesh_quic(&self, data: &[u8]) -> bool {
        if data.len() < 5 {
            return false;
        }

        let first_byte = data[0];
        let is_long_header = (first_byte & 0x80) != 0;

        if is_long_header && data.len() >= 5 {
            let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
            if version == 0 || (version & 0xFF000000) == 0xFF000000 {
                return true;
            }
            if version == 1 || version == 2 {
                return true;
            }
        }

        false
    }

    fn looks_like_redis(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        let first_char = data[0] as char;
        let line = extract_first_line(data);

        if first_char == '*' && line.len() > 1 && line[1..].parse::<u32>().is_ok() {
            return true;
        }
        if first_char == '$' && line.len() > 1 && line[1..].parse::<i32>().is_ok() {
            return true;
        }
        if first_char == ':'
            && line.len() > 1
            && line[1..].chars().all(|c| c.is_ascii_digit() || c == '-')
        {
            return true;
        }
        false
    }

    fn looks_like_mongodb(&self, data: &[u8]) -> bool {
        if data.len() < 16 {
            return false;
        }
        let msg_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if msg_len > 0 && msg_len < 48000000 && data.len() >= msg_len && data.len() >= 12 {
            let _request_id = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
            let _response_to = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
            let opcode = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
            if (1..=2010).contains(&opcode) {
                return true;
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
        if api_key <= 64 && data.len() >= 6 {
            let api_version = u16::from_be_bytes([data[6], data[7]]);
            if api_version <= 20 {
                let correlation_id = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                return correlation_id > 0 || api_key == 18;
            }
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

    fn looks_like_memcached_binary(&self, data: &[u8]) -> bool {
        if data.len() < 24 {
            return false;
        }

        let magic = data[0];
        if magic != 0x80 && magic != 0x81 {
            return false;
        }

        let opcode = data[1];
        let _key_len = u16::from_be_bytes([data[2], data[3]]);
        let body_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        let header_len = 24;
        if (data.len() as u32) < header_len + body_len {
            return false;
        }

        if opcode <= 0x1f || opcode == 0x30 || opcode == 0x31 {
            return true;
        }

        false
    }

    fn looks_like_mariadb(&self, data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }

        let packet_len = u32::from_be_bytes([0, data[0], data[1], data[2]]);
        if packet_len == 0 {
            return false;
        }

        if data.len() >= 5 {
            let _sequence = data[3];
            let payload_start = 4;

            if data.len() > payload_start {
                if data[payload_start] == 0xFF {
                    return true;
                }
                if data[payload_start] == 0xFE && data.len() >= payload_start + 4 {
                    let auth_plugin_len =
                        u16::from_be_bytes([data[data.len() - 2], data[data.len() - 1]]);
                    if auth_plugin_len > 0 && auth_plugin_len < 256 {
                        return true;
                    }
                }
            }
        }

        false
    }

    fn looks_like_cassandra(&self, data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }

        let version = data[0];
        if version != 0x01
            && version != 0x02
            && version != 0x03
            && version != 0x04
            && version != 0x05
            && version != 0x06
            && version != 0x07
            && version != 0x08
            && version != 0x81
            && version != 0x82
            && version != 0x83
            && version != 0x84
            && version != 0x85
            && version != 0x86
            && version != 0x87
            && version != 0x88
        {
            return false;
        }

        let flags = data[1];
        if flags > 0x3F {
            return false;
        }

        let _stream_id = data[2];
        let opcode = data[3];
        if opcode > 0x1F {
            return false;
        }

        true
    }

    fn looks_like_cassandra_cql(&self, data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }

        let version = data[0];
        if (!(1..=5).contains(&version)) && (!(0x81..=0x85).contains(&version)) {
            return false;
        }

        let flags = data[1];
        if flags > 0x07 {
            return false;
        }

        let opcode = data[3];
        if opcode == 0x01
            || opcode == 0x03
            || opcode == 0x05
            || opcode == 0x06
            || opcode == 0x07
            || opcode == 0x08
            || opcode == 0x09
            || opcode == 0x0A
            || opcode == 0x0B
            || opcode == 0x0C
            || opcode == 0x0D
            || opcode == 0x0E
            || opcode == 0x0F
            || opcode == 0x10
            || opcode == 0x11
            || opcode == 0x40
        {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smtp_detection() {
        let detector = ProtocolDetector::new();
        assert_eq!(
            detector.detect_from_bytes(b"EHLO example.com\r\n"),
            Protocol::Smtp
        );
        assert_eq!(
            detector.detect_from_bytes(b"MAIL FROM:<test@example.com>\r\n"),
            Protocol::Smtp
        );
    }

    #[test]
    fn test_http_detection() {
        let detector = ProtocolDetector::new();
        assert_eq!(
            detector.detect_from_bytes(b"GET / HTTP/1.1\r\n"),
            Protocol::Http
        );
        assert_eq!(
            detector.detect_from_bytes(b"POST /api HTTP/1.1\r\n"),
            Protocol::Http
        );
    }

    #[test]
    fn test_imap_detection() {
        let detector = ProtocolDetector::new();
        assert_eq!(
            detector.detect_from_bytes(b"A0001 LOGIN user pass\r\n"),
            Protocol::Imap
        );
        assert_eq!(
            detector.detect_from_bytes(b"A0002 SELECT INBOX\r\n"),
            Protocol::Imap
        );
    }

    #[test]
    fn test_redis_detection() {
        let detector = ProtocolDetector::new();
        assert_eq!(
            detector.detect_from_bytes(b"*1\r\n$4\r\nPING\r\n"),
            Protocol::Redis
        );
        assert_eq!(
            detector.detect_from_bytes(b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n"),
            Protocol::Redis
        );
        assert_eq!(
            detector.detect_from_bytes(b"$5\r\nhello\r\n"),
            Protocol::Redis
        );
        assert_eq!(detector.detect_from_bytes(b":1000\r\n"), Protocol::Redis);
    }

    #[test]
    fn test_memcached_detection() {
        let detector = ProtocolDetector::new();
        assert_eq!(
            detector.detect_from_bytes(b"get mykey\r\n"),
            Protocol::Memcached
        );
        assert_eq!(
            detector.detect_from_bytes(b"set mykey 0 3600 5\r\nhello\r\n"),
            Protocol::Memcached
        );
    }

    #[test]
    fn test_ssh_detection() {
        let detector = ProtocolDetector::new();
        assert_eq!(
            detector.detect_from_bytes(b"SSH-2.0-OpenSSH_8.2p1\r\n"),
            Protocol::Ssh
        );
    }

    #[test]
    fn test_vnc_detection() {
        let detector = ProtocolDetector::new();
        assert_eq!(detector.detect_from_bytes(b"RFB 003.008\n"), Protocol::Vnc);
    }

    #[test]
    fn test_amqp_detection() {
        let detector = ProtocolDetector::new();
        assert_eq!(
            detector.detect_from_bytes(b"AMQP\x00\x00\x09\x01"),
            Protocol::Amqp
        );
    }

    #[test]
    fn test_rtsp_detection() {
        use crate::protocol::detect_common::extract_first_line;
        let detector = ProtocolDetector::new();

        let data = b"OPTIONS rtsp://example.com RTSP/1.0\r\n";
        let first_line = extract_first_line(data);
        let upper_line = first_line.to_uppercase();
        eprintln!("first_line: {:?}", first_line);
        eprintln!("upper_line: {:?}", upper_line);
        eprintln!(
            "starts_with OPTIONS: {}",
            first_line.starts_with("OPTIONS ")
        );
        eprintln!(
            "upper_line.contains RTSP/: {}",
            upper_line.contains("RTSP/")
        );

        assert_eq!(
            detector.detect_from_bytes(b"OPTIONS rtsp://example.com RTSP/1.0\r\n"),
            Protocol::Rtsp
        );
        assert_eq!(
            detector.detect_from_bytes(b"DESCRIBE rtsp://example.com RTSP/1.0\r\n"),
            Protocol::Rtsp
        );
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
        assert_eq!(
            detector.detect_from_bytes(b"<?xml version='1.0'?><stream:stream>"),
            Protocol::Xmpp
        );
        assert_eq!(
            detector.detect_from_bytes(b"<stream:stream to='example.com'>"),
            Protocol::Xmpp
        );
    }

    #[test]
    fn test_http2_detection() {
        let detector = ProtocolDetector::new();
        assert_eq!(
            detector.detect_from_bytes(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
            Protocol::Http2
        );
    }

    #[test]
    fn test_grpc_detection() {
        let detector = ProtocolDetector::new();

        let h2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        assert_eq!(detector.detect_from_bytes(h2_preface), Protocol::Http2);

        let h2_preface_with_settings =
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00";
        assert_eq!(
            detector.detect_from_bytes(h2_preface_with_settings),
            Protocol::Http2
        );
    }
}
