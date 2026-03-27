use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ProtocolType {
    Http,
    Https,
    WebSocket,
    Wss,
    Grpc,
    GrpcTls,
    Tcp,
    Udp,
    #[default]
    Unknown,
}

impl ProtocolType {
    pub fn is_secure(&self) -> bool {
        matches!(self, Self::Https | Self::Wss | Self::GrpcTls)
    }

    pub fn is_websocket(&self) -> bool {
        matches!(self, Self::WebSocket | Self::Wss)
    }

    pub fn is_grpc(&self) -> bool {
        matches!(self, Self::Grpc | Self::GrpcTls)
    }

    pub fn family(&self) -> ProtocolFamily {
        match self {
            Self::Http | Self::Https => ProtocolFamily::Http,
            Self::WebSocket | Self::Wss => ProtocolFamily::WebSocket,
            Self::Grpc | Self::GrpcTls => ProtocolFamily::Grpc,
            Self::Tcp => ProtocolFamily::Tcp,
            Self::Udp => ProtocolFamily::Udp,
            Self::Unknown => ProtocolFamily::Http,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolRequest {
    pub client_ip: SocketAddr,
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub protocol: ProtocolType,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub trailers: HashMap<String, String>,
}

impl ProtocolResponse {
    pub fn new(status_code: u16) -> Self {
        Self {
            status_code,
            headers: HashMap::new(),
            body: Vec::new(),
            trailers: HashMap::new(),
        }
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtocolMetrics {
    pub requests_total: u64,
    pub requests_blocked: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub avg_request_size: u64,
    pub avg_response_size: u64,
}

impl ProtocolMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_request(&mut self, request_size: u64, blocked: bool) {
        self.requests_total += 1;
        if blocked {
            self.requests_blocked += 1;
        }
        self.bytes_in += request_size;
    }

    pub fn record_response(&mut self, response_size: u64) {
        self.bytes_out += response_size;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ProtocolFamily {
    #[default]
    Http,
    WebSocket,
    Grpc,
    Tcp,
    Udp,
}
