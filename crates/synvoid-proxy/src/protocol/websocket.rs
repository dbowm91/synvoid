#![allow(unused_variables, dead_code)]

use super::trait_def::{ProtocolError, ProtocolHandler, WafAction, WafCoreBackend};
use super::types::{ProtocolMetrics, ProtocolRequest, ProtocolResponse, ProtocolType};
use synvoid_upstream::{Backend, UpstreamPool};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const WS_FRAME_HEADER_MIN: usize = 2;
const WS_FRAME_HEADER_MAX: usize = 14;

const WS_OPCODE_MASK: u8 = 0x0f;
const WS_FIN_MASK: u8 = 0x80;
const WS_MASK_MASK: u8 = 0x80;
const WS_PAYLOAD_LEN_MASK: u8 = 0x7f;

const WS_OPCODE_CONTINUATION: u8 = 0x0;
const WS_OPCODE_TEXT: u8 = 0x1;
const WS_OPCODE_BINARY: u8 = 0x2;
const WS_OPCODE_CLOSE: u8 = 0x8;
const WS_OPCODE_PING: u8 = 0x9;
const WS_OPCODE_PONG: u8 = 0xA;

pub struct WebSocketHandler {
    waf: Option<Arc<dyn WafCoreBackend>>,
    upstream_pool: Option<Arc<UpstreamPool>>,
    metrics: Arc<WsMetrics>,
    max_message_size: usize,
    enable_frame_validation: bool,
    enable_message_validation: bool,
    mask_required: bool,
}

#[derive(Default)]
struct WsMetrics {
    connections_opened: AtomicU64,
    connections_closed: AtomicU64,
    messages_sent: AtomicU64,
    messages_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    invalid_frames: AtomicU64,
    blocked_messages: AtomicU64,
}

impl Default for WebSocketHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl WebSocketHandler {
    pub fn new() -> Self {
        tracing::debug!("Initializing WebSocket protocol handler");
        Self {
            waf: None,
            upstream_pool: None,
            metrics: Arc::new(WsMetrics::default()),
            max_message_size: 16 * 1024 * 1024,
            enable_frame_validation: true,
            enable_message_validation: true,
            mask_required: false,
        }
    }

    pub fn with_max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    pub fn with_mask_required(mut self, required: bool) -> Self {
        self.mask_required = required;
        self
    }

    pub fn detect(data: &[u8]) -> bool {
        if data.len() < 3 {
            return false;
        }

        let first_line = Self::extract_first_line(data);

        if first_line.to_uppercase().contains("UPGRADE: WEBSOCKET")
            || first_line.to_uppercase().contains("SEC-WEBSOCKET-KEY")
            || first_line.starts_with("GET")
                && data
                    .windows(10)
                    .any(|w| w[0].eq_ignore_ascii_case(&b'U') && &w[1..9] == b"PGRADE".as_slice())
        {
            return true;
        }

        if Self::is_websocket_frame(data) {
            return true;
        }

        false
    }

    fn extract_first_line(data: &[u8]) -> String {
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

    fn is_websocket_frame(data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }

        let first_byte = data[0];
        let opcode = first_byte & WS_OPCODE_MASK;

        matches!(
            opcode,
            WS_OPCODE_CONTINUATION
                | WS_OPCODE_TEXT
                | WS_OPCODE_BINARY
                | WS_OPCODE_CLOSE
                | WS_OPCODE_PING
                | WS_OPCODE_PONG
        )
    }

    fn parse_frame(data: &[u8]) -> Option<WebSocketFrame> {
        if data.len() < WS_FRAME_HEADER_MIN {
            return None;
        }

        let first_byte = data[0];
        let second_byte = data[1];

        let fin = (first_byte & WS_FIN_MASK) != 0;
        let opcode = first_byte & WS_OPCODE_MASK;
        let masked = (second_byte & WS_MASK_MASK) != 0;
        let payload_len = (second_byte & WS_PAYLOAD_LEN_MASK) as usize;

        let mut header_size = 2;

        let actual_payload_len = if payload_len == 126 {
            if data.len() < 4 {
                return None;
            }
            header_size = 4;
            u16::from_be_bytes([data[2], data[3]]) as usize
        } else if payload_len == 127 {
            if data.len() < 10 {
                return None;
            }
            header_size = 10;
            usize::from_be_bytes([
                data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
            ])
        } else {
            payload_len
        };

        let mask_key = if masked {
            if data.len() < header_size + 4 {
                return None;
            }
            Some([
                data[header_size],
                data[header_size + 1],
                data[header_size + 2],
                data[header_size + 3],
            ])
        } else {
            None
        };

        let payload_start = header_size + if masked { 4 } else { 0 };

        if data.len() < payload_start + actual_payload_len {
            return None;
        }

        let mut payload = data[payload_start..payload_start + actual_payload_len].to_vec();

        if let Some(key) = mask_key {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= key[i % 4];
            }
        }

        Some(WebSocketFrame {
            fin,
            opcode,
            payload,
            masked,
        })
    }

    fn build_frame(opcode: u8, payload: &[u8], fin: bool) -> Vec<u8> {
        let header_size = if payload.len() < 126 {
            2
        } else if payload.len() < 65536 {
            4
        } else {
            10
        };
        let mut frame = Vec::with_capacity(header_size + payload.len());

        let first_byte = if fin { opcode | 0x80 } else { opcode };
        frame.push(first_byte);

        let payload_len = payload.len();
        if payload_len < 126 {
            frame.push(payload_len as u8);
        } else if payload_len < 65536 {
            frame.push(126);
            frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
        } else {
            frame.push(127);
            frame.extend_from_slice(&payload_len.to_be_bytes());
        }

        frame.extend_from_slice(payload);
        frame
    }

    fn validate_message(&self, frame: &WebSocketFrame) -> Option<WafAction> {
        if frame.payload.len() > self.max_message_size {
            tracing::warn!(
                protocol = "websocket",
                size = frame.payload.len(),
                max = self.max_message_size,
                "WebSocket message exceeds max size"
            );
            self.metrics
                .blocked_messages
                .fetch_add(1, Ordering::Relaxed);
            return Some(WafAction::Block);
        }

        if self.enable_message_validation {
            if let Ok(text) = std::str::from_utf8(&frame.payload) {
                if text.contains("<script") || text.contains("javascript:") {
                    tracing::warn!(
                        protocol = "websocket",
                        "XSS attempt detected in WebSocket message"
                    );
                    self.metrics
                        .blocked_messages
                        .fetch_add(1, Ordering::Relaxed);
                    return Some(WafAction::Block);
                }
            }
        }

        None
    }
}

#[derive(Debug, Clone)]
struct WebSocketFrame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
    masked: bool,
}

impl ProtocolHandler for WebSocketHandler {
    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::WebSocket
    }

    fn name(&self) -> &'static str {
        "WebSocket"
    }

    fn detect(&self, data: &[u8]) -> bool {
        Self::detect(data)
    }

    fn parse_request(&self, data: &[u8]) -> Result<ProtocolRequest, ProtocolError> {
        if Self::is_websocket_frame(data) {
            let frame = Self::parse_frame(data)
                .ok_or_else(|| ProtocolError::Framing("Invalid WebSocket frame".to_string()))?;

            self.metrics
                .messages_received
                .fetch_add(1, Ordering::Relaxed);
            self.metrics
                .bytes_received
                .fetch_add(data.len() as u64, Ordering::Relaxed);

            if frame.opcode == WS_OPCODE_CLOSE {
                return Err(ProtocolError::ConnectionClosed);
            }

            let _body_str = String::from_utf8_lossy(&frame.payload).to_string();

            return Ok(ProtocolRequest {
                client_ip: SocketAddr::from(([0, 0, 0, 0], 0)),
                method: match frame.opcode {
                    WS_OPCODE_TEXT => "TEXT".to_string(),
                    WS_OPCODE_BINARY => "BINARY".to_string(),
                    WS_OPCODE_PING => "PING".to_string(),
                    WS_OPCODE_PONG => "PONG".to_string(),
                    _ => "UNKNOWN".to_string(),
                },
                path: "/ws".to_string(),
                headers: HashMap::new(),
                body: frame.payload,
                protocol: ProtocolType::WebSocket,
                metadata: HashMap::new(),
            });
        }

        let first_line = Self::extract_first_line(data);

        if first_line.starts_with("GET") {
            self.metrics
                .connections_opened
                .fetch_add(1, Ordering::Relaxed);

            return Ok(ProtocolRequest {
                client_ip: SocketAddr::from(([0, 0, 0, 0], 0)),
                method: "GET".to_string(),
                path: "/ws".to_string(),
                headers: HashMap::new(),
                body: data.to_vec(),
                protocol: ProtocolType::WebSocket,
                metadata: HashMap::new(),
            });
        }

        Err(ProtocolError::Parse("Not a WebSocket request".to_string()))
    }

    fn build_request_for_upstream(&self, request: &ProtocolRequest) -> Vec<u8> {
        Self::build_frame(WS_OPCODE_TEXT, &request.body, true)
    }

    fn parse_response(&self, data: &[u8]) -> Result<ProtocolResponse, ProtocolError> {
        if Self::is_websocket_frame(data) {
            let frame = Self::parse_frame(data)
                .ok_or_else(|| ProtocolError::Framing("Invalid WebSocket frame".to_string()))?;

            self.metrics.messages_sent.fetch_add(1, Ordering::Relaxed);
            self.metrics
                .bytes_sent
                .fetch_add(data.len() as u64, Ordering::Relaxed);

            return Ok(ProtocolResponse::new(200).with_body(frame.payload));
        }

        Ok(ProtocolResponse::new(200).with_body(data.to_vec()))
    }

    fn apply_waf(
        &self,
        request: &mut ProtocolRequest,
        _waf: &Arc<dyn WafCoreBackend>,
    ) -> WafAction {
        tracing::debug!(protocol = "websocket", method = %request.method, "Applying WAF rules");

        if Self::is_websocket_frame(&request.body) {
            if let Some(frame) = Self::parse_frame(&request.body) {
                if let Some(action) = self.validate_message(&frame) {
                    return action;
                }
            }
        }

        WafAction::Allow
    }

    fn select_upstream(&self, _request: &ProtocolRequest, _pool: &UpstreamPool) -> Option<Backend> {
        if let Some(ref upstream_pool) = self.upstream_pool {
            upstream_pool.try_select_backend()
        } else {
            None
        }
    }

    fn metrics(&self) -> ProtocolMetrics {
        ProtocolMetrics {
            requests_total: self.metrics.connections_opened.load(Ordering::Relaxed),
            requests_blocked: self.metrics.blocked_messages.load(Ordering::Relaxed),
            bytes_in: self.metrics.bytes_received.load(Ordering::Relaxed),
            bytes_out: self.metrics.bytes_sent.load(Ordering::Relaxed),
            avg_request_size: 0,
            avg_response_size: 0,
        }
    }

    fn set_waf(&mut self, waf: Arc<dyn WafCoreBackend>) {
        self.waf = Some(waf);
    }

    fn set_upstream_pool(&mut self, pool: Arc<UpstreamPool>) {
        self.upstream_pool = Some(pool);
    }
}
