#![allow(unused_variables, dead_code)]

use super::trait_def::{ProtocolError, ProtocolHandler, WafAction};
use super::types::{ProtocolMetrics, ProtocolRequest, ProtocolResponse, ProtocolType};
use crate::upstream::pool::{Backend, UpstreamPool};
use crate::waf::WafCore;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

const GRPC_FRAME_HEADER_SIZE: usize = 5;
const GRPC_COMPRESSION_MASK: u8 = 0x01;
const GRPC_MESSAGE_TYPE_MASK: u8 = 0x08;
const GRPC_FLAGS_MASK: u8 = 0x1f;

pub struct GrpcHandler {
    waf: Option<Arc<WafCore>>,
    upstream_pool: Option<Arc<UpstreamPool>>,
    metrics: Arc<GrpcMetrics>,
    max_message_size: usize,
    enable_request_validation: bool,
}

#[derive(Default)]
struct GrpcMetrics {
    requests_total: AtomicU64,
    requests_blocked: AtomicU64,
    stream_messages: AtomicU64,
    invalid_frames: AtomicU64,
}

impl Default for GrpcHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl GrpcHandler {
    pub fn new() -> Self {
        tracing::debug!("Initializing gRPC protocol handler");
        Self {
            waf: None,
            upstream_pool: None,
            metrics: Arc::new(GrpcMetrics::default()),
            max_message_size: 4 * 1024 * 1024,
            enable_request_validation: true,
        }
    }

    pub fn with_max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    fn detect_grpc_frame(data: &[u8]) -> bool {
        if data.len() < GRPC_FRAME_HEADER_SIZE {
            return false;
        }

        let length = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        if length > 8 * 1024 * 1024 {
            return false;
        }

        true
    }

    fn detect_h2_preface(data: &[u8]) -> bool {
        data.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    }

    fn parse_grpc_method_path(data: &[u8]) -> Option<String> {
        if data.len() < GRPC_FRAME_HEADER_SIZE {
            return None;
        }

        let length = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        if data.len() < GRPC_FRAME_HEADER_SIZE + length {
            return None;
        }

        let payload = &data[GRPC_FRAME_HEADER_SIZE..GRPC_FRAME_HEADER_SIZE + length];

        if payload.len() > 1 && payload[0] == 0x00 {
            if let Ok(text) = std::str::from_utf8(&payload[1..]) {
                return Some(text.to_string());
            }
        }

        None
    }

    fn extract_grpc_metadata(headers: &[u8]) -> HashMap<String, String> {
        let mut metadata = HashMap::new();

        let mut pos = 0;
        while pos + GRPC_FRAME_HEADER_SIZE < headers.len() {
            let length = u32::from_be_bytes([
                headers[pos + 1],
                headers[pos + 2],
                headers[pos + 3],
                headers[pos + 4],
            ]) as usize;

            if pos + GRPC_FRAME_HEADER_SIZE + length > headers.len() {
                break;
            }

            let key_data =
                &headers[GRPC_FRAME_HEADER_SIZE..GRPC_FRAME_HEADER_SIZE + length.min(256)];
            if let Ok(key) = std::str::from_utf8(key_data) {
                if let Some((k, v)) = key.split_once(": ") {
                    metadata.insert(k.to_string(), v.to_string());
                }
            }

            pos += GRPC_FRAME_HEADER_SIZE + length;
        }

        metadata
    }
}

impl ProtocolHandler for GrpcHandler {
    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::Grpc
    }

    fn name(&self) -> &'static str {
        "gRPC"
    }

    fn detect(&self, data: &[u8]) -> bool {
        Self::detect_h2_preface(data) || Self::detect_grpc_frame(data)
    }

    fn parse_request(&self, data: &[u8]) -> Result<ProtocolRequest, ProtocolError> {
        if data.len() < GRPC_FRAME_HEADER_SIZE {
            return Err(ProtocolError::Framing(
                "Insufficient data for gRPC frame".to_string(),
            ));
        }

        let method_path = Self::parse_grpc_method_path(data);

        let (method, path) = if let Some(ref p) = method_path {
            if p.starts_with("/") {
                if let Some((_svc, _method)) = p.strip_prefix("/").and_then(|s| s.split_once("/")) {
                    ("POST".to_string(), p.clone())
                } else {
                    ("POST".to_string(), p.clone())
                }
            } else {
                ("POST".to_string(), p.clone())
            }
        } else {
            ("POST".to_string(), "/".to_string())
        };

        self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);

        Ok(ProtocolRequest {
            client_ip: SocketAddr::from(([0, 0, 0, 0], 0)),
            method,
            path,
            headers: HashMap::new(),
            body: data.to_vec(),
            protocol: ProtocolType::Grpc,
            metadata: HashMap::new(),
        })
    }

    fn build_request_for_upstream(&self, request: &ProtocolRequest) -> Vec<u8> {
        request.body.clone()
    }

    fn parse_response(&self, data: &[u8]) -> Result<ProtocolResponse, ProtocolError> {
        if data.len() < GRPC_FRAME_HEADER_SIZE {
            return Err(ProtocolError::Framing("Invalid gRPC response".to_string()));
        }

        let status = if data.len() > GRPC_FRAME_HEADER_SIZE {
            let payload = &data[GRPC_FRAME_HEADER_SIZE..];
            if payload.starts_with(&[0x00]) {
                if let Ok(text) = std::str::from_utf8(&payload[1..]) {
                    if let Ok(code) = text.parse::<u16>() {
                        code
                    } else {
                        0
                    }
                } else {
                    0
                }
            } else {
                0
            }
        } else {
            0
        };

        Ok(ProtocolResponse::new(status))
    }

    fn apply_waf(&self, request: &mut ProtocolRequest, _waf: &Arc<WafCore>) -> WafAction {
        tracing::debug!(protocol = "grpc", path = %request.path, "Applying WAF rules");

        if self.enable_request_validation {
            if request.path.contains("..") || request.path.contains("//") {
                tracing::warn!(protocol = "grpc", path = %request.path, "Path traversal attempt detected");
                self.metrics
                    .requests_blocked
                    .fetch_add(1, Ordering::Relaxed);
                return WafAction::Block;
            }

            if request.body.len() > self.max_message_size {
                tracing::warn!(
                    protocol = "grpc",
                    size = request.body.len(),
                    "gRPC message exceeds max size"
                );
                self.metrics
                    .requests_blocked
                    .fetch_add(1, Ordering::Relaxed);
                return WafAction::Block;
            }
        }

        WafAction::Allow
    }

    fn select_upstream(&self, _request: &ProtocolRequest, _pool: &UpstreamPool) -> Option<Backend> {
        if let Some(ref upstream_pool) = self.upstream_pool {
            upstream_pool.select_backend()
        } else {
            None
        }
    }

    fn metrics(&self) -> ProtocolMetrics {
        ProtocolMetrics {
            requests_total: self.metrics.requests_total.load(Ordering::Relaxed),
            requests_blocked: self.metrics.requests_blocked.load(Ordering::Relaxed),
            bytes_in: 0,
            bytes_out: 0,
            avg_request_size: 0,
            avg_response_size: 0,
        }
    }

    fn set_waf(&mut self, waf: Arc<WafCore>) {
        self.waf = Some(waf);
    }

    fn set_upstream_pool(&mut self, pool: Arc<UpstreamPool>) {
        self.upstream_pool = Some(pool);
    }
}
