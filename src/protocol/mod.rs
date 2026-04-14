pub mod detect_common;
pub mod grpc;
pub mod trait_def;
pub mod types;
pub mod websocket;

pub use detect_common::{extract_first_line, looks_like_dns, ProtocolDetectionResult};
pub use trait_def::ProtocolHandler;
pub use types::{ProtocolMetrics, ProtocolRequest, ProtocolResponse, ProtocolType};

pub fn register_protocol_types() {
    tracing::debug!("Registering protocol handlers: gRPC, WebSocket");
}
