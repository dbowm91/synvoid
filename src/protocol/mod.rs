pub mod detect_common;
pub mod grpc;
pub mod trait_def;
pub mod types;
pub mod websocket;

pub use detect_common::{extract_first_line, looks_like_dns, ProtocolDetectionResult};
pub use trait_def::{BoxedHandler, ProtocolHandler};
pub use types::{ProtocolMetrics, ProtocolRequest, ProtocolResponse, ProtocolType};

use self::grpc::GrpcHandler;
use self::websocket::WebSocketHandler;

pub fn create_handler(protocol: &ProtocolType) -> Option<BoxedHandler> {
    match protocol {
        ProtocolType::Grpc | ProtocolType::GrpcTls => Some(Box::new(GrpcHandler::new())),
        ProtocolType::WebSocket | ProtocolType::Wss => Some(Box::new(WebSocketHandler::new())),
        _ => None,
    }
}

pub fn register_protocol_types() {
    tracing::debug!("Registering protocol handlers: gRPC, WebSocket");
}
