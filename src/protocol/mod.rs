pub mod trait_def;
pub mod grpc;
pub mod websocket;
pub mod types;

pub use trait_def::{ProtocolHandler, BoxedHandler};
pub use types::{ProtocolRequest, ProtocolResponse, ProtocolMetrics, ProtocolType};

use self::grpc::GrpcHandler;
use self::websocket::WebSocketHandler;
use std::sync::Arc;

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
