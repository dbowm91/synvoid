use std::time::Duration;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MeshTransportError {
    #[error("No seed nodes available")]
    NoSeedsAvailable,
    #[error("Transport not available")]
    NotAvailable,
    #[error("Peer not connected: {0}")]
    PeerNotConnected(String),
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Send failed: {0}")]
    SendFailed(String),
    #[error("Receive failed: {0}")]
    ReceiveFailed(String),
    #[error("Version mismatch: expected {expected}, got {got}")]
    VersionMismatch { expected: u8, got: u8 },
    #[error("Unexpected message type")]
    UnexpectedMessage,
    #[error("Peer error: {code} - {message}")]
    PeerError { code: u16, message: String },
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    #[error("No route to upstream: {0}")]
    NoRouteToUpstream(String),
    #[error("Service not allowed: {0}")]
    ServiceNotAllowed(String),
    #[error("Runtime not set")]
    RuntimeNotSet,
    #[error("Timeout")]
    Timeout,
    #[error("Rate limited - too many connection attempts")]
    RateLimited,
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    #[error("Not implemented for this transport")]
    NotImplemented,
    #[error("Lifecycle conflict: {0}")]
    LifecycleConflict(String),
    #[error("Startup failed: {0}")]
    StartupFailed(String),
    #[error("Shutdown timed out after {0:?}")]
    ShutdownTimeout(Duration),
    #[error("Already starting")]
    AlreadyStarting,
}

impl From<quinn::ConnectionError> for MeshTransportError {
    fn from(e: quinn::ConnectionError) -> Self {
        MeshTransportError::ConnectionFailed(e.to_string())
    }
}

impl From<prost::EncodeError> for MeshTransportError {
    fn from(e: prost::EncodeError) -> Self {
        MeshTransportError::SendFailed(e.to_string())
    }
}

impl From<tokio::io::Error> for MeshTransportError {
    fn from(e: tokio::io::Error) -> Self {
        MeshTransportError::SendFailed(e.to_string())
    }
}

impl From<quinn::WriteError> for MeshTransportError {
    fn from(e: quinn::WriteError) -> Self {
        MeshTransportError::SendFailed(e.to_string())
    }
}

impl From<quinn::ReadError> for MeshTransportError {
    fn from(e: quinn::ReadError) -> Self {
        MeshTransportError::ReceiveFailed(e.to_string())
    }
}

impl From<quinn::ReadExactError> for MeshTransportError {
    fn from(e: quinn::ReadExactError) -> Self {
        MeshTransportError::ReceiveFailed(e.to_string())
    }
}
