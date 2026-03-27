pub mod client;
pub mod framing;
pub mod health;
pub mod ipc;
pub mod messages;
pub mod registry;
pub mod runtime;
pub mod server;
pub mod tls;
pub mod validation;

pub use client::{QuicClientSession, QuicTunnelClient};
pub use framing::{
    read_message, read_message_default, write_message, TunnelFramingError, TunnelMessageCodec,
};
pub use health::{
    ConnectionQuality, HealthCheckConfig as QuicHealthCheckConfig, QuicHealthMonitor,
};
pub use messages::{
    DatagramCapabilities, DatagramMessage, FragmentInfo, PortMapping, TunnelMessage,
};
pub use registry::{QuicTunnelProxy, QuicTunnelRegistry, TunnelSessionInfo, QUIC_TUNNEL_REGISTRY};
pub use runtime::{QuicConnection, QuicRuntime};
pub use server::{QuicTunnelServer, QuicTunnelSession, TunnelProxyRequest};
pub use tls::{generate_client_cert, generate_self_signed_cert, QuicTlsConfig, QuicTlsError};
pub use validation::{
    is_valid_token_format, secure_token_compare, validate_client_id, validate_identifier,
    validate_max_message_size, validate_peer_id, validate_port, JitteredBackoff, ValidationError,
    DEFAULT_MESSAGE_SIZE, MAX_MESSAGE_SIZE, MIN_MESSAGE_SIZE,
};
