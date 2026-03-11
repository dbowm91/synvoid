pub mod messages;
pub mod runtime;
pub mod server;
pub mod client;
pub mod tls;
pub mod registry;
pub mod health;
pub mod ipc;
pub mod framing;
pub mod validation;

pub use messages::{TunnelMessage, PortMapping, DatagramMessage, DatagramCapabilities, FragmentInfo};
pub use runtime::{QuicRuntime, QuicConnection};
pub use server::{QuicTunnelServer, QuicTunnelSession, TunnelProxyRequest};
pub use client::{QuicTunnelClient, QuicClientSession};
pub use tls::{QuicTlsConfig, QuicTlsError, generate_self_signed_cert, generate_client_cert};
pub use registry::{QuicTunnelRegistry, TunnelSessionInfo, QUIC_TUNNEL_REGISTRY, QuicTunnelProxy};
pub use health::{QuicHealthMonitor, HealthCheckConfig as QuicHealthCheckConfig, ConnectionQuality};
pub use framing::{TunnelMessageCodec, TunnelFramingError, read_message, write_message, read_message_default};
pub use validation::{
    validate_identifier, validate_client_id, validate_peer_id, 
    validate_port, validate_max_message_size, JitteredBackoff, ValidationError,
    MIN_MESSAGE_SIZE, MAX_MESSAGE_SIZE, DEFAULT_MESSAGE_SIZE,
    secure_token_compare, is_valid_token_format,
};
