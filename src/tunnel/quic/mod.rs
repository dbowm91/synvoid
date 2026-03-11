pub mod messages;
pub mod runtime;
pub mod server;
pub mod client;
pub mod tls;
pub mod registry;
pub mod health;
pub mod ipc;

pub use messages::{TunnelMessage, PortMapping, DatagramMessage, DatagramCapabilities};
pub use runtime::{QuicRuntime, QuicConnection};
pub use server::{QuicTunnelServer, QuicTunnelSession, TunnelProxyRequest};
pub use client::{QuicTunnelClient, QuicClientSession};
pub use tls::{QuicTlsConfig, QuicTlsError, generate_self_signed_cert, generate_client_cert};
pub use registry::{QuicTunnelRegistry, TunnelSessionInfo, QUIC_TUNNEL_REGISTRY, QuicTunnelProxy};
pub use health::{QuicHealthMonitor, HealthCheckConfig as QuicHealthCheckConfig, ConnectionQuality};
