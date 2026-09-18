pub mod address;
pub mod health;
pub mod pool;
pub mod shared_state;
pub mod tls_adapter;
pub mod tunnel;

pub use address::{QuicTunnelStream, SocketErrorTracker, UpstreamAddress, UpstreamError};
pub use health::{HealthCheckConfig, HealthCheckMethod, HealthChecker};
pub use pool::{Backend, BackendProtocol, LoadBalanceAlgorithm, UpstreamMetrics, UpstreamPool};
pub use shared_state::{
    ConnectionTableLayout, RateLimitTableLayout, SharedConnectionTable, SharedRateLimitTable,
    CONNECTION_HEADER_LEN, CONNECTION_TABLE_MAGIC, CONNECTION_TABLE_VERSION, MAX_MAPPING_BYTES,
    MAX_RATELIMIT_SLOTS, MAX_TABLE_BACKENDS, MAX_TABLE_WORKERS, RATELIMIT_HEADER_LEN,
    RATELIMIT_TABLE_MAGIC, RATELIMIT_TABLE_VERSION,
};
pub use tls_adapter::upstream_tls_from_site_config;
pub use tunnel::{NoopTunnelConnector, TunnelConnector};
