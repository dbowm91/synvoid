pub use synvoid_http_client::*;

pub mod quic_tunnel_dispatch;
pub mod streaming_waf_body;

pub use quic_tunnel_dispatch::{is_quictunnel_url, send_request_via_quic_tunnel};
