// This is a thin compatibility shim re-exporting synvoid_http_client public API.
// Canonical code lives in crates/synvoid-http-client (split modules post-iter6):
// - tls.rs for TLS/webpki (UpstreamTlsConfig, build_tls_config, native/webpki/custom CA, HostnameSkippingVerifier)
// - pool.rs for caching (UpstreamClientKey, moka caches, build_upstream/create_upstream_*)
// - client.rs (aliases + create_*), unix.rs, request.rs, response.rs + erased_pool + streaming_waf_body
// Root retains quic_tunnel_dispatch (depends on root tunnel/quic + QUIC_TUNNEL_REGISTRY; not suitable for crate)
// and streaming_waf_body (pure re-export shim).
// No TLS implementation or typed-pool code remains in root.

pub use synvoid_http_client::*;

pub mod quic_tunnel_dispatch;
pub mod streaming_waf_body;

pub use quic_tunnel_dispatch::{is_quictunnel_url, send_request_via_quic_tunnel};
