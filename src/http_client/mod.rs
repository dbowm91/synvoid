// This is a thin compatibility shim re-exporting synvoid_http_client public API.
// Canonical code lives in crates/synvoid-http-client (split modules post-iter6):
// - tls.rs for TLS/webpki (UpstreamTlsConfig, build_tls_config, native/webpki/custom CA, HostnameSkippingVerifier)
// - pool.rs for caching (UpstreamClientKey, moka caches, build_upstream/create_upstream_*)
// - client.rs (aliases + create_*), unix.rs, request.rs, response.rs + erased_pool
// Phase 34 moves (transport stays policy-free):
// - site-config → TLS conversion lives in synvoid-upstream (`tls_adapter`)
// - WAF-scanning bodies live in synvoid-http (`streaming_waf_body`)
// Root retains quic_tunnel_dispatch (depends on root tunnel/quic + QUIC_TUNNEL_REGISTRY; not suitable for crate)
// and streaming_waf_body (pure re-export shim, now pointing at synvoid-http).
// No TLS implementation or typed-pool code remains in root.
//
// Phase 60: explicit re-export list (was `pub use synvoid_http_client::*`).
// The frozen compatibility surface above stays byte-for-byte stable
// (`architecture/eggfetch_0_2_compatibility_matrix.md` §4). The eggfetch
// lane below is the production path: *crate* consumers import it from
// `synvoid-http-client` directly, while *root* consumers (`src/admin`,
// `src/waf`) go through this entitled facade — the root dependency ledger
// (`architecture/root_dependency_ownership.md`) entitles only
// `http, http_client, tls` to consume `synvoid-http-client` directly.
// This module's disposition (`facade with local adapter`,
// `architecture/facade_disposition_matrix.md`) already retains root-owned
// adapters (precedent: `quic_tunnel_dispatch`); the operator lane handle
// is another such adapter, not transport implementation.

pub use synvoid_http_client::{
    create_http_client, create_http_client_with_config, create_simple_http_client,
    create_upstream_client, create_upstream_streaming_client, get, get_with_auth, get_with_timeout,
    head_with_auth, post_json, post_json_response, post_json_response_with_timeout,
    post_json_with_timeout, send_request, send_request_erased_streaming, send_request_streaming,
    send_request_streaming_generic, send_request_with_body_and_timeout,
    send_request_with_body_and_timeout_with_limit, send_request_with_body_headers_and_timeout,
    send_request_with_timeout, send_request_with_timeout_and_headers, BoxErasedBody, EmptyBody,
    ErasedBody, ErasedBodyImpl, ErasedConnectionPool, ErasedHttpClient, HttpClient, HttpResponse,
    PoolKey, StreamingHttpClient, UpstreamTlsConfig,
};
#[cfg(unix)]
pub use synvoid_http_client::{
    create_unix_http_client, is_unix_socket_url, send_unix_request_with_body,
    send_unix_request_with_timeout, UnixHttpClient,
};

pub mod quic_tunnel_dispatch;
pub mod streaming_waf_body;

pub use quic_tunnel_dispatch::{is_quictunnel_url, send_request_via_quic_tunnel};
pub use synvoid_http_client::eggfetch_transport::EggfetchUpstreamClient;

/// Phase 60: operator-plane eggfetch lane handle.
///
/// Alert webhooks and rule/IP/threat feeds fetch operator-configured URLs
/// (frequently plaintext internal endpoints). Mirrors the retired
/// `create_simple_http_client(30s)`: 5s connect, 100 idle/host, 30s pool
/// idle, plaintext-allowed default. `cached` shares one underlying pool
/// for this policy across all operator clients.
pub fn operator_lane_client() -> EggfetchUpstreamClient {
    let plaintext_default = synvoid_http_client::UpstreamTlsConfig {
        allow_plaintext: true,
        ..synvoid_http_client::UpstreamTlsConfig::default()
    };
    EggfetchUpstreamClient::cached(
        std::time::Duration::from_secs(5),
        100,
        std::time::Duration::from_secs(30),
        &plaintext_default,
    )
    .expect("eggfetch lane must build for default policy")
}
