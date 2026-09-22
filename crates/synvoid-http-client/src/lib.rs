//! HTTP client abstraction for upstream proxy connections.
//!
//! Provides TLS-configurable HTTP/1.1 and HTTP/2 clients using hyper,
//! with support for connection pooling, timeouts, and per-site TLS settings.
//!
//! This crate is split into focused modules while preserving 100% source-compatible
//! public API via re-exports from lib.rs.
//!
//! Phase 34 boundary: this is the **generic transport core**. SynVoid policy
//! adapters live one layer up and are deliberately absent here:
//!
//! - site-config → TLS conversion: `synvoid_upstream::tls_adapter`
//! - WAF-scanning request bodies: `synvoid_http::streaming_waf_body`
//! - QUIC/tunnel dispatch: root `src/http_client/quic_tunnel_dispatch.rs`
//!
//! `is_quictunnel_url` remains only as a dependency-free scheme predicate so
//! existing dispatch call sites keep compiling; it performs no I/O and owns
//! no tunnel state.

mod client;
#[cfg(test)]
mod eggfetch_differential;
mod eggfetch_policy;
// Phase 60: crate-public internal lane for consumer migration. NOT
// re-exported here and NOT part of the root surface (`src/http_client/`
// uses explicit re-exports that exclude it); carries no stability promise.
pub mod eggfetch_transport;
mod erased_pool;
mod pool;
mod request;
mod response;
mod tls;
#[cfg(unix)]
mod unix;

// Re-export erased items unchanged.
pub use erased_pool::{
    ErasedBody, ErasedBodyImpl, ErasedConnectionPool, ErasedHttpClient, PoolKey,
};

// Client type aliases and entry points (client.rs owns the impls + EmptyBody).
pub use client::{
    create_http_client, create_http_client_with_config, create_simple_http_client,
    create_upstream_client, create_upstream_streaming_client, is_quictunnel_url, EmptyBody,
    HttpClient, StreamingHttpClient,
};
#[cfg(unix)]
pub use client::{create_unix_http_client, UnixHttpClient};

// BoxErasedBody is re-exported directly from its owning module (erased_pool) for public API.
// (client.rs uses it privately to define StreamingHttpClient type alias.)
pub use erased_pool::BoxErasedBody;

// TLS config (public surface only). Site-config conversion lives in
// `synvoid_upstream::tls_adapter` (Phase 34); the transport layer keeps
// only the neutral policy type.
pub use tls::UpstreamTlsConfig;

// Unix helpers (public surface).
#[cfg(unix)]
pub use unix::{is_unix_socket_url, send_unix_request_with_body, send_unix_request_with_timeout};

// Response wrapper.
pub use response::HttpResponse;

// Request helpers (all send_* and convenience wrappers).
pub use request::{
    get, get_with_auth, get_with_timeout, head_with_auth, post_json, post_json_response,
    post_json_response_with_timeout, post_json_with_timeout, send_request,
    send_request_erased_streaming, send_request_streaming, send_request_streaming_generic,
    send_request_with_body_and_timeout, send_request_with_body_and_timeout_with_limit,
    send_request_with_body_headers_and_timeout, send_request_with_timeout,
    send_request_with_timeout_and_headers,
};
