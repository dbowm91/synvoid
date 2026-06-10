//! HTTP client abstraction for upstream proxy connections.
//!
//! Provides TLS-configurable HTTP/1.1 and HTTP/2 clients using hyper,
//! with support for connection pooling, timeouts, and per-site TLS settings.
//!
//! This crate is split into focused modules while preserving 100% source-compatible
//! public API via re-exports from lib.rs.

mod client;
mod erased_pool;
mod pool;
mod request;
mod response;
mod streaming_waf_body;
mod tls;
mod unix;

// Re-export erased and streaming items unchanged.
pub use erased_pool::{
    ErasedBody, ErasedBodyImpl, ErasedConnectionPool, ErasedHttpClient, PoolKey,
};
pub use streaming_waf_body::{StreamingWafBody, StreamingWafDecision, StreamingWafScanner};

// Client type aliases and entry points (client.rs owns the impls + EmptyBody).
pub use client::{
    create_http_client, create_http_client_with_config, create_simple_http_client,
    create_unix_http_client, create_upstream_client, create_upstream_streaming_client,
    is_quictunnel_url, EmptyBody, HttpClient, StreamingHttpClient, UnixHttpClient,
};

// BoxErasedBody is re-exported directly from its owning module (erased_pool) for public API.
// (client.rs uses it privately to define StreamingHttpClient type alias.)
pub use erased_pool::BoxErasedBody;

// TLS config (public surface only).
pub use tls::{upstream_tls_from_site_config, UpstreamTlsConfig};

// Unix helpers (public surface).
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
