//! HTTP/3 request handler stub.
//!
//! Note: The actual HTTP/3 request handling is implemented in `Http3Server::handle_request()`
//! in `src/http3/server.rs`. This module provides placeholder types for potential future
//! direct HTTP/3 handling scenarios.
//!
//! ## Current Implementation
//!
//! HTTP/3 requests are currently handled via `src/http3/server.rs` which implements the full
//! request pipeline including WAF checks, routing, and response handling.

use std::sync::Arc;

use crate::router::Router;
use crate::waf::WafCore;

pub struct Http3Handler;

impl Http3Handler {
    pub async fn handle(
        _router: Arc<Router>,
        _waf: Arc<WafCore>,
        _client_addr: std::net::SocketAddr,
    ) -> Self {
        Self
    }
}

/// HTTP/3 request handler stub.
///
/// This function is a placeholder. Actual HTTP/3 request handling is implemented
/// in `Http3Server::handle_request()` in `src/http3/server.rs`.
pub async fn handle_h3_request(
    _router: Arc<Router>,
    _waf: Arc<WafCore>,
    _client_addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::warn!("HTTP/3 requests should be handled via Http3Server::handle_request() in src/http3/server.rs");
    Ok(())
}
