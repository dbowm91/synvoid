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

pub async fn handle_h3_request(
    _router: Arc<Router>,
    _waf: Arc<WafCore>,
    _client_addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!("HTTP/3 request handling not fully implemented");
    Ok(())
}
