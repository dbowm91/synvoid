use async_trait::async_trait;

/// Trait for tunnel connection establishment.
/// The root crate implements this with QuicRuntime.
#[async_trait]
pub trait TunnelConnector: Send + Sync + 'static {
    async fn open_tunnel_stream_to_peer(
        &self,
        peer: &str,
        identifier: &str,
    ) -> Result<(quinn::SendStream, quinn::RecvStream), Box<dyn std::error::Error + Send + Sync>>;
}

/// No-op implementation that always fails (used when QUIC tunnel is not configured).
pub struct NoopTunnelConnector;

#[async_trait]
impl TunnelConnector for NoopTunnelConnector {
    async fn open_tunnel_stream_to_peer(
        &self,
        _peer: &str,
        _identifier: &str,
    ) -> Result<(quinn::SendStream, quinn::RecvStream), Box<dyn std::error::Error + Send + Sync>>
    {
        Err("QUIC tunnel not configured".into())
    }
}
