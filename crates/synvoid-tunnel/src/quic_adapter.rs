use async_trait::async_trait;
use synvoid_upstream::TunnelConnector;

pub struct QuicTunnelAdapter;

#[async_trait]
impl TunnelConnector for QuicTunnelAdapter {
    async fn open_tunnel_stream_to_peer(
        &self,
        peer: &str,
        identifier: &str,
    ) -> Result<(quinn::SendStream, quinn::RecvStream), Box<dyn std::error::Error + Send + Sync>>
    {
        let runtime = crate::QUIC_TUNNEL_REGISTRY
            .get_runtime()
            .await
            .ok_or("QUIC tunnel runtime not initialized")?;

        runtime.open_tunnel_stream_to_peer(peer, identifier).await
    }
}
