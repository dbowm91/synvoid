pub mod listener;
pub mod protocol;
pub mod filter;

pub use listener::{TcpListenerPool, TcpListenerConfig};
pub use protocol::{ProtocolDetector, Protocol, ProtocolResult};
pub use filter::{ProtocolFilter, FilterAction, FilterConfig};

use std::net::SocketAddr;
use tokio::net::TcpStream;

pub use crate::listener::ConnectionContext;

#[allow(dead_code)]
pub struct TcpProxy {
    config: TcpProxyConfig,
    protocol_detector: ProtocolDetector,
    protocol_filter: ProtocolFilter,
}

#[derive(Clone)]
pub struct TcpProxyConfig {
    pub max_response_size: usize,
    pub connection_timeout_secs: u64,
    pub read_timeout_secs: u64,
}

impl Default for TcpProxyConfig {
    fn default() -> Self {
        Self {
            max_response_size: 10_000_000,
            connection_timeout_secs: 5,
            read_timeout_secs: 30,
        }
    }
}

impl TcpProxy {
    pub fn new(config: TcpProxyConfig, filter_config: FilterConfig) -> Self {
        Self {
            config,
            protocol_detector: ProtocolDetector::new(),
            protocol_filter: ProtocolFilter::new(filter_config),
        }
    }

    pub async fn handle_connection(
        &self,
        client_addr: SocketAddr,
        mut upstream_stream: TcpStream,
        expected_protocol: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let detection_result = self.protocol_detector.detect(&mut upstream_stream).await?;

        let filter_action = self.protocol_filter.check(
            expected_protocol,
            &detection_result.protocol,
        );

        match filter_action {
            FilterAction::Drop => {
                tracing::info!(
                    "Protocol mismatch: expected {} but got {} from {}",
                    expected_protocol,
                    detection_result.protocol.as_str(),
                    client_addr
                );
                metrics::counter!("maluwaf.tcp.protocol_mismatch").increment(1);
                return Ok(());
            }
            FilterAction::Stall => {
                tracing::info!(
                    "Protocol mismatch: expected {} but got {} from {} - stalling",
                    expected_protocol,
                    detection_result.protocol.as_str(),
                    client_addr
                );
                metrics::counter!("maluwaf.tcp.protocol_stalled").increment(1);
                return Ok(());
            }
            FilterAction::Allow => {}
        }

        Ok(())
    }
}
