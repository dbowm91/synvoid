pub mod filter;
pub mod listener;
pub mod protocol;

pub use filter::{UdpFilterAction, UdpFilterConfig, UdpProtocolFilter};
pub use listener::{UdpListenerConfig, UdpListenerPool};
pub use protocol::{UdpProtocol, UdpProtocolDetector, UdpProtocolResult};

pub use crate::listener::ConnectionContext;

pub struct UdpProxy {
    protocol_detector: UdpProtocolDetector,
    protocol_filter: UdpProtocolFilter,
}

#[derive(Clone)]
pub struct UdpProxyConfig {
    pub max_packet_size: usize,
    pub response_timeout_secs: u64,
    pub buffer_size: usize,
}

impl Default for UdpProxyConfig {
    fn default() -> Self {
        Self {
            max_packet_size: 65535,
            response_timeout_secs: 5,
            buffer_size: 8192,
        }
    }
}

impl UdpProxy {
    pub fn new(_config: UdpProxyConfig, filter_config: UdpFilterConfig) -> Self {
        Self {
            protocol_detector: UdpProtocolDetector::new(),
            protocol_filter: UdpProtocolFilter::new(filter_config),
        }
    }

    pub fn check_packet(&self, data: &[u8], expected_protocol: &str) -> UdpFilterAction {
        let detection_result = self.protocol_detector.detect_from_bytes(data);
        self.protocol_filter
            .check(expected_protocol, &detection_result.protocol)
    }
}
