use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const MAX_DATAGRAM_PAYLOAD: usize = 1200;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum TunnelMessage {
    Hello {
        client_id: String,
        auth_token: String,
        mappings: HashMap<String, PortMapping>,
        supports_datagrams: bool,
    },
    HelloAck {
        server_session_id: String,
        server_mappings: HashMap<String, PortMapping>,
        supports_datagrams: bool,
        max_datagram_size: usize,
    },
    AuthFailure {
        reason: String,
    },
    KeepAlive,
    KeepAliveAck,
    PortOpen {
        identifier: String,
        port: u16,
        protocol: String,
    },
    PortClose {
        identifier: String,
    },
    PortData {
        identifier: String,
    },
    RequestProxy {
        identifier: String,
        target_host: String,
        target_port: u16,
    },
    ProxyResponse {
        identifier: String,
        success: bool,
        message: Option<String>,
    },
    PeerHello {
        peer_id: String,
        auth_token: String,
        supports_datagrams: bool,
    },
    PeerHelloAck {
        session_id: String,
        supports_datagrams: bool,
        max_datagram_size: usize,
    },
    Error {
        code: u16,
        message: String,
    },
    DataChunk {
        identifier: String,
        sequence: u64,
        data: Vec<u8>,
        fin: bool,
    },
    DataAck {
        identifier: String,
        sequence: u64,
    },
    StreamOpen {
        identifier: String,
        port: u16,
        protocol: String,
    },
    StreamOpenAck {
        identifier: String,
        success: bool,
        message: Option<String>,
    },
    StreamClose {
        identifier: String,
    },
    UdpTunnelOpen {
        identifier: String,
        port: u16,
    },
    UdpTunnelOpenAck {
        identifier: String,
        success: bool,
        message: Option<String>,
    },
    UdpTunnelClose {
        identifier: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub port: u16,
    pub protocol: String,
    pub upstream_host: Option<String>,
    pub upstream_port: Option<u16>,
}

impl PortMapping {
    pub fn new(port: u16, protocol: &str) -> Self {
        Self {
            port,
            protocol: protocol.to_string(),
            upstream_host: None,
            upstream_port: None,
        }
    }

    pub fn with_upstream(mut self, host: &str, port: u16) -> Self {
        self.upstream_host = Some(host.to_string());
        self.upstream_port = Some(port);
        self
    }
}

impl TunnelMessage {
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data)
            .map_err(|e| tracing::warn!("Failed to decode message: {}", e))
            .ok()
    }

    pub fn encode_with_length(&self) -> Vec<u8> {
        let encoded = self.encode().unwrap_or_else(|e| {
            tracing::error!("Failed to encode message: {}", e);
            Vec::new()
        });
        let len = (encoded.len() as u32).to_be_bytes().to_vec();
        len.into_iter().chain(encoded.into_iter()).collect()
    }

    pub fn decode_with_length(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + len {
            return None;
        }
        let msg = Self::decode(&data[4..4 + len])?;
        Some((msg, 4 + len))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatagramMessage {
    pub identifier: String,
    pub sequence: u64,
    pub data: Vec<u8>,
    pub port: u16,
    pub source_addr: String,
}

impl DatagramMessage {
    pub fn new(
        identifier: String,
        sequence: u64,
        data: Vec<u8>,
        port: u16,
        source_addr: String,
    ) -> Self {
        Self {
            identifier,
            sequence,
            data,
            port,
            source_addr,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data)
            .map_err(|e| tracing::trace!("Failed to decode datagram: {}", e))
            .ok()
    }

    pub fn max_payload_size() -> usize {
        MAX_DATAGRAM_PAYLOAD
    }

    pub fn encoded_size(&self) -> usize {
        bincode::serialized_size(self).unwrap_or(0) as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramCapabilities {
    pub supported: bool,
    pub max_size: usize,
}

impl Default for DatagramCapabilities {
    fn default() -> Self {
        Self {
            supported: false,
            max_size: 0,
        }
    }
}

impl DatagramCapabilities {
    pub fn new(supported: bool, max_size: usize) -> Self {
        Self {
            supported,
            max_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_message() {
        let msg = TunnelMessage::Hello {
            client_id: "home-server".to_string(),
            auth_token: "secret".to_string(),
            mappings: HashMap::from([
                ("http".to_string(), PortMapping::new(80, "tcp")),
                ("https".to_string(), PortMapping::new(443, "tcp")),
            ]),
            supports_datagrams: true,
        };

        let encoded = msg.encode().unwrap();
        let decoded = TunnelMessage::decode(&encoded).unwrap();

        match decoded {
            TunnelMessage::Hello {
                client_id,
                auth_token,
                mappings,
                supports_datagrams,
            } => {
                assert_eq!(client_id, "home-server");
                assert_eq!(auth_token, "secret");
                assert_eq!(mappings.len(), 2);
                assert!(supports_datagrams);
            }
            _ => panic!("Expected Hello message"),
        }
    }

    #[test]
    fn test_encode_with_length() {
        let msg = TunnelMessage::KeepAlive;
        let encoded = msg.encode_with_length();

        let (decoded, consumed) = TunnelMessage::decode_with_length(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());

        match decoded {
            TunnelMessage::KeepAlive => {}
            _ => panic!("Expected KeepAlive"),
        }
    }

    #[test]
    fn test_datagram_message() {
        let msg = DatagramMessage::new(
            "udp-53".to_string(),
            1,
            vec![1, 2, 3, 4, 5],
            53,
            "192.168.1.1:12345".to_string(),
        );

        let encoded = msg.encode().unwrap();
        let decoded = DatagramMessage::decode(&encoded).unwrap();

        assert_eq!(decoded.identifier, "udp-53");
        assert_eq!(decoded.sequence, 1);
        assert_eq!(decoded.data, vec![1, 2, 3, 4, 5]);
        assert_eq!(decoded.port, 53);
        assert_eq!(decoded.source_addr, "192.168.1.1:12345");
    }

    #[test]
    fn test_udp_tunnel_message() {
        let msg = TunnelMessage::UdpTunnelOpen {
            identifier: "dns-udp".to_string(),
            port: 53,
        };
        let encoded = msg.encode().unwrap();
        let decoded = TunnelMessage::decode(&encoded).unwrap();

        match decoded {
            TunnelMessage::UdpTunnelOpen { identifier, port } => {
                assert_eq!(identifier, "dns-udp");
                assert_eq!(port, 53);
            }
            _ => panic!("Expected UdpTunnelOpen"),
        }
    }
}
