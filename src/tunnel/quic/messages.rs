use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const MAX_DATAGRAM_PAYLOAD: usize = 1200;

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        #[serde(default)]
        access_level: Option<String>,
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
        #[serde(default)]
        tls_passthrough: bool,
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
    UdpData {
        identifier: String,
        data: Vec<u8>,
    },
    UdpClose {
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
    pub fn encode(&self) -> std::io::Result<Vec<u8>> {
        crate::serialization::serialize_bincode(self)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        crate::serialization::deserialize_bincode(data)
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

    pub async fn write_data_chunk_zero_copy<W: tokio::io::AsyncWrite + Unpin>(
        writer: &mut W,
        identifier: &str,
        sequence: u64,
        data: &[u8],
        fin: bool,
    ) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        
        let header = DataChunkHeader {
            identifier: identifier.to_string(),
            sequence,
            data_len: data.len() as u32,
            fin,
        };
        let header_bytes = crate::serialization::serialize(&header)?;
        
        let msg_type: u8 = 100;
        let total_len = 1 + header_bytes.len() + data.len();
        writer.write_all(&(total_len as u32).to_be_bytes()).await?;
        writer.write_all(&[msg_type]).await?;
        writer.write_all(&header_bytes).await?;
        writer.write_all(data).await?;
        Ok(())
    }

    pub fn decode_data_chunk_zero_copy(data: &[u8]) -> Option<(String, u64, &[u8], bool)> {
        if data.is_empty() || data[0] != 100 {
            return None;
        }
        let header: DataChunkHeader = crate::serialization::deserialize(&data[1..]).ok()?;
        let header_size = crate::serialization::serialized_size(&header).ok()? as usize;
        let data_start = 1 + header_size;
        if data.len() < data_start + header.data_len as usize {
            return None;
        }
        let chunk_data = &data[data_start..data_start + header.data_len as usize];
        Some((header.identifier, header.sequence, chunk_data, header.fin))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DataChunkHeader {
    identifier: String,
    sequence: u64,
    data_len: u32,
    fin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatagramMessage {
    pub identifier: String,
    pub sequence: u64,
    pub data: Vec<u8>,
    pub port: u16,
    pub source_addr: String,
    pub return_addr: Option<String>,
    pub fragment_info: Option<FragmentInfo>,
    pub hop_count: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentInfo {
    pub fragment_id: u32,
    pub fragment_index: u16,
    pub fragment_total: u16,
    pub is_last: bool,
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
            return_addr: None,
            fragment_info: None,
            hop_count: 0,
        }
    }

    pub fn with_return_addr(mut self, return_addr: String) -> Self {
        self.return_addr = Some(return_addr);
        self
    }

    pub fn with_fragment(mut self, fragment_info: FragmentInfo) -> Self {
        self.fragment_info = Some(fragment_info);
        self
    }

    pub fn with_hop_count(mut self, hop_count: u8) -> Self {
        self.hop_count = hop_count;
        self
    }

    pub fn encode(&self) -> std::io::Result<Vec<u8>> {
        crate::serialization::serialize_bincode(self)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        crate::serialization::deserialize_bincode(data)
            .map_err(|e| tracing::trace!("Failed to decode datagram: {}", e))
            .ok()
    }

    pub fn max_payload_size() -> usize {
        MAX_DATAGRAM_PAYLOAD
    }

    pub fn encoded_size(&self) -> usize {
        crate::serialization::serialized_size(self).unwrap_or(0) as usize
    }

    pub fn is_fragmented(&self) -> bool {
        self.fragment_info.is_some()
    }

    pub fn is_first_fragment(&self) -> bool {
        self.fragment_info.as_ref().map_or(false, |f| f.fragment_index == 0)
    }

    pub fn estimated_header_size() -> usize {
        128
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
        )
        .with_return_addr("10.0.0.1:53".to_string())
        .with_hop_count(1);

        let encoded = msg.encode().unwrap();
        let decoded = DatagramMessage::decode(&encoded).unwrap();

        assert_eq!(decoded.identifier, "udp-53");
        assert_eq!(decoded.sequence, 1);
        assert_eq!(decoded.data, vec![1, 2, 3, 4, 5]);
        assert_eq!(decoded.port, 53);
        assert_eq!(decoded.source_addr, "192.168.1.1:12345");
        assert_eq!(decoded.return_addr, Some("10.0.0.1:53".to_string()));
        assert_eq!(decoded.hop_count, 1);
        assert!(!decoded.is_fragmented());
    }

    #[test]
    fn test_datagram_message_fragmented() {
        let fragment = FragmentInfo {
            fragment_id: 12345,
            fragment_index: 0,
            fragment_total: 3,
            is_last: false,
        };
        
        let msg = DatagramMessage::new(
            "udp-53".to_string(),
            1,
            vec![1, 2, 3, 4, 5],
            53,
            "192.168.1.1:12345".to_string(),
        )
        .with_fragment(fragment.clone());

        assert!(msg.is_fragmented());
        assert!(msg.is_first_fragment());
        
        let encoded = msg.encode().unwrap();
        let decoded = DatagramMessage::decode(&encoded).unwrap();
        
        assert!(decoded.is_fragmented());
        let frag = decoded.fragment_info.unwrap();
        assert_eq!(frag.fragment_id, 12345);
        assert_eq!(frag.fragment_index, 0);
        assert_eq!(frag.fragment_total, 3);
        assert!(!frag.is_last);
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
