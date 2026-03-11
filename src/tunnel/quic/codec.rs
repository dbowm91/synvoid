use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TunnelMessage {
    Hello {
        client_id: String,
        auth_token: String,
        mappings: HashMap<String, u16>,
    },
    HelloAck {
        server_session_id: String,
        server_mappings: HashMap<String, u16>,
    },
    AuthFailure {
        reason: String,
    },
    KeepAlive,
    KeepAliveAck,
    PortOpen {
        identifier: String,
    },
    PortClose {
        identifier: String,
    },
    PortData {
        identifier: String,
    },
    Error {
        code: u16,
        message: String,
    },
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
}

pub struct TunnelCodec;

impl TunnelCodec {
    pub async fn write_message<W: tokio::io::AsyncWriteExt + Unpin>(
        writer: &mut W,
        msg: &TunnelMessage,
    ) -> std::io::Result<()> {
        let data = msg.encode()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Encode error: {}", e)))?;
        let len = (data.len() as u32).to_be_bytes();
        writer.write_all(&len).await?;
        writer.write_all(&data).await?;
        Ok(())
    }

    pub async fn read_message<R: tokio::io::AsyncReadExt + Unpin>(
        reader: &mut R,
        max_size: usize,
    ) -> std::io::Result<Option<TunnelMessage>> {
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        };

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > max_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Message too large",
            ));
        }

        let mut data = vec![0u8; len];
        reader.read_exact(&mut data).await?;

        Ok(TunnelMessage::decode(&data))
    }
}
