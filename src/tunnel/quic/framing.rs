
use quinn::{SendStream, RecvStream};

use super::messages::TunnelMessage;
use crate::buffer::BufferPool;

const DEFAULT_MAX_MESSAGE_SIZE: usize = 1024 * 1024;

pub struct TunnelMessageCodec {
    max_message_size: usize,
}

impl TunnelMessageCodec {
    pub fn new() -> Self {
        Self {
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
        }
    }

    pub fn with_max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    pub fn max_message_size(&self) -> usize {
        self.max_message_size
    }

    pub async fn read(
        &self,
        recv_stream: &mut RecvStream,
    ) -> Result<TunnelMessage, TunnelFramingError> {
        self.read_with_max(recv_stream, self.max_message_size).await
    }

    pub async fn read_with_max(
        &self,
        recv_stream: &mut RecvStream,
        max_size: usize,
    ) -> Result<TunnelMessage, TunnelFramingError> {
        let mut len_buf = [0u8; 4];
        recv_stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| TunnelFramingError::ReadLength(e.to_string()))?;

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > max_size {
            return Err(TunnelFramingError::MessageTooLarge(len, max_size));
        }

        let mut pooled = BufferPool::acquire(len);
        recv_stream
            .read_exact(pooled.as_mut_slice())
            .await
            .map_err(|e| TunnelFramingError::ReadMessage(e.to_string()))?;

        TunnelMessage::decode(pooled.as_slice()).ok_or(TunnelFramingError::Decode)
    }

    pub async fn write(
        &self,
        send_stream: &mut SendStream,
        msg: &TunnelMessage,
    ) -> Result<(), TunnelFramingError> {
        let data = msg
            .encode()
            .map_err(|e| TunnelFramingError::Encode(e.to_string()))?;

        let len = (data.len() as u32).to_be_bytes();
        send_stream
            .write_all(&len)
            .await
            .map_err(|e| TunnelFramingError::WriteLength(e.to_string()))?;

        send_stream
            .write_all(&data)
            .await
            .map_err(|e| TunnelFramingError::WriteMessage(e.to_string()))?;

        Ok(())
    }
}

impl Default for TunnelMessageCodec {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum TunnelFramingError {
    ReadLength(String),
    ReadMessage(String),
    WriteLength(String),
    WriteMessage(String),
    Encode(String),
    Decode,
    MessageTooLarge(usize, usize),
}

impl std::fmt::Display for TunnelFramingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadLength(e) => write!(f, "Failed to read message length: {}", e),
            Self::ReadMessage(e) => write!(f, "Failed to read message: {}", e),
            Self::WriteLength(e) => write!(f, "Failed to write message length: {}", e),
            Self::WriteMessage(e) => write!(f, "Failed to write message: {}", e),
            Self::Encode(e) => write!(f, "Failed to encode message: {}", e),
            Self::Decode => write!(f, "Failed to decode message"),
            Self::MessageTooLarge(actual, max) => {
                write!(f, "Message too large: {} bytes (max {})", actual, max)
            }
        }
    }
}

impl std::error::Error for TunnelFramingError {}

pub async fn read_message(
    recv_stream: &mut RecvStream,
    max_message_size: usize,
) -> Result<TunnelMessage, Box<dyn std::error::Error + Send + Sync>> {
    let codec = TunnelMessageCodec::new().with_max_message_size(max_message_size);
    codec.read(recv_stream).await.map_err(|e| e.into())
}

pub async fn write_message(
    send_stream: &mut SendStream,
    msg: &TunnelMessage,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let codec = TunnelMessageCodec::new();
    codec.write(send_stream, msg).await.map_err(|e| e.into())
}

pub async fn read_message_default(
    recv_stream: &mut RecvStream,
) -> Result<TunnelMessage, Box<dyn std::error::Error + Send + Sync>> {
    read_message(recv_stream, DEFAULT_MAX_MESSAGE_SIZE).await
}
