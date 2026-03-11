use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, BufMut, BytesMut};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixStream, UnixListener};

#[cfg(windows)]
use tokio::net::TcpListener;
#[cfg(windows)]
use tokio::net::TcpStream;

use metrics::{counter, gauge, histogram};

const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;
const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;
const MAX_CONCURRENT_STREAMS: u32 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamType {
    Tcp = 1,
    Udp = 2,
    Control = 0,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiplexFrame {
    pub stream_id: u64,
    pub stream_type: StreamType,
    pub flags: u8,
    pub payload: Vec<u8>,
}

impl MultiplexFrame {
    pub const FLAG_FIN: u8 = 0x01;
    pub const FLAG_SYN: u8 = 0x02;
    pub const FLAG_RST: u8 = 0x04;
    pub const FLAG_DATA: u8 = 0x00;

    pub fn new(stream_id: u64, stream_type: StreamType, flags: u8, payload: Vec<u8>) -> Self {
        Self {
            stream_id,
            stream_type,
            flags,
            payload,
        }
    }

    pub fn syn(stream_id: u64, stream_type: StreamType) -> Self {
        Self::new(stream_id, stream_type, Self::FLAG_SYN, Vec::new())
    }

    pub fn fin(stream_id: u64, stream_type: StreamType) -> Self {
        Self::new(stream_id, stream_type, Self::FLAG_FIN, Vec::new())
    }

    pub fn rst(stream_id: u64, stream_type: StreamType) -> Self {
        Self::new(stream_id, stream_type, Self::FLAG_RST, Vec::new())
    }

    pub fn data(stream_id: u64, stream_type: StreamType, payload: Vec<u8>) -> Self {
        Self::new(stream_id, stream_type, Self::FLAG_DATA, payload)
    }

    pub fn is_syn(&self) -> bool {
        self.flags & Self::FLAG_SYN != 0
    }

    pub fn is_fin(&self) -> bool {
        self.flags & Self::FLAG_FIN != 0
    }

    pub fn is_rst(&self) -> bool {
        self.flags & Self::FLAG_RST != 0
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(4 + 8 + 1 + 1 + 4 + self.payload.len());
        
        buf.put_u32(0);
        buf.put_u64(self.stream_id);
        buf.put_u8(self.stream_type as u8);
        buf.put_u8(self.flags);
        buf.put_u32(self.payload.len() as u32);
        buf.put_slice(&self.payload);

        let len = buf.len() as u32;
        buf[0..4].copy_from_slice(&len.to_be_bytes());
        
        buf.to_vec()
    }

    pub fn decode(data: &[u8]) -> io::Result<Option<(Self, usize)>> {
        if data.len() < 18 {
            return Ok(None);
        }

        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if len > MAX_FRAME_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Frame too large"));
        }

        if data.len() < len {
            return Ok(None);
        }

        let stream_id = u64::from_be_bytes([
            data[4], data[5], data[6], data[7],
            data[8], data[9], data[10], data[11],
        ]);
        
        let stream_type = match data[12] {
            0 => StreamType::Control,
            1 => StreamType::Tcp,
            2 => StreamType::Udp,
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid stream type")),
        };
        
        let flags = data[13];
        let payload_len = u32::from_be_bytes([data[14], data[15], data[16], data[17]]) as usize;
        
        if data.len() < 18 + payload_len {
            return Ok(None);
        }

        let payload = data[18..18 + payload_len].to_vec();

        Ok(Some((Self {
            stream_id,
            stream_type,
            flags,
            payload,
        }, len)))
    }
}

pub struct StreamInfo {
    pub stream_id: u64,
    pub stream_type: StreamType,
    pub created_at: std::time::Instant,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub is_closed: bool,
}

pub struct MultiplexServer {
    listener: UnixListener,
    streams: Arc<DashMap<u64, StreamInfo>>,
    next_stream_id: AtomicU64,
    shutdown_tx: broadcast::Sender<()>,
    frame_tx: mpsc::Sender<(u64, MultiplexFrame)>,
    frame_rx: Option<mpsc::Receiver<(u64, MultiplexFrame)>>,
}

impl MultiplexServer {
    pub async fn bind(path: &std::path::Path) -> io::Result<Self> {
        if path.exists() {
            std::fs::remove_file(path)?;
        }

        let listener = UnixListener::bind(path)?;
        let (shutdown_tx, _) = broadcast::channel(1);
        let (frame_tx, frame_rx) = mpsc::channel(1024);

        Ok(Self {
            listener,
            streams: Arc::new(DashMap::new()),
            next_stream_id: AtomicU64::new(1),
            shutdown_tx,
            frame_tx,
            frame_rx: Some(frame_rx),
        })
    }

    pub async fn accept(&self) -> io::Result<MultiplexConnection> {
        let (stream, _addr) = self.listener.accept().await?;
        
        Ok(MultiplexConnection::new(
            stream,
            self.streams.clone(),
            self.frame_tx.clone(),
        ))
    }

    pub fn get_stream_info(&self, stream_id: u64) -> Option<StreamInfo> {
        self.streams.get(&stream_id).map(|s| StreamInfo {
            stream_id: s.stream_id,
            stream_type: s.stream_type,
            created_at: s.created_at,
            bytes_sent: s.bytes_sent,
            bytes_received: s.bytes_received,
            is_closed: s.is_closed,
        })
    }

    pub fn list_streams(&self) -> Vec<StreamInfo> {
        self.streams.iter().map(|s| StreamInfo {
            stream_id: s.stream_id,
            stream_type: s.stream_type,
            created_at: s.created_at,
            bytes_sent: s.bytes_sent,
            bytes_received: s.bytes_received,
            is_closed: s.is_closed,
        }).collect()
    }

    pub fn active_stream_count(&self) -> usize {
        self.streams.len()
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

pub struct MultiplexClient {
    streams: Arc<DashMap<u64, StreamInfo>>,
    next_stream_id: AtomicU64,
    frame_tx: mpsc::Sender<(u64, MultiplexFrame)>,
}

impl MultiplexClient {
    pub async fn connect(path: &std::path::Path) -> io::Result<(Self, MultiplexConnection)> {
        let stream = UnixStream::connect(path).await?;
        
        let streams = Arc::new(DashMap::new());
        let (frame_tx, mut frame_rx) = mpsc::channel(1024);
        
        let conn = MultiplexConnection::new(
            stream,
            streams.clone(),
            frame_tx.clone(),
        );

        Ok((Self {
            streams,
            next_stream_id: AtomicU64::new(1),
            frame_tx,
        }, conn))
    }

    pub fn next_stream_id(&self) -> u64 {
        self.next_stream_id.fetch_add(1, Ordering::SeqCst)
    }

    pub fn open_stream(&self, stream_type: StreamType) -> MultiplexStream {
        let stream_id = self.next_stream_id();
        
        self.streams.insert(stream_id, StreamInfo {
            stream_id,
            stream_type,
            created_at: std::time::Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            is_closed: false,
        });

        MultiplexStream {
            stream_id,
            stream_type,
            frame_tx: self.frame_tx.clone(),
        }
    }

    pub fn close_stream(&self, stream_id: u64) {
        if let Some(mut info) = self.streams.get_mut(&stream_id) {
            info.is_closed = true;
        }
        self.streams.remove(&stream_id);
    }

    pub fn get_stream_info(&self, stream_id: u64) -> Option<StreamInfo> {
        self.streams.get(&stream_id).map(|s| StreamInfo {
            stream_id: s.stream_id,
            stream_type: s.stream_type,
            created_at: s.created_at,
            bytes_sent: s.bytes_sent,
            bytes_received: s.bytes_received,
            is_closed: s.is_closed,
        })
    }
}

pub struct MultiplexConnection {
    stream: UnixStream,
    streams: Arc<DashMap<u64, StreamInfo>>,
    frame_tx: mpsc::Sender<(u64, MultiplexFrame)>,
    read_buffer: Vec<u8>,
}

impl MultiplexConnection {
    fn new(
        stream: UnixStream,
        streams: Arc<DashMap<u64, StreamInfo>>,
        frame_tx: mpsc::Sender<(u64, MultiplexFrame)>,
    ) -> Self {
        Self {
            stream,
            streams,
            frame_tx,
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
        }
    }

    pub async fn send_frame(&mut self, frame: &MultiplexFrame) -> io::Result<()> {
        let data = frame.encode();
        self.stream.write_all(&data).await?;
        self.stream.flush().await?;

        if let Some(mut info) = self.streams.get_mut(&frame.stream_id) {
            info.bytes_sent += frame.payload.len() as u64;
        }

        counter!("rustwaf.tunnel.ipc.frames_sent").increment(1);
        histogram!("rustwaf.tunnel.ipc.frame_size").record(frame.payload.len() as f64);
        
        Ok(())
    }

    pub async fn recv_frame(&mut self) -> io::Result<Option<MultiplexFrame>> {
        let mut temp_buf = [0u8; 4096];
        
        match self.stream.read(&mut temp_buf).await {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Connection closed",
                ));
            }
            Ok(n) => {
                self.read_buffer.extend_from_slice(&temp_buf[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        }

        if let Some((frame, consumed)) = MultiplexFrame::decode(&self.read_buffer)? {
            self.read_buffer.drain(..consumed);

            if let Some(mut info) = self.streams.get_mut(&frame.stream_id) {
                info.bytes_received += frame.payload.len() as u64;
            }

            if frame.is_syn() {
                self.streams.insert(frame.stream_id, StreamInfo {
                    stream_id: frame.stream_id,
                    stream_type: frame.stream_type,
                    created_at: std::time::Instant::now(),
                    bytes_sent: 0,
                    bytes_received: 0,
                    is_closed: false,
                });
                counter!("rustwaf.tunnel.ipc.streams_created").increment(1);
            } else if frame.is_fin() || frame.is_rst() {
                if let Some(mut info) = self.streams.get_mut(&frame.stream_id) {
                    info.is_closed = true;
                }
                self.streams.remove(&frame.stream_id);
                counter!("rustwaf.tunnel.ipc.streams_closed").increment(1);
            }

            counter!("rustwaf.tunnel.ipc.frames_received").increment(1);
            return Ok(Some(frame));
        }

        Ok(None)
    }

    pub async fn close(&mut self) -> io::Result<()> {
        self.stream.shutdown().await
    }
}

pub struct MultiplexStream {
    stream_id: u64,
    stream_type: StreamType,
    frame_tx: mpsc::Sender<(u64, MultiplexFrame)>,
}

impl MultiplexStream {
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    pub fn stream_type(&self) -> StreamType {
        self.stream_type
    }

    pub async fn send(&self, data: Vec<u8>) -> io::Result<()> {
        let frame = MultiplexFrame::data(self.stream_id, self.stream_type, data);
        self.frame_tx.send((self.stream_id, frame)).await
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
        Ok(())
    }

    pub async fn close(&self) -> io::Result<()> {
        let frame = MultiplexFrame::fin(self.stream_id, self.stream_type);
        self.frame_tx.send((self.stream_id, frame)).await
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
        Ok(())
    }

    pub async fn reset(&self) -> io::Result<()> {
        let frame = MultiplexFrame::rst(self.stream_id, self.stream_type);
        self.frame_tx.send((self.stream_id, frame)).await
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QuicIpcMessage {
    OpenStream {
        peer_id: String,
        identifier: String,
        port: u16,
        protocol: String,
        request_id: u64,
    },
    OpenStreamResponse {
        request_id: u64,
        stream_id: u64,
        success: bool,
        error: Option<String>,
    },
    CloseStream {
        stream_id: u64,
    },
    SendData {
        stream_id: u64,
        data: Vec<u8>,
    },
    SendDatagram {
        peer_id: String,
        identifier: String,
        data: Vec<u8>,
        port: u16,
    },
    HealthCheck {
        peer_id: String,
    },
    HealthCheckResponse {
        peer_id: String,
        healthy: bool,
        rtt_ms: Option<f64>,
    },
    ConnectionQuality {
        peer_id: String,
        quality: String,
        rtt_ms: f64,
        loss_rate: f64,
    },
    RegisterPeer {
        peer_id: String,
        session_id: String,
    },
    UnregisterPeer {
        peer_id: String,
    },
}

impl QuicIpcMessage {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }
}

#[cfg(windows)]
pub struct WindowsMultiplexServer {
    listener: TcpListener,
    streams: Arc<DashMap<u64, StreamInfo>>,
    next_stream_id: AtomicU64,
    shutdown_tx: broadcast::Sender<()>,
    frame_tx: mpsc::Sender<(u64, MultiplexFrame)>,
}

#[cfg(windows)]
impl WindowsMultiplexServer {
    pub async fn bind(addr: &str) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let (shutdown_tx, _) = broadcast::channel(1);
        let (frame_tx, _frame_rx) = mpsc::channel(1024);

        Ok(Self {
            listener,
            streams: Arc::new(DashMap::new()),
            next_stream_id: AtomicU64::new(1),
            shutdown_tx,
            frame_tx,
        })
    }

    pub async fn accept(&self) -> io::Result<WindowsMultiplexConnection> {
        let (stream, _addr) = self.listener.accept().await?;
        
        Ok(WindowsMultiplexConnection::new(
            stream,
            self.streams.clone(),
            self.frame_tx.clone(),
        ))
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

#[cfg(windows)]
pub struct WindowsMultiplexConnection {
    stream: TcpStream,
    streams: Arc<DashMap<u64, StreamInfo>>,
    frame_tx: mpsc::Sender<(u64, MultiplexFrame)>,
    read_buffer: Vec<u8>,
}

#[cfg(windows)]
impl WindowsMultiplexConnection {
    fn new(
        stream: TcpStream,
        streams: Arc<DashMap<u64, StreamInfo>>,
        frame_tx: mpsc::Sender<(u64, MultiplexFrame)>,
    ) -> Self {
        Self {
            stream,
            streams,
            frame_tx,
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
        }
    }

    pub async fn send_frame(&mut self, frame: &MultiplexFrame) -> io::Result<()> {
        let data = frame.encode();
        self.stream.write_all(&data).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn recv_frame(&mut self) -> io::Result<Option<MultiplexFrame>> {
        let mut temp_buf = [0u8; 4096];
        
        match self.stream.read(&mut temp_buf).await {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Connection closed",
                ));
            }
            Ok(n) => {
                self.read_buffer.extend_from_slice(&temp_buf[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        }

        if let Some((frame, consumed)) = MultiplexFrame::decode(&self.read_buffer)? {
            self.read_buffer.drain(..consumed);
            return Ok(Some(frame));
        }

        Ok(None)
    }

    pub async fn close(&mut self) -> io::Result<()> {
        use tokio::io::AsyncWrite;
        self.stream.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_encode_decode() {
        let frame = MultiplexFrame::data(123, StreamType::Tcp, vec![1, 2, 3, 4, 5]);
        let encoded = frame.encode();
        let (decoded, consumed) = MultiplexFrame::decode(&encoded).unwrap().unwrap();

        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.stream_id, 123);
        assert_eq!(decoded.stream_type, StreamType::Tcp);
        assert!(!decoded.is_syn());
        assert!(!decoded.is_fin());
        assert_eq!(decoded.payload, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_frame_flags() {
        let syn = MultiplexFrame::syn(1, StreamType::Tcp);
        assert!(syn.is_syn());
        assert!(!syn.is_fin());
        assert!(!syn.is_rst());

        let fin = MultiplexFrame::fin(1, StreamType::Tcp);
        assert!(!fin.is_syn());
        assert!(fin.is_fin());
        assert!(!fin.is_rst());

        let rst = MultiplexFrame::rst(1, StreamType::Tcp);
        assert!(!rst.is_syn());
        assert!(!rst.is_fin());
        assert!(rst.is_rst());
    }

    #[test]
    fn test_ipc_message_encoding() {
        let msg = QuicIpcMessage::OpenStream {
            peer_id: "peer1".to_string(),
            identifier: "stream-1".to_string(),
            port: 8080,
            protocol: "tcp".to_string(),
            request_id: 1,
        };
        
        let encoded = msg.encode();
        let decoded = QuicIpcMessage::decode(&encoded).unwrap();

        match decoded {
            QuicIpcMessage::OpenStream { peer_id, identifier, port, protocol, request_id } => {
                assert_eq!(peer_id, "peer1");
                assert_eq!(identifier, "stream-1");
                assert_eq!(port, 8080);
                assert_eq!(protocol, "tcp");
                assert_eq!(request_id, 1);
            }
            _ => panic!("Wrong message type"),
        }
    }
}
