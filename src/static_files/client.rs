use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use parking_lot::RwLock;

use crate::process::{IpcStream, Message};

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(unix)]
fn connect_to_static_worker(socket_path: &PathBuf) -> io::Result<IpcStream> {
    use std::os::unix::net::UnixStream;
    let stream = UnixStream::connect(socket_path)?;
    stream.set_nonblocking(false).ok();
    Ok(IpcStream::new(stream))
}

#[cfg(windows)]
fn connect_to_static_worker(_socket_path: &PathBuf) -> io::Result<IpcStream> {
    // On Windows, named pipes would be needed
    Err(io::Error::new(
        io::ErrorKind::Other,
        "Static worker IPC not supported on Windows",
    ))
}

#[derive(Clone)]
pub struct MinifierClient {
    socket_path: PathBuf,
    timeout_ms: u64,
    pending_requests: Arc<RwLock<Vec<(u64, std::time::Instant)>>>,
}

impl MinifierClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            timeout_ms: 5000,
            pending_requests: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    pub fn request_minify(
        &self,
        site_id: &str,
        path: &str,
        encoding: Option<&str>,
    ) -> Result<MinifyResult, MinifierClientError> {
        let mut ipc = connect_to_static_worker(&self.socket_path)
            .map_err(|e| MinifierClientError::ConnectionFailed(e.to_string()))?;

        let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);

        let request = Message::MinifyRequest {
            request_id,
            site_id: site_id.to_string(),
            path: path.to_string(),
            encoding: encoding.map(|s| s.to_string()),
        };

        ipc.send(&request)
            .map_err(|e| MinifierClientError::SendFailed(e.to_string()))?;

        let start = std::time::Instant::now();
        loop {
            if start.elapsed().as_millis() as u64 > self.timeout_ms {
                return Err(MinifierClientError::Timeout);
            }

            match ipc.recv(100) {
                Ok(Some(Message::MinifyResponse {
                    request_id: resp_id,
                    site_id: _,
                    path: _,
                    content,
                    content_type,
                    encoding: resp_encoding,
                    queued_encodings,
                })) => {
                    if resp_id == request_id {
                        return Ok(MinifyResult {
                            content: Bytes::from(content),
                            content_type,
                            encoding: resp_encoding,
                            queued_encodings,
                        });
                    }
                }
                Ok(Some(Message::MinifyError {
                    request_id: resp_id,
                    error,
                })) => {
                    if resp_id == request_id {
                        return Err(MinifierClientError::MinificationFailed(error));
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    return Err(MinifierClientError::ReceiveFailed(e.to_string()));
                }
            }
        }
    }

    pub fn get_compressed(
        &self,
        site_id: &str,
        path: &str,
        encoding: &str,
    ) -> Result<Bytes, MinifierClientError> {
        let mut ipc = connect_to_static_worker(&self.socket_path)
            .map_err(|e| MinifierClientError::ConnectionFailed(e.to_string()))?;

        let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);

        let request = Message::GetCompressedRequest {
            request_id,
            site_id: site_id.to_string(),
            path: path.to_string(),
            encoding: encoding.to_string(),
        };

        ipc.send(&request)
            .map_err(|e| MinifierClientError::SendFailed(e.to_string()))?;

        let start = std::time::Instant::now();
        loop {
            if start.elapsed().as_millis() as u64 > self.timeout_ms {
                return Err(MinifierClientError::Timeout);
            }

            match ipc.recv(100) {
                Ok(Some(Message::GetCompressedResponse {
                    request_id: resp_id,
                    content,
                })) => {
                    if resp_id == request_id {
                        return Ok(Bytes::from(content));
                    }
                }
                Ok(Some(Message::MinifyError {
                    request_id: resp_id,
                    error,
                })) => {
                    if resp_id == request_id {
                        return Err(MinifierClientError::MinificationFailed(error));
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    return Err(MinifierClientError::ReceiveFailed(e.to_string()));
                }
            }
        }
    }

    pub fn is_available(&self) -> bool {
        connect_to_static_worker(&self.socket_path).is_ok()
    }
}

#[derive(Debug)]
pub struct MinifyResult {
    pub content: Bytes,
    pub content_type: String,
    pub encoding: Option<String>,
    pub queued_encodings: Vec<String>,
}

#[derive(Debug)]
pub enum MinifierClientError {
    ConnectionFailed(String),
    SendFailed(String),
    ReceiveFailed(String),
    Timeout,
    MinificationFailed(String),
}

impl std::fmt::Display for MinifierClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MinifierClientError::ConnectionFailed(e) => write!(f, "Connection failed: {}", e),
            MinifierClientError::SendFailed(e) => write!(f, "Send failed: {}", e),
            MinifierClientError::ReceiveFailed(e) => write!(f, "Receive failed: {}", e),
            MinifierClientError::Timeout => write!(f, "Request timed out"),
            MinifierClientError::MinificationFailed(e) => write!(f, "Minification failed: {}", e),
        }
    }
}

impl std::error::Error for MinifierClientError {}
