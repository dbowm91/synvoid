use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::Mutex as TokioMutex;

use crate::process::ipc_transport::IpcEndpoint;
use crate::process::ipc_transport::IpcStream as AsyncIpcStream;
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
    let pipe_name = "\\\\.\\pipe\\synvoid-static-worker";

    let mut attempts = 0;
    let max_attempts = 10;

    loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe_name)
        {
            Ok(handle) => {
                return Ok(IpcStream::new(handle));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && attempts < max_attempts => {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return Err(e),
        }
    }
}

#[derive(Clone)]
pub struct MinifierClient {
    socket_path: PathBuf,
    timeout_ms: u64,
}

impl MinifierClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            timeout_ms: 5000,
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

#[derive(Clone)]
pub struct AsyncMinifierClient {
    socket_path: PathBuf,
    timeout_ms: u64,
    connection: Arc<TokioMutex<Option<AsyncIpcStream>>>,
}

impl AsyncMinifierClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            timeout_ms: 5000,
            connection: Arc::new(TokioMutex::new(None)),
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    async fn get_connection(&self) -> Result<AsyncIpcStream, MinifierClientError> {
        let mut guard = self.connection.lock().await;

        if guard.is_none() {
            let socket_name = self
                .socket_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("static-worker");

            let endpoint = IpcEndpoint::new(socket_name);
            let stream = endpoint
                .connect()
                .await
                .map_err(|e| MinifierClientError::ConnectionFailed(e.to_string()))?;
            *guard = Some(stream);
        }

        Ok(guard.take().unwrap())
    }

    async fn return_connection(&self, stream: AsyncIpcStream) {
        let mut guard = self.connection.lock().await;
        *guard = Some(stream);
    }

    pub async fn request_minify(
        &self,
        site_id: &str,
        path: &str,
        encoding: Option<&str>,
    ) -> Result<MinifyResult, MinifierClientError> {
        let mut ipc = self.get_connection().await?;

        let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);

        let request = Message::MinifyRequest {
            request_id,
            site_id: site_id.to_string(),
            path: path.to_string(),
            encoding: encoding.map(|s| s.to_string()),
        };

        ipc.send(&request)
            .await
            .map_err(|e| MinifierClientError::SendFailed(e.to_string()))?;

        let start = std::time::Instant::now();
        loop {
            if start.elapsed().as_millis() as u64 > self.timeout_ms {
                self.return_connection(ipc).await;
                return Err(MinifierClientError::Timeout);
            }

            match ipc.recv_with_timeout::<Message>(100).await {
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
                        self.return_connection(ipc).await;
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
                        self.return_connection(ipc).await;
                        return Err(MinifierClientError::MinificationFailed(error));
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(e) => {
                    self.return_connection(ipc).await;
                    return Err(MinifierClientError::ReceiveFailed(e.to_string()));
                }
            }
        }
    }

    pub async fn get_compressed(
        &self,
        site_id: &str,
        path: &str,
        encoding: &str,
    ) -> Result<Bytes, MinifierClientError> {
        let mut ipc = self.get_connection().await?;

        let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);

        let request = Message::GetCompressedRequest {
            request_id,
            site_id: site_id.to_string(),
            path: path.to_string(),
            encoding: encoding.to_string(),
        };

        ipc.send(&request)
            .await
            .map_err(|e| MinifierClientError::SendFailed(e.to_string()))?;

        let start = std::time::Instant::now();
        loop {
            if start.elapsed().as_millis() as u64 > self.timeout_ms {
                self.return_connection(ipc).await;
                return Err(MinifierClientError::Timeout);
            }

            match ipc.recv_with_timeout::<Message>(100).await {
                Ok(Some(Message::GetCompressedResponse {
                    request_id: resp_id,
                    content,
                })) => {
                    if resp_id == request_id {
                        self.return_connection(ipc).await;
                        return Ok(Bytes::from(content));
                    }
                }
                Ok(Some(Message::MinifyError {
                    request_id: resp_id,
                    error,
                })) => {
                    if resp_id == request_id {
                        self.return_connection(ipc).await;
                        return Err(MinifierClientError::MinificationFailed(error));
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(e) => {
                    self.return_connection(ipc).await;
                    return Err(MinifierClientError::ReceiveFailed(e.to_string()));
                }
            }
        }
    }

    pub async fn is_available(&self) -> bool {
        let socket_name = self
            .socket_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("static-worker");

        let endpoint = IpcEndpoint::new(socket_name);
        if let Ok(mut ipc) = endpoint.connect().await {
            return ipc.recv_with_timeout::<Message>(100).await.is_ok();
        }
        false
    }
}

static POISON_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum PoisonImageClientError {
    ConnectionFailed(String),
    SendFailed(String),
    ReceiveFailed(String),
    Timeout,
    PoisoningFailed(String),
}

impl std::fmt::Display for PoisonImageClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoisonImageClientError::ConnectionFailed(e) => write!(f, "Connection failed: {}", e),
            PoisonImageClientError::SendFailed(e) => write!(f, "Send failed: {}", e),
            PoisonImageClientError::ReceiveFailed(e) => write!(f, "Receive failed: {}", e),
            PoisonImageClientError::Timeout => write!(f, "Request timed out"),
            PoisonImageClientError::PoisoningFailed(e) => write!(f, "Poisoning failed: {}", e),
        }
    }
}

impl std::error::Error for PoisonImageClientError {}

#[derive(Clone)]
pub struct PoisonImageClient {
    socket_path: PathBuf,
    timeout_ms: u64,
}

impl PoisonImageClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            timeout_ms: 5000,
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    pub async fn poison_image(
        &self,
        site_id: &str,
        body: Vec<u8>,
        last_modified: Option<String>,
        level: Option<String>,
        intensity: Option<f32>,
        seed: Option<u64>,
        max_dimension: Option<u32>,
        jpeg_quality: Option<u8>,
    ) -> Result<Vec<u8>, PoisonImageClientError> {
        let socket_name = self
            .socket_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("static-worker");

        let endpoint = IpcEndpoint::new(socket_name);

        let mut ipc = endpoint
            .connect()
            .await
            .map_err(|e| PoisonImageClientError::ConnectionFailed(e.to_string()))?;

        let request_id = POISON_REQUEST_ID.fetch_add(1, Ordering::Relaxed);

        let request = crate::process::Message::PoisonImageRequest {
            request_id,
            site_id: site_id.to_string(),
            body,
            last_modified,
            level,
            intensity,
            seed,
            max_dimension,
            jpeg_quality,
        };

        ipc.send(&request)
            .await
            .map_err(|e| PoisonImageClientError::SendFailed(e.to_string()))?;

        let start = std::time::Instant::now();
        loop {
            if start.elapsed().as_millis() as u64 > self.timeout_ms {
                return Err(PoisonImageClientError::Timeout);
            }

            match ipc.recv_with_timeout::<crate::process::Message>(100).await {
                Ok(Some(crate::process::Message::PoisonImageResponse {
                    request_id: resp_id,
                    poisoned_body,
                })) => {
                    if resp_id == request_id {
                        return Ok(poisoned_body);
                    }
                }
                Ok(Some(crate::process::Message::PoisonImageError {
                    request_id: resp_id,
                    error,
                })) => {
                    if resp_id == request_id {
                        return Err(PoisonImageClientError::PoisoningFailed(error));
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(e) => {
                    return Err(PoisonImageClientError::ReceiveFailed(e.to_string()));
                }
            }
        }
    }

    pub async fn is_available(&self) -> bool {
        let socket_name = self
            .socket_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("static-worker");

        let endpoint = IpcEndpoint::new(socket_name);
        if let Ok(mut ipc) = endpoint.connect().await {
            return ipc
                .recv_with_timeout::<crate::process::Message>(100)
                .await
                .is_ok();
        }
        false
    }
}
