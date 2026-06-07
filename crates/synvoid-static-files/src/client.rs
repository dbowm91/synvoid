use std::collections::HashMap;
use std::io;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use metrics::{counter, gauge};
use tempfile::{Builder, NamedTempFile};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use synvoid_ipc::ipc_transport::IpcEndpoint;
use synvoid_ipc::{IpcStream, Message};

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);
static GLOBAL_ASYNC_CPU_OFFLOAD_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
static GLOBAL_ASYNC_CPU_OFFLOAD_EVICTIONS: AtomicU64 = AtomicU64::new(0);
static GLOBAL_ASYNC_CPU_OFFLOAD_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
static GLOBAL_ASYNC_CPU_OFFLOAD_SUBMISSIONS: AtomicU64 = AtomicU64::new(0);
static GLOBAL_ASYNC_CPU_OFFLOAD_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static GLOBAL_ASYNC_CPU_OFFLOAD_REJECTIONS: AtomicU64 = AtomicU64::new(0);
static GLOBAL_ASYNC_CPU_OFFLOAD_FALLBACKS: AtomicU64 = AtomicU64::new(0);
const DEFAULT_ASYNC_CPU_POOL_MAX_CONNECTIONS: usize = 4;
const DEFAULT_ASYNC_CPU_MAX_IN_FLIGHT_PER_CONNECTION: usize = 1;
const ASYNC_CPU_POOL_MAX_CONNECTIONS_ENV: &str = "SYNVOID_CPU_TASK_POOL_MAX_CONNECTIONS";
const ASYNC_CPU_MAX_IN_FLIGHT_PER_CONNECTION_ENV: &str =
    "SYNVOID_CPU_TASK_MAX_IN_FLIGHT_PER_CONNECTION";

#[derive(Clone, Copy)]
struct AsyncCpuPoolLimits {
    max_connections: usize,
    max_in_flight_per_connection: usize,
}

impl AsyncCpuPoolLimits {
    fn from_env_or_default() -> Self {
        let max_connections = std::env::var(ASYNC_CPU_POOL_MAX_CONNECTIONS_ENV)
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_ASYNC_CPU_POOL_MAX_CONNECTIONS)
            .max(1);
        let max_in_flight_per_connection =
            std::env::var(ASYNC_CPU_MAX_IN_FLIGHT_PER_CONNECTION_ENV)
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(DEFAULT_ASYNC_CPU_MAX_IN_FLIGHT_PER_CONNECTION)
                .max(1);

        Self {
            max_connections,
            max_in_flight_per_connection,
        }
    }
}

#[cfg(unix)]
fn connect_to_cpu_worker(socket_path: &PathBuf) -> io::Result<IpcStream> {
    use std::os::unix::net::UnixStream;
    let stream = UnixStream::connect(socket_path)?;
    stream.set_nonblocking(false).ok();
    Ok(IpcStream::new(stream))
}

#[cfg(windows)]
fn connect_to_cpu_worker(_socket_path: &PathBuf) -> io::Result<IpcStream> {
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
        let mut ipc = connect_to_cpu_worker(&self.socket_path)
            .map_err(|e| MinifierClientError::ConnectionFailed(e.to_string()))?;

        let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let deadline_unix_ms = synvoid_utils::current_timestamp()
            .saturating_mul(1000)
            .saturating_add(self.timeout_ms);

        let request = Message::CpuTaskRequest {
            request_id,
            task_kind: synvoid_ipc::CpuTaskKind::Minify,
            priority: synvoid_ipc::CpuTaskPriority::Normal,
            policy: synvoid_ipc::CpuTaskPolicy::SkipTransform,
            deadline_unix_ms,
            payload_size_limit: 1024 * 1024,
            output_size_limit: 16 * 1024 * 1024,
            file_payload_path: None,
            payload: synvoid_ipc::CpuTaskPayload::Minify {
                site_id: site_id.to_string(),
                path: path.to_string(),
                encoding: encoding.map(|s| s.to_string()),
            },
        };

        ipc.send(&request)
            .map_err(|e| MinifierClientError::SendFailed(e.to_string()))?;

        let start = std::time::Instant::now();
        loop {
            if start.elapsed().as_millis() as u64 > self.timeout_ms {
                send_cpu_task_cancel_sync(&mut ipc, request_id, synvoid_ipc::CpuTaskKind::Minify);
                record_cpu_offload_timeout();
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
                Ok(Some(Message::CpuTaskResponse {
                    request_id: resp_id,
                    task_kind: synvoid_ipc::CpuTaskKind::Minify,
                    result:
                        synvoid_ipc::CpuTaskResult::Minify {
                            content,
                            content_type,
                            encoding: resp_encoding,
                            queued_encodings,
                            ..
                        },
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
                Ok(Some(Message::CpuTaskError {
                    request_id: resp_id,
                    code,
                    message,
                    ..
                })) => {
                    if resp_id == request_id {
                        return Err(map_cpu_task_error_for_minifier(code, message));
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
        let mut ipc = connect_to_cpu_worker(&self.socket_path)
            .map_err(|e| MinifierClientError::ConnectionFailed(e.to_string()))?;

        let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let deadline_unix_ms = synvoid_utils::current_timestamp()
            .saturating_mul(1000)
            .saturating_add(self.timeout_ms);

        let request = Message::CpuTaskRequest {
            request_id,
            task_kind: synvoid_ipc::CpuTaskKind::GetCompressed,
            priority: synvoid_ipc::CpuTaskPriority::Normal,
            policy: synvoid_ipc::CpuTaskPolicy::SkipTransform,
            deadline_unix_ms,
            payload_size_limit: 1024 * 1024,
            output_size_limit: 16 * 1024 * 1024,
            file_payload_path: None,
            payload: synvoid_ipc::CpuTaskPayload::GetCompressed {
                site_id: site_id.to_string(),
                path: path.to_string(),
                encoding: encoding.to_string(),
            },
        };

        ipc.send(&request)
            .map_err(|e| MinifierClientError::SendFailed(e.to_string()))?;

        let start = std::time::Instant::now();
        loop {
            if start.elapsed().as_millis() as u64 > self.timeout_ms {
                send_cpu_task_cancel_sync(
                    &mut ipc,
                    request_id,
                    synvoid_ipc::CpuTaskKind::GetCompressed,
                );
                record_cpu_offload_timeout();
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
                Ok(Some(Message::CpuTaskResponse {
                    request_id: resp_id,
                    task_kind: synvoid_ipc::CpuTaskKind::GetCompressed,
                    result: synvoid_ipc::CpuTaskResult::GetCompressed { content },
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
                Ok(Some(Message::CpuTaskError {
                    request_id: resp_id,
                    code,
                    message,
                    ..
                })) => {
                    if resp_id == request_id {
                        return Err(map_cpu_task_error_for_minifier(code, message));
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
        connect_to_cpu_worker(&self.socket_path).is_ok()
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
    Backpressure(String),
    PayloadTooLarge(String),
    InvalidRequest(String),
    MinificationFailed(String),
}

impl std::fmt::Display for MinifierClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MinifierClientError::ConnectionFailed(e) => write!(f, "Connection failed: {}", e),
            MinifierClientError::SendFailed(e) => write!(f, "Send failed: {}", e),
            MinifierClientError::ReceiveFailed(e) => write!(f, "Receive failed: {}", e),
            MinifierClientError::Timeout => write!(f, "Request timed out"),
            MinifierClientError::Backpressure(e) => write!(f, "CPU task backpressure: {}", e),
            MinifierClientError::PayloadTooLarge(e) => {
                write!(f, "CPU task payload/output too large: {}", e)
            }
            MinifierClientError::InvalidRequest(e) => write!(f, "Invalid CPU task request: {}", e),
            MinifierClientError::MinificationFailed(e) => write!(f, "Minification failed: {}", e),
        }
    }
}

impl std::error::Error for MinifierClientError {}

#[derive(Debug, Clone)]
enum AsyncCpuTaskDispatchError {
    ConnectionFailed(String),
    SendFailed(String),
    ReceiveFailed(String),
    Timeout,
}

enum AsyncCpuTaskCommand {
    Submit {
        request: Message,
        response_tx: oneshot::Sender<Result<Message, AsyncCpuTaskDispatchError>>,
    },
    Cancel {
        request_id: u64,
        task_kind: synvoid_ipc::CpuTaskKind,
    },
}

struct AsyncCpuTaskConnection {
    command_tx: mpsc::UnboundedSender<AsyncCpuTaskCommand>,
    closed: Arc<AtomicBool>,
    in_flight: AtomicUsize,
}

impl AsyncCpuTaskConnection {
    async fn connect(socket_path: &PathBuf) -> Result<Arc<Self>, MinifierClientError> {
        let socket_name = socket_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("static-worker");
        let endpoint = IpcEndpoint::new(socket_name);
        let stream = endpoint
            .connect()
            .await
            .map_err(|e| MinifierClientError::ConnectionFailed(e.to_string()))?;
        let signer = stream.signer();
        let transport = stream.into_inner();
        let (read_half, write_half) = tokio::io::split(transport);
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let closed = Arc::new(AtomicBool::new(false));
        let connection = Arc::new(Self {
            command_tx,
            closed: closed.clone(),
            in_flight: AtomicUsize::new(0),
        });

        tokio::spawn(run_async_cpu_task_connection_driver(
            read_half, write_half, signer, command_rx, closed,
        ));

        Ok(connection)
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn submit(
        &self,
        request: Message,
    ) -> Result<
        oneshot::Receiver<Result<Message, AsyncCpuTaskDispatchError>>,
        AsyncCpuTaskDispatchError,
    > {
        if self.is_closed() {
            return Err(AsyncCpuTaskDispatchError::ConnectionFailed(
                "CPU task connection is closed".to_string(),
            ));
        }

        let (response_tx, response_rx) = oneshot::channel();
        self.command_tx
            .send(AsyncCpuTaskCommand::Submit {
                request,
                response_tx,
            })
            .map_err(|_| {
                self.closed.store(true, Ordering::Release);
                AsyncCpuTaskDispatchError::ConnectionFailed(
                    "CPU task connection driver is no longer available".to_string(),
                )
            })?;
        Ok(response_rx)
    }

    async fn submit_with_timeout(
        &self,
        request: Message,
        request_id: u64,
        task_kind: synvoid_ipc::CpuTaskKind,
        timeout_ms: u64,
    ) -> Result<Message, AsyncCpuTaskDispatchError> {
        let response_rx = self.submit(request)?;

        match tokio::time::timeout(Duration::from_millis(timeout_ms), response_rx).await {
            Ok(Ok(Ok(message))) => Ok(message),
            Ok(Ok(Err(err))) => Err(err),
            Ok(Err(_)) => Err(AsyncCpuTaskDispatchError::ReceiveFailed(
                "CPU task response channel closed".to_string(),
            )),
            Err(_) => {
                if !self.cancel(request_id, task_kind) {
                    self.closed.store(true, Ordering::Release);
                }
                Err(AsyncCpuTaskDispatchError::Timeout)
            }
        }
    }

    fn cancel(&self, request_id: u64, task_kind: synvoid_ipc::CpuTaskKind) -> bool {
        if self.is_closed() {
            return false;
        }

        match self.command_tx.send(AsyncCpuTaskCommand::Cancel {
            request_id,
            task_kind,
        }) {
            Ok(()) => true,
            Err(_) => {
                self.closed.store(true, Ordering::Release);
                false
            }
        }
    }
}

async fn send_framed_async_cpu_task_message<W>(
    writer: &mut W,
    signer: Option<&Arc<synvoid_ipc::IpcSigner>>,
    message: &Message,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if let Some(signer) = signer {
        let data = synvoid_ipc::SignedIpcMessage::serialize_signed(message, signer)?;
        writer.write_all(&data).await?;
        writer.flush().await?;
        Ok(())
    } else {
        synvoid_ipc::ipc_framing::write_message(writer, message).await
    }
}

async fn recv_framed_async_cpu_task_message<R>(
    reader: &mut R,
    signer: Option<&Arc<synvoid_ipc::IpcSigner>>,
    buffer: &mut Vec<u8>,
) -> io::Result<Option<Message>>
where
    R: AsyncRead + Unpin,
{
    if let Some(signer) = signer {
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }

        let total_len = u32::from_be_bytes(len_buf) as usize;
        if total_len > synvoid_ipc::ipc_signed::MAX_IPC_MESSAGE_SIZE {
            synvoid_ipc::ipc_signed::increment_oversized_rejected();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "signed message too large",
            ));
        }

        let mut raw = vec![0u8; total_len];
        reader
            .read_exact(&mut raw)
            .await
            .map_err(io::Error::other)?;
        synvoid_ipc::SignedIpcMessage::deserialize_signed(&raw, signer).map(Some)
    } else {
        synvoid_ipc::ipc_framing::read_message(reader, buffer).await
    }
}

fn async_cpu_task_message_request_id(message: &Message) -> Option<u64> {
    match message {
        Message::MinifyRequest { request_id, .. }
        | Message::PoisonImageRequest { request_id, .. }
        | Message::GetCompressedRequest { request_id, .. }
        | Message::CpuTaskRequest { request_id, .. }
        | Message::MinifyResponse { request_id, .. }
        | Message::MinifyError { request_id, .. }
        | Message::PoisonImageResponse { request_id, .. }
        | Message::PoisonImageError { request_id, .. }
        | Message::GetCompressedResponse { request_id, .. }
        | Message::CpuTaskResponse { request_id, .. }
        | Message::CpuTaskError { request_id, .. } => Some(*request_id),
        _ => None,
    }
}

async fn close_and_drain_async_cpu_task_connection(
    closed: &Arc<AtomicBool>,
    pending: &std::sync::Mutex<
        HashMap<u64, oneshot::Sender<Result<Message, AsyncCpuTaskDispatchError>>>,
    >,
    error: AsyncCpuTaskDispatchError,
) {
    closed.store(true, Ordering::Release);
    let drained = {
        let mut guard = pending.lock().expect("cpu task pending lock poisoned");
        guard.drain().collect::<Vec<_>>()
    };

    for (_, sender) in drained {
        let _ = sender.send(Err(error.clone()));
    }
}

async fn handle_async_cpu_task_command<W>(
    command: AsyncCpuTaskCommand,
    writer: &mut W,
    signer: Option<&Arc<synvoid_ipc::IpcSigner>>,
    pending: &std::sync::Mutex<
        HashMap<u64, oneshot::Sender<Result<Message, AsyncCpuTaskDispatchError>>>,
    >,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    match command {
        AsyncCpuTaskCommand::Submit {
            request,
            response_tx,
        } => {
            let Some(request_id) = async_cpu_task_message_request_id(&request) else {
                let _ = response_tx.send(Err(AsyncCpuTaskDispatchError::SendFailed(
                    "CPU task request missing request_id".to_string(),
                )));
                return Ok(());
            };

            {
                let mut guard = pending.lock().expect("cpu task pending lock poisoned");
                guard.insert(request_id, response_tx);
            }

            if let Err(e) = send_framed_async_cpu_task_message(writer, signer, &request).await {
                if let Some(sender) = pending
                    .lock()
                    .expect("cpu task pending lock poisoned")
                    .remove(&request_id)
                {
                    let _ = sender.send(Err(AsyncCpuTaskDispatchError::SendFailed(e.to_string())));
                }
                return Err(e);
            }
            Ok(())
        }
        AsyncCpuTaskCommand::Cancel {
            request_id,
            task_kind,
        } => {
            let _ = pending
                .lock()
                .expect("cpu task pending lock poisoned")
                .remove(&request_id);

            let cancel = Message::CpuTaskCancel {
                request_id,
                task_kind,
            };
            send_framed_async_cpu_task_message(writer, signer, &cancel).await
        }
    }
}

async fn run_async_cpu_task_connection_driver<R, W>(
    mut read_half: R,
    mut write_half: W,
    signer: Option<Arc<synvoid_ipc::IpcSigner>>,
    mut command_rx: mpsc::UnboundedReceiver<AsyncCpuTaskCommand>,
    closed: Arc<AtomicBool>,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let pending: std::sync::Mutex<
        HashMap<u64, oneshot::Sender<Result<Message, AsyncCpuTaskDispatchError>>>,
    > = std::sync::Mutex::new(HashMap::new());
    let mut read_buffer = Vec::with_capacity(64 * 1024);
    let mut commands_closed = false;

    loop {
        if closed.load(Ordering::Acquire) {
            break;
        }

        let pending_empty = pending
            .lock()
            .expect("cpu task pending lock poisoned")
            .is_empty();

        if pending_empty {
            if commands_closed {
                break;
            }

            match command_rx.recv().await {
                Some(command) => {
                    if let Err(e) = handle_async_cpu_task_command(
                        command,
                        &mut write_half,
                        signer.as_ref(),
                        &pending,
                    )
                    .await
                    {
                        close_and_drain_async_cpu_task_connection(
                            &closed,
                            &pending,
                            AsyncCpuTaskDispatchError::ReceiveFailed(e.to_string()),
                        )
                        .await;
                        break;
                    }
                }
                None => {
                    commands_closed = true;
                }
            }
            continue;
        }

        if commands_closed {
            match recv_framed_async_cpu_task_message(
                &mut read_half,
                signer.as_ref(),
                &mut read_buffer,
            )
            .await
            {
                Ok(Some(message)) => {
                    if let Some(request_id) = async_cpu_task_message_request_id(&message) {
                        if let Some(sender) = pending
                            .lock()
                            .expect("cpu task pending lock poisoned")
                            .remove(&request_id)
                        {
                            let _ = sender.send(Ok(message));
                        }
                    }
                }
                Ok(None) => {
                    close_and_drain_async_cpu_task_connection(
                        &closed,
                        &pending,
                        AsyncCpuTaskDispatchError::ReceiveFailed(
                            "CPU task connection closed".to_string(),
                        ),
                    )
                    .await;
                    break;
                }
                Err(e) => {
                    close_and_drain_async_cpu_task_connection(
                        &closed,
                        &pending,
                        AsyncCpuTaskDispatchError::ReceiveFailed(e.to_string()),
                    )
                    .await;
                    break;
                }
            }
            continue;
        }

        tokio::select! {
            maybe_command = command_rx.recv() => {
                match maybe_command {
                    Some(command) => {
                        if let Err(e) = handle_async_cpu_task_command(
                            command,
                            &mut write_half,
                            signer.as_ref(),
                            &pending,
                        ).await {
                            close_and_drain_async_cpu_task_connection(
                                &closed,
                                &pending,
                                AsyncCpuTaskDispatchError::ReceiveFailed(e.to_string()),
                            ).await;
                            break;
                        }
                    }
                    None => {
                        commands_closed = true;
                    }
                }
            }
            message = recv_framed_async_cpu_task_message(
                &mut read_half,
                signer.as_ref(),
                &mut read_buffer,
            ) => {
                match message {
                    Ok(Some(message)) => {
                        if let Some(request_id) = async_cpu_task_message_request_id(&message) {
                            if let Some(sender) = pending
                                .lock()
                                .expect("cpu task pending lock poisoned")
                                .remove(&request_id)
                            {
                                let _ = sender.send(Ok(message));
                            }
                        }
                    }
                    Ok(None) => {
                        close_and_drain_async_cpu_task_connection(
                            &closed,
                            &pending,
                            AsyncCpuTaskDispatchError::ReceiveFailed(
                                "CPU task connection closed".to_string(),
                            ),
                        ).await;
                        break;
                    }
                    Err(e) => {
                        close_and_drain_async_cpu_task_connection(
                            &closed,
                            &pending,
                            AsyncCpuTaskDispatchError::ReceiveFailed(e.to_string()),
                        ).await;
                        break;
                    }
                }
            }
        }
    }

    closed.store(true, Ordering::Release);
    let drained = {
        let mut guard = pending.lock().expect("cpu task pending lock poisoned");
        guard.drain().collect::<Vec<_>>()
    };
    for (_, sender) in drained {
        let _ = sender.send(Err(AsyncCpuTaskDispatchError::ReceiveFailed(
            "CPU task connection closed".to_string(),
        )));
    }
}

fn map_async_cpu_task_dispatch_error_for_minifier(
    err: AsyncCpuTaskDispatchError,
) -> MinifierClientError {
    match err {
        AsyncCpuTaskDispatchError::ConnectionFailed(e) => MinifierClientError::ConnectionFailed(e),
        AsyncCpuTaskDispatchError::SendFailed(e) => MinifierClientError::SendFailed(e),
        AsyncCpuTaskDispatchError::ReceiveFailed(e) => MinifierClientError::ReceiveFailed(e),
        AsyncCpuTaskDispatchError::Timeout => MinifierClientError::Timeout,
    }
}

#[derive(Clone)]
pub struct AsyncMinifierClient {
    socket_path: PathBuf,
    timeout_ms: u64,
    pool: AsyncCpuTaskConnectionPool,
}

#[derive(Clone)]
struct AsyncCpuTaskConnectionPool {
    socket_path: PathBuf,
    max_connections: usize,
    max_in_flight_per_connection: usize,
    connections: Arc<tokio::sync::Mutex<Vec<Arc<AsyncCpuTaskConnection>>>>,
    total_in_flight: Arc<AtomicUsize>,
    evictions: Arc<AtomicU64>,
}

#[derive(Debug, Clone, Copy)]
pub struct AsyncCpuTaskPoolStats {
    pub active_in_flight: usize,
    pub pooled_connections: usize,
    pub evictions: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct GlobalAsyncCpuOffloadStats {
    pub active_in_flight: usize,
    pub pooled_connections: usize,
    pub evictions: u64,
    pub submissions: u64,
    pub timeouts: u64,
    pub rejections: u64,
    pub fallbacks: u64,
}

pub fn get_global_async_cpu_offload_stats() -> GlobalAsyncCpuOffloadStats {
    GlobalAsyncCpuOffloadStats {
        active_in_flight: GLOBAL_ASYNC_CPU_OFFLOAD_IN_FLIGHT.load(Ordering::Acquire),
        pooled_connections: GLOBAL_ASYNC_CPU_OFFLOAD_CONNECTIONS.load(Ordering::Acquire),
        evictions: GLOBAL_ASYNC_CPU_OFFLOAD_EVICTIONS.load(Ordering::Acquire),
        submissions: GLOBAL_ASYNC_CPU_OFFLOAD_SUBMISSIONS.load(Ordering::Acquire),
        timeouts: GLOBAL_ASYNC_CPU_OFFLOAD_TIMEOUTS.load(Ordering::Acquire),
        rejections: GLOBAL_ASYNC_CPU_OFFLOAD_REJECTIONS.load(Ordering::Acquire),
        fallbacks: GLOBAL_ASYNC_CPU_OFFLOAD_FALLBACKS.load(Ordering::Acquire),
    }
}

fn record_cpu_offload_submission() {
    GLOBAL_ASYNC_CPU_OFFLOAD_SUBMISSIONS.fetch_add(1, Ordering::AcqRel);
    counter!("synvoid.static.cpu_offload.submissions").increment(1);
}

fn record_cpu_offload_timeout() {
    GLOBAL_ASYNC_CPU_OFFLOAD_TIMEOUTS.fetch_add(1, Ordering::AcqRel);
    counter!("synvoid.static.cpu_offload.task_timeouts").increment(1);
}

fn record_cpu_offload_rejection() {
    GLOBAL_ASYNC_CPU_OFFLOAD_REJECTIONS.fetch_add(1, Ordering::AcqRel);
    counter!("synvoid.static.cpu_offload.task_rejections").increment(1);
}

pub fn record_cpu_offload_fallback() {
    GLOBAL_ASYNC_CPU_OFFLOAD_FALLBACKS.fetch_add(1, Ordering::AcqRel);
    counter!("synvoid.static.cpu_offload.fallbacks").increment(1);
}

fn send_cpu_task_cancel_sync(
    ipc: &mut IpcStream,
    request_id: u64,
    task_kind: synvoid_ipc::CpuTaskKind,
) {
    let _ = ipc.send(&Message::CpuTaskCancel {
        request_id,
        task_kind,
    });
}

impl AsyncCpuTaskConnectionPool {
    fn new(
        socket_path: PathBuf,
        max_connections: usize,
        max_in_flight_per_connection: usize,
    ) -> Self {
        Self {
            socket_path,
            max_connections: max_connections.max(1),
            max_in_flight_per_connection: max_in_flight_per_connection.max(1),
            connections: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            total_in_flight: Arc::new(AtomicUsize::new(0)),
            evictions: Arc::new(AtomicU64::new(0)),
        }
    }

    async fn acquire_for_task_kind(
        &self,
        task_kind: synvoid_ipc::CpuTaskKind,
        acquire_timeout_ms: u64,
    ) -> Result<Arc<AsyncCpuTaskConnection>, MinifierClientError> {
        let max_in_flight_for_task = match task_kind {
            // Keep expensive scans single-flight per connection to avoid
            // head-of-line blocking for other task types.
            synvoid_ipc::CpuTaskKind::YaraScan => 1,
            _ => self.max_in_flight_per_connection,
        };
        let start = std::time::Instant::now();

        loop {
            if start.elapsed().as_millis() as u64 > acquire_timeout_ms {
                record_cpu_offload_rejection();
                return Err(MinifierClientError::Backpressure(
                    "CPU task pool saturated while waiting for an available connection".to_string(),
                ));
            }

            if let Some(conn) = self.try_acquire_existing(max_in_flight_for_task).await {
                record_cpu_offload_submission();
                return Ok(conn);
            }

            if let Some(conn) = self.try_connect_new(max_in_flight_for_task).await? {
                record_cpu_offload_submission();
                return Ok(conn);
            }

            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    async fn try_acquire_existing(
        &self,
        max_in_flight_for_task: usize,
    ) -> Option<Arc<AsyncCpuTaskConnection>> {
        let guard = self.connections.lock().await;
        let mut best_conn: Option<&Arc<AsyncCpuTaskConnection>> = None;
        let mut best_depth = usize::MAX;

        for conn in guard.iter() {
            if conn.is_closed() {
                continue;
            }
            let depth = conn.in_flight.load(Ordering::Acquire);
            if depth < max_in_flight_for_task && depth < best_depth {
                best_depth = depth;
                best_conn = Some(conn);
            }
        }

        if let Some(conn) = best_conn {
            conn.in_flight.fetch_add(1, Ordering::AcqRel);
            let total = self.total_in_flight.fetch_add(1, Ordering::AcqRel) + 1;
            GLOBAL_ASYNC_CPU_OFFLOAD_IN_FLIGHT.fetch_add(1, Ordering::AcqRel);
            gauge!("synvoid.static.cpu_offload.pool_in_flight").set(total as f64);
            return Some(conn.clone());
        }
        None
    }

    async fn try_connect_new(
        &self,
        max_in_flight_for_task: usize,
    ) -> Result<Option<Arc<AsyncCpuTaskConnection>>, MinifierClientError> {
        let can_create = {
            let guard = self.connections.lock().await;
            guard.len() < self.max_connections
        };
        if !can_create {
            return Ok(None);
        }
        let conn = AsyncCpuTaskConnection::connect(&self.socket_path).await?;

        let mut guard = self.connections.lock().await;
        if guard.len() < self.max_connections {
            conn.in_flight.store(1, Ordering::Release);
            guard.push(conn.clone());
            GLOBAL_ASYNC_CPU_OFFLOAD_CONNECTIONS.fetch_add(1, Ordering::AcqRel);
            gauge!("synvoid.static.cpu_offload.pool_connections").set(guard.len() as f64);
            let total = self.total_in_flight.fetch_add(1, Ordering::AcqRel) + 1;
            GLOBAL_ASYNC_CPU_OFFLOAD_IN_FLIGHT.fetch_add(1, Ordering::AcqRel);
            gauge!("synvoid.static.cpu_offload.pool_in_flight").set(total as f64);
            Ok(Some(conn))
        } else if let Some(existing) = guard.iter().find(|c| {
            !c.is_closed() && c.in_flight.load(Ordering::Acquire) < max_in_flight_for_task
        }) {
            existing.in_flight.fetch_add(1, Ordering::AcqRel);
            let total = self.total_in_flight.fetch_add(1, Ordering::AcqRel) + 1;
            GLOBAL_ASYNC_CPU_OFFLOAD_IN_FLIGHT.fetch_add(1, Ordering::AcqRel);
            gauge!("synvoid.static.cpu_offload.pool_in_flight").set(total as f64);
            Ok(Some(existing.clone()))
        } else {
            Ok(None)
        }
    }

    fn release(&self, conn: &AsyncCpuTaskConnection) {
        if conn
            .in_flight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_sub(1))
            .is_ok()
        {
            let _ = self
                .total_in_flight
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_sub(1));
            let _ = GLOBAL_ASYNC_CPU_OFFLOAD_IN_FLIGHT.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |v| v.checked_sub(1),
            );
            gauge!("synvoid.static.cpu_offload.pool_in_flight")
                .set(self.total_in_flight.load(Ordering::Acquire) as f64);
        }
    }

    async fn evict(&self, conn: &Arc<AsyncCpuTaskConnection>) {
        let mut guard = self.connections.lock().await;
        let before = guard.len();
        guard.retain(|candidate| !Arc::ptr_eq(candidate, conn));
        if guard.len() < before {
            self.evictions.fetch_add(1, Ordering::AcqRel);
            GLOBAL_ASYNC_CPU_OFFLOAD_EVICTIONS.fetch_add(1, Ordering::AcqRel);
            let _ = GLOBAL_ASYNC_CPU_OFFLOAD_CONNECTIONS.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |v| v.checked_sub(1),
            );
            counter!("synvoid.static.cpu_offload.pool_evictions").increment(1);
        }
        gauge!("synvoid.static.cpu_offload.pool_connections").set(guard.len() as f64);
    }

    async fn stats(&self) -> AsyncCpuTaskPoolStats {
        let guard = self.connections.lock().await;
        AsyncCpuTaskPoolStats {
            active_in_flight: self.total_in_flight.load(Ordering::Acquire),
            pooled_connections: guard.len(),
            evictions: self.evictions.load(Ordering::Acquire),
        }
    }
}

impl AsyncMinifierClient {
    pub fn new(socket_path: PathBuf) -> Self {
        let limits = AsyncCpuPoolLimits::from_env_or_default();
        Self {
            pool: AsyncCpuTaskConnectionPool::new(
                socket_path.clone(),
                limits.max_connections,
                limits.max_in_flight_per_connection,
            ),
            socket_path,
            timeout_ms: 5000,
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    pub async fn request_wasm_transform(
        &self,
        site_id: &str,
        plugin_names: &[String],
        status_code: u16,
        body: Vec<u8>,
        env: std::collections::HashMap<String, String>,
        policy: synvoid_ipc::CpuTaskPolicy,
        timeout_ms: u64,
    ) -> Result<(u16, Vec<u8>), MinifierClientError> {
        let connection = self
            .pool
            .acquire_for_task_kind(synvoid_ipc::CpuTaskKind::WasmExecute, self.timeout_ms)
            .await?;

        let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let deadline_unix_ms = synvoid_utils::current_timestamp()
            .saturating_mul(1000)
            .saturating_add(timeout_ms);

        let payload_size = body.len();
        let request = Message::CpuTaskRequest {
            request_id,
            task_kind: synvoid_ipc::CpuTaskKind::WasmExecute,
            priority: synvoid_ipc::CpuTaskPriority::Normal,
            policy,
            deadline_unix_ms,
            payload_size_limit: (payload_size as u64).max(1024 * 1024),
            output_size_limit: (payload_size as u64 + 65536).max(2 * 1024 * 1024),
            file_payload_path: None,
            payload: synvoid_ipc::CpuTaskPayload::WasmTransformResponse {
                site_id: site_id.to_string(),
                plugin_names: plugin_names.to_vec(),
                status_code,
                body,
                env,
                timeout_ms,
            },
        };

        let response = match connection
            .submit_with_timeout(
                request,
                request_id,
                synvoid_ipc::CpuTaskKind::WasmExecute,
                timeout_ms,
            )
            .await
        {
            Ok(message) => message,
            Err(err) => {
                let is_timeout = matches!(err, AsyncCpuTaskDispatchError::Timeout);
                if is_timeout {
                    record_cpu_offload_timeout();
                }
                self.pool.release(&connection);
                if is_timeout && connection.is_closed() {
                    self.pool.evict(&connection).await;
                } else {
                    self.pool.evict(&connection).await;
                }
                return Err(map_async_cpu_task_dispatch_error_for_minifier(err));
            }
        };

        self.pool.release(&connection);

        match response {
            Message::CpuTaskResponse {
                result: synvoid_ipc::CpuTaskResult::WasmTransformResponse { status_code, body },
                ..
            } => Ok((status_code, body)),
            Message::CpuTaskError { message, .. } => {
                Err(MinifierClientError::MinificationFailed(message))
            }
            _ => Err(MinifierClientError::ReceiveFailed(
                "Unexpected response type".to_string(),
            )),
        }
    }

    pub async fn request_minify(
        &self,
        site_id: &str,
        path: &str,
        encoding: Option<&str>,
    ) -> Result<MinifyResult, MinifierClientError> {
        let connection = self
            .pool
            .acquire_for_task_kind(synvoid_ipc::CpuTaskKind::Minify, self.timeout_ms)
            .await?;

        let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let deadline_unix_ms = synvoid_utils::current_timestamp()
            .saturating_mul(1000)
            .saturating_add(self.timeout_ms);

        let request = Message::CpuTaskRequest {
            request_id,
            task_kind: synvoid_ipc::CpuTaskKind::Minify,
            priority: synvoid_ipc::CpuTaskPriority::Normal,
            policy: synvoid_ipc::CpuTaskPolicy::SkipTransform,
            deadline_unix_ms,
            payload_size_limit: 1024 * 1024,
            output_size_limit: 16 * 1024 * 1024,
            file_payload_path: None,
            payload: synvoid_ipc::CpuTaskPayload::Minify {
                site_id: site_id.to_string(),
                path: path.to_string(),
                encoding: encoding.map(|s| s.to_string()),
            },
        };

        let response = match connection
            .submit_with_timeout(
                request,
                request_id,
                synvoid_ipc::CpuTaskKind::Minify,
                self.timeout_ms,
            )
            .await
        {
            Ok(message) => message,
            Err(err) => {
                let is_timeout = matches!(err, AsyncCpuTaskDispatchError::Timeout);
                if is_timeout {
                    record_cpu_offload_timeout();
                }
                self.pool.release(&connection);
                if is_timeout {
                    if connection.is_closed() {
                        self.pool.evict(&connection).await;
                    }
                } else {
                    self.pool.evict(&connection).await;
                }
                return Err(map_async_cpu_task_dispatch_error_for_minifier(err));
            }
        };

        self.pool.release(&connection);

        match response {
            Message::MinifyResponse {
                request_id: resp_id,
                site_id: _,
                path: _,
                content,
                content_type,
                encoding: resp_encoding,
                queued_encodings,
            } => {
                if resp_id == request_id {
                    return Ok(MinifyResult {
                        content: Bytes::from(content),
                        content_type,
                        encoding: resp_encoding,
                        queued_encodings,
                    });
                }
            }
            Message::CpuTaskResponse {
                request_id: resp_id,
                task_kind: synvoid_ipc::CpuTaskKind::Minify,
                result:
                    synvoid_ipc::CpuTaskResult::Minify {
                        content,
                        content_type,
                        encoding: resp_encoding,
                        queued_encodings,
                        ..
                    },
            } => {
                if resp_id == request_id {
                    return Ok(MinifyResult {
                        content: Bytes::from(content),
                        content_type,
                        encoding: resp_encoding,
                        queued_encodings,
                    });
                }
            }
            Message::MinifyError {
                request_id: resp_id,
                error,
            } => {
                if resp_id == request_id {
                    return Err(MinifierClientError::MinificationFailed(error));
                }
            }
            Message::CpuTaskError {
                request_id: resp_id,
                code,
                message,
                ..
            } => {
                if resp_id == request_id {
                    return Err(map_cpu_task_error_for_minifier(code, message));
                }
            }
            _ => {}
        }

        Err(MinifierClientError::ReceiveFailed(
            "CPU task response channel closed before matching response".to_string(),
        ))
    }

    pub async fn get_compressed(
        &self,
        site_id: &str,
        path: &str,
        encoding: &str,
    ) -> Result<Bytes, MinifierClientError> {
        let connection = self
            .pool
            .acquire_for_task_kind(synvoid_ipc::CpuTaskKind::GetCompressed, self.timeout_ms)
            .await?;

        let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let deadline_unix_ms = synvoid_utils::current_timestamp()
            .saturating_mul(1000)
            .saturating_add(self.timeout_ms);

        let request = Message::CpuTaskRequest {
            request_id,
            task_kind: synvoid_ipc::CpuTaskKind::GetCompressed,
            priority: synvoid_ipc::CpuTaskPriority::Normal,
            policy: synvoid_ipc::CpuTaskPolicy::SkipTransform,
            deadline_unix_ms,
            payload_size_limit: 1024 * 1024,
            output_size_limit: 16 * 1024 * 1024,
            file_payload_path: None,
            payload: synvoid_ipc::CpuTaskPayload::GetCompressed {
                site_id: site_id.to_string(),
                path: path.to_string(),
                encoding: encoding.to_string(),
            },
        };

        let response = match connection
            .submit_with_timeout(
                request,
                request_id,
                synvoid_ipc::CpuTaskKind::GetCompressed,
                self.timeout_ms,
            )
            .await
        {
            Ok(message) => message,
            Err(err) => {
                let is_timeout = matches!(err, AsyncCpuTaskDispatchError::Timeout);
                if is_timeout {
                    record_cpu_offload_timeout();
                }
                self.pool.release(&connection);
                if is_timeout {
                    if connection.is_closed() {
                        self.pool.evict(&connection).await;
                    }
                } else {
                    self.pool.evict(&connection).await;
                }
                return Err(map_async_cpu_task_dispatch_error_for_minifier(err));
            }
        };

        self.pool.release(&connection);

        match response {
            Message::GetCompressedResponse {
                request_id: resp_id,
                content,
            } => {
                if resp_id == request_id {
                    return Ok(Bytes::from(content));
                }
            }
            Message::CpuTaskResponse {
                request_id: resp_id,
                task_kind: synvoid_ipc::CpuTaskKind::GetCompressed,
                result: synvoid_ipc::CpuTaskResult::GetCompressed { content },
            } => {
                if resp_id == request_id {
                    return Ok(Bytes::from(content));
                }
            }
            Message::MinifyError {
                request_id: resp_id,
                error,
            } => {
                if resp_id == request_id {
                    return Err(MinifierClientError::MinificationFailed(error));
                }
            }
            Message::CpuTaskError {
                request_id: resp_id,
                code,
                message,
                ..
            } => {
                if resp_id == request_id {
                    return Err(map_cpu_task_error_for_minifier(code, message));
                }
            }
            _ => {}
        }

        Err(MinifierClientError::ReceiveFailed(
            "CPU task response channel closed before matching response".to_string(),
        ))
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

    pub async fn pool_stats(&self) -> AsyncCpuTaskPoolStats {
        self.pool.stats().await
    }
}

static IMAGE_RIGHTS_REQUEST_ID: AtomicU64 = AtomicU64::new(1);
const FILE_BACKED_PAYLOAD_THRESHOLD_BYTES: usize = 256 * 1024;

#[derive(Debug)]
pub enum ImageRightsClientError {
    ConnectionFailed(String),
    SendFailed(String),
    ReceiveFailed(String),
    Timeout,
    Backpressure(String),
    PayloadTooLarge(String),
    InvalidRequest(String),
    MarkingFailed(String),
}

impl std::fmt::Display for ImageRightsClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageRightsClientError::ConnectionFailed(e) => write!(f, "Connection failed: {}", e),
            ImageRightsClientError::SendFailed(e) => write!(f, "Send failed: {}", e),
            ImageRightsClientError::ReceiveFailed(e) => write!(f, "Receive failed: {}", e),
            ImageRightsClientError::Timeout => write!(f, "Request timed out"),
            ImageRightsClientError::Backpressure(e) => write!(f, "CPU task backpressure: {}", e),
            ImageRightsClientError::PayloadTooLarge(e) => {
                write!(f, "CPU task payload/output too large: {}", e)
            }
            ImageRightsClientError::InvalidRequest(e) => {
                write!(f, "Invalid CPU task request: {}", e)
            }
            ImageRightsClientError::MarkingFailed(e) => write!(f, "Poisoning failed: {}", e),
        }
    }
}

fn map_cpu_task_error_for_minifier(
    code: synvoid_ipc::CpuTaskErrorCode,
    message: String,
) -> MinifierClientError {
    match code {
        synvoid_ipc::CpuTaskErrorCode::Timeout => {
            record_cpu_offload_timeout();
            MinifierClientError::Timeout
        }
        synvoid_ipc::CpuTaskErrorCode::QueueSaturated => {
            record_cpu_offload_rejection();
            MinifierClientError::Backpressure(message)
        }
        synvoid_ipc::CpuTaskErrorCode::PayloadTooLarge => {
            record_cpu_offload_rejection();
            MinifierClientError::PayloadTooLarge(message)
        }
        synvoid_ipc::CpuTaskErrorCode::InvalidRequest => {
            record_cpu_offload_rejection();
            MinifierClientError::InvalidRequest(message)
        }
        synvoid_ipc::CpuTaskErrorCode::InternalError => {
            MinifierClientError::MinificationFailed(message)
        }
    }
}

fn map_cpu_task_error_for_image_rights(
    code: synvoid_ipc::CpuTaskErrorCode,
    message: String,
) -> ImageRightsClientError {
    match code {
        synvoid_ipc::CpuTaskErrorCode::Timeout => {
            record_cpu_offload_timeout();
            ImageRightsClientError::Timeout
        }
        synvoid_ipc::CpuTaskErrorCode::QueueSaturated => {
            record_cpu_offload_rejection();
            ImageRightsClientError::Backpressure(message)
        }
        synvoid_ipc::CpuTaskErrorCode::PayloadTooLarge => {
            record_cpu_offload_rejection();
            ImageRightsClientError::PayloadTooLarge(message)
        }
        synvoid_ipc::CpuTaskErrorCode::InvalidRequest => {
            record_cpu_offload_rejection();
            ImageRightsClientError::InvalidRequest(message)
        }
        synvoid_ipc::CpuTaskErrorCode::InternalError => {
            ImageRightsClientError::MarkingFailed(message)
        }
    }
}

fn map_pool_acquire_error_for_image_rights(err: MinifierClientError) -> ImageRightsClientError {
    match err {
        MinifierClientError::ConnectionFailed(e) => ImageRightsClientError::ConnectionFailed(e),
        MinifierClientError::SendFailed(e) => ImageRightsClientError::SendFailed(e),
        MinifierClientError::ReceiveFailed(e) => ImageRightsClientError::ReceiveFailed(e),
        MinifierClientError::Timeout => ImageRightsClientError::Timeout,
        MinifierClientError::Backpressure(e) => ImageRightsClientError::Backpressure(e),
        MinifierClientError::PayloadTooLarge(e) => ImageRightsClientError::PayloadTooLarge(e),
        MinifierClientError::InvalidRequest(e) => ImageRightsClientError::InvalidRequest(e),
        MinifierClientError::MinificationFailed(e) => ImageRightsClientError::MarkingFailed(e),
    }
}

fn map_pool_acquire_error_for_yara(err: MinifierClientError) -> YaraScanClientError {
    match err {
        MinifierClientError::ConnectionFailed(e) => YaraScanClientError::ConnectionFailed(e),
        MinifierClientError::SendFailed(e) => YaraScanClientError::SendFailed(e),
        MinifierClientError::ReceiveFailed(e) => YaraScanClientError::ReceiveFailed(e),
        MinifierClientError::Timeout => YaraScanClientError::Timeout,
        MinifierClientError::Backpressure(e) => YaraScanClientError::Backpressure(e),
        MinifierClientError::PayloadTooLarge(e) => YaraScanClientError::PayloadTooLarge(e),
        MinifierClientError::InvalidRequest(e) => YaraScanClientError::InvalidRequest(e),
        MinifierClientError::MinificationFailed(e) => YaraScanClientError::ScanFailed(e),
    }
}

impl std::error::Error for ImageRightsClientError {}

#[derive(Clone)]
pub struct ImageRightsClient {
    socket_path: PathBuf,
    timeout_ms: u64,
    pool: AsyncCpuTaskConnectionPool,
}

impl ImageRightsClient {
    pub fn new(socket_path: PathBuf) -> Self {
        let limits = AsyncCpuPoolLimits::from_env_or_default();
        Self {
            pool: AsyncCpuTaskConnectionPool::new(
                socket_path.clone(),
                limits.max_connections,
                limits.max_in_flight_per_connection,
            ),
            socket_path,
            timeout_ms: 5000,
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    pub async fn mark_image_rights(
        &self,
        site_id: &str,
        body: Vec<u8>,
        last_modified: Option<String>,
        level: Option<String>,
        intensity: Option<f32>,
        seed: Option<u64>,
        max_dimension: Option<u32>,
        jpeg_quality: Option<u8>,
    ) -> Result<Vec<u8>, ImageRightsClientError> {
        let connection = self
            .pool
            .acquire_for_task_kind(synvoid_ipc::CpuTaskKind::PoisonImage, self.timeout_ms)
            .await
            .map_err(map_pool_acquire_error_for_image_rights)?;

        let request_id = IMAGE_RIGHTS_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let deadline_unix_ms = synvoid_utils::current_timestamp()
            .saturating_mul(1000)
            .saturating_add(self.timeout_ms);
        let mut temp_payload_file: Option<NamedTempFile> = None;
        let (payload_body, file_payload_path) = if body.len() > FILE_BACKED_PAYLOAD_THRESHOLD_BYTES
        {
            let mut temp_file = match Builder::new()
                .prefix("synvoid-cpu-task-")
                .tempfile_in(std::env::temp_dir())
            {
                Ok(file) => file,
                Err(e) => {
                    self.pool.release(&connection);
                    return Err(ImageRightsClientError::SendFailed(e.to_string()));
                }
            };
            if let Err(e) = temp_file.write_all(&body) {
                self.pool.release(&connection);
                return Err(ImageRightsClientError::SendFailed(e.to_string()));
            }
            let payload_path = temp_file.path().to_string_lossy().to_string();
            temp_payload_file = Some(temp_file);
            (Vec::new(), Some(payload_path))
        } else {
            (body, None)
        };

        let request = synvoid_ipc::Message::CpuTaskRequest {
            request_id,
            task_kind: synvoid_ipc::CpuTaskKind::PoisonImage,
            priority: synvoid_ipc::CpuTaskPriority::Normal,
            policy: synvoid_ipc::CpuTaskPolicy::DegradeToInlineSmallOnly,
            deadline_unix_ms,
            payload_size_limit: 64 * 1024 * 1024,
            output_size_limit: 64 * 1024 * 1024,
            file_payload_path,
            payload: synvoid_ipc::CpuTaskPayload::PoisonImage {
                site_id: site_id.to_string(),
                body: payload_body,
                last_modified,
                level,
                intensity,
                seed,
                max_dimension,
                jpeg_quality,
            },
        };

        let _keep_file_until_response = temp_payload_file;

        let response = match connection
            .submit_with_timeout(
                request,
                request_id,
                synvoid_ipc::CpuTaskKind::PoisonImage,
                self.timeout_ms,
            )
            .await
        {
            Ok(message) => message,
            Err(err) => {
                let is_timeout = matches!(err, AsyncCpuTaskDispatchError::Timeout);
                if is_timeout {
                    record_cpu_offload_timeout();
                }
                self.pool.release(&connection);
                if is_timeout {
                    if connection.is_closed() {
                        self.pool.evict(&connection).await;
                    }
                } else {
                    self.pool.evict(&connection).await;
                }
                return Err(map_pool_acquire_error_for_image_rights(
                    map_async_cpu_task_dispatch_error_for_minifier(err),
                ));
            }
        };

        self.pool.release(&connection);

        match response {
            synvoid_ipc::Message::PoisonImageResponse {
                request_id: resp_id,
                poisoned_body,
            } => {
                if resp_id == request_id {
                    return Ok(poisoned_body);
                }
            }
            synvoid_ipc::Message::CpuTaskResponse {
                request_id: resp_id,
                task_kind: synvoid_ipc::CpuTaskKind::PoisonImage,
                result: synvoid_ipc::CpuTaskResult::PoisonImage { poisoned_body },
            } => {
                if resp_id == request_id {
                    return Ok(poisoned_body);
                }
            }
            synvoid_ipc::Message::PoisonImageError {
                request_id: resp_id,
                error,
            } => {
                if resp_id == request_id {
                    return Err(ImageRightsClientError::MarkingFailed(error));
                }
            }
            synvoid_ipc::Message::CpuTaskError {
                request_id: resp_id,
                code,
                message,
                ..
            } => {
                if resp_id == request_id {
                    return Err(map_cpu_task_error_for_image_rights(code, message));
                }
            }
            _ => {}
        }

        Err(ImageRightsClientError::ReceiveFailed(
            "CPU task response channel closed before matching response".to_string(),
        ))
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
                .recv_with_timeout::<synvoid_ipc::Message>(100)
                .await
                .is_ok();
        }
        false
    }

    pub async fn pool_stats(&self) -> AsyncCpuTaskPoolStats {
        self.pool.stats().await
    }
}

static YARA_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum YaraScanClientError {
    ConnectionFailed(String),
    SendFailed(String),
    ReceiveFailed(String),
    Timeout,
    Backpressure(String),
    PayloadTooLarge(String),
    InvalidRequest(String),
    ScanFailed(String),
}

impl std::fmt::Display for YaraScanClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            YaraScanClientError::ConnectionFailed(e) => write!(f, "Connection failed: {}", e),
            YaraScanClientError::SendFailed(e) => write!(f, "Send failed: {}", e),
            YaraScanClientError::ReceiveFailed(e) => write!(f, "Receive failed: {}", e),
            YaraScanClientError::Timeout => write!(f, "Request timed out"),
            YaraScanClientError::Backpressure(e) => write!(f, "CPU task backpressure: {}", e),
            YaraScanClientError::PayloadTooLarge(e) => {
                write!(f, "CPU task payload/output too large: {}", e)
            }
            YaraScanClientError::InvalidRequest(e) => {
                write!(f, "Invalid CPU task request: {}", e)
            }
            YaraScanClientError::ScanFailed(e) => write!(f, "YARA scan failed: {}", e),
        }
    }
}

impl std::error::Error for YaraScanClientError {}

fn map_cpu_task_error_for_yara(
    code: synvoid_ipc::CpuTaskErrorCode,
    message: String,
) -> YaraScanClientError {
    match code {
        synvoid_ipc::CpuTaskErrorCode::Timeout => {
            record_cpu_offload_timeout();
            YaraScanClientError::Timeout
        }
        synvoid_ipc::CpuTaskErrorCode::QueueSaturated => {
            record_cpu_offload_rejection();
            YaraScanClientError::Backpressure(message)
        }
        synvoid_ipc::CpuTaskErrorCode::PayloadTooLarge => {
            record_cpu_offload_rejection();
            YaraScanClientError::PayloadTooLarge(message)
        }
        synvoid_ipc::CpuTaskErrorCode::InvalidRequest => {
            record_cpu_offload_rejection();
            YaraScanClientError::InvalidRequest(message)
        }
        synvoid_ipc::CpuTaskErrorCode::InternalError => YaraScanClientError::ScanFailed(message),
    }
}

#[derive(Clone)]
pub struct YaraScanClient {
    socket_path: PathBuf,
    timeout_ms: u64,
    pool: AsyncCpuTaskConnectionPool,
}

impl YaraScanClient {
    pub fn new(socket_path: PathBuf) -> Self {
        let limits = AsyncCpuPoolLimits::from_env_or_default();
        Self {
            pool: AsyncCpuTaskConnectionPool::new(
                socket_path.clone(),
                limits.max_connections,
                limits.max_in_flight_per_connection,
            ),
            socket_path,
            timeout_ms: 5000,
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    pub async fn scan_bytes(
        &self,
        site_id: &str,
        body: Vec<u8>,
        excluded_categories: Vec<String>,
    ) -> Result<Vec<String>, YaraScanClientError> {
        let connection = self
            .pool
            .acquire_for_task_kind(synvoid_ipc::CpuTaskKind::YaraScan, self.timeout_ms)
            .await
            .map_err(map_pool_acquire_error_for_yara)?;

        let request_id = YARA_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let deadline_unix_ms = synvoid_utils::current_timestamp()
            .saturating_mul(1000)
            .saturating_add(self.timeout_ms);
        let mut temp_payload_file: Option<NamedTempFile> = None;
        let (payload_body, file_payload_path) = if body.len() > FILE_BACKED_PAYLOAD_THRESHOLD_BYTES
        {
            let mut temp_file = match Builder::new()
                .prefix("synvoid-cpu-task-")
                .tempfile_in(std::env::temp_dir())
            {
                Ok(file) => file,
                Err(e) => {
                    self.pool.release(&connection);
                    return Err(YaraScanClientError::SendFailed(e.to_string()));
                }
            };
            if let Err(e) = temp_file.write_all(&body) {
                self.pool.release(&connection);
                return Err(YaraScanClientError::SendFailed(e.to_string()));
            }
            let payload_path = temp_file.path().to_string_lossy().to_string();
            temp_payload_file = Some(temp_file);
            (Vec::new(), Some(payload_path))
        } else {
            (body, None)
        };

        let request = synvoid_ipc::Message::CpuTaskRequest {
            request_id,
            task_kind: synvoid_ipc::CpuTaskKind::YaraScan,
            priority: synvoid_ipc::CpuTaskPriority::High,
            policy: synvoid_ipc::CpuTaskPolicy::FailClosed,
            deadline_unix_ms,
            payload_size_limit: 64 * 1024 * 1024,
            output_size_limit: 4 * 1024 * 1024,
            file_payload_path,
            payload: synvoid_ipc::CpuTaskPayload::YaraScan {
                site_id: site_id.to_string(),
                body: payload_body,
                excluded_categories,
            },
        };

        let _keep_file_until_response = temp_payload_file;

        let response = match connection
            .submit_with_timeout(
                request,
                request_id,
                synvoid_ipc::CpuTaskKind::YaraScan,
                self.timeout_ms,
            )
            .await
        {
            Ok(message) => message,
            Err(err) => {
                let is_timeout = matches!(err, AsyncCpuTaskDispatchError::Timeout);
                if is_timeout {
                    record_cpu_offload_timeout();
                }
                self.pool.release(&connection);
                if is_timeout {
                    if connection.is_closed() {
                        self.pool.evict(&connection).await;
                    }
                } else {
                    self.pool.evict(&connection).await;
                }
                return Err(map_pool_acquire_error_for_yara(
                    map_async_cpu_task_dispatch_error_for_minifier(err),
                ));
            }
        };

        self.pool.release(&connection);

        match response {
            synvoid_ipc::Message::CpuTaskResponse {
                request_id: resp_id,
                task_kind: synvoid_ipc::CpuTaskKind::YaraScan,
                result: synvoid_ipc::CpuTaskResult::YaraScan { matches },
            } => {
                if resp_id == request_id {
                    return Ok(matches);
                }
            }
            synvoid_ipc::Message::CpuTaskError {
                request_id: resp_id,
                code,
                message,
                ..
            } => {
                if resp_id == request_id {
                    return Err(map_cpu_task_error_for_yara(code, message));
                }
            }
            _ => {}
        }

        Err(YaraScanClientError::ReceiveFailed(
            "CPU task response channel closed before matching response".to_string(),
        ))
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
                .recv_with_timeout::<synvoid_ipc::Message>(100)
                .await
                .is_ok();
        }
        false
    }

    pub async fn pool_stats(&self) -> AsyncCpuTaskPoolStats {
        self.pool.stats().await
    }
}

/// Deprecated compatibility alias. Use `ImageRightsClient`.
pub type PoisonImageClient = ImageRightsClient;

/// Deprecated compatibility alias. Use `ImageRightsClientError`.
pub type PoisonImageClientError = ImageRightsClientError;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn with_pool_env<F>(max_connections: Option<&str>, max_in_flight: Option<&str>, f: F)
    where
        F: FnOnce(),
    {
        let _guard = env_test_lock().lock().expect("env lock poisoned");
        let prev_max_connections = std::env::var(ASYNC_CPU_POOL_MAX_CONNECTIONS_ENV).ok();
        let prev_max_in_flight = std::env::var(ASYNC_CPU_MAX_IN_FLIGHT_PER_CONNECTION_ENV).ok();

        match max_connections {
            Some(v) => {
                // SAFETY: Serialized by process-wide test lock above.
                unsafe { std::env::set_var(ASYNC_CPU_POOL_MAX_CONNECTIONS_ENV, v) }
            }
            None => {
                // SAFETY: Serialized by process-wide test lock above.
                unsafe { std::env::remove_var(ASYNC_CPU_POOL_MAX_CONNECTIONS_ENV) }
            }
        }
        match max_in_flight {
            Some(v) => {
                // SAFETY: Serialized by process-wide test lock above.
                unsafe { std::env::set_var(ASYNC_CPU_MAX_IN_FLIGHT_PER_CONNECTION_ENV, v) }
            }
            None => {
                // SAFETY: Serialized by process-wide test lock above.
                unsafe { std::env::remove_var(ASYNC_CPU_MAX_IN_FLIGHT_PER_CONNECTION_ENV) }
            }
        }

        f();

        match prev_max_connections {
            Some(v) => {
                // SAFETY: Serialized by process-wide test lock above.
                unsafe { std::env::set_var(ASYNC_CPU_POOL_MAX_CONNECTIONS_ENV, v) }
            }
            None => {
                // SAFETY: Serialized by process-wide test lock above.
                unsafe { std::env::remove_var(ASYNC_CPU_POOL_MAX_CONNECTIONS_ENV) }
            }
        }
        match prev_max_in_flight {
            Some(v) => {
                // SAFETY: Serialized by process-wide test lock above.
                unsafe { std::env::set_var(ASYNC_CPU_MAX_IN_FLIGHT_PER_CONNECTION_ENV, v) }
            }
            None => {
                // SAFETY: Serialized by process-wide test lock above.
                unsafe { std::env::remove_var(ASYNC_CPU_MAX_IN_FLIGHT_PER_CONNECTION_ENV) }
            }
        }
    }

    #[test]
    fn async_cpu_pool_limits_use_defaults_when_env_missing() {
        with_pool_env(None, None, || {
            let limits = AsyncCpuPoolLimits::from_env_or_default();
            assert_eq!(
                limits.max_connections,
                DEFAULT_ASYNC_CPU_POOL_MAX_CONNECTIONS
            );
            assert_eq!(
                limits.max_in_flight_per_connection,
                DEFAULT_ASYNC_CPU_MAX_IN_FLIGHT_PER_CONNECTION
            );
        });
    }

    #[test]
    fn async_cpu_pool_limits_allow_multiple_in_flight_requests() {
        with_pool_env(Some("7"), Some("3"), || {
            let limits = AsyncCpuPoolLimits::from_env_or_default();
            assert_eq!(limits.max_connections, 7);
            assert_eq!(limits.max_in_flight_per_connection, 3);
        });
    }

    #[test]
    fn async_cpu_pool_limits_clamp_invalid_or_zero_values() {
        with_pool_env(Some("0"), Some("not-a-number"), || {
            let limits = AsyncCpuPoolLimits::from_env_or_default();
            assert_eq!(limits.max_connections, 1);
            assert_eq!(
                limits.max_in_flight_per_connection,
                DEFAULT_ASYNC_CPU_MAX_IN_FLIGHT_PER_CONNECTION
            );
        });
    }

    #[tokio::test]
    async fn async_cpu_pool_stats_are_zero_for_fresh_clients() {
        with_pool_env(None, None, || {});
        let socket_path = PathBuf::from("/tmp/nonexistent-static-worker.sock");
        let minifier = AsyncMinifierClient::new(socket_path.clone());
        let image_rights = ImageRightsClient::new(socket_path.clone());
        let yara = YaraScanClient::new(socket_path);

        let minifier_stats = minifier.pool_stats().await;
        assert_eq!(minifier_stats.active_in_flight, 0);
        assert_eq!(minifier_stats.pooled_connections, 0);
        assert_eq!(minifier_stats.evictions, 0);

        let image_rights_stats = image_rights.pool_stats().await;
        assert_eq!(image_rights_stats.active_in_flight, 0);
        assert_eq!(image_rights_stats.pooled_connections, 0);
        assert_eq!(image_rights_stats.evictions, 0);

        let yara_stats = yara.pool_stats().await;
        assert_eq!(yara_stats.active_in_flight, 0);
        assert_eq!(yara_stats.pooled_connections, 0);
        assert_eq!(yara_stats.evictions, 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn async_minifier_client_demuxes_out_of_order_responses() {
        let socket_name = format!(
            "async-cpu-demux-{}-{}",
            std::process::id(),
            NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
        );
        let client_socket_path = PathBuf::from(format!("/tmp/{}.sock", socket_name));
        let endpoint_name = client_socket_path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("socket path should have a file name");
        let server_socket_path = synvoid_ipc::ipc_transport::IpcEndpoint::new(endpoint_name)
            .socket_path()
            .to_path_buf();

        let _ = std::fs::remove_file(&server_socket_path);
        let listener = tokio::net::UnixListener::bind(&server_socket_path)
            .expect("failed to bind mock CPU task socket");
        let (first_request_seen_tx, first_request_seen_rx) = tokio::sync::oneshot::channel();

        let client = {
            let _guard = env_test_lock().lock().expect("env lock poisoned");
            let prev_max_connections = std::env::var(ASYNC_CPU_POOL_MAX_CONNECTIONS_ENV).ok();
            let prev_max_in_flight = std::env::var(ASYNC_CPU_MAX_IN_FLIGHT_PER_CONNECTION_ENV).ok();

            unsafe { std::env::set_var(ASYNC_CPU_POOL_MAX_CONNECTIONS_ENV, "1") };
            unsafe { std::env::set_var(ASYNC_CPU_MAX_IN_FLIGHT_PER_CONNECTION_ENV, "2") };

            let client = AsyncMinifierClient::new(client_socket_path.clone()).with_timeout(2000);

            match prev_max_connections {
                Some(v) => unsafe { std::env::set_var(ASYNC_CPU_POOL_MAX_CONNECTIONS_ENV, v) },
                None => unsafe { std::env::remove_var(ASYNC_CPU_POOL_MAX_CONNECTIONS_ENV) },
            }
            match prev_max_in_flight {
                Some(v) => unsafe {
                    std::env::set_var(ASYNC_CPU_MAX_IN_FLIGHT_PER_CONNECTION_ENV, v)
                },
                None => unsafe { std::env::remove_var(ASYNC_CPU_MAX_IN_FLIGHT_PER_CONNECTION_ENV) },
            }

            client
        };

        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("failed to accept mock client");
            let (mut read_half, mut write_half) = tokio::io::split(stream);
            let mut read_buffer = Vec::with_capacity(64 * 1024);

            let first = recv_framed_async_cpu_task_message(&mut read_half, None, &mut read_buffer)
                .await
                .expect("failed to read first request")
                .expect("first request missing");
            let _ = first_request_seen_tx.send(());
            let second = recv_framed_async_cpu_task_message(&mut read_half, None, &mut read_buffer)
                .await
                .expect("failed to read second request")
                .expect("second request missing");

            let (first_id, first_path) = match first {
                Message::CpuTaskRequest {
                    request_id,
                    task_kind: synvoid_ipc::CpuTaskKind::Minify,
                    payload: synvoid_ipc::CpuTaskPayload::Minify { path, .. },
                    ..
                } => (request_id, path),
                other => panic!("unexpected first request: {:?}", other),
            };
            let (second_id, second_path) = match second {
                Message::CpuTaskRequest {
                    request_id,
                    task_kind: synvoid_ipc::CpuTaskKind::Minify,
                    payload: synvoid_ipc::CpuTaskPayload::Minify { path, .. },
                    ..
                } => (request_id, path),
                other => panic!("unexpected second request: {:?}", other),
            };

            let response_for_second = Message::CpuTaskResponse {
                request_id: second_id,
                task_kind: synvoid_ipc::CpuTaskKind::Minify,
                result: synvoid_ipc::CpuTaskResult::Minify {
                    site_id: "site-a".to_string(),
                    path: second_path,
                    content: b"second".to_vec(),
                    content_type: "text/plain".to_string(),
                    encoding: None,
                    queued_encodings: vec![],
                },
            };
            let response_for_first = Message::CpuTaskResponse {
                request_id: first_id,
                task_kind: synvoid_ipc::CpuTaskKind::Minify,
                result: synvoid_ipc::CpuTaskResult::Minify {
                    site_id: "site-a".to_string(),
                    path: first_path,
                    content: b"first".to_vec(),
                    content_type: "text/plain".to_string(),
                    encoding: None,
                    queued_encodings: vec![],
                },
            };

            send_framed_async_cpu_task_message(&mut write_half, None, &response_for_second)
                .await
                .expect("failed to send second response");
            send_framed_async_cpu_task_message(&mut write_half, None, &response_for_first)
                .await
                .expect("failed to send first response");
        });

        let (first_result, second_result) = tokio::time::timeout(Duration::from_secs(5), async {
            let first_handle = {
                let client = client.clone();
                tokio::spawn(
                    async move { client.request_minify("site-a", "/first.css", None).await },
                )
            };

            first_request_seen_rx
                .await
                .expect("server dropped first-request signal");

            let second_handle = {
                let client = client.clone();
                tokio::spawn(
                    async move { client.request_minify("site-a", "/second.css", None).await },
                )
            };

            let first_result = first_handle.await.expect("first request task panicked");
            let second_result = second_handle.await.expect("second request task panicked");
            (first_result, second_result)
        })
        .await
        .expect("demux test timed out");

        let first_result = first_result.expect("first request failed");
        let second_result = second_result.expect("second request failed");
        assert_eq!(first_result.content, Bytes::from_static(b"first"));
        assert_eq!(second_result.content, Bytes::from_static(b"second"));

        server.await.expect("mock server task panicked");
        let _ = std::fs::remove_file(&server_socket_path);
    }

    #[test]
    fn global_async_cpu_offload_evictions_counter_is_monotonic() {
        let before = get_global_async_cpu_offload_stats();
        let after = get_global_async_cpu_offload_stats();
        assert!(after.submissions >= before.submissions);
        assert!(after.evictions >= before.evictions);
        assert!(after.fallbacks >= before.fallbacks);
    }
}
