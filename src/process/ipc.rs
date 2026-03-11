use std::io::{self, Read, Write};
use std::time::SystemTime;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommandMethod {
    UnixSocket,
    NamedPipe,
    Signal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MasterCommand {
    Stop { graceful: bool },
    ReloadConfig,
    Status,
    HealthCheck,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterStatus {
    pub master_pid: u32,
    pub started_at: u64,
    pub uptime_secs: u64,
    pub version: String,
    pub workers: Vec<WorkerStatusInfo>,
    pub stats: StatusStats,
    pub threat_summary: ThreatSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStatusInfo {
    pub id: usize,
    pub pid: u32,
    pub port: u16,
    pub status: String,
    pub requests: u64,
    pub blocked: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusStats {
    pub total_requests: u64,
    pub blocked_last_hour: u64,
    pub challenged_last_hour: u64,
    pub proxied_last_hour: u64,
    pub active_blocks: usize,
    pub active_violations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSummary {
    pub critical_ips: usize,
    pub elevated_ips: usize,
    pub total_blocked_ips: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerId(pub usize);

impl WorkerId {
    pub fn as_usize(&self) -> usize {
        self.0
    }
}

impl std::fmt::Display for WorkerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorSeverity {
    Warning,
    Error,
    Critical,
}

impl std::fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorSeverity::Warning => write!(f, "warning"),
            ErrorSeverity::Error => write!(f, "error"),
            ErrorSeverity::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    Unknown,
    ConfigLoadFailed,
    SocketBindFailed,
    UpstreamConnectionFailed,
    WorkerPanic,
    ResourceExhausted,
    Timeout,
    AuthenticationFailed,
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorCode::Unknown => write!(f, "unknown"),
            ErrorCode::ConfigLoadFailed => write!(f, "config_load_failed"),
            ErrorCode::SocketBindFailed => write!(f, "socket_bind_failed"),
            ErrorCode::UpstreamConnectionFailed => write!(f, "upstream_connection_failed"),
            ErrorCode::WorkerPanic => write!(f, "worker_panic"),
            ErrorCode::ResourceExhausted => write!(f, "resource_exhausted"),
            ErrorCode::Timeout => write!(f, "timeout"),
            ErrorCode::AuthenticationFailed => write!(f, "authentication_failed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    WorkerStarted {
        id: WorkerId,
        pid: u32,
        port: u16,
        timestamp: u64,
    },
    WorkerReady {
        id: WorkerId,
    },
    WorkerHeartbeat {
        id: WorkerId,
        timestamp: u64,
        metrics: WorkerMetricsPayload,
    },
    WorkerShutdownComplete {
        id: WorkerId,
    },
    WorkerError {
        id: WorkerId,
        error: String,
        severity: ErrorSeverity,
        error_code: ErrorCode,
    },
    MasterShutdown {
        graceful: bool,
        timeout_secs: u64,
    },
    MasterConfigReload {
        config_path: String,
    },
    MasterHealthCheck {
        timestamp: u64,
    },
    MasterResizeThreadpool {
        worker_threads: u32,
    },
    HealthCheckAck {
        timestamp: u64,
    },
    WorkerResizeAck {
        id: WorkerId,
        worker_threads: u32,
    },
    StaticWorkerStarted {
        worker_id: usize,
        pid: u32,
    },
    StaticWorkerReady {
        worker_id: usize,
    },
    StaticWorkerHeartbeat {
        worker_id: usize,
        timestamp: u64,
    },
    StaticWorkerShutdownComplete {
        worker_id: usize,
    },
    StaticWorkerBackgroundTasksDone {
        worker_id: usize,
    },
    StaticWorkerResizeAck {
        worker_id: usize,
        worker_threads: u32,
    },
    StaticWorkerScan {
        site_id: String,
    },
    StaticWorkerCacheUpdate {
        site_id: String,
        path: String,
        minified_path: String,
    },
    MinifyRequest {
        request_id: u64,
        site_id: String,
        path: String,
        encoding: Option<String>,
    },
    MinifyResponse {
        request_id: u64,
        site_id: String,
        path: String,
        content: Vec<u8>,
        content_type: String,
        encoding: Option<String>,
        queued_encodings: Vec<String>,
    },
    MinifyError {
        request_id: u64,
        error: String,
    },
    GetCompressedRequest {
        request_id: u64,
        site_id: String,
        path: String,
        encoding: String,
    },
    GetCompressedResponse {
        request_id: u64,
        content: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkerMetricsPayload {
    pub total_requests: u64,
    pub blocked: u64,
    pub challenged: u64,
    pub proxied: u64,
    pub errors: u64,
    pub current_concurrent: u64,
    pub peak_concurrent: u64,
    pub avg_latency_ms: f64,
    pub uptime_secs: u64,
    pub memory_bytes: u64,
    pub cpu_percent: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerStatus {
    Starting,
    Ready,
    Running,
    Stopping,
    Stopped,
    Failed,
}

/// Platform-specific stream wrapper for IPC.
///
/// On Windows: uses named pipes (via File handle)
pub struct IpcStream {
    #[cfg(unix)]
    stream: UnixStream,
    #[cfg(windows)]
    stream: std::fs::File,
    read_buffer: Vec<u8>,
}

/// Windows-specific named pipe server for accepting worker connections.
/// On Unix, we use UnixListener instead.
#[cfg(windows)]
pub struct WindowsIpcListener {
    pipe_path: String,
}

/// Windows IPC listener implementation
#[cfg(windows)]
impl WindowsIpcListener {
    pub fn new(pipe_name: &str) -> Self {
        Self {
            pipe_path: format!("\\\\.\\pipe\\{}", pipe_name),
        }
    }

    /// Create the named pipe and listen for connections
    /// This is a synchronous version that can be converted to async
    pub fn bind(&self) -> io::Result<()> {
        use windows_sys::Win32::Foundation::FILE_FLAG_OVERLAPPED;
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::System::Pipes::CreateNamedPipeW;
        use windows_sys::Win32::System::Pipes::PIPE_ACCESS_DUPLEX;
        use windows_sys::Win32::System::Pipes::PIPE_READMODE_MESSAGE;
        use windows_sys::Win32::System::Pipes::PIPE_TYPE_MESSAGE;
        use windows_sys::Win32::System::Pipes::PIPE_WAIT;

        let pipe_name: Vec<u16> = self
            .pipe_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let handle: HANDLE = CreateNamedPipeW(
                pipe_name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1,     // max instances
                65536, // out buffer size
                65536, // in buffer size
                0,     // timeout (default = 50ms)
                std::ptr::null_mut(),
            );

            if handle == 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }

    /// Get the pipe path for workers to connect to
    pub fn path(&self) -> &str {
        &self.pipe_path
    }
}

/// Create a platform-appropriate IPC listener path.
/// On Unix: returns the socket path as-is.
/// On Windows: converts to pipe name.
pub fn get_ipc_path(socket_path: &std::path::Path) -> String {
    #[cfg(unix)]
    {
        socket_path.to_string_lossy().to_string()
    }

    #[cfg(windows)]
    {
        let pipe_name = socket_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("rustwaf-master");
        format!("\\\\.\\pipe\\{}", pipe_name)
    }
}

/// Connect to the master process IPC endpoint.
/// This is the platform-agnostic way for workers to connect to master.
pub fn connect_to_master(path: &std::path::Path) -> io::Result<IpcStream> {
    #[cfg(unix)]
    {
        let stream = UnixStream::connect(path)?;
        stream.set_nonblocking(true).ok();
        Ok(IpcStream {
            stream,
            read_buffer: Vec::with_capacity(64 * 1024),
        })
    }

    #[cfg(windows)]
    {
        let pipe_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("rustwaf-master");
        let pipe_path = format!("\\\\.\\pipe\\{}", pipe_name);

        let mut attempts = 0;
        let max_attempts = 10;

        loop {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&pipe_path)
            {
                Ok(handle) => {
                    return Ok(IpcStream {
                        stream: handle,
                        read_buffer: Vec::with_capacity(64 * 1024),
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound && attempts < max_attempts => {
                    attempts += 1;
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl IpcStream {
    /// Create a new IpcStream from an existing UnixStream.
    /// This is used on the server side (master accepting connections).
    #[cfg(unix)]
    pub fn new(stream: UnixStream) -> Self {
        stream.set_nonblocking(true).ok();
        Self {
            stream,
            read_buffer: Vec::with_capacity(64 * 1024),
        }
    }

    /// Create a new IpcStream from a Windows named pipe handle.
    /// This is used on the server side (master accepting connections) on Windows.
    #[cfg(windows)]
    pub fn new(stream: std::fs::File) -> Self {
        Self {
            stream,
            read_buffer: Vec::with_capacity(64 * 1024),
        }
    }

    pub fn send(&mut self, msg: &Message) -> io::Result<()> {
        let json =
            serde_json::to_vec(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let len = json.len() as u32;
        self.stream.write_all(&len.to_be_bytes())?;
        self.stream.write_all(&json)?;
        self.stream.flush()?;
        Ok(())
    }

    pub fn try_recv(&mut self) -> io::Result<Option<Message>> {
        if self.read_buffer.len() < 4 {
            let mut temp_buf = [0u8; 4096];
            match self.stream.read(&mut temp_buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed",
                    ))
                }
                Ok(n) => {
                    self.read_buffer.extend_from_slice(&temp_buf[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            }
        }

        if self.read_buffer.len() < 4 {
            return Ok(None);
        }

        let len_bytes: [u8; 4] = [
            self.read_buffer[0],
            self.read_buffer[1],
            self.read_buffer[2],
            self.read_buffer[3],
        ];
        let len = u32::from_be_bytes(len_bytes) as usize;

        if len > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message too large",
            ));
        }

        let total_needed = 4 + len;
        if self.read_buffer.len() < total_needed {
            let mut temp_buf = [0u8; 4096];
            loop {
                match self.stream.read(&mut temp_buf) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "connection closed",
                        ))
                    }
                    Ok(n) => {
                        self.read_buffer.extend_from_slice(&temp_buf[..n]);
                        if self.read_buffer.len() >= total_needed {
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        return Ok(None);
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        if self.read_buffer.len() < total_needed {
            return Ok(None);
        }

        let json = self.read_buffer[4..total_needed].to_vec();
        self.read_buffer.drain(..total_needed);

        let msg: Message = serde_json::from_slice(&json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(Some(msg))
    }

    pub fn recv(&mut self, timeout_ms: u64) -> io::Result<Option<Message>> {
        let start = std::time::Instant::now();

        loop {
            match self.try_recv() {
                Ok(Some(msg)) => return Ok(Some(msg)),
                Ok(None) => {
                    if start.elapsed().as_millis() as u64 >= timeout_ms {
                        return Ok(None);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => return Err(e),
            }
        }
    }

    #[cfg(unix)]
    pub fn into_inner(self) -> UnixStream {
        self.stream
    }

    #[cfg(windows)]
    pub fn into_inner(self) -> std::fs::File {
        self.stream
    }
}

pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
