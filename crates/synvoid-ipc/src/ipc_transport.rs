use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer};

#[allow(unused_imports)]
use super::ipc_framing::{
    endpoint_to_socket_path, read_message, read_message_with_timeout, write_message,
    DEFAULT_BUFFER_SIZE,
};
use super::ipc_signed::IpcSigner;

pub trait AsyncIpcTransport: AsyncRead + AsyncWrite + Unpin + Send + Sync + std::any::Any {
    fn peer_pid(&self) -> Option<u32>;
    #[cfg(unix)]
    fn as_raw_fd(&self) -> io::Result<std::os::unix::io::RawFd>;
}

#[cfg(unix)]
impl AsyncIpcTransport for UnixStream {
    fn peer_pid(&self) -> Option<u32> {
        // ... (existing logic)
        use socket2::SockRef;
        use std::mem::size_of;
        use std::os::unix::io::AsRawFd;

        let sock_ref = SockRef::from(self);
        let raw_fd = sock_ref.as_raw_fd();

        #[repr(C)]
        struct UCred {
            pid: libc::pid_t,
            uid: libc::uid_t,
            gid: libc::gid_t,
        }

        let mut cred: UCred = unsafe { std::mem::zeroed() };
        let mut cred_len = size_of::<UCred>() as libc::socklen_t;

        #[cfg(target_os = "linux")]
        {
            let result = unsafe {
                libc::getsockopt(
                    raw_fd,
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    &mut cred as *mut _ as *mut libc::c_void,
                    &mut cred_len,
                )
            };

            if result == 0 && cred.pid > 0 {
                return Some(cred.pid as u32);
            }
        }

        None
    }

    fn as_raw_fd(&self) -> io::Result<std::os::unix::io::RawFd> {
        use std::os::unix::io::AsRawFd;
        Ok(AsRawFd::as_raw_fd(self))
    }
}

#[cfg(windows)]
impl AsyncIpcTransport for NamedPipeClient {
    fn peer_pid(&self) -> Option<u32> {
        None
    }
}

#[cfg(windows)]
impl AsyncIpcTransport for NamedPipeServer {
    fn peer_pid(&self) -> Option<u32> {
        None
    }
}

pub struct IpcStream {
    inner: Box<dyn AsyncIpcTransport>,
    read_buffer: Vec<u8>,
    signer: Option<Arc<IpcSigner>>,
    _enforce_signing: bool,
}

pub struct IpcListener {
    #[cfg(unix)]
    inner: UnixListener,
    #[cfg(windows)]
    pipe_name: String,
    #[cfg(windows)]
    server: Option<NamedPipeServer>,
}

pub struct IpcEndpoint {
    name: String,
    #[cfg(unix)]
    socket_path: PathBuf,
    #[cfg(windows)]
    pipe_name: String,
}

impl IpcEndpoint {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            #[cfg(unix)]
            socket_path: endpoint_to_socket_path(name),
            #[cfg(windows)]
            pipe_name: endpoint_to_pipe_name(name),
        }
    }

    pub fn supervisor() -> Self {
        Self::new("supervisor")
    }

    pub fn cpu_worker() -> Self {
        Self::new("static-worker")
    }

    pub fn commands() -> Self {
        Self::new("commands")
    }

    pub async fn bind(&self) -> io::Result<IpcListener> {
        IpcListener::bind(self).await
    }

    pub async fn connect(&self) -> io::Result<IpcStream> {
        IpcStream::connect(self).await
    }

    pub async fn connect_with_signer(&self, signer: Arc<IpcSigner>) -> io::Result<IpcStream> {
        IpcStream::connect_with_signer(self, signer).await
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    #[cfg(unix)]
    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    #[cfg(windows)]
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }
}

impl IpcListener {
    #[cfg(unix)]
    pub async fn bind(endpoint: &IpcEndpoint) -> io::Result<Self> {
        let socket_path = endpoint.socket_path();

        if let Some(parent) = socket_path.parent() {
            tokio::fs::create_dir_all(parent).await.ok();
        }

        if socket_path.exists() {
            tokio::fs::remove_file(socket_path).await?;
        }

        let listener = UnixListener::bind(socket_path)?;

        super::socket_path::set_socket_permissions(socket_path)?;

        Ok(Self { inner: listener })
    }

    #[cfg(windows)]
    pub async fn bind(endpoint: &IpcEndpoint) -> io::Result<Self> {
        let pipe_name = endpoint.pipe_name();

        let server = create_named_pipe_server(pipe_name)?;

        Ok(Self {
            pipe_name: pipe_name.to_string(),
            server: Some(server),
        })
    }

    #[cfg(unix)]
    pub async fn accept(&self) -> io::Result<IpcStream> {
        let (stream, _) = self.inner.accept().await?;
        Ok(IpcStream::from_unix_stream(stream))
    }

    #[cfg(windows)]
    pub async fn accept(&self) -> io::Result<IpcStream> {
        let server = self
            .server
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "server not initialized"))?;

        server.connect().await?;

        let connected_server = self
            .server
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "failed to take server"))?;

        let new_server = create_named_pipe_server(&self.pipe_name)?;
        self.server.replace(new_server);

        Ok(IpcStream::from_named_pipe(connected_server))
    }

    #[cfg(unix)]
    pub fn local_addr(&self) -> io::Result<tokio::net::unix::SocketAddr> {
        self.inner.local_addr()
    }

    #[cfg(windows)]
    pub fn local_addr(&self) -> io::Result<tokio::net::unix::SocketAddr> {
        Err(io::Error::new(
            io::ErrorKind::NotSupported,
            "local_addr not supported for named pipes",
        ))
    }
}

impl IpcStream {
    #[cfg(unix)]
    pub fn from_unix_stream(stream: UnixStream) -> Self {
        Self {
            inner: Box::new(stream),
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
            signer: None,
            _enforce_signing: false,
        }
    }

    #[cfg(unix)]
    pub fn from_unix_stream_with_signer(stream: UnixStream, signer: Arc<IpcSigner>) -> Self {
        Self {
            inner: Box::new(stream),
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
            signer: Some(signer),
            _enforce_signing: true,
        }
    }

    #[cfg(unix)]
    pub fn from_unix_stream_with_signer_optional(
        stream: UnixStream,
        signer: Option<Arc<IpcSigner>>,
        enforce_signing: bool,
    ) -> Self {
        if enforce_signing && signer.is_none() {
            tracing::warn!("IPC signing enforced but no signer provided - connection may fail");
        }
        Self {
            inner: Box::new(stream),
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
            signer,
            _enforce_signing: enforce_signing,
        }
    }

    #[cfg(windows)]
    pub fn from_named_pipe(pipe: NamedPipeServer) -> Self {
        Self {
            inner: Box::new(pipe),
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
            signer: None,
            _enforce_signing: false,
        }
    }

    #[cfg(windows)]
    pub fn from_named_pipe_with_signer(pipe: NamedPipeServer, signer: Arc<IpcSigner>) -> Self {
        Self {
            inner: Box::new(pipe),
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
            signer: Some(signer),
            _enforce_signing: true,
        }
    }

    #[cfg(windows)]
    pub fn from_named_pipe_with_signer_optional(
        pipe: NamedPipeServer,
        signer: Option<Arc<IpcSigner>>,
        enforce_signing: bool,
    ) -> Self {
        if enforce_signing && signer.is_none() {
            tracing::warn!("IPC signing enforced but no signer provided - connection may fail");
        }
        Self {
            inner: Box::new(pipe),
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
            signer,
            _enforce_signing: enforce_signing,
        }
    }

    #[cfg(unix)]
    pub async fn connect(endpoint: &IpcEndpoint) -> io::Result<Self> {
        let stream = UnixStream::connect(endpoint.socket_path()).await?;
        Ok(Self::from_unix_stream(stream))
    }

    #[cfg(unix)]
    pub async fn connect_with_signer(
        endpoint: &IpcEndpoint,
        signer: Arc<IpcSigner>,
    ) -> io::Result<Self> {
        let stream = UnixStream::connect(endpoint.socket_path()).await?;
        Ok(Self::from_unix_stream_with_signer(stream, signer))
    }

    #[cfg(windows)]
    pub async fn connect(endpoint: &IpcEndpoint) -> io::Result<Self> {
        use std::time::Duration;

        let pipe_name = endpoint.pipe_name();
        let mut attempts = 0;
        let max_attempts = 10;

        loop {
            match NamedPipeClient::connect(pipe_name) {
                Ok(client) => {
                    return Ok(Self {
                        inner: Box::new(client),
                        read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
                        signer: None,
                        _enforce_signing: false,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound && attempts < max_attempts => {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    #[cfg(windows)]
    pub async fn connect_with_signer(
        endpoint: &IpcEndpoint,
        signer: Arc<IpcSigner>,
    ) -> io::Result<Self> {
        use std::time::Duration;

        let pipe_name = endpoint.pipe_name();
        let mut attempts = 0;
        let max_attempts = 10;

        loop {
            match NamedPipeClient::connect(pipe_name) {
                Ok(client) => {
                    return Ok(Self {
                        inner: Box::new(client),
                        read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
                        signer: Some(signer),
                        _enforce_signing: true,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound && attempts < max_attempts => {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    pub async fn send<T: Serialize>(&mut self, msg: &T) -> io::Result<()> {
        if let Some(ref signer) = self.signer {
            use super::ipc_signed::SignedIpcMessage;
            let data = SignedIpcMessage::serialize_signed(msg, signer)?;
            self.inner.write_all(&data).await?;
            self.inner.flush().await?;
            Ok(())
        } else {
            tracing::error!(
                "IPC signing is enforced but no signer configured - rejecting unsigned message"
            );
            Err(io::Error::other(
                "IPC signing enforced but no signer configured",
            ))
        }
    }

    pub async fn recv<T: DeserializeOwned>(&mut self) -> io::Result<Option<T>> {
        if let Some(ref signer) = self.signer {
            use super::ipc_signed::SignedIpcMessage;

            let mut len_buf = [0u8; 4];
            match self.inner.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e),
            }

            let len = u32::from_be_bytes(len_buf) as usize;
            if len > super::ipc_framing::MAX_MESSAGE_SIZE {
                super::ipc_signed::increment_oversized_rejected();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "message too large",
                ));
            }

            let mut data = vec![0u8; len];
            self.inner
                .read_exact(&mut data)
                .await
                .map_err(io::Error::other)?;

            let mut framed = Vec::with_capacity(4 + data.len());
            framed.extend_from_slice(&len_buf);
            framed.extend_from_slice(&data);
            match SignedIpcMessage::deserialize_signed(&framed, signer) {
                Ok(msg) => Ok(Some(msg)),
                Err(e) => Err(e),
            }
        } else {
            tracing::error!(
                "IPC signing is enforced but no signer configured - rejecting unsigned connection"
            );
            Err(io::Error::other(
                "IPC signing enforced but no signer configured",
            ))
        }
    }

    pub async fn recv_with_timeout<T: DeserializeOwned>(
        &mut self,
        timeout_ms: u64,
    ) -> io::Result<Option<T>> {
        if self.signer.is_some() {
            use tokio::time::{timeout, Duration};

            let result = timeout(Duration::from_millis(timeout_ms), self.recv::<T>()).await;

            match result {
                Ok(r) => r,
                Err(_) => Ok(None),
            }
        } else {
            tracing::error!(
                "IPC signing is enforced but no signer configured - rejecting unsigned connection"
            );
            Err(io::Error::other(
                "IPC signing enforced but no signer configured",
            ))
        }
    }

    pub fn into_inner(self) -> Box<dyn AsyncIpcTransport> {
        self.inner
    }

    #[cfg(unix)]
    pub fn with_signer(self, signer: Arc<IpcSigner>) -> Self {
        Self {
            inner: self.inner,
            read_buffer: self.read_buffer,
            signer: Some(signer),
            _enforce_signing: true,
        }
    }

    pub fn is_signed(&self) -> bool {
        self.signer.is_some()
    }

    pub fn signer(&self) -> Option<Arc<IpcSigner>> {
        self.signer.as_ref().cloned()
    }

    pub fn peer_pid(&self) -> Option<u32> {
        self.inner.peer_pid()
    }
}

impl AsyncRead for IpcStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for IpcStream {
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_shutdown(cx)
    }

    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut *self.inner).poll_write(cx, buf)
    }
}

#[cfg(windows)]
fn create_named_pipe_server(pipe_name: &str) -> io::Result<NamedPipeServer> {
    use tokio::net::windows::named_pipe::ServerOptions;

    ServerOptions::new()
        .first_pipe_instance(true)
        .max_instances(1)
        .out_buffer_size(65536)
        .in_buffer_size(65536)
        .create(pipe_name)
}

pub async fn connect_to_endpoint(name: &str) -> io::Result<IpcStream> {
    let endpoint = IpcEndpoint::new(name);
    endpoint.connect().await
}

pub async fn connect_to_endpoint_signed(
    name: &str,
    signer: Arc<IpcSigner>,
) -> io::Result<IpcStream> {
    let endpoint = IpcEndpoint::new(name);
    endpoint.connect_with_signer(signer).await
}

pub async fn connect_to_supervisor_async() -> io::Result<IpcStream> {
    IpcEndpoint::supervisor().connect().await
}

pub async fn connect_to_supervisor_signed(signer: Arc<IpcSigner>) -> io::Result<IpcStream> {
    IpcEndpoint::supervisor().connect_with_signer(signer).await
}

pub async fn connect_to_cpu_worker_async() -> io::Result<IpcStream> {
    IpcEndpoint::cpu_worker().connect().await
}

pub async fn connect_to_cpu_worker_signed(signer: Arc<IpcSigner>) -> io::Result<IpcStream> {
    IpcEndpoint::cpu_worker().connect_with_signer(signer).await
}

pub async fn connect_to_commands_async() -> io::Result<IpcStream> {
    IpcEndpoint::commands().connect().await
}

pub async fn connect_to_commands_signed(signer: Arc<IpcSigner>) -> io::Result<IpcStream> {
    IpcEndpoint::commands().connect_with_signer(signer).await
}
