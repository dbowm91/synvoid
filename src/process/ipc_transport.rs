use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;

use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer};

use super::ipc_framing::{
    endpoint_to_socket_path, read_message, read_message_with_timeout, write_message,
    DEFAULT_BUFFER_SIZE,
};
use super::ipc_signed::IpcSigner;

static WARNED_UNSIGNED: OnceLock<()> = OnceLock::new();

pub struct IpcStream {
    #[cfg(unix)]
    inner: UnixStream,
    #[cfg(windows)]
    inner: NamedPipeClient,
    read_buffer: Vec<u8>,
    signer: Option<Arc<IpcSigner>>,
    enforce_signing: bool,
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

    pub fn master() -> Self {
        Self::new("master")
    }

    pub fn static_worker() -> Self {
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
            inner: stream,
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
            signer: None,
            enforce_signing: false,
        }
    }

    #[cfg(unix)]
    pub fn from_unix_stream_with_signer(stream: UnixStream, signer: Arc<IpcSigner>) -> Self {
        Self {
            inner: stream,
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
            signer: Some(signer),
            enforce_signing: true,
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
            inner: stream,
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
            signer,
            enforce_signing,
        }
    }

    #[cfg(windows)]
    pub fn from_named_pipe(pipe: NamedPipeServer) -> Self {
        Self {
            inner: pipe.into(),
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
            signer: None,
            enforce_signing: false,
        }
    }

    #[cfg(windows)]
    pub fn from_named_pipe_with_signer(pipe: NamedPipeServer, signer: Arc<IpcSigner>) -> Self {
        Self {
            inner: pipe.into(),
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
            signer: Some(signer),
            enforce_signing: true,
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
            inner: pipe.into(),
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
            signer,
            enforce_signing,
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
                        inner: client,
                        read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
                        signer: None,
                        enforce_signing: false,
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
                        inner: client,
                        read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
                        signer: Some(signer),
                        enforce_signing: true,
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
            if self.enforce_signing {
                tracing::error!(
                    "IPC signing is enforced but no signer available - rejecting message"
                );
                return Err(io::Error::other(
                    "IPC signing enforced but no signer configured",
                ));
            }
WARNED_UNSIGNED.get_or_init(|| {
                tracing::warn!("Using unsigned IPC communication - this is insecure for production deployments");
            });
            write_message(&mut self.inner, msg).await
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

            match SignedIpcMessage::deserialize_signed(&data, signer) {
                Ok(msg) => Ok(Some(msg)),
                Err(e) => Err(e),
            }
        } else {
            if self.enforce_signing {
                tracing::error!(
                    "IPC signing is enforced but no signer available - rejecting connection"
                );
                return Err(io::Error::other(
                    "IPC signing enforced but no signer configured",
                ));
            }
WARNED_UNSIGNED.get_or_init(|| {
                tracing::warn!("Using unsigned IPC communication - this is insecure for production deployments");
            });
            read_message(&mut self.inner, &mut self.read_buffer).await
        }
    }

    pub async fn recv_with_timeout<T: DeserializeOwned>(
        &mut self,
        timeout_ms: u64,
    ) -> io::Result<Option<T>> {
        if let Some(ref _signer) = self.signer {
            use tokio::time::{timeout, Duration};

            let result = timeout(Duration::from_millis(timeout_ms), self.recv::<T>()).await;

            match result {
                Ok(r) => r,
                Err(_) => Ok(None),
            }
        } else {
            if self.enforce_signing {
                tracing::error!(
                    "IPC signing is enforced but no signer available - rejecting connection"
                );
                return Err(io::Error::other(
                    "IPC signing enforced but no signer configured",
                ));
            }
WARNED_UNSIGNED.get_or_init(|| {
                tracing::warn!("Using unsigned IPC communication - this is insecure for production deployments");
            });
            read_message_with_timeout(&mut self.inner, &mut self.read_buffer, timeout_ms).await
        }
    }

    pub fn into_inner(self) -> IpcStreamInner {
        IpcStreamInner {
            #[cfg(unix)]
            unix: self.inner,
            #[cfg(windows)]
            windows: self.inner,
        }
    }

    pub fn is_signed(&self) -> bool {
        self.signer.is_some()
    }
}

pub struct IpcStreamInner {
    #[cfg(unix)]
    pub unix: UnixStream,
    #[cfg(windows)]
    pub windows: NamedPipeClient,
}

impl AsyncRead for IpcStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for IpcStream {
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
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

pub async fn connect_to_master_async() -> io::Result<IpcStream> {
    IpcEndpoint::master().connect().await
}

pub async fn connect_to_master_signed(signer: Arc<IpcSigner>) -> io::Result<IpcStream> {
    IpcEndpoint::master().connect_with_signer(signer).await
}

pub async fn connect_to_static_worker_async() -> io::Result<IpcStream> {
    IpcEndpoint::static_worker().connect().await
}

pub async fn connect_to_static_worker_signed(signer: Arc<IpcSigner>) -> io::Result<IpcStream> {
    IpcEndpoint::static_worker()
        .connect_with_signer(signer)
        .await
}

pub async fn connect_to_commands_async() -> io::Result<IpcStream> {
    IpcEndpoint::commands().connect().await
}

pub async fn connect_to_commands_signed(signer: Arc<IpcSigner>) -> io::Result<IpcStream> {
    IpcEndpoint::commands().connect_with_signer(signer).await
}
