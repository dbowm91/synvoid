use std::io;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::Duration;

use crate::process::{
    get_secure_socket_path, raw_fd_to_tcp_listener, IpcStream, Message, SocketFDError,
    SocketFDPassing, SocketHolder,
};

#[derive(Debug, thiserror::Error)]
pub enum SocketHandoffError {
    #[error("Failed to create handoff socket: {0}")]
    SocketCreate(io::Error),

    #[error("Failed to connect to handoff socket: {0}")]
    SocketConnect(io::Error),

    #[error("Failed to send file descriptors: {0}")]
    SendFailed(SocketFDError),

    #[error("Failed to receive file descriptors: {0}")]
    RecvFailed(SocketFDError),

    #[error("IPC error: {0}")]
    IpcError(String),

    #[error("Timeout waiting for handoff")]
    Timeout,

    #[error("Handoff cancelled: {0}")]
    Cancelled(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Feature not supported on this platform: {0}")]
    NotSupported(String),
}

impl From<SocketFDError> for SocketHandoffError {
    fn from(e: SocketFDError) -> Self {
        SocketHandoffError::SendFailed(e)
    }
}

pub const HANDOFF_SOCKET_NAME: &str = "socket-handoff.sock";
pub const HANDOFF_TIMEOUT_SECS: u64 = 30;

pub fn get_handoff_socket_path() -> PathBuf {
    get_secure_socket_path(HANDOFF_SOCKET_NAME)
}

#[cfg(unix)]
pub struct SocketHandoffServer {
    listener: UnixListener,
    ports: Vec<u16>,
    socket_holder: SocketHolder,
}

#[cfg(not(unix))]
pub struct SocketHandoffServer {
    ports: Vec<u16>,
    socket_holder: SocketHolder,
}

#[cfg(unix)]
impl SocketHandoffServer {
    pub fn new(ports: Vec<u16>) -> Result<Self, SocketHandoffError> {
        let socket_path = get_handoff_socket_path();

        if socket_path.exists() {
            let _ = std::fs::remove_file(&socket_path);
        }

        let listener =
            UnixListener::bind(&socket_path).map_err(SocketHandoffError::SocketCreate)?;

        listener
            .set_nonblocking(true)
            .map_err(SocketHandoffError::SocketCreate)?;

        let mut socket_holder = SocketHolder::new();
        for port in &ports {
            socket_holder
                .add_socket(*port, true)
                .map_err(SocketHandoffError::SendFailed)?;
        }

        tracing::info!(
            "Socket handoff server created for ports {:?} at {:?}",
            ports,
            socket_path
        );

        Ok(Self {
            listener,
            ports,
            socket_holder,
        })
    }

    pub fn get_fds(&self) -> Vec<i32> {
        self.socket_holder.get_fds()
    }

    pub fn get_tcp_listeners(&self) -> io::Result<Vec<std::net::TcpListener>> {
        self.socket_holder
            .get_socket_info()
            .iter()
            .map(|info| {
                let fd_dup = nix::unistd::dup(info.fd).map_err(io::Error::other)?;
                // SAFETY: fd_dup is a valid file descriptor from dup(), we transfer ownership
                Ok(unsafe { raw_fd_to_tcp_listener(fd_dup) })
            })
            .collect()
    }

    pub async fn wait_for_handoff_request(&self) -> Result<Option<IpcStream>, SocketHandoffError> {
        let timeout = Duration::from_secs(HANDOFF_TIMEOUT_SECS);
        let start = std::time::Instant::now();

        loop {
            match self.listener.accept() {
                Ok((stream, _addr)) => {
                    stream
                        .set_nonblocking(true)
                        .map_err(SocketHandoffError::SocketCreate)?;
                    let ipc = IpcStream::new(stream);
                    return Ok(Some(ipc));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if start.elapsed() >= timeout {
                        return Ok(None);
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(e) => return Err(SocketHandoffError::SocketCreate(e)),
            }
        }
    }

    pub async fn perform_handoff(
        &mut self,
        mut ipc: IpcStream,
    ) -> Result<Vec<u16>, SocketHandoffError> {
        let msg = ipc
            .recv(HANDOFF_TIMEOUT_SECS * 1000)
            .map_err(|e| SocketHandoffError::IpcError(e.to_string()))?
            .ok_or(SocketHandoffError::Timeout)?;

        match msg {
            Message::SocketHandoffRequest { socket_path } => {
                let expected_path = get_handoff_socket_path();
                if socket_path != expected_path.to_string_lossy() {
                    return Err(SocketHandoffError::InvalidState(format!(
                        "Unexpected socket path: {}",
                        socket_path
                    )));
                }
            }
            Message::SocketHandoffReady { ports } => {
                if ports != self.ports {
                    tracing::warn!("Port mismatch: expected {:?}, got {:?}", self.ports, ports);
                }
            }
            _ => {
                return Err(SocketHandoffError::IpcError(format!(
                    "Unexpected message: {:?}",
                    msg
                )));
            }
        }

        ipc.send(&Message::SocketHandoffReady {
            ports: self.ports.clone(),
        })
        .map_err(|e| SocketHandoffError::IpcError(e.to_string()))?;

        let passer = SocketFDPassing::from_stream(ipc.into_inner());
        self.socket_holder
            .send_all(&passer)
            .map_err(SocketHandoffError::SendFailed)?;

        tracing::info!("Sent {} socket FDs to new master", self.socket_holder.len());

        Ok(self.ports.clone())
    }

    pub fn close(self) {
        #[cfg(unix)]
        {
            drop(self.listener);
            let socket_path = get_handoff_socket_path();
            let _ = std::fs::remove_file(socket_path);
        }
    }
}

#[cfg(not(unix))]
impl SocketHandoffServer {
    pub fn new(ports: Vec<u16>) -> Result<Self, SocketHandoffError> {
        tracing::info!("Creating socket handoff server for Windows (port-swap mode)");

        let mut socket_holder = SocketHolder::new();
        for port in &ports {
            socket_holder
                .add_socket(*port, false)
                .map_err(SocketHandoffError::SendFailed)?;
        }

        Ok(Self {
            ports,
            socket_holder,
        })
    }

    pub fn get_fds(&self) -> Vec<i32> {
        self.socket_holder.get_fds()
    }

    pub fn get_tcp_listeners(&self) -> io::Result<Vec<std::net::TcpListener>> {
        self.socket_holder
            .get_socket_info()
            .iter()
            .map(|info| {
                // SAFETY: info.fd is a valid socket we own
                Ok(unsafe { raw_fd_to_tcp_listener(info.fd) })
            })
            .collect()
    }

    pub async fn wait_for_handoff_request(&self) -> Result<Option<IpcStream>, SocketHandoffError> {
        #[cfg(windows)]
        {
            use crate::process::ipc_windows::{accept_pipe_connection, create_named_pipe_server};

            let pipe_name = get_windows_handoff_pipe_name();
            let handle =
                create_named_pipe_server(&pipe_name).map_err(SocketHandoffError::SocketCreate)?;

            accept_pipe_connection(&handle).map_err(SocketHandoffError::SocketCreate)?;

            let file = handle;
            let ipc = IpcStream::new(file);
            Ok(Some(ipc))
        }

        #[cfg(not(windows))]
        {
            Err(SocketHandoffError::NotSupported(
                "Socket handoff is not supported on this platform".to_string(),
            ))
        }
    }

    pub async fn perform_handoff(
        &mut self,
        mut ipc: IpcStream,
    ) -> Result<Vec<u16>, SocketHandoffError> {
        #[cfg(windows)]
        {
            let msg = ipc
                .recv(HANDOFF_TIMEOUT_SECS * 1000)
                .map_err(|e| SocketHandoffError::IpcError(e.to_string()))?
                .ok_or(SocketHandoffError::Timeout)?;

            match msg {
                Message::SocketHandoffRequest { .. } | Message::SocketHandoffReady { .. } => {}
                _ => {
                    return Err(SocketHandoffError::IpcError(format!(
                        "Unexpected message: {:?}",
                        msg
                    )));
                }
            }

            ipc.send(&Message::SocketHandoffReady {
                ports: self.ports.clone(),
            })
            .map_err(|e| SocketHandoffError::IpcError(e.to_string()))?;

            let target_pid = std::process::id();

            for info in self.socket_holder.get_socket_info() {
                if let Ok(protocol_info) = crate::platform::windows_impl::duplicate_socket_for_child(
                    info.fd as std::os::windows::io::RawSocket,
                    target_pid,
                ) {
                    ipc.send(&Message::WindowsSocketInfo {
                        protocol_info: protocol_info.into_boxed_slice().into_vec(),
                        port: info.port,
                    })
                    .map_err(|e| SocketHandoffError::IpcError(e.to_string()))?;
                }
            }

            ipc.send(&Message::SocketHandoffComplete {
                success: true,
                fd_count: self.socket_holder.len(),
            })
            .map_err(|e| SocketHandoffError::IpcError(e.to_string()))?;

            tracing::info!(
                "Sent {} socket protocol infos to new master",
                self.socket_holder.len()
            );

            Ok(self.ports.clone())
        }

        #[cfg(not(windows))]
        {
            let _ = ipc;
            Err(SocketHandoffError::NotSupported(
                "Socket handoff is not supported on this platform".to_string(),
            ))
        }
    }

    pub fn close(self) {
        #[cfg(windows)]
        {
            if let Some(info) = self.socket_holder.get_socket_info().first() {
                // SAFETY: closesocket is called on a valid socket we own.
                unsafe {
                    windows_sys::Win32::Networking::WinSock::closesocket(info.fd as _);
                }
            }
        }
    }
}

#[cfg(windows)]
fn get_windows_handoff_pipe_name() -> String {
    "\\\\.\\pipe\\maluwaf-socket-handoff".to_string()
}

pub struct SocketHandoffClient {
    socket_path: PathBuf,
}

impl SocketHandoffClient {
    pub fn new() -> Self {
        Self {
            socket_path: get_handoff_socket_path(),
        }
    }

    #[cfg(unix)]
    pub async fn request_socket_handoff(
        &self,
        _expected_ports: &[u16],
    ) -> Result<SocketHolder, SocketHandoffError> {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(HANDOFF_TIMEOUT_SECS);

        let stream = loop {
            match UnixStream::connect(&self.socket_path) {
                Ok(s) => break s,
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                    if start.elapsed() >= timeout {
                        return Err(SocketHandoffError::Timeout);
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                Err(e) => return Err(SocketHandoffError::SocketConnect(e)),
            }
        };

        stream
            .set_nonblocking(true)
            .map_err(SocketHandoffError::SocketCreate)?;

        let mut ipc = IpcStream::new(stream);

        ipc.send(&Message::SocketHandoffRequest {
            socket_path: self.socket_path.to_string_lossy().to_string(),
        })
        .map_err(|e| SocketHandoffError::IpcError(e.to_string()))?;

        let msg = ipc
            .recv(HANDOFF_TIMEOUT_SECS * 1000)
            .map_err(|e| SocketHandoffError::IpcError(e.to_string()))?
            .ok_or(SocketHandoffError::Timeout)?;

        let ports = match msg {
            Message::SocketHandoffReady { ports } => ports,
            _ => {
                return Err(SocketHandoffError::IpcError(format!(
                    "Unexpected response: {:?}",
                    msg
                )))
            }
        };

        tracing::info!("Old master ready to send sockets for ports {:?}", ports);

        let passer = SocketFDPassing::from_stream(ipc.into_inner());
        let (fds, data) = passer
            .recv_fds(ports.len())
            .map_err(SocketHandoffError::RecvFailed)?;

        tracing::info!("Received {} socket FDs", fds.len());

        if fds.len() != ports.len() {
            return Err(SocketHandoffError::IpcError(format!(
                "FD count mismatch: expected {} FDs for ports {:?}, received {}",
                ports.len(),
                ports,
                fds.len()
            )));
        }

        let mut holder = SocketHolder::new();
        for (fd, port) in fds.iter().zip(ports.iter()) {
            holder.add_existing_fd(*fd, *port, crate::process::SocketType::Tcp);
        }

        if !data.is_empty() {
            tracing::debug!("Received handoff data: {} bytes", data.len());
        }

        Ok(holder)
    }

    #[cfg(not(unix))]
    pub async fn request_socket_handoff(
        &self,
        expected_ports: &[u16],
    ) -> Result<SocketHolder, SocketHandoffError> {
        #[cfg(windows)]
        {
            use crate::process::ipc_windows::connect_to_named_pipe;

            let pipe_name = get_windows_handoff_pipe_name();

            let start = std::time::Instant::now();
            let timeout = Duration::from_secs(HANDOFF_TIMEOUT_SECS);

            let file = loop {
                match connect_to_named_pipe(&pipe_name, 10) {
                    Ok(f) => break f,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        if start.elapsed() >= timeout {
                            return Err(SocketHandoffError::Timeout);
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    Err(e) => return Err(SocketHandoffError::SocketConnect(e)),
                }
            };

            let mut ipc = IpcStream::new(file);

            ipc.send(&Message::SocketHandoffRequest {
                socket_path: pipe_name.clone(),
            })
            .map_err(|e| SocketHandoffError::IpcError(e.to_string()))?;

            let msg = ipc
                .recv(HANDOFF_TIMEOUT_SECS * 1000)
                .map_err(|e| SocketHandoffError::IpcError(e.to_string()))?
                .ok_or(SocketHandoffError::Timeout)?;

            let ports = match msg {
                Message::SocketHandoffReady { ports } => ports,
                _ => {
                    return Err(SocketHandoffError::IpcError(format!(
                        "Unexpected response: {:?}",
                        msg
                    )))
                }
            };

            tracing::info!("Old master ready to send sockets for ports {:?}", ports);

            let mut holder = SocketHolder::new();

            loop {
                let msg = ipc
                    .recv(HANDOFF_TIMEOUT_SECS * 1000)
                    .map_err(|e| SocketHandoffError::IpcError(e.to_string()))?
                    .ok_or(SocketHandoffError::Timeout)?;

                match msg {
                    Message::WindowsSocketInfo {
                        protocol_info,
                        port,
                    } => {
                        if let Ok(handle) =
                            crate::platform::windows_impl::create_socket_from_duplicate(
                                &protocol_info,
                            )
                        {
                            let socket = handle.socket();
                            holder.add_existing_fd(
                                socket as i32,
                                port,
                                crate::process::SocketType::Tcp,
                            );
                            tracing::debug!("Received Windows socket info for port {}", port);
                        }
                    }
                    Message::SocketHandoffComplete { success, fd_count } => {
                        if success {
                            tracing::info!("Received {} Windows sockets from old master", fd_count);
                        } else {
                            return Err(SocketHandoffError::RecvFailed(
                                SocketFDError::NoFdsReceived,
                            ));
                        }
                        break;
                    }
                    _ => {
                        tracing::warn!(
                            "Unexpected message during Windows socket handoff: {:?}",
                            msg
                        );
                    }
                }
            }

            Ok(holder)
        }

        #[cfg(not(windows))]
        {
            let _ = expected_ports;
            Err(SocketHandoffError::NotSupported(
                "Socket handoff is not supported on this platform".to_string(),
            ))
        }
    }
}

impl Default for SocketHandoffClient {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DualMasterHandoff {
    server: Option<SocketHandoffServer>,
    client: Option<SocketHandoffClient>,
    ports: Vec<u16>,
}

impl DualMasterHandoff {
    pub fn new(ports: Vec<u16>) -> Self {
        Self {
            server: None,
            client: None,
            ports,
        }
    }

    pub fn prepare_as_old_master(&mut self) -> Result<(), SocketHandoffError> {
        self.server = Some(SocketHandoffServer::new(self.ports.clone())?);
        tracing::info!("Prepared as old master for socket handoff");
        Ok(())
    }

    pub fn prepare_as_new_master(&mut self) {
        self.client = Some(SocketHandoffClient::new());
        tracing::info!("Prepared as new master for socket handoff");
    }

    pub fn get_listening_sockets(&self) -> Option<Vec<std::net::TcpListener>> {
        self.server
            .as_ref()
            .and_then(|s| s.get_tcp_listeners().ok())
    }

    pub async fn wait_for_new_master(&mut self) -> Result<(), SocketHandoffError> {
        let server = self
            .server
            .as_mut()
            .ok_or(SocketHandoffError::InvalidState(
                "Not prepared as old master".to_string(),
            ))?;

        let ipc = server
            .wait_for_handoff_request()
            .await?
            .ok_or(SocketHandoffError::Timeout)?;

        server.perform_handoff(ipc).await?;

        tracing::info!("Socket handoff to new master complete");
        Ok(())
    }

    pub async fn receive_sockets_from_old_master(
        &mut self,
    ) -> Result<SocketHolder, SocketHandoffError> {
        let client = self
            .client
            .as_ref()
            .ok_or(SocketHandoffError::InvalidState(
                "Not prepared as new master".to_string(),
            ))?;

        let holder = client.request_socket_handoff(&self.ports).await?;

        tracing::info!("Received sockets from old master");
        Ok(holder)
    }

    pub fn cleanup(&mut self) {
        if let Some(server) = self.server.take() {
            server.close();
        }
        self.client = None;

        let socket_path = get_handoff_socket_path();
        if socket_path.exists() {
            let _ = std::fs::remove_file(socket_path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handoff_socket_path() {
        let path = get_handoff_socket_path();
        assert!(path.to_string_lossy().contains(HANDOFF_SOCKET_NAME));
    }
}
