use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use serde::{Deserialize, Serialize};

use super::ipc::{MasterCommand, MasterStatus};
use super::ipc_framing::{read_exact_message_sync, write_message_sync};
use super::ipc_signed::{IpcSigner, SignedIpcMessage};

pub struct CommandClient {
    socket_path: Option<PathBuf>,
    grpc_addr: Option<String>,
    method: super::ipc::CommandMethod,
}

impl CommandClient {
    pub fn new(socket_path: Option<PathBuf>, grpc_addr: Option<String>) -> Self {
        let method = if let Some(ref addr) = grpc_addr {
            super::ipc::CommandMethod::GRpc
        } else if socket_path.as_ref().map(|p| p.exists()).unwrap_or(false) {
            #[cfg(unix)]
            {
                super::ipc::CommandMethod::UnixSocket
            }
            #[cfg(windows)]
            {
                super::ipc::CommandMethod::NamedPipe
            }
        } else {
            #[cfg(unix)]
            {
                super::ipc::CommandMethod::Signal
            }
            #[cfg(windows)]
            {
                super::ipc::CommandMethod::NamedPipe
            }
        };

        Self {
            socket_path,
            grpc_addr,
            method,
        }
    }

    pub fn is_unix_socket_available(&self) -> bool {
        matches!(self.method, super::ipc::CommandMethod::UnixSocket)
    }

    pub fn method(&self) -> super::ipc::CommandMethod {
        self.method
    }

    pub fn send_command(&self, command: MasterCommand) -> Result<String, CommandError> {
        match self.method {
            super::ipc::CommandMethod::UnixSocket => self.send_via_socket(command),
            super::ipc::CommandMethod::NamedPipe => self.send_via_named_pipe(command),
            super::ipc::CommandMethod::Signal => self.send_via_signal(command),
            super::ipc::CommandMethod::GRpc => self.send_via_grpc(command),
        }
    }

    fn send_via_grpc(&self, command: MasterCommand) -> Result<String, CommandError> {
        let addr = self.grpc_addr.as_ref().ok_or(CommandError::NoSocket)?;
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| CommandError::ConnectionFailed(e.to_string()))?;

        rt.block_on(async {
            use crate::supervisor::api::proto::control_plane_client::ControlPlaneClient;
            use crate::supervisor::api::proto::{
                ApplyUpgradeRequest, ReloadRequest, StageBinaryRequest, StatusRequest, StopRequest,
                UpgradeStatusRequest,
            };

            let mut client = ControlPlaneClient::connect(format!("http://{}", addr))
                .await
                .map_err(|e| CommandError::ConnectionFailed(e.to_string()))?;

            match command {
                MasterCommand::Status => {
                    let response = client
                        .get_status(StatusRequest {})
                        .await
                        .map_err(|e| CommandError::ServerError(e.to_string()))?;
                    Ok(serde_json::to_string_pretty(&response.into_inner()).unwrap_or_default())
                }
                MasterCommand::ReloadConfig => {
                    let response = client
                        .reload_config(ReloadRequest {})
                        .await
                        .map_err(|e| CommandError::ServerError(e.to_string()))?;
                    Ok(response.into_inner().message)
                }
                MasterCommand::Stop { graceful } => {
                    let _ = client
                        .stop(StopRequest { graceful })
                        .await
                        .map_err(|e| CommandError::ServerError(e.to_string()))?;
                    Ok("Shutdown initiated".to_string())
                }
                MasterCommand::HealthCheck => {
                    let _ = client
                        .get_status(StatusRequest {})
                        .await
                        .map_err(|e| CommandError::ServerError(e.to_string()))?;
                    Ok("true".to_string())
                }
                MasterCommand::StageBinary { binary_path } => {
                    let response = client
                        .stage_binary(StageBinaryRequest {
                            binary_path: binary_path.to_string_lossy().to_string(),
                        })
                        .await
                        .map_err(|e| CommandError::ServerError(e.to_string()))?;
                    let resp = response.into_inner();
                    if resp.success {
                        Ok(format!("Binary staged: checksum={}", resp.checksum))
                    } else {
                        Ok(format!("Stage failed: {}", resp.message))
                    }
                }
                MasterCommand::ApplyUpgrade => {
                    let response = client
                        .apply_upgrade(ApplyUpgradeRequest {})
                        .await
                        .map_err(|e| CommandError::ServerError(e.to_string()))?;
                    let resp = response.into_inner();
                    if resp.success {
                        Ok(format!(
                            "Upgrade applied: {} upgraded, {} failed",
                            resp.upgraded_count, resp.failed_count
                        ))
                    } else {
                        Ok(format!("Apply failed: {}", resp.message))
                    }
                }
                MasterCommand::GetUpgradeStatus => {
                    let response = client
                        .get_upgrade_status(UpgradeStatusRequest {})
                        .await
                        .map_err(|e| CommandError::ServerError(e.to_string()))?;
                    Ok(serde_json::to_string_pretty(&response.into_inner()).unwrap_or_default())
                }
                MasterCommand::RollbackUpgrade => {
                    Ok("Rollback not implemented via gRPC".to_string())
                }
            }
        })
    }

    fn send_via_socket(&self, command: MasterCommand) -> Result<String, CommandError> {
        let socket_path = self.socket_path.as_ref().ok_or(CommandError::NoSocket)?;

        let mut stream = UnixStream::connect(socket_path)
            .map_err(|e| CommandError::ConnectionFailed(e.to_string()))?;

        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| CommandError::ConnectionFailed(e.to_string()))?;

        if let Some(signer) = IpcSigner::try_from_env() {
            let signed_data = SignedIpcMessage::serialize_signed(&command, &signer)
                .map_err(|e| CommandError::SendFailed(e.to_string()))?;
            stream
                .write_all(&signed_data)
                .map_err(|e| CommandError::SendFailed(e.to_string()))?;
            stream
                .flush()
                .map_err(|e| CommandError::SendFailed(e.to_string()))?;
        } else {
            write_message_sync(&mut stream, &command)
                .map_err(|e| CommandError::SendFailed(e.to_string()))?;
        }

        let response: CommandResponse = read_exact_message_sync(&mut stream)
            .map_err(|e| CommandError::ReceiveFailed(e.to_string()))?;

        match response {
            CommandResponse::Ok(msg) => Ok(msg),
            CommandResponse::Error(msg) => Err(CommandError::ServerError(msg)),
            CommandResponse::Status(status) => {
                Ok(serde_json::to_string_pretty(&status).unwrap_or_default())
            }
        }
    }

    #[cfg(windows)]
    fn send_via_named_pipe(&self, command: MasterCommand) -> Result<String, CommandError> {
        let pipe_name = "\\\\.\\pipe\\synvoid-commands";

        let mut stream = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe_name)
            .map_err(|e| CommandError::ConnectionFailed(e.to_string()))?;

        if let Some(signer) = IpcSigner::try_from_env() {
            let signed_data = SignedIpcMessage::serialize_signed(&command, &signer)
                .map_err(|e| CommandError::SendFailed(e.to_string()))?;
            stream
                .write_all(&signed_data)
                .map_err(|e| CommandError::SendFailed(e.to_string()))?;
            stream
                .flush()
                .map_err(|e| CommandError::SendFailed(e.to_string()))?;
        } else {
            write_message_sync(&mut stream, &command)
                .map_err(|e| CommandError::SendFailed(e.to_string()))?;
        }

        let response: CommandResponse = read_exact_message_sync(&mut stream)
            .map_err(|e| CommandError::ReceiveFailed(e.to_string()))?;

        match response {
            CommandResponse::Ok(msg) => Ok(msg),
            CommandResponse::Error(msg) => Err(CommandError::ServerError(msg)),
            CommandResponse::Status(status) => {
                Ok(serde_json::to_string_pretty(&status).unwrap_or_default())
            }
        }
    }

    #[cfg(unix)]
    fn send_via_named_pipe(&self, _command: MasterCommand) -> Result<String, CommandError> {
        Err(CommandError::NotSupported(
            "Named pipe not supported on Unix".to_string(),
        ))
    }

    fn send_via_signal(&self, command: MasterCommand) -> Result<String, CommandError> {
        let pid = self
            .get_master_pid()
            .ok_or(CommandError::NoRunningInstance)?;

        #[cfg(unix)]
        {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            let sig = match command {
                MasterCommand::Stop { .. } => Signal::SIGTERM,
                MasterCommand::ReloadConfig => Signal::SIGHUP,
                MasterCommand::HealthCheck => Signal::SIGUSR1,
                MasterCommand::Status => Signal::SIGUSR2,
                MasterCommand::StageBinary { .. }
                | MasterCommand::ApplyUpgrade
                | MasterCommand::GetUpgradeStatus
                | MasterCommand::RollbackUpgrade => {
                    return Err(CommandError::NotSupported(
                        "Upgrade commands not supported via signal".to_string(),
                    ));
                }
            };

            let pid = Pid::from_raw(pid as i32);
            kill(pid, sig).map_err(|e| CommandError::SignalFailed(e.to_string()))?;

            Ok(format!("Signal {:?} sent to PID {}", sig, pid))
        }

        #[cfg(not(unix))]
        {
            Err(CommandError::NotSupported(
                "Signals not supported on this platform".to_string(),
            ))
        }
    }

    fn get_master_pid(&self) -> Option<u32> {
        let _socket_path = self.socket_path.as_ref()?;

        let data_dir = dirs::data_dir()
            .map(|d| d.join(".synvoid"))
            .unwrap_or_else(|| PathBuf::from(".synvoid"));

        let pid_file = data_dir.join("synvoidwaf.pid");
        if pid_file.exists() {
            if let Ok(content) = std::fs::read_to_string(&pid_file) {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                    return parsed.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32);
                }
            }
        }
        None
    }

    pub fn get_status(&self) -> Result<MasterStatus, CommandError> {
        match self.method {
            super::ipc::CommandMethod::UnixSocket => {
                let socket_path = self.socket_path.as_ref().ok_or(CommandError::NoSocket)?;

                let mut stream = UnixStream::connect(socket_path)
                    .map_err(|e| CommandError::ConnectionFailed(e.to_string()))?;

                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .map_err(|e| CommandError::ConnectionFailed(e.to_string()))?;

                let command = MasterCommand::Status;
                write_message_sync(&mut stream, &command)
                    .map_err(|e| CommandError::SendFailed(e.to_string()))?;

                let response: CommandResponse = read_exact_message_sync(&mut stream)
                    .map_err(|e| CommandError::ReceiveFailed(e.to_string()))?;

                match response {
                    CommandResponse::Status(status) => Ok(status),
                    CommandResponse::Ok(msg) => Err(CommandError::UnexpectedResponse(msg)),
                    CommandResponse::Error(msg) => Err(CommandError::ServerError(msg)),
                }
            }
            super::ipc::CommandMethod::NamedPipe => {
                let pipe_name = "\\\\.\\pipe\\synvoid-commands";

                let mut stream = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(pipe_name)
                    .map_err(|e| CommandError::ConnectionFailed(e.to_string()))?;

                let command = MasterCommand::Status;
                write_message_sync(&mut stream, &command)
                    .map_err(|e| CommandError::SendFailed(e.to_string()))?;

                let response: CommandResponse = read_exact_message_sync(&mut stream)
                    .map_err(|e| CommandError::ReceiveFailed(e.to_string()))?;

                match response {
                    CommandResponse::Status(status) => Ok(status),
                    CommandResponse::Ok(msg) => Err(CommandError::UnexpectedResponse(msg)),
                    CommandResponse::Error(msg) => Err(CommandError::ServerError(msg)),
                }
            }
            super::ipc::CommandMethod::Signal => Err(CommandError::NotSupported(
                "Status not available via signal".to_string(),
            )),
            super::ipc::CommandMethod::GRpc => {
                let addr = self.grpc_addr.as_ref().ok_or(CommandError::NoSocket)?;
                let rt = tokio::runtime::Runtime::new()
                    .map_err(|e| CommandError::ConnectionFailed(e.to_string()))?;

                rt.block_on(async {
                    use crate::supervisor::api::proto::control_plane_client::ControlPlaneClient;
                    use crate::supervisor::api::proto::StatusRequest;

                    let mut client = ControlPlaneClient::connect(format!("http://{}", addr))
                        .await
                        .map_err(|e| CommandError::ConnectionFailed(e.to_string()))?;

                    let response = client
                        .get_status(StatusRequest {})
                        .await
                        .map_err(|e| CommandError::ServerError(e.to_string()))?;

                    let inner = response.into_inner();
                    let stats = inner.stats.unwrap_or_default();

                    let workers = inner
                        .workers
                        .into_iter()
                        .map(|w| super::ipc::WorkerStatusInfo {
                            id: w.id as usize,
                            pid: w.pid,
                            port: w.port as u16,
                            status: w.status,
                            requests: w.requests,
                            blocked: w.blocked,
                        })
                        .collect();

                    Ok(MasterStatus {
                        master_pid: inner.pid,
                        started_at: 0,
                        uptime_secs: inner.uptime_secs,
                        version: inner.version,
                        workers,
                        stats: super::ipc::StatusStats {
                            total_requests: stats.total_requests,
                            blocked_last_hour: stats.blocked_last_hour,
                            challenged_last_hour: stats.challenged_last_hour,
                            proxied_last_hour: 0,
                            active_blocks: stats.active_blocks as usize,
                            active_violations: 0,
                        },
                        threat_summary: super::ipc::ThreatSummary::default(),
                    })
                })
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CommandResponse {
    Ok(String),
    Error(String),
    Status(MasterStatus),
}

#[derive(Debug)]
pub enum CommandError {
    NoSocket,
    NoRunningInstance,
    ConnectionFailed(String),
    SendFailed(String),
    ReceiveFailed(String),
    SerializationFailed(String),
    DeserializationFailed(String),
    UnexpectedResponse(String),
    ServerError(String),
    SignalFailed(String),
    NotSupported(String),
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandError::NoSocket => write!(f, "No socket path available"),
            CommandError::NoRunningInstance => write!(f, "No running instance found"),
            CommandError::ConnectionFailed(e) => write!(f, "Connection failed: {}", e),
            CommandError::SendFailed(e) => write!(f, "Send failed: {}", e),
            CommandError::ReceiveFailed(e) => write!(f, "Receive failed: {}", e),
            CommandError::SerializationFailed(e) => write!(f, "Serialization failed: {}", e),
            CommandError::DeserializationFailed(e) => write!(f, "Deserialization failed: {}", e),
            CommandError::UnexpectedResponse(e) => write!(f, "Unexpected response: {}", e),
            CommandError::ServerError(e) => write!(f, "Server error: {}", e),
            CommandError::SignalFailed(e) => write!(f, "Signal failed: {}", e),
            CommandError::NotSupported(e) => write!(f, "Not supported: {}", e),
        }
    }
}

impl std::error::Error for CommandError {}
