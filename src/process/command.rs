use std::path::PathBuf;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use serde::{Deserialize, Serialize};

use super::ipc::{MasterCommand, MasterStatus};
use super::ipc_framing::{read_exact_message_sync, write_message_sync};

pub struct CommandClient {
    socket_path: Option<PathBuf>,
    method: super::ipc::CommandMethod,
}

impl CommandClient {
    pub fn new(socket_path: Option<PathBuf>) -> Self {
        let method = if socket_path.as_ref().map(|p| p.exists()).unwrap_or(false) {
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
        }
    }

    fn send_via_socket(&self, command: MasterCommand) -> Result<String, CommandError> {
        let socket_path = self.socket_path.as_ref().ok_or(CommandError::NoSocket)?;

        let mut stream = UnixStream::connect(socket_path)
            .map_err(|e| CommandError::ConnectionFailed(e.to_string()))?;

        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| CommandError::ConnectionFailed(e.to_string()))?;

        write_message_sync(&mut stream, &command)
            .map_err(|e| CommandError::SendFailed(e.to_string()))?;

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
        let pipe_name = "\\\\.\\pipe\\maluwaf-commands";

        let mut stream = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe_name)
            .map_err(|e| CommandError::ConnectionFailed(e.to_string()))?;

        write_message_sync(&mut stream, &command)
            .map_err(|e| CommandError::SendFailed(e.to_string()))?;

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
            .map(|d| d.join(".maluwaf"))
            .unwrap_or_else(|| PathBuf::from(".maluwaf"));

        let pid_file = data_dir.join("maluwafwaf.pid");
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
                let pipe_name = "\\\\.\\pipe\\maluwaf-commands";

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
