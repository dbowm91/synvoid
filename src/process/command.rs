use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use serde::{Deserialize, Serialize};

use super::ipc::{MasterCommand, MasterStatus};

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

        let json = serde_json::to_vec(&command)
            .map_err(|e| CommandError::SerializationFailed(e.to_string()))?;

        let len = json.len() as u32;
        stream
            .write_all(&len.to_be_bytes())
            .map_err(|e| CommandError::SendFailed(e.to_string()))?;
        stream
            .write_all(&json)
            .map_err(|e| CommandError::SendFailed(e.to_string()))?;
        stream
            .flush()
            .map_err(|e| CommandError::SendFailed(e.to_string()))?;

        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .map_err(|e| CommandError::ReceiveFailed(e.to_string()))?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > 1024 * 1024 {
            return Err(CommandError::ReceiveFailed(
                "Response too large".to_string(),
            ));
        }

        let mut response_buf = vec![0u8; len];
        stream
            .read_exact(&mut response_buf)
            .map_err(|e| CommandError::ReceiveFailed(e.to_string()))?;

        let response: CommandResponse = serde_json::from_slice(&response_buf)
            .map_err(|e| CommandError::DeserializationFailed(e.to_string()))?;

        match response {
            CommandResponse::Ok(msg) => Ok(msg),
            CommandResponse::Error(msg) => Err(CommandError::ServerError(msg)),
            CommandResponse::Status(status) => {
                Ok(serde_json::to_string_pretty(&status).unwrap_or_default())
            }
        }
    }

    /// Send command to master via Windows named pipe.
    ///
    /// On Windows, we use a named pipe for CLI commands instead of signals.
    /// The pipe path is: \\.\pipe\rustwaf-commands
    #[cfg(windows)]
    fn send_via_named_pipe(&self, command: MasterCommand) -> Result<String, CommandError> {
        use std::os::windows::ffi::OsStrExt;

        let pipe_name = "\\\\.\\pipe\\rustwaf-commands";

        let mut stream = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe_name)
            .map_err(|e| CommandError::ConnectionFailed(e.to_string()))?;

        let json = serde_json::to_vec(&command)
            .map_err(|e| CommandError::SerializationFailed(e.to_string()))?;

        let len = json.len() as u32;
        stream
            .write_all(&len.to_be_bytes())
            .map_err(|e| CommandError::SendFailed(e.to_string()))?;
        stream
            .write_all(&json)
            .map_err(|e| CommandError::SendFailed(e.to_string()))?;
        stream
            .flush()
            .map_err(|e| CommandError::SendFailed(e.to_string()))?;

        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .map_err(|e| CommandError::ReceiveFailed(e.to_string()))?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > 1024 * 1024 {
            return Err(CommandError::ReceiveFailed(
                "Response too large".to_string(),
            ));
        }

        let mut response_buf = vec![0u8; len];
        stream
            .read_exact(&mut response_buf)
            .map_err(|e| CommandError::ReceiveFailed(e.to_string()))?;

        let response: CommandResponse = serde_json::from_slice(&response_buf)
            .map_err(|e| CommandError::DeserializationFailed(e.to_string()))?;

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

    /// Send command to master via signal.
    ///
    /// Signal handling notes:
    /// - This is used by external clients (e.g., CLI tools) to communicate with the master
    /// - On Unix, signals are the primary mechanism for external commands
    /// - On Windows, signals are not available - this path returns an error
    /// - The master handles these signals via tokio's signal handlers in main.rs
    /// - For a more robust solution on Windows, we could use named events or a control pipe
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
        let socket_path = self.socket_path.as_ref()?;

        // Try to get PID from socket filename or read from a pid file
        // For now, we'll check the default locations
        let data_dir = dirs::data_dir()
            .map(|d| d.join(".rustwaf"))
            .unwrap_or_else(|| PathBuf::from(".rustwaf"));

        let pid_file = data_dir.join("rustwaf.pid");
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
                let json = serde_json::to_vec(&command)
                    .map_err(|e| CommandError::SerializationFailed(e.to_string()))?;

                let len = json.len() as u32;
                stream
                    .write_all(&len.to_be_bytes())
                    .map_err(|e| CommandError::SendFailed(e.to_string()))?;
                stream
                    .write_all(&json)
                    .map_err(|e| CommandError::SendFailed(e.to_string()))?;
                stream
                    .flush()
                    .map_err(|e| CommandError::SendFailed(e.to_string()))?;

                let mut len_buf = [0u8; 4];
                stream
                    .read_exact(&mut len_buf)
                    .map_err(|e| CommandError::ReceiveFailed(e.to_string()))?;
                let len = u32::from_be_bytes(len_buf) as usize;

                let mut response_buf = vec![0u8; len];
                stream
                    .read_exact(&mut response_buf)
                    .map_err(|e| CommandError::ReceiveFailed(e.to_string()))?;

                let response: CommandResponse = serde_json::from_slice(&response_buf)
                    .map_err(|e| CommandError::DeserializationFailed(e.to_string()))?;

                match response {
                    CommandResponse::Status(status) => Ok(status),
                    CommandResponse::Ok(msg) => Err(CommandError::UnexpectedResponse(msg)),
                    CommandResponse::Error(msg) => Err(CommandError::ServerError(msg)),
                }
            }
            super::ipc::CommandMethod::NamedPipe => {
                // Named pipe status is similar to socket
                let pipe_name = "\\\\.\\pipe\\rustwaf-commands";

                let mut stream = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(pipe_name)
                    .map_err(|e| CommandError::ConnectionFailed(e.to_string()))?;

                let command = MasterCommand::Status;
                let json = serde_json::to_vec(&command)
                    .map_err(|e| CommandError::SerializationFailed(e.to_string()))?;

                let len = json.len() as u32;
                stream
                    .write_all(&len.to_be_bytes())
                    .map_err(|e| CommandError::SendFailed(e.to_string()))?;
                stream
                    .write_all(&json)
                    .map_err(|e| CommandError::SendFailed(e.to_string()))?;
                stream
                    .flush()
                    .map_err(|e| CommandError::SendFailed(e.to_string()))?;

                let mut len_buf = [0u8; 4];
                stream
                    .read_exact(&mut len_buf)
                    .map_err(|e| CommandError::ReceiveFailed(e.to_string()))?;
                let len = u32::from_be_bytes(len_buf) as usize;

                if len > 1024 * 1024 {
                    return Err(CommandError::ReceiveFailed(
                        "Response too large".to_string(),
                    ));
                }

                let mut response_buf = vec![0u8; len];
                stream
                    .read_exact(&mut response_buf)
                    .map_err(|e| CommandError::ReceiveFailed(e.to_string()))?;

                let response: CommandResponse = serde_json::from_slice(&response_buf)
                    .map_err(|e| CommandError::DeserializationFailed(e.to_string()))?;

                match response {
                    CommandResponse::Status(status) => Ok(status),
                    CommandResponse::Ok(msg) => Err(CommandError::UnexpectedResponse(msg)),
                    CommandResponse::Error(msg) => Err(CommandError::ServerError(msg)),
                }
            }
            super::ipc::CommandMethod::Signal => {
                // For signal mode, we'd need the master to write status to a file
                // For now, return an error
                Err(CommandError::NotSupported(
                    "Status not available via signal".to_string(),
                ))
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
