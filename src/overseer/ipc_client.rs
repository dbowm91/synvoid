use std::io;
use std::path::PathBuf;

use crate::process::{IpcStream, Message};

pub struct IpcClient {
    socket_path: PathBuf,
    timeout_ms: u64,
}

impl IpcClient {
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

    pub fn connect(&self) -> Result<IpcStream, String> {
        IpcStream::connect_unix(&self.socket_path)
            .map_err(|e| format!("Failed to connect to {}: {}", self.socket_path.display(), e))
    }

    pub fn send_and_expect<F>(&mut self, request: &Message, expected: F) -> Result<Message, String>
    where
        F: FnOnce(&Message) -> bool,
    {
        let mut stream = self.connect()?;

        stream
            .send(request)
            .map_err(|e| format!("Failed to send message: {}", e))?;

        match stream.recv(self.timeout_ms) {
            Ok(Some(msg)) if expected(&msg) => Ok(msg),
            Ok(Some(msg)) => Err(format!("Unexpected response: {:?}", msg)),
            Ok(None) => Err(format!(
                "Timeout waiting for response after {}ms",
                self.timeout_ms
            )),
            Err(e) => Err(format!("IPC error: {}", e)),
        }
    }

    pub fn try_send(&mut self, msg: &Message) -> Result<(), String> {
        let mut stream = self.connect()?;
        stream
            .send(msg)
            .map_err(|e| format!("Failed to send: {}", e))
    }

    pub fn recv(&mut self) -> Result<Message, String> {
        let mut stream = self.connect()?;
        match stream.recv(self.timeout_ms) {
            Ok(Some(msg)) => Ok(msg),
            Ok(None) => Err(format!(
                "Timeout waiting for response after {}ms",
                self.timeout_ms
            )),
            Err(e) => Err(format!("IPC error: {}", e)),
        }
    }

    pub fn send_and_recv(&mut self, msg: &Message) -> Result<Message, String> {
        let mut stream = self.connect()?;

        stream
            .send(msg)
            .map_err(|e| format!("Failed to send: {}", e))?;

        match stream.recv(self.timeout_ms) {
            Ok(Some(resp)) => Ok(resp),
            Ok(None) => Err(format!(
                "Timeout waiting for response after {}ms",
                self.timeout_ms
            )),
            Err(e) => Err(format!("IPC error: {}", e)),
        }
    }
}

pub fn connect_and_expect(
    socket_path: &PathBuf,
    request: &Message,
    expected: impl FnOnce(&Message) -> bool,
    timeout_ms: Option<u64>,
) -> Result<Message, String> {
    let mut client = IpcClient::new(socket_path.clone()).with_timeout(timeout_ms.unwrap_or(5000));
    client.send_and_expect(request, expected)
}

pub fn send_and_receive(
    socket_path: &PathBuf,
    request: &Message,
    timeout_ms: u64,
) -> Result<Message, String> {
    let mut client = IpcClient::new(socket_path.clone()).with_timeout(timeout_ms);
    client.send_and_recv(request)
}

pub fn send_message(socket_path: &PathBuf, msg: &Message) -> Result<(), String> {
    let mut stream = IpcStream::connect_unix(socket_path)
        .map_err(|e| format!("Failed to connect to {}: {}", socket_path.display(), e))?;
    stream
        .send(msg)
        .map_err(|e| format!("Failed to send: {}", e))
}

pub fn map_ipc_error<T>(result: Result<T, io::Error>, context: &str) -> Result<T, String> {
    result.map_err(|e| format!("{}: {}", context, e))
}

pub fn require_health_check_ack(msg: &Message) -> bool {
    matches!(msg, Message::HealthCheckAck { .. })
}

pub fn require_upgrade_prepare_ack(msg: &Message) -> bool {
    matches!(msg, Message::OverseerUpgradePrepareAck { .. })
}

pub fn require_drain_workers_ack(msg: &Message) -> bool {
    matches!(msg, Message::OverseerDrainWorkersAck { .. })
}

pub fn require_drain_status_response(msg: &Message) -> bool {
    matches!(msg, Message::DrainStatusResponse { .. })
}

pub fn require_status_response(msg: &Message) -> bool {
    matches!(msg, Message::OverseerStatusResponse { .. })
}
