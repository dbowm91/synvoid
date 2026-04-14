use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use crate::process::{IpcSigner, IpcStream, Message};
use crate::utils::errors::ipc as ipc_errors;

fn create_ipc_signer() -> Option<Arc<IpcSigner>> {
    if let Ok(key_file) = std::env::var("MALUWAF_IPC_KEY_FILE") {
        if let Ok(key_hex) = std::fs::read_to_string(&key_file) {
            let key_hex = key_hex.trim();
            if key_hex.len() == 64 {
                let mut key = [0u8; 32];
                let mut valid = true;
                for (i, chunk) in key_hex.as_bytes().chunks(2).enumerate() {
                    if chunk.len() != 2 {
                        valid = false;
                        break;
                    }
                    if let Ok(s) = std::str::from_utf8(chunk) {
                        if let Ok(b) = u8::from_str_radix(s, 16) {
                            key[i] = b;
                        } else {
                            valid = false;
                            break;
                        }
                    } else {
                        valid = false;
                        break;
                    }
                }
                if valid {
                    let _ = std::fs::remove_file(&key_file);
                    return Some(Arc::new(IpcSigner::new(&key)));
                }
            }
        }
    }
    if let Ok(key_hex) = std::env::var("MALUWAF_IPC_KEY") {
        if key_hex.len() == 64 {
            let mut key = [0u8; 32];
            let mut valid = true;
            for (i, chunk) in key_hex.as_bytes().chunks(2).enumerate() {
                if chunk.len() != 2 {
                    valid = false;
                    break;
                }
                if let Ok(s) = std::str::from_utf8(chunk) {
                    if let Ok(b) = u8::from_str_radix(s, 16) {
                        key[i] = b;
                    } else {
                        valid = false;
                        break;
                    }
                } else {
                    valid = false;
                    break;
                }
            }
            if valid {
                return Some(Arc::new(IpcSigner::new(&key)));
            }
        }
    }
    None
}

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

    fn connect(&self) -> Result<IpcStream, String> {
        if let Some(signer) = create_ipc_signer() {
            IpcStream::connect_with_signer(&self.socket_path, signer)
                .map_err(|e| ipc_errors::connect_failed(&e))
        } else {
            IpcStream::connect_unix(&self.socket_path).map_err(|e| ipc_errors::connect_failed(&e))
        }
    }

    fn handle_recv_result(
        &self,
        result: Result<Option<Message>, io::Error>,
    ) -> Result<Message, String> {
        match result {
            Ok(Some(msg)) => Ok(msg),
            Ok(None) => Err(self.timeout_error()),
            Err(e) => Err(format!("IPC error: {}", e)),
        }
    }

    fn timeout_error(&self) -> String {
        format!("Timeout waiting for response after {}ms", self.timeout_ms)
    }

    pub fn send_and_expect<F>(&mut self, request: &Message, expected: F) -> Result<Message, String>
    where
        F: FnOnce(&Message) -> bool,
    {
        let mut stream = self.connect()?;

        stream
            .send_signed(request)
            .map_err(|e| format!("Failed to send message: {}", e))?;

        let result = stream.recv(self.timeout_ms);
        match result {
            Ok(Some(msg)) if expected(&msg) => Ok(msg),
            Ok(Some(msg)) => Err(format!("Unexpected response: {:?}", msg)),
            _ => self.handle_recv_result(result),
        }
    }

    pub fn try_send(&mut self, msg: &Message) -> Result<(), String> {
        let mut stream = self.connect()?;
        stream
            .send_signed(msg)
            .map_err(|e| format!("Failed to send: {}", e))
    }

    pub fn recv(&mut self) -> Result<Message, String> {
        let mut stream = self.connect()?;
        self.handle_recv_result(stream.recv(self.timeout_ms))
    }

    pub fn send_and_recv(&mut self, msg: &Message) -> Result<Message, String> {
        let mut stream = self.connect()?;

        stream
            .send_signed(msg)
            .map_err(|e| format!("Failed to send: {}", e))?;

        self.handle_recv_result(stream.recv(self.timeout_ms))
    }
}

pub trait IpcCommand: Send + Sync {
    type Response;

    fn socket_path(&self) -> &PathBuf;
    fn timeout_ms(&self) -> u64;
    fn build_request(&self) -> Message;
    fn handle_response(&self, msg: Message) -> Result<Self::Response, String>;
    fn expected_message(&self) -> Box<dyn Fn(&Message) -> bool + '_> {
        Box::new(|_| true)
    }
}

pub fn execute_ipc_command<C: IpcCommand>(cmd: &C) -> Result<C::Response, String> {
    let mut client = IpcClient::new(cmd.socket_path().clone()).with_timeout(cmd.timeout_ms());

    let request = cmd.build_request();
    let expected = cmd.expected_message();

    client
        .send_and_expect(&request, move |msg| expected(msg))
        .and_then(|msg| cmd.handle_response(msg))
}

pub struct SimpleIpcCommand {
    socket_path: PathBuf,
    timeout_ms: u64,
    request: Message,
    expected_fn: fn(&Message) -> bool,
    response_fn: fn(Message) -> Result<String, String>,
}

impl SimpleIpcCommand {
    pub fn new(
        socket_path: PathBuf,
        timeout_ms: u64,
        request: Message,
        expected: fn(&Message) -> bool,
        response: fn(Message) -> Result<String, String>,
    ) -> Self {
        Self {
            socket_path,
            timeout_ms,
            request,
            expected_fn: expected,
            response_fn: response,
        }
    }
}

impl IpcCommand for SimpleIpcCommand {
    type Response = String;

    fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }

    fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    fn build_request(&self) -> Message {
        self.request.clone()
    }

    fn handle_response(&self, msg: Message) -> Result<Self::Response, String> {
        (self.response_fn)(msg)
    }

    fn expected_message(&self) -> Box<dyn Fn(&Message) -> bool + '_> {
        Box::new(self.expected_fn)
    }
}

pub fn connect_and_expect(
    socket_path: &std::path::Path,
    request: &Message,
    expected: impl FnOnce(&Message) -> bool,
    timeout_ms: Option<u64>,
) -> Result<Message, String> {
    let mut client =
        IpcClient::new(socket_path.to_path_buf()).with_timeout(timeout_ms.unwrap_or(5000));
    client.send_and_expect(request, expected)
}

pub fn send_and_receive(
    socket_path: &std::path::Path,
    request: &Message,
    timeout_ms: u64,
) -> Result<Message, String> {
    let mut client = IpcClient::new(socket_path.to_path_buf()).with_timeout(timeout_ms);
    client.send_and_recv(request)
}

pub fn send_message(socket_path: &std::path::Path, msg: &Message) -> Result<(), String> {
    let mut stream = if let Some(signer) = create_ipc_signer() {
        IpcStream::connect_with_signer(socket_path, signer)
            .map_err(|e| ipc_errors::connect_failed(&e))?
    } else {
        IpcStream::connect_unix(socket_path).map_err(|e| ipc_errors::connect_failed(&e))?
    };
    stream
        .send_signed(msg)
        .map_err(|e| ipc_errors::send_failed(&e))
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

pub fn send_and_expect_response(
    socket_path: &std::path::Path,
    msg: Message,
    expected: fn(&Message) -> bool,
    timeout_ms: u64,
) -> Result<Message, String> {
    let mut stream = if let Some(signer) = create_ipc_signer() {
        IpcStream::connect_with_signer(socket_path, signer)
            .map_err(|e| ipc_errors::connect_failed(&e))?
    } else {
        IpcStream::connect_unix(socket_path).map_err(|e| ipc_errors::connect_failed(&e))?
    };

    stream
        .send_signed(&msg)
        .map_err(|e| ipc_errors::send_failed(&e))?;

    match stream.recv(timeout_ms) {
        Ok(Some(response)) if expected(&response) => Ok(response),
        Ok(Some(other)) => Err(format!("Unexpected response: {:?}", other)),
        Ok(None) => Err(format!(
            "Timeout waiting for response after {}ms",
            timeout_ms
        )),
        Err(e) => Err(format!("IPC error: {}", e)),
    }
}
