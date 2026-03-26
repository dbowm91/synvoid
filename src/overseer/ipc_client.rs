use std::io;
use std::path::PathBuf;

use crate::process::{IpcStream, Message};
use crate::utils::errors::ipc as ipc_errors;

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
        IpcStream::connect_unix(&self.socket_path).map_err(|e| ipc_errors::connect_failed(&e))
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
            .send(request)
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
            .send(msg)
            .map_err(|e| format!("Failed to send: {}", e))
    }

    pub fn recv(&mut self) -> Result<Message, String> {
        let mut stream = self.connect()?;
        self.handle_recv_result(stream.recv(self.timeout_ms))
    }

    pub fn send_and_recv(&mut self, msg: &Message) -> Result<Message, String> {
        let mut stream = self.connect()?;

        stream
            .send(msg)
            .map_err(|e| format!("Failed to send: {}", e))?;

        self.handle_recv_result(stream.recv(self.timeout_ms))
    }
}

/// Trait for executing IPC commands with a consistent pattern.
///
/// Implement this trait to create reusable IPC command handlers that follow
/// the connect -> send -> receive -> handle response pattern.
pub trait IpcCommand: Send + Sync {
    /// The type of response expected from this command.
    type Response;

    /// Returns the socket path to connect to.
    fn socket_path(&self) -> &PathBuf;
    /// Returns the timeout in milliseconds for this command.
    fn timeout_ms(&self) -> u64;
    /// Builds the request message to send.
    fn build_request(&self) -> Message;
    /// Handles the response message and converts it to the target response type.
    fn handle_response(&self, msg: Message) -> Result<Self::Response, String>;
    /// Returns a filter function to validate expected response messages.
    /// Default accepts any message.
    fn expected_message(&self) -> Box<dyn Fn(&Message) -> bool + '_> {
        Box::new(|_| true)
    }
}

/// Executes an IPC command using the IpcCommand trait.
///
/// This function handles the full lifecycle: connect, send, receive, and response handling.
pub fn execute_ipc_command<C: IpcCommand>(cmd: &C) -> Result<C::Response, String> {
    let mut client = IpcClient::new(cmd.socket_path().clone()).with_timeout(cmd.timeout_ms());

    let request = cmd.build_request();
    let expected = cmd.expected_message();

    client
        .send_and_expect(&request, move |msg| expected(msg))
        .and_then(|msg| cmd.handle_response(msg))
}

/// A simple IPC command implementation that uses function pointers.
///
/// Useful for one-off commands without implementing the full trait.
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
    let mut stream =
        IpcStream::connect_unix(socket_path).map_err(|e| ipc_errors::connect_failed(&e))?;
    stream.send(msg).map_err(|e| ipc_errors::send_failed(&e))
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
    let mut stream =
        IpcStream::connect_unix(socket_path).map_err(|e| ipc_errors::connect_failed(&e))?;

    stream.send(&msg).map_err(|e| ipc_errors::send_failed(&e))?;

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
