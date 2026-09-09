#![allow(dead_code)]

use std::sync::Arc;

use hyper_util::rt::TokioIo;
use parking_lot::Mutex;

use crate::worker::drain_state::WorkerDrainState;
use synvoid_utils::RunningFlag;

// Canonical protocol-sniff helpers (Phase 20): single implementation in
// `synvoid_http::framing`, re-exported here for the accept loop. Behavior
// tests live canonically in `crates/synvoid-http/src/framing.rs`.
pub(super) use synvoid_http::framing::{is_tls_client_hello, is_valid_http_request_start};

pub(super) struct ProtocolValidatingStream<S> {
    stream: S,
    pub(super) initial_bytes: Option<Vec<u8>>,
}

impl<S> ProtocolValidatingStream<S> {
    pub(super) fn new(stream: S, initial_bytes: Vec<u8>) -> Self {
        Self {
            stream,
            initial_bytes: Some(initial_bytes),
        }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for ProtocolValidatingStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(bytes) = self.initial_bytes.take() {
            let len = bytes.len().min(buf.remaining());
            buf.put_slice(&bytes[..len]);
            if len < bytes.len() {
                self.initial_bytes = Some(bytes[len..].to_vec());
            }
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for ProtocolValidatingStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

pub(super) struct HttpConnection {
    io: Mutex<Option<TokioIo<ProtocolValidatingStream<tokio::net::TcpStream>>>>,
    drop_requested: RunningFlag,
}

impl HttpConnection {
    pub(super) fn new(stream: tokio::net::TcpStream, initial_bytes: Vec<u8>) -> Self {
        let stream = if initial_bytes.is_empty() {
            ProtocolValidatingStream::new(stream, vec![])
        } else {
            ProtocolValidatingStream::new(stream, initial_bytes)
        };
        Self {
            io: Mutex::new(Some(TokioIo::new(stream))),
            drop_requested: RunningFlag::new(),
        }
    }

    pub(super) fn request_drop(&self) {
        self.drop_requested.stop();
    }

    pub(super) fn should_drop(&self) -> bool {
        !self.drop_requested.is_running()
    }

    pub(super) fn take_stream(
        &self,
    ) -> Option<TokioIo<ProtocolValidatingStream<tokio::net::TcpStream>>> {
        self.io.lock().take()
    }
}

pub(super) struct DrainGuard {
    state: Option<Arc<WorkerDrainState>>,
}

impl DrainGuard {
    pub(super) fn new(state: Option<Arc<WorkerDrainState>>) -> Self {
        if let Some(ref ds) = state {
            ds.increment_active();
        }
        Self { state }
    }
}

impl Drop for DrainGuard {
    fn drop(&mut self) {
        if let Some(ref state) = self.state {
            state.decrement_active();
        }
    }
}
