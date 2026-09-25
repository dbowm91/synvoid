//! Transport-neutral inbound request boundary (Phase 74).
//!
//! The canonical request pipeline consumes [`InboundRequest`] instead of
//! concrete transport types. Hyper ingress is converted in
//! [`crate::hyper_adapter`]; H2 flows through the same conversion, H3 was
//! already neutral, and the future direct-H1 service adapter (Phase 75)
//! targets this same type without changing it.
//!
//! This module names no Hyper or downstream-runtime types.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;

/// Neutral inbound body error.
///
/// Every variant fails closed downstream exactly like today's body errors:
/// the buffered path renders its existing 403/413/empty outcomes and the
/// streaming path surfaces the failure without retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundBodyError {
    /// Transport/read failure; message preserved for diagnostics.
    Transport(String),
    /// Consumption cancelled (peer disconnect, drop, shutdown).
    Cancelled,
    /// Framing/protocol violation observed while streaming.
    Protocol(String),
}

impl std::fmt::Display for InboundBodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(msg) => write!(f, "inbound body transport error: {msg}"),
            Self::Cancelled => write!(f, "inbound body consumption cancelled"),
            Self::Protocol(msg) => write!(f, "inbound body protocol error: {msg}"),
        }
    }
}

impl std::error::Error for InboundBodyError {}

/// Neutral inbound request body: incremental DATA, body errors, terminal
/// trailers, drop/cancellation, unknown length. Size hints are hints only;
/// nothing here forces full buffering.
pub struct InboundBody {
    inner: BoxBody<Bytes, InboundBodyError>,
}

impl InboundBody {
    /// Empty body with an exact zero hint.
    pub fn empty() -> Self {
        use http_body_util::BodyExt as _;
        Self {
            inner: http_body_util::Empty::<Bytes>::new()
                .map_err(|e| match e {})
                .boxed(),
        }
    }

    /// Deterministic in-memory body (tests, internal endpoints).
    pub fn from_bytes(bytes: Bytes) -> Self {
        use http_body_util::BodyExt as _;
        Self {
            inner: http_body_util::Full::new(bytes)
                .map_err(|e| match e {})
                .boxed(),
        }
    }

    /// Adapt any streaming body. Errors map through `Debug` into
    /// [`InboundBodyError::Transport`], preserving today's behavior where
    /// downstream treats transport failures uniformly.
    pub fn from_body<B>(body: B) -> Self
    where
        B: http_body::Body<Data = Bytes> + Send + Sync + Unpin + 'static,
        B::Error: std::fmt::Debug + Send + Sync + 'static,
    {
        use http_body_util::BodyExt as _;
        Self {
            inner: body
                .map_err(|e| InboundBodyError::Transport(format!("{e:?}")))
                .boxed(),
        }
    }

    /// Deterministic frame stream (tests): DATA frames, errors, and a
    /// terminal trailers frame.
    pub fn from_frame_stream<S>(stream: S) -> Self
    where
        S: futures::Stream<Item = Result<http_body::Frame<Bytes>, InboundBodyError>>
            + Send
            + Sync
            + 'static,
    {
        Self {
            inner: http_body_util::combinators::BoxBody::new(http_body_util::StreamBody::new(
                stream,
            )),
        }
    }

    /// Unwrap for generic body consumers (`StreamingWafBody`, collectors,
    /// upstream dispatch). The error type stays neutral.
    pub fn into_boxed(self) -> BoxBody<Bytes, InboundBodyError> {
        self.inner
    }
}

impl http_body::Body for InboundBody {
    type Data = Bytes;
    type Error = InboundBodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, InboundBodyError>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// Validated upgrade/tunnel intent, without transport types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeRequest {
    /// Lowercase protocol token, e.g. `websocket`.
    pub protocol: String,
}

impl UpgradeRequest {
    /// The only upgrade intent SynVoid currently routes.
    pub fn websocket() -> Self {
        Self {
            protocol: "websocket".to_string(),
        }
    }
}

/// Neutral handshake description. Legal duplicate/opaque header values are
/// preserved (`http::HeaderMap`, never a lossy map).
#[derive(Debug, Clone)]
pub struct UpgradeHandshake {
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
}

/// Upgrade acceptance failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeError {
    /// Application handshake metadata tried to control transfer framing.
    ForbiddenHeader(String),
    /// The transport handoff is gone (peer disconnect, already committed).
    Gone(String),
}

impl std::fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForbiddenHeader(name) => {
                write!(f, "forbidden handshake header: {name}")
            }
            Self::Gone(msg) => write!(f, "upgrade handoff gone: {msg}"),
        }
    }
}

impl std::error::Error for UpgradeError {}

/// Opaque duplex stream handed to tunnel handlers: Tokio `AsyncRead` +
/// `AsyncWrite` + `Unpin` + `Send`. Read-ahead bytes and cancellation flow
/// through the transport's own bridging.
pub trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

impl<T> AsyncReadWrite for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// Boxed tunnel IO for object-safe handlers.
pub type BoxTunnelIo = Box<dyn AsyncReadWrite>;

/// Tunnel handler future.
pub type TunnelFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// One-shot tunnel handler: consumes the duplex stream.
pub type TunnelHandler = Box<dyn FnOnce(BoxTunnelIo) -> TunnelFuture + Send + 'static>;

/// One-shot neutral upgrade capability, sufficient for the current Hyper
/// handoff and the future direct-H1 tunnel capability.
///
/// Semantics: inspect validated intent via [`request`](Self::request);
/// accept at most once (consuming); the application supplies only allowed
/// handshake metadata plus a handler and never controls transfer framing;
/// decline/drop stays ordinary HTTP.
pub trait UpgradeCapability: Send {
    /// Validated upgrade intent.
    fn request(&self) -> &UpgradeRequest;

    /// Accept the upgrade: stage the transport handoff, run `handler` with
    /// the duplex stream, and return the handshake to send. Consuming:
    /// a second accept is a compile-time impossibility.
    fn accept(
        self: Box<Self>,
        headers: http::HeaderMap,
        handler: TunnelHandler,
    ) -> Result<UpgradeHandshake, UpgradeError>;
}

/// Neutral inbound request: standard parts, neutral body, optional neutral
/// upgrade capability. No transport-runtime types.
pub struct InboundRequest {
    /// Method/URI/version/headers as parsed by the transport.
    pub parts: http::request::Parts,
    /// Neutral body.
    pub body: InboundBody,
    /// Present only when the transport captured a validated upgrade handoff.
    pub upgrade: Option<Box<dyn UpgradeCapability>>,
}
