//! EggServe direct H1 adapter (Phase 75).
//!
//! Root composition/transport only: projects SynVoid configuration onto the
//! exact pinned EggServe runtime, adapts EggServe requests into the neutral
//! [`synvoid_http::inbound`] boundary served by the shared
//! [`super::service_core`] pipeline, and converts SynVoid responses back to
//! EggServe canonical responses. No listener/TLS path switches here.

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use eggserve_primitives::canonical::{
    Response as EggserveResponse, ResponseBody as EggserveResponseBody,
    ResponseStream as EggserveResponseStream, ResponseStreamError as EggserveResponseStreamError,
    StatusCode as EggserveStatusCode,
};
use eggserve_primitives::{
    HeaderBlock as EggserveHeaderBlock, HeaderName as EggserveHeaderName,
    HeaderValue as EggserveHeaderValue, Request as EggserveRequest,
    RequestBody as EggserveRequestBody, RequestBodyError as EggserveRequestBodyError,
    TrailerDeclaration as EggserveTrailerDeclaration, Trailers as EggserveTrailers,
};
use eggserve_server::{
    AdmissionOwner, AdmissionOwnership, ConnectionShutdown, H1ConnectionPolicy, H1PolicyOwnership,
    Http1RequestTargetMode, PolicyOwner, ResponseMetadataOwnership, RuntimeConfig, RuntimeState,
};
use http_body_util::combinators::BoxBody;
use synvoid_config::http::HttpConfig;
use synvoid_http::inbound::{
    BoxTunnelIo, InboundBodyError, InboundRequest, UpgradeError, UpgradeHandshake, UpgradeRequest,
};
use synvoid_proxy::ForwardedProtocol;

use super::service_core::NeutralServiceContext;

// ---------------------------------------------------------------------------
// Track B — one configuration projector
// ---------------------------------------------------------------------------

/// Projected EggServe H1 runtime: validated config, shared connection
/// policy, and one shared runtime state per owning server instance.
/// Construct once at server startup; never per request/connection.
pub struct ProjectedEggserveH1 {
    pub config: RuntimeConfig,
    pub policy: Arc<H1ConnectionPolicy>,
    pub state: Arc<RuntimeState>,
}

/// Ownership profile: every deadline/admission/ceiling authority stays
/// SynVoid-owned (`External`); the total connection lifetime is disabled.
/// Scalar placeholders that remain (timeouts, admission numerics, header
/// aggregate ceiling, body ceiling scalar) are valid but behaviorally dead.
pub fn external_ownership_profile() -> (H1PolicyOwnership, AdmissionOwnership) {
    (
        H1PolicyOwnership {
            handler_deadline: PolicyOwner::External,
            request_body_deadline: PolicyOwner::External,
            keep_alive_idle_deadline: PolicyOwner::External,
            response_write_progress_deadline: PolicyOwner::External,
            global_request_body_ceiling: PolicyOwner::External,
            request_target_ceiling: PolicyOwner::External,
        },
        AdmissionOwnership {
            service_calls: AdmissionOwner::External,
            tunnels: AdmissionOwner::External,
        },
    )
}

/// Project `HttpConfig` onto the exact pinned EggServe runtime.
/// Mandatory parser fields map exactly (Phase 73 range compatibility);
/// externally-owned policies keep valid inert placeholders.
pub fn project_eggserve_h1(
    http_config: &HttpConfig,
) -> Result<ProjectedEggserveH1, eggserve_server::errors::ServerError> {
    let (policy_ownership, admission_ownership) = external_ownership_profile();
    let config = RuntimeConfig::builder()
        .header_read_timeout(Duration::from_secs(http_config.header_read_timeout_secs))
        .max_buf_size(http_config.max_request_size)
        .max_headers(http_config.max_headers)
        // `max_header_bytes`: inert placeholder; `request_header_bytes_owner
        // = External` (below) deadens it and SynVoid's canonical
        // `max_header_size_ingress` remains the policy authority.
        // `max_request_body_bytes`: maximum valid scalar; the External
        // global ceiling deadens enforcement and SynVoid's
        // `max_streaming_body_size`/WAF ordering remains authoritative.
        .max_request_body_bytes(eggserve_server::runtime_limits::MAX_REQUEST_BODY_BYTES)
        .disable_connection_total_timeout()
        .http1_request_target_mode(Http1RequestTargetMode::OriginOnly)
        .policy_ownership(policy_ownership)
        .admission_ownership(admission_ownership)
        .runtime_rejection_presenter(Arc::new(SynVoidRejectionPresenter))
        .build()?;
    let policy = Arc::new(
        config
            .h1_connection_policy()?
            .with_request_header_bytes_owner(PolicyOwner::External)
            .with_response_metadata_ownership(ResponseMetadataOwnership {
                date: PolicyOwner::External,
                server: PolicyOwner::External,
            }),
    );
    let state = Arc::new(RuntimeState::try_new(&config)?);
    Ok(ProjectedEggserveH1 {
        config,
        policy,
        state,
    })
}

// ---------------------------------------------------------------------------
// Phase 79 Finding D — truthful local-endpoint provenance
// ---------------------------------------------------------------------------

/// Build a truthful H1 connection context from observed socket endpoints.
///
/// The local endpoint is recorded only when actually observed. A missing
/// local address is carried as `None`; it is NEVER replaced with the remote
/// peer address (that substitution would fabricate transport provenance).
/// Routing behavior is unchanged when a truthful local address is
/// available; when it is absent the request pipeline observes `None`
/// rather than an invented endpoint.
pub fn h1_connection_context(
    local_addr: Option<SocketAddr>,
    remote_addr: SocketAddr,
    tls: Option<eggserve_primitives::TlsInfo>,
) -> eggserve_server::ConnectionContext {
    let scheme = if tls.is_some() {
        eggserve_primitives::connection_info::Scheme::Https
    } else {
        eggserve_primitives::connection_info::Scheme::Http
    };
    eggserve_server::ConnectionContext::new(local_addr, Some(remote_addr), scheme, tls)
}

// ---------------------------------------------------------------------------
// Phase 79 Finding A — signal-then-drain connection driving
// ---------------------------------------------------------------------------

/// Drive a constructed EggServe H1 connection future to its normal bounded
/// completion.
///
/// Worker/server shutdown signals the per-connection [`ConnectionShutdown`]
/// token exactly once (idempotent, level-triggered) and the SAME connection
/// future keeps being polled to completion. Returning early from the
/// shutdown branch would drop the still-running driver future and truncate
/// an active response or tunnel instead of letting the driver execute its
/// shutdown/drain path.
///
/// There is no second idle/total/shutdown authority here and no new timeout
/// constant: completion is bounded by the driver's own graceful-close path
/// (the shared projector disables the total lifetime and keeps every
/// deadline/admission authority SynVoid-owned/External). WAF `Drop`
/// continues to signal the same connection token; it never creates a
/// competing close path.
pub async fn drive_h1_connection<F>(
    conn_future: F,
    conn_shutdown: &ConnectionShutdown,
    mut worker_shutdown: tokio::sync::broadcast::Receiver<()>,
) -> eggserve_server::ConnectionOutcome
where
    F: core::future::Future<Output = eggserve_server::ConnectionOutcome>,
{
    tokio::pin!(conn_future);
    tokio::select! {
        outcome = &mut conn_future => outcome,
        r = worker_shutdown.recv() => {
            // Signal-then-drain: the token is level-triggered, so a second
            // shutdown edge (or a concurrent WAF Drop on the same token)
            // needs no further action from this task.
            let _ = r;
            conn_shutdown.shutdown();
            conn_future.await
        }
    }
}

// ---------------------------------------------------------------------------
// Track J — runtime rejection presenter
// ---------------------------------------------------------------------------

/// Presents genuinely pre-service EggServe runtime rejections with fixed
/// SynVoid-styled bodies. No request data is reflected: status plus a fixed
/// reason phrase only.
#[derive(Debug, Default)]
pub struct SynVoidRejectionPresenter;

impl eggserve_server::rejection::RuntimeRejectionPresenter for SynVoidRejectionPresenter {
    fn present(
        &self,
        rejection: &eggserve_server::rejection::RuntimeRejection,
    ) -> Option<eggserve_server::rejection::RuntimeErrorPresentation> {
        let status = rejection.status().as_u16();
        let body = format!("{status} {}", reason_phrase(status));
        Some(eggserve_server::rejection::RuntimeErrorPresentation {
            headers: EggserveHeaderBlock::new(),
            body: body.into_bytes(),
        })
    }
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        404 => "Not Found",
        408 => "Request Timeout",
        413 => "Content Too Large",
        414 => "URI Too Long",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}

// ---------------------------------------------------------------------------
// Request conversion (Track E): EggServe request -> neutral InboundRequest
// ---------------------------------------------------------------------------

fn map_body_error(err: EggserveRequestBodyError) -> InboundBodyError {
    match err {
        EggserveRequestBodyError::Cancelled | EggserveRequestBodyError::Disconnected => {
            InboundBodyError::Cancelled
        }
        EggserveRequestBodyError::Transport(msg) => InboundBodyError::Transport(msg),
        other => InboundBodyError::Protocol(other.to_string()),
    }
}

fn header_block_to_map(block: &EggserveHeaderBlock) -> Result<http::HeaderMap, String> {
    let mut map = http::HeaderMap::new();
    for field in block.iter() {
        let name = http::HeaderName::from_bytes(field.name.as_str().as_bytes())
            .map_err(|e| format!("bad header name: {e:?}"))?;
        let value = http::HeaderValue::from_bytes(field.value.as_bytes())
            .map_err(|e| format!("bad header value: {e:?}"))?;
        map.append(name, value);
    }
    Ok(map)
}

fn header_map_to_block(map: &http::HeaderMap) -> Result<EggserveHeaderBlock, String> {
    let mut block = EggserveHeaderBlock::new();
    for (name, value) in map.iter() {
        let n = EggserveHeaderName::new(name.as_str()).map_err(|e| format!("bad name: {e:?}"))?;
        let v = EggserveHeaderValue::from_bytes(value.as_bytes())
            .map_err(|e| format!("bad value: {e:?}"))?;
        block.push(n, v);
    }
    Ok(block)
}

/// Streaming bridge: EggServe `RequestBody` (DATA + terminal trailers +
/// errors) polled as neutral frames without buffering.
///
/// The body sits behind a mutex to satisfy the shared-polling `Sync`
/// bound: it is only ever polled by the single connection task, so the
/// lock is uncontended and never held across an await.
struct EggserveInboundBody {
    body: std::sync::Mutex<EggserveRequestBody>,
    trailers_done: bool,
}

impl futures::Stream for EggserveInboundBody {
    type Item = Result<http_body::Frame<Bytes>, InboundBodyError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Ok(mut guard) = self.body.try_lock() else {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        };
        match Pin::new(&mut *guard).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Some(Ok(http_body::Frame::data(chunk)))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(map_body_error(e)))),
            Poll::Ready(None) => {
                // Release the body borrow before touching the flag.
                drop(guard);
                if self.trailers_done {
                    Poll::Ready(None)
                } else {
                    self.trailers_done = true;
                    let Ok(mut guard) = self.body.try_lock() else {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    };
                    match guard.take_completed_trailers() {
                        Some(trailers) => match header_block_to_map(trailers.as_block()) {
                            Ok(map) => Poll::Ready(Some(Ok(http_body::Frame::trailers(map)))),
                            Err(e) => Poll::Ready(Some(Err(InboundBodyError::Protocol(e)))),
                        },
                        None => Poll::Ready(None),
                    }
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Convert an EggServe request head/body into the neutral boundary,
/// preserving method, origin-form target, version, duplicate/opaque
/// headers, and body DATA/trailers/errors. Never enables absolute-form
/// targets: only origin-form is accepted here.
fn convert_request(
    request: EggserveRequest,
) -> Result<
    (
        http::request::Parts,
        synvoid_http::inbound::InboundBody,
        IpAddr,
        Option<SocketAddr>,
    ),
    eggserve_server::service::ServiceError,
> {
    use eggserve_server::service::ServiceError;
    let connection = request.connection().clone();
    let (head, body) = request.into_head_and_body();

    let method = http::Method::from_bytes(head.method().as_str().as_bytes())
        .map_err(|_| ServiceError::rejected(400, "bad method"))?;
    if head.version() != eggserve_primitives::version::HttpVersion::Http11 {
        return Err(ServiceError::rejected(505, "version not supported"));
    }
    // Origin-form only (Phase 75): absolute-form stays rejected even though
    // the upstream capability exists.
    let raw_target = head.target().raw();
    if raw_target.starts_with("http://") || raw_target.starts_with("https://") {
        return Err(ServiceError::rejected(400, "absolute-form target rejected"));
    }
    let uri: http::Uri = raw_target
        .parse()
        .map_err(|_| ServiceError::rejected(400, "bad request target"))?;
    let headers = header_block_to_map(head.headers()).map_err(ServiceError::internal)?;
    let mut builder = http::Request::builder()
        .method(method)
        .uri(uri)
        .version(http::Version::HTTP_11);
    for (name, value) in headers.iter() {
        builder = builder.header(name, value);
    }
    let parts = builder
        .body(())
        .map_err(|_| ServiceError::rejected(400, "bad request head"))?
        .into_parts()
        .0;

    // Phase 79 Finding D: the peer address is read directly from the
    // recorded remote endpoint. A missing local endpoint (truthful `None`
    // from `h1_connection_context`) must not fail peer resolution and must
    // never be back-filled with the peer address.
    let client_ip = connection
        .remote_addr
        .ok_or_else(|| ServiceError::internal("missing peer address"))?
        .ip();
    let local_addr = connection.local_addr;

    let inbound = synvoid_http::inbound::InboundBody::from_frame_stream(EggserveInboundBody {
        body: std::sync::Mutex::new(body),
        trailers_done: false,
    });
    Ok((parts, inbound, client_ip, local_addr))
}

// ---------------------------------------------------------------------------
// Tunnel conversion (Track G)
// ---------------------------------------------------------------------------

/// Neutral capability backed by the native EggServe `TunnelCapability`.
struct EggserveUpgradeCapability {
    request: UpgradeRequest,
    inner: Option<eggserve_server::tunnel::TunnelCapability>,
}

impl synvoid_http::inbound::UpgradeCapability for EggserveUpgradeCapability {
    fn request(&self) -> &UpgradeRequest {
        &self.request
    }

    fn accept(
        self: Box<Self>,
        headers: http::HeaderMap,
        handler: synvoid_http::inbound::TunnelHandler,
    ) -> Result<UpgradeHandshake, UpgradeError> {
        let this = *self;
        let capability = this
            .inner
            .ok_or_else(|| UpgradeError::Gone("eggserve tunnel capability missing".to_string()))?;
        let block = header_map_to_block(&headers).map_err(UpgradeError::ForbiddenHeader)?;
        let response = capability
            .accept(
                block,
                move |io: eggserve_server::tunnel::TunnelIo| async move {
                    handler(Box::new(io) as BoxTunnelIo).await;
                },
            )
            .map_err(|e| UpgradeError::Gone(e.to_string()))?;
        let status = http::StatusCode::from_u16(response.status().as_u16())
            .map_err(|e| UpgradeError::Gone(e.to_string()))?;
        let headers =
            header_block_to_map(response.headers()).map_err(UpgradeError::ForbiddenHeader)?;
        Ok(UpgradeHandshake { status, headers })
    }
}

// ---------------------------------------------------------------------------
// Response conversion (Track F)
// ---------------------------------------------------------------------------

/// Responses that must not carry a body or trailers on the wire.
fn is_body_forbidden_status(status: http::StatusCode) -> bool {
    status.is_informational()
        || status == http::StatusCode::NO_CONTENT
        || status == http::StatusCode::NOT_MODIFIED
}

/// Map an HTTP trailer section into the canonical EggServe trailer block.
///
/// Duplicate legal fields survive; undecodable names/values are skipped
/// (same policy as the streaming bridge); a block that fails canonical
/// validation (forbidden framing fields, over limits) yields `None` so the
/// caller keeps the trailer-free representation rather than emitting a
/// half-validated block.
fn eggserve_trailers_from_map(map: &http::HeaderMap) -> Option<EggserveTrailers> {
    let mut block = EggserveHeaderBlock::new();
    for (name, value) in map.iter() {
        let Ok(n) = EggserveHeaderName::new(name.as_str()) else {
            continue;
        };
        let Ok(v) = EggserveHeaderValue::from_bytes(value.as_bytes()) else {
            continue;
        };
        block.push(n, v);
    }
    if block.is_empty() {
        return None;
    }
    EggserveTrailers::new(block).ok()
}

/// Head-time trailer declaration built from an already-collected trailer
/// block (exact/buffered bodies).
///
/// EggServe only serializes an H1 terminal trailer block when the response
/// head declares the field names before commitment; a declaration that fails
/// canonical validation yields `None` so the caller keeps the undeclared
/// (H1-suppressed, H2/H3-emitted) representation instead of a half-declared
/// head.
fn trailer_declaration_from_map(map: &http::HeaderMap) -> Option<EggserveTrailerDeclaration> {
    let names = map
        .keys()
        .filter_map(|name| EggserveHeaderName::new(name.as_str()).ok())
        .collect::<Vec<_>>();
    EggserveTrailerDeclaration::new(names).ok()
}

/// Head-time trailer declaration taken from the application's own `Trailer`
/// response header (streaming bodies, whose trailer fields are unknown until
/// the producer finishes). Invalid tokens are skipped; an empty or wholly
/// invalid declaration yields `None`.
fn trailer_declaration_from_headers(
    headers: &http::HeaderMap,
) -> Option<EggserveTrailerDeclaration> {
    let mut names = Vec::new();
    for value in headers.get_all(http::header::TRAILER) {
        let Ok(text) = value.to_str() else {
            continue;
        };
        for token in text.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if let Ok(name) = EggserveHeaderName::new(token) {
                names.push(name);
            }
        }
    }
    EggserveTrailerDeclaration::new(names).ok()
}

/// Bodies at or below this exact size convert buffered; larger or
/// unknown-length bodies stream without buffering.
const BUFFERED_RESPONSE_THRESHOLD: u64 = 8 * 1024 * 1024;

/// Convert a SynVoid response to the EggServe canonical response without
/// full buffering. Status, ordered duplicates, DATA frames, trailers, and
/// unknown-length streaming are preserved; framing stays EggServe-owned
/// downstream (normalization is idempotent).
async fn convert_response(
    resp: http::Response<BoxBody<Bytes, std::convert::Infallible>>,
    is_head: bool,
) -> Result<EggserveResponse, eggserve_server::service::ServiceError> {
    use eggserve_server::service::ServiceError;
    let (parts, body) = resp.into_parts();
    let status = EggserveStatusCode::new(parts.status.as_u16())
        .map_err(|_| ServiceError::internal("bad response status"))?;
    // Equivalent-GET length for HEAD: the pipeline renders HEAD with an
    // empty body but an explicit Content-Length; carry it as
    // `EmptyWithLength` so EggServe framing matches Hyper's wire bytes.
    let head_length_hint = if is_head {
        parts
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
    } else {
        None
    };
    let mut builder = EggserveResponse::builder().status(status);
    for (name, value) in parts.headers.iter() {
        let n = EggserveHeaderName::new(name.as_str())
            .map_err(|e| ServiceError::internal(format!("bad header name: {e:?}")))?;
        let v = EggserveHeaderValue::from_bytes(value.as_bytes())
            .map_err(|e| ServiceError::internal(format!("bad header value: {e:?}")))?;
        builder = builder.push_header(n, v);
    }
    let exact = {
        use http_body::Body as _;
        body.size_hint().exact()
    };
    // Phase 79 Finding B: HEAD and body-forbidden responses never carry a
    // body or trailers. Suppress WITHOUT polling the application body:
    // EggServe drops such streams unpolled, so dropping here is equivalent
    // and discovers no impossible/irrelevant trailers.
    if is_head || is_body_forbidden_status(parts.status) {
        if let Some(equivalent) = head_length_hint {
            return builder
                .body(EggserveResponseBody::EmptyWithLength(equivalent))
                .map_err(|e| ServiceError::internal(e.to_string()));
        }
        return builder
            .body(EggserveResponseBody::Empty)
            .map_err(|e| ServiceError::internal(e.to_string()));
    }
    // Buffered fast path: exact small bodies only. Empty stays Empty (no
    // invented framing). Terminal trailers retained by the collection are
    // preserved: `size_hint().exact()` never proves trailer absence, so
    // the collected trailer map is inspected before consuming DATA bytes.
    if let Some(len) = exact {
        if len <= BUFFERED_RESPONSE_THRESHOLD {
            use http_body_util::BodyExt as _;
            let collected = match body.collect().await {
                Ok(c) => c,
                Err(never) => match never {},
            };
            let declared_trailers = collected
                .trailers()
                .filter(|map| !map.is_empty())
                .and_then(trailer_declaration_from_map);
            let trailers = collected
                .trailers()
                .filter(|map| !map.is_empty())
                .and_then(eggserve_trailers_from_map);
            let data = collected.to_bytes();
            match trailers {
                Some(trailers) => {
                    // Known DATA length plus trailers: a one-shot
                    // known-length canonical stream plus trailer future
                    // rather than degrading to `ResponseBody::Bytes`
                    // (which cannot carry trailers). Duplicate legal
                    // trailer fields survive via the canonical block; the
                    // head-time declaration is what lets EggServe render
                    // the terminal block on H1.
                    let data_stream = futures::stream::once(async move {
                        Ok::<Bytes, EggserveResponseStreamError>(data)
                    });
                    let trailer_future = Box::pin(async move {
                        Ok::<Option<EggserveTrailers>, EggserveResponseStreamError>(Some(trailers))
                    }) as EggserveTrailersFuture;
                    let stream = match declared_trailers {
                        Some(declaration) => {
                            EggserveResponseStream::with_known_length_and_declared_trailers(
                                data_stream,
                                len,
                                declaration,
                                trailer_future,
                            )
                        }
                        None => EggserveResponseStream::with_known_length_and_trailers(
                            data_stream,
                            len,
                            trailer_future,
                        ),
                    };
                    return builder
                        .body(EggserveResponseBody::Stream(stream))
                        .map_err(|e| ServiceError::internal(e.to_string()));
                }
                None => {
                    if len == 0 {
                        return builder
                            .body(EggserveResponseBody::Empty)
                            .map_err(|e| ServiceError::internal(e.to_string()));
                    }
                    return builder
                        .body(EggserveResponseBody::Bytes(data.to_vec()))
                        .map_err(|e| ServiceError::internal(e.to_string()));
                }
            }
        }
    }
    // Streaming path: lazy bridge for DATA; terminal trailers captured
    // into the canonical trailer slot and attached via the trailer future
    // (known and unknown lengths both have trailer-capable constructors).
    // The producer's trailer fields are unknown here, so the only head-time
    // declaration available is the application's `Trailer` header.
    let declared_trailers = trailer_declaration_from_headers(&parts.headers);
    let bridge = ResponseBridge::wrap(body);
    let slot = bridge.trailers();
    let trailer_future =
        Box::pin(async move { Ok(slot.lock().unwrap().take()) }) as EggserveTrailersFuture;
    let stream = match (exact, declared_trailers) {
        (Some(len), Some(declaration)) => {
            EggserveResponseStream::with_known_length_and_declared_trailers(
                bridge,
                len,
                declaration,
                trailer_future,
            )
        }
        (Some(len), None) => {
            EggserveResponseStream::with_known_length_and_trailers(bridge, len, trailer_future)
        }
        (None, Some(declaration)) => {
            EggserveResponseStream::with_declared_trailers(bridge, declaration, trailer_future)
        }
        (None, None) => EggserveResponseStream::with_trailers(bridge, trailer_future),
    };
    builder
        .body(EggserveResponseBody::Stream(stream))
        .map_err(|e| ServiceError::internal(e.to_string()))
}

/// Lazy DATA bridge with terminal-trailer capture.
struct ResponseBridge {
    inner: Option<BoxBody<Bytes, std::convert::Infallible>>,
    trailers: std::sync::Arc<std::sync::Mutex<Option<EggserveTrailers>>>,
}

type EggserveTrailersFuture = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<Option<EggserveTrailers>, EggserveResponseStreamError>,
            > + Send,
    >,
>;

impl ResponseBridge {
    fn wrap(body: BoxBody<Bytes, std::convert::Infallible>) -> Self {
        Self {
            inner: Some(body),
            trailers: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    fn trailers(&self) -> std::sync::Arc<std::sync::Mutex<Option<EggserveTrailers>>> {
        self.trailers.clone()
    }
}

impl futures::Stream for ResponseBridge {
    type Item = Result<Bytes, EggserveResponseStreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        use http_body::Body as _;
        let this = self.get_mut();
        loop {
            let body = this.inner.as_mut().expect("polled after end");
            match Pin::new(body).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => return Poll::Ready(Some(Ok(data))),
                    Err(frame) => {
                        if let Some(tr) = frame.trailers_ref() {
                            let mut block = EggserveHeaderBlock::new();
                            for (name, value) in tr.iter() {
                                let Ok(n) = EggserveHeaderName::new(name.as_str()) else {
                                    continue;
                                };
                                let Ok(v) = EggserveHeaderValue::from_bytes(value.as_bytes())
                                else {
                                    continue;
                                };
                                block.push(n, v);
                            }
                            if let Ok(trailers) = EggserveTrailers::new(block) {
                                *this.trailers.lock().unwrap() = Some(trailers);
                            }
                        }
                        continue;
                    }
                },
                Poll::Ready(Some(Err(never))) => match never {},
                Poll::Ready(None) => {
                    this.inner = None;
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tracks D, H, I — EggServe Service adapter around the shared pipeline
// ---------------------------------------------------------------------------

/// EggServe direct-H1 service driving the shared neutral pipeline.
///
/// Construction is per connection (cheap clones of server-owned Arcs plus
/// the connection's shutdown token, JA4, and scheme); the single shared
/// `H1ConnectionPolicy`/`RuntimeState` from [`project_eggserve_h1`] stay
/// with the driver, never here.
#[derive(Clone)]
pub struct EggserveH1Service<W, D> {
    ctx: NeutralServiceContext<W, D>,
    conn_shutdown: ConnectionShutdown,
    ja4_hash: Option<String>,
    forwarded_protocol: ForwardedProtocol,
    local_addr_fallback: Option<SocketAddr>,
    drain_guard_state: Option<Arc<crate::worker::drain_state::WorkerDrainState>>,
}

impl<W, D> EggserveH1Service<W, D> {
    pub fn new(
        ctx: NeutralServiceContext<W, D>,
        conn_shutdown: ConnectionShutdown,
        ja4_hash: Option<String>,
        forwarded_protocol: ForwardedProtocol,
        local_addr_fallback: Option<SocketAddr>,
        drain_guard_state: Option<Arc<crate::worker::drain_state::WorkerDrainState>>,
    ) -> Self {
        Self {
            ctx,
            conn_shutdown,
            ja4_hash,
            forwarded_protocol,
            local_addr_fallback,
            drain_guard_state,
        }
    }
}

impl<W, D> EggserveH1Service<W, D>
where
    W: synvoid_http::BufferedRequestWaf
        + synvoid_http::RequestBodyWaf
        + synvoid_proxy::protocol::trait_def::WafCoreBackend
        + synvoid_http::UploadValidationWaf
        + synvoid_http::WafErrorPageRenderer
        + Send
        + Sync
        + 'static,
    D: synvoid_http::internal_handlers::HttpDrainControl + Send + Sync + 'static,
{
    fn call_shared(
        &self,
        request: EggserveRequest,
        tunnel: Option<eggserve_server::tunnel::TunnelCapability>,
    ) -> eggserve_server::ServiceFuture<'_> {
        Box::pin(async move {
            let cancellation = request.lifecycle_clone();
            tokio::select! {
                out = self.serve_inner(request, tunnel) => out,
                _ = cancellation.cancelled() => {
                    Err(eggserve_server::service::ServiceError::internal(
                        "client disconnected",
                    ))
                }
            }
        })
    }

    async fn serve_inner(
        &self,
        request: EggserveRequest,
        tunnel: Option<eggserve_server::tunnel::TunnelCapability>,
    ) -> Result<EggserveResponse, eggserve_server::service::ServiceError> {
        use eggserve_server::service::ServiceError;
        let (parts, inbound_body, client_ip, local_addr) = convert_request(request)?;
        let local_addr = local_addr.or(self.local_addr_fallback);
        let is_head = parts.method == http::Method::HEAD;

        let upgrade: Option<Box<dyn synvoid_http::inbound::UpgradeCapability>> =
            tunnel.map(|capability| {
                let boxed: Box<dyn synvoid_http::inbound::UpgradeCapability> =
                    Box::new(EggserveUpgradeCapability {
                        request: UpgradeRequest {
                            protocol: capability
                                .request()
                                .protocol()
                                .map(|p| p.as_str().to_lowercase())
                                .unwrap_or_else(|| "unknown".to_string()),
                        },
                        inner: Some(capability),
                    });
                boxed
            });
        let inbound = InboundRequest {
            parts,
            body: inbound_body,
            upgrade,
        };

        // Track I: the lane's drop callback signals this connection's
        // EggServe shutdown token (worker/server drain bridges to the same
        // token at the driver).
        let shutdown = self.conn_shutdown.clone();
        let request_drop: Arc<dyn Fn() + Send + Sync> = Arc::new(move || shutdown.shutdown());

        let response = super::service_core::handle_neutral_request(
            &self.ctx,
            inbound,
            client_ip,
            local_addr,
            request_drop,
            self.ja4_hash.clone(),
            self.forwarded_protocol,
            self.drain_guard_state.clone(),
        )
        .await
        .map_err(|e| ServiceError::internal(format!("pipeline error: {e}")))?;
        convert_response(response, is_head).await
    }
}

impl<W, D> eggserve_server::Service for EggserveH1Service<W, D>
where
    W: synvoid_http::BufferedRequestWaf
        + synvoid_http::RequestBodyWaf
        + synvoid_proxy::protocol::trait_def::WafCoreBackend
        + synvoid_http::UploadValidationWaf
        + synvoid_http::WafErrorPageRenderer
        + Send
        + Sync
        + 'static,
    D: synvoid_http::internal_handlers::HttpDrainControl + Send + Sync + 'static,
{
    fn request_body_policy(
        &self,
        _head: &eggserve_primitives::request_head::RequestHead,
    ) -> eggserve_server::RequestBodyPolicy {
        // Non-preempting stream limit: SynVoid's `max_streaming_body_size`
        // and WAF ordering remain authoritative (runtime ceiling is External
        // and the scalar is maximally non-interfering).
        eggserve_server::RequestBodyPolicy::Stream {
            max_bytes: u64::MAX,
        }
    }

    fn call(&self, request: EggserveRequest) -> eggserve_server::ServiceFuture<'_> {
        self.call_shared(request, None)
    }

    fn call_with_tunnel(
        &self,
        request: EggserveRequest,
        tunnel: Option<eggserve_server::tunnel::TunnelCapability>,
    ) -> eggserve_server::ServiceFuture<'_> {
        self.call_shared(request, tunnel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http_config_for_projection() -> HttpConfig {
        HttpConfig {
            header_read_timeout_secs: 7,
            // Above the legacy 0.3.0 guidance maxima on purpose: the 0.3.1
            // contract must accept the full valid SynVoid range.
            max_request_size: 5 * 1024 * 1024,
            max_headers: 20_000,
            ..Default::default()
        }
    }

    #[test]
    fn projector_maps_mandatory_fields_exactly() {
        let projected = project_eggserve_h1(&http_config_for_projection()).unwrap();
        assert_eq!(projected.config.header_read_timeout, Duration::from_secs(7));
        assert_eq!(projected.config.max_buf_size, 5 * 1024 * 1024);
        assert_eq!(projected.config.max_headers, 20_000);
        // Total lifetime disabled: current SynVoid has no total lifetime.
        assert!(projected.config.connection_total_timeout.is_zero());
        // Origin-form only: never absolute-form.
        assert!(matches!(
            projected.config.http1_request_target_mode,
            Http1RequestTargetMode::OriginOnly
        ));
    }

    #[test]
    fn projector_keeps_all_authority_external() {
        let projected = project_eggserve_h1(&HttpConfig::default()).unwrap();
        let ownership = projected.config.policy_ownership;
        assert_eq!(ownership.handler_deadline, PolicyOwner::External);
        assert_eq!(ownership.request_body_deadline, PolicyOwner::External);
        assert_eq!(ownership.keep_alive_idle_deadline, PolicyOwner::External);
        assert_eq!(
            ownership.response_write_progress_deadline,
            PolicyOwner::External
        );
        assert_eq!(ownership.global_request_body_ceiling, PolicyOwner::External);
        assert_eq!(ownership.request_target_ceiling, PolicyOwner::External);
        let admission = projected.config.admission_ownership;
        assert_eq!(admission.service_calls, AdmissionOwner::External);
        assert_eq!(admission.tunnels, AdmissionOwner::External);
    }

    #[test]
    fn inert_placeholders_validate_and_differ_only_inertly() {
        // Two projections differing only in inert placeholder scalars must
        // both validate; wire invariance is proven differentially.
        let base = project_eggserve_h1(&HttpConfig::default()).unwrap();
        let tweaked = RuntimeConfig::builder()
            .max_header_bytes(1024 * 1024)
            .max_request_body_bytes(1024)
            .max_in_flight_requests(1024)
            .max_active_tunnels(1024)
            .build()
            .unwrap();
        tweaked.validate().unwrap();
        base.config.validate().unwrap();
        assert_ne!(base.config.max_header_bytes, tweaked.max_header_bytes);
    }

    #[test]
    fn rejection_presenter_renders_fixed_bodies() {
        use eggserve_server::rejection::{
            RuntimeErrorPresentation, RuntimeRejection, RuntimeRejectionKind,
            RuntimeRejectionPresenter,
        };
        let presenter = SynVoidRejectionPresenter;
        let rejection = RuntimeRejection::new(
            RuntimeRejectionKind::RequestHeadersTooLarge,
            EggserveStatusCode::new(431).unwrap(),
        );
        let presented: RuntimeErrorPresentation = presenter.present(&rejection).expect("presented");
        assert_eq!(presented.body, b"431 Request Header Fields Too Large");
        assert_eq!(presented.headers.len(), 0);
    }

    fn eggserve_test_request(target: &str, body: Vec<u8>) -> EggserveRequest {
        use eggserve_primitives::connection_info::{ConnectionInfo, Scheme};
        let mut headers = EggserveHeaderBlock::new();
        headers.push_str("host", "localhost").unwrap();
        headers.push_str("x-dup", "one").unwrap();
        headers.push_str("x-dup", "two").unwrap();
        let head = eggserve_primitives::request_head::RequestHead::new(
            eggserve_primitives::method::Method::new("POST").unwrap(),
            eggserve_primitives::request_target::RequestTarget::parse(target).unwrap(),
            eggserve_primitives::version::HttpVersion::Http11,
            headers,
        );
        EggserveRequest::new(
            head,
            EggserveRequestBody::from_bytes(body, u64::MAX),
            ConnectionInfo::with_socket_addrs(
                "127.0.0.1:80".parse().unwrap(),
                "127.0.0.1:12345".parse().unwrap(),
                Scheme::Http,
                None,
            ),
        )
    }

    #[tokio::test]
    async fn request_conversion_preserves_shape_and_body() {
        let request = eggserve_test_request("/x?q=1", b"payload".to_vec());
        let (parts, inbound, client_ip, local_addr) = convert_request(request).unwrap();
        assert_eq!(parts.method, http::Method::POST);
        assert_eq!(parts.uri.path(), "/x");
        assert_eq!(parts.uri.query(), Some("q=1"));
        assert_eq!(parts.version, http::Version::HTTP_11);
        let dups: Vec<_> = parts
            .headers
            .get_all("x-dup")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(dups, vec!["one".to_string(), "two".to_string()]);
        assert_eq!(client_ip, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(
            local_addr,
            Some("127.0.0.1:80".parse::<SocketAddr>().unwrap())
        );
        use http_body_util::BodyExt as _;
        let bytes = inbound.into_boxed().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"payload");
    }

    #[test]
    fn request_conversion_rejects_absolute_form() {
        // Upstream `parse` already refuses absolute-form (OriginOnly
        // runtime); build one via components to pin the adapter's own
        // defense-in-depth rejection.
        let absolute =
            eggserve_primitives::request_target::RequestTarget::from_absolute_components(
                "http",
                eggserve_primitives::authority::Authority::parse("evil.example").unwrap(),
                "/",
            )
            .unwrap();
        assert!(absolute.raw().starts_with("http://"));
        let mut headers = EggserveHeaderBlock::new();
        headers.push_str("host", "localhost").unwrap();
        let head = eggserve_primitives::request_head::RequestHead::new(
            eggserve_primitives::method::Method::new("POST").unwrap(),
            absolute,
            eggserve_primitives::version::HttpVersion::Http11,
            headers,
        );
        use eggserve_primitives::connection_info::{ConnectionInfo, Scheme};
        let request = EggserveRequest::new(
            head,
            EggserveRequestBody::from_bytes(Vec::new(), u64::MAX),
            ConnectionInfo::with_socket_addrs(
                "127.0.0.1:80".parse().unwrap(),
                "127.0.0.1:12345".parse().unwrap(),
                Scheme::Http,
                None,
            ),
        );
        match convert_request(request) {
            Err(err) => assert_eq!(err.status_code().as_u16(), 400),
            Ok(_) => panic!("absolute-form target must be rejected"),
        }
    }

    #[tokio::test]
    async fn response_conversion_preserves_shape() {
        use http_body_util::BodyExt as _;
        // Empty stays empty.
        let resp = http::Response::builder()
            .status(204)
            .body(http_body_util::Empty::<Bytes>::new().boxed())
            .unwrap();
        let converted = convert_response(resp, false).await.unwrap();
        assert_eq!(converted.status(), EggserveStatusCode::NO_CONTENT);
        assert!(matches!(
            converted.body(),
            Some(EggserveResponseBody::Empty)
        ));

        // Fixed bytes with duplicates and cookies.
        let mut resp = http::Response::builder()
            .status(200)
            .header("set-cookie", "a=1")
            .body(http_body_util::Full::new(Bytes::from_static(b"hi")).boxed())
            .unwrap();
        resp.headers_mut()
            .append("set-cookie", "b=2".parse().unwrap());
        let converted = convert_response(resp, false).await.unwrap();
        assert!(matches!(
            converted.body(),
            Some(EggserveResponseBody::Bytes(_))
        ));
        let cookies: Vec<_> = converted
            .headers()
            .iter()
            .filter(|f| f.name.as_str() == "set-cookie")
            .collect();
        assert_eq!(cookies.len(), 2);
    }

    #[tokio::test]
    async fn head_empty_body_keeps_equivalent_get_length() {
        use http_body_util::BodyExt as _;
        // Pipeline HEAD shape: empty body with explicit Content-Length.
        let resp = http::Response::builder()
            .status(200)
            .header("content-length", "14")
            .body(http_body_util::Empty::<Bytes>::new().boxed())
            .unwrap();
        let converted = convert_response(resp, true).await.unwrap();
        assert!(matches!(
            converted.body(),
            Some(EggserveResponseBody::EmptyWithLength(14))
        ));
    }

    // --- Phase 79 Finding A: signal-then-drain ---

    use std::sync::atomic::{AtomicBool, Ordering};

    struct CancelProbe {
        completed: Arc<AtomicBool>,
        dropped_before_complete: Arc<AtomicBool>,
    }

    impl Drop for CancelProbe {
        fn drop(&mut self) {
            if !self.completed.load(Ordering::SeqCst) {
                self.dropped_before_complete.store(true, Ordering::SeqCst);
            }
        }
    }

    fn cancellable_driver(
        shutdown: &eggserve_server::ConnectionShutdown,
    ) -> (
        impl core::future::Future<Output = eggserve_server::ConnectionOutcome> + '_,
        Arc<AtomicBool>,
        Arc<AtomicBool>,
    ) {
        let completed = Arc::new(AtomicBool::new(false));
        let dropped_before_complete = Arc::new(AtomicBool::new(false));
        let probe = CancelProbe {
            completed: completed.clone(),
            dropped_before_complete: dropped_before_complete.clone(),
        };
        let completed_inner = completed.clone();
        let fut = async move {
            let _probe = probe;
            shutdown.cancelled().await;
            completed_inner.store(true, Ordering::SeqCst);
            eggserve_server::ConnectionOutcome::Shutdown
        };
        (fut, completed, dropped_before_complete)
    }

    #[tokio::test]
    async fn drive_helper_completes_same_future_after_shutdown() {
        let shutdown = eggserve_server::ConnectionShutdown::new();
        let (tx, rx) = tokio::sync::broadcast::channel(1);
        let (fut, completed, dropped_before_complete) = cancellable_driver(&shutdown);
        tx.send(()).unwrap();
        let outcome = drive_h1_connection(fut, &shutdown, rx).await;
        assert!(matches!(
            outcome,
            eggserve_server::ConnectionOutcome::Shutdown
        ));
        assert!(
            completed.load(Ordering::SeqCst),
            "driver future must run to completion after shutdown"
        );
        assert!(
            !dropped_before_complete.load(Ordering::SeqCst),
            "driver future must not be cancelled by the shutdown branch"
        );
        assert!(shutdown.is_shutdown());
    }

    #[tokio::test]
    async fn drive_helper_repeated_shutdown_is_idempotent() {
        let shutdown = eggserve_server::ConnectionShutdown::new();
        let (tx, rx) = tokio::sync::broadcast::channel(2);
        let (fut, completed, _) = cancellable_driver(&shutdown);
        tx.send(()).unwrap();
        tx.send(()).unwrap();
        let outcome = drive_h1_connection(fut, &shutdown, rx).await;
        assert!(matches!(
            outcome,
            eggserve_server::ConnectionOutcome::Shutdown
        ));
        assert!(completed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn old_select_drop_pattern_cancels_driver_on_shutdown() {
        // Negative control pinning the `2242e191` defect shape: racing the
        // driver against shutdown and exiting the `select!` on the shutdown
        // branch drops the still-running driver future.
        let shutdown = eggserve_server::ConnectionShutdown::new();
        let (tx, mut rx) = tokio::sync::broadcast::channel(1);
        let (fut, completed, dropped_before_complete) = cancellable_driver(&shutdown);
        // Box the driver so `drop` below destroys the future itself (a
        // `tokio::pin!` shadow would only drop the pin wrapper, not the
        // future, hiding the cancellation being pinned here).
        let mut fut = Box::pin(fut);
        tx.send(()).unwrap();
        tokio::select! {
            _ = &mut fut => {}
            _ = rx.recv() => {
                shutdown.shutdown();
            }
        }
        drop(fut);
        assert!(
            !completed.load(Ordering::SeqCst),
            "old pattern must not complete the driver after shutdown wins"
        );
        assert!(
            dropped_before_complete.load(Ordering::SeqCst),
            "old pattern must cancel the driver future on shutdown"
        );
    }

    // --- Phase 79 Finding B: exact-body trailer preservation ---

    struct TrailerBody {
        data: Option<Bytes>,
        trailers: Option<http::HeaderMap>,
        exact: Option<u64>,
    }

    impl http_body::Body for TrailerBody {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
            let _ = cx;
            let this = self.get_mut();
            if let Some(data) = this.data.take() {
                return Poll::Ready(Some(Ok(http_body::Frame::data(data))));
            }
            if let Some(trailers) = this.trailers.take() {
                return Poll::Ready(Some(Ok(http_body::Frame::trailers(trailers))));
            }
            Poll::Ready(None)
        }

        fn size_hint(&self) -> http_body::SizeHint {
            match self.exact {
                Some(len) => http_body::SizeHint::with_exact(len),
                None => http_body::SizeHint::new(),
            }
        }
    }

    fn trailer_map_with_dups() -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        map.insert("x-checksum", "a1".parse().unwrap());
        map.append("x-checksum", "a2".parse().unwrap());
        map.insert("x-final", "yes".parse().unwrap());
        map
    }

    #[tokio::test]
    async fn exact_small_body_with_trailers_keeps_length_and_trailers() {
        use futures::StreamExt as _;
        let body = TrailerBody {
            data: Some(Bytes::from_static(b"hello")),
            trailers: Some(trailer_map_with_dups()),
            exact: Some(5),
        };
        let resp = http::Response::builder()
            .status(200)
            .body(http_body_util::BodyExt::boxed(body))
            .unwrap();
        let mut converted = convert_response(resp, false).await.unwrap();
        let Some(EggserveResponseBody::Stream(stream)) = converted.take_body() else {
            panic!("exact body with trailers must use the trailer-capable stream");
        };
        assert_eq!(stream.known_length(), Some(5));
        assert!(stream.has_trailers());
        let (mut bytes, trailer_future) = stream.into_parts();
        let mut collected = Vec::new();
        while let Some(chunk) = bytes.next().await {
            collected.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(collected, b"hello");
        let trailers = trailer_future
            .unwrap()
            .await
            .unwrap()
            .expect("trailer block must survive");
        let dups: Vec<_> = trailers
            .as_block()
            .iter()
            .filter(|f| f.name.as_str() == "x-checksum")
            .collect();
        assert_eq!(dups.len(), 2, "duplicate legal trailer fields survive");
    }

    #[tokio::test]
    async fn exact_zero_data_with_trailers_uses_known_zero_stream() {
        let body = TrailerBody {
            data: None,
            trailers: Some(trailer_map_with_dups()),
            exact: Some(0),
        };
        let resp = http::Response::builder()
            .status(200)
            .body(http_body_util::BodyExt::boxed(body))
            .unwrap();
        let mut converted = convert_response(resp, false).await.unwrap();
        let Some(EggserveResponseBody::Stream(stream)) = converted.take_body() else {
            panic!("zero-DATA body with trailers must not degrade to Empty");
        };
        assert_eq!(stream.known_length(), Some(0));
        assert!(stream.has_trailers());
    }

    #[tokio::test]
    async fn exact_body_without_trailers_keeps_bytes_fast_path() {
        let body = TrailerBody {
            data: Some(Bytes::from_static(b"plain")),
            trailers: None,
            exact: Some(5),
        };
        let resp = http::Response::builder()
            .status(200)
            .body(http_body_util::BodyExt::boxed(body))
            .unwrap();
        let converted = convert_response(resp, false).await.unwrap();
        assert!(
            matches!(converted.body(), Some(EggserveResponseBody::Bytes(_))),
            "trailer-free exact bodies retain the buffered fast path"
        );
    }

    #[tokio::test]
    async fn exact_empty_without_trailers_stays_empty() {
        let body = TrailerBody {
            data: None,
            trailers: None,
            exact: Some(0),
        };
        let resp = http::Response::builder()
            .status(200)
            .body(http_body_util::BodyExt::boxed(body))
            .unwrap();
        let converted = convert_response(resp, false).await.unwrap();
        assert!(matches!(
            converted.body(),
            Some(EggserveResponseBody::Empty)
        ));
    }

    #[tokio::test]
    async fn unknown_length_trailers_stay_on_streaming_path() {
        let body = TrailerBody {
            data: Some(Bytes::from_static(b"chunk")),
            trailers: Some(trailer_map_with_dups()),
            exact: None,
        };
        let resp = http::Response::builder()
            .status(200)
            .body(http_body_util::BodyExt::boxed(body))
            .unwrap();
        let mut converted = convert_response(resp, false).await.unwrap();
        let Some(EggserveResponseBody::Stream(stream)) = converted.take_body() else {
            panic!("unknown-length bodies must stream");
        };
        assert_eq!(stream.known_length(), None);
        assert!(stream.has_trailers());
    }

    struct PollCountingBody {
        polls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl http_body::Body for PollCountingBody {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
            self.polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn head_never_polls_application_body() {
        let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let resp = http::Response::builder()
            .status(200)
            .header("content-length", "9")
            .body(http_body_util::BodyExt::boxed(PollCountingBody {
                polls: polls.clone(),
            }))
            .unwrap();
        let converted = convert_response(resp, true).await.unwrap();
        assert!(matches!(
            converted.body(),
            Some(EggserveResponseBody::EmptyWithLength(9))
        ));
        assert_eq!(
            polls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "HEAD must not poll the application body to discover trailers"
        );
    }

    #[tokio::test]
    async fn body_forbidden_status_never_polls_or_emits() {
        for status in [204u16, 304] {
            let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let resp = http::Response::builder()
                .status(status)
                .body(http_body_util::BodyExt::boxed(PollCountingBody {
                    polls: polls.clone(),
                }))
                .unwrap();
            let converted = convert_response(resp, false).await.unwrap();
            assert!(
                matches!(converted.body(), Some(EggserveResponseBody::Empty)),
                "status {status} must not emit a body"
            );
            assert_eq!(
                polls.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "status {status} must not poll the application body"
            );
        }
    }

    // --- Phase 79 Finding D: provenance ---

    #[test]
    fn connection_context_never_substitutes_peer_for_local() {
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let ctx = h1_connection_context(None, peer, None);
        assert_eq!(ctx.local_addr, None);
        assert_eq!(ctx.remote_addr, Some(peer));
    }

    #[test]
    fn connection_context_preserves_truthful_local() {
        let local: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let ctx = h1_connection_context(Some(local), peer, None);
        assert_eq!(ctx.local_addr, Some(local));
        assert_eq!(ctx.remote_addr, Some(peer));
    }

    #[test]
    fn connection_context_tls_selects_https_scheme() {
        use eggserve_primitives::connection_info::Scheme;
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let plain = h1_connection_context(Some(peer), peer, None);
        assert_eq!(plain.scheme, Scheme::Http);
        let tls = h1_connection_context(
            None,
            peer,
            Some(eggserve_primitives::TlsInfo {
                protocol_version: None,
                server_name: None,
                alpn: Some("http/1.1".to_string()),
                client_authenticated: false,
                peer_certificates_present: false,
                peer_certificate_chain: None,
            }),
        );
        assert_eq!(tls.scheme, Scheme::Https);
        assert_eq!(tls.local_addr, None);
        assert_eq!(tls.remote_addr, Some(peer));
    }

    #[test]
    fn request_conversion_resolves_peer_without_local() {
        use eggserve_primitives::connection_info::{ConnectionInfo, Scheme};
        let mut headers = EggserveHeaderBlock::new();
        headers.push_str("host", "localhost").unwrap();
        let head = eggserve_primitives::request_head::RequestHead::new(
            eggserve_primitives::method::Method::new("GET").unwrap(),
            eggserve_primitives::request_target::RequestTarget::parse("/").unwrap(),
            eggserve_primitives::version::HttpVersion::Http11,
            headers,
        );
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let request = EggserveRequest::new(
            head,
            EggserveRequestBody::from_bytes(Vec::new(), u64::MAX),
            ConnectionInfo::new(None, Some(peer), Scheme::Http, None),
        );
        let (_parts, _inbound, client_ip, local_addr) = convert_request(request).unwrap();
        assert_eq!(client_ip, peer.ip());
        assert_eq!(local_addr, None);
    }
}
