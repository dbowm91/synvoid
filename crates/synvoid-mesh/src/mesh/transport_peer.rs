#![allow(dead_code, clippy::redundant_locals)] // Reserved for future peer communication handling

use std::sync::atomic::Ordering;

use crate::raft::state_machine::{
    ClientProposalPayload, CommandKind, GlobalRegistryConfig, RaftCommand,
};
use crate::transport::{
    MeshTransport, MeshTransportError, MAX_BATCH_KEYS, MAX_BLOCK_DURATION_SECS, MAX_MESSAGE_SIZE,
};
use hex;
use openraft::raft::SnapshotResponse;
use openraft::type_config::alias::{SnapshotMetaOf, VoteOf};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use quinn::{Connection, RecvStream, SendStream};
use tokio::sync::broadcast;

use crate::protocol::{ArcStr, HealthStatus, MeshMessage, RaftSnapshotFrame};

use crate::topology::{MeshTopology, PeerStatus};

/// Parsed result of reading an HTTP request head (headers + body prefix).
///
/// The `body_prefix` contains any bytes coalesced with the final header
/// read that belong to the request body. The complete request is
/// `header_bytes` ++ `body_prefix` ++ remaining body reads.
#[derive(Debug)]
pub struct FramedHttpRequestHead {
    /// Raw header bytes including the terminating \r\n\r\n.
    pub header_bytes: Vec<u8>,
    /// Body bytes that arrived in the same read as the header terminator.
    pub body_prefix: Vec<u8>,
    /// Parsed Content-Length value, if present and valid.
    pub content_length: Option<usize>,
    /// Whether chunked Transfer-Encoding was detected.
    pub chunked: bool,
}

/// Classification of the HTTP request body framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpBodyKind {
    /// No body (GET, HEAD, DELETE, etc. or no Content-Length/Transfer-Encoding).
    None,
    /// Fixed-length body with the given byte count.
    ContentLength(usize),
    /// Chunked Transfer-Encoding.
    Chunked,
}

/// Errors specific to HTTP-over-mesh framing.
#[derive(Debug)]
pub enum HttpFramingError {
    /// Headers exceeded the configured byte limit.
    HeaderTooLarge,
    /// Total header framing deadline expired.
    HeaderFramingTimeout,
    /// Invalid or conflicting Content-Length header.
    InvalidContentLength(String),
    /// Unsupported Transfer-Encoding (e.g., chunked not implemented).
    UnsupportedTransferEncoding(String),
    /// Request body exceeds the configured byte limit.
    BodyTooLarge { limit: usize, declared: usize },
    /// Premature EOF before the declared body was fully received.
    PrematureEof { expected: usize, received: usize },
    /// CONNECT or upgrade request not supported.
    UnsupportedMethod(String),
    /// Malformed HTTP header syntax.
    MalformedHeaders(String),
    /// I/O error during framing.
    Io(String),
    /// No-body request has trailing bytes after header terminator.
    AmbiguousTrailingBytes { count: usize },
}

impl std::fmt::Display for HttpFramingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeaderTooLarge => write!(f, "HTTP headers exceeded maximum size"),
            Self::HeaderFramingTimeout => write!(f, "HTTP header framing deadline expired"),
            Self::InvalidContentLength(msg) => write!(f, "Invalid Content-Length: {msg}"),
            Self::UnsupportedTransferEncoding(msg) => {
                write!(f, "Unsupported Transfer-Encoding: {msg}")
            }
            Self::BodyTooLarge { limit, declared } => {
                write!(
                    f,
                    "Body too large: declared {declared} bytes, limit {limit}"
                )
            }
            Self::PrematureEof { expected, received } => {
                write!(
                    f,
                    "Premature EOF: expected {expected} bytes, received {received}"
                )
            }
            Self::UnsupportedMethod(method) => {
                write!(f, "Unsupported HTTP method for mesh proxy: {method}")
            }
            Self::MalformedHeaders(msg) => write!(f, "Malformed HTTP headers: {msg}"),
            Self::Io(msg) => write!(f, "I/O error during HTTP framing: {msg}"),
            Self::AmbiguousTrailingBytes { count } => {
                write!(
                    f,
                    "No-body request has {count} trailing bytes after header terminator"
                )
            }
        }
    }
}

impl std::error::Error for HttpFramingError {}

impl From<HttpFramingError> for MeshTransportError {
    fn from(e: HttpFramingError) -> Self {
        MeshTransportError::ReceiveFailed(e.to_string())
    }
}

/// HTTP response version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http10,
    Http11,
}

/// Encoding of the response body as received on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpResponseBodyEncoding {
    None,
    FixedLength,
    Chunked,
    CloseDelimited,
}

/// Parsed result of reading an HTTP response head from a backend.
#[derive(Debug)]
pub struct FramedHttpResponseHead {
    pub header_bytes: Vec<u8>,
    pub body_prefix: Vec<u8>,
    pub status_code: u16,
    pub content_length: Option<usize>,
    pub chunked: bool,
    pub connection_close: bool,
    pub http_version: HttpVersion,
    pub body_encoding: HttpResponseBodyEncoding,
}

/// Errors specific to HTTP response framing.
#[derive(Debug)]
pub enum HttpResponseFramingError {
    MalformedStatusLine(String),
    InvalidStatusCode(String),
    HeaderTooLarge,
    HeaderFramingTimeout,
    InvalidContentLength(String),
    UnsupportedTransferEncoding(String),
    BodyTooLarge { limit: usize, declared: usize },
    TrailerTooLarge { limit: usize, observed: usize },
    PrematureEof { expected: usize, received: usize },
    MalformedChunkedBody(String),
    BackendClosedBeforeCompleteResponse,
    ResponseBodyPrefixExceedsContentLength { prefix: usize, declared: usize },
    MalformedHeaderLine(String),
    UnexpectedBodyBytesForNoBodyResponse { status: u16, observed: usize },
    Io(String),
}

impl std::fmt::Display for HttpResponseFramingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedStatusLine(msg) => write!(f, "Malformed status line: {msg}"),
            Self::InvalidStatusCode(msg) => write!(f, "Invalid status code: {msg}"),
            Self::HeaderTooLarge => write!(f, "Response headers exceeded maximum size"),
            Self::HeaderFramingTimeout => write!(f, "Response header framing deadline expired"),
            Self::InvalidContentLength(msg) => write!(f, "Invalid Content-Length: {msg}"),
            Self::UnsupportedTransferEncoding(msg) => {
                write!(f, "Unsupported Transfer-Encoding: {msg}")
            }
            Self::BodyTooLarge { limit, declared } => {
                write!(
                    f,
                    "Response body too large: declared {declared} bytes, limit {limit}"
                )
            }
            Self::TrailerTooLarge { limit, observed } => {
                write!(
                    f,
                    "Response trailer too large: {observed} bytes exceeds limit {limit}"
                )
            }
            Self::PrematureEof { expected, received } => {
                write!(
                    f,
                    "Premature EOF: expected {expected} bytes, received {received}"
                )
            }
            Self::MalformedChunkedBody(msg) => write!(f, "Malformed chunked body: {msg}"),
            Self::BackendClosedBeforeCompleteResponse => {
                write!(f, "Backend closed before complete response")
            }
            Self::ResponseBodyPrefixExceedsContentLength { prefix, declared } => {
                write!(
                    f,
                    "Response body prefix ({prefix} bytes) exceeds declared Content-Length ({declared})"
                )
            }
            Self::MalformedHeaderLine(line) => {
                write!(f, "malformed response header line: {line}")
            }
            Self::UnexpectedBodyBytesForNoBodyResponse { status, observed } => {
                write!(
                    f,
                    "unexpected {observed} bytes after {status} response with no body"
                )
            }
            Self::Io(msg) => write!(f, "I/O error during response framing: {msg}"),
        }
    }
}

impl std::error::Error for HttpResponseFramingError {}

impl From<HttpResponseFramingError> for MeshTransportError {
    fn from(e: HttpResponseFramingError) -> Self {
        MeshTransportError::ReceiveFailed(e.to_string())
    }
}

/// Internal adapter that consumes prefix bytes before reading from the inner reader.
/// Used by chunked framing to treat body_prefix as unread input.
struct PrefixReader<R> {
    prefix: std::io::Cursor<Vec<u8>>,
    prefix_exhausted: bool,
    inner: R,
}

impl<R: tokio::io::AsyncRead + Unpin> PrefixReader<R> {
    fn new(prefix: Vec<u8>, inner: R) -> Self {
        Self {
            prefix: std::io::Cursor::new(prefix),
            prefix_exhausted: false,
            inner,
        }
    }

    async fn read_byte_with_timeout(
        &mut self,
        deadline: tokio::time::Instant,
        idle_timeout: Duration,
    ) -> Result<u8, HttpResponseFramingError> {
        let mut buf = [0u8; 1];
        // Try prefix first (synchronous read from Cursor), but only if not exhausted.
        if !self.prefix_exhausted {
            let n = std::io::Read::read(&mut self.prefix, &mut buf)
                .map_err(|e| HttpResponseFramingError::Io(e.to_string()))?;
            if n == 1 {
                return Ok(buf[0]);
            }
            // n == 0 means prefix is exhausted (EOF on Cursor).
            self.prefix_exhausted = true;
        }
        // Read from inner (async)
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(HttpResponseFramingError::Io("read timeout".to_string()));
        }
        let remaining = deadline.duration_since(now);
        let effective = idle_timeout.min(remaining);
        use tokio::io::AsyncReadExt;
        let n = tokio::time::timeout(effective, self.inner.read(&mut buf))
            .await
            .map_err(|_| HttpResponseFramingError::Io("read timeout".to_string()))?
            .map_err(|e| HttpResponseFramingError::Io(e.to_string()))?;
        if n == 0 {
            return Err(HttpResponseFramingError::BackendClosedBeforeCompleteResponse);
        }
        Ok(buf[0])
    }

    async fn read_exact_with_timeout(
        &mut self,
        buf: &mut [u8],
        deadline: tokio::time::Instant,
        idle_timeout: Duration,
    ) -> Result<(), HttpResponseFramingError> {
        let mut filled = 0;
        while filled < buf.len() {
            // Try prefix first (synchronous read from Cursor), but only if not exhausted.
            if !self.prefix_exhausted {
                use std::io::Read;
                let n = std::io::Read::read(&mut self.prefix, &mut buf[filled..])
                    .map_err(|e| HttpResponseFramingError::Io(e.to_string()))?;
                filled += n;
                if filled == buf.len() {
                    return Ok(());
                }
                if n == 0 {
                    self.prefix_exhausted = true;
                }
            }
            // Read from inner (async)
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(HttpResponseFramingError::Io("read timeout".to_string()));
            }
            let remaining = deadline.duration_since(now);
            let effective = idle_timeout.min(remaining);
            use tokio::io::AsyncReadExt;
            let n = tokio::time::timeout(effective, self.inner.read(&mut buf[filled..]))
                .await
                .map_err(|_| HttpResponseFramingError::Io("read timeout".to_string()))?
                .map_err(|e| HttpResponseFramingError::Io(e.to_string()))?;
            if n == 0 {
                return Err(HttpResponseFramingError::PrematureEof {
                    expected: buf.len(),
                    received: filled,
                });
            }
            filled += n;
        }
        Ok(())
    }
}

/// Case-insensitive check for a token within a comma-separated header value.
fn header_contains_token(value: &str, token: &str) -> bool {
    for part in value.split(',') {
        if part.trim().eq_ignore_ascii_case(token) {
            return true;
        }
    }
    false
}

/// Strictly parse an HTTP response status line.
///
/// Validates:
/// - Version token is exactly `HTTP/1.0` or `HTTP/1.1`
/// - Status token is exactly 3 ASCII digits in `100..=599`
/// - Malformed control characters are rejected
fn parse_http_response_status_line(
    line: &str,
) -> Result<(HttpVersion, u16), HttpResponseFramingError> {
    let mut parts = line.splitn(3, ' ');
    let version_str = parts
        .next()
        .ok_or_else(|| {
            HttpResponseFramingError::MalformedStatusLine("missing version token".to_string())
        })?
        .trim_end();

    let http_version = match version_str {
        "HTTP/1.0" => HttpVersion::Http10,
        "HTTP/1.1" => HttpVersion::Http11,
        other => {
            return Err(HttpResponseFramingError::MalformedStatusLine(format!(
                "unsupported HTTP version: {other}"
            )));
        }
    };

    let status_str = parts
        .next()
        .ok_or_else(|| {
            HttpResponseFramingError::MalformedStatusLine("missing status code".to_string())
        })?
        .trim();

    // Status must be exactly 3 ASCII digits
    if status_str.len() != 3 {
        return Err(HttpResponseFramingError::InvalidStatusCode(format!(
            "status code must be 3 digits, got {} chars: {status_str}",
            status_str.len()
        )));
    }
    for byte in status_str.bytes() {
        if !byte.is_ascii_digit() {
            return Err(HttpResponseFramingError::InvalidStatusCode(format!(
                "non-digit in status code: {status_str}"
            )));
        }
    }
    let status_code: u16 = status_str.parse().map_err(|_| {
        HttpResponseFramingError::InvalidStatusCode(format!("out of range: {status_str}"))
    })?;
    if !(100..=599).contains(&status_code) {
        return Err(HttpResponseFramingError::InvalidStatusCode(format!(
            "status code {status_code} out of range 100..=599"
        )));
    }

    Ok((http_version, status_code))
}

/// Try to parse a complete HTTP response head from a byte buffer.
///
/// Returns:
/// - `Ok(None)` when `\r\n\r\n` is not yet present in the buffer
/// - `Ok(Some((head, consumed)))` when a complete head is available;
///   `consumed` is the byte index immediately after the header terminator
/// - `Err(...)` on malformed input
///
/// The caller retains bytes after `consumed` for subsequent reads.
fn try_parse_http_response_head(
    buffer: &[u8],
    max_header_bytes: usize,
) -> Result<Option<(FramedHttpResponseHead, usize)>, HttpResponseFramingError> {
    let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Ok(None);
    };

    let header_end = pos + 4;
    if header_end > max_header_bytes {
        return Err(HttpResponseFramingError::HeaderTooLarge);
    }
    let header_bytes = buffer[..header_end].to_vec();
    let body_prefix = buffer[header_end..].to_vec();

    let header_str = String::from_utf8_lossy(&header_bytes);
    let status_line = header_str.lines().next().unwrap_or("");

    let (http_version, status_code) = parse_http_response_status_line(status_line)?;

    let (content_length, chunked, connection_close) = parse_http_response_framing(&header_str)?;

    let body_encoding = if chunked {
        HttpResponseBodyEncoding::Chunked
    } else if content_length.is_some() {
        HttpResponseBodyEncoding::FixedLength
    } else if connection_close || matches!(http_version, HttpVersion::Http10) {
        HttpResponseBodyEncoding::CloseDelimited
    } else {
        HttpResponseBodyEncoding::None
    };

    // For informational responses, the body prefix is NOT returned to the
    // caller — it becomes part of the sequence buffer for the next response.
    // For final responses, body_prefix is returned for body framing.
    let is_informational = status_code < 200;
    let returned_prefix = if is_informational {
        Vec::new()
    } else {
        body_prefix
    };

    Ok(Some((
        FramedHttpResponseHead {
            header_bytes,
            body_prefix: returned_prefix,
            status_code,
            content_length,
            chunked,
            connection_close,
            http_version,
            body_encoding,
        },
        header_end,
    )))
}

/// Parse Content-Length, Transfer-Encoding, and Connection from response header bytes.
///
/// Uses exact header-name splitting (`split_once(':')`) rather than prefix
/// matching to prevent accidental matches against malformed names such as
/// `Content-Length-Extra:`. Duplicate equal Content-Length values are accepted;
/// conflicting duplicates are rejected. Only a single `chunked` Transfer-Encoding
/// token is accepted; lists containing other codings are rejected.
fn parse_http_response_framing(
    header_str: &str,
) -> Result<(Option<usize>, bool, bool), HttpResponseFramingError> {
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut connection_close = false;

    for (i, line) in header_str.lines().enumerate() {
        // Skip the status line (first line) and empty lines.
        if i == 0 {
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Exact header-name splitting: require a colon separator.
        let (name, value) = match trimmed.split_once(':') {
            Some(pair) => pair,
            None => {
                return Err(HttpResponseFramingError::MalformedHeaderLine(
                    line.to_string(),
                ));
            }
        };

        let name = name.trim();
        let value = value.trim();

        if name.eq_ignore_ascii_case("content-length") {
            let v: usize = value.parse().map_err(|_| {
                HttpResponseFramingError::InvalidContentLength(format!(
                    "non-numeric value: {value}"
                ))
            })?;
            if let Some(existing) = content_length {
                if existing != v {
                    return Err(HttpResponseFramingError::InvalidContentLength(format!(
                        "conflicting values: {existing} and {v}"
                    )));
                }
            }
            content_length = Some(v);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            let te_lower = value.to_lowercase();
            if te_lower == "chunked" {
                chunked = true;
            } else {
                return Err(HttpResponseFramingError::UnsupportedTransferEncoding(
                    te_lower,
                ));
            }
        } else if name.eq_ignore_ascii_case("connection") {
            if header_contains_token(value, "close") {
                connection_close = true;
            }
        }
    }

    if chunked && content_length.is_some() {
        return Err(HttpResponseFramingError::InvalidContentLength(
            "both Content-Length and Transfer-Encoding: chunked present".to_string(),
        ));
    }

    Ok((content_length, chunked, connection_close))
}

/// Read an HTTP/1.x response head from an async reader.
///
/// Maintains a local buffer and calls `try_parse_http_response_head()` after
/// every read. Enforces per-read idle timeout, total header framing deadline,
/// and maximum header byte cap.
pub async fn read_http_response_head<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    idle_timeout: Duration,
    total_timeout: Duration,
    max_header_bytes: usize,
) -> Result<FramedHttpResponseHead, HttpResponseFramingError> {
    if max_header_bytes < 4 {
        return Err(HttpResponseFramingError::HeaderTooLarge);
    }

    let deadline = tokio::time::Instant::now() + total_timeout;
    let mut buffer = Vec::with_capacity(4096);
    let mut read_buf = [0u8; 4096];

    loop {
        // Try to parse from what we have so far.
        if let Some((head, _consumed)) = try_parse_http_response_head(&buffer, max_header_bytes)? {
            return Ok(head);
        }

        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(HttpResponseFramingError::HeaderFramingTimeout);
        }
        let remaining_total = deadline.duration_since(now);
        let effective_timeout = idle_timeout.min(remaining_total);

        let remaining_capacity = max_header_bytes
            .checked_sub(buffer.len())
            .ok_or(HttpResponseFramingError::HeaderTooLarge)?;
        if remaining_capacity == 0 {
            return Err(HttpResponseFramingError::HeaderTooLarge);
        }
        let read_size = remaining_capacity.min(read_buf.len());

        use tokio::io::AsyncReadExt;
        let n = tokio::time::timeout(effective_timeout, reader.read(&mut read_buf[..read_size]))
            .await
            .map_err(|_| HttpResponseFramingError::HeaderFramingTimeout)?
            .map_err(|e| HttpResponseFramingError::Io(e.to_string()))?;

        match n {
            0 => {
                return Err(HttpResponseFramingError::BackendClosedBeforeCompleteResponse);
            }
            n => {
                buffer.extend_from_slice(&read_buf[..n]);
            }
        }
    }
}

/// Read an HTTP/1.x response sequence, consuming informational responses (1xx)
/// until a final response (>= 200) is obtained.
///
/// Uses a single persistent buffer across all responses so that partial final
/// heads left over after an informational response are preserved until more
/// bytes arrive. Every response is parsed by the same `try_parse_http_response_head`
/// parser — no duplicated status/version/header logic.
///
/// Informational responses (100 Continue, 103 Early Hints, etc.) are consumed
/// and discarded. `101 Switching Protocols` is rejected because upgrades are
/// unsupported. If the backend closes before a final response, an error is returned.
pub async fn read_http_response_sequence<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    idle_timeout: Duration,
    total_timeout: Duration,
    max_header_bytes: usize,
) -> Result<FramedHttpResponseHead, HttpResponseFramingError> {
    let deadline = tokio::time::Instant::now() + total_timeout;
    let mut buffer: Vec<u8> = Vec::new();

    loop {
        // Try to parse from what we have so far.
        if let Some((head, consumed)) = try_parse_http_response_head(&buffer, max_header_bytes)? {
            if head.status_code == 101 {
                return Err(HttpResponseFramingError::MalformedStatusLine(
                    "101 Switching Protocols not supported".to_string(),
                ));
            }

            // Split off bytes after the header terminator.
            let remainder = buffer.split_off(consumed);

            if head.status_code >= 200 {
                // Final response — return with body prefix.
                let mut final_head = head;
                final_head.body_prefix = remainder;

                // For HEAD requests (checking the request method), 204, and 304 responses,
                // reject non-empty body_prefix bytes.
                // Note: We don't have access to request method in this function,
                // so we only check 204 and 304 here. HEAD response handling
                // requires request-method context from the caller.
                if (final_head.status_code == 204 || final_head.status_code == 304)
                    && !final_head.body_prefix.is_empty()
                {
                    return Err(
                        HttpResponseFramingError::UnexpectedBodyBytesForNoBodyResponse {
                            status: final_head.status_code,
                            observed: final_head.body_prefix.len(),
                        },
                    );
                }

                return Ok(final_head);
            }

            // Informational — carry forward remaining bytes, loop for next response.
            buffer = remainder;
            continue;
        }

        // Need more bytes — read from the socket.
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(HttpResponseFramingError::HeaderFramingTimeout);
        }
        let remaining = deadline.saturating_duration_since(now);
        let effective_timeout = idle_timeout.min(remaining);

        let remaining_capacity = max_header_bytes
            .checked_sub(buffer.len())
            .ok_or(HttpResponseFramingError::HeaderTooLarge)?;
        if remaining_capacity == 0 {
            return Err(HttpResponseFramingError::HeaderTooLarge);
        }

        let mut read_buf = [0u8; 4096];
        let read_size = remaining_capacity.min(read_buf.len());

        use tokio::io::AsyncReadExt;
        let n = tokio::time::timeout(effective_timeout, reader.read(&mut read_buf[..read_size]))
            .await
            .map_err(|_| HttpResponseFramingError::HeaderFramingTimeout)?
            .map_err(|e| HttpResponseFramingError::Io(e.to_string()))?;

        match n {
            0 => {
                // Backend EOF — if buffer has partial data, that's an error.
                if !buffer.is_empty() {
                    return Err(HttpResponseFramingError::BackendClosedBeforeCompleteResponse);
                }
                return Err(HttpResponseFramingError::BackendClosedBeforeCompleteResponse);
            }
            n => {
                buffer.extend_from_slice(&read_buf[..n]);
            }
        }
    }
}

/// Read a fixed-length HTTP response body from an async reader.
pub async fn read_fixed_http_response_body<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    prefix: Vec<u8>,
    content_length: usize,
    idle_timeout: Duration,
    total_timeout: Duration,
    max_body_bytes: usize,
) -> Result<Vec<u8>, HttpResponseFramingError> {
    if prefix.len() > content_length {
        return Err(
            HttpResponseFramingError::ResponseBodyPrefixExceedsContentLength {
                prefix: prefix.len(),
                declared: content_length,
            },
        );
    }

    if content_length > max_body_bytes {
        return Err(HttpResponseFramingError::BodyTooLarge {
            limit: max_body_bytes,
            declared: content_length,
        });
    }

    let remaining = content_length - prefix.len();
    if remaining == 0 {
        return Ok(prefix);
    }

    let deadline = tokio::time::Instant::now() + total_timeout;
    let mut body = prefix;
    body.reserve(remaining);
    let mut read_buf = [0u8; 8192];
    let mut total_read = 0usize;

    loop {
        if total_read >= remaining {
            break;
        }

        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(HttpResponseFramingError::Io(
                "body framing deadline expired".to_string(),
            ));
        }
        let remaining_total = deadline.duration_since(now);
        let effective_timeout = idle_timeout.min(remaining_total);

        let to_read = (remaining - total_read).min(read_buf.len());

        use tokio::io::AsyncReadExt;
        let n = tokio::time::timeout(effective_timeout, reader.read(&mut read_buf[..to_read]))
            .await
            .map_err(|_| HttpResponseFramingError::Io("body read timeout".to_string()))?
            .map_err(|e| HttpResponseFramingError::Io(e.to_string()))?;

        match n {
            0 => {
                return Err(HttpResponseFramingError::PrematureEof {
                    expected: remaining,
                    received: total_read,
                });
            }
            n => {
                body.extend_from_slice(&read_buf[..n]);
                total_read += n;
            }
        }
    }

    Ok(body)
}

/// Read a chunked HTTP response body from an async reader.
///
/// Preserves the raw wire chunked framing in the returned bytes.
/// Trailer bytes are independently capped by `max_trailer_bytes` after the
/// zero-size chunk, separate from the broader `max_body_bytes` limit.
pub async fn read_chunked_http_response_body<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
    prefix: Vec<u8>,
    idle_timeout: Duration,
    total_timeout: Duration,
    max_body_bytes: usize,
    max_trailer_bytes: usize,
) -> Result<Vec<u8>, HttpResponseFramingError> {
    let deadline = tokio::time::Instant::now() + total_timeout;
    let mut total_wire_bytes = 0usize;
    let mut output = Vec::new();
    let mut line_buf: Vec<u8> = Vec::with_capacity(64);
    let mut reader = PrefixReader::new(prefix, reader);

    loop {
        line_buf.clear();
        loop {
            if line_buf.len() >= 2 && line_buf[line_buf.len() - 2..] == *b"\r\n" {
                break;
            }
            if line_buf.len() >= max_trailer_bytes {
                return Err(HttpResponseFramingError::TrailerTooLarge {
                    limit: max_trailer_bytes,
                    observed: line_buf.len(),
                });
            }
            let byte = reader
                .read_byte_with_timeout(deadline, idle_timeout)
                .await?;
            line_buf.push(byte);
        }

        total_wire_bytes += line_buf.len();
        if total_wire_bytes > max_body_bytes {
            return Err(HttpResponseFramingError::BodyTooLarge {
                limit: max_body_bytes,
                declared: total_wire_bytes,
            });
        }
        output.extend_from_slice(&line_buf);

        let line_str = String::from_utf8_lossy(&line_buf);
        let size_str = line_str.trim_end_matches("\r\n");
        let size_str = size_str.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(size_str, 16).map_err(|_| {
            HttpResponseFramingError::MalformedChunkedBody(format!(
                "invalid chunk size: {size_str}"
            ))
        })?;

        if chunk_size == 0 {
            // Trailer section: independently bounded by max_trailer_bytes.
            let mut trailer_bytes = 0usize;
            loop {
                let byte = reader
                    .read_byte_with_timeout(deadline, idle_timeout)
                    .await?;
                trailer_bytes += 1;
                if trailer_bytes > max_trailer_bytes {
                    return Err(HttpResponseFramingError::TrailerTooLarge {
                        limit: max_trailer_bytes,
                        observed: trailer_bytes,
                    });
                }
                total_wire_bytes += 1;
                if total_wire_bytes > max_body_bytes {
                    return Err(HttpResponseFramingError::BodyTooLarge {
                        limit: max_body_bytes,
                        declared: total_wire_bytes,
                    });
                }
                output.push(byte);
                if output.len() >= 4 && output[output.len() - 4..] == *b"\r\n\r\n" {
                    return Ok(output);
                }
            }
        }

        let payload_and_crlf = chunk_size + 2;
        let mut chunk_buf = vec![0u8; payload_and_crlf];
        reader
            .read_exact_with_timeout(&mut chunk_buf, deadline, idle_timeout)
            .await?;

        total_wire_bytes += chunk_buf.len();
        if total_wire_bytes > max_body_bytes {
            return Err(HttpResponseFramingError::BodyTooLarge {
                limit: max_body_bytes,
                declared: total_wire_bytes,
            });
        }
        output.extend_from_slice(&chunk_buf);
    }
}

/// Read a close-delimited HTTP response body from an async reader.
///
/// Enforces both per-read idle timeout and total body deadline. The prefix
/// bytes (already coalesced with the header read) are included in size
/// accounting. EOF terminates successfully. Returns an error on body-limit
/// overflow or timeout — never truncated output.
pub async fn read_close_delimited_http_response_body<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    prefix: Vec<u8>,
    idle_timeout: Duration,
    total_timeout: Duration,
    max_body_bytes: usize,
) -> Result<Vec<u8>, HttpResponseFramingError> {
    if prefix.len() > max_body_bytes {
        return Err(HttpResponseFramingError::BodyTooLarge {
            limit: max_body_bytes,
            declared: prefix.len(),
        });
    }

    let deadline = tokio::time::Instant::now() + total_timeout;
    let mut body = prefix;
    let mut read_buf = [0u8; 8192];

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(HttpResponseFramingError::Io(
                "close-delimited body total deadline expired".to_string(),
            ));
        }
        let remaining_total = deadline.duration_since(now);
        let effective_timeout = idle_timeout.min(remaining_total);

        use tokio::io::AsyncReadExt;
        let n = tokio::time::timeout(effective_timeout, reader.read(&mut read_buf))
            .await
            .map_err(|_| {
                HttpResponseFramingError::Io("close-delimited body read timeout".to_string())
            })?
            .map_err(|e| HttpResponseFramingError::Io(e.to_string()))?;

        if n == 0 {
            // EOF — successful close-delimited termination.
            return Ok(body);
        }

        body.extend_from_slice(&read_buf[..n]);
        if body.len() > max_body_bytes {
            return Err(HttpResponseFramingError::BodyTooLarge {
                limit: max_body_bytes,
                declared: body.len(),
            });
        }
    }
}

/// Strictly parsed HTTP request metadata extracted from header bytes only.
///
/// Avoids decoding body bytes as UTF-8 and prevents body content from
/// corrupting host/path/method extraction.
#[derive(Debug, Clone)]
pub struct ParsedHttpRequestMeta {
    pub method: String,
    pub target: String,
    pub version: String,
    pub host: String,
    pub upgrade_requested: bool,
    pub connection_upgrade: bool,
}

/// Parse an HTTP request head from header bytes (NOT the full body).
///
/// Extracts method, target, version, Host, and upgrade semantics.
/// Rejects malformed request lines, missing Host for HTTP/1.1,
/// conflicting duplicate Host values, and empty/missing headers.
pub fn parse_http_request_meta(
    header_bytes: &[u8],
) -> Result<ParsedHttpRequestMeta, HttpFramingError> {
    let header_str = String::from_utf8_lossy(header_bytes);

    let mut lines = header_str.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| HttpFramingError::MalformedHeaders("empty request".to_string()))?;
    let request_line = request_line.trim();
    if request_line.is_empty() {
        return Err(HttpFramingError::MalformedHeaders(
            "empty request line".to_string(),
        ));
    }

    let tokens: Vec<&str> = request_line.split(' ').filter(|s| !s.is_empty()).collect();
    if tokens.len() != 3 {
        return Err(HttpFramingError::MalformedHeaders(format!(
            "expected 3 tokens in request line, got {}",
            tokens.len()
        )));
    }

    let method = tokens[0].to_string();
    let target = tokens[1].to_string();
    let version = tokens[2].to_string();

    let mut host_found: Option<String> = None;
    let mut upgrade_header = false;
    let mut connection_upgrade = false;

    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            break;
        }

        if let Some(colon_pos) = line.find(':') {
            let name = line[..colon_pos].trim();
            let value = line[colon_pos + 1..].trim();

            if name.eq_ignore_ascii_case("Host") {
                let host_val = value.to_string();
                if let Some(existing) = &host_found {
                    if existing != &host_val {
                        return Err(HttpFramingError::MalformedHeaders(
                            "conflicting Host header values".to_string(),
                        ));
                    }
                } else {
                    host_found = Some(host_val);
                }
            } else if name.eq_ignore_ascii_case("Upgrade") {
                upgrade_header = true;
            } else if name.eq_ignore_ascii_case("Connection") {
                for token in value.split(',') {
                    if token.trim().eq_ignore_ascii_case("upgrade") {
                        connection_upgrade = true;
                    }
                }
            }
        }
    }

    if version.eq_ignore_ascii_case("HTTP/1.1") && host_found.is_none() {
        return Err(HttpFramingError::MalformedHeaders(
            "HTTP/1.1 requires Host header".to_string(),
        ));
    }

    let host = host_found.unwrap_or_default();

    Ok(ParsedHttpRequestMeta {
        method,
        target,
        version,
        host,
        upgrade_requested: upgrade_header,
        connection_upgrade,
    })
}

/// Read an HTTP/1.x request head from an async reader.
///
/// Reads until `\r\n\r\n` is found, enforcing:
/// - per-read idle timeout
/// - total header framing deadline
/// - maximum header byte cap
///
/// Returns the parsed header head including any body bytes coalesced
/// with the final header read.
pub async fn read_http_request_head<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    first_byte: u8,
    idle_timeout: Duration,
    total_timeout: Duration,
    max_header_bytes: usize,
) -> Result<FramedHttpRequestHead, HttpFramingError> {
    if max_header_bytes < 4 {
        return Err(HttpFramingError::HeaderTooLarge);
    }

    let deadline = tokio::time::Instant::now() + total_timeout;
    let mut buffer = vec![first_byte];
    let mut read_buf = [0u8; 4096];

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(HttpFramingError::HeaderFramingTimeout);
        }
        let remaining_total = deadline.duration_since(now);
        let effective_timeout = idle_timeout.min(remaining_total);

        let remaining_capacity = max_header_bytes
            .checked_sub(buffer.len())
            .ok_or(HttpFramingError::HeaderTooLarge)?;
        if remaining_capacity == 0 {
            return Err(HttpFramingError::HeaderTooLarge);
        }
        let read_size = remaining_capacity.min(read_buf.len());

        use tokio::io::AsyncReadExt;
        let n = tokio::time::timeout(effective_timeout, reader.read(&mut read_buf[..read_size]))
            .await
            .map_err(|_| HttpFramingError::HeaderFramingTimeout)?
            .map_err(|e| HttpFramingError::Io(e.to_string()))?;

        match n {
            0 => {
                return Err(HttpFramingError::MalformedHeaders(
                    "Connection closed before header terminator".to_string(),
                ));
            }
            n => {
                buffer.extend_from_slice(&read_buf[..n]);
            }
        }

        if buffer.len() > max_header_bytes {
            return Err(HttpFramingError::HeaderTooLarge);
        }

        if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            let header_end = pos + 4;
            let header_bytes = buffer[..header_end].to_vec();
            let body_prefix = buffer[header_end..].to_vec();

            let header_str = String::from_utf8_lossy(&header_bytes);
            let (content_length, chunked) = match parse_http_body_framing(&header_str) {
                Ok(framing) => framing,
                Err(e) => return Err(e),
            };

            return Ok(FramedHttpRequestHead {
                header_bytes,
                body_prefix,
                content_length,
                chunked,
            });
        }
    }
}

/// Parse Content-Length and Transfer-Encoding from raw HTTP header bytes.
///
/// Uses exact header-name splitting (`split_once(':')`) for consistency with
/// the response-side parser.
fn parse_http_body_framing(header_str: &str) -> Result<(Option<usize>, bool), HttpFramingError> {
    let mut content_length: Option<usize> = None;
    let mut chunked = false;

    for line in header_str.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (name, value) = match trimmed.split_once(':') {
            Some(pair) => pair,
            None => continue,
        };

        let name = name.trim();
        let value = value.trim();

        if name.eq_ignore_ascii_case("content-length") {
            let v: usize = value.parse().map_err(|_| {
                HttpFramingError::InvalidContentLength(format!("non-numeric value: {value}"))
            })?;
            if let Some(existing) = content_length {
                if existing != v {
                    return Err(HttpFramingError::InvalidContentLength(format!(
                        "conflicting values: {existing} and {v}"
                    )));
                }
            }
            content_length = Some(v);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            let te_lower = value.to_lowercase();
            if te_lower == "chunked" {
                chunked = true;
            } else {
                return Err(HttpFramingError::UnsupportedTransferEncoding(te_lower));
            }
        }
    }

    if chunked && content_length.is_some() {
        return Err(HttpFramingError::InvalidContentLength(
            "both Content-Length and Transfer-Encoding: chunked present".to_string(),
        ));
    }

    Ok((content_length, chunked))
}

/// Read a fixed-length HTTP body from an async reader.
///
/// Reads exactly `content_length` bytes, preserving any `prefix` bytes
/// that were already coalesced with the header read.
pub async fn read_fixed_http_body<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    prefix: Vec<u8>,
    content_length: usize,
    idle_timeout: Duration,
    total_timeout: Duration,
) -> Result<Vec<u8>, HttpFramingError> {
    if prefix.len() > content_length {
        return Err(HttpFramingError::MalformedHeaders(format!(
            "body prefix {} bytes exceeds declared Content-Length {content_length}",
            prefix.len(),
        )));
    }

    let remaining = content_length - prefix.len();
    if remaining == 0 {
        return Ok(prefix);
    }

    let deadline = tokio::time::Instant::now() + total_timeout;
    let mut body = prefix;
    body.reserve(remaining);
    let mut read_buf = [0u8; 8192];
    let mut total_read = 0usize;

    loop {
        if total_read >= remaining {
            break;
        }

        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(HttpFramingError::Io(
                "body framing deadline expired".to_string(),
            ));
        }
        let remaining_total = deadline.duration_since(now);
        let effective_timeout = idle_timeout.min(remaining_total);

        let to_read = (remaining - total_read).min(read_buf.len());

        use tokio::io::AsyncReadExt;
        let n = tokio::time::timeout(effective_timeout, reader.read(&mut read_buf[..to_read]))
            .await
            .map_err(|_| HttpFramingError::Io("body read timeout".to_string()))?
            .map_err(|e| HttpFramingError::Io(e.to_string()))?;

        match n {
            0 => {
                return Err(HttpFramingError::PrematureEof {
                    expected: remaining,
                    received: total_read,
                });
            }
            n => {
                body.extend_from_slice(&read_buf[..n]);
                total_read += n;
            }
        }
    }

    Ok(body)
}

/// Iteration 77, Phase 7: read-timeout helper that wraps only RecvStream
/// reads, not the entire handler. Used by both `handle_peer_message` and
/// `perform_health_check`.
async fn read_exact_with_timeout(
    recv: &mut RecvStream,
    buf: &mut [u8],
    timeout: Duration,
) -> Result<(), MeshTransportError> {
    tokio::time::timeout(timeout, recv.read_exact(buf))
        .await
        .map_err(|_| MeshTransportError::Timeout)?
        .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))
}

impl MeshTransport {
    pub(crate) async fn send_keepalive_datagram(
        &self,
        peer_id: &str,
    ) -> Result<(), MeshTransportError> {
        self.send_datagram_to_peer(peer_id, &MeshMessage::KeepAlive)
            .await
    }

    /// Iteration 77, Phase 22: deadline-aware drain of datagram handler tasks.
    ///
    /// Cooperative drain with a deadline, followed by abort of remaining handlers.
    /// This ensures no handler outlives the service shutdown signal.
    async fn drain_datagram_handlers(
        handlers: &mut tokio::task::JoinSet<Result<(), MeshTransportError>>,
        timeout: Duration,
    ) {
        let deadline = tokio::time::Instant::now() + timeout;

        while !handlers.is_empty() {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                break;
            }
            match tokio::time::timeout(left, handlers.join_next()).await {
                Ok(Some(result)) => {
                    let _ = result;
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }

        if !handlers.is_empty() {
            handlers.abort_all();
            while let Some(result) = handlers.join_next().await {
                let _ = result;
            }
        }
    }

    pub(crate) async fn start_datagram_handler(
        self: Arc<Self>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        use tokio::task::JoinSet;

        let max_concurrent = self.config.connection.max_concurrent_datagram_handlers;
        let drain_timeout =
            Duration::from_secs(self.config.connection.datagram_handler_drain_timeout_secs);
        let mut handlers: JoinSet<Result<(), MeshTransportError>> = JoinSet::new();

        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.recv() => {
                    tracing::info!("Datagram handler shutting down, draining {} handlers", handlers.len());
                    break;
                }
                Some(result) = handlers.join_next(), if !handlers.is_empty() => {
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            tracing::debug!("Datagram handler error: {}", e);
                        }
                        Err(e) if e.is_panic() => {
                            tracing::warn!("Datagram handler panicked: {}", e);
                        }
                        Err(_) => {} // cancelled during shutdown
                    }
                }
                peer_entry = self.wait_for_peer_datagrams() => {
                    if let Some((peer_id, data)) = peer_entry {
                        if handlers.len() >= max_concurrent {
                            tracing::trace!(
                                "Datagram handler capacity reached ({}/{}), dropping datagram from {}",
                                handlers.len(), max_concurrent, peer_id
                            );
                            continue;
                        }
                        let transport = self.clone();
                        handlers.spawn(async move {
                            transport.handle_incoming_datagram(&peer_id, data).await
                        });
                    }
                }
            }
        }

        // Iteration 77, Phase 22: drain/abort/await all handlers before return
        Self::drain_datagram_handlers(&mut handlers, drain_timeout).await;
    }

    pub(crate) async fn wait_for_peer_datagrams(&self) -> Option<(String, Bytes)> {
        use futures::future;
        use tokio::time::{timeout, Duration};

        const POLL_TIMEOUT_MS: u64 = 100;

        let peers: Vec<(String, quinn::Connection)> = self
            .peer_connections
            .iter()
            .map(|e| (e.key().clone(), e.value().connection.clone()))
            .collect();

        if peers.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
            return None;
        }

        let futures = peers.iter().map(|(peer_id, connection)| async move {
            match timeout(
                Duration::from_millis(POLL_TIMEOUT_MS),
                connection.read_datagram(),
            )
            .await
            {
                Ok(Ok(data)) => Some((peer_id.clone(), data)),
                Ok(Err(e)) => {
                    let err_str = e.to_string();
                    if err_str.contains("unsupported") {
                        tracing::debug!("Peer {} does not support datagrams", peer_id);
                    } else if err_str.contains("finished") || err_str.contains("FinRead") {
                    } else {
                        tracing::trace!("Datagram read error from {}: {}", peer_id, e);
                    }
                    None
                }
                Err(_) => None,
            }
        });

        let results = future::join_all(futures).await;

        results.into_iter().flatten().next()
    }

    pub(crate) async fn handle_incoming_datagram(
        &self,
        peer_id: &str,
        data: Bytes,
    ) -> Result<(), MeshTransportError> {
        let msg = match MeshMessage::decode(&data) {
            Some(m) => m,
            None => {
                return Err(MeshTransportError::ReceiveFailed(
                    "Failed to decode message".to_string(),
                ))
            }
        };

        if let Some(msg_id) = msg.message_id() {
            if self.is_message_seen(&msg_id) {
                tracing::debug!("Duplicate message ignored: {}", msg_id);
                return Ok(());
            }
            self.mark_message_seen(&msg_id);
        }

        if self.is_global_rate_limit_exceeded() {
            tracing::warn!("Global mesh rate limit exceeded, dropping message");
            return Ok(());
        }

        match msg {
            MeshMessage::RouteQuery {
                query_id,
                upstream_id,
                max_hops,
                initiator,
                sequence: _,
                timestamp: _,
                nonce: _,
            } => {
                self.handle_route_query_datagram(
                    peer_id,
                    &query_id,
                    &upstream_id,
                    max_hops,
                    &initiator,
                )
                .await;
            }
            MeshMessage::RouteResponse {
                query_id,
                upstream_id,
                provider_node_id,
                hops,
                ttl_secs,
                signature,
                timestamp,
                upstream_url,
                waf_policy,
                priority_tier,
                tier_claim,
                org_id,
                mesh_name,
                ..
            } => {
                self.handle_route_response(
                    &query_id,
                    &upstream_id,
                    &provider_node_id,
                    hops as u32,
                    ttl_secs,
                    timestamp,
                    signature,
                    upstream_url.clone(),
                    waf_policy.clone(),
                    priority_tier,
                    tier_claim,
                    org_id,
                    mesh_name,
                )
                .await;
                // Send ACK to confirm receipt
                let ack = MeshMessage::RouteResponseAck {
                    query_id: query_id.clone(),
                    upstream_id: upstream_id.clone(),
                    provider_node_id: provider_node_id.clone(),
                };
                let _ = self.send_datagram_to_peer(peer_id, &ack).await;
            }
            MeshMessage::RouteNotFound {
                query_id,
                upstream_id,
            } => {
                self.handle_route_not_found(&query_id, &upstream_id).await;
            }
            MeshMessage::KeepAlive => {
                self.handle_keepalive_datagram(peer_id).await;
            }
            MeshMessage::LookupRequest {
                request_id,
                key,
                lookup_type,
            } => {
                self.handle_lookup_request(peer_id, &request_id, &key, lookup_type)
                    .await;
            }
            MeshMessage::HotThreatGossip {
                bloom_filter,
                hashes,
                timestamp,
                immediate_indicator,
            } => {
                if let Some(ref threat_intel) = self.threat_intel {
                    threat_intel.handle_hot_threat_gossip(
                        bloom_filter,
                        hashes,
                        timestamp,
                        immediate_indicator,
                    );
                }
            }
            MeshMessage::BlocklistEventGossip { .. } => {
                tracing::debug!("Received blocklist event gossip from {}", peer_id);
                if let Some(ref ti) = self.threat_intel {
                    let bs = ti.get_block_store();
                    if let MeshMessage::BlocklistEventGossip {
                        ref event_id,
                        ref source_node,
                        timestamp,
                        operation,
                        target_kind,
                        ref identifier,
                        ref site_scope,
                        ref reason,
                        provenance_kind,
                        ref provenance_source,
                        ttl_secs,
                        version,
                        source_sequence,
                        logical_time,
                        ..
                    } = msg
                    {
                        use crate::blocklist_event::{
                            operation_from_u32, provenance_kind_from_u32, target_kind_from_u32,
                        };
                        let event = synvoid_core::block_store::BlocklistEvent {
                            operation: operation_from_u32(operation),
                            target_kind: target_kind_from_u32(target_kind),
                            identifier: identifier.to_string(),
                            site_scope: site_scope.to_string(),
                            reason: reason.as_ref().map(|r| r.to_string()),
                            provenance: synvoid_core::block_store::BlockProvenance {
                                kind: provenance_kind_from_u32(provenance_kind),
                                source: provenance_source.as_ref().map(|s| s.to_string()),
                            },
                            timestamp,
                            source_node: Some(source_node.to_string()),
                            event_id: Some(event_id.to_string()),
                            ttl_secs,
                            version,
                            source_sequence,
                            logical_time,
                        };
                        let result = bs.apply_blocklist_event(&event);
                        tracing::info!(
                            "Applied blocklist event gossip from {}: {:?} {:?} on {:?} -> {:?}",
                            peer_id,
                            operation,
                            target_kind,
                            identifier,
                            result
                        );
                    }
                }
            }
            MeshMessage::BlocklistCatchupRequest {
                requesting_node: _,
                since_sequence,
                since_timestamp: _,
                max_events,
            } => {
                tracing::debug!(
                    "Received blocklist catchup request from {} (since_seq={:?}, max={})",
                    peer_id,
                    since_sequence,
                    max_events
                );
                if let Some(ref ti) = self.threat_intel {
                    let bs = ti.get_block_store();
                    let cursor = crate::stubs::block_store::BlocklistEventCursor {
                        since_sequence,
                        max_events,
                    };
                    let result = bs.query_blocklist_catchup(&cursor);
                    let events: Vec<crate::blocklist_event::BlocklistEventData> = result
                        .events
                        .iter()
                        .map(crate::blocklist_event::BlocklistEventData::from_event)
                        .collect();
                    let response = MeshMessage::BlocklistCatchupResponse {
                        events,
                        history_complete: result.history_complete,
                        latest_sequence: Some(result.latest_sequence),
                        latest_timestamp: Some(result.latest_timestamp),
                        snapshot_required: result.snapshot_required,
                    };
                    let _ = self.send_datagram_to_peer(peer_id, &response).await;
                    tracing::debug!(
                        "Sent blocklist catchup response to {}: {} events, history_complete={}",
                        peer_id,
                        result.events.len(),
                        result.history_complete
                    );
                } else {
                    tracing::trace!(
                        "Blocklist catchup request received but threat intel not enabled"
                    );
                }
            }
            MeshMessage::BlocklistCatchupResponse {
                ref events,
                history_complete,
                latest_sequence,
                latest_timestamp,
                snapshot_required,
            } => {
                tracing::debug!(
                    "Received blocklist catchup response from {}: {} events, history_complete={}",
                    peer_id,
                    events.len(),
                    history_complete
                );
                if snapshot_required {
                    tracing::info!(
                        "Peer {} indicates blocklist snapshot required (history incomplete), requesting snapshot",
                        peer_id
                    );
                    let request_id =
                        format!("snap-{}-{}", peer_id, synvoid_utils::safe_unix_timestamp());
                    let snapshot_request = MeshMessage::BlocklistSnapshotRequest {
                        requesting_node: self.config.node_id().into(),
                        request_id: request_id.into(),
                        include_ip_blocks: true,
                        include_mesh_id_blocks: true,
                        include_target_state: true,
                        site_scope: None,
                        page_token: None,
                        max_items: 500,
                    };
                    if let Err(e) = self.send_datagram_to_peer(peer_id, &snapshot_request).await {
                        tracing::warn!(
                            "Failed to send blocklist snapshot request to {}: {}",
                            peer_id,
                            e
                        );
                    }
                }
                if let Some(ref ti) = self.threat_intel {
                    let bs = ti.get_block_store();
                    let mut applied = 0u32;
                    let mut noop = 0u32;
                    let mut stale = 0u32;
                    for event_data in events {
                        let event = event_data.to_event();
                        match bs.apply_blocklist_event(&event) {
                            crate::stubs::block_store::BlocklistApplyResult::Applied => {
                                applied += 1;
                            }
                            crate::stubs::block_store::BlocklistApplyResult::NoopDuplicate => {
                                noop += 1;
                            }
                            crate::stubs::block_store::BlocklistApplyResult::IgnoredStale => {
                                stale += 1;
                            }
                            _ => {}
                        }
                    }
                    tracing::info!(
                        "Blocklist catchup from {}: applied={}, noop={}, stale={}, latest_seq={:?}",
                        peer_id,
                        applied,
                        noop,
                        stale,
                        latest_sequence
                    );
                    // Phase 5: Update persisted peer cursor after successful catchup.
                    if applied > 0 || noop > 0 {
                        if let Some(latest_seq) = latest_sequence {
                            if let Some(latest_ts) = latest_timestamp {
                                let now = synvoid_utils::safe_unix_timestamp();
                                let record = crate::stubs::block_store::BlocklistPeerCursorRecord {
                                    peer_id: peer_id.to_string(),
                                    source_node: self.config.node_id().to_string(),
                                    last_sequence: Some(latest_seq),
                                    last_timestamp: latest_ts,
                                    last_event_id: None,
                                    updated_at: now,
                                    expires_at: Some(now.saturating_add(86400 * 7)),
                                };
                                bs.update_blocklist_peer_cursor(record);
                                bs.persist_peer_cursors();
                                tracing::debug!(
                                    "Updated blocklist peer cursor for {}: seq={}, ts={}",
                                    peer_id,
                                    latest_seq,
                                    latest_ts
                                );
                            }
                        }
                    }
                } else {
                    tracing::trace!(
                        "Blocklist catchup response received but threat intel not enabled"
                    );
                }
            }

            MeshMessage::BlocklistSnapshotRequest {
                requesting_node: _,
                request_id,
                include_ip_blocks,
                include_mesh_id_blocks,
                include_target_state,
                site_scope,
                page_token,
                max_items,
            } => {
                tracing::debug!(
                    "Received blocklist snapshot request from {} (request_id={})",
                    peer_id,
                    request_id
                );
                if let Some(ref ti) = self.threat_intel {
                    let bs = ti.get_block_store();
                    let options = crate::stubs::block_store::BlocklistSnapshotOptions {
                        include_ip_blocks,
                        include_mesh_id_blocks,
                        include_target_state,
                        site_scope: site_scope.as_ref().map(|s| s.to_string()),
                        max_items,
                    };
                    let cursor = crate::stubs::block_store::BlocklistSnapshotCursor {
                        page_token: page_token.as_ref().map(|s| s.to_string()),
                    };
                    let chunk = bs.export_blocklist_snapshot(&options, &cursor);

                    // Convert to wire format.
                    let ip_blocks: Vec<crate::blocklist_event::SnapshotIpBlockData> = chunk
                        .ip_blocks
                        .iter()
                        .map(crate::blocklist_event::SnapshotIpBlockData::from_record)
                        .collect();
                    let mesh_blocks: Vec<crate::blocklist_event::SnapshotMeshBlockData> = chunk
                        .mesh_blocks
                        .iter()
                        .map(crate::blocklist_event::SnapshotMeshBlockData::from_record)
                        .collect();
                    let target_state_records: Vec<crate::blocklist_event::SnapshotTargetStateData> =
                        chunk
                            .target_state_records
                            .iter()
                            .map(crate::blocklist_event::SnapshotTargetStateData::from_record)
                            .collect();

                    let response = MeshMessage::BlocklistSnapshotResponse {
                        request_id,
                        source_node: self.config.node_id().into(),
                        timestamp: synvoid_utils::safe_unix_timestamp(),
                        ip_blocks,
                        mesh_blocks,
                        target_state_records,
                        next_page_token: chunk.next_page_token.map(|t| t.into()),
                        has_more: chunk.has_more,
                        snapshot_complete: chunk.snapshot_complete,
                        truncated_reason: chunk.truncated_reason.map(|t| t.into()),
                        error: None,
                    };
                    let _ = self.send_datagram_to_peer(peer_id, &response).await;
                    tracing::debug!(
                        "Sent blocklist snapshot response to {}: ip_blocks={}, mesh_blocks={}, target_state={}, has_more={}",
                        peer_id,
                        chunk.ip_blocks.len(),
                        chunk.mesh_blocks.len(),
                        chunk.target_state_records.len(),
                        chunk.has_more
                    );
                } else {
                    tracing::trace!(
                        "Blocklist snapshot request received but threat intel not enabled"
                    );
                }
            }

            MeshMessage::BlocklistSnapshotResponse {
                ref request_id,
                source_node: _,
                timestamp: _,
                ref ip_blocks,
                ref mesh_blocks,
                ref target_state_records,
                ref next_page_token,
                has_more,
                snapshot_complete,
                truncated_reason: _,
                error,
            } => {
                if let Some(ref err) = error {
                    tracing::warn!(
                        "Blocklist snapshot response from {} contains error: {} (request_id={})",
                        peer_id,
                        err,
                        request_id
                    );
                    return Ok(());
                }
                tracing::debug!(
                    "Received blocklist snapshot response from {}: ip_blocks={}, mesh_blocks={}, target_state={}, has_more={}, request_id={}",
                    peer_id,
                    ip_blocks.len(),
                    mesh_blocks.len(),
                    target_state_records.len(),
                    has_more,
                    request_id
                );
                if let Some(ref ti) = self.threat_intel {
                    let bs = ti.get_block_store();

                    // Convert wire format to core types.
                    let core_ip_blocks: Vec<synvoid_core::block_store::BlockRecord> = ip_blocks
                        .iter()
                        .map(|b| synvoid_core::block_store::BlockRecord {
                            target_kind: synvoid_core::block_store::BlockTargetKind::Ip,
                            identifier: b.ip.clone(),
                            reason: b.reason.clone(),
                            blocked_at: b.blocked_at,
                            ban_expire_seconds: b.ban_expire_seconds,
                            site_scope: b.site_scope.clone(),
                            access_count: b.access_count,
                            last_access: b.last_access,
                            provenance: synvoid_core::block_store::BlockProvenance {
                                kind: crate::blocklist_event::provenance_kind_from_u32(
                                    b.provenance_kind,
                                ),
                                source: b.provenance_source.clone(),
                            },
                        })
                        .collect();
                    let core_mesh_blocks: Vec<synvoid_core::block_store::BlockRecord> = mesh_blocks
                        .iter()
                        .map(|b| synvoid_core::block_store::BlockRecord {
                            target_kind: synvoid_core::block_store::BlockTargetKind::MeshId,
                            identifier: b.mesh_id.clone(),
                            reason: b.reason.clone(),
                            blocked_at: b.blocked_at,
                            ban_expire_seconds: b.ban_expire_seconds,
                            site_scope: b.site_scope.clone(),
                            access_count: b.access_count,
                            last_access: b.last_access,
                            provenance: synvoid_core::block_store::BlockProvenance {
                                kind: crate::blocklist_event::provenance_kind_from_u32(
                                    b.provenance_kind,
                                ),
                                source: b.provenance_source.clone(),
                            },
                        })
                        .collect();
                    let core_target_state: Vec<
                        synvoid_core::block_store::BlocklistTargetStateRecord,
                    > = target_state_records
                        .iter()
                        .map(|r| synvoid_core::block_store::BlocklistTargetStateRecord {
                            target_kind: crate::blocklist_event::target_kind_from_u32(
                                r.target_kind,
                            ),
                            site_scope: r.site_scope.clone(),
                            identifier: r.identifier.clone(),
                            last_operation: crate::blocklist_event::operation_from_u32(
                                r.last_operation,
                            ),
                            timestamp: r.timestamp,
                            version: r.version,
                            event_id: r.event_id.clone(),
                            source_node: r.source_node.clone(),
                            provenance: synvoid_core::block_store::BlockProvenance {
                                kind: crate::blocklist_event::provenance_kind_from_u32(
                                    r.provenance_kind,
                                ),
                                source: r.provenance_source.clone(),
                            },
                            recorded_at: r.recorded_at,
                            expires_at: r.expires_at,
                            source_sequence: r.source_sequence,
                            logical_time: r.logical_time,
                        })
                        .collect();

                    let chunk = crate::stubs::block_store::BlocklistSnapshotChunk {
                        ip_blocks: core_ip_blocks,
                        mesh_blocks: core_mesh_blocks,
                        target_state_records: core_target_state,
                        next_page_token: next_page_token.as_ref().map(|t| t.to_string()),
                        has_more,
                        snapshot_complete,
                        truncated_reason: None,
                    };

                    let result = bs.apply_blocklist_snapshot(&chunk);
                    tracing::info!(
                        "Blocklist snapshot applied from {}: ip_applied={}, ip_updated={}, mesh_applied={}, mesh_updated={}, target_state={}, stale_ignored={}, invalid_ignored={}, expired_ignored={}",
                        peer_id,
                        result.ip_blocks_applied,
                        result.ip_blocks_updated,
                        result.mesh_blocks_applied,
                        result.mesh_blocks_updated,
                        result.target_state_records_applied,
                        result.stale_records_ignored,
                        result.invalid_records_ignored,
                        result.expired_records_ignored,
                    );

                    // Request next page if needed.
                    if has_more {
                        if let Some(ref token) = next_page_token {
                            let next_request = MeshMessage::BlocklistSnapshotRequest {
                                requesting_node: self.config.node_id().into(),
                                request_id: request_id.clone(),
                                include_ip_blocks: true,
                                include_mesh_id_blocks: true,
                                include_target_state: true,
                                site_scope: None,
                                page_token: Some(token.clone()),
                                max_items: 500,
                            };
                            if let Err(e) = self.send_datagram_to_peer(peer_id, &next_request).await
                            {
                                tracing::warn!(
                                    "Failed to send next blocklist snapshot request to {}: {}",
                                    peer_id,
                                    e
                                );
                            }
                        } else {
                            tracing::warn!(
                                "Blocklist snapshot response from {} has has_more=true but next_page_token is None, stopping pagination",
                                peer_id
                            );
                        }
                    } else {
                        tracing::info!("Blocklist snapshot convergence complete from {}", peer_id);
                    }
                } else {
                    tracing::trace!(
                        "Blocklist snapshot response received but threat intel not enabled"
                    );
                }
            }

            MeshMessage::LookupBatchRequest { request_id, keys } => {
                self.handle_lookup_batch_request(peer_id, &request_id, &keys)
                    .await;
            }
            MeshMessage::PeerHealthCheck {
                peer_id: target_peer_id,
                timestamp,
            } => {
                self.handle_peer_health_check(peer_id, &target_peer_id, timestamp)
                    .await;
            }
            MeshMessage::PeerAnnounce {
                node_id,
                address,
                role,
                capabilities,
                announced_at,
            } => {
                self.handle_peer_announce(
                    peer_id,
                    &node_id,
                    &address,
                    role,
                    &capabilities,
                    announced_at,
                )
                .await;
            }
            MeshMessage::PeerGone { node_id, reason } => {
                self.handle_peer_gone(peer_id, &node_id, &reason).await;
            }
            MeshMessage::TopologySyncRequest {
                request_id,
                from_version,
                prefer_delta: _,
            } => {
                self.handle_topology_sync_request(peer_id, &request_id, from_version)
                    .await;
            }
            MeshMessage::SeedListRequest {
                node_id,
                request_full_mesh,
            } => {
                self.handle_seed_list_request(peer_id, &node_id, request_full_mesh)
                    .await;
            }
            MeshMessage::SeedListResponse {
                global_nodes,
                edge_nodes,
                version: _,
                genesis_org_id,
            } => {
                self.handle_seed_list_response(global_nodes, edge_nodes, genesis_org_id)
                    .await;
            }
            MeshMessage::PeerLoadReport {
                node_id,
                active_connections,
                cpu_load_percent,
                memory_percent,
                requests_per_second,
            } => {
                self.handle_peer_load_report(
                    &node_id,
                    active_connections,
                    cpu_load_percent,
                    memory_percent,
                    requests_per_second,
                )
                .await;
            }
            MeshMessage::PeerLoadUpdate {
                node_id,
                load_score,
            } => {
                self.handle_peer_load_update(&node_id, load_score).await;
            }
            MeshMessage::RouteUsageReport {
                upstream_id,
                request_count,
                bytes_transferred,
            } => {
                self.handle_route_usage_report(&upstream_id, request_count, bytes_transferred)
                    .await;
            }
            MeshMessage::UpstreamBlocked {
                mesh_identifier,
                service_id,
                blocked_until,
                reason,
                origin_node_id,
            } => {
                self.handle_upstream_blocked(
                    &mesh_identifier,
                    &service_id,
                    blocked_until,
                    &reason,
                    &origin_node_id,
                )
                .await;
            }
            MeshMessage::BandwidthReport {
                upstream_id,
                bytes_sent,
                bytes_received,
                request_count,
                interval_secs,
                timestamp,
            } => {
                self.handle_bandwidth_report(
                    &upstream_id,
                    bytes_sent,
                    bytes_received,
                    request_count,
                    interval_secs,
                    timestamp,
                )
                .await;
            }
            MeshMessage::OrgRegistrationRequest {
                request_id,
                org_name,
                requesting_node_id,
                requesting_node_pubkey,
                timestamp: _,
                signature: _,
            } => {
                self.handle_org_registration_request(
                    peer_id,
                    &request_id,
                    &org_name,
                    &requesting_node_id,
                    &requesting_node_pubkey,
                )
                .await;
            }
            MeshMessage::OrgRegistrationResponse {
                request_id: _,
                org_id,
                org_name: _,
                approved,
                reason: _,
                initial_tier_key,
                signature: _,
                timestamp: _,
            } => {
                self.handle_org_registration_response(
                    peer_id,
                    &org_id,
                    approved,
                    initial_tier_key.as_ref(),
                )
                .await;
            }
            MeshMessage::UpstreamVerificationQuery {
                request_id,
                upstream_id,
                querying_node_id,
                timestamp: _,
                provider_node_id,
            } => {
                self.handle_upstream_verification_query(
                    peer_id,
                    &request_id,
                    &upstream_id,
                    &querying_node_id,
                    &provider_node_id,
                )
                .await;
            }
            MeshMessage::UpstreamVerificationResponse {
                request_id,
                upstream_id,
                verified,
                global_node_id,
                global_node_signature: _,
                upstream_url: _,
                org_id: _,
                timestamp: _,
                provider_node_id,
            } => {
                self.handle_upstream_verification_response(
                    peer_id,
                    &request_id,
                    &upstream_id,
                    verified,
                    &global_node_id,
                    &provider_node_id,
                )
                .await;
            }
            MeshMessage::UpstreamOwnershipChallenge {
                request_id,
                upstream_id,
                challenge_type,
                challenge_token,
                global_node_id,
                timestamp,
            } => {
                self.handle_upstream_ownership_challenge(
                    peer_id,
                    &request_id,
                    &upstream_id,
                    &challenge_type,
                    &challenge_token,
                    &global_node_id,
                    timestamp,
                )
                .await;
            }
            MeshMessage::OrgInvitationRequest {
                request_id,
                org_id,
                inviter_node_id,
                invited_node_id,
                invited_node_pubkey: _,
                invitation_token,
                expires_at,
                timestamp: _,
                signature: _,
            } => {
                self.handle_org_invitation_request(
                    peer_id,
                    &request_id,
                    &org_id,
                    &inviter_node_id,
                    &invited_node_id,
                    &invitation_token,
                    expires_at,
                )
                .await;
            }
            MeshMessage::OrgInvitationAccept {
                request_id,
                org_id,
                invited_node_id,
                invitation_token,
                proof_of_key,
                timestamp: _,
                signature: _,
            } => {
                self.handle_org_invitation_accept(
                    peer_id,
                    &request_id,
                    &org_id,
                    &invited_node_id,
                    &invitation_token,
                    &proof_of_key,
                )
                .await;
            }
            MeshMessage::OrgMemberAnnounce {
                org_id,
                member_node_id,
                announced_by,
                joined_at,
                signature: _,
            } => {
                self.handle_org_member_announce(&org_id, &member_node_id, &announced_by, joined_at)
                    .await;
            }
            MeshMessage::TierKeyAnnounce {
                org_id,
                key,
                signature: _,
            } => {
                self.handle_tier_key_announce(&org_id, &key).await;
            }
            MeshMessage::TierKeyRevoke {
                org_id,
                key_id,
                signature: _,
            } => {
                self.handle_tier_key_revoke(&org_id, &key_id).await;
            }
            MeshMessage::GlobalNodeAnnounce {
                node_id,
                public_key,
                action,
                timestamp,
                signature,
                key_exchange_endpoint,
                cert_chain,
            } => {
                self.handle_global_node_announce(
                    peer_id,
                    &node_id,
                    &public_key,
                    action,
                    timestamp,
                    &signature,
                    key_exchange_endpoint.as_deref(),
                    cert_chain.as_ref(),
                )
                .await;
            }
            MeshMessage::GenesisKeyTransition {
                sequence,
                new_key_fingerprint,
                announced_by,
                timestamp,
                genesis_signature,
            } => {
                self.handle_genesis_key_transition(
                    peer_id,
                    sequence,
                    &new_key_fingerprint,
                    &announced_by,
                    timestamp,
                    &genesis_signature,
                )
                .await;
            }
            MeshMessage::RevokeGlobalNode {
                node_id,
                reason,
                timestamp,
                genesis_signature,
            } => {
                self.handle_revoke_global_node(
                    peer_id,
                    &node_id,
                    &reason,
                    timestamp,
                    &genesis_signature,
                )
                .await;
            }
            MeshMessage::UnspentTierKeyAnnounce {
                org_id,
                tier_keys,
                signature: _,
                timestamp: _,
            } => {
                self.handle_unspent_tier_key_announce(&org_id, &tier_keys)
                    .await;
            }
            MeshMessage::KeySigned {
                session_id,
                key_id,
                mesh_id,
                origin_mesh_id,
                origin_ed25519_pubkey,
                server_x25519_pubkey,
                origin_signature,
                nonce: _,
                timestamp: _,
            } => {
                self.handle_key_signed(
                    peer_id,
                    &session_id,
                    &key_id,
                    &mesh_id,
                    &origin_mesh_id,
                    &origin_ed25519_pubkey,
                    &server_x25519_pubkey,
                    &origin_signature,
                )
                .await;
            }
            MeshMessage::DhtSnapshotRequest {
                request_id,
                node_id,
                from_version,
                signature,
                signer_public_key,
            } => {
                self.handle_dht_snapshot_request(
                    peer_id,
                    &request_id,
                    &node_id,
                    from_version,
                    &signature,
                    signer_public_key.as_deref().unwrap_or(""),
                )
                .await;
            }
            MeshMessage::DhtSnapshotResponse {
                request_id,
                records,
                version,
                timestamp,
                signature,
                signer_public_key,
            } => {
                self.handle_dht_snapshot_response(
                    peer_id,
                    &request_id,
                    records,
                    version,
                    timestamp,
                    &signature,
                    signer_public_key.as_deref().unwrap_or(""),
                )
                .await;
            }
            MeshMessage::DhtRecordAnnounce {
                request_id: _,
                records,
                write_quorum: _,
                timestamp: _,
                source_node_id,
                signature: _,
                ..
            } => {
                if self
                    .validate_peer_node_id_binding(peer_id, &source_node_id)
                    .is_err()
                {
                    tracing::warn!(
                        "DhtRecordAnnounce rejected: source_node_id {} doesn't match peer {}",
                        source_node_id,
                        peer_id
                    );
                    return Ok(());
                }
                self.handle_dht_record_announce(peer_id, &source_node_id, records)
                    .await;
            }
            MeshMessage::DhtRecordQuery {
                request_id,
                key,
                timestamp: _,
                source_node_id: _,
            } => {
                if let Some(ref record_store) = self.record_store {
                    if let Some(response) =
                        record_store.handle_record_query(&request_id, &key, peer_id)
                    {
                        let _ = self.send_datagram_to_peer(peer_id, &response).await;
                    }
                }
            }
            MeshMessage::DhtRecordResponse {
                request_id,
                key,
                value,
                found,
                timestamp,
                source_node_id,
                signature,
                signer_public_key,
            } => {
                if found {
                    let record = crate::protocol::DhtRecord {
                        key: key.to_string(),
                        value: value.clone(),
                        timestamp,
                        sequence_number: 0,
                        ttl_seconds: 0,
                        source_node_id: source_node_id.to_string(),
                        signature,
                        signer_public_key,
                        content_hash: {
                            use sha2::{Digest, Sha256};
                            let mut hasher = Sha256::new();
                            hasher.update(&value);
                            hasher.finalize().to_vec()
                        },
                        quorum_proof: Vec::new(),
                        request_id: None,
                    };
                    let _ = self.complete_dht_query(&request_id, record).await;
                }
            }
            MeshMessage::DhtSyncRequest {
                request_id,
                node_id,
                from_version,
                timestamp,
                nonce,
                signature,
                signer_public_key,
            } => {
                if self
                    .validate_peer_node_id_binding(peer_id, &node_id)
                    .is_err()
                {
                    tracing::warn!(
                        "DhtSyncRequest rejected: node_id {} doesn't match peer {}",
                        node_id,
                        peer_id
                    );
                    return Ok(());
                }
                self.handle_dht_sync_request(
                    peer_id,
                    &request_id,
                    &node_id,
                    from_version,
                    timestamp,
                    &nonce,
                    &signature,
                    signer_public_key.as_deref(),
                )
                .await;
            }
            MeshMessage::DhtSyncResponse {
                request_id,
                records,
                version,
                timestamp,
                signature,
                signer_public_key,
            } => {
                self.handle_dht_sync_response(
                    peer_id,
                    &request_id,
                    records,
                    version,
                    timestamp,
                    &signature,
                    signer_public_key.as_deref(),
                )
                .await;
            }
            MeshMessage::DhtAntiEntropyRequest {
                request_id,
                node_id,
                local_root_hash,
                interested_keys,
                timestamp,
                nonce,
                signature,
                signer_public_key,
                ..
            } => {
                if self
                    .validate_peer_node_id_binding(peer_id, &node_id)
                    .is_err()
                {
                    tracing::warn!(
                        "DhtAntiEntropyRequest rejected: node_id {} doesn't match peer {}",
                        node_id,
                        peer_id
                    );
                    return Ok(());
                }
                self.handle_dht_anti_entropy_request(
                    peer_id,
                    &request_id,
                    &node_id,
                    &local_root_hash,
                    &interested_keys,
                    timestamp,
                    &nonce,
                    &signature,
                    signer_public_key.as_deref(),
                )
                .await;
            }
            MeshMessage::DhtAntiEntropyResponse {
                request_id: _,
                root_hash: _,
                proof_keys: _,
                proof_hashes: _,
                missing_records,
                timestamp,
                signature,
                signer_public_key,
                ..
            } => {
                self.handle_dht_anti_entropy_response(
                    peer_id,
                    missing_records,
                    timestamp,
                    &signature,
                    signer_public_key.as_deref(),
                )
                .await;
            }
            MeshMessage::FindNode {
                request_id,
                target_node_id,
                requester_node_id,
                timestamp: _,
            } => {
                self.handle_find_node(peer_id, &request_id, target_node_id, &requester_node_id)
                    .await;
            }
            MeshMessage::FindNodeResponse {
                request_id: _,
                peers,
                responder_node_id: _,
                timestamp: _,
            } => {
                self.handle_find_node_response(peer_id, peers).await;
            }
            MeshMessage::OriginKeyQuery {
                request_id,
                mesh_id,
                timestamp: _,
            } => {
                self.handle_origin_key_query(peer_id, &request_id, &mesh_id)
                    .await;
            }
            MeshMessage::OriginKeyQueryResponse {
                request_id: _,
                mesh_id,
                public_key,
                timestamp: _,
            } => {
                if let Some(ref pk) = public_key {
                    tracing::debug!("Received origin public key for mesh {}: {}", mesh_id, pk);
                }
            }
            #[cfg(feature = "dns")]
            MeshMessage::NodeShutdown {
                node_id,
                role,
                domains,
                graceful,
                shutdown_at,
                timestamp,
                signature: _,
            } => {
                let domains_vec: Vec<std::sync::Arc<str>> =
                    domains.iter().map(|d| d.as_arc()).collect();
                self.handle_node_shutdown(
                    peer_id,
                    &node_id,
                    role,
                    domains_vec.as_slice(),
                    graceful,
                    shutdown_at,
                    timestamp,
                )
                .await;
            }
            #[cfg(not(feature = "dns"))]
            MeshMessage::NodeShutdown { .. } => {
                tracing::debug!("NodeShutdown received but DNS feature not enabled");
            }
            MeshMessage::SiteConfigSync {
                request_id,
                site_id,
                config_version,
                config_json,
                timestamp,
                source_node_id,
                signature,
                signer_public_key,
                proxy_cache_preferences,
            } => {
                self.handle_site_config_sync(
                    peer_id,
                    &request_id,
                    &site_id,
                    config_version,
                    &config_json,
                    timestamp,
                    &source_node_id,
                    signature.as_ref(),
                    signer_public_key.as_deref(),
                    proxy_cache_preferences.as_ref(),
                )
                .await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::DnsDomainRegisterRequest {
                request_id,
                domain,
                origin_node_id,
                challenge_token,
                geo,
                capacity,
                timestamp,
                signature,
            } => {
                self.handle_dns_domain_register_request(
                    peer_id,
                    &request_id,
                    &domain,
                    &origin_node_id,
                    &challenge_token,
                    geo.as_deref(),
                    capacity,
                    timestamp,
                    &signature,
                )
                .await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::DnsDomainRegisterResponse {
                request_id,
                domain,
                origin_node_id,
                verified,
                reason,
                timestamp,
                signature: _,
            } => {
                self.handle_dns_domain_register_response(
                    peer_id,
                    &request_id,
                    &domain,
                    &origin_node_id,
                    verified,
                    &reason,
                    timestamp,
                )
                .await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::DnsDomainDeregisterRequest {
                request_id,
                domain,
                origin_node_id,
                reason,
                timestamp,
                signature: _,
            } => {
                self.handle_dns_domain_deregister_request(
                    peer_id,
                    &request_id,
                    &domain,
                    &origin_node_id,
                    &reason,
                    timestamp,
                )
                .await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::DnsDomainRegistered {
                domain,
                origin_node_id,
                verified_by_global_node,
                geo,
                capacity,
                registered_at,
                expires_at,
                signature: _,
            } => {
                self.handle_dns_domain_registered(
                    peer_id,
                    &domain,
                    &origin_node_id,
                    &verified_by_global_node,
                    geo.as_deref(),
                    capacity,
                    registered_at,
                    expires_at,
                )
                .await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::DnsDomainDeregistered {
                domain,
                origin_node_id,
                deregistered_by_global_node,
                reason,
                deregistered_at,
                signature: _,
            } => {
                self.handle_dns_domain_deregistered(
                    peer_id,
                    &domain,
                    &origin_node_id,
                    &deregistered_by_global_node,
                    &reason,
                    deregistered_at,
                )
                .await;
            }
            MeshMessage::Ping {
                request_id,
                node_id: _,
                timestamp: _,
            } => {
                self.handle_ping(peer_id, &request_id).await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::AnycastNodeRegistration { .. } => {
                tracing::debug!("AnycastNodeRegistration received");
            }
            #[cfg(feature = "dns")]
            MeshMessage::AnycastHealthUpdate {
                node_id,
                anycast_ips,
                healthy,
                latency_ms,
                load_percent,
                timestamp: _,
            } => {
                self.handle_anycast_health_update(
                    peer_id,
                    &node_id,
                    anycast_ips,
                    healthy,
                    latency_ms,
                    load_percent,
                )
                .await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::ZoneSyncRequest {
                request_id,
                zone_origin,
                serial,
                requesting_node_id,
                timestamp: _,
            } => {
                self.handle_zone_sync_request(
                    peer_id,
                    &request_id,
                    &zone_origin,
                    serial,
                    &requesting_node_id,
                )
                .await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::ZoneSyncResponse {
                request_id,
                zone_origin,
                records_json,
                serial,
                complete,
                timestamp: _,
                origin_signature,
                origin_pubkey,
                previous_serial,
                compressed,
            } => {
                self.handle_zone_sync_response(
                    peer_id,
                    &request_id,
                    &zone_origin,
                    &records_json,
                    serial,
                    complete,
                    &origin_signature,
                    origin_pubkey.as_deref(),
                    previous_serial,
                    compressed,
                )
                .await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::ZoneSyncAck {
                request_id,
                zone_origin,
                serial,
                timestamp: _,
            } => {
                self.handle_zone_sync_ack(peer_id, &request_id, &zone_origin, serial)
                    .await;
            }
            MeshMessage::ThreatAnnounce { .. }
            | MeshMessage::ThreatSyncRequest { .. }
            | MeshMessage::ThreatSyncResponse { .. }
            | MeshMessage::ThreatAcknowledgement { .. } => {
                if let Some(ref threat_intel) = self.threat_intel {
                    let peer_role = self
                        .topology
                        .get_peer(peer_id)
                        .await
                        .map(|p| p.role)
                        .unwrap_or(crate::config::MeshNodeRole::EDGE);
                    if let Some(response) = threat_intel.handle_mesh_message(
                        &msg,
                        peer_id,
                        peer_role,
                        self.mesh_signer.as_ref(),
                    ) {
                        let _ = self.send_datagram_to_peer(peer_id, &response).await;
                    }
                } else {
                    tracing::trace!(
                        "Threat message received but threat intel not enabled: {:?}",
                        msg
                    );
                }
            }
            MeshMessage::YaraRuleAnnounce { .. }
            | MeshMessage::YaraRuleSyncRequest { .. }
            | MeshMessage::YaraRuleSyncResponse { .. }
            | MeshMessage::YaraRuleAcknowledgement { .. }
            | MeshMessage::YaraRuleSubmission { .. }
            | MeshMessage::YaraRuleSubmissionResponse { .. } => {
                if let Some(ref yara_rules) = self.yara_rules {
                    if let Some(response) = yara_rules.handle_mesh_message(&msg, peer_id) {
                        let _ = self.send_datagram_to_peer(peer_id, &response).await;
                    }
                } else {
                    tracing::trace!(
                        "YARA message received but YARA rules not enabled: {:?}",
                        msg
                    );
                }
            }
            MeshMessage::OrgKeySignRequest { .. } | MeshMessage::OrgKeySignResponse { .. } => {
                if let Some(response) = self.org_key_manager.handle_mesh_message(msg).await {
                    let _ = self.send_datagram_to_peer(peer_id, &response).await;
                }
            }
            MeshMessage::ReplicaSyncRequest {
                request_id,
                last_sync_index,
                node_id: _,
            } => {
                self.handle_replica_sync_request(peer_id, &request_id, last_sync_index)
                    .await;
            }
            MeshMessage::ReplicaSyncResponse { .. } => {
                // Handled by pending responses in RaftAwareClient or transport
            }
            MeshMessage::UpstreamAnnounce {
                upstream_id,
                action,
                signature,
                origin_ed25519_pubkey,
                origin_signature,
            } => {
                use crate::dht::keys::DhtKey;
                use crate::protocol::AnnounceAction;
                use ed25519_dalek::Verifier;

                let upstream_id_str = upstream_id.to_string();
                let origin_pk_str = origin_ed25519_pubkey.to_string();

                let sign_data = format!("{}:{:?}:{}", upstream_id_str, action, peer_id);

                let signature_valid = if !origin_signature.is_empty()
                    && !origin_ed25519_pubkey.is_empty()
                {
                    let pk_bytes = hex::decode(&origin_pk_str);
                    let sig_bytes: Vec<u8> = origin_signature.clone();
                    if pk_bytes.as_ref().map_or(false, |b| b.len() == 32) && sig_bytes.len() == 64 {
                        let pk_bytes = pk_bytes.unwrap();
                        let mut pk_array = [0u8; 32];
                        pk_array.copy_from_slice(&pk_bytes);

                        let mut sig_array = [0u8; 64];
                        sig_array.copy_from_slice(&sig_bytes);

                        match ed25519_dalek::VerifyingKey::from_bytes(&pk_array) {
                            Ok(pk) => pk
                                .verify(
                                    sign_data.as_bytes(),
                                    &ed25519_dalek::Signature::from_bytes(&sig_array),
                                )
                                .is_ok(),
                            Err(_) => false,
                        }
                    } else {
                        false
                    }
                } else {
                    false
                };

                if !signature_valid {
                    tracing::warn!(
                        "UpstreamAnnounce from {} for {} rejected: invalid origin signature",
                        peer_id,
                        upstream_id_str
                    );
                    return Ok(());
                }

                let key = DhtKey::verified_upstream(&upstream_id_str);
                let key_str = key.as_str();

                match action {
                    AnnounceAction::Add | AnnounceAction::Update => {
                        if let Some(ref record_store) = self.record_store {
                            let origin_node_id = if let Ok(pk_bytes) = hex::decode(&origin_pk_str) {
                                crate::dht::routing::node_id::NodeId::from_public_key(&pk_bytes)
                                    .to_string()
                            } else {
                                origin_pk_str.clone()
                            };

                            let verified_upstream = crate::dht::VerifiedUpstream {
                                upstream_id: upstream_id_str.clone(),
                                origin_node_id,
                                upstream_url: upstream_id_str.clone(),
                                org_id: None,
                                global_node_id: peer_id.to_string(),
                                global_node_signature: signature.clone(),
                                origin_signature: origin_signature.clone(),
                                origin_pubkey: {
                                    use base64::{engine::general_purpose::STANDARD, Engine};
                                    hex::decode(&origin_pk_str)
                                        .ok()
                                        .map(|bytes| STANDARD.encode(&bytes))
                                },
                                registered_at: synvoid_utils::safe_unix_timestamp(),
                                expires_at: synvoid_utils::safe_unix_timestamp() + 300,
                            };
                            if let Ok(bytes) = serde_json::to_vec(&verified_upstream) {
                                let ttl = 300;
                                record_store.store_and_announce(key_str.to_string(), bytes, ttl);
                                tracing::debug!(
                                    "Stored verified upstream {} in DHT (action: {:?})",
                                    upstream_id_str,
                                    action
                                );
                            }
                        }
                    }
                    AnnounceAction::Remove => {
                        tracing::debug!(
                            "Upstream {} announced removed (expires via TTL)",
                            upstream_id_str
                        );
                    }
                }
            }
            MeshMessage::DhtRecordPush {
                request_id,
                records,
                hop_count,
                seen_node_ids,
                timestamp,
                nonce,
                signature,
                signer_public_key,
            } => {
                if self
                    .validate_peer_node_id_binding(peer_id, peer_id)
                    .is_err()
                {
                    tracing::debug!(
                        "DhtRecordPush from {} rejected: peer binding failed",
                        peer_id
                    );
                    return Ok(());
                }

                if !crate::dht::signed::validate_message_timestamp(timestamp) {
                    tracing::warn!(
                        "DhtRecordPush from {} rejected: timestamp too old or far in future",
                        peer_id
                    );
                    return Ok(());
                }

                let require_signed = self
                    .config
                    .dht
                    .as_ref()
                    .map(|d| d.require_signed_record_push)
                    .unwrap_or(true);
                let compat_until = self
                    .config
                    .dht
                    .as_ref()
                    .and_then(|d| d.unsigned_record_push_compat_until_unix);
                let now_unix = synvoid_utils::safe_unix_timestamp();
                let has_auth = !signature.is_empty()
                    && signer_public_key.as_ref().is_some_and(|s| !s.is_empty())
                    && !nonce.is_empty();
                if !has_auth {
                    let compat_active = compat_until.is_some_and(|deadline| now_unix < deadline);
                    if require_signed && !compat_active {
                        tracing::warn!(
                            "DhtRecordPush from {} rejected: missing envelope signature/nonce (require_signed_record_push={}, compat_until={:?}, now={})",
                            peer_id,
                            require_signed,
                            compat_until,
                            now_unix
                        );
                        return Ok(());
                    }
                } else {
                    if !crate::dht::signed::verify_dht_record_push_envelope_signature_bytes(
                        &request_id,
                        peer_id,
                        &records,
                        hop_count,
                        &nonce,
                        timestamp,
                        &signature,
                        signer_public_key.as_deref(),
                    ) {
                        tracing::warn!(
                            "DhtRecordPush from {} rejected: invalid envelope signature",
                            peer_id
                        );
                        return Ok(());
                    }

                    if !self.verify_signer_node_binding(
                        peer_id,
                        signer_public_key.as_deref(),
                        "DhtRecordPush",
                    ) {
                        return Ok(());
                    }
                }

                let replay_state = self
                    .peer_connections
                    .get(peer_id)
                    .map(|conn| conn.replay_protection.clone());
                if let Some(replay_protection) = replay_state {
                    let replay_result = replay_protection
                        .write()
                        .await
                        .check_and_add(&nonce, timestamp);
                    if !matches!(replay_result, crate::protocol::ReplayResult::Valid) {
                        tracing::warn!(
                            "DhtRecordPush from {} rejected: replay protection {}",
                            peer_id,
                            match replay_result {
                                crate::protocol::ReplayResult::FutureTimestamp =>
                                    "future_timestamp",
                                crate::protocol::ReplayResult::ExpiredTimestamp =>
                                    "expired_timestamp",
                                crate::protocol::ReplayResult::ReplayDetected => "replay_detected",
                                crate::protocol::ReplayResult::Valid => "valid",
                            }
                        );
                        return Ok(());
                    }
                }

                if let Some(ref record_store) = self.record_store {
                    if seen_node_ids.contains(&self.config.node_id()) {
                        tracing::debug!("DhtRecordPush already seen by this node, skipping");
                        return Ok(());
                    }

                    let reputation = self
                        .topology
                        .get_peer_audit_reputation(peer_id)
                        .await
                        .map(|rep| (rep * 100.0) as i64)
                        .unwrap_or(0);

                    let ingress_ctx = crate::dht::signed::DhtRecordIngressContext::new_remote(
                        peer_id.to_string(),
                        peer_id.to_string(),
                        crate::dht::signed::SourceClassification::Unknown,
                        crate::dht::signed::IngressPath::Push,
                    )
                    .with_policy_context(record_store.ingress_policy_context());

                    for record in records.iter() {
                        record_store.store_record_from_ingress(
                            record.clone(),
                            &ingress_ctx,
                            reputation,
                        );
                        record_store.init_propagation_state(&record.key);
                    }
                    record_store.compute_merkle_tree();

                    if hop_count < 5 {
                        let ack = MeshMessage::DhtRecordPushAck {
                            request_id: format!("{}-ack", request_id).into(),
                            original_request_id: request_id.clone(),
                            node_id: self.config.node_id().into(),
                            accepted: true,
                            missing_keys: Vec::new(),
                            timestamp: MeshMessage::generate_timestamp(),
                        };
                        let _ = self.send_datagram_to_peer(peer_id, &ack).await;
                    }
                }
            }
            _ => {
                tracing::trace!(
                    "Received unhandled datagram type from {}: {:?}",
                    peer_id,
                    msg
                );
            }
        }

        Ok(())
    }

    pub(crate) async fn handle_keepalive_datagram(&self, peer_id: &str) {
        tracing::trace!("Received keepalive from {}", peer_id);
        if let Some(mut peer) = self.peer_connections.get_mut(peer_id) {
            peer.last_seen = Instant::now();
        }
    }

    pub(crate) fn validate_peer_node_id_binding(
        &self,
        peer_id: &str,
        source_node_id: &str,
    ) -> Result<(), ()> {
        // Existing in-memory check
        if let Some(peer) = self.peer_connections.get(peer_id) {
            if peer.node_id != source_node_id {
                tracing::warn!(
                    "Node ID mismatch: peer_id={}, expected node_id={}, got source_node_id={}",
                    peer_id,
                    peer.node_id,
                    source_node_id
                );
                return Err(());
            }
        }

        // MESH-14: If require_pki_binding enabled, verify against cert chain
        if self.config.tls.require_pki_binding {
            let cert_mgr = self.cert_manager.read();
            if let Some(cert_binding) = cert_mgr.get_cert_binding(source_node_id) {
                // Verify the TLS peer's public key matches the certified key
                if let Some(peer_pubkey) = cert_mgr.get_global_node_key(source_node_id) {
                    if peer_pubkey != cert_binding.certified_public_key {
                        tracing::warn!(
                            "PKI binding check failed: peer {} public key does not match cert binding for {}",
                            peer_id, source_node_id
                        );
                        return Err(());
                    }
                } else {
                    tracing::warn!(
                        "PKI binding check failed: no public key registered for node {}",
                        source_node_id
                    );
                    return Err(());
                }
            } else {
                tracing::warn!(
                    "PKI binding check failed: no cert binding for node {}",
                    source_node_id
                );
                return Err(());
            }
        }

        Ok(())
    }

    pub(crate) async fn handle_lookup_request(
        &self,
        from_peer: &str,
        request_id: &str,
        key: &str,
        lookup_type: crate::protocol::LookupType,
    ) {
        tracing::debug!(
            "Received lookup request: {} for key {} from {}",
            request_id,
            key,
            from_peer
        );

        let value = match lookup_type {
            crate::protocol::LookupType::Route => {
                if let Some((provider, hops)) = self.topology.get_cached_route(key).await {
                    Some(format!("{}:{}", provider, hops).into_bytes())
                } else {
                    self.topology
                        .get_upstream_info(key)
                        .await
                        .map(|_local| format!("local:{}", self.config.node_id()).into_bytes())
                }
            }
            crate::protocol::LookupType::Peer => {
                if let Some(peer) = self.topology.get_peer(key).await {
                    Some(peer.address.clone().into_bytes())
                } else {
                    None
                }
            }
            crate::protocol::LookupType::KeyValue
            | crate::protocol::LookupType::Certificate
            | crate::protocol::LookupType::Config => None,
        };

        let response = MeshMessage::LookupResponse {
            request_id: request_id.into(),
            key: key.into(),
            value: value.clone(),
            found: value.is_some(),
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!("Failed to send lookup response to {}: {}", from_peer, e);
        }
    }

    pub(crate) async fn handle_lookup_batch_request(
        &self,
        from_peer: &str,
        request_id: &str,
        keys: &[crate::protocol::ArcStr],
    ) {
        if keys.len() > MAX_BATCH_KEYS {
            tracing::warn!(
                "Batch lookup request from {} rejected: {} keys exceeds limit of {}",
                from_peer,
                keys.len(),
                MAX_BATCH_KEYS
            );
            let response = MeshMessage::Error {
                code: 400,
                message: format!("Too many keys: {} (max {})", keys.len(), MAX_BATCH_KEYS).into(),
            };
            let _ = self.send_datagram_to_peer(from_peer, &response).await;
            return;
        }

        tracing::debug!(
            "Received batch lookup request: {} for {} keys from {}",
            request_id,
            keys.len(),
            from_peer
        );

        let mut results = HashMap::new();

        for key in keys {
            if let Some((provider, _)) = self.topology.get_cached_route(key).await {
                results.insert(
                    key.to_string(),
                    Some(format!("{}:{}", provider, 0).into_bytes()),
                );
            } else if self.topology.has_local_upstream(key).await {
                results.insert(
                    key.to_string(),
                    Some(format!("local:{}", self.config.node_id()).into_bytes()),
                );
            } else {
                results.insert(key.to_string(), None);
            }
        }

        let response = MeshMessage::LookupBatchResponse {
            request_id: request_id.into(),
            results,
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!(
                "Failed to send batch lookup response to {}: {}",
                from_peer,
                e
            );
        }
    }

    pub(crate) async fn handle_peer_health_check(
        &self,
        from_peer: &str,
        target_peer_id: &str,
        _timestamp: u64,
    ) {
        tracing::trace!(
            "Received health check request for {} from {}",
            target_peer_id,
            from_peer
        );

        let status = if let Some(peer) = self.topology.get_peer(target_peer_id).await {
            if peer.is_healthy() {
                crate::protocol::HealthStatus::Healthy
            } else {
                crate::protocol::HealthStatus::Degraded
            }
        } else {
            crate::protocol::HealthStatus::Unknown
        };

        let response = MeshMessage::PeerHealthResponse {
            peer_id: target_peer_id.into(),
            status,
            latency_ms: None,
            timestamp: synvoid_utils::safe_unix_timestamp(),
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!("Failed to send health response to {}: {}", from_peer, e);
        }
    }

    pub(crate) async fn handle_peer_announce(
        &self,
        from_peer: &str,
        node_id: &str,
        address: &str,
        role: crate::config::MeshNodeRole,
        capabilities: &crate::protocol::MeshCapabilities,
        _announced_at: u64,
    ) {
        tracing::debug!(
            "Received peer announce: {} ({}) from {}",
            node_id,
            address,
            from_peer
        );

        self.topology
            .add_peer(
                crate::protocol::MeshPeerInfo {
                    node_id: node_id.to_string(),
                    address: address.to_string(),
                    role,
                    capabilities: capabilities.clone(),
                    is_global: role.is_global(),
                    latency_ms: None,
                    upstreams: vec![],
                    is_trusted: role.is_global(),
                    quic_port: None,
                    wireguard_port: None,
                    advertised_port: None,
                    dns_serving_healthy: false,
                },
                PeerStatus::Healthy,
            )
            .await;

        self.update_threat_intel_global_nodes().await;
    }

    pub(crate) async fn handle_peer_gone(&self, from_peer: &str, node_id: &str, reason: &str) {
        tracing::info!(
            "Peer {} announced departure from {}: {}",
            node_id,
            from_peer,
            reason
        );

        let was_global = {
            if let Some(peer) = self.topology.get_peer(node_id).await {
                peer.role.is_global()
            } else {
                false
            }
        };

        self.topology.remove_peer(node_id).await;

        if was_global {
            tracing::info!("Global node {} departed, triggering DHT rebalance", node_id);
            if let Some(ref record_store) = self.record_store {
                record_store.rebalance_after_departure(node_id).await;
            }
        }

        self.update_threat_intel_global_nodes().await;
    }

    pub(crate) async fn handle_site_config_sync(
        &self,
        _from_peer: &str,
        _request_id: &str,
        site_id: &str,
        config_version: u64,
        config_json: &str,
        timestamp: u64,
        source_node_id: &str,
        signature: &[u8],
        signer_public_key: Option<&str>,
        proxy_cache_preferences: Option<&crate::protocol::ProxyCachePreferences>,
    ) {
        tracing::info!(
            "Received site config sync for site {} version {} from node {}",
            site_id,
            config_version,
            source_node_id
        );

        let is_valid_origin = {
            let origins = self.topology.find_all_origins_for_site(site_id).await;
            origins.contains(&source_node_id.to_string())
        };

        if !is_valid_origin {
            tracing::warn!(
                "Site config sync from {} who is not an origin for site {} - rejecting",
                source_node_id,
                site_id
            );
            return;
        }

        if signature.is_empty() {
            tracing::warn!(
                "Site config sync from {} has no signature - rejecting",
                source_node_id
            );
            return;
        }

        let public_key = match signer_public_key {
            Some(pk) => pk,
            None => {
                tracing::warn!(
                    "Site config sync from {} has signature but no public key - rejecting",
                    source_node_id
                );
                return;
            }
        };

        let sign_data = format!(
            "{}:{}:{}:{}",
            site_id,
            config_version,
            config_json.len(),
            timestamp
        );

        let verified =
            match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, public_key) {
                Ok(pubkey_bytes) => {
                    let result = synvoid_integrity::signing::verify_ed25519_raw(
                        &pubkey_bytes,
                        &sign_data,
                        signature,
                    );
                    if result {
                        tracing::info!(
                            "Site config sync signature verified for site {} from {}",
                            site_id,
                            source_node_id
                        );
                    } else {
                        tracing::warn!(
                            "Site config sync signature verification FAILED for site {} from {}",
                            site_id,
                            source_node_id
                        );
                    }
                    result
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to decode public key for site config sync from {}: {}",
                        source_node_id,
                        e
                    );
                    false
                }
            };

        if !verified {
            tracing::warn!(
                "Rejected site config sync from {} due to invalid signature",
                source_node_id
            );
            return;
        }

        let tx_to_send = {
            let tx_option = self.site_config_sync_tx.read();
            tx_option.clone()
        };

        if let Some(tx) = tx_to_send {
            let _ = tx
                .send((
                    site_id.to_string(),
                    config_json.to_string(),
                    proxy_cache_preferences.cloned(),
                ))
                .await;
            tracing::debug!("Sent site config sync to callback handler");
        } else {
            tracing::warn!("No site config sync callback configured");
        }
    }

    pub(crate) async fn handle_topology_sync_request(
        &self,
        from_peer: &str,
        request_id: &str,
        from_version: u64,
    ) {
        tracing::debug!(
            "Received topology sync request: {} from version {} from {}",
            request_id,
            from_version,
            from_peer
        );

        let peers = self.topology.get_all_peers().await;
        let upstreams = self.topology.get_upstream_owners().await;
        let version = self.topology.get_topology_version().await;

        let response = MeshMessage::TopologySyncResponse {
            request_id: request_id.into(),
            peers: peers
                .into_iter()
                .map(|p| crate::protocol::MeshPeerInfo {
                    node_id: p.node_id,
                    address: p.address,
                    role: p.role,
                    capabilities: p.capabilities,
                    is_global: p.is_global,
                    latency_ms: p.latency_ms,
                    upstreams: p.upstreams.into_iter().collect(),
                    is_trusted: p.role.is_global(),
                    quic_port: p.quic_port,
                    wireguard_port: p.wireguard_port,
                    advertised_port: p.advertised_port,
                    dns_serving_healthy: false,
                })
                .collect(),
            upstreams,
            version,
            is_delta: false,
            removed_peers: vec![],
            removed_upstreams: vec![],
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!(
                "Failed to send topology sync response to {}: {}",
                from_peer,
                e
            );
        }
    }

    pub(crate) async fn handle_seed_list_request(
        &self,
        from_peer: &str,
        _node_id: &str,
        request_full_mesh: bool,
    ) {
        tracing::debug!(
            "Received seed list request from {} (full_mesh: {})",
            from_peer,
            request_full_mesh
        );

        let response = if self.topology.is_global() {
            let global_nodes = self.topology.get_seeded_global_nodes().await;
            let edge_nodes = if request_full_mesh {
                self.topology.get_seeded_edge_nodes().await
            } else {
                Vec::new()
            };

            MeshMessage::SeedListResponse {
                global_nodes,
                edge_nodes,
                version: 1,
                genesis_org_id: Some(self.config.node_identity.genesis_org_id().into()),
            }
        } else {
            MeshMessage::Error {
                code: 403,
                message: "Only global nodes can serve seed lists".into(),
            }
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!("Failed to send seed list response to {}: {}", from_peer, e);
        }
    }

    pub(crate) async fn handle_peer_load_report(
        &self,
        node_id: &str,
        active_connections: u32,
        cpu_load_percent: f32,
        memory_percent: f32,
        _requests_per_second: f32,
    ) {
        tracing::trace!(
            "Received load report from {}: conns={}, cpu={}%, mem={}%",
            node_id,
            active_connections,
            cpu_load_percent,
            memory_percent
        );

        let load_score = ((cpu_load_percent as f64 / 100.0) * 0.6
            + (memory_percent as f64 / 100.0) * 0.4)
            .clamp(0.0, 1.0);

        let mut scores = self.topology.peer_scores().write().await;
        if let Some(score) = scores.get_mut(node_id) {
            score.load_score = 1.0 - load_score;
            score.last_updated = synvoid_utils::safe_unix_timestamp();
        } else {
            scores.insert(
                node_id.to_string(),
                crate::topology::PeerScore {
                    node_id: node_id.to_string(),
                    latency_score: 0.5,
                    stability_score: 0.5,
                    load_score: 1.0 - load_score,
                    traffic_score: 0.0,
                    upstream_score: 0.0,
                    total_score: 0.5,
                    last_updated: synvoid_utils::safe_unix_timestamp(),
                },
            );
        }
    }

    pub(crate) async fn handle_peer_load_update(&self, node_id: &str, load_score: f64) {
        tracing::trace!(
            "Received load update from {}: score={}",
            node_id,
            load_score
        );

        let mut scores = self.topology.peer_scores().write().await;
        if let Some(score) = scores.get_mut(node_id) {
            score.load_score = 1.0 - load_score;
            score.last_updated = synvoid_utils::safe_unix_timestamp();
        }
    }

    pub(crate) async fn handle_route_usage_report(
        &self,
        upstream_id: &str,
        request_count: u64,
        bytes_transferred: u64,
    ) {
        tracing::trace!(
            "Received route usage report for {}: {} requests, {} bytes",
            upstream_id,
            request_count,
            bytes_transferred
        );

        self.topology
            .record_route_usage(upstream_id.to_string(), bytes_transferred)
            .await;

        if let Some(score) = self
            .topology
            .peer_scores()
            .write()
            .await
            .get_mut(upstream_id)
        {
            let usage = self.topology.route_usage().read().await;
            score.traffic_score = usage.get_upstream_score(upstream_id);
        }
    }

    pub(crate) async fn handle_upstream_blocked(
        &self,
        mesh_identifier: &str,
        service_id: &str,
        blocked_until: u64,
        reason: &str,
        origin_node_id: &str,
    ) {
        // blocked_until is Unix timestamp when block expires
        let now_unix = synvoid_utils::safe_unix_timestamp();

        // Validate: block timestamp not unreasonably far in the future
        let max_allowed = now_unix + MAX_BLOCK_DURATION_SECS;
        if blocked_until > max_allowed {
            tracing::warn!(
                "Received block with timestamp too far in future: {} (current: {}, max: {}). Ignoring.",
                blocked_until, now_unix, max_allowed
            );
            return;
        }

        // Calculate remaining duration, skip if already expired
        let remaining_secs = blocked_until.saturating_sub(now_unix);
        if remaining_secs == 0 {
            tracing::debug!(
                "Received expired block notification for {}.{}, ignoring",
                mesh_identifier,
                service_id
            );
            return;
        }

        let blocked_instant = Instant::now() + Duration::from_secs(remaining_secs);

        tracing::info!(
            "Received upstream blocked notification: {}.{} blocked for {}s (reason: {})",
            mesh_identifier,
            service_id,
            remaining_secs,
            reason
        );

        self.topology
            .block_upstream(
                mesh_identifier,
                service_id,
                blocked_instant,
                reason,
                origin_node_id,
            )
            .await;
    }

    pub(crate) async fn handle_bandwidth_report(
        &self,
        upstream_id: &str,
        bytes_sent: u64,
        bytes_received: u64,
        request_count: u64,
        interval_secs: u64,
        _timestamp: u64,
    ) {
        tracing::trace!(
            "Received bandwidth report for {}: {}B sent, {}B recv, {} reqs in {}s",
            upstream_id,
            bytes_sent,
            bytes_received,
            request_count,
            interval_secs
        );

        self.topology
            .record_route_usage(upstream_id.to_string(), bytes_sent + bytes_received)
            .await;
    }

    pub(crate) async fn handle_upstream_verification_query(
        &self,
        peer_id: &str,
        request_id: &str,
        upstream_id: &str,
        querying_node_id: &str,
        provider_node_id: &str,
    ) {
        tracing::info!(
            "Received upstream verification query for {} (provider: {}) from node {} (request_id: {})",
            upstream_id,
            provider_node_id,
            querying_node_id,
            request_id
        );

        let upstream_info = self.topology.get_upstream_info(upstream_id).await;

        let (verified, upstream_url) = match upstream_info {
            Some(info) => {
                let url = info.upstream_url.clone();
                match self.verify_upstream_reachability(&url).await {
                    Ok(_) => (true, url),
                    Err(e) => {
                        tracing::warn!("Upstream {} verification failed: {}", upstream_id, e);
                        (false, url)
                    }
                }
            }
            None => {
                tracing::warn!("Upstream {} not found for verification", upstream_id);
                (false, String::new())
            }
        };

        let timestamp = synvoid_utils::safe_unix_timestamp();
        let signable_content = format!(
            "{}:{}:{}:{}:{}:{}",
            request_id, upstream_id, verified, querying_node_id, timestamp, provider_node_id
        );
        let global_node_signature = self
            .mesh_signer
            .as_ref()
            .map(|signer| signer.sign(signable_content.as_bytes()));

        let response = MeshMessage::UpstreamVerificationResponse {
            request_id: request_id.into(),
            upstream_id: upstream_id.into(),
            verified,
            global_node_id: querying_node_id.into(),
            global_node_signature,
            upstream_url: upstream_url.into(),
            org_id: None,
            timestamp,
            provider_node_id: provider_node_id.into(),
        };

        if let Err(e) = self.send_message_to_peer(peer_id, &response).await {
            tracing::warn!("Failed to send verification response to {}: {}", peer_id, e);
        }
    }

    async fn verify_upstream_reachability(&self, upstream_url: &str) -> Result<(), String> {
        use std::time::Duration;

        let url = url::Url::parse(upstream_url).map_err(|e| format!("Invalid URL: {}", e))?;

        let host = url.host_str().ok_or("No host in URL")?;
        let port = url.port().unwrap_or(80);
        let addr = format!("{}:{}", host, port);

        let connect_timeout = Duration::from_secs(5);
        let _read_timeout = Duration::from_secs(5);

        match tokio::time::timeout(connect_timeout, tokio::net::TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(format!("Connection failed: {}", e)),
            Err(_) => Err("Connection timed out".to_string()),
        }
    }

    pub(crate) async fn handle_upstream_verification_response(
        &self,
        peer_id: &str,
        request_id: &str,
        upstream_id: &str,
        verified: bool,
        _global_node_id: &str,
        provider_node_id: &str,
    ) {
        tracing::info!(
            "Received verification response for {} (provider: {}) from node {}: verified={} (request_id: {})",
            upstream_id,
            provider_node_id,
            peer_id,
            verified,
            request_id
        );

        if let Some(ref verification_mgr) = self.get_verification_manager() {
            verification_mgr.record_verification_result(
                upstream_id,
                provider_node_id,
                peer_id,
                verified,
            );
        }
    }

    pub(crate) fn get_verification_manager(
        &self,
    ) -> Option<Arc<crate::verification::VerificationTaskManager>> {
        self.verification_manager.read().clone()
    }

    pub(crate) async fn handle_upstream_ownership_challenge(
        &self,
        _peer_id: &str,
        request_id: &str,
        upstream_id: &str,
        challenge_type: &crate::protocol::OwnershipChallengeType,
        challenge_token: &str,
        global_node_id: &str,
        timestamp: u64,
    ) {
        tracing::info!(
            "Received upstream ownership challenge for {} from global node {} (request_id: {})",
            upstream_id,
            global_node_id,
            request_id
        );

        if let Err(e) = self
            .verify_challenge_signature(request_id, global_node_id, timestamp, challenge_token)
            .await
        {
            tracing::warn!(
                "Challenge signature verification failed from global node {}: {}",
                global_node_id,
                e
            );
            return;
        }

        tracing::debug!(
            "Challenge signature verified for global node {}",
            global_node_id
        );

        match challenge_type {
            #[cfg(feature = "dns")]
            crate::protocol::OwnershipChallengeType::Dns01 {
                domain,
                txt_record_name,
                txt_record_value,
            } => {
                tracing::info!(
                    "DNS-01 challenge for domain {}: storing TXT record {} = {} for mesh DNS serving",
                    domain,
                    txt_record_name,
                    txt_record_value
                );

                self.store_dns01_challenge(
                    txt_record_name.clone(),
                    domain.clone(),
                    txt_record_value.clone(),
                    upstream_id.to_string(),
                );

                let proof = crate::protocol::OwnershipChallengeProof::Dns01 {
                    txt_record_value: txt_record_value.clone(),
                };

                let response = MeshMessage::UpstreamChallengeProof {
                    request_id: request_id.into(),
                    upstream_id: upstream_id.into(),
                    challenge_proof: proof,
                    origin_node_id: self.config.node_id().into(),
                    timestamp: synvoid_utils::safe_unix_timestamp(),
                };

                if let Err(e) = self.send_datagram_to_peer(peer_id, &response).await {
                    tracing::warn!("Failed to send challenge proof to {}: {}", peer_id, e);
                }
            }
            #[cfg(feature = "dns")]
            crate::protocol::OwnershipChallengeType::Http01 {
                token,
                key_authorization,
            } => {
                tracing::info!(
                    "HTTP-01 challenge: storing key authorization for token {} at /.well-known/synvoid-challenge/{}",
                    token,
                    token
                );

                self.store_http01_challenge(
                    token.clone(),
                    key_authorization.clone(),
                    upstream_id.to_string(),
                );

                let proof = crate::protocol::OwnershipChallengeProof::Http01 {
                    key_authorization: key_authorization.clone(),
                };

                let response = MeshMessage::UpstreamChallengeProof {
                    request_id: request_id.into(),
                    upstream_id: upstream_id.into(),
                    challenge_proof: proof,
                    origin_node_id: self.config.node_id().into(),
                    timestamp: synvoid_utils::safe_unix_timestamp(),
                };

                if let Err(e) = self.send_datagram_to_peer(peer_id, &response).await {
                    tracing::warn!("Failed to send challenge proof to {}: {}", peer_id, e);
                }
            }
            #[cfg(not(feature = "dns"))]
            _ => {
                tracing::warn!("Ownership challenge type not available without dns feature");
            }
        }
    }

    async fn verify_challenge_signature(
        &self,
        request_id: &str,
        global_node_id: &str,
        timestamp: u64,
        challenge_token: &str,
    ) -> Result<(), String> {
        if challenge_token.is_empty() {
            return Err("Empty challenge token".to_string());
        }

        if let Some(signature_hex) = challenge_token.strip_prefix("signed:") {
            let signature_bytes =
                hex::decode(signature_hex).map_err(|e| format!("Invalid signature hex: {}", e))?;

            if signature_bytes.len() != 64 {
                return Err(format!(
                    "Invalid signature length: expected 64, got {}",
                    signature_bytes.len()
                ));
            }

            let cert_manager = self.cert_manager.read();
            let public_key_bytes = cert_manager
                .get_global_node_key(global_node_id)
                .ok_or_else(|| format!("No public key found for global node {}", global_node_id))?;

            let signable = format!("{}:{}:{}", request_id, global_node_id, timestamp);

            if crate::cert::verify_ed25519(&signable, &signature_bytes, &public_key_bytes) {
                tracing::debug!(
                    "Challenge signature verified for global node {}",
                    global_node_id
                );
                Ok(())
            } else {
                Err(format!(
                    "Signature verification failed for global node {}",
                    global_node_id
                ))
            }
        } else {
            Err("Unsupported challenge token format - expected 'signed:' prefix".to_string())
        }
    }

    pub(crate) async fn send_load_report_to_peers(&self) {
        let active_connections = crate::stubs::admin_stub::get_current_connections() as u32;
        let (cpu_load_percent, memory_percent) = crate::stubs::admin_stub::get_cpu_memory_usage();
        let requests_per_second = 0.0_f32;

        let load_report = MeshMessage::PeerLoadReport {
            node_id: self.config.node_id().into(),
            active_connections,
            cpu_load_percent,
            memory_percent,
            requests_per_second,
        };

        let peer_ids: Vec<String> = self
            .peer_connections
            .iter()
            .map(|e| e.key().clone())
            .collect();

        for peer_id in peer_ids {
            if let Err(e) = self.send_datagram_to_peer(&peer_id, &load_report).await {
                tracing::debug!("Failed to send load report to {}: {}", peer_id, e);
            }
        }

        tracing::trace!(
            "Sent load report to peers: conns={}, cpu={}%, mem={}%",
            active_connections,
            cpu_load_percent,
            memory_percent
        );
    }

    pub(crate) async fn peer_message_loop(
        &self,
        session_id: String,
        peer_node_id: String,
        connection: Connection,
        topology: Arc<MeshTopology>,
        generation: u64,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> crate::lifecycle::PeerSessionExit {
        use tokio::task::JoinSet;

        let mut stream_handlers: JoinSet<Result<(), MeshTransportError>> = JoinSet::new();
        let max_concurrent_streams = self.config.connection.max_concurrent_peer_streams;
        let peer_message_read_timeout = self.peer_message_read_timeout();
        let peer_stream_total_timeout = self.peer_stream_total_timeout();

        let topology_for_loop = topology.clone();
        let peer_node_id_for_loop = peer_node_id.clone();

        // Track the session exit reason across all paths. Cooperative
        // cancellation wins over connection close (Phase 7-8, Phase 9).
        let mut cancelled = false;

        loop {
            tokio::select! {
                biased;
                // Phase 6-7: Cooperative session cancellation branch.
                // When the parent rollback/recovery/shutdown code calls
                // `task.shutdown_tx.send(true)`, we stop accepting new
                // streams and proceed into the normal drain path before
                // parent return.
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::debug!(
                            "Peer session {} received cooperative shutdown signal",
                            session_id
                        );
                        cancelled = true;
                        break;
                    }
                }
                result = connection.accept_bi() => {
                    match result {
                        Ok((mut send_stream, mut recv_stream)) => {
                            // Phase 25: Capacity limit — reject streams beyond the bound
                            if stream_handlers.len() >= max_concurrent_streams {
                                tracing::warn!(
                                    "Peer {} session {}: stream handler capacity reached ({}/{}), rejecting stream",
                                    peer_node_id, session_id, stream_handlers.len(), max_concurrent_streams
                                );
                                drop(send_stream);
                                drop(recv_stream);
                                continue;
                            }

                            let transport = self.clone();
                            let topo = topology_for_loop.clone();
                            let pid = peer_node_id_for_loop.clone();
                            let read_timeout = peer_message_read_timeout;
                            let total_timeout = peer_stream_total_timeout;

                            // Iteration 77, Phase 5: read timeout is passed
                            // into handle_peer_message for actual reads only.
                            // Optional total timeout wraps the entire handler.
                            stream_handlers.spawn(async move {
                                let handler = transport.handle_peer_message(
                                    &mut send_stream,
                                    &mut recv_stream,
                                    &topo,
                                    pid,
                                    read_timeout,
                                );

                                if let Some(total) = total_timeout {
                                    tokio::time::timeout(total, handler)
                                        .await
                                        .unwrap_or(Err(MeshTransportError::Timeout))
                                } else {
                                    handler.await
                                }
                            });
                        }
                        Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                            tracing::info!("Peer {} disconnected", peer_node_id);
                            break;
                        }
                        Err(e) => {
                            tracing::warn!("Peer {} connection error: {}", peer_node_id, e);
                            break;
                        }
                    }
                }
                // Phase 24: Reap completed handlers during the session lifetime
                Some(result) = stream_handlers.join_next(), if !stream_handlers.is_empty() => {
                    match result {
                        Ok(Ok(())) => {
                            // Clean handler completion — no action needed
                        }
                        Ok(Err(e)) => {
                            tracing::debug!(
                                "Peer session {} stream handler error: {}",
                                session_id, e
                            );
                        }
                        Err(join_error) => {
                            if join_error.is_panic() {
                                tracing::warn!(
                                    "Peer session {} stream handler panicked: {}",
                                    session_id, join_error
                                );
                            }
                            // Cancelled during shutdown — expected
                        }
                    }
                }
                _ = connection.closed() => {
                    tracing::info!("Peer {} connection closed", peer_node_id);
                    break;
                }
            }
        }

        // Phase 27 / Phase 8: Centralized finalization — every exit path
        // (connection close, error, cooperative cancellation) passes through
        // the same child cleanup. The drain timeout is bounded by the
        // remaining budget passed in via `drain_budget`.
        let drain_budget =
            Duration::from_secs(self.config.connection.peer_stream_drain_timeout_secs);
        let drain_report = drain_peer_stream_handlers(&mut stream_handlers, drain_budget).await;

        tracing::debug!(
            "Peer session {} stream drain: drained={}, aborted={}, failed={}",
            session_id,
            drain_report.drained,
            drain_report.aborted,
            drain_report.failed
        );

        // Phase 23: Aggregate stream handler drain stats for shutdown report.
        self.aggregate_handler_drained
            .fetch_add(drain_report.drained, Ordering::Relaxed);
        self.aggregate_handler_aborted
            .fetch_add(drain_report.aborted, Ordering::Relaxed);
        self.aggregate_handler_failed
            .fetch_add(drain_report.failed, Ordering::Relaxed);

        // Update topology status
        topology
            .update_peer_status(&peer_node_id, PeerStatus::Disconnected)
            .await;

        // Phase 7-8: Emit the exit reason that reflects which path the
        // session took. Cooperative cancellation takes precedence over
        // connection close when both are present. Phase 22: child
        // stream handler failures are promoted to ChildTaskFailed.
        let reason = if drain_report.failed > 0 {
            crate::lifecycle::PeerSessionExitReason::ChildTaskFailed(format!(
                "{} handler(s) panicked or errored during drain",
                drain_report.failed
            ))
        } else if cancelled {
            crate::lifecycle::PeerSessionExitReason::Cancelled
        } else {
            crate::lifecycle::PeerSessionExitReason::ConnectionClosed
        };

        crate::lifecycle::PeerSessionExit {
            session_id,
            node_id: peer_node_id,
            reason,
            generation,
            stream_drain: drain_report,
        }
    }

    pub(crate) async fn handle_peer_message(
        &self,
        send_stream: &mut SendStream,
        recv_stream: &mut RecvStream,
        topology: &MeshTopology,
        peer_node_id: String,
        read_timeout: Duration,
    ) -> Result<(), MeshTransportError> {
        let mut first_byte = [0u8; 1];
        read_exact_with_timeout(recv_stream, &mut first_byte, read_timeout).await?;

        let http_methods = [
            b'G', // GET
            b'P', // POST, PUT, PATCH
            b'H', // HTTP/
            b'D', // DELETE
            b'O', // OPTIONS
            b'T', // TRACE
            b'C', // CONNECT
        ];

        if http_methods.contains(&first_byte[0]) {
            // Iteration 78: HTTP-over-mesh framing with body support.
            // One QUIC bidirectional stream carries exactly one HTTP/1.x
            // request and one HTTP/1.x response.
            let total_timeout =
                Duration::from_secs(self.config.connection.peer_http_header_total_timeout_secs);

            let head = read_http_request_head(
                recv_stream,
                first_byte[0],
                read_timeout,
                total_timeout,
                self.config.connection.max_peer_http_header_bytes,
            )
            .await?;

            // Reject CONNECT and upgrade requests — not supported.
            let mut request_bytes = head.header_bytes;
            let parsed_meta = parse_http_request_meta(&request_bytes)?;
            if parsed_meta.method.eq_ignore_ascii_case("CONNECT") {
                let resp = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                send_stream
                    .write_all(resp)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                let _ = send_stream.finish();
                return Ok(());
            }
            if parsed_meta.upgrade_requested || parsed_meta.connection_upgrade {
                let resp = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                send_stream
                    .write_all(resp)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                let _ = send_stream.finish();
                return Ok(());
            }

            // Determine body kind and read body if present.
            let body_kind = match (head.content_length, head.chunked) {
                (Some(len), false) => HttpBodyKind::ContentLength(len),
                (None, true) => HttpBodyKind::Chunked,
                (None, false) => HttpBodyKind::None,
                // parse_http_body_framing already rejects (Some, true).
                _ => unreachable!(),
            };

            match body_kind {
                HttpBodyKind::None => {
                    if !head.body_prefix.is_empty() {
                        let resp = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        send_stream
                            .write_all(resp)
                            .await
                            .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                        let _ = send_stream.finish();
                        return Ok(());
                    }
                }
                HttpBodyKind::ContentLength(content_length) => {
                    let max_body = self.config.connection.max_peer_http_body_bytes;
                    if content_length > max_body {
                        let resp = b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        send_stream
                            .write_all(resp)
                            .await
                            .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                        let _ = send_stream.finish();
                        return Ok(());
                    }

                    let body_total_timeout = Duration::from_secs(
                        self.config.connection.peer_http_body_total_timeout_secs,
                    );
                    let body = read_fixed_http_body(
                        recv_stream,
                        head.body_prefix,
                        content_length,
                        read_timeout,
                        body_total_timeout,
                    )
                    .await?;
                    request_bytes.extend_from_slice(&body);
                }
                HttpBodyKind::Chunked => {
                    // Explicitly reject chunked requests for now.
                    let resp = b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    send_stream
                        .write_all(resp)
                        .await
                        .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                    let _ = send_stream.finish();
                    return Ok(());
                }
            }

            return self
                .handle_http_proxy_stream(
                    &parsed_meta,
                    request_bytes,
                    send_stream,
                    topology,
                    peer_node_id,
                )
                .await;
        }

        let mut len_buf = [0u8; 3];
        read_exact_with_timeout(recv_stream, &mut len_buf, read_timeout).await?;

        let full_len_buf = [first_byte[0], len_buf[0], len_buf[1], len_buf[2]];
        let len = u32::from_be_bytes(full_len_buf) as usize;
        if len > MAX_MESSAGE_SIZE {
            return Err(MeshTransportError::ReceiveFailed(format!(
                "Message too large: {} bytes (max {})",
                len, MAX_MESSAGE_SIZE
            )));
        }
        let mut data = vec![0u8; len];
        read_exact_with_timeout(recv_stream, &mut data, read_timeout).await?;

        let msg = MeshMessage::decode(&data).ok_or_else(|| {
            MeshTransportError::ReceiveFailed("Failed to decode message".to_string())
        })?;

        match msg {
            MeshMessage::RouteQuery {
                query_id,
                upstream_id,
                max_hops,
                initiator,
                sequence: _,
                timestamp: _,
                nonce: _,
            } => {
                self.handle_route_query(
                    send_stream,
                    query_id.to_string(),
                    upstream_id.to_string(),
                    max_hops,
                    initiator.to_string(),
                    topology,
                )
                .await?;
            }
            MeshMessage::RouteResponse {
                query_id,
                upstream_id,
                provider_node_id,
                hops,
                ttl_secs,
                upstream_url: _,
                waf_policy: _,
                priority_tier: _,
                ..
            } => {
                let _ = query_id;
                tracing::debug!(
                    "Got route response: {} -> {} ({} hops)",
                    upstream_id,
                    provider_node_id,
                    hops
                );
                topology
                    .cache_route(
                        &upstream_id,
                        provider_node_id.to_string(),
                        hops,
                        Duration::from_secs(ttl_secs as u64),
                    )
                    .await;
            }
            MeshMessage::RouteNotFound {
                query_id,
                upstream_id,
            } => {
                let _ = query_id;
                tracing::debug!("Route not found: {} from query {}", upstream_id, query_id);
            }
            MeshMessage::UpstreamUpdate {
                upstream_id,
                info: _,
                signature: _,
            } => {
                tracing::debug!("Upstream update: {}", upstream_id);
            }
            MeshMessage::KeepAlive => {
                let response = MeshMessage::KeepAliveAck
                    .encode()
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                let len = (response.len() as u32).to_be_bytes();
                send_stream
                    .write_all(&len)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                send_stream
                    .write_all(&response)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
            }
            MeshMessage::Hello { .. } | MeshMessage::HelloAck { .. } => {
                tracing::warn!("Unexpected handshake message in peer loop");
            }
            MeshMessage::SessionRotate {
                session_id,
                peer_id,
                key_version,
                peer_entropy,
                timestamp: _,
            } => {
                tracing::debug!(
                    "Received SessionRotate for session {} from peer {} (key_version={})",
                    session_id,
                    peer_id,
                    key_version,
                );
                if let Some(ref session_mgr) = self.mlkem_session_manager {
                    if let Err(e) =
                        session_mgr.apply_peer_rotation(&session_id, key_version, &peer_entropy)
                    {
                        tracing::warn!("Failed to apply peer session rotation: {}", e);
                    } else {
                        let ack = MeshMessage::SessionRotateAck {
                            session_id,
                            peer_id: self.config.node_id().into(),
                            key_version,
                            peer_entropy: Vec::new(),
                            timestamp: synvoid_utils::current_timestamp(),
                        };
                        let encoded = ack
                            .encode()
                            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                        let len = (encoded.len() as u32).to_be_bytes();
                        let _ = send_stream.write_all(&len).await;
                        let _ = send_stream.write_all(&encoded).await;
                    }
                }
            }
            MeshMessage::SessionRotateAck {
                session_id,
                peer_id: _,
                key_version: _,
                peer_entropy,
                timestamp: _,
            } => {
                tracing::debug!("Received SessionRotateAck for session {}", session_id);
                if let Some(ref session_mgr) = self.mlkem_session_manager {
                    if let Err(e) = session_mgr.finalize_rotation(&session_id, &peer_entropy) {
                        tracing::warn!("Failed to finalize session rotation: {}", e);
                    }
                }
            }
            MeshMessage::Ping {
                request_id,
                node_id: _,
                timestamp: _,
            } => {
                let response = MeshMessage::Pong {
                    request_id,
                    node_id: self.config.node_id().into(),
                    timestamp: synvoid_utils::safe_unix_timestamp(),
                };
                let encoded = response
                    .encode()
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                let len = (encoded.len() as u32).to_be_bytes();
                let _ = send_stream.write_all(&len).await;
                let _ = send_stream.write_all(&encoded).await;
            }
            MeshMessage::Pong {
                request_id: _,
                node_id: _,
                timestamp: _,
            } => {
                tracing::trace!("Received Pong via stream");
            }
            MeshMessage::PeerHealthResponse {
                peer_id: _,
                status: _,
                latency_ms,
                timestamp: _,
            } => {
                if let Some(latency) = latency_ms {
                    tracing::trace!("Peer health response: latency={}ms", latency);
                }
            }
            MeshMessage::MeshAck {
                original_message_id: _,
                status: _,
                timestamp: _,
            } => {
                tracing::trace!("Received MeshAck via stream");
            }
            MeshMessage::RouteResponseAck {
                query_id,
                upstream_id: _,
                provider_node_id: _,
            } => {
                tracing::debug!("Route response ack for query {}", query_id);
            }
            MeshMessage::RouteRejected {
                query_id,
                upstream_id: _,
                reason: _,
                alternatives: _,
            } => {
                tracing::debug!("Route rejected for query {}", query_id);
            }
            MeshMessage::PeerHealthCheck {
                peer_id: _,
                timestamp: _,
            } => {
                let response = MeshMessage::PeerHealthResponse {
                    peer_id: self.config.node_id().into(),
                    status: HealthStatus::Healthy,
                    latency_ms: None,
                    timestamp: synvoid_utils::safe_unix_timestamp(),
                };
                let encoded = response
                    .encode()
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                let len = (encoded.len() as u32).to_be_bytes();
                let _ = send_stream.write_all(&len).await;
                let _ = send_stream.write_all(&encoded).await;
            }
            MeshMessage::ServerlessFunctionAnnounce(announce) => {
                tracing::debug!(
                    "Received serverless function announce: {} v{}",
                    announce.function_name,
                    announce.version
                );
                self.handle_serverless_function_announce(announce).await;
            }
            MeshMessage::ServerlessInvokeRequest(req) => {
                tracing::debug!(
                    "Received serverless invoke request: {} from {}",
                    req.function_name,
                    req.caller_node_id
                );
                self.handle_serverless_invoke_request(&req).await?;
            }
            MeshMessage::ServerlessInvokeResponse(response) => {
                tracing::debug!(
                    "Received ServerlessInvokeResponse from {}: success={}, function={}",
                    response.caller_node_id,
                    response.success,
                    response.function_name
                );
                self.handle_serverless_invoke_response(&response).await?;
            }
            MeshMessage::RaftCommitNotification {
                leader_id: _,
                commit_index: _,
                namespace,
                key_id,
                timestamp: _,
            } => {
                tracing::debug!(
                    "Received RaftCommitNotification for namespace {:?} key {}",
                    namespace,
                    key_id
                );
                // Clone Arcs outside the guard scope to keep the future Send.
                let (erm, rclient) = {
                    let guard = self.edge_replica_manager.read();
                    let Some(ref edge_replica) = *guard else {
                        return Ok(());
                    };
                    let Some(ref rclient) = self.org_key_manager.get_raft_client() else {
                        return Ok(());
                    };
                    (edge_replica.clone(), rclient.clone())
                };
                let ns = namespace.clone();
                let key = key_id.clone();
                // Phase 24: edge replica notification is intentionally
                // fire-and-forget. The edge replica is a cache — stale
                // data is acceptable and will be refreshed on next read.
                // Blocking the datagram handler on the leader query would
                // add latency to every RaftCommitNotification. Failure to
                // update the cache is logged but does not affect core DHT
                // state or datagram response.
                let refresh_future = async move {
                    match rclient.query_leader_for_record(ns.clone(), &key).await {
                        Ok(Some(data)) => {
                            if let Err(e) = erm.update_from_notification(&ns, &key, &data) {
                                tracing::error!("Failed to update edge replica: {}", e);
                                crate::lifecycle::MeshTaskExitReason::Error(format!(
                                    "update failed: {}",
                                    e
                                ))
                            } else {
                                tracing::info!("Edge replica updated for {:?} key {}", ns, key);
                                crate::lifecycle::MeshTaskExitReason::CleanCompletion
                            }
                        }
                        Ok(None) => {
                            if let Err(e) = erm.delete_from_notification(&ns, &key) {
                                tracing::error!("Failed to delete from edge replica: {}", e);
                                crate::lifecycle::MeshTaskExitReason::Error(format!(
                                    "delete failed: {}",
                                    e
                                ))
                            } else {
                                crate::lifecycle::MeshTaskExitReason::CleanCompletion
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to query leader for record: {}", e);
                            crate::lifecycle::MeshTaskExitReason::Error(format!(
                                "leader query failed: {}",
                                e
                            ))
                        }
                    }
                };
                let dedup_key = Some(format!("edge_refresh:{}:{}", namespace.as_str(), key_id));
                // Phase 22-25: Spawn via shared helper which handles AuxiliaryTaskExit
                // publication, deduplication (abort+await), and capacity gating.
                if let Err(e) = self
                    .spawn_auxiliary_task(
                        crate::lifecycle::AuxiliaryTaskKind::EdgeReplicaRefresh,
                        "edge-replica-refresh",
                        None,
                        dedup_key,
                        refresh_future,
                    )
                    .await
                {
                    tracing::debug!(
                        "Edge-replica refresh rejected for {:?}/{}: {e}",
                        namespace,
                        key_id
                    );
                }
            }
            MeshMessage::JoinRequest {
                request_id,
                public_key,
                invite_token,
                attestation_report,
                timestamp,
                signature,
            } => {
                self.handle_join_request(
                    &peer_node_id,
                    &request_id,
                    &public_key,
                    &invite_token,
                    attestation_report.as_deref(),
                    timestamp,
                    &signature,
                )
                .await;
            }
            MeshMessage::JoinResponse { .. } => {
                // Handled by pending responses
            }
            MeshMessage::Raft {
                target_node_id,
                payload,
            } => {
                tracing::debug!(
                    "Received Raft message for target {} via stream",
                    target_node_id
                );
                let response_data = self
                    .handle_raft_message(
                        target_node_id.to_string(),
                        payload,
                        send_stream,
                        &peer_node_id,
                    )
                    .await?;
                if let Some(data) = response_data {
                    let len = (data.len() as u32).to_be_bytes();
                    send_stream.write_all(&len).await.map_err(|e| {
                        MeshTransportError::SendFailed(format!("Write failed: {}", e))
                    })?;
                    send_stream.write_all(&data).await.map_err(|e| {
                        MeshTransportError::SendFailed(format!("Write failed: {}", e))
                    })?;
                }
            }
            _ => {
                tracing::trace!("Stream peer handler: unhandled message type received via stream");
            }
        }

        Ok(())
    }

    pub(crate) async fn handle_serverless_function_announce(
        &self,
        announce: crate::protocol::ServerlessFunctionAnnounce,
    ) {
        let Some(record_store) = self.record_store.clone() else {
            tracing::warn!("Serverless function announce received but no record store available");
            return;
        };

        let key = crate::dht::keys::DhtKey::serverless_function(&announce.function_name);
        let key_str = key.as_str();

        let value = serde_json::json!({
            "function_name": announce.function_name,
            "version": announce.version,
            "checksum": announce.checksum,
            "routes": announce.routes,
            "allowed_methods": announce.allowed_methods,
            "memory_mb": announce.memory_mb,
            "timeout_seconds": announce.timeout_seconds,
            "priority": announce.priority,
            "announced_at": chrono::Utc::now().timestamp(),
        });

        if let Ok(bytes) = serde_json::to_vec(&value) {
            let ttl = 3600;
            if record_store.store_and_announce(key_str.to_string(), bytes, ttl) {
                tracing::debug!(
                    "Stored serverless function {} in DHT with TTL {}s",
                    announce.function_name,
                    ttl
                );
            } else {
                tracing::warn!(
                    "Failed to store serverless function {} in DHT",
                    announce.function_name
                );
            }
        }
    }

    pub(crate) async fn handle_serverless_invoke_request(
        &self,
        req: &crate::protocol::ServerlessInvokeRequest,
    ) -> Result<(), MeshTransportError> {
        use std::time::Instant;
        use synvoid_serverless::manager::CallerContext;

        let start = Instant::now();

        let sm = {
            let guard = self.serverless_manager.read();
            guard.clone()
        };

        let Some(serverless_manager) = sm else {
            tracing::warn!(
                "ServerlessInvokeRequest for '{}' but serverless manager not available",
                req.function_name
            );
            return Ok(());
        };

        let caller = CallerContext {
            node_id: req.caller_node_id.clone(),
            role: crate::config::MeshNodeRole::EDGE,
            org_id: None,
            tier: None,
            is_local: false,
        };

        let function_name = req.function_name.clone();
        let result = serverless_manager
            .invoke_for_mesh(
                &function_name,
                "POST",
                "/",
                &http::HeaderMap::new(),
                None,
                caller,
            )
            .await;

        let execution_time_ms = start.elapsed().as_millis() as u64;

        let (success, response_data, error_message) = match result {
            Ok(response) => {
                tracing::debug!(
                    "Serverless invoke '{}' completed: status={}, {}ms",
                    function_name,
                    response.status_code,
                    execution_time_ms
                );
                let body_vec = response.body.to_vec();
                (true, body_vec, String::new())
            }
            Err(e) => {
                tracing::warn!("Serverless invoke '{}' failed: {}", function_name, e);
                (false, Vec::new(), e.to_string())
            }
        };

        let response_msg =
            MeshMessage::ServerlessInvokeResponse(crate::protocol::ServerlessInvokeResponse {
                function_name,
                caller_node_id: req.caller_node_id.clone(),
                timestamp: synvoid_utils::safe_unix_timestamp(),
                response_data,
                success,
                error_message,
                execution_time_ms,
                response_signature: Vec::new(),
            });

        if let Err(e) = self
            .send_message_to_peer(&req.caller_node_id, &response_msg)
            .await
        {
            tracing::warn!(
                "Failed to send ServerlessInvokeResponse to {}: {}",
                req.caller_node_id,
                e
            );
        }

        Ok(())
    }

    pub(crate) async fn handle_serverless_invoke_response(
        &self,
        response: &crate::protocol::ServerlessInvokeResponse,
    ) -> Result<(), MeshTransportError> {
        let mut pending = self.pending_serverless_invocations.lock().await;
        let key = format!("{}:{}", response.function_name, response.caller_node_id);
        if let Some(sender) = pending.remove(&key) {
            tracing::debug!(
                "Delivering serverless invocation response for '{}' to waiting caller",
                response.function_name
            );
            let _ = sender.send(response.clone());
        } else {
            tracing::warn!(
                "Received ServerlessInvokeResponse for '{}' but no pending invocation found",
                response.function_name
            );
        }
        Ok(())
    }

    async fn verify_and_maybe_store_client_proposal(
        &self,
        command: &RaftCommand,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let (namespace, key, source_node_id, signature) = match command {
            RaftCommand::Set {
                namespace,
                key,
                source_node_id,
                signature,
                ..
            } => (
                namespace.clone(),
                key.clone(),
                source_node_id.clone(),
                signature.clone(),
            ),
            RaftCommand::Delete {
                namespace,
                key,
                source_node_id,
                signature,
            } => (
                namespace.clone(),
                key.clone(),
                source_node_id.clone(),
                signature.clone(),
            ),
        };

        let source_node_id = match source_node_id {
            Some(id) => id,
            None => {
                tracing::warn!("ClientProposal missing source_node_id");
                return Ok(false);
            }
        };

        let signature = match signature {
            Some(sig) => sig.clone(),
            None => {
                tracing::warn!("ClientProposal missing signature");
                return Ok(false);
            }
        };

        let signer = match self.mesh_signer.as_ref() {
            Some(s) => s,
            None => {
                tracing::warn!("No mesh signer configured, rejecting signed proposal");
                return Ok(false);
            }
        };

        let payload = ClientProposalPayload::new(
            namespace.clone(),
            key.clone(),
            &[],
            CommandKind::Set,
            source_node_id.clone(),
            0,
            0,
        );
        let signable_content = payload.get_signable_content();

        let public_key = signer.get_public_key_bytes();
        if !signer.verify(&signable_content, &signature, &public_key) {
            tracing::warn!(
                "ClientProposal signature verification failed for node {}",
                source_node_id
            );
            return Ok(false);
        }

        let mut replay_cache = self.raft_proposal_replay_cache.lock().await;
        let timestamp = synvoid_utils::safe_unix_timestamp();
        if !replay_cache.check_and_insert(&source_node_id, timestamp, 0) {
            tracing::warn!(
                "ClientProposal replay detected from node {}",
                source_node_id
            );
            return Ok(false);
        }

        Ok(true)
    }

    pub(crate) async fn handle_raft_message(
        &self,
        target_node_id: String,
        payload: crate::protocol::RaftPayload,
        _send_stream: &mut quinn::SendStream,
        from_node_id: &str,
    ) -> Result<Option<Vec<u8>>, MeshTransportError> {
        let local_node_id = self.config.node_id();
        if target_node_id != local_node_id {
            tracing::warn!(
                "Received Raft message for node {} but local node is {} - forwarding not implemented",
                target_node_id,
                local_node_id
            );
            return Ok(None);
        }

        let instance = {
            let guard = self.raft_instance.read();
            guard.clone()
        };

        let peer = self.topology.get_peer(from_node_id).await;
        let is_authorized = self.check_raft_peer_authorization(
            from_node_id,
            payload.msg_type,
            instance.as_ref(),
            peer.as_ref(),
        );
        if !is_authorized {
            tracing::warn!(
                "Rejected Raft message type {:?} from unauthorized node {}",
                payload.msg_type,
                from_node_id
            );
            return Ok(None);
        }

        let response_data = match payload.msg_type {
            crate::protocol::RaftMsgType::ClientProposal => {
                let request_id = payload.request_id.clone();
                let command: crate::raft::state_machine::RaftCommand =
                    match postcard::from_bytes(&payload.data) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!("Failed to deserialize Raft command: {}", e);
                            return Ok(None);
                        }
                    };

                if let Some(ref inst) = instance {
                    if !inst.is_leader().await {
                        let leader_hint = inst.get_leader_id().await.map(|id| id.to_string());
                        let response = crate::protocol::MeshMessage::NotLeader {
                            request_id: ArcStr::from(
                                request_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                            ),
                            leader_node_id: leader_hint.map(ArcStr::from),
                            current_term: None,
                        };
                        Some(
                            response
                                .encode()
                                .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?,
                        )
                    } else {
                        match self.verify_and_maybe_store_client_proposal(&command).await {
                            Ok(true) => {}
                            Ok(false) => {
                                tracing::warn!(
                                    "ClientProposal rejected: signature verification failed or replay detected"
                                );
                                return Ok(None);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "ClientProposal rejected: authorization error: {}",
                                    e
                                );
                                return Ok(None);
                            }
                        }
                        match inst.client_write(command).await {
                            Ok(commit_index) => {
                                let response =
                                    crate::protocol::MeshMessage::ConsistentReadResponse {
                                        request_id: ArcStr::from(
                                            request_id.unwrap_or_else(|| {
                                                uuid::Uuid::new_v4().to_string()
                                            }),
                                        ),
                                        value: Some(commit_index.to_le_bytes().to_vec()),
                                        leader_node_id: Some(ArcStr::from(
                                            local_node_id.to_string(),
                                        )),
                                        timestamp: synvoid_utils::safe_unix_timestamp(),
                                    };
                                Some(response.encode().map_err(|e| {
                                    MeshTransportError::SendFailed(format!("{:?}", e))
                                })?)
                            }
                            Err(e) => {
                                tracing::warn!("Raft client_write failed: {}", e);
                                None
                            }
                        }
                    }
                } else {
                    tracing::warn!("Received Raft message but no Raft instance available");
                    None
                }
            }
            crate::protocol::RaftMsgType::AppendEntries => {
                let _request_id = payload.request_id.clone();
                let rpc: openraft::raft::AppendEntriesRequest<
                    crate::raft::state_machine::GlobalRegistryConfig,
                > = match postcard::from_bytes(&payload.data) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("Failed to deserialize AppendEntries request: {}", e);
                        return Ok(None);
                    }
                };

                if let Some(ref inst) = instance {
                    match inst.raft_append_entries(rpc).await {
                        Ok(resp) => {
                            let encoded = postcard::to_stdvec(&resp).map_err(|e| {
                                MeshTransportError::SendFailed(format!("Serialize error: {}", e))
                            })?;
                            Some(encoded)
                        }
                        Err(e) => {
                            tracing::warn!("Raft append_entries failed: {}", e);
                            None
                        }
                    }
                } else {
                    tracing::warn!("Received AppendEntries but no Raft instance available");
                    None
                }
            }
            crate::protocol::RaftMsgType::VoteRequest => {
                let _request_id = payload.request_id.clone();
                let rpc: openraft::raft::VoteRequest<
                    crate::raft::state_machine::GlobalRegistryConfig,
                > = match postcard::from_bytes(&payload.data) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("Failed to deserialize VoteRequest: {}", e);
                        return Ok(None);
                    }
                };

                if let Some(ref inst) = instance {
                    match inst.raft_vote(rpc).await {
                        Ok(resp) => {
                            let encoded = postcard::to_stdvec(&resp).map_err(|e| {
                                MeshTransportError::SendFailed(format!("Serialize error: {}", e))
                            })?;
                            Some(encoded)
                        }
                        Err(e) => {
                            tracing::warn!("Raft vote failed: {}", e);
                            None
                        }
                    }
                } else {
                    tracing::warn!("Received VoteRequest but no Raft instance available");
                    None
                }
            }
            crate::protocol::RaftMsgType::InstallSnapshot => {
                let _request_id = payload.request_id.clone().unwrap_or_default();
                match postcard::from_bytes::<RaftSnapshotFrame>(&payload.data) {
                    Ok(frame) => match frame {
                        RaftSnapshotFrame::Header(header) => {
                            tracing::info!(
                                "Received snapshot header: request_id={}, total_size={}",
                                header.request_id,
                                header.total_size
                            );
                            let mut pending = self.pending_snapshot_transfers.lock().await;
                            pending.insert(
                                header.request_id.clone(),
                                crate::transport::InProgressSnapshot::with_sender(
                                    header.request_id,
                                    header.total_size,
                                    header.vote,
                                    header.meta,
                                    from_node_id.to_string(),
                                ),
                            );
                            None
                        }
                        RaftSnapshotFrame::Chunk(chunk) => {
                            let mut pending = self.pending_snapshot_transfers.lock().await;
                            let request_id = chunk.request_id.clone();
                            let is_complete = if let Some(snapshot) = pending.get_mut(&request_id) {
                                if !snapshot.add_chunk(
                                    chunk.offset,
                                    chunk.data.clone(),
                                    chunk.is_last,
                                    Some(from_node_id),
                                ) {
                                    tracing::warn!(
                                        "Failed to add chunk at offset {} for request_id {}",
                                        chunk.offset,
                                        request_id
                                    );
                                    pending.remove(&request_id);
                                    false
                                } else {
                                    snapshot.is_complete()
                                }
                            } else {
                                false
                            };
                            drop(pending);
                            if is_complete {
                                tracing::info!(
                                    "Snapshot assembly complete for request_id {}, installing...",
                                    request_id
                                );
                                let mut pending = self.pending_snapshot_transfers.lock().await;
                                let completed = pending.remove(&request_id);
                                if let Some(snapshot) = completed {
                                    let vote: VoteOf<GlobalRegistryConfig> =
                                        match postcard::from_bytes(&snapshot.vote) {
                                            Ok(v) => v,
                                            Err(e) => {
                                                tracing::warn!("Failed to deserialize vote: {}", e);
                                                return Ok(None);
                                            }
                                        };
                                    let meta: SnapshotMetaOf<
                                        crate::raft::state_machine::GlobalRegistryConfig,
                                    > = match postcard::from_bytes(&snapshot.meta) {
                                        Ok(m) => m,
                                        Err(e) => {
                                            tracing::warn!(
                                                "Failed to deserialize snapshot meta: {}",
                                                e
                                            );
                                            return Ok(None);
                                        }
                                    };
                                    if let Some(ref inst) = instance {
                                        if let Err(e) =
                                            inst.install_snapshot(&meta, snapshot.data.into()).await
                                        {
                                            tracing::error!("Failed to install snapshot: {}", e);
                                        } else {
                                            tracing::info!("Snapshot installed successfully");
                                            let response =
                                                SnapshotResponse::<GlobalRegistryConfig> { vote };
                                            let encoded =
                                                postcard::to_stdvec(&response).map_err(|e| {
                                                    MeshTransportError::SendFailed(format!(
                                                        "Serialize error: {}",
                                                        e
                                                    ))
                                                })?;
                                            return Ok(Some(encoded));
                                        }
                                    }
                                }
                                None
                            } else {
                                tracing::warn!(
                                    "Received chunk for unknown or completed request_id: {}",
                                    request_id
                                );
                                None
                            }
                        }
                    },
                    Err(e) => {
                        tracing::warn!(
                            "Failed to decode RaftSnapshotFrame, using legacy length heuristic: {}",
                            e
                        );
                        if payload.data.len() < 100 {
                            let header: crate::protocol::SnapshotHeader =
                                match postcard::from_bytes(&payload.data) {
                                    Ok(h) => h,
                                    Err(e) => {
                                        tracing::warn!(
                                            "Failed to deserialize SnapshotHeader: {}",
                                            e
                                        );
                                        return Ok(None);
                                    }
                                };
                            tracing::info!(
                                "Received snapshot header: request_id={}, total_size={}",
                                header.request_id,
                                header.total_size
                            );
                            let mut pending = self.pending_snapshot_transfers.lock().await;
                            pending.insert(
                                header.request_id.clone(),
                                crate::transport::InProgressSnapshot::with_sender(
                                    header.request_id,
                                    header.total_size,
                                    header.vote,
                                    header.meta,
                                    from_node_id.to_string(),
                                ),
                            );
                            None
                        } else {
                            let chunk: crate::protocol::SnapshotChunk =
                                match postcard::from_bytes(&payload.data) {
                                    Ok(c) => c,
                                    Err(e) => {
                                        tracing::warn!(
                                            "Failed to deserialize SnapshotChunk: {}",
                                            e
                                        );
                                        return Ok(None);
                                    }
                                };
                            let mut pending = self.pending_snapshot_transfers.lock().await;
                            let request_id = chunk.request_id.clone();
                            let is_complete = if let Some(snapshot) = pending.get_mut(&request_id) {
                                if !snapshot.add_chunk(
                                    chunk.offset,
                                    chunk.data.clone(),
                                    chunk.is_last,
                                    Some(from_node_id),
                                ) {
                                    tracing::warn!(
                                        "Failed to add chunk at offset {} for request_id {}",
                                        chunk.offset,
                                        request_id
                                    );
                                    pending.remove(&request_id);
                                    false
                                } else {
                                    snapshot.is_complete()
                                }
                            } else {
                                false
                            };
                            drop(pending);
                            if is_complete {
                                tracing::info!(
                                    "Snapshot assembly complete for request_id {}, installing...",
                                    request_id
                                );
                                let mut pending = self.pending_snapshot_transfers.lock().await;
                                let completed = pending.remove(&request_id);
                                if let Some(snapshot) = completed {
                                    let vote: VoteOf<GlobalRegistryConfig> =
                                        match postcard::from_bytes(&snapshot.vote) {
                                            Ok(v) => v,
                                            Err(e) => {
                                                tracing::warn!("Failed to deserialize vote: {}", e);
                                                return Ok(None);
                                            }
                                        };
                                    let meta: SnapshotMetaOf<
                                        crate::raft::state_machine::GlobalRegistryConfig,
                                    > = match postcard::from_bytes(&snapshot.meta) {
                                        Ok(m) => m,
                                        Err(e) => {
                                            tracing::warn!(
                                                "Failed to deserialize snapshot meta: {}",
                                                e
                                            );
                                            return Ok(None);
                                        }
                                    };
                                    if let Some(ref inst) = instance {
                                        if let Err(e) =
                                            inst.install_snapshot(&meta, snapshot.data.into()).await
                                        {
                                            tracing::error!("Failed to install snapshot: {}", e);
                                        } else {
                                            tracing::info!("Snapshot installed successfully");
                                            let response =
                                                SnapshotResponse::<GlobalRegistryConfig> { vote };
                                            let encoded =
                                                postcard::to_stdvec(&response).map_err(|e| {
                                                    MeshTransportError::SendFailed(format!(
                                                        "Serialize error: {}",
                                                        e
                                                    ))
                                                })?;
                                            return Ok(Some(encoded));
                                        }
                                    }
                                }
                                None
                            } else {
                                tracing::warn!(
                                    "Received chunk for unknown or completed request_id: {}",
                                    request_id
                                );
                                None
                            }
                        }
                    }
                }
            }
            _ => {
                tracing::warn!("Unhandled Raft message type: {:?}", payload.msg_type);
                None
            }
        };

        Ok(response_data)
    }

    pub(crate) async fn perform_health_check(&self, peer_id: &str) -> Option<u32> {
        let start = Instant::now();
        // Iteration 77, Phase 9: health check reads bounded by per-message
        // read timeout to prevent indefinite stalls on dead/slow peers.
        let read_timeout = Duration::from_secs(self.config.connection.peer_message_timeout_secs);

        if let Some(peer) = self.peer_connections.get(peer_id) {
            let result = async {
                let (mut send_stream, mut recv_stream) = {
                    let mut pool = peer.stream_pool.lock().await;
                    pool.acquire().await
                }
                .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

                let msg = MeshMessage::PeerHealthCheck {
                    peer_id: self.config.node_id().into(),
                    timestamp: synvoid_utils::safe_unix_timestamp(),
                };

                let encoded = msg.encode()?;
                let len = (encoded.len() as u32).to_be_bytes();
                send_stream.write_all(&len).await?;
                send_stream.write_all(&encoded).await?;

                let mut len_buf = [0u8; 4];
                read_exact_with_timeout(&mut recv_stream, &mut len_buf, read_timeout).await?;
                let len = u32::from_be_bytes(len_buf) as usize;
                if len > MAX_MESSAGE_SIZE {
                    return Err(MeshTransportError::ReceiveFailed(format!(
                        "Health check response too large: {} bytes (max {})",
                        len, MAX_MESSAGE_SIZE
                    )));
                }
                let mut buf = vec![0u8; len];
                read_exact_with_timeout(&mut recv_stream, &mut buf, read_timeout).await?;

                {
                    let mut pool = peer.stream_pool.lock().await;
                    pool.release((send_stream, recv_stream));
                }

                Ok::<_, MeshTransportError>(())
            }
            .await;

            let latency = start.elapsed().as_millis() as u32;

            if result.is_ok() {
                self.topology.record_connection_success(peer_id).await;
                self.topology
                    .update_peer_latency_for_score(peer_id, latency)
                    .await;
                self.topology.update_peer_latency(peer_id, latency).await;
                self.topology
                    .update_peer_status(peer_id, PeerStatus::Healthy)
                    .await;
                tracing::trace!("Health check OK for {}: {}ms", peer_id, latency);
                return Some(latency);
            } else {
                self.topology.record_connection_failure(peer_id).await;
                self.topology
                    .update_peer_status(peer_id, PeerStatus::Unhealthy)
                    .await;
                tracing::warn!("Health check failed for {}: {:?}", peer_id, result.err());
                return None;
            }
        }

        None
    }

    async fn handle_http_proxy_stream(
        &self,
        parsed_meta: &ParsedHttpRequestMeta,
        http_data: Vec<u8>,
        send_stream: &mut SendStream,
        topology: &MeshTopology,
        peer_node_id: String,
    ) -> Result<(), MeshTransportError> {
        if parsed_meta.host.is_empty() {
            return Err(MeshTransportError::ReceiveFailed(
                "No Host header found in HTTP request".to_string(),
            ));
        }
        let upstream_id = format!("http://{}", parsed_meta.host);

        let upstream_info = topology.get_upstream_info(&upstream_id).await;
        let backend_url = match upstream_info {
            Some(info) => info.upstream_url,
            None => {
                tracing::debug!("No local backend found for {}", upstream_id);
                let not_found = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
                send_stream
                    .write_all(not_found)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                let _ = send_stream.finish();
                return Ok(());
            }
        };

        #[cfg(feature = "dns")]
        if parsed_meta.method.eq_ignore_ascii_case("GET") {
            if let Some(token) = parsed_meta
                .target
                .strip_prefix("/.well-known/acme-challenge/")
            {
                let token = token.trim();
                if !token.is_empty() && !token.contains('\r') && !token.contains('\n') {
                    if let Some(key_authz) = self.get_http01_challenge(token) {
                        tracing::debug!(
                            "ACME HTTP-01 challenge served from mesh for token {}",
                            token
                        );
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                            key_authz.len(),
                            key_authz
                        );
                        send_stream
                            .write_all(resp.as_bytes())
                            .await
                            .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                        let _ = send_stream.finish();
                        return Ok(());
                    }
                }
            }
        }

        if upstream_id.starts_with("serverless_function:") {
            return self
                .handle_serverless_proxy_stream(
                    &upstream_id,
                    parsed_meta,
                    &http_data,
                    send_stream,
                    peer_node_id,
                )
                .await;
        }

        let parsed_url = match url::Url::parse(&backend_url) {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!("Failed to parse backend URL {}: {}", backend_url, e);
                let error_resp = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
                send_stream
                    .write_all(error_resp)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                let _ = send_stream.finish();
                return Ok(());
            }
        };

        let host_str = parsed_url.host_str().unwrap_or("127.0.0.1");
        let port = parsed_url.port().unwrap_or(80);

        if let Ok(ip) = host_str.parse::<std::net::IpAddr>() {
            if synvoid_proxy::headers::is_private_ip(&ip) {
                tracing::warn!(
                    "SSRF prevention: rejecting connection to private IP {} via mesh proxy",
                    ip
                );
                let forbidden = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
                send_stream
                    .write_all(forbidden)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                let _ = send_stream.finish();
                return Ok(());
            }
        } else {
            match tokio::net::lookup_host(format!("{}:{}", host_str, port)).await {
                Ok(ips) => {
                    for ip in ips {
                        let ip_addr = ip.ip();
                        if synvoid_proxy::headers::is_private_ip(&ip_addr) {
                            tracing::warn!(
                                "SSRF prevention: rejecting connection to private IP {} resolved from domain {} via mesh proxy",
                                ip_addr,
                                host_str
                            );
                            let forbidden = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
                            send_stream
                                .write_all(forbidden)
                                .await
                                .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                            let _ = send_stream.finish();
                            return Ok(());
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to resolve domain {} for SSRF check: {}",
                        host_str,
                        e
                    );
                }
            }
        }

        let addr = format!("{}:{}", host_str, port);

        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpStream;

        let mut backend_conn = match TcpStream::connect(&addr).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Failed to connect to backend {}: {}", addr, e);
                let bad_gateway = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
                send_stream
                    .write_all(bad_gateway)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                let _ = send_stream.finish();
                return Ok(());
            }
        };

        backend_conn
            .write_all(&http_data)
            .await
            .map_err(|e| MeshTransportError::SendFailed(format!("Backend write failed: {}", e)))?;

        let idle_timeout =
            Duration::from_secs(self.config.connection.peer_http_backend_idle_timeout_secs);
        let header_total_timeout = Duration::from_secs(
            self.config
                .connection
                .peer_http_response_header_total_timeout_secs,
        );
        let body_total_timeout = Duration::from_secs(
            self.config
                .connection
                .peer_http_response_body_total_timeout_secs,
        );
        let max_header_bytes = self.config.connection.max_peer_http_response_header_bytes;
        let max_body_bytes = self.config.connection.max_peer_http_response_body_bytes;
        let max_trailer_bytes = self.config.connection.max_peer_http_response_trailer_bytes;

        let resp_head = match read_http_response_sequence(
            &mut backend_conn,
            idle_timeout,
            header_total_timeout,
            max_header_bytes,
        )
        .await
        {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!("Backend response header read error: {}", e);
                let err_resp = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
                send_stream
                    .write_all(err_resp)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                let _ = send_stream.finish();
                return Ok(());
            }
        };

        let is_head = parsed_meta.method.eq_ignore_ascii_case("HEAD");
        let is_no_body_status = resp_head.status_code < 200
            || resp_head.status_code == 204
            || resp_head.status_code == 304;

        let body_bytes = if is_head || is_no_body_status {
            Vec::new()
        } else if resp_head.chunked {
            match read_chunked_http_response_body(
                backend_conn,
                resp_head.body_prefix,
                idle_timeout,
                body_total_timeout,
                max_body_bytes,
                max_trailer_bytes,
            )
            .await
            {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("Backend chunked body read error: {}", e);
                    let err_resp = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
                    send_stream
                        .write_all(err_resp)
                        .await
                        .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                    let _ = send_stream.finish();
                    return Ok(());
                }
            }
        } else if let Some(cl) = resp_head.content_length {
            match read_fixed_http_response_body(
                &mut backend_conn,
                resp_head.body_prefix,
                cl,
                idle_timeout,
                body_total_timeout,
                max_body_bytes,
            )
            .await
            {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("Backend fixed body read error: {}", e);
                    let err_resp = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
                    send_stream
                        .write_all(err_resp)
                        .await
                        .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                    let _ = send_stream.finish();
                    return Ok(());
                }
            }
        } else {
            let allowed_close_delimited = match resp_head.http_version {
                HttpVersion::Http10 => true,
                HttpVersion::Http11 => resp_head.connection_close,
            };
            if !allowed_close_delimited {
                tracing::warn!(
                    "HTTP/1.1 response with no Content-Length, no chunked encoding, \
                     and no Connection: close — ambiguous framing rejected"
                );
                let err_resp = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
                send_stream
                    .write_all(err_resp)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                let _ = send_stream.finish();
                return Ok(());
            }
            match read_close_delimited_http_response_body(
                &mut backend_conn,
                resp_head.body_prefix,
                idle_timeout,
                body_total_timeout,
                max_body_bytes,
            )
            .await
            {
                Ok(body) => body,
                Err(HttpResponseFramingError::BodyTooLarge { limit, declared }) => {
                    tracing::warn!(
                        "Backend close-delimited body exceeded limit ({declared} > {limit})"
                    );
                    return Err(MeshTransportError::ReceiveFailed(format!(
                        "Close-delimited body exceeded limit: {declared} > {limit}"
                    )));
                }
                Err(HttpResponseFramingError::Io(msg)) => {
                    if msg.contains("timeout") {
                        tracing::warn!("Backend close-delimited body timed out: {}", msg);
                        return Err(MeshTransportError::ReceiveFailed(format!(
                            "Close-delimited body timeout: {msg}"
                        )));
                    }
                    tracing::warn!("Backend close-delimited body read error: {}", msg);
                    return Err(MeshTransportError::ReceiveFailed(format!(
                        "Close-delimited body error: {msg}"
                    )));
                }
                Err(e) => {
                    tracing::warn!("Backend close-delimited body error: {}", e);
                    return Err(MeshTransportError::ReceiveFailed(format!(
                        "Close-delimited body error: {e}"
                    )));
                }
            }
        };

        let mut full_response = resp_head.header_bytes;
        full_response.extend_from_slice(&body_bytes);

        let skip_transforms = resp_head.body_encoding == HttpResponseBodyEncoding::Chunked;
        if skip_transforms {
            tracing::debug!(
                "Skipping response transforms for chunked body from {}",
                upstream_id
            );
        }

        let (transformed_response, did_transform) = if skip_transforms {
            (full_response, false)
        } else {
            match self
                .apply_response_transforms(&full_response, &upstream_id)
                .await
            {
                Ok((resp, transformed)) => (resp, transformed),
                Err(e) => {
                    tracing::warn!("Transform error for {}: {}", upstream_id, e);
                    (full_response, false)
                }
            }
        };

        send_stream
            .write_all(&transformed_response)
            .await
            .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;

        if did_transform {
            tracing::debug!("Sent transformed response for {}", upstream_id);
        }

        let _ = send_stream.finish();

        Ok(())
    }

    async fn apply_response_transforms(
        &self,
        response: &[u8],
        upstream_id: &str,
    ) -> Result<(Vec<u8>, bool), MeshTransportError> {
        let Some(record_store) = &self.record_store else {
            return Ok((response.to_vec(), false));
        };

        let response_str = match String::from_utf8(response.to_vec()) {
            Ok(s) => s,
            Err(_) => return Ok((response.to_vec(), false)),
        };

        let header_end_pos = response_str.find("\r\n\r\n").map(|p| p + 4);
        let Some(header_end) = header_end_pos else {
            return Ok((response.to_vec(), false));
        };

        let headers_section = &response_str[..header_end];
        let body_start = header_end;

        let content_type = self
            .extract_content_type_from_headers(headers_section)
            .unwrap_or_default();

        let transformable = content_type.contains("text/html")
            || content_type.contains("text/css")
            || content_type.contains("javascript")
            || content_type.contains("image/svg");

        if !transformable {
            return Ok((response.to_vec(), false));
        }

        let minification_key = format!("upstream_minification:{}", upstream_id);
        let min_config: Option<serde_json::Value> = record_store
            .get_record(&minification_key)
            .and_then(|r| serde_json::from_slice(&r.value).ok());

        let min_enabled = min_config
            .as_ref()
            .and_then(|c| c.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !min_enabled {
            return Ok((response.to_vec(), false));
        }

        let enable_html = min_config
            .as_ref()
            .and_then(|c| c.get("enable_html"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let enable_css = min_config
            .as_ref()
            .and_then(|c| c.get("enable_css"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let enable_js = min_config
            .as_ref()
            .and_then(|c| c.get("enable_js"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let body = &response[body_start..];
        let body_str = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(_) => return Ok((response.to_vec(), false)),
        };

        let generator = crate::stubs::static_files_stub::minifier::MinifierGenerator::new();
        let mut minified_body = body_str.to_string();

        if content_type.contains("text/html") && enable_html {
            if let Ok(minified) = generator.minify_html(body_str) {
                minified_body = minified;
            }
        } else if content_type.contains("text/css") && enable_css {
            if let Ok(minified) = generator.minify_css(body_str) {
                minified_body = minified;
            }
        } else if (content_type.contains("javascript") || content_type.contains("js")) && enable_js
        {
            if let Ok(minified) = generator.minify_js(body_str) {
                minified_body = minified;
            }
        }

        let new_body_len = minified_body.len();

        let mut new_headers = String::new();
        for line in headers_section.lines() {
            let line_lower = line.to_lowercase();
            if line_lower.starts_with("content-length:") {
                new_headers.push_str(&format!("Content-Length: {}\r\n", new_body_len));
            } else if !line_lower.starts_with("transfer-encoding:") {
                new_headers.push_str(line);
                new_headers.push_str("\r\n");
            }
        }
        new_headers.push_str("\r\n");

        let mut new_response = new_headers.into_bytes();
        new_response.extend_from_slice(minified_body.as_bytes());

        tracing::debug!(
            "Applied minification to {}: {} -> {} bytes",
            upstream_id,
            body.len(),
            new_body_len
        );

        Ok((new_response, true))
    }

    fn extract_content_type_from_headers(&self, headers: &str) -> Option<String> {
        for line in headers.lines() {
            let line_lower = line.to_lowercase();
            if line_lower.starts_with("content-type:") {
                return Some(
                    line.split(':')
                        .skip(1)
                        .collect::<String>()
                        .trim()
                        .to_string(),
                );
            }
        }
        None
    }

    async fn handle_serverless_proxy_stream(
        &self,
        upstream_id: &str,
        parsed_meta: &ParsedHttpRequestMeta,
        http_data: &[u8],
        send_stream: &mut SendStream,
        peer_node_id: String,
    ) -> Result<(), MeshTransportError> {
        let function_name = upstream_id
            .strip_prefix("serverless_function:")
            .unwrap_or(upstream_id);

        let serverless_manager_opt = {
            let sm_guard = self.serverless_manager.read();
            sm_guard.as_ref().cloned()
        };

        let Some(serverless_manager) = serverless_manager_opt else {
            tracing::warn!("Serverless proxy request but no serverless manager configured");
            let not_found = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
            send_stream
                .write_all(not_found)
                .await
                .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
            let _ = send_stream.finish();
            return Ok(());
        };

        let peer_role = self
            .topology
            .get_peer(&peer_node_id)
            .await
            .map(|p| p.role)
            .unwrap_or(crate::config::MeshNodeRole::EDGE);

        let caller = synvoid_serverless::manager::CallerContext::mesh(peer_node_id, peer_role);

        let method = parsed_meta.method.clone();
        let path = parsed_meta.target.clone();

        let header_str = match String::from_utf8(http_data.to_vec()) {
            Ok(s) => s,
            Err(_) => {
                let error_resp = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
                send_stream
                    .write_all(error_resp)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                let _ = send_stream.finish();
                return Ok(());
            }
        };

        let mut headers = http::HeaderMap::new();
        for line in header_str.lines() {
            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim();
                let value = line[colon_pos + 1..].trim();
                if let Ok(header_name) = name.parse::<http::header::HeaderName>() {
                    if let Ok(header_value) = value.parse::<http::header::HeaderValue>() {
                        headers.insert(header_name, header_value);
                    }
                }
            }
        }

        let body_offset = header_str
            .find("\r\n\r\n")
            .map(|p| p + 4)
            .unwrap_or(header_str.len());
        let body = if body_offset < http_data.len() {
            Some(bytes::Bytes::copy_from_slice(&http_data[body_offset..]))
        } else {
            None
        };

        match serverless_manager
            .invoke_for_mesh(function_name, &method, &path, &headers, body, caller)
            .await
        {
            Ok(response) => {
                let status_line = format!("HTTP/1.1 {} \r\n", response.status_code);
                let mut response_bytes = status_line.into_bytes();

                for (name, value) in response.headers.iter() {
                    response_bytes.extend_from_slice(name.as_str().as_bytes());
                    response_bytes.extend_from_slice(b": ");
                    response_bytes.extend_from_slice(value.as_bytes());
                    response_bytes.extend_from_slice(b"\r\n");
                }
                response_bytes.extend_from_slice(b"\r\n");
                response_bytes.extend_from_slice(&response.body);

                send_stream
                    .write_all(&response_bytes)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                let _ = send_stream.finish();

                tracing::debug!(
                    "Serverless function '{}' responded with {} in {}ms",
                    function_name,
                    response.status_code,
                    response.execution_time_ms
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Serverless function '{}' invocation failed: {}",
                    function_name,
                    e
                );
                let error_body = format!("Serverless error: {}", e);
                let error_resp = format!(
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                    error_body.len(),
                    error_body
                );
                send_stream
                    .write_all(error_resp.as_bytes())
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                let _ = send_stream.finish();
            }
        }

        Ok(())
    }

    fn check_raft_peer_authorization(
        &self,
        from_node_id: &str,
        msg_type: crate::protocol::RaftMsgType,
        instance: Option<&Arc<crate::raft::instance::RaftInstance>>,
        peer: Option<&crate::topology::PeerState>,
    ) -> bool {
        match msg_type {
            crate::protocol::RaftMsgType::ClientProposal => {
                if let Some(inst) = instance {
                    if let Some(membership) = inst.get_applied_membership() {
                        if let Ok(node_id) = from_node_id.parse::<u64>() {
                            let mem = membership.membership();
                            if mem.voter_ids().any(|id| id == node_id)
                                || mem.learner_ids().any(|id| id == node_id)
                            {
                                return true;
                            }
                        }
                    }
                }
                if let Some(p) = peer {
                    if p.role.is_global() || p.role.is_edge() {
                        tracing::warn!("ClientProposal from non-member {} rejected", from_node_id);
                        return false;
                    }
                }
                true
            }
            crate::protocol::RaftMsgType::AppendEntries
            | crate::protocol::RaftMsgType::VoteRequest
            | crate::protocol::RaftMsgType::InstallSnapshot => {
                if let Some(inst) = instance {
                    if let Some(membership) = inst.get_applied_membership() {
                        if let Ok(node_id) = from_node_id.parse::<u64>() {
                            let mem = membership.membership();
                            if mem.voter_ids().any(|id| id == node_id) {
                                return true;
                            }
                            if mem.learner_ids().any(|id| id == node_id) {
                                if matches!(msg_type, crate::protocol::RaftMsgType::AppendEntries) {
                                    return true;
                                }
                                tracing::warn!(
                                    "Learner {} attempted {:?} - only AppendEntries allowed for learners",
                                    from_node_id,
                                    msg_type
                                );
                                return false;
                            }
                        }
                    } else {
                        tracing::debug!(
                            "No membership info available, allowing {:?} from {}",
                            msg_type,
                            from_node_id
                        );
                        return true;
                    }
                }
                if let Some(p) = peer {
                    if p.role.is_global() || p.role.is_edge() {
                        tracing::warn!(
                            "{:?} from {} rejected - edge/origin nodes not authorized for Raft consensus",
                            msg_type,
                            from_node_id
                        );
                        return false;
                    }
                }
                true
            }
            _ => true,
        }
    }

    pub(crate) async fn handle_join_request(
        &self,
        peer_id: &str,
        request_id: &str,
        public_key: &str,
        invite_token: &str,
        attestation_report: Option<&str>,
        _timestamp: u64,
        _signature: &[u8],
    ) {
        tracing::info!(
            "Received JoinRequest from peer {} (pk: {}, token: {})",
            peer_id,
            public_key,
            invite_token
        );

        let valid_token = self.config.global_node.is_invite_token_valid(invite_token);
        if !valid_token {
            tracing::warn!("Invalid invite token '{}' from {}", invite_token, peer_id);
            let response = crate::protocol::MeshMessage::JoinResponse {
                request_id: request_id.into(),
                approved: false,
                trust_level: 0,
                reason: Some("Invalid invite token".into()),
                timestamp: synvoid_utils::safe_unix_timestamp(),
                signature: Vec::new(),
            };
            let _ = self.send_datagram_to_peer(peer_id, &response).await;
            return;
        }

        let mut trust_level = 1;
        if attestation_report.is_some() {
            trust_level = 2;
        }

        let new_node = crate::raft::state_machine::AuthorizedGlobalNode {
            public_key: public_key.to_string(),
            trust_level,
            attestation_report: attestation_report.map(|s| s.to_string()),
            authorized_at: synvoid_utils::safe_unix_timestamp(),
        };

        let value = postcard::to_stdvec(
            &crate::raft::state_machine::StateMachineValue::AuthorizedGlobalNode(new_node),
        )
        .unwrap_or_default();
        let cmd = crate::raft::state_machine::RaftCommand::Set {
            namespace: crate::raft::state_machine::Namespace::AuthorizedGlobalNodes,
            key: public_key.to_string(),
            value,
            source_node_id: Some(self.config.node_id().to_string()),
            signature: Some(Vec::new()),
        };

        let raft = {
            let guard = self.raft_instance.read();
            guard.clone()
        };

        let approved = if let Some(ref raft_arc) = raft {
            match raft_arc.client_write(cmd).await {
                Ok(_) => true,
                Err(e) => {
                    tracing::error!("Raft write failed for JoinRequest: {}", e);
                    false
                }
            }
        } else {
            tracing::warn!("Raft instance not available, cannot process JoinRequest");
            false
        };

        let response = crate::protocol::MeshMessage::JoinResponse {
            request_id: request_id.into(),
            approved,
            trust_level: if approved { trust_level } else { 0 },
            reason: if approved {
                None
            } else {
                Some("Internal error proposing to Raft".into())
            },
            timestamp: synvoid_utils::safe_unix_timestamp(),
            signature: Vec::new(),
        };
        let _ = self.send_datagram_to_peer(peer_id, &response).await;
    }
}

/// Classify a cooperative drain join result (Iteration 77, Phase 2).
///
/// Post-abort cancellations are classified as aborted only when we
/// explicitly called `abort_all()` — which happens after this loop.
/// Unexpected cancellation before explicit abort is classified as failed.
fn classify_stream_join(
    result: Result<Result<(), MeshTransportError>, tokio::task::JoinError>,
    report: &mut crate::lifecycle::PeerStreamDrainReport,
) {
    match result {
        Ok(Ok(())) => report.drained += 1,
        Ok(Err(_)) => report.failed += 1,
        Err(e) if e.is_panic() => report.failed += 1,
        Err(_) => report.failed += 1,
    }
}

/// Classify a forced-abort join result (Iteration 77, Phase 2).
///
/// After `abort_all()`, cancelled tasks are expected. Panicked or
/// already-failed tasks are counted as failed.
fn classify_forced_stream_join(
    result: Result<Result<(), MeshTransportError>, tokio::task::JoinError>,
    report: &mut crate::lifecycle::PeerStreamDrainReport,
) {
    match result {
        Ok(Ok(())) => report.drained += 1,
        Ok(Err(_)) => report.failed += 1,
        Err(e) if e.is_panic() => report.failed += 1,
        Err(_) => report.aborted += 1,
    }
}

/// Drain all per-stream message handlers before emitting a `PeerSessionExit`.
///
/// Cooperative drain with a deadline, followed by abort of remaining handlers.
/// This ensures no handler outlives the session that owns it (Iteration 75).
async fn drain_peer_stream_handlers(
    handlers: &mut tokio::task::JoinSet<Result<(), MeshTransportError>>,
    timeout: Duration,
) -> crate::lifecycle::PeerStreamDrainReport {
    use crate::lifecycle::PeerStreamDrainReport;

    let mut report = PeerStreamDrainReport::default();

    if handlers.is_empty() {
        return report;
    }

    let deadline = tokio::time::Instant::now() + timeout;

    // Cooperative drain with deadline enforcement — a single hung handler
    // cannot prevent the deadline from being observed (Iteration 77, Phase 1).
    while !handlers.is_empty() {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }

        match tokio::time::timeout(left, handlers.join_next()).await {
            Ok(Some(result)) => classify_stream_join(result, &mut report),
            Ok(None) => break,
            Err(_) => break,
        }
    }

    // Abort remaining handlers and await every one (Iteration 77, Phase 1).
    let forced = handlers.len();
    if forced > 0 {
        handlers.abort_all();
        while let Some(result) = handlers.join_next().await {
            classify_forced_stream_join(result, &mut report);
        }
    }

    report
}

impl MeshTransport {
    /// Per-stream read/framing timeout (Iteration 77, Phase 5-7).
    ///
    /// Applied only to actual `RecvStream` read operations, not to the
    /// entire handler lifetime. Long-lived post-framing work (proxy,
    /// streaming) is not bounded by this timeout.
    pub(crate) fn peer_message_read_timeout(&self) -> Duration {
        Duration::from_secs(self.config.connection.peer_message_timeout_secs)
    }

    /// Optional total stream lifetime timeout (Iteration 76, Phase 20).
    ///
    /// When `None` (default), no total bound is applied — read timeouts
    /// guard framing, and explicit session cancellation bounds lifetime.
    /// When `Some(_)`, the entire stream handler is bounded by this duration.
    pub(crate) fn peer_stream_total_timeout(&self) -> Option<Duration> {
        match self.config.connection.peer_stream_total_timeout_secs {
            0 => None,
            secs => Some(Duration::from_secs(secs)),
        }
    }
}

// ── Iteration 77: Test-visible helpers ──────────────────────────────────────

pub(crate) async fn drain_peer_stream_handlers_for_test(
    handlers: &mut tokio::task::JoinSet<Result<(), MeshTransportError>>,
    timeout: Duration,
) -> crate::lifecycle::PeerStreamDrainReport {
    drain_peer_stream_handlers(handlers, timeout).await
}

// ── Iteration 78: Test-visible helpers ──────────────────────────────────────

pub(crate) async fn drain_datagram_handlers_for_test(
    handlers: &mut tokio::task::JoinSet<Result<(), MeshTransportError>>,
    timeout: Duration,
) {
    MeshTransport::drain_datagram_handlers(handlers, timeout).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn drain_stream_handlers_aborts_hung_handlers() {
        let mut handlers = tokio::task::JoinSet::<Result<(), MeshTransportError>>::new();
        handlers.spawn(async { Ok(()) });
        handlers.spawn(std::future::pending::<Result<(), MeshTransportError>>());

        let report =
            drain_peer_stream_handlers_for_test(&mut handlers, Duration::from_millis(100)).await;

        assert!(
            report.aborted >= 1,
            "expected at least 1 aborted: {report:?}"
        );
        assert!(handlers.is_empty(), "JoinSet should be empty after drain");
    }

    #[tokio::test]
    async fn drain_datagram_handlers_aborts_hung_handlers() {
        let mut handlers = tokio::task::JoinSet::<Result<(), MeshTransportError>>::new();
        handlers.spawn(async { Ok(()) });
        handlers.spawn(std::future::pending::<Result<(), MeshTransportError>>());

        let start = std::time::Instant::now();
        drain_datagram_handlers_for_test(&mut handlers, Duration::from_millis(100)).await;
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_secs(2),
            "drain took too long: {elapsed:?}"
        );
        assert!(handlers.is_empty(), "JoinSet should be empty after drain");
    }

    // ── Iteration 80, Part D: Chunked encoding transforms-skip invariant ──

    /// Verify the body_encoding detection pipeline for all encoding types.
    ///
    /// The proxy code at `handle_http_proxy_stream` derives:
    ///     `skip_transforms = resp_head.body_encoding == HttpResponseBodyEncoding::Chunked`
    ///
    /// This test proves the detection step is correct for every encoding variant,
    /// ensuring chunked responses are marked "do not transform" and all other
    /// encodings are eligible for transforms.
    #[tokio::test]
    async fn body_encoding_detection_matches_transform_skip_invariant() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Helper: parse a response and return its body_encoding.
        async fn detect_encoding(response: &[u8]) -> HttpResponseBodyEncoding {
            let (mut client, mut server) = tokio::io::duplex(response.len());
            client.write_all(response).await.unwrap();
            client.shutdown().await.unwrap();
            let head = read_http_response_head(
                &mut server,
                Duration::from_secs(5),
                Duration::from_secs(10),
                8192,
            )
            .await
            .unwrap();
            head.body_encoding
        }

        // Chunked → skip transforms
        let enc = detect_encoding(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").await;
        assert_eq!(
            enc,
            HttpResponseBodyEncoding::Chunked,
            "chunked must be detected"
        );

        // Fixed-length → apply transforms
        let enc = detect_encoding(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").await;
        assert_eq!(
            enc,
            HttpResponseBodyEncoding::FixedLength,
            "fixed-length must be detected"
        );

        // Close-delimited HTTP/1.0 → apply transforms
        let enc = detect_encoding(b"HTTP/1.0 200 OK\r\n\r\nhello").await;
        assert_eq!(
            enc,
            HttpResponseBodyEncoding::CloseDelimited,
            "HTTP/1.0 close-delimited must be detected"
        );

        // Close-delimited HTTP/1.1 with Connection: close → apply transforms
        let enc = detect_encoding(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello").await;
        assert_eq!(
            enc,
            HttpResponseBodyEncoding::CloseDelimited,
            "HTTP/1.1 Connection: close must be detected"
        );

        // No body (204) → no transforms needed
        let enc = detect_encoding(b"HTTP/1.1 204 No Content\r\n\r\n").await;
        assert_eq!(
            enc,
            HttpResponseBodyEncoding::None,
            "204 must be None encoding"
        );

        // HTTP/1.1 ambiguous (no CL, no TE, no Connection: close) → None (caller rejects)
        let enc = detect_encoding(b"HTTP/1.1 200 OK\r\n\r\n").await;
        assert_eq!(
            enc,
            HttpResponseBodyEncoding::None,
            "ambiguous must be None"
        );
    }

    /// Verify that the chunked wire body is returned verbatim (no decoding,
    /// no truncation, no modification) — proving the raw bytes are preserved
    /// for the transform-skip path.
    #[tokio::test]
    async fn chunked_body_preserved_verbatim_through_parser() {
        // Build a complete chunked wire body: "hello world" in two chunks.
        let mut wire_body = Vec::new();
        wire_body.extend_from_slice(b"5\r\nhello\r\n");
        wire_body.extend_from_slice(b"6\r\n world\r\n");
        wire_body.extend_from_slice(b"0\r\n\r\n");

        let result = read_chunked_http_response_body(
            &wire_body[..],
            Vec::new(),
            Duration::from_secs(5),
            Duration::from_secs(10),
            65536,
            65536,
        )
        .await
        .unwrap();

        assert_eq!(
            result, wire_body,
            "chunked parser must return the complete wire body unchanged"
        );
    }

    // ── Iteration 82: Focused polish tests for response framing ──

    #[test]
    fn malformed_header_line_rejected() {
        let mut buffer = b"HTTP/1.1 200 OK\r\nBadHeader\r\n\r\n".to_vec();
        let result = try_parse_http_response_head(&mut buffer, 4096);
        assert!(result.is_err());
        match result.unwrap_err() {
            HttpResponseFramingError::MalformedHeaderLine(line) => {
                assert!(
                    line.contains("BadHeader"),
                    "error should reference the bad header: {line}"
                );
            }
            other => panic!("expected MalformedHeaderLine, got {:?}", other),
        }
    }

    #[test]
    fn folded_header_line_rejected() {
        let mut buffer = b"HTTP/1.1 200 OK\r\nX-Header: value\r\n folded-value\r\n\r\n".to_vec();
        let result = try_parse_http_response_head(&mut buffer, 4096);
        assert!(result.is_err());
        match result.unwrap_err() {
            HttpResponseFramingError::MalformedHeaderLine(line) => {
                assert!(
                    line.contains("folded-value"),
                    "error should reference the folded line: {line}"
                );
            }
            other => panic!("expected MalformedHeaderLine, got {:?}", other),
        }
    }

    #[test]
    fn empty_header_lines_are_skipped() {
        // Status line + bare \r\n (the header terminator) — should succeed.
        let mut buffer = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        let result = try_parse_http_response_head(&mut buffer, 4096);
        assert!(result.is_ok());
        let (head, _consumed) = result.unwrap().expect("should parse successfully");
        assert_eq!(head.status_code, 200);
    }

    #[test]
    fn pure_parser_enforces_header_limit() {
        let mut buffer = b"HTTP/1.1 200 OK\r\nX-Long: aaaaabbbbcccccdddddeeeee\r\n\r\n".to_vec();
        // max_header_bytes=10 is less than the actual header size.
        let result = try_parse_http_response_head(&mut buffer, 10);
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                HttpResponseFramingError::HeaderTooLarge
            ),
            "expected HeaderTooLarge"
        );
    }

    #[test]
    fn valid_headers_accepted() {
        let mut buffer =
            b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\nContent-Type: text/plain\r\n\r\n".to_vec();
        let result = try_parse_http_response_head(&mut buffer, 4096);
        assert!(result.is_ok());
        let (head, _consumed) = result.unwrap().expect("should parse successfully");
        assert_eq!(head.status_code, 200);
        assert_eq!(head.content_length, Some(42));
    }

    #[test]
    fn conflicting_content_length_rejected() {
        let mut buffer =
            b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\nContent-Length: 100\r\n\r\n".to_vec();
        let result = try_parse_http_response_head(&mut buffer, 4096);
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                HttpResponseFramingError::InvalidContentLength(_)
            ),
            "expected InvalidContentLength for conflicting values"
        );
    }

    #[test]
    fn duplicate_equal_content_length_accepted() {
        let mut buffer =
            b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\nContent-Length: 42\r\n\r\n".to_vec();
        let result = try_parse_http_response_head(&mut buffer, 4096);
        assert!(result.is_ok());
        let (head, _consumed) = result.unwrap().expect("should parse successfully");
        assert_eq!(head.content_length, Some(42));
    }

    #[test]
    fn chunked_and_content_length_rejected() {
        let mut buffer =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 10\r\n\r\n".to_vec();
        let result = try_parse_http_response_head(&mut buffer, 4096);
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                HttpResponseFramingError::InvalidContentLength(_)
            ),
            "expected InvalidContentLength for chunked + CL"
        );
    }

    #[test]
    fn unsupported_transfer_encoding_rejected() {
        let mut buffer = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n".to_vec();
        let result = try_parse_http_response_head(&mut buffer, 4096);
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                HttpResponseFramingError::UnsupportedTransferEncoding(_)
            ),
            "expected UnsupportedTransferEncoding"
        );
    }

    #[test]
    fn invalid_status_line_rejected() {
        let mut buffer = b"HTTP/1.1 2000 OK\r\n\r\n".to_vec();
        let result = try_parse_http_response_head(&mut buffer, 4096);
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                HttpResponseFramingError::InvalidStatusCode(_)
            ),
            "expected InvalidStatusCode"
        );
    }

    #[test]
    fn malformed_status_line_rejected() {
        let mut buffer = b"NOTHTTP 200 OK\r\n\r\n".to_vec();
        let result = try_parse_http_response_head(&mut buffer, 4096);
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                HttpResponseFramingError::MalformedStatusLine(_)
            ),
            "expected MalformedStatusLine"
        );
    }

    #[test]
    fn informational_1xx_returns_empty_body_prefix() {
        // 103 Early Hints — informational, body_prefix should be empty.
        let mut buffer = b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec();
        let result = try_parse_http_response_head(&mut buffer, 4096);
        assert!(result.is_ok());
        let (head, consumed) = result.unwrap().expect("should parse successfully");
        assert_eq!(head.status_code, 103);
        assert!(
            head.body_prefix.is_empty(),
            "informational response must have empty body_prefix"
        );
        // consumed should point past the first \r\n\r\n, into the second response.
        assert_eq!(&buffer[consumed..consumed + 5], b"HTTP/");
    }

    #[test]
    fn body_prefix_present_for_final_response() {
        let mut buffer = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloworld".to_vec();
        let result = try_parse_http_response_head(&mut buffer, 4096);
        assert!(result.is_ok());
        let (head, consumed) = result.unwrap().expect("should parse successfully");
        assert_eq!(head.status_code, 200);
        assert_eq!(head.body_prefix, b"helloworld");
        assert_eq!(
            consumed,
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n".len()
        );
    }

    #[test]
    fn header_limit_at_exact_boundary_accepted() {
        // Header exactly at the limit should be accepted.
        let header = b"HTTP/1.1 200 OK\r\nX-Header: short\r\n\r\n";
        let mut buffer = header.to_vec();
        let result = try_parse_http_response_head(&mut buffer, header.len());
        assert!(result.is_ok());
    }

    #[test]
    fn header_limit_one_byte_over_rejected() {
        let header = b"HTTP/1.1 200 OK\r\nX-Header: short\r\n\r\n";
        let mut buffer = header.to_vec();
        let result = try_parse_http_response_head(&mut buffer, header.len() - 1);
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                HttpResponseFramingError::HeaderTooLarge
            ),
            "expected HeaderTooLarge one byte over limit"
        );
    }

    #[test]
    fn connection_close_detected() {
        let mut buffer = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
        let result = try_parse_http_response_head(&mut buffer, 4096);
        assert!(result.is_ok());
        let (head, _consumed) = result.unwrap().expect("should parse successfully");
        assert!(head.connection_close);
        assert_eq!(head.body_encoding, HttpResponseBodyEncoding::CloseDelimited);
    }

    #[test]
    fn http10_default_close_delimited() {
        let mut buffer = b"HTTP/1.0 200 OK\r\n\r\n".to_vec();
        let result = try_parse_http_response_head(&mut buffer, 4096);
        assert!(result.is_ok());
        let (head, _consumed) = result.unwrap().expect("should parse successfully");
        assert_eq!(head.http_version, HttpVersion::Http10);
        assert_eq!(head.body_encoding, HttpResponseBodyEncoding::CloseDelimited);
    }

    #[test]
    fn chunked_encoding_detected() {
        let mut buffer = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        let result = try_parse_http_response_head(&mut buffer, 4096);
        assert!(result.is_ok());
        let (head, _consumed) = result.unwrap().expect("should parse successfully");
        assert!(head.chunked);
        assert_eq!(head.body_encoding, HttpResponseBodyEncoding::Chunked);
    }

    #[test]
    fn no_body_response_none_encoding() {
        let mut buffer = b"HTTP/1.1 204 No Content\r\n\r\n".to_vec();
        let result = try_parse_http_response_head(&mut buffer, 4096);
        assert!(result.is_ok());
        let (head, _consumed) = result.unwrap().expect("should parse successfully");
        assert_eq!(head.status_code, 204);
        assert_eq!(head.body_encoding, HttpResponseBodyEncoding::None);
    }
}
