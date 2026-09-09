//! Canonical HTTP/1 framing and authority policy (Phase 20).
//!
//! This module is the single fail-closed owner of transfer-framing and
//! host/authority validation for the HTTP/1 request path. Every protocol
//! frontend that evaluates equivalent HTTP semantics must call these helpers
//! (or prove equivalent policy with differential tests) before routing and
//! WAF evaluation see the request.
//!
//! Canonical order (see `architecture/http_ownership_convergence.md`):
//!
//! 1. `is_tls_client_hello` / `is_valid_http_request_start` — listener-level
//!    protocol sniffing (re exported here so `src/http` and `src/tls` share
//!    one implementation).
//! 2. `validate_transfer_framing` — `Content-Length` / `Transfer-Encoding`
//!    ambiguity rejects the request (duplicate `Content-Length`,
//!    `Content-Length` + `Transfer-Encoding`, unsupported codings, malformed
//!    lengths).
//! 3. `validate_host_authority` — duplicate `Host` and absolute-form vs
//!    origin-form authority conflicts reject the request.
//! 4. Downstream stages (`request_parse::extract_request_metadata`,
//!    routing, body policy, WAF) consume the single validated representation.
//!
//! Wire-level details owned elsewhere and intentionally not duplicated here:
//!
//! - obs-fold / header whitespace: rejected by hyper (HTTP/1 service) and by
//!   httparse (`early_parse::EarlyHttpParser` returns `None`) before policy
//!   runs.
//! - malformed chunk sizes / terminators: owned by hyper's `Incoming` body
//!   state machine; decode errors surface as `hyper::Error` and fail the
//!   request.
//! - content-encoding expansion bounds: enforced by body policy
//!   (`body_policy::collect_and_scan_request_body` via
//!   `max_streaming_body_size`) and upstream response limits, not by framing.
//! - HTTP/3 has no transfer-framing ambiguity (QUIC frames carry explicit
//!   lengths); only the overlapping `Host` duplicate check applies there.

use http::{HeaderMap, Uri, Version};

/// Valid request-line methods for listener-level protocol sniffing.
///
/// Canonical home (Phase 20): previously duplicated in
/// `src/http/server/connection_types.rs` and `src/tls/server.rs`.
pub const HTTP_VALID_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

/// Listener-level TLS ClientHello sniff (first bytes `0x16 0x03 0x00..0x03`).
///
/// Used to reject TLS on the plaintext HTTP port (and vice versa) when
/// `strict_protocol_validation` is enabled. Pure byte check, no allocation.
pub fn is_tls_client_hello(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && bytes[0] == 0x16 && bytes[1] == 0x03 && (bytes[2] <= 0x03)
}

/// Listener-level HTTP request-line sniff (`METHOD /... ` prefix).
///
/// Used to reject non-HTTP bytes on the HTTP port when
/// `strict_protocol_validation` is enabled. Pure byte check, no allocation.
pub fn is_valid_http_request_start(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }

    for method in HTTP_VALID_METHODS {
        let method_bytes = method.as_bytes();
        if bytes.len() > method_bytes.len()
            && bytes[..method_bytes.len()] == *method_bytes
            && bytes[method_bytes.len()] == b' '
        {
            return true;
        }
    }
    false
}

/// Fail-closed framing/authority rejection.
///
/// Every variant denies the request with `400` (`status()`); `candidate()`
/// projects onto the canonical enforcement vocabulary so disposition counters
/// stay on bounded labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingError {
    /// Two or more `Content-Length` values (even identical ones).
    DuplicateContentLength,
    /// `Content-Length` combined with any `Transfer-Encoding`.
    ContentLengthAndTransferEncoding,
    /// `Transfer-Encoding` names a coding the server does not implement.
    UnsupportedTransferCoding,
    /// `Content-Length` is not a valid decimal byte count.
    InvalidContentLength,
    /// Two or more `Host` headers (even identical ones).
    DuplicateHost,
    /// Missing `Host` where HTTP/1.1 requires it, or absolute-form
    /// authority conflicting with the `Host` header.
    InvalidHost,
}

impl FramingError {
    /// HTTP status rendered for every framing rejection.
    pub const fn status(self) -> u16 {
        400
    }

    /// Project a framing rejection onto the canonical enforcement contract.
    ///
    /// All variants deny (fail closed): a new variant that mapped to Allow
    /// would be a request-smuggling regression.
    pub const fn candidate(self) -> synvoid_core::enforcement::EnforcementCandidate {
        use synvoid_core::enforcement::{
            EnforcementCandidate, EnforcementClass, EnforcementReason, EnforcementSource,
        };
        let reason = match self {
            Self::DuplicateContentLength
            | Self::ContentLengthAndTransferEncoding
            | Self::UnsupportedTransferCoding
            | Self::InvalidContentLength => EnforcementReason::BodyTooLarge,
            Self::DuplicateHost | Self::InvalidHost => EnforcementReason::BodyBlocked,
        };
        EnforcementCandidate::new(
            EnforcementClass::Block,
            EnforcementSource::StreamingBodyScan,
            reason,
        )
    }
}

/// Transfer codings the server implements.
///
/// hyper decodes `chunked`; `identity` is a documented no-op. Anything else
/// (`gzip`, `xchunked`, …) as a transfer coding is rejected — content
/// compression belongs in `Content-Encoding`, which is bounded by body
/// policy, not by framing.
const SUPPORTED_TRANSFER_CODINGS: &[&str] = &["chunked", "identity"];

fn parse_content_lengths(headers: &HeaderMap) -> Result<Option<usize>, FramingError> {
    let mut values = headers
        .get_all(http::header::CONTENT_LENGTH)
        .iter()
        .peekable();
    if values.peek().is_none() {
        return Ok(None);
    }
    let mut canonical: Option<usize> = None;
    let mut count = 0usize;
    for value in values {
        count += 1;
        let raw = value
            .to_str()
            .map_err(|_| FramingError::InvalidContentLength)?;
        let trimmed = raw.trim();
        if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
            return Err(FramingError::InvalidContentLength);
        }
        let parsed: usize = trimmed
            .parse()
            .map_err(|_| FramingError::InvalidContentLength)?;
        match canonical {
            Some(first) if first != parsed => {
                return Err(FramingError::DuplicateContentLength);
            }
            Some(_) => {}
            None => canonical = Some(parsed),
        }
    }
    if count > 1 {
        // Fail closed on repeats even when identical: intermediaries have
        // historically disagreed on first-wins vs last-wins.
        return Err(FramingError::DuplicateContentLength);
    }
    Ok(canonical)
}

fn transfer_codings(headers: &HeaderMap) -> Result<Vec<String>, FramingError> {
    let mut codings = Vec::new();
    for value in headers.get_all(http::header::TRANSFER_ENCODING).iter() {
        let raw = value
            .to_str()
            .map_err(|_| FramingError::UnsupportedTransferCoding)?;
        for token in raw.split(',') {
            let coding = token
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if coding.is_empty() {
                return Err(FramingError::UnsupportedTransferCoding);
            }
            codings.push(coding);
        }
    }
    Ok(codings)
}

/// Validate `Content-Length` / `Transfer-Encoding` combination.
///
/// Returns the validated content length (`None` when chunked/absent).
/// Any ambiguity or unsupported coding is an error — the caller must reject
/// the request before routing and WAF evaluation.
pub fn validate_transfer_framing(headers: &HeaderMap) -> Result<Option<usize>, FramingError> {
    let content_length = parse_content_lengths(headers)?;
    let codings = transfer_codings(headers)?;

    if codings.is_empty() {
        return Ok(content_length);
    }

    if content_length.is_some() {
        return Err(FramingError::ContentLengthAndTransferEncoding);
    }

    for coding in &codings {
        if !SUPPORTED_TRANSFER_CODINGS.contains(&coding.as_str()) {
            return Err(FramingError::UnsupportedTransferCoding);
        }
    }

    Ok(None)
}

fn strip_userinfo(authority: &str) -> &str {
    authority.rsplit('@').next().unwrap_or(authority)
}

fn split_host_port(host: &str) -> (&str, Option<&str>) {
    if let Some(stripped) = host.strip_prefix('[') {
        // Bracketed IPv6 literal: `[::1]` or `[::1]:8080`.
        return match stripped.find(']') {
            Some(end) => {
                let after = &stripped[end + 1..];
                let port = after.strip_prefix(':').filter(|p| !p.is_empty());
                (&host[..end + 2], port)
            }
            None => (host, None),
        };
    }
    match host.rfind(':') {
        Some(idx) => (&host[..idx], Some(&host[idx + 1..])),
        None => (host, None),
    }
}

/// Validated authority for routing and logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAuthority {
    /// Effective host: the `Host` header, or the absolute-form URI
    /// authority when no `Host` header is present.
    pub host: String,
}

/// Validate `Host` / absolute-form authority.
///
/// - More than one `Host` header line rejects the request, even when the
///   values are identical.
/// - An absolute-form request target (`http://authority/path`) must agree
///   with the `Host` header when both are present.
/// - HTTP/1.1 without any host information rejects the request; older
///   versions and H2/H3-style requests without one pass through with an
///   empty host (matching historical routing behavior).
pub fn validate_host_authority(
    headers: &HeaderMap,
    uri: &Uri,
    version: Version,
) -> Result<ValidatedAuthority, FramingError> {
    let mut host_iter = headers.get_all(http::header::HOST).iter();
    let first = host_iter.next();
    if host_iter.next().is_some() {
        return Err(FramingError::DuplicateHost);
    }
    let header_host = first
        .map(|v| v.to_str().unwrap_or("").trim().to_string())
        .unwrap_or_default();

    let uri_authority = uri.authority().map(|a| a.to_string()).unwrap_or_default();

    if !header_host.is_empty() && !uri_authority.is_empty() {
        let header_lower = header_host.to_ascii_lowercase();
        let authority_lower = uri_authority.to_ascii_lowercase();
        // Compare host parts case-insensitively; when both carry an
        // explicit port the ports must agree as well.
        let (header_host_only, header_port) = split_host_port(strip_userinfo(&header_lower));
        let (uri_host_only, uri_port) = split_host_port(&authority_lower);
        let hosts_equal = header_host_only == uri_host_only
            && header_host_only
                .strip_suffix('.')
                .unwrap_or(header_host_only)
                == uri_host_only.strip_suffix('.').unwrap_or(uri_host_only);
        let ports_equal = match (header_port, uri_port) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        };
        if !hosts_equal || !ports_equal {
            return Err(FramingError::InvalidHost);
        }
        return Ok(ValidatedAuthority { host: header_host });
    }

    if !header_host.is_empty() {
        return Ok(ValidatedAuthority { host: header_host });
    }

    if !uri_authority.is_empty() {
        return Ok(ValidatedAuthority {
            host: uri_authority,
        });
    }

    if version == Version::HTTP_11 {
        return Err(FramingError::InvalidHost);
    }

    Ok(ValidatedAuthority {
        host: String::new(),
    })
}

/// Combined framing + authority validation for the HTTP/1 preflight path.
///
/// Runs `validate_transfer_framing` then `validate_host_authority` so there
/// is exactly one call site ordering to audit.
pub fn validate_request_framing(
    headers: &HeaderMap,
    uri: &Uri,
    version: Version,
) -> Result<(Option<usize>, ValidatedAuthority), FramingError> {
    let content_length = validate_transfer_framing(headers)?;
    let authority = validate_host_authority(headers, uri, version)?;
    Ok((content_length, authority))
}

#[cfg(test)]
mod tests {
    use super::*;
    use synvoid_core::enforcement::{EnforcementClass, EnforcementSource};

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                http::header::HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn framing_errors_are_terminal_and_fail_closed() {
        for error in [
            FramingError::DuplicateContentLength,
            FramingError::ContentLengthAndTransferEncoding,
            FramingError::UnsupportedTransferCoding,
            FramingError::InvalidContentLength,
            FramingError::DuplicateHost,
            FramingError::InvalidHost,
        ] {
            assert_eq!(error.status(), 400);
            let candidate = error.candidate();
            assert_eq!(candidate.class, EnforcementClass::Block);
            assert!(candidate.class.is_terminal());
            assert_eq!(candidate.source, EnforcementSource::StreamingBodyScan);
        }
    }

    #[test]
    fn single_content_length_accepted() {
        let h = headers(&[("content-length", "42")]);
        assert_eq!(validate_transfer_framing(&h), Ok(Some(42)));
    }

    #[test]
    fn absent_framing_accepted() {
        let h = headers(&[("x-custom", "1")]);
        assert_eq!(validate_transfer_framing(&h), Ok(None));
    }

    #[test]
    fn duplicate_conflicting_content_length_rejected() {
        let h = headers(&[("content-length", "5"), ("content-length", "10")]);
        assert_eq!(
            validate_transfer_framing(&h),
            Err(FramingError::DuplicateContentLength)
        );
    }

    #[test]
    fn duplicate_identical_content_length_rejected() {
        // Fail closed: intermediaries disagree on first-wins vs last-wins.
        let h = headers(&[("content-length", "5"), ("content-length", "5")]);
        assert_eq!(
            validate_transfer_framing(&h),
            Err(FramingError::DuplicateContentLength)
        );
    }

    #[test]
    fn comma_joined_content_length_rejected() {
        let h = headers(&[("content-length", "5, 5")]);
        assert_eq!(
            validate_transfer_framing(&h),
            Err(FramingError::InvalidContentLength)
        );
    }

    #[test]
    fn content_length_plus_transfer_encoding_rejected() {
        let h = headers(&[("content-length", "10"), ("transfer-encoding", "chunked")]);
        assert_eq!(
            validate_transfer_framing(&h),
            Err(FramingError::ContentLengthAndTransferEncoding)
        );
    }

    #[test]
    fn chunked_without_content_length_accepted() {
        let h = headers(&[("transfer-encoding", "chunked")]);
        assert_eq!(validate_transfer_framing(&h), Ok(None));
    }

    #[test]
    fn chunked_coding_is_case_insensitive() {
        let h = headers(&[("transfer-encoding", "Chunked")]);
        assert_eq!(validate_transfer_framing(&h), Ok(None));
    }

    #[test]
    fn obfuscated_chunked_coding_rejected() {
        for coding in ["xchunked", "chunkedx", "gzip2", ""] {
            let value = if coding.is_empty() {
                ",".to_string()
            } else {
                coding.to_string()
            };
            let h = headers(&[("transfer-encoding", value.as_str())]);
            assert_eq!(
                validate_transfer_framing(&h),
                Err(FramingError::UnsupportedTransferCoding),
                "coding {coding:?} must be rejected"
            );
        }
    }

    #[test]
    fn malformed_content_length_rejected() {
        for bad in ["not-a-number", "-5", "+5", "5.0", "", "  ", "0x10"] {
            let h = headers(&[("content-length", bad)]);
            assert_eq!(
                validate_transfer_framing(&h),
                Err(FramingError::InvalidContentLength),
                "content-length {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn content_length_overflow_rejected() {
        // Far beyond any plausible body; must not wrap or truncate.
        let h = headers(&[("content-length", "99999999999999999999999")]);
        assert_eq!(
            validate_transfer_framing(&h),
            Err(FramingError::InvalidContentLength)
        );
    }

    #[test]
    fn duplicate_host_rejected_even_when_identical() {
        let h = headers(&[("host", "example.com"), ("host", "example.com")]);
        let uri: Uri = "/".parse().unwrap();
        assert_eq!(
            validate_host_authority(&h, &uri, Version::HTTP_11),
            Err(FramingError::DuplicateHost)
        );
    }

    #[test]
    fn absolute_form_matching_host_accepted() {
        let h = headers(&[("host", "example.com")]);
        let uri: Uri = "http://example.com/path?q=1".parse().unwrap();
        assert_eq!(
            validate_host_authority(&h, &uri, Version::HTTP_11),
            Ok(ValidatedAuthority {
                host: "example.com".to_string()
            })
        );
    }

    #[test]
    fn absolute_form_conflicting_host_rejected() {
        let h = headers(&[("host", "example.com")]);
        let uri: Uri = "http://evil.test/path".parse().unwrap();
        assert_eq!(
            validate_host_authority(&h, &uri, Version::HTTP_11),
            Err(FramingError::InvalidHost)
        );
    }

    #[test]
    fn absolute_form_without_host_header_uses_authority() {
        let h = headers(&[]);
        let uri: Uri = "http://example.com/path".parse().unwrap();
        assert_eq!(
            validate_host_authority(&h, &uri, Version::HTTP_11),
            Ok(ValidatedAuthority {
                host: "example.com".to_string()
            })
        );
    }

    #[test]
    fn missing_host_on_http11_rejected() {
        let h = headers(&[]);
        let uri: Uri = "/".parse().unwrap();
        assert_eq!(
            validate_host_authority(&h, &uri, Version::HTTP_11),
            Err(FramingError::InvalidHost)
        );
    }

    #[test]
    fn missing_host_on_http10_tolerated() {
        let h = headers(&[]);
        let uri: Uri = "/".parse().unwrap();
        assert_eq!(
            validate_host_authority(&h, &uri, Version::HTTP_10),
            Ok(ValidatedAuthority {
                host: String::new()
            })
        );
    }

    #[test]
    fn protocol_sniff_helpers_behave() {
        assert!(is_tls_client_hello(&[0x16, 0x03, 0x01]));
        assert!(!is_tls_client_hello(b"GET / HTTP/1.1\r\n"));
        assert!(!is_tls_client_hello(&[]));
        assert!(is_valid_http_request_start(b"GET / HTTP/1.1\r\n"));
        assert!(is_valid_http_request_start(
            b"POST /path?query=value HTTP/1.1\r\n"
        ));
        assert!(!is_valid_http_request_start(b""));
        assert!(!is_valid_http_request_start(b"GET/ HTTP/1.1"));
        assert!(!is_valid_http_request_start(b"INVALID / HTTP/1.1\r\n"));
    }
}
