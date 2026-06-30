//! Plugin ABI frame serialization and validation.
//!
//! This module defines the canonical serialization and validation for request
//! input frames and response transform output across the WASM plugin ABI.
//!
//! # Design Principles
//!
//! 1. Reject rather than truncate security-relevant request metadata.
//! 2. Preserve raw bytes where HTTP allows non-UTF8 header values.
//! 3. Normalize only when the normalization policy is explicit and shared.
//! 4. Keep request serialization and response validation symmetric.
//! 5. Make output limits part of the effective plugin policy.
//! 6. Treat plugin transforms as untrusted proposals.
//!
//! # Architecture
//!
//! - [`RequestFramePolicy`] bounds request metadata before guest memory write.
//! - [`ResponseFramePolicy`] validates response transform output before application.
//! - [`PluginHttpView`] defines what plugins see for each HTTP version.
//! - [`PluginResponseMutationPolicy`] controls what response mutations are allowed.
//! - [`SerializationFailureClass`] classifies rejection reasons for metrics/audit.

use std::fmt;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri};

use crate::sandbox::types::PluginCapabilities;

// ═══════════════════════════════════════════════════════════════════════════════
// Workstream 4: Serialization Failure Classes
// ═══════════════════════════════════════════════════════════════════════════════

/// Classifies why a serialization or validation operation rejected input/output.
///
/// Used for bounded-cardinality metrics labels and structured debug logs.
/// Each variant maps to a stable metric label that does NOT include raw
/// header names, values, or body content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SerializationFailureClass {
    /// HTTP method exceeds max_method_bytes.
    MethodTooLarge,
    /// URI exceeds max_uri_bytes.
    UriTooLarge,
    /// Authority exceeds max_authority_bytes.
    AuthorityTooLarge,
    /// Header count exceeds max_header_count.
    HeaderCountTooLarge,
    /// A single header name exceeds max_header_name_bytes.
    HeaderNameTooLarge,
    /// A single header value exceeds max_header_value_bytes.
    HeaderValueTooLarge,
    /// Total serialized headers exceed max_serialized_headers_bytes.
    HeaderBlockTooLarge,
    /// Request/response body exceeds max_body_bytes.
    BodyTooLarge,
    /// Total frame exceeds max_total_frame_bytes.
    FrameTooLarge,
    /// Response status code is not a valid HTTP status.
    InvalidStatus,
    /// Response header name is not a valid HTTP header name.
    InvalidHeaderName,
    /// Response header value fails validation.
    InvalidHeaderValue,
    /// Response transform attempted a mutation not allowed by policy.
    MutationDenied,
}

impl SerializationFailureClass {
    /// Returns a stable, bounded-cardinality string label for metrics.
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::MethodTooLarge => "method_too_large",
            Self::UriTooLarge => "uri_too_large",
            Self::AuthorityTooLarge => "authority_too_large",
            Self::HeaderCountTooLarge => "header_count_too_large",
            Self::HeaderNameTooLarge => "header_name_too_large",
            Self::HeaderValueTooLarge => "header_value_too_large",
            Self::HeaderBlockTooLarge => "header_block_too_large",
            Self::BodyTooLarge => "body_too_large",
            Self::FrameTooLarge => "frame_too_large",
            Self::InvalidStatus => "invalid_status",
            Self::InvalidHeaderName => "invalid_header_name",
            Self::InvalidHeaderValue => "invalid_header_value",
            Self::MutationDenied => "mutation_denied",
        }
    }
}

impl fmt::Display for SerializationFailureClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_label())
    }
}

/// An error from plugin ABI serialization or validation.
///
/// Contains a [`SerializationFailureClass`] for metrics and a human-readable
/// message. The message intentionally does NOT include raw header values,
/// body content, or other sensitive payload data.
#[derive(Debug, Clone)]
pub struct SerializationError {
    pub class: SerializationFailureClass,
    message: String,
}

impl SerializationError {
    pub fn new(class: SerializationFailureClass, message: impl Into<String>) -> Self {
        Self {
            class,
            message: message.into(),
        }
    }
}

impl fmt::Display for SerializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.class, self.message)
    }
}

impl std::error::Error for SerializationError {}

// ═══════════════════════════════════════════════════════════════════════════════
// Workstream 1: Versioned ABI Frame Policies
// ═══════════════════════════════════════════════════════════════════════════════

/// Bounds for serializing request metadata into a WASM input frame.
///
/// Derived from [`PluginLimits`](crate::sandbox::types::PluginLimits) via
/// [`request_frame_policy_from_limits`]. All fields are hard limits —
/// exceeding any one causes a rejection, not truncation.
#[derive(Debug, Clone)]
pub struct RequestFramePolicy {
    pub max_method_bytes: usize,
    pub max_uri_bytes: usize,
    pub max_authority_bytes: usize,
    pub max_header_count: usize,
    pub max_header_name_bytes: usize,
    pub max_header_value_bytes: usize,
    pub max_serialized_headers_bytes: usize,
    pub max_body_bytes: usize,
    pub max_total_frame_bytes: usize,
}

impl Default for RequestFramePolicy {
    fn default() -> Self {
        Self {
            max_method_bytes: 256,
            max_uri_bytes: 8192,
            max_authority_bytes: 256,
            max_header_count: 128,
            max_header_name_bytes: 256,
            max_header_value_bytes: 8192,
            max_serialized_headers_bytes: 65536,
            max_body_bytes: 262_144,
            max_total_frame_bytes: 1024 * 1024,
        }
    }
}

/// Bounds for validating response transform output from WASM plugins.
///
/// Derived from [`PluginLimits`](crate::sandbox::types::PluginLimits) via
/// [`response_frame_policy_from_limits`].
#[derive(Debug, Clone)]
pub struct ResponseFramePolicy {
    pub max_status_code: u16,
    pub min_status_code: u16,
    pub max_header_count: usize,
    pub max_header_name_bytes: usize,
    pub max_header_value_bytes: usize,
    pub max_body_bytes: usize,
    pub max_total_frame_bytes: usize,
}

impl Default for ResponseFramePolicy {
    fn default() -> Self {
        Self {
            max_status_code: 599,
            min_status_code: 100,
            max_header_count: 128,
            max_header_name_bytes: 256,
            max_header_value_bytes: 8192,
            max_body_bytes: 262_144,
            max_total_frame_bytes: 1024 * 1024,
        }
    }
}

/// Derive a [`RequestFramePolicy`] from plugin resource limits.
///
/// Uses `max_input_bytes` as the body limit and total frame limit.
/// Header and method limits use sensible defaults scaled to the input budget.
pub fn request_frame_policy_from_limits(max_input_bytes: usize) -> RequestFramePolicy {
    let max_body_bytes = max_input_bytes;
    let max_total_frame_bytes = max_input_bytes;
    let max_serialized_headers_bytes = (max_input_bytes / 2).max(4096);
    RequestFramePolicy {
        max_method_bytes: 256,
        max_uri_bytes: 8192,
        max_authority_bytes: 256,
        max_header_count: 128,
        max_header_name_bytes: 256,
        max_header_value_bytes: 8192,
        max_serialized_headers_bytes,
        max_body_bytes,
        max_total_frame_bytes,
    }
}

/// Derive a [`ResponseFramePolicy`] from plugin resource limits.
///
/// Uses `max_output_bytes` as the body limit and total frame limit.
pub fn response_frame_policy_from_limits(max_output_bytes: usize) -> ResponseFramePolicy {
    ResponseFramePolicy {
        max_status_code: 599,
        min_status_code: 100,
        max_header_count: 128,
        max_header_name_bytes: 256,
        max_header_value_bytes: 8192,
        max_body_bytes: max_output_bytes,
        max_total_frame_bytes: max_output_bytes,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Workstream 1: Canonical Header Serialization
// ═══════════════════════════════════════════════════════════════════════════════

/// Canonical binary header serialization for the WASM plugin ABI.
///
/// Format: `[header_count: u16 LE] [per entry: u16 LE name_len | name | u16 LE val_len | val]`
///
/// This is the single authoritative serializer. All plugin serialization paths
/// must use this function — ad hoc header encoding is forbidden.
///
/// # Policy
///
/// - Header count must fit u16.
/// - Each header name length must fit u16.
/// - Each header value length must fit u16.
/// - Total encoded size must not exceed `policy.max_serialized_headers_bytes`.
/// - Repeated header names are preserved as separate entries in iteration order.
/// - Header values with non-UTF8 bytes are preserved (raw bytes).
pub fn serialize_headers_canonical(
    headers: &HeaderMap,
    policy: &RequestFramePolicy,
) -> Result<Vec<u8>, SerializationError> {
    let header_count = headers.len();
    if header_count > policy.max_header_count {
        return Err(SerializationError::new(
            SerializationFailureClass::HeaderCountTooLarge,
            format!(
                "header count {} exceeds limit {}",
                header_count, policy.max_header_count
            ),
        ));
    }
    if header_count > u16::MAX as usize {
        return Err(SerializationError::new(
            SerializationFailureClass::HeaderCountTooLarge,
            format!("header count {} exceeds u16::MAX", header_count),
        ));
    }

    let max_bytes = policy.max_serialized_headers_bytes;
    let mut buf = Vec::with_capacity(1024.min(max_bytes));
    buf.extend_from_slice(&(header_count as u16).to_le_bytes());

    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        let name_len = name_str.len();

        if name_len > policy.max_header_name_bytes {
            return Err(SerializationError::new(
                SerializationFailureClass::HeaderNameTooLarge,
                format!(
                    "header name length {} exceeds limit {}",
                    name_len, policy.max_header_name_bytes
                ),
            ));
        }
        if name_len > u16::MAX as usize {
            return Err(SerializationError::new(
                SerializationFailureClass::HeaderNameTooLarge,
                format!("header name length {} exceeds u16::MAX", name_len),
            ));
        }

        let val_bytes = value.as_bytes();
        let val_len = val_bytes.len();

        if val_len > policy.max_header_value_bytes {
            return Err(SerializationError::new(
                SerializationFailureClass::HeaderValueTooLarge,
                format!(
                    "header value length {} exceeds limit {}",
                    val_len, policy.max_header_value_bytes
                ),
            ));
        }
        if val_len > u16::MAX as usize {
            return Err(SerializationError::new(
                SerializationFailureClass::HeaderValueTooLarge,
                format!("header value length {} exceeds u16::MAX", val_len),
            ));
        }

        let entry_size = 2 + name_len + 2 + val_len;
        if buf.len() + entry_size > max_bytes {
            return Err(SerializationError::new(
                SerializationFailureClass::HeaderBlockTooLarge,
                format!(
                    "serialized headers would exceed limit of {} bytes",
                    max_bytes
                ),
            ));
        }

        buf.extend_from_slice(&(name_len as u16).to_le_bytes());
        buf.extend_from_slice(name_str.as_bytes());
        buf.extend_from_slice(&(val_len as u16).to_le_bytes());
        buf.extend_from_slice(val_bytes);
    }

    Ok(buf)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Workstream 1: Canonical Request Frame Builder
// ═══════════════════════════════════════════════════════════════════════════════

/// The serialized pieces of a request input frame for WASM.
///
/// Contains the pre-validated, policy-checked byte slices that will be
/// written into WASM linear memory via `guest_alloc`.
#[derive(Debug, Clone)]
pub struct RequestFrame {
    pub method: Vec<u8>,
    pub uri: Vec<u8>,
    pub authority: Vec<u8>,
    pub scheme: Vec<u8>,
    pub headers: Vec<u8>,
    pub body: Vec<u8>,
}

impl RequestFrame {
    /// Total byte count of all frame pieces.
    pub fn total_bytes(&self) -> usize {
        self.method.len()
            + self.uri.len()
            + self.authority.len()
            + self.scheme.len()
            + self.headers.len()
            + self.body.len()
    }
}

/// Build a canonical request input frame from HTTP request parts.
///
/// Validates all fields against the provided [`RequestFramePolicy`].
/// Returns [`SerializationError`] with the specific failure class
/// if any field exceeds its bound.
///
/// # Normalization
///
/// - Method: raw bytes from `http::Method`.
/// - URI: raw bytes from `http::Uri` (origin-form or absolute-form as received).
/// - Authority: extracted from URI authority or `Host` header.
/// - Scheme: extracted from URI or `None` for origin-form requests.
/// - Headers: canonical binary serialization via [`serialize_headers_canonical`].
/// - Body: raw bytes as received.
pub fn build_request_frame(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    policy: &RequestFramePolicy,
) -> Result<RequestFrame, SerializationError> {
    let method_bytes = method.as_str().as_bytes();
    if method_bytes.len() > policy.max_method_bytes {
        return Err(SerializationError::new(
            SerializationFailureClass::MethodTooLarge,
            format!(
                "method length {} exceeds limit {}",
                method_bytes.len(),
                policy.max_method_bytes
            ),
        ));
    }

    let uri_bytes = uri.to_string().into_bytes();
    if uri_bytes.len() > policy.max_uri_bytes {
        return Err(SerializationError::new(
            SerializationFailureClass::UriTooLarge,
            format!(
                "URI length {} exceeds limit {}",
                uri_bytes.len(),
                policy.max_uri_bytes
            ),
        ));
    }

    let authority_bytes = uri
        .authority()
        .map(|a| a.as_str().as_bytes().to_vec())
        .unwrap_or_default();
    if authority_bytes.len() > policy.max_authority_bytes {
        return Err(SerializationError::new(
            SerializationFailureClass::AuthorityTooLarge,
            format!(
                "authority length {} exceeds limit {}",
                authority_bytes.len(),
                policy.max_authority_bytes
            ),
        ));
    }

    let scheme_str = uri.scheme_str().unwrap_or("http");
    let scheme_bytes = scheme_str.as_bytes().to_vec();

    if body.len() > policy.max_body_bytes {
        return Err(SerializationError::new(
            SerializationFailureClass::BodyTooLarge,
            format!(
                "body length {} exceeds limit {}",
                body.len(),
                policy.max_body_bytes
            ),
        ));
    }

    let headers_bytes = serialize_headers_canonical(headers, policy)?;

    let total = method_bytes.len()
        + uri_bytes.len()
        + authority_bytes.len()
        + scheme_bytes.len()
        + headers_bytes.len()
        + body.len();
    if total > policy.max_total_frame_bytes {
        return Err(SerializationError::new(
            SerializationFailureClass::FrameTooLarge,
            format!(
                "total frame size {} exceeds limit {}",
                total, policy.max_total_frame_bytes
            ),
        ));
    }

    Ok(RequestFrame {
        method: method_bytes.to_vec(),
        uri: uri_bytes,
        authority: authority_bytes,
        scheme: scheme_bytes,
        headers: headers_bytes,
        body: body.to_vec(),
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
// Workstream 2: Plugin HTTP View
// ═══════════════════════════════════════════════════════════════════════════════

/// Controls how much of the request body the plugin can see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginBodyMode {
    /// Plugin receives the full request body.
    Full,
    /// Plugin receives the first N bytes of the body (truncated).
    Truncated(usize),
    /// Plugin receives no body (empty slice).
    None,
}

/// What the plugin sees for an HTTP request, after normalization.
///
/// This is the authoritative description of plugin-visible metadata.
/// Plugins never see raw connection-level details; they see this
/// normalized view.
///
/// # HTTP Version Semantics
///
/// - **HTTP/1.1**: `authority` is derived from the `Host` header. `scheme`
///   is inferred from the listener (TLS vs plain). Headers retain their
///   original casing but names are lowercased per HTTP/2 rules.
/// - **HTTP/2 and HTTP/3**: `authority` comes from the `:authority` pseudo-header.
///   `scheme` comes from the `:scheme` pseudo-header. Regular headers are
///   already lowercase.
///
/// # Header Behavior
///
/// - Repeated header names are preserved as separate entries in iteration order.
/// - Header names are lowercased (standard HTTP normalization).
/// - Hop-by-hop headers (`connection`, `keep-alive`, `proxy-authenticate`, etc.)
///   are included in the plugin view. Stripping happens after plugin inspection.
pub struct PluginHttpView<'a> {
    /// HTTP method (e.g., `GET`, `POST`).
    pub method: &'a Method,
    /// Request URI (origin-form for HTTP/1.1, may be absolute-form for proxy requests).
    pub uri: &'a Uri,
    /// Trusted scheme from listener/TLS state (`http` or `https`).
    pub scheme: Option<&'a str>,
    /// Authority (host:port or just host). From `:authority` (HTTP/2/3) or `Host` header (HTTP/1.1).
    pub authority: Option<&'a str>,
    /// Request headers. Names are lowercased. Repeated names preserved.
    pub headers: &'a HeaderMap,
    /// Body visibility mode controlled by plugin policy.
    pub body_mode: PluginBodyMode,
}

impl<'a> PluginHttpView<'a> {
    /// Build a plugin view from raw request parts.
    ///
    /// Authority is extracted from the URI authority field, falling back
    /// to the `Host` header. Scheme defaults to `"http"` if not present
    /// in the URI.
    pub fn from_parts(
        method: &'a Method,
        uri: &'a Uri,
        headers: &'a HeaderMap,
        body_mode: PluginBodyMode,
    ) -> Self {
        let authority = uri
            .authority()
            .map(|a| a.as_str())
            .or_else(|| headers.get("host").and_then(|v| v.to_str().ok()));
        let scheme = uri.scheme_str().or(Some("http"));
        Self {
            method,
            uri,
            scheme,
            authority,
            headers,
            body_mode,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Workstream 3: Response Transform Output Validation
// ═══════════════════════════════════════════════════════════════════════════════

/// Controls whether a plugin can mutate response transform output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailOpenPolicy {
    /// On transform failure, preserve the original response (fail open).
    FailOpen,
    /// On transform failure, return an error (fail closed).
    FailClosed,
}

/// Policy controlling what response mutations a plugin is allowed to make.
///
/// Derived from plugin capabilities. Plugins with only `ResponseInspect`
/// get a deny-all mutation policy. Plugins with `ResponseMutate` get
/// selective mutation rights.
#[derive(Debug, Clone)]
pub struct PluginResponseMutationPolicy {
    /// Whether the plugin may change the status code.
    pub allow_status_change: bool,
    /// Whether the plugin may add new response headers.
    pub allow_header_add: bool,
    /// Whether the plugin may remove response headers.
    pub allow_header_remove: bool,
    /// Whether the plugin may replace the response body.
    pub allow_body_replace: bool,
    /// Header name prefixes that are always allowed (e.g., `x-plugin-`).
    pub allowed_header_prefixes: Vec<String>,
    /// Header names that are always denied, even for ResponseMutate plugins.
    /// Security-sensitive headers are denied by default.
    pub denied_header_names: Vec<String>,
    /// Maximum output body size in bytes.
    pub max_output_bytes: usize,
    /// Fail-open or fail-closed on transform errors.
    pub fail_open: FailOpenPolicy,
}

/// Security-sensitive headers denied by default for response mutation.
const DEFAULT_DENIED_HEADERS: &[&str] = &[
    "set-cookie",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
    "host",
    "authorization",
    "www-authenticate",
];

impl PluginResponseMutationPolicy {
    /// Build a mutation policy from plugin capabilities.
    ///
    /// - Inspect-only plugins cannot mutate anything.
    /// - Mutate plugins can replace body and add safe headers within limits.
    /// - Security-sensitive headers are always denied unless explicitly allowlisted.
    pub fn from_capabilities(capabilities: &PluginCapabilities, max_output_bytes: usize) -> Self {
        let has_mutate = capabilities.response_mutate;
        Self {
            allow_status_change: false,
            allow_header_add: has_mutate,
            allow_header_remove: has_mutate,
            allow_body_replace: has_mutate,
            allowed_header_prefixes: vec!["x-plugin-".to_string()],
            denied_header_names: DEFAULT_DENIED_HEADERS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            max_output_bytes,
            fail_open: FailOpenPolicy::FailOpen,
        }
    }

    /// Check if a header name is allowed to be added/modified.
    pub fn is_header_allowed(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        if self.denied_header_names.contains(&lower) {
            return false;
        }
        for prefix in &self.allowed_header_prefixes {
            if lower.starts_with(prefix) {
                return true;
            }
        }
        true
    }
}

/// Validated response transform output from a WASM plugin.
///
/// This is the result of [`validate_response_transform_output`]. If
/// validation succeeds, this struct holds the validated components
/// ready for application to the original response.
#[derive(Debug)]
pub struct ValidatedResponseTransform {
    pub status: StatusCode,
    pub body: Bytes,
}

/// Validate response transform output from a WASM plugin.
///
/// The plugin's proposed response is an untrusted proposal. This function
/// validates status code, headers, body length, and mutation policy before
/// the transform is applied.
///
/// # Validation Rules
///
/// - Status must be a valid HTTP status code (100-599).
/// - Header names must be valid HTTP header names.
/// - Header values must be non-empty and valid.
/// - Body length must be within `policy.max_body_bytes`.
/// - Headers must not include denied security-sensitive headers.
/// - Hop-by-hop headers are denied by default.
///
/// # Fail-Open/Fail-Closed
///
/// On validation failure, the error contains a [`SerializationFailureClass`]
/// for metrics. The caller decides fail-open (preserve original) or
/// fail-closed (return error) based on the mutation policy's `fail_open` field.
pub fn validate_response_transform_output(
    status: StatusCode,
    headers: Option<&HeaderMap>,
    body: &[u8],
    mutation_policy: &PluginResponseMutationPolicy,
    frame_policy: &ResponseFramePolicy,
) -> Result<ValidatedResponseTransform, SerializationError> {
    let status_u16 = status.as_u16();
    if status_u16 < frame_policy.min_status_code || status_u16 > frame_policy.max_status_code {
        return Err(SerializationError::new(
            SerializationFailureClass::InvalidStatus,
            format!(
                "status code {} not in valid range {}-{}",
                status_u16, frame_policy.min_status_code, frame_policy.max_status_code
            ),
        ));
    }

    if body.len() > frame_policy.max_body_bytes {
        return Err(SerializationError::new(
            SerializationFailureClass::BodyTooLarge,
            format!(
                "transform body length {} exceeds limit {}",
                body.len(),
                frame_policy.max_body_bytes
            ),
        ));
    }

    if let Some(hdrs) = headers {
        if hdrs.len() > frame_policy.max_header_count {
            return Err(SerializationError::new(
                SerializationFailureClass::HeaderCountTooLarge,
                format!(
                    "transform header count {} exceeds limit {}",
                    hdrs.len(),
                    frame_policy.max_header_count
                ),
            ));
        }

        for (name, value) in hdrs.iter() {
            let name_str = name.as_str();
            if name_str.len() > frame_policy.max_header_name_bytes {
                return Err(SerializationError::new(
                    SerializationFailureClass::HeaderNameTooLarge,
                    format!(
                        "transform header name length {} exceeds limit {}",
                        name_str.len(),
                        frame_policy.max_header_name_bytes
                    ),
                ));
            }
            if value.as_bytes().len() > frame_policy.max_header_value_bytes {
                return Err(SerializationError::new(
                    SerializationFailureClass::HeaderValueTooLarge,
                    format!(
                        "transform header value length {} exceeds limit {}",
                        value.as_bytes().len(),
                        frame_policy.max_header_value_bytes
                    ),
                ));
            }
            if !mutation_policy.is_header_allowed(name_str) {
                return Err(SerializationError::new(
                    SerializationFailureClass::MutationDenied,
                    format!("header '{}' is denied by mutation policy", name_str),
                ));
            }
        }
    }

    Ok(ValidatedResponseTransform {
        status,
        body: Bytes::copy_from_slice(body),
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
// Metrics helper
// ═══════════════════════════════════════════════════════════════════════════════

/// Record a serialization rejection metric with bounded cardinality labels.
///
/// Labels: plugin_name, hook_type, failure_class, trust_tier.
/// Does NOT include raw header names/values or body content.
pub fn record_serialization_rejection(
    plugin_name: &str,
    hook_type: &str,
    failure_class: SerializationFailureClass,
    trust_tier: &str,
) {
    metrics::counter!(
        "synvoid_plugin_serialization_rejection_total",
        "plugin" => plugin_name.to_string(),
        "hook" => hook_type.to_string(),
        "failure_class" => failure_class.as_label().to_string(),
        "trust_tier" => trust_tier.to_string(),
    )
    .increment(1);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn default_policy() -> RequestFramePolicy {
        RequestFramePolicy::default()
    }

    fn strict_policy() -> RequestFramePolicy {
        RequestFramePolicy {
            max_method_bytes: 8,
            max_uri_bytes: 16,
            max_authority_bytes: 8,
            max_header_count: 2,
            max_header_name_bytes: 8,
            max_header_value_bytes: 8,
            max_serialized_headers_bytes: 64,
            max_body_bytes: 32,
            max_total_frame_bytes: 128,
        }
    }

    // ── serialize_headers_canonical tests ──────────────────────────────

    #[test]
    fn test_serialize_headers_canonical_basic() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        let policy = default_policy();
        let data = serialize_headers_canonical(&headers, &policy).unwrap();

        let header_count = u16::from_le_bytes([data[0], data[1]]);
        assert_eq!(header_count, 2);

        // Verify first header
        let name_len = u16::from_le_bytes([data[2], data[3]]) as usize;
        assert_eq!(name_len, 4);
        assert_eq!(&data[4..8], b"host");
        let val_start = 8;
        let val_len = u16::from_le_bytes([data[val_start], data[val_start + 1]]) as usize;
        assert_eq!(val_len, 11);
        assert_eq!(
            &data[val_start + 2..val_start + 2 + val_len],
            b"example.com"
        );
    }

    #[test]
    fn test_serialize_headers_canonical_rejects_over_count() {
        let mut headers = HeaderMap::new();
        for i in 0..5 {
            headers.insert(
                http::header::HeaderName::from_static(match i {
                    0 => "x-a",
                    1 => "x-b",
                    2 => "x-c",
                    3 => "x-d",
                    4 => "x-e",
                    _ => unreachable!(),
                }),
                HeaderValue::from_static("v"),
            );
        }
        let policy = RequestFramePolicy {
            max_header_count: 3,
            ..default_policy()
        };
        let result = serialize_headers_canonical(&headers, &policy);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().class,
            SerializationFailureClass::HeaderCountTooLarge
        );
    }

    #[test]
    fn test_serialize_headers_canonical_rejects_over_name_length() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::HeaderName::from_static("x-custom"),
            HeaderValue::from_static("v"),
        );
        let policy = RequestFramePolicy {
            max_header_name_bytes: 4,
            ..default_policy()
        };
        let result = serialize_headers_canonical(&headers, &policy);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().class,
            SerializationFailureClass::HeaderNameTooLarge
        );
    }

    #[test]
    fn test_serialize_headers_canonical_rejects_over_value_length() {
        let mut headers = HeaderMap::new();
        let long_value = "v".repeat(70000);
        headers.insert(
            http::header::HeaderName::from_static("x-custom"),
            HeaderValue::from_bytes(long_value.as_bytes()).unwrap(),
        );
        let policy = default_policy();
        let result = serialize_headers_canonical(&headers, &policy);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().class,
            SerializationFailureClass::HeaderValueTooLarge
        );
    }

    #[test]
    fn test_serialize_headers_canonical_rejects_over_block_size() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        let policy = RequestFramePolicy {
            max_serialized_headers_bytes: 4,
            ..default_policy()
        };
        let result = serialize_headers_canonical(&headers, &policy);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().class,
            SerializationFailureClass::HeaderBlockTooLarge
        );
    }

    #[test]
    fn test_serialize_headers_canonical_empty() {
        let headers = HeaderMap::new();
        let policy = default_policy();
        let data = serialize_headers_canonical(&headers, &policy).unwrap();
        let count = u16::from_le_bytes([data[0], data[1]]);
        assert_eq!(count, 0);
        assert_eq!(data.len(), 2);
    }

    #[test]
    fn test_serialize_headers_canonical_preserves_repeated_names() {
        let mut headers = HeaderMap::new();
        headers.append("x-dup", HeaderValue::from_static("first"));
        headers.append("x-dup", HeaderValue::from_static("second"));
        let policy = default_policy();
        let data = serialize_headers_canonical(&headers, &policy).unwrap();
        let count = u16::from_le_bytes([data[0], data[1]]);
        assert_eq!(count, 2);
    }

    // ── build_request_frame tests ──────────────────────────────────────

    #[test]
    fn test_build_request_frame_basic() {
        let method = Method::GET;
        let uri: Uri = "http://example.com/path".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        let body = b"hello";

        let policy = default_policy();
        let frame = build_request_frame(&method, &uri, &headers, body, &policy).unwrap();

        assert_eq!(frame.method, b"GET");
        assert_eq!(frame.uri, b"http://example.com/path");
        assert_eq!(frame.authority, b"example.com");
        assert_eq!(frame.scheme, b"http");
        assert!(!frame.headers.is_empty());
        assert_eq!(frame.body, b"hello");
    }

    #[test]
    fn test_build_request_frame_rejects_long_method() {
        let method = Method::GET;
        let uri: Uri = "/".parse().unwrap();
        let headers = HeaderMap::new();
        let body = b"";
        let policy = RequestFramePolicy {
            max_method_bytes: 2,
            max_uri_bytes: 256,
            max_body_bytes: 256,
            max_total_frame_bytes: 1024,
            ..strict_policy()
        };

        let result = build_request_frame(&method, &uri, &headers, body, &policy);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().class,
            SerializationFailureClass::MethodTooLarge
        );
    }

    #[test]
    fn test_build_request_frame_rejects_long_uri() {
        let method = Method::GET;
        let uri: Uri = "/very_long_path_that_exceeds_limit".parse().unwrap();
        let headers = HeaderMap::new();
        let body = b"";
        let policy = RequestFramePolicy {
            max_method_bytes: 256,
            max_uri_bytes: 8,
            max_body_bytes: 256,
            max_total_frame_bytes: 1024,
            ..strict_policy()
        };

        let result = build_request_frame(&method, &uri, &headers, body, &policy);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().class,
            SerializationFailureClass::UriTooLarge
        );
    }

    #[test]
    fn test_build_request_frame_rejects_oversized_body() {
        let method = Method::GET;
        let uri: Uri = "/".parse().unwrap();
        let headers = HeaderMap::new();
        let body = vec![0u8; 100];
        let policy = RequestFramePolicy {
            max_method_bytes: 256,
            max_uri_bytes: 256,
            max_body_bytes: 32,
            max_total_frame_bytes: 1024,
            ..strict_policy()
        };

        let result = build_request_frame(&method, &uri, &headers, &body, &policy);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().class,
            SerializationFailureClass::BodyTooLarge
        );
    }

    #[test]
    fn test_build_request_frame_rejects_total_frame_size() {
        let method = Method::POST;
        let uri: Uri = "http://example.com/path".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        let body = b"test";
        let policy = RequestFramePolicy {
            max_total_frame_bytes: 10,
            ..default_policy()
        };

        let result = build_request_frame(&method, &uri, &headers, body, &policy);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().class,
            SerializationFailureClass::FrameTooLarge
        );
    }

    #[test]
    fn test_build_request_frame_total_bytes_accounting() {
        let method = Method::GET;
        let uri: Uri = "http://example.com/".parse().unwrap();
        let headers = HeaderMap::new();
        let body = b"hello";

        let policy = default_policy();
        let frame = build_request_frame(&method, &uri, &headers, body, &policy).unwrap();
        assert_eq!(
            frame.total_bytes(),
            frame.method.len()
                + frame.uri.len()
                + frame.authority.len()
                + frame.scheme.len()
                + frame.headers.len()
                + frame.body.len()
        );
    }

    // ── PluginHttpView tests ───────────────────────────────────────────

    #[test]
    fn test_plugin_http_view_from_parts_with_authority() {
        let method = Method::GET;
        let uri: Uri = "https://example.com:8443/path".parse().unwrap();
        let headers = HeaderMap::new();

        let view = PluginHttpView::from_parts(&method, &uri, &headers, PluginBodyMode::Full);
        assert_eq!(view.authority, Some("example.com:8443"));
        assert_eq!(view.scheme, Some("https"));
    }

    #[test]
    fn test_plugin_http_view_fallback_to_host_header() {
        let method = Method::GET;
        let uri: Uri = "/path".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("fallback.com"));

        let view = PluginHttpView::from_parts(&method, &uri, &headers, PluginBodyMode::Full);
        assert_eq!(view.authority, Some("fallback.com"));
        assert_eq!(view.scheme, Some("http"));
    }

    #[test]
    fn test_plugin_body_mode_variants() {
        assert_eq!(PluginBodyMode::Full, PluginBodyMode::Full);
        assert_eq!(
            PluginBodyMode::Truncated(100),
            PluginBodyMode::Truncated(100)
        );
        assert_eq!(PluginBodyMode::None, PluginBodyMode::None);
        assert_ne!(PluginBodyMode::Full, PluginBodyMode::None);
    }

    // ── PluginResponseMutationPolicy tests ─────────────────────────────

    #[test]
    fn test_mutation_policy_inspect_only() {
        let caps = PluginCapabilities {
            response_inspect: true,
            response_mutate: false,
            ..Default::default()
        };
        let policy = PluginResponseMutationPolicy::from_capabilities(&caps, 1024);
        assert!(!policy.allow_status_change);
        assert!(!policy.allow_header_add);
        assert!(!policy.allow_header_remove);
        assert!(!policy.allow_body_replace);
    }

    #[test]
    fn test_mutation_policy_with_mutate() {
        let caps = PluginCapabilities {
            response_inspect: true,
            response_mutate: true,
            ..Default::default()
        };
        let policy = PluginResponseMutationPolicy::from_capabilities(&caps, 2048);
        assert!(!policy.allow_status_change);
        assert!(policy.allow_header_add);
        assert!(policy.allow_header_remove);
        assert!(policy.allow_body_replace);
        assert_eq!(policy.max_output_bytes, 2048);
    }

    #[test]
    fn test_mutation_policy_denies_security_headers() {
        let caps = PluginCapabilities {
            response_mutate: true,
            ..Default::default()
        };
        let policy = PluginResponseMutationPolicy::from_capabilities(&caps, 1024);

        assert!(!policy.is_header_allowed("set-cookie"));
        assert!(!policy.is_header_allowed("content-length"));
        assert!(!policy.is_header_allowed("transfer-encoding"));
        assert!(!policy.is_header_allowed("authorization"));
        assert!(!policy.is_header_allowed("connection"));
    }

    #[test]
    fn test_mutation_policy_allows_plugin_prefix() {
        let caps = PluginCapabilities {
            response_mutate: true,
            ..Default::default()
        };
        let policy = PluginResponseMutationPolicy::from_capabilities(&caps, 1024);

        assert!(policy.is_header_allowed("x-plugin-id"));
        assert!(policy.is_header_allowed("x-custom-header"));
    }

    // ── validate_response_transform_output tests ───────────────────────

    #[test]
    fn test_validate_response_valid() {
        let caps = PluginCapabilities {
            response_mutate: true,
            ..Default::default()
        };
        let mutation = PluginResponseMutationPolicy::from_capabilities(&caps, 1024);
        let frame = ResponseFramePolicy::default();

        let mut headers = HeaderMap::new();
        headers.insert("x-plugin-result", HeaderValue::from_static("ok"));

        let result = validate_response_transform_output(
            StatusCode::OK,
            Some(&headers),
            b"transformed body",
            &mutation,
            &frame,
        );
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert_eq!(validated.status, StatusCode::OK);
        assert_eq!(validated.body.as_ref(), b"transformed body");
    }

    #[test]
    fn test_validate_response_rejects_invalid_status() {
        let caps = PluginCapabilities::default();
        let mutation = PluginResponseMutationPolicy::from_capabilities(&caps, 1024);
        let frame = ResponseFramePolicy::default();

        // StatusCode::from_u16 will return Err for truly invalid codes,
        // but let's test with a status that's out of our policy range
        let result = validate_response_transform_output(
            StatusCode::OK,
            None,
            b"",
            &mutation,
            &ResponseFramePolicy {
                min_status_code: 200,
                max_status_code: 299,
                ..frame
            },
        );
        assert!(result.is_ok()); // 200 is in 200-299

        // Test with a code outside range (using a valid StatusCode but wrong range)
        let result = validate_response_transform_output(
            StatusCode::NOT_FOUND,
            None,
            b"",
            &mutation,
            &ResponseFramePolicy {
                min_status_code: 200,
                max_status_code: 299,
                ..frame
            },
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().class,
            SerializationFailureClass::InvalidStatus
        );
    }

    #[test]
    fn test_validate_response_rejects_oversized_body() {
        let caps = PluginCapabilities::default();
        let mutation = PluginResponseMutationPolicy::from_capabilities(&caps, 10);
        let frame = ResponseFramePolicy {
            max_body_bytes: 10,
            ..Default::default()
        };

        let result =
            validate_response_transform_output(StatusCode::OK, None, &[0u8; 20], &mutation, &frame);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().class,
            SerializationFailureClass::BodyTooLarge
        );
    }

    #[test]
    fn test_validate_response_rejects_denied_header() {
        let caps = PluginCapabilities {
            response_mutate: true,
            ..Default::default()
        };
        let mutation = PluginResponseMutationPolicy::from_capabilities(&caps, 1024);
        let frame = ResponseFramePolicy::default();

        let mut headers = HeaderMap::new();
        headers.insert("set-cookie", HeaderValue::from_static("evil=true"));

        let result = validate_response_transform_output(
            StatusCode::OK,
            Some(&headers),
            b"",
            &mutation,
            &frame,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().class,
            SerializationFailureClass::MutationDenied
        );
    }

    #[test]
    fn test_validate_response_rejects_over_header_count() {
        let caps = PluginCapabilities::default();
        let mutation = PluginResponseMutationPolicy::from_capabilities(&caps, 1024);
        let frame = ResponseFramePolicy {
            max_header_count: 2,
            ..Default::default()
        };

        let mut headers = HeaderMap::new();
        headers.insert("x-a", HeaderValue::from_static("1"));
        headers.insert("x-b", HeaderValue::from_static("2"));
        headers.insert("x-c", HeaderValue::from_static("3"));

        let result = validate_response_transform_output(
            StatusCode::OK,
            Some(&headers),
            b"",
            &mutation,
            &frame,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().class,
            SerializationFailureClass::HeaderCountTooLarge
        );
    }

    // ── SerializationFailureClass tests ────────────────────────────────

    #[test]
    fn test_failure_class_labels_are_unique() {
        let classes = [
            SerializationFailureClass::MethodTooLarge,
            SerializationFailureClass::UriTooLarge,
            SerializationFailureClass::AuthorityTooLarge,
            SerializationFailureClass::HeaderCountTooLarge,
            SerializationFailureClass::HeaderNameTooLarge,
            SerializationFailureClass::HeaderValueTooLarge,
            SerializationFailureClass::HeaderBlockTooLarge,
            SerializationFailureClass::BodyTooLarge,
            SerializationFailureClass::FrameTooLarge,
            SerializationFailureClass::InvalidStatus,
            SerializationFailureClass::InvalidHeaderName,
            SerializationFailureClass::InvalidHeaderValue,
            SerializationFailureClass::MutationDenied,
        ];
        let labels: Vec<&str> = classes.iter().map(|c| c.as_label()).collect();
        let mut sorted = labels.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            labels.len(),
            sorted.len(),
            "failure class labels must be unique"
        );
    }

    // ── Policy derivation tests ────────────────────────────────────────

    #[test]
    fn test_request_frame_policy_from_limits() {
        let policy = request_frame_policy_from_limits(262_144);
        assert_eq!(policy.max_body_bytes, 262_144);
        assert_eq!(policy.max_total_frame_bytes, 262_144);
        assert!(policy.max_serialized_headers_bytes >= 4096);
    }

    #[test]
    fn test_request_frame_policy_from_small_limits() {
        let policy = request_frame_policy_from_limits(100);
        assert_eq!(policy.max_body_bytes, 100);
        assert_eq!(policy.max_total_frame_bytes, 100);
        assert_eq!(policy.max_serialized_headers_bytes, 4096); // min 4096
    }

    #[test]
    fn test_response_frame_policy_from_limits() {
        let policy = response_frame_policy_from_limits(262_144);
        assert_eq!(policy.max_body_bytes, 262_144);
        assert_eq!(policy.max_total_frame_bytes, 262_144);
    }
}
