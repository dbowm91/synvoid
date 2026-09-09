//! Sandbox jail protocol: versioned, length-bounded, typed IPC for the
//! WASM/YARA jail processes.
//!
//! Normative spec: `architecture/sandbox_jail_protocol.md`. This module holds
//! the DTOs, validation, framing, typed errors, isolation policy, and
//! observability counters. Process supervision (parent handle, restart policy,
//! child serve loop) lives in [`crate::jail_process`].
//!
//! Transport notes:
//!
//! - Frames travel over parent-created anonymous stdio pipes inherited by the
//!   jail child. There is no connectable namespace, so peer identity is
//!   guaranteed by descriptor inheritance and no token handshake is used.
//! - Wire format reuses the `ipc_framing` convention: 4-byte big-endian length
//!   prefix followed by a postcard payload.
//! - At most one request is in flight per jail process (no pipelining), so
//!   request IDs only need per-connection monotonicity, not a full session.

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Protocol identity and bounds
// ---------------------------------------------------------------------------

/// Frame magic: ASCII `SVJL` (SynVoid JaiL).
pub const JAIL_MAGIC: u32 = u32::from_be_bytes(*b"SVJL");

/// Current jail protocol version. Unknown versions are rejected.
pub const JAIL_PROTOCOL_VERSION: u16 = 1;

/// Maximum bytes for any single frame, including loads. The length prefix is
/// validated before any payload allocation.
pub const JAIL_MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Maximum WASM invoke input (headers plus body).
pub const JAIL_MAX_INVOKE_INPUT_BYTES: usize = 1024 * 1024;

/// Maximum WASM invoke output body.
pub const JAIL_MAX_INVOKE_OUTPUT_BYTES: usize = 1024 * 1024;

/// Maximum YARA scan input buffer.
pub const JAIL_MAX_SCAN_INPUT_BYTES: usize = 4 * 1024 * 1024;

/// Maximum WASM module bytes per load.
pub const JAIL_MAX_MODULE_BYTES: usize = 8 * 1024 * 1024;

/// Maximum YARA rule-text bytes per load.
pub const JAIL_MAX_RULES_BYTES: usize = 2 * 1024 * 1024;

/// Maximum loaded WASM modules per jail process.
pub const JAIL_MAX_MODULES: usize = 16;

/// Maximum loaded YARA rule sets per jail process.
pub const JAIL_MAX_RULESETS: usize = 16;

/// Maximum YARA matches returned per scan.
pub const JAIL_MAX_MATCHES: usize = 256;

/// Maximum headers per WASM invoke.
pub const JAIL_MAX_HEADERS: usize = 64;

/// Maximum module/rules ID length.
pub const JAIL_MAX_ID_LEN: usize = 128;

/// Maximum length for a single match text field (rule name, tags, ...).
pub const JAIL_MAX_TEXT_FIELD: usize = 256;

/// Maximum error message length crossing the boundary.
pub const JAIL_MAX_ERROR_MESSAGE: usize = 512;

/// Maximum HTTP method length.
pub const JAIL_MAX_METHOD_LEN: usize = 32;

/// Maximum URI length.
pub const JAIL_MAX_URI_LEN: usize = 8192;

/// Maximum single header name/value length.
pub const JAIL_MAX_HEADER_NAME_LEN: usize = 128;
pub const JAIL_MAX_HEADER_VALUE_LEN: usize = 16384;

/// Default per-call deadline in milliseconds.
pub const JAIL_DEFAULT_CALL_TIMEOUT_MS: u64 = 5000;

/// Grace period for orderly jail shutdown before `kill`.
pub const JAIL_SHUTDOWN_GRACE_MS: u64 = 1000;

/// Default bounded restart budget per jail handle.
pub const JAIL_MAX_RESTARTS: u32 = 5;

/// Restart backoff floor/ceiling in milliseconds.
pub const JAIL_RESTART_BASE_BACKOFF_MS: u64 = 100;
pub const JAIL_RESTART_MAX_BACKOFF_MS: u64 = 5000;

/// Minimum/maximum per-invocation execution timeout accepted in load requests.
pub const JAIL_MIN_TIMEOUT_MS: u64 = 1;
pub const JAIL_MAX_TIMEOUT_MS: u64 = 60_000;

/// Minimum/maximum WASM linear-memory pages accepted in load requests.
pub const JAIL_MIN_MEMORY_PAGES: u32 = 1;
pub const JAIL_MAX_MEMORY_PAGES: u32 = 1024;

/// Maximum WASM fuel budget accepted in load requests (fuel must be nonzero).
pub const JAIL_MAX_FUEL: u64 = 1_000_000_000_000;

// ---------------------------------------------------------------------------
// Kind
// ---------------------------------------------------------------------------

/// Which jail workload a handle or serve loop is dedicated to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JailKind {
    Wasm,
    Yara,
}

impl JailKind {
    /// Bounded vocabulary for logs and metric selection (never user input).
    pub fn as_str(self) -> &'static str {
        match self {
            JailKind::Wasm => "wasm",
            JailKind::Yara => "yara",
        }
    }

    /// CLI flag that spawns this jail kind. Fixed strings only.
    pub fn cli_flag(self) -> &'static str {
        match self {
            JailKind::Wasm => "--wasm-jail",
            JailKind::Yara => "--yara-jail",
        }
    }
}

// ---------------------------------------------------------------------------
// Operations and results
// ---------------------------------------------------------------------------

/// Hook-only capabilities a WASM jail load may request.
///
/// Only request/response hook flags exist here by construction: filesystem,
/// network, mesh, admin, persistence, and metrics authority cannot be
/// expressed in this type and are therefore never granted inside a jail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct JailHookCapabilities {
    pub request_inspect: bool,
    pub request_mutate: bool,
    pub response_inspect: bool,
    pub response_mutate: bool,
}

impl JailHookCapabilities {
    /// At least one hook flag must be set, otherwise the load is useless.
    pub fn validate(&self) -> Result<(), JailError> {
        if !(self.request_inspect
            || self.request_mutate
            || self.response_inspect
            || self.response_mutate)
        {
            return Err(JailError::PolicyDenied(
                "wasm jail load grants no hook capability".to_string(),
            ));
        }
        Ok(())
    }
}

/// Closed set of jail operations. There is intentionally no generic
/// command-execution variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JailOperation {
    /// Health/version handshake. The first Ping doubles as the handshake.
    Ping,
    /// Orderly shutdown request.
    Shutdown,
    /// Load a parent-approved WASM module for `handle_request` invocation.
    WasmLoad {
        module_id: String,
        /// Lowercase hex SHA-256 of `wasm_bytes`, verified by the child.
        digest_sha256_hex: String,
        #[serde(with = "serde_bytes")]
        wasm_bytes: Vec<u8>,
        /// Wasmtime fuel budget (must be nonzero).
        fuel: u64,
        memory_pages: Option<u32>,
        timeout_ms: u64,
        capabilities: JailHookCapabilities,
    },
    /// Invoke the `handle_request` export of a loaded module.
    WasmInvoke {
        module_id: String,
        method: String,
        uri: String,
        headers: Vec<(String, String)>,
        #[serde(with = "serde_bytes")]
        body: Vec<u8>,
    },
    /// Evict a loaded module.
    WasmUnload { module_id: String },
    /// Load a parent-approved YARA rule set.
    YaraLoadRules {
        rules_id: String,
        /// Lowercase hex SHA-256 of `rules_text`, verified by the child.
        digest_sha256_hex: String,
        rules_text: String,
    },
    /// Scan a bounded buffer with a loaded rule set.
    YaraScan {
        rules_id: String,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    /// Evict a loaded rule set.
    YaraUnload { rules_id: String },
}

/// Single YARA match DTO with bounded text fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct YaraMatchDto {
    pub rule_name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub category: String,
    pub severity: String,
    pub description: String,
}

impl YaraMatchDto {
    /// Truncate every text field to [`JAIL_MAX_TEXT_FIELD`].
    pub fn truncated(mut self) -> Self {
        truncate_in_place(&mut self.rule_name);
        truncate_in_place(&mut self.namespace);
        truncate_in_place(&mut self.category);
        truncate_in_place(&mut self.severity);
        truncate_in_place(&mut self.description);
        for tag in &mut self.tags {
            truncate_in_place(tag);
        }
        if self.tags.len() > 32 {
            self.tags.truncate(32);
        }
        self
    }
}

fn truncate_in_place(s: &mut String) {
    if s.len() > JAIL_MAX_TEXT_FIELD {
        s.truncate(JAIL_MAX_TEXT_FIELD);
    }
}

/// Successful jail call output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JailOutput {
    Pong,
    WasmLoaded,
    WasmResult {
        status: u16,
        headers: Vec<(String, String)>,
        #[serde(with = "serde_bytes")]
        body: Vec<u8>,
    },
    WasmUnloaded,
    YaraRulesLoaded,
    YaraScanResult {
        matches: Vec<YaraMatchDto>,
    },
    YaraUnloaded,
    ShutdownAck,
}

/// Bounded error DTO crossing the jail boundary. Messages are truncated to
/// [`JAIL_MAX_ERROR_MESSAGE`] and must never contain secrets, paths, or rule
/// text (enforced at construction sites, asserted by guard tests).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JailErrorDto {
    pub code: JailErrorCode,
    pub message: String,
}

impl JailErrorDto {
    pub fn new(code: JailErrorCode, message: impl Into<String>) -> Self {
        let mut message: String = message.into();
        if message.len() > JAIL_MAX_ERROR_MESSAGE {
            message.truncate(JAIL_MAX_ERROR_MESSAGE);
        }
        Self { code, message }
    }
}

/// Typed result of a jail call. An explicit enum (rather than `Result`) keeps
/// the wire format version-stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JailResult {
    Ok(JailOutput),
    Err(JailErrorDto),
}

/// Framed jail request envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JailRequest {
    pub magic: u32,
    pub version: u16,
    pub id: u64,
    pub op: JailOperation,
}

/// Framed jail response envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JailResponse {
    pub magic: u32,
    pub version: u16,
    pub id: u64,
    pub result: JailResult,
}

impl JailRequest {
    pub fn new(id: u64, op: JailOperation) -> Self {
        Self {
            magic: JAIL_MAGIC,
            version: JAIL_PROTOCOL_VERSION,
            id,
            op,
        }
    }
}

impl JailResponse {
    pub fn new(id: u64, result: JailResult) -> Self {
        Self {
            magic: JAIL_MAGIC,
            version: JAIL_PROTOCOL_VERSION,
            id,
            result,
        }
    }
}

// ---------------------------------------------------------------------------
// Typed errors
// ---------------------------------------------------------------------------

/// Fixed error vocabulary for jail failures. Used for metrics indexing, so
/// variants are a closed set with no payload data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JailErrorCode {
    Unavailable,
    HandshakeFailed,
    ProtocolViolation,
    Oversized,
    Timeout,
    ChildExited,
    FramingError,
    ResourceExhausted,
    Unsupported,
    RestartBudgetExhausted,
    PolicyDenied,
    ExecutionFailed,
    DigestMismatch,
    NotFound,
}

impl JailErrorCode {
    /// All variants, for metrics array sizing and exhaustive tests.
    pub const ALL: &'static [JailErrorCode] = &[
        JailErrorCode::Unavailable,
        JailErrorCode::HandshakeFailed,
        JailErrorCode::ProtocolViolation,
        JailErrorCode::Oversized,
        JailErrorCode::Timeout,
        JailErrorCode::ChildExited,
        JailErrorCode::FramingError,
        JailErrorCode::ResourceExhausted,
        JailErrorCode::Unsupported,
        JailErrorCode::RestartBudgetExhausted,
        JailErrorCode::PolicyDenied,
        JailErrorCode::ExecutionFailed,
        JailErrorCode::DigestMismatch,
        JailErrorCode::NotFound,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            JailErrorCode::Unavailable => "unavailable",
            JailErrorCode::HandshakeFailed => "handshake_failed",
            JailErrorCode::ProtocolViolation => "protocol_violation",
            JailErrorCode::Oversized => "oversized",
            JailErrorCode::Timeout => "timeout",
            JailErrorCode::ChildExited => "child_exited",
            JailErrorCode::FramingError => "framing_error",
            JailErrorCode::ResourceExhausted => "resource_exhausted",
            JailErrorCode::Unsupported => "unsupported",
            JailErrorCode::RestartBudgetExhausted => "restart_budget_exhausted",
            JailErrorCode::PolicyDenied => "policy_denied",
            JailErrorCode::ExecutionFailed => "execution_failed",
            JailErrorCode::DigestMismatch => "digest_mismatch",
            JailErrorCode::NotFound => "not_found",
        }
    }

    fn index(self) -> usize {
        match self {
            JailErrorCode::Unavailable => 0,
            JailErrorCode::HandshakeFailed => 1,
            JailErrorCode::ProtocolViolation => 2,
            JailErrorCode::Oversized => 3,
            JailErrorCode::Timeout => 4,
            JailErrorCode::ChildExited => 5,
            JailErrorCode::FramingError => 6,
            JailErrorCode::ResourceExhausted => 7,
            JailErrorCode::Unsupported => 8,
            JailErrorCode::RestartBudgetExhausted => 9,
            JailErrorCode::PolicyDenied => 10,
            JailErrorCode::ExecutionFailed => 11,
            JailErrorCode::DigestMismatch => 12,
            JailErrorCode::NotFound => 13,
        }
    }
}

/// Parent-side typed jail error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JailError {
    #[error("jail unavailable: {0}")]
    Unavailable(String),
    #[error("jail handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("jail protocol violation: {0}")]
    ProtocolViolation(String),
    #[error("jail message oversized: {0}")]
    Oversized(String),
    #[error("jail call timed out: {0}")]
    Timeout(String),
    #[error("jail child exited: {0}")]
    ChildExited(String),
    #[error("jail framing error: {0}")]
    FramingError(String),
    #[error("jail resource exhausted: {0}")]
    ResourceExhausted(String),
    #[error("jail unsupported: {0}")]
    Unsupported(String),
    #[error("jail restart budget exhausted: {0}")]
    RestartBudgetExhausted(String),
    #[error("jail policy denied: {0}")]
    PolicyDenied(String),
    #[error("jail execution failed: {0}")]
    ExecutionFailed(String),
    #[error("jail digest mismatch: {0}")]
    DigestMismatch(String),
    #[error("jail object not found: {0}")]
    NotFound(String),
}

impl JailError {
    pub fn code(&self) -> JailErrorCode {
        match self {
            JailError::Unavailable(_) => JailErrorCode::Unavailable,
            JailError::HandshakeFailed(_) => JailErrorCode::HandshakeFailed,
            JailError::ProtocolViolation(_) => JailErrorCode::ProtocolViolation,
            JailError::Oversized(_) => JailErrorCode::Oversized,
            JailError::Timeout(_) => JailErrorCode::Timeout,
            JailError::ChildExited(_) => JailErrorCode::ChildExited,
            JailError::FramingError(_) => JailErrorCode::FramingError,
            JailError::ResourceExhausted(_) => JailErrorCode::ResourceExhausted,
            JailError::Unsupported(_) => JailErrorCode::Unsupported,
            JailError::RestartBudgetExhausted(_) => JailErrorCode::RestartBudgetExhausted,
            JailError::PolicyDenied(_) => JailErrorCode::PolicyDenied,
            JailError::ExecutionFailed(_) => JailErrorCode::ExecutionFailed,
            JailError::DigestMismatch(_) => JailErrorCode::DigestMismatch,
            JailError::NotFound(_) => JailErrorCode::NotFound,
        }
    }

    /// Convert to the boundary DTO (message truncated, no payload data).
    pub fn to_dto(&self) -> JailErrorDto {
        JailErrorDto::new(self.code(), self.to_string())
    }

    fn framing(source: impl std::fmt::Display) -> Self {
        let mut message = format!("{source}");
        if message.len() > JAIL_MAX_ERROR_MESSAGE {
            message.truncate(JAIL_MAX_ERROR_MESSAGE);
        }
        JailError::FramingError(message)
    }
}

impl From<JailErrorDto> for JailError {
    fn from(dto: JailErrorDto) -> Self {
        match dto.code {
            JailErrorCode::Unavailable => JailError::Unavailable(dto.message),
            JailErrorCode::HandshakeFailed => JailError::HandshakeFailed(dto.message),
            JailErrorCode::ProtocolViolation => JailError::ProtocolViolation(dto.message),
            JailErrorCode::Oversized => JailError::Oversized(dto.message),
            JailErrorCode::Timeout => JailError::Timeout(dto.message),
            JailErrorCode::ChildExited => JailError::ChildExited(dto.message),
            JailErrorCode::FramingError => JailError::FramingError(dto.message),
            JailErrorCode::ResourceExhausted => JailError::ResourceExhausted(dto.message),
            JailErrorCode::Unsupported => JailError::Unsupported(dto.message),
            JailErrorCode::RestartBudgetExhausted => JailError::RestartBudgetExhausted(dto.message),
            JailErrorCode::PolicyDenied => JailError::PolicyDenied(dto.message),
            JailErrorCode::ExecutionFailed => JailError::ExecutionFailed(dto.message),
            JailErrorCode::DigestMismatch => JailError::DigestMismatch(dto.message),
            JailErrorCode::NotFound => JailError::NotFound(dto.message),
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Module/rules IDs are parent-assigned names, never paths. Restrict the
/// charset so IDs cannot smuggle path separators or control characters.
fn validate_id(id: &str, what: &str) -> Result<(), JailError> {
    if id.is_empty() || id.len() > JAIL_MAX_ID_LEN {
        return Err(JailError::Oversized(format!(
            "{what} id length out of bounds"
        )));
    }
    let ok = id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'));
    if !ok {
        return Err(JailError::ProtocolViolation(format!(
            "{what} id contains forbidden characters"
        )));
    }
    Ok(())
}

fn validate_digest_hex(hex: &str) -> Result<(), JailError> {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(JailError::DigestMismatch(
            "digest must be 64 lowercase hex characters".to_string(),
        ));
    }
    Ok(())
}

impl JailOperation {
    /// Validate bounds before sending (parent fail-fast) and after receiving
    /// (child defense in depth). Never logs or returns payload bytes.
    pub fn validate(&self) -> Result<(), JailError> {
        match self {
            JailOperation::Ping | JailOperation::Shutdown => Ok(()),
            JailOperation::WasmLoad {
                module_id,
                digest_sha256_hex,
                wasm_bytes,
                fuel,
                memory_pages,
                timeout_ms,
                capabilities,
            } => {
                validate_id(module_id, "module")?;
                validate_digest_hex(digest_sha256_hex)?;
                if wasm_bytes.len() > JAIL_MAX_MODULE_BYTES {
                    return Err(JailError::Oversized(format!(
                        "wasm module too large: {} bytes",
                        wasm_bytes.len()
                    )));
                }
                if *fuel == 0 || *fuel > JAIL_MAX_FUEL {
                    return Err(JailError::PolicyDenied(
                        "wasm fuel budget out of bounds (must be nonzero)".to_string(),
                    ));
                }
                if let Some(pages) = memory_pages {
                    if *pages < JAIL_MIN_MEMORY_PAGES || *pages > JAIL_MAX_MEMORY_PAGES {
                        return Err(JailError::PolicyDenied(
                            "wasm memory pages out of bounds".to_string(),
                        ));
                    }
                }
                if *timeout_ms < JAIL_MIN_TIMEOUT_MS || *timeout_ms > JAIL_MAX_TIMEOUT_MS {
                    return Err(JailError::PolicyDenied(
                        "wasm timeout out of bounds".to_string(),
                    ));
                }
                capabilities.validate()?;
                Ok(())
            }
            JailOperation::WasmInvoke {
                module_id,
                method,
                uri,
                headers,
                body,
            } => {
                validate_id(module_id, "module")?;
                if method.is_empty() || method.len() > JAIL_MAX_METHOD_LEN {
                    return Err(JailError::Oversized(
                        "invoke method length out of bounds".to_string(),
                    ));
                }
                if uri.len() > JAIL_MAX_URI_LEN {
                    return Err(JailError::Oversized(
                        "invoke uri length out of bounds".to_string(),
                    ));
                }
                if headers.len() > JAIL_MAX_HEADERS {
                    return Err(JailError::Oversized("too many headers".to_string()));
                }
                for (name, value) in headers {
                    if name.is_empty()
                        || name.len() > JAIL_MAX_HEADER_NAME_LEN
                        || value.len() > JAIL_MAX_HEADER_VALUE_LEN
                    {
                        return Err(JailError::Oversized(
                            "header name/value length out of bounds".to_string(),
                        ));
                    }
                }
                let input_len = body.len() + uri.len() + headers.len() * 64;
                if input_len > JAIL_MAX_INVOKE_INPUT_BYTES {
                    return Err(JailError::Oversized("invoke input too large".to_string()));
                }
                Ok(())
            }
            JailOperation::WasmUnload { module_id } => validate_id(module_id, "module"),
            JailOperation::YaraLoadRules {
                rules_id,
                digest_sha256_hex,
                rules_text,
            } => {
                validate_id(rules_id, "rules")?;
                validate_digest_hex(digest_sha256_hex)?;
                if rules_text.len() > JAIL_MAX_RULES_BYTES {
                    return Err(JailError::Oversized(format!(
                        "yara rules too large: {} bytes",
                        rules_text.len()
                    )));
                }
                Ok(())
            }
            JailOperation::YaraScan { rules_id, data } => {
                validate_id(rules_id, "rules")?;
                if data.len() > JAIL_MAX_SCAN_INPUT_BYTES {
                    return Err(JailError::Oversized(format!(
                        "yara scan input too large: {} bytes",
                        data.len()
                    )));
                }
                Ok(())
            }
            JailOperation::YaraUnload { rules_id } => validate_id(rules_id, "rules"),
        }
    }

    /// Which jail kind must serve this operation.
    pub fn required_kind(&self) -> JailKind {
        match self {
            JailOperation::Ping
            | JailOperation::Shutdown
            | JailOperation::WasmLoad { .. }
            | JailOperation::WasmInvoke { .. }
            | JailOperation::WasmUnload { .. } => JailKind::Wasm,
            JailOperation::YaraLoadRules { .. }
            | JailOperation::YaraScan { .. }
            | JailOperation::YaraUnload { .. } => JailKind::Yara,
        }
    }
}

// ---------------------------------------------------------------------------
// Digest helpers
// ---------------------------------------------------------------------------

/// Lowercase hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Constant-time digest comparison. `expected_hex` must already have passed
/// [`validate_digest_hex`]; malformed input returns `false` without leaking
/// timing about the digest itself.
pub fn verify_sha256_hex(data: &[u8], expected_hex: &str) -> bool {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;
    if expected_hex.len() != 64 {
        return false;
    }
    let mut expected = [0u8; 32];
    let bytes = expected_hex.as_bytes();
    for (i, chunk) in bytes.chunks(2).enumerate() {
        if i >= 32 || chunk.len() != 2 {
            return false;
        }
        let hi = (chunk[0] as char).to_digit(16);
        let lo = (chunk[1] as char).to_digit(16);
        match (hi, lo) {
            (Some(h), Some(l)) => expected[i] = ((h << 4) | l) as u8,
            _ => return false,
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(data);
    let actual: [u8; 32] = hasher.finalize().into();
    actual.ct_eq(&expected).into()
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

/// Encode a request envelope to a length-delimited frame buffer.
pub fn encode_request(req: &JailRequest) -> Result<Vec<u8>, JailError> {
    if req.magic != JAIL_MAGIC {
        return Err(JailError::ProtocolViolation(
            "bad request magic".to_string(),
        ));
    }
    if req.version != JAIL_PROTOCOL_VERSION {
        return Err(JailError::ProtocolViolation(
            "unsupported request version".to_string(),
        ));
    }
    if req.id == 0 {
        return Err(JailError::ProtocolViolation(
            "request id must be nonzero".to_string(),
        ));
    }
    req.op.validate()?;
    let payload = synvoid_utils::serialization::serialize(req).map_err(JailError::framing)?;
    if payload.len() > JAIL_MAX_FRAME_BYTES {
        return Err(JailError::Oversized(format!(
            "encoded request too large: {} bytes",
            payload.len()
        )));
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Encode a response envelope to a length-delimited frame buffer.
pub fn encode_response(res: &JailResponse) -> Result<Vec<u8>, JailError> {
    if res.magic != JAIL_MAGIC {
        return Err(JailError::ProtocolViolation(
            "bad response magic".to_string(),
        ));
    }
    if res.version != JAIL_PROTOCOL_VERSION {
        return Err(JailError::ProtocolViolation(
            "unsupported response version".to_string(),
        ));
    }
    if res.id == 0 {
        return Err(JailError::ProtocolViolation(
            "response id must be nonzero".to_string(),
        ));
    }
    if let JailResult::Ok(JailOutput::WasmResult { body, .. }) = &res.result {
        if body.len() > JAIL_MAX_INVOKE_OUTPUT_BYTES {
            return Err(JailError::Oversized("response body too large".to_string()));
        }
    }
    if let JailResult::Ok(JailOutput::YaraScanResult { matches }) = &res.result {
        if matches.len() > JAIL_MAX_MATCHES {
            return Err(JailError::Oversized("too many matches".to_string()));
        }
    }
    let payload = synvoid_utils::serialization::serialize(res).map_err(JailError::framing)?;
    if payload.len() > JAIL_MAX_FRAME_BYTES {
        return Err(JailError::Oversized(format!(
            "encoded response too large: {} bytes",
            payload.len()
        )));
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Write one length-delimited frame.
pub fn write_frame<W: Write>(writer: &mut W, frame: &[u8]) -> io::Result<()> {
    writer.write_all(frame)?;
    writer.flush()
}

/// Outcome of a blocking frame read.
#[derive(Debug)]
pub enum FrameRead {
    /// A complete payload (length prefix consumed).
    Frame(Vec<u8>),
    /// Clean EOF before any frame byte: orderly peer shutdown.
    CleanEof,
}

/// Blocking read of one length-delimited frame.
///
/// The length prefix is validated against `max_bytes` before any payload
/// allocation, so a corrupt/huge prefix cannot cause unbounded allocation.
/// Returns [`FrameRead::CleanEof`] only when zero bytes were available (peer
/// exited or closed the pipe); a mid-frame EOF is a [`JailError::FramingError`].
pub fn read_frame<R: Read>(reader: &mut R, max_bytes: usize) -> Result<FrameRead, JailError> {
    let mut len_buf = [0u8; 4];
    let mut got = 0usize;
    while got < 4 {
        match reader.read(&mut len_buf[got..]) {
            Ok(0) => {
                if got == 0 {
                    return Ok(FrameRead::CleanEof);
                }
                return Err(JailError::FramingError(
                    "truncated frame length prefix".to_string(),
                ));
            }
            Ok(n) => got += n,
            Err(e) => return Err(JailError::framing(e)),
        }
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Err(JailError::FramingError("empty frame".to_string()));
    }
    if len > max_bytes {
        return Err(JailError::Oversized(format!(
            "frame length {len} exceeds limit {max_bytes}"
        )));
    }
    let mut payload = vec![0u8; len];
    if let Err(e) = reader.read_exact(&mut payload) {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            return Err(JailError::FramingError(
                "truncated frame payload".to_string(),
            ));
        }
        return Err(JailError::framing(e));
    }
    Ok(FrameRead::Frame(payload))
}

/// Deserialize and envelope-validate a request payload.
pub fn decode_request(payload: &[u8]) -> Result<JailRequest, JailError> {
    let req: JailRequest =
        synvoid_utils::serialization::deserialize(payload).map_err(JailError::framing)?;
    if req.magic != JAIL_MAGIC {
        return Err(JailError::ProtocolViolation(
            "bad request magic".to_string(),
        ));
    }
    if req.version != JAIL_PROTOCOL_VERSION {
        return Err(JailError::ProtocolViolation(format!(
            "unsupported request version: {}",
            req.version
        )));
    }
    if req.id == 0 {
        return Err(JailError::ProtocolViolation(
            "request id must be nonzero".to_string(),
        ));
    }
    req.op.validate()?;
    Ok(req)
}

/// Deserialize and envelope-validate a response payload.
pub fn decode_response(payload: &[u8]) -> Result<JailResponse, JailError> {
    let res: JailResponse =
        synvoid_utils::serialization::deserialize(payload).map_err(JailError::framing)?;
    if res.magic != JAIL_MAGIC {
        return Err(JailError::ProtocolViolation(
            "bad response magic".to_string(),
        ));
    }
    if res.version != JAIL_PROTOCOL_VERSION {
        return Err(JailError::ProtocolViolation(format!(
            "unsupported response version: {}",
            res.version
        )));
    }
    if res.id == 0 {
        return Err(JailError::ProtocolViolation(
            "response id must be nonzero".to_string(),
        ));
    }
    Ok(res)
}

// ---------------------------------------------------------------------------
// Isolation policy
// ---------------------------------------------------------------------------

/// Execution routing policy for jail-capable call sites.
///
/// Migration is incremental: production defaults to [`IsolationPolicy::InProcess`];
/// each call site opts into jail routing explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationPolicy {
    /// Execute in-process; never consult a jail.
    InProcess,
    /// Route to the jail when healthy. `fallback_in_process` permits
    /// in-process execution when the jail is unavailable, but only where the
    /// call site documents the fallback as safe (YARA detection scans,
    /// fail-open response transforms). Fail-closed request filtering must use
    /// `fallback_in_process: false` or [`IsolationPolicy::Required`].
    Preferred { fallback_in_process: bool },
    /// Jail or fail closed. Any jail outage, launch failure, or timeout is a
    /// hard error and must never silently fall back to in-process execution.
    Required,
}

/// Routing decision produced by [`resolve_route`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JailRoute {
    ExecuteInJail,
    ExecuteInProcess,
    FailClosed(JailError),
}

/// Single decision point for jail routing. `jail_ready` means a supervised,
/// handshake-verified jail handle exists for the required kind.
pub fn resolve_route(policy: IsolationPolicy, jail_ready: bool) -> JailRoute {
    match (policy, jail_ready) {
        (IsolationPolicy::InProcess, _) => JailRoute::ExecuteInProcess,
        (IsolationPolicy::Required, true) => JailRoute::ExecuteInJail,
        (IsolationPolicy::Preferred { .. }, true) => JailRoute::ExecuteInJail,
        (IsolationPolicy::Required, false) => JailRoute::FailClosed(JailError::Unavailable(
            "required jail isolation unavailable; failing closed".to_string(),
        )),
        (
            IsolationPolicy::Preferred {
                fallback_in_process: true,
            },
            false,
        ) => JailRoute::ExecuteInProcess,
        (
            IsolationPolicy::Preferred {
                fallback_in_process: false,
            },
            false,
        ) => JailRoute::FailClosed(JailError::Unavailable(
            "preferred jail isolation unavailable without fallback; failing closed".to_string(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Observability (bounded, label-free counters)
// ---------------------------------------------------------------------------

/// Snapshot of jail metrics. Counters are process-local atomics with no string
/// labels, so cardinality is structurally bounded: module names, digests,
/// paths, and rule text can never appear.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JailMetricsSnapshot {
    pub starts: u64,
    pub restarts: u64,
    pub exits: u64,
    pub shutdowns: u64,
    pub invocations_wasm: u64,
    pub invocations_yara: u64,
    pub timeouts: u64,
    pub oversized_rejected: u64,
    pub protocol_violations: u64,
    pub restart_budget_exhausted: u64,
    pub failures_by_code: Vec<(String, u64)>,
}

static JAIL_STARTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static JAIL_RESTARTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static JAIL_EXITS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static JAIL_SHUTDOWNS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static JAIL_INVOCATIONS_WASM: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static JAIL_INVOCATIONS_YARA: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static JAIL_TIMEOUTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static JAIL_OVERSIZED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static JAIL_PROTOCOL_VIOLATIONS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static JAIL_RESTART_BUDGET_EXHAUSTED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static JAIL_FAILURES_BY_CODE: LazyLock<Vec<AtomicU64>> = LazyLock::new(|| {
    (0..JailErrorCode::ALL.len())
        .map(|_| AtomicU64::new(0))
        .collect()
});

fn fetch(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

fn incr(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// Record a jail process start.
pub fn record_jail_start() {
    incr(&JAIL_STARTS);
}

/// Record a jail restart (quarantine + respawn).
pub fn record_jail_restart() {
    incr(&JAIL_RESTARTS);
}

/// Record a jail child exit observation.
pub fn record_jail_exit() {
    incr(&JAIL_EXITS);
}

/// Record an orderly jail shutdown.
pub fn record_jail_shutdown() {
    incr(&JAIL_SHUTDOWNS);
}

/// Record one jail invocation of the given kind.
pub fn record_jail_invocation(kind: JailKind) {
    match kind {
        JailKind::Wasm => incr(&JAIL_INVOCATIONS_WASM),
        JailKind::Yara => incr(&JAIL_INVOCATIONS_YARA),
    }
}

/// Record one jail failure under its bounded error category.
pub fn record_jail_failure(err: &JailError) {
    let code = err.code();
    if let Some(slot) = JAIL_FAILURES_BY_CODE.get(code.index()) {
        slot.fetch_add(1, Ordering::Relaxed);
    }
    match code {
        JailErrorCode::Timeout => incr(&JAIL_TIMEOUTS),
        JailErrorCode::Oversized => incr(&JAIL_OVERSIZED),
        JailErrorCode::ProtocolViolation | JailErrorCode::FramingError => {
            incr(&JAIL_PROTOCOL_VIOLATIONS);
        }
        JailErrorCode::RestartBudgetExhausted => incr(&JAIL_RESTART_BUDGET_EXHAUSTED),
        _ => {}
    }
}

/// Capture a snapshot of all jail counters.
pub fn jail_metrics_snapshot() -> JailMetricsSnapshot {
    JailMetricsSnapshot {
        starts: fetch(&JAIL_STARTS),
        restarts: fetch(&JAIL_RESTARTS),
        exits: fetch(&JAIL_EXITS),
        shutdowns: fetch(&JAIL_SHUTDOWNS),
        invocations_wasm: fetch(&JAIL_INVOCATIONS_WASM),
        invocations_yara: fetch(&JAIL_INVOCATIONS_YARA),
        timeouts: fetch(&JAIL_TIMEOUTS),
        oversized_rejected: fetch(&JAIL_OVERSIZED),
        protocol_violations: fetch(&JAIL_PROTOCOL_VIOLATIONS),
        restart_budget_exhausted: fetch(&JAIL_RESTART_BUDGET_EXHAUSTED),
        failures_by_code: JailErrorCode::ALL
            .iter()
            .map(|code| {
                (
                    code.as_str().to_string(),
                    JAIL_FAILURES_BY_CODE
                        .get(code.index())
                        .map(fetch)
                        .unwrap_or(0),
                )
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hook_caps() -> JailHookCapabilities {
        JailHookCapabilities {
            request_inspect: true,
            request_mutate: false,
            response_inspect: false,
            response_mutate: false,
        }
    }

    #[test]
    fn error_codes_cover_all_variants_without_payload() {
        // Fixed vocabulary: metrics indexing relies on a closed set.
        assert_eq!(JailErrorCode::ALL.len(), 14);
        let mut seen = std::collections::HashSet::new();
        for code in JailErrorCode::ALL {
            assert!(seen.insert(code.as_str()), "duplicate code string");
            assert!(code.as_str().len() < 40);
        }
    }

    #[test]
    fn request_response_round_trip() {
        let req = JailRequest::new(
            7,
            JailOperation::WasmInvoke {
                module_id: "mod-1".to_string(),
                method: "GET".to_string(),
                uri: "/".to_string(),
                headers: vec![("host".to_string(), "example.com".to_string())],
                body: b"hello".to_vec(),
            },
        );
        let frame = encode_request(&req).unwrap();
        assert!(frame.len() > 4);
        let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(len, frame.len() - 4);
        let mut slice: &[u8] = &frame;
        match read_frame(&mut slice, JAIL_MAX_FRAME_BYTES).unwrap() {
            FrameRead::Frame(payload) => {
                let decoded = decode_request(&payload).unwrap();
                assert_eq!(decoded, req);
            }
            FrameRead::CleanEof => panic!("expected frame"),
        }

        let res = JailResponse::new(
            7,
            JailResult::Ok(JailOutput::WasmResult {
                status: 200,
                headers: vec![],
                body: b"ok".to_vec(),
            }),
        );
        let frame = encode_response(&res).unwrap();
        let mut slice: &[u8] = &frame;
        match read_frame(&mut slice, JAIL_MAX_FRAME_BYTES).unwrap() {
            FrameRead::Frame(payload) => {
                let decoded = decode_response(&payload).unwrap();
                assert_eq!(decoded, res);
            }
            FrameRead::CleanEof => panic!("expected frame"),
        }
    }

    #[test]
    fn unknown_version_rejected() {
        let mut req = JailRequest::new(1, JailOperation::Ping);
        req.version = 99;
        assert!(encode_request(&req).is_err());

        // A tampered payload that parses but carries a bad version is also
        // rejected at decode time.
        let mut req = JailRequest::new(1, JailOperation::Ping);
        req.version = JAIL_PROTOCOL_VERSION;
        let payload = synvoid_utils::serialization::serialize(&req).unwrap();
        let mut tampered: JailRequest =
            synvoid_utils::serialization::deserialize(&payload).unwrap();
        tampered.version = 99;
        let payload = synvoid_utils::serialization::serialize(&tampered).unwrap();
        let err = decode_request(&payload).unwrap_err();
        assert!(matches!(err, JailError::ProtocolViolation(_)));
    }

    #[test]
    fn unknown_magic_rejected() {
        let mut req = JailRequest::new(1, JailOperation::Ping);
        req.magic = 0xDEAD_BEEF;
        assert!(encode_request(&req).is_err());
    }

    #[test]
    fn zero_id_rejected() {
        let req = JailRequest::new(0, JailOperation::Ping);
        assert!(encode_request(&req).is_err());
    }

    #[test]
    fn oversized_frame_rejected_before_allocation() {
        let big = vec![0u8; JAIL_MAX_FRAME_BYTES + 1];
        let mut frame = Vec::new();
        frame.extend_from_slice(&((big.len()) as u32).to_be_bytes());
        // read_frame must reject from the prefix alone without consuming the
        // (absent) payload.
        let mut slice: &[u8] = &frame;
        let err = read_frame(&mut slice, JAIL_MAX_FRAME_BYTES).unwrap_err();
        assert!(matches!(err, JailError::Oversized(_)));
    }

    #[test]
    fn truncated_payload_rejected() {
        let req = JailRequest::new(1, JailOperation::Ping);
        let frame = encode_request(&req).unwrap();
        let cut = &frame[..frame.len() - 2];
        let mut slice: &[u8] = cut;
        let err = read_frame(&mut slice, JAIL_MAX_FRAME_BYTES).unwrap_err();
        assert!(matches!(err, JailError::FramingError(_)));
    }

    #[test]
    fn truncated_prefix_rejected() {
        let frame = [0u8; 2];
        let mut slice: &[u8] = &frame;
        let err = read_frame(&mut slice, JAIL_MAX_FRAME_BYTES).unwrap_err();
        assert!(matches!(err, JailError::FramingError(_)));
    }

    #[test]
    fn clean_eof_on_empty_stream() {
        let empty: &[u8] = &[];
        let mut slice = empty;
        assert!(matches!(
            read_frame(&mut slice, JAIL_MAX_FRAME_BYTES).unwrap(),
            FrameRead::CleanEof
        ));
    }

    #[test]
    fn malformed_postcard_rejected() {
        let mut frame = Vec::new();
        let garbage = b"not a postcard jail request envelope at all....";
        frame.extend_from_slice(&(garbage.len() as u32).to_be_bytes());
        frame.extend_from_slice(garbage);
        let mut slice: &[u8] = &frame;
        match read_frame(&mut slice, JAIL_MAX_FRAME_BYTES).unwrap() {
            FrameRead::Frame(payload) => {
                let err = decode_request(&payload).unwrap_err();
                assert!(matches!(
                    err,
                    JailError::FramingError(_) | JailError::ProtocolViolation(_)
                ));
            }
            FrameRead::CleanEof => panic!("expected frame"),
        }
    }

    #[test]
    fn id_charset_rejects_path_traversal() {
        for bad in [
            "",
            "../escape",
            "/abs",
            "a/b",
            "semi;colon",
            "sp ace",
            "null\0",
        ] {
            let op = JailOperation::WasmUnload {
                module_id: bad.to_string(),
            };
            assert!(op.validate().is_err(), "id accepted: {bad:?}");
        }
        let op = JailOperation::WasmUnload {
            module_id: "mod-1_2.3:stable".to_string(),
        };
        assert!(op.validate().is_ok());
    }

    #[test]
    fn digest_format_enforced() {
        let op = JailOperation::WasmLoad {
            module_id: "m".to_string(),
            digest_sha256_hex: "not-hex".to_string(),
            wasm_bytes: vec![0u8; 8],
            fuel: 1000,
            memory_pages: None,
            timeout_ms: 100,
            capabilities: hook_caps(),
        };
        assert!(matches!(
            op.validate().unwrap_err(),
            JailError::DigestMismatch(_)
        ));
    }

    #[test]
    fn zero_fuel_rejected() {
        let op = JailOperation::WasmLoad {
            module_id: "m".to_string(),
            digest_sha256_hex: "a".repeat(64),
            wasm_bytes: vec![0u8; 8],
            fuel: 0,
            memory_pages: None,
            timeout_ms: 100,
            capabilities: hook_caps(),
        };
        assert!(matches!(
            op.validate().unwrap_err(),
            JailError::PolicyDenied(_)
        ));
    }

    #[test]
    fn empty_hook_capabilities_rejected() {
        let op = JailOperation::WasmLoad {
            module_id: "m".to_string(),
            digest_sha256_hex: "a".repeat(64),
            wasm_bytes: vec![0u8; 8],
            fuel: 1000,
            memory_pages: None,
            timeout_ms: 100,
            capabilities: JailHookCapabilities {
                request_inspect: false,
                request_mutate: false,
                response_inspect: false,
                response_mutate: false,
            },
        };
        assert!(matches!(
            op.validate().unwrap_err(),
            JailError::PolicyDenied(_)
        ));
    }

    #[test]
    fn oversized_invoke_rejected() {
        let op = JailOperation::WasmInvoke {
            module_id: "m".to_string(),
            method: "GET".to_string(),
            uri: "/".to_string(),
            headers: vec![],
            body: vec![0u8; JAIL_MAX_INVOKE_INPUT_BYTES + 1],
        };
        assert!(matches!(
            op.validate().unwrap_err(),
            JailError::Oversized(_)
        ));
    }

    #[test]
    fn oversized_scan_rejected() {
        let op = JailOperation::YaraScan {
            rules_id: "r".to_string(),
            data: vec![0u8; JAIL_MAX_SCAN_INPUT_BYTES + 1],
        };
        assert!(matches!(
            op.validate().unwrap_err(),
            JailError::Oversized(_)
        ));
    }

    #[test]
    fn digest_verify_round_trip_constant_time() {
        let data = b"module bytes";
        let hex = sha256_hex(data);
        assert_eq!(hex.len(), 64);
        assert!(verify_sha256_hex(data, &hex));
        let mut bad = hex.clone();
        bad.replace_range(0..1, "0");
        // May coincidentally match if first nibble was 0; flip both nibbles.
        bad.replace_range(0..2, "ff");
        if hex[0..2] != *"ff" {
            assert!(!verify_sha256_hex(data, &bad));
        }
        assert!(!verify_sha256_hex(data, "short"));
        assert!(!verify_sha256_hex(b"other", &hex));
    }

    #[test]
    fn policy_routes_fail_closed_when_required() {
        assert_eq!(
            resolve_route(IsolationPolicy::Required, true),
            JailRoute::ExecuteInJail
        );
        assert!(matches!(
            resolve_route(IsolationPolicy::Required, false),
            JailRoute::FailClosed(_)
        ));
        assert_eq!(
            resolve_route(
                IsolationPolicy::Preferred {
                    fallback_in_process: true
                },
                false
            ),
            JailRoute::ExecuteInProcess
        );
        assert!(matches!(
            resolve_route(
                IsolationPolicy::Preferred {
                    fallback_in_process: false
                },
                false
            ),
            JailRoute::FailClosed(_)
        ));
        assert_eq!(
            resolve_route(IsolationPolicy::InProcess, true),
            JailRoute::ExecuteInProcess
        );
    }

    #[test]
    fn metrics_snapshot_has_fixed_width_categories() {
        let snapshot = jail_metrics_snapshot();
        assert_eq!(snapshot.failures_by_code.len(), JailErrorCode::ALL.len());
        record_jail_failure(&JailError::Timeout("t".to_string()));
        let after = jail_metrics_snapshot();
        assert!(after.timeouts >= snapshot.timeouts + 1);
        let entry = after
            .failures_by_code
            .iter()
            .find(|(name, _)| name == "timeout")
            .unwrap();
        assert!(entry.1 >= 1);
    }

    #[test]
    fn error_dto_truncates_message() {
        let dto = JailErrorDto::new(JailErrorCode::ExecutionFailed, "x".repeat(600));
        assert_eq!(dto.message.len(), JAIL_MAX_ERROR_MESSAGE);
    }

    #[test]
    fn match_dto_truncates_text() {
        let m = YaraMatchDto {
            rule_name: "r".repeat(300),
            namespace: "n".to_string(),
            tags: vec!["t".repeat(300)],
            category: "c".to_string(),
            severity: "s".to_string(),
            description: "d".repeat(600),
        }
        .truncated();
        assert!(m.rule_name.len() <= JAIL_MAX_TEXT_FIELD);
        assert!(m.description.len() <= JAIL_MAX_TEXT_FIELD);
        assert!(m.tags[0].len() <= JAIL_MAX_TEXT_FIELD);
    }
}
