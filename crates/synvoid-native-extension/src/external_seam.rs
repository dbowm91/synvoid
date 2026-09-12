//! Concrete follow-up seam for a future external native-extension host.
//!
//! Phase 28 deliberately does NOT implement out-of-process hosting and does
//! NOT add a generic command-execution IPC API. This module defines the
//! smallest typed contract a future external host backend would need, so the
//! follow-up has versioned DTOs and explicit bounds to build on — with tests
//! asserting the seam claims no execution today.
//!
//! Non-goals (explicit):
//! - no generic command execution or remote-eval operations from the request path;
//! - no inherited secrets beyond explicit capability grants;
//! - no mesh-distributed native binaries (mesh peers distribute signed WASM,
//!   never shared libraries).

/// Wire/protocol version of the external-host contract.
pub const EXTERNAL_HOST_CONTRACT_VERSION: u32 = 1;

/// Maximum request header block (bytes) an external host may receive.
pub const MAX_EXTERNAL_REQUEST_HEADERS_BYTES: usize = 64 * 1024;

/// Maximum request body (bytes) forwarded to an external host.
pub const MAX_EXTERNAL_REQUEST_BODY_BYTES: usize = 256 * 1024;

/// Default per-request deadline for an external host call.
pub const DEFAULT_EXTERNAL_HOST_TIMEOUT_MS: u64 = 50;

/// Default concurrency bound per external host backend.
pub const DEFAULT_EXTERNAL_HOST_MAX_INFLIGHT: usize = 64;

/// Versioned request forwarded to an external native-extension host.
///
/// Fixed-shape and size-bounded: no streaming, no file descriptors, no
/// environment/secret inheritance.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExternalHostRequest {
    /// Contract version (must equal [`EXTERNAL_HOST_CONTRACT_VERSION`]).
    pub contract_version: u32,
    /// Request ID for deadline/cancellation correlation (opaque caller token).
    pub request_id: String,
    /// HTTP method (uppercase, bounded length).
    pub method: String,
    /// Request path (origin-form, bounded length).
    pub path: String,
    /// Headers as name/value pairs (bounded count and bytes).
    pub headers: Vec<(String, String)>,
    /// Optional body (bounded by [`MAX_EXTERNAL_REQUEST_BODY_BYTES`]).
    pub body: Option<Vec<u8>>,
}

/// Versioned decision returned by an external native-extension host.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ExternalHostDecision {
    /// Pass the request through unchanged.
    Pass,
    /// Block with a status code and bounded body.
    Block {
        /// HTTP status code (4xx/5xx).
        status: u16,
        /// Bounded response body.
        body: String,
    },
}

/// Capability grant explicitly handed to an external host call.
///
/// There are no ambient capabilities: an external host receives exactly what
/// is listed here, nothing inherited from the server process.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ExternalHostCapabilities {
    /// Whether the host may return mutated response headers.
    pub allow_header_mutation: bool,
}

/// Error from external-host contract validation (local only, no transport).
#[derive(Debug, thiserror::Error)]
pub enum ExternalSeamError {
    #[error("unsupported external host contract version {got}, expected {expected}")]
    VersionMismatch { got: u32, expected: u32 },
    #[error("external host request exceeds bound: {0}")]
    BoundExceeded(String),
}

/// Validate an [`ExternalHostRequest`] against the contract bounds.
///
/// This is pure local validation for the future host boundary. It performs no
/// I/O and executes no plugin code.
pub fn validate_external_host_request(
    request: &ExternalHostRequest,
) -> Result<(), ExternalSeamError> {
    if request.contract_version != EXTERNAL_HOST_CONTRACT_VERSION {
        return Err(ExternalSeamError::VersionMismatch {
            got: request.contract_version,
            expected: EXTERNAL_HOST_CONTRACT_VERSION,
        });
    }
    if request.method.len() > 16 {
        return Err(ExternalSeamError::BoundExceeded(
            "method longer than 16 bytes".to_string(),
        ));
    }
    if request.path.len() > 4096 {
        return Err(ExternalSeamError::BoundExceeded(
            "path longer than 4096 bytes".to_string(),
        ));
    }
    if request.headers.len() > 128 {
        return Err(ExternalSeamError::BoundExceeded(
            "more than 128 headers".to_string(),
        ));
    }
    let mut header_bytes = 0usize;
    for (name, value) in &request.headers {
        header_bytes += name.len() + value.len();
        if name.len() > 1024 || value.len() > 8192 {
            return Err(ExternalSeamError::BoundExceeded(
                "header name/value too large".to_string(),
            ));
        }
    }
    if header_bytes > MAX_EXTERNAL_REQUEST_HEADERS_BYTES {
        return Err(ExternalSeamError::BoundExceeded(
            "header block exceeds 64 KiB".to_string(),
        ));
    }
    if let Some(body) = &request.body {
        if body.len() > MAX_EXTERNAL_REQUEST_BODY_BYTES {
            return Err(ExternalSeamError::BoundExceeded(
                "body exceeds 256 KiB".to_string(),
            ));
        }
    }
    if request.request_id.len() > 128 {
        return Err(ExternalSeamError::BoundExceeded(
            "request_id longer than 128 bytes".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_request() -> ExternalHostRequest {
        ExternalHostRequest {
            contract_version: EXTERNAL_HOST_CONTRACT_VERSION,
            request_id: "req-1".to_string(),
            method: "GET".to_string(),
            path: "/health".to_string(),
            headers: vec![("host".to_string(), "example.com".to_string())],
            body: None,
        }
    }

    #[test]
    fn valid_request_passes_validation() {
        assert!(validate_external_host_request(&valid_request()).is_ok());
    }

    #[test]
    fn wrong_contract_version_rejected() {
        let mut req = valid_request();
        req.contract_version = EXTERNAL_HOST_CONTRACT_VERSION + 1;
        assert!(matches!(
            validate_external_host_request(&req),
            Err(ExternalSeamError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn oversized_body_rejected() {
        let mut req = valid_request();
        req.body = Some(vec![0u8; MAX_EXTERNAL_REQUEST_BODY_BYTES + 1]);
        assert!(matches!(
            validate_external_host_request(&req),
            Err(ExternalSeamError::BoundExceeded(_))
        ));
    }

    #[test]
    fn too_many_headers_rejected() {
        let mut req = valid_request();
        req.headers = (0..129)
            .map(|i| (format!("x-h-{i}"), "v".to_string()))
            .collect();
        assert!(validate_external_host_request(&req).is_err());
    }

    #[test]
    fn seam_claims_no_execution() {
        // The seam must not grow transport/executor surface: assert the module
        // source contains no process-spawning, socket, or dynamic-loading APIs.
        // (Split before the test module: the forbidden list itself lives below
        // and must not self-match.)
        let src = include_str!("external_seam.rs");
        let code = src.split("#[cfg(test)]").next().unwrap_or(src);
        for forbidden in [
            "Command",
            "Stdio",
            "TcpStream",
            "UdpSocket",
            "UnixStream",
            "libloading",
            "Library",
            "dlopen",
            "shell",
        ] {
            assert!(
                !code.contains(forbidden),
                "external seam must not contain execution primitive '{forbidden}'"
            );
        }
    }
}
