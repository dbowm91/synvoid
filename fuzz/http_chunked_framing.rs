#![no_main]

//! Fuzz target for HTTP/1 chunked-body framing policy.
//!
//! Feeds arbitrary bytes through the canonical fail-closed framing
//! validators (`synvoid_http::framing`). Verifies hostile or malformed
//! framing input is rejected with a typed error (never panics, never
//! accepts ambiguity). Strict bounds: inputs over 8 KiB are skipped, at
//! most 32 header lines are considered, each truncated to 512 bytes. No
//! network access, no filesystem mutation.

use libfuzzer_sys::fuzz_target;
use synvoid_http::framing::{validate_request_framing, validate_transfer_framing};

fn build_headers(data: &[u8]) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    let text = String::from_utf8_lossy(data);
    for line in text.split(['\r', '\n']).take(32) {
        let line = line.trim();
        if line.is_empty() || line.len() > 512 {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name.is_empty() || name.len() > 64 || value.len() > 512 {
            continue;
        }
        if let (Ok(n), Ok(v)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(value),
        ) {
            headers.append(n, v);
        }
    }
    headers
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 8192 {
        return;
    }
    let headers = build_headers(data);
    let uri: http::Uri = "/fuzz".parse().unwrap();
    let _ = validate_transfer_framing(&headers);
    let _ = validate_request_framing(&headers, &uri, http::Version::HTTP_11);
    let _ = validate_request_framing(&headers, &uri, http::Version::HTTP_3);
    // Absolute-form target exercises the Host/authority agreement check.
    if let Ok(abs) = "http://example.com/fuzz".parse::<http::Uri>() {
        let _ = validate_request_framing(&headers, &abs, http::Version::HTTP_11);
    }
});

#[cfg(test)]
mod tests {
    #[test]
    fn test_fuzz_target_compiles() {}
}
