//! Shared header encoding for the WASM jail ABI.
//!
//! Canonical owner (Phase 29): this crate. The root
//! `src/sandbox/policy.rs` re-exports this helper for in-process comparison
//! harnesses so both paths observe identical input. Duplicate header names
//! collapse last-wins, matching the in-process serverless path.

use std::collections::HashMap;

use synvoid_ipc::{
    JailError, JAIL_MAX_HEADERS, JAIL_MAX_HEADER_NAME_LEN, JAIL_MAX_HEADER_VALUE_LEN,
};

/// Encode guest header pairs to the JSON object string the `handle_request`
/// ABI expects (same encoding as the in-process serverless path: duplicate
/// names collapse last-wins).
pub fn headers_to_guest_json(headers: &[(String, String)]) -> Result<String, JailError> {
    if headers.len() > JAIL_MAX_HEADERS {
        return Err(JailError::Oversized("too many headers".to_string()));
    }
    let mut map: HashMap<&str, &str> = HashMap::with_capacity(headers.len());
    for (name, value) in headers {
        if name.is_empty()
            || name.len() > JAIL_MAX_HEADER_NAME_LEN
            || value.len() > JAIL_MAX_HEADER_VALUE_LEN
        {
            return Err(JailError::Oversized(
                "header name/value length out of bounds".to_string(),
            ));
        }
        map.insert(name.as_str(), value.as_str());
    }
    serde_json::to_string(&map)
        .map_err(|e| JailError::FramingError(format!("header encoding failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_encode_last_wins_and_bounded() {
        let headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("X-Dup".to_string(), "first".to_string()),
            ("X-Dup".to_string(), "second".to_string()),
        ];
        let json = headers_to_guest_json(&headers).unwrap();
        let map: HashMap<String, String> = serde_json::from_str(&json).unwrap();
        assert_eq!(map.get("Host").map(String::as_str), Some("example.com"));
        assert_eq!(map.get("X-Dup").map(String::as_str), Some("second"));
        let too_many = vec![("h".to_string(), "v".to_string()); 65];
        assert!(headers_to_guest_json(&too_many).is_err());
    }
}
