#![no_main]

//! Fuzz target for IPC message handling.
//!
//! Tests deserialization and validation of [`maluwaf::process::Message`]
//! variants from arbitrary byte input, including signed IPC messages
//! with randomly generated keys. Verifies that malformed input is
//! rejected without panicking.

use libfuzzer_sys::fuzz_target;
use maluwaf::process::ipc_signed::{IpcSigner, SignedIpcMessage};
use maluwaf::process::{ErrorCode, ErrorSeverity, Message, WorkerId};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Test 1: Raw message deserialization
    if let Ok(msg) = postcard::from_bytes::<Message>(data) {
        let _ = msg.validate();
    }

    // Test 2: Signed message deserialization with various keys
    if data.len() > 32 {
        let key: [u8; 32] = match data[..32].try_into() {
            Ok(k) => k,
            Err(_) => return,
        };

        let signer = IpcSigner::new(&key);

        // Try to deserialize as signed message
        if let Ok(msg) = SignedIpcMessage::deserialize_signed::<Message>(&data[32..], &signer) {
            let _ = msg.validate();
        }
    }

    // Test 3: Construct various message types with fuzzed string data
    let fuzz_string = String::from_utf8_lossy(data).to_string();

    // Test WorkerError
    let _ = Message::WorkerError {
        id: WorkerId(0),
        error: fuzz_string.clone(),
        severity: ErrorSeverity::Error,
        error_code: ErrorCode::Unknown,
    };

    // Test ThreatIndicatorAnnounce
    let _ = Message::ThreatIndicatorAnnounce {
        worker_id: 0,
        threat_type: maluwaf::process::ThreatIndicatorType::IpBlock,
        indicator_value: fuzz_string.clone(),
        severity: maluwaf::process::ThreatSeverityLevel::Medium,
        reason: fuzz_string.clone(),
        ttl_seconds: 3600,
        site_scope: fuzz_string.clone(),
        rate_limit_requests: None,
        rate_limit_window_secs: None,
        suspicious_pattern: None,
    };

    // Test SocketHandoffFailed
    let _ = Message::SocketHandoffFailed { error: fuzz_string };
});

#[cfg(test)]
mod tests {
    #[test]
    fn test_fuzz_target_compiles() {
        assert!(true);
    }
}
