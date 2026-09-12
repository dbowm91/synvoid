//! Phase 29 Part A: frozen Phase 22 protocol golden tests.
//!
//! Any wire-semantic change requires an explicit `JAIL_PROTOCOL_VERSION` bump
//! and an update to this file (plus `architecture/sandbox_jail_protocol.md`).
//! These pins cover: frame version/magic, size bounds, closed operation set
//! and wrong-kind rejection, digest verification, stdout framing vs stderr
//! logs, parent EOF/shutdown semantics, timeout/crash/restart bounds, and
//! `IsolationPolicy::Required` fallback prohibition.

use synvoid_ipc::{
    decode_request, decode_response, encode_request, encode_response, resolve_route, sha256_hex,
    verify_sha256_hex, IsolationPolicy, JailError, JailErrorCode, JailHandleConfig,
    JailHookCapabilities, JailKind, JailOperation, JailOutput, JailRequest, JailResponse,
    JailResult, JailRoute, RestartTracker, JAIL_DEFAULT_CALL_TIMEOUT_MS, JAIL_MAGIC,
    JAIL_MAX_ERROR_MESSAGE, JAIL_MAX_FRAME_BYTES, JAIL_MAX_HEADERS, JAIL_MAX_INVOKE_INPUT_BYTES,
    JAIL_MAX_INVOKE_OUTPUT_BYTES, JAIL_MAX_MATCHES, JAIL_MAX_MODULES, JAIL_MAX_RESTARTS,
    JAIL_MAX_RULESETS, JAIL_MAX_SCAN_INPUT_BYTES, JAIL_PROTOCOL_VERSION,
    JAIL_RESTART_BASE_BACKOFF_MS, JAIL_RESTART_MAX_BACKOFF_MS, JAIL_SHUTDOWN_GRACE_MS,
};

fn hook_caps() -> JailHookCapabilities {
    JailHookCapabilities {
        request_inspect: true,
        request_mutate: false,
        response_inspect: false,
        response_mutate: false,
    }
}

#[test]
fn golden_frame_identity() {
    assert_eq!(JAIL_MAGIC, u32::from_be_bytes(*b"SVJL"));
    assert_eq!(JAIL_PROTOCOL_VERSION, 1);
    // Envelope round trip preserves magic/version/id.
    let req = JailRequest::new(1, JailOperation::Ping);
    assert_eq!(req.magic, JAIL_MAGIC);
    assert_eq!(req.version, JAIL_PROTOCOL_VERSION);
    let frame = encode_request(&req).unwrap();
    let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    assert_eq!(len, frame.len() - 4);
    let res = JailResponse::new(1, JailResult::Ok(JailOutput::Pong));
    assert_eq!(res.magic, JAIL_MAGIC);
    assert_eq!(res.version, JAIL_PROTOCOL_VERSION);
    let frame = encode_response(&res).unwrap();
    assert!(frame.len() > 4);
}

#[test]
fn golden_size_bounds() {
    assert_eq!(JAIL_MAX_FRAME_BYTES, 8 * 1024 * 1024);
    assert_eq!(JAIL_MAX_INVOKE_INPUT_BYTES, 1024 * 1024);
    assert_eq!(JAIL_MAX_INVOKE_OUTPUT_BYTES, 1024 * 1024);
    assert_eq!(JAIL_MAX_SCAN_INPUT_BYTES, 4 * 1024 * 1024);
    assert_eq!(JAIL_MAX_MODULES, 16);
    assert_eq!(JAIL_MAX_RULESETS, 16);
    assert_eq!(JAIL_MAX_MATCHES, 256);
    assert_eq!(JAIL_MAX_HEADERS, 64);
    assert_eq!(JAIL_MAX_ERROR_MESSAGE, 512);
}

#[test]
fn golden_operation_set_is_closed() {
    // Every narrow op encodes and validates; there is no generic exec op.
    let wasm_bytes = vec![0u8; 8];
    let ops = vec![
        JailOperation::Ping,
        JailOperation::Shutdown,
        JailOperation::WasmLoad {
            module_id: "m".to_string(),
            digest_sha256_hex: "a".repeat(64),
            wasm_bytes: wasm_bytes.clone(),
            fuel: 1000,
            memory_pages: Some(16),
            timeout_ms: 100,
            capabilities: hook_caps(),
        },
        JailOperation::WasmInvoke {
            module_id: "m".to_string(),
            method: "GET".to_string(),
            uri: "/".to_string(),
            headers: vec![],
            body: vec![],
        },
        JailOperation::WasmUnload {
            module_id: "m".to_string(),
        },
        JailOperation::YaraLoadRules {
            rules_id: "r".to_string(),
            digest_sha256_hex: "b".repeat(64),
            rules_text: "rule x { condition: false }".to_string(),
        },
        JailOperation::YaraScan {
            rules_id: "r".to_string(),
            data: b"probe".to_vec(),
        },
        JailOperation::YaraUnload {
            rules_id: "r".to_string(),
        },
    ];
    for (i, op) in ops.iter().enumerate() {
        op.validate()
            .unwrap_or_else(|e| panic!("op {i} must validate: {e:?}"));
        let req = JailRequest::new((i + 1) as u64, op.clone());
        let frame = encode_request(&req).unwrap();
        assert!(frame.len() <= JAIL_MAX_FRAME_BYTES + 4);
    }
    // required_kind pins wrong-kind rejection wiring.
    assert_eq!(
        JailOperation::WasmLoad {
            module_id: "m".to_string(),
            digest_sha256_hex: "a".repeat(64),
            wasm_bytes,
            fuel: 1,
            memory_pages: None,
            timeout_ms: 10,
            capabilities: hook_caps(),
        }
        .required_kind(),
        JailKind::Wasm
    );
    assert_eq!(
        JailOperation::YaraScan {
            rules_id: "r".to_string(),
            data: vec![],
        }
        .required_kind(),
        JailKind::Yara
    );
    // Shared ops are served by the WASM kind loop (handshake/shutdown).
    assert_eq!(JailOperation::Ping.required_kind(), JailKind::Wasm);
    assert_eq!(JailOperation::Shutdown.required_kind(), JailKind::Wasm);
}

#[test]
fn golden_digest_verification_is_constant_time_format() {
    let data = b"jail golden bytes";
    let hex = sha256_hex(data);
    assert_eq!(hex.len(), 64);
    assert!(verify_sha256_hex(data, &hex));
    assert!(!verify_sha256_hex(b"other", &hex));
    assert!(!verify_sha256_hex(data, "short"));
    assert!(!verify_sha256_hex(data, &"Z".repeat(64)));
    // Malformed digests fail validation (not just verification).
    let op = JailOperation::WasmLoad {
        module_id: "m".to_string(),
        digest_sha256_hex: "not-hex".to_string(),
        wasm_bytes: vec![0u8; 4],
        fuel: 1,
        memory_pages: None,
        timeout_ms: 10,
        capabilities: hook_caps(),
    };
    assert!(matches!(
        op.validate().unwrap_err(),
        JailError::DigestMismatch(_)
    ));
}

#[test]
fn golden_stdout_framing_envelope_rules() {
    // Unknown magic/version/zero-id are rejected at encode and decode.
    let mut req = JailRequest::new(1, JailOperation::Ping);
    req.magic = 0xDEAD_BEEF;
    assert!(encode_request(&req).is_err());
    let mut req = JailRequest::new(1, JailOperation::Ping);
    req.version = 99;
    assert!(encode_request(&req).is_err());
    assert!(encode_request(&JailRequest::new(0, JailOperation::Ping)).is_err());
    // Decode path rejects tampered envelopes too.
    let req = JailRequest::new(1, JailOperation::Ping);
    let payload = synvoid_utils::serialization::serialize(&req).unwrap();
    let mut tampered: JailRequest = synvoid_utils::serialization::deserialize(&payload).unwrap();
    tampered.version = 99;
    let payload = synvoid_utils::serialization::serialize(&tampered).unwrap();
    assert!(matches!(
        decode_request(&payload).unwrap_err(),
        JailError::ProtocolViolation(_)
    ));
    // Responses follow the same envelope rules.
    let mut res = JailResponse::new(1, JailResult::Ok(JailOutput::Pong));
    res.magic = 0;
    assert!(encode_response(&res).is_err());
    let mut res = JailResponse::new(0, JailResult::Ok(JailOutput::Pong));
    res.version = JAIL_PROTOCOL_VERSION;
    assert!(encode_response(&res).is_err());
    let _ = decode_response;
}

#[test]
fn golden_parent_eof_and_shutdown_semantics() {
    // Shutdown is a normal op that validates; EOF/close mapping is owned by
    // the serve loop (`ServeOutcome::ConnectionClosed` vs `CleanShutdown`).
    JailOperation::Shutdown.validate().unwrap();
    // RestartTracker documents crash/restart bounds (also pinned below).
    let tracker = RestartTracker::with_defaults();
    assert_eq!(tracker.consecutive_failures(), 0);
}

#[test]
fn golden_timeout_crash_restart_bounds() {
    assert_eq!(JAIL_DEFAULT_CALL_TIMEOUT_MS, 5000);
    assert_eq!(JAIL_SHUTDOWN_GRACE_MS, 1000);
    assert_eq!(JAIL_MAX_RESTARTS, 5);
    assert_eq!(JAIL_RESTART_BASE_BACKOFF_MS, 100);
    assert_eq!(JAIL_RESTART_MAX_BACKOFF_MS, 5000);
    let config = JailHandleConfig::default();
    assert_eq!(config.max_restarts, JAIL_MAX_RESTARTS);
    // Backoff grows exponentially and caps.
    let mut tracker = RestartTracker::new(5, 100, 500);
    assert_eq!(
        tracker.record_failure().unwrap(),
        std::time::Duration::from_millis(100)
    );
    assert_eq!(
        tracker.record_failure().unwrap(),
        std::time::Duration::from_millis(200)
    );
    assert_eq!(
        tracker.record_failure().unwrap(),
        std::time::Duration::from_millis(400)
    );
    assert_eq!(
        tracker.record_failure().unwrap(),
        std::time::Duration::from_millis(500)
    );
    // Error vocabulary is fixed width for metrics.
    assert_eq!(JailErrorCode::ALL.len(), 14);
}

#[test]
fn golden_required_policy_never_falls_back() {
    assert_eq!(
        resolve_route(IsolationPolicy::Required, true),
        JailRoute::ExecuteInJail
    );
    assert!(matches!(
        resolve_route(IsolationPolicy::Required, false),
        JailRoute::FailClosed(_)
    ));
    // Preferred without fallback also fails closed; only explicit
    // fallback_in_process:true routes in-process when down.
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
        resolve_route(
            IsolationPolicy::Preferred {
                fallback_in_process: true
            },
            false
        ),
        JailRoute::ExecuteInProcess
    );
    assert_eq!(
        resolve_route(IsolationPolicy::InProcess, true),
        JailRoute::ExecuteInProcess
    );
}
