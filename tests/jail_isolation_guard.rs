//! Root-test ownership: COMPOSITION
//! Rationale: validates sandbox jail IPC across synvoid-ipc (protocol +
//! supervision + binary resolution), synvoid-jail-runtime (child services +
//! sandbox entry, Phase 29), src/sandbox (parent policy/composition facades),
//! synvoid-plugin-runtime (in-jail WASM execution), and synvoid-yara
//! (canonical YARA engine, Phase 26).
//!
//! Phase 22 (sandbox jail IPC and runtime closure) coverage plus Phase 29
//! (jail runtime package/process split):
//!
//! - static policy: no generic exec RPC, no secrets/payloads in argv or env,
//!   no test-hatch wiring in production spawn paths, no detached children,
//!   composition-boundary imports respected, deterministic exe-dir binary
//!   resolution (no CWD/PATH/writable-dir search)
//! - behavioral: WASM/YARA round trips (in-process services, framed loop, and
//!   live child processes via compat shims and dedicated binaries),
//!   adversarial framing, deadlines, crash isolation with bounded restart,
//!   required-mode fail-closed, graceful reaping
//!
//! Live-child tests spawn `CARGO_BIN_EXE_synvoid --wasm-jail/--yara-jail`
//! (compat shims forwarding to `synvoid-jail-runtime`) with
//! `SYNVOID_JAIL_PERMIT_NO_SANDBOX=1` (test-only hatch: hermetic on any
//! platform; every other jail property — framing, digests, limits,
//! supervision — is exercised for real). Dedicated-binary round trips live in
//! `crates/synvoid-jail-runtime/tests/jail_binary_integration.rs`. Tests that
//! need POSIX-only helpers are `cfg(unix)`-gated and recorded in
//! `architecture/sandbox_jail_protocol.md`.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use synvoid::sandbox::{
    headers_to_guest_json, JailClient, WasmJailService, YaraJailService, JAIL_PERMIT_NO_SANDBOX_ENV,
};
use synvoid_ipc::{
    decode_request, decode_response, encode_request, read_frame, resolve_route,
    serve_jail_connection, sha256_hex, write_frame, FrameRead, IsolationPolicy, JailError,
    JailErrorCode, JailHandle, JailHandleConfig, JailHandler, JailHookCapabilities, JailKind,
    JailOperation, JailOutput, JailRequest, JailResponse, JailResult, JailRoute, JailSpawnSpec,
    JAIL_MAX_FRAME_BYTES, JAIL_MAX_INVOKE_INPUT_BYTES, JAIL_MAX_MATCHES, JAIL_MAX_MODULES,
    JAIL_MAX_RULESETS, JAIL_MAX_SCAN_INPUT_BYTES, JAIL_PROTOCOL_VERSION,
};

// ─── Shared helpers ─────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_source(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e))
}

fn strip_comments_and_strings(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut in_char = false;
    let mut in_line_comment = false;
    let mut in_block_comment: usize = 0;
    while let Some(c) = chars.next() {
        if in_line_comment {
            if c == '\n' {
                in_line_comment = false;
                out.push(c);
            }
            continue;
        }
        if in_block_comment > 0 {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block_comment -= 1;
            } else if c == '/' && chars.peek() == Some(&'*') {
                chars.next();
                in_block_comment += 1;
            }
            continue;
        }
        if in_string {
            if c == '\\' {
                chars.next();
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        if in_char {
            if c == '\\' {
                chars.next();
            } else if c == '\'' {
                in_char = false;
            }
            continue;
        }
        match c {
            '/' if chars.peek() == Some(&'/') => {
                chars.next();
                in_line_comment = true;
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                in_block_comment += 1;
            }
            '"' => in_string = true,
            '\'' => in_char = true,
            _ => out.push(c),
        }
    }
    out
}

fn hook_caps() -> JailHookCapabilities {
    JailHookCapabilities {
        request_inspect: true,
        request_mutate: false,
        response_inspect: false,
        response_mutate: false,
    }
}

/// Minimal `handle_request` module: writes status 0 (decoded as 200 via
/// unwrap_or(OK)) and returns body length 0. Same shape as the
/// plugin-runtime `minimal_handler` fixture.
fn minimal_handler_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (memory (export "memory") 2)
            (global $heap (mut i32) (i32.const 0))
            (func (export "guest_alloc") (param $size i32) (result i32)
                (local $ptr i32)
                (local.set $ptr (global.get $heap))
                (global.set $heap (i32.add (global.get $heap) (local.get $size)))
                (local.get $ptr))
            (func (export "guest_free") (param $ptr i32) (param $size i32))
            (func (export "handle_request")
                (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
                (result i32)
                (i32.store8 (local.get 8) (i32.const 0))
                (i32.store8 (i32.add (local.get 8) (i32.const 1)) (i32.const 0))
                (i32.store8 (i32.add (local.get 8) (i32.const 2)) (i32.const 0))
                (i32.store8 (i32.add (local.get 8) (i32.const 3)) (i32.const 0))
                i32.const 0)
        )
        "#,
    )
    .expect("valid WAT")
}

fn wasm_load_op(module_id: &str, wasm_bytes: Vec<u8>) -> JailOperation {
    JailOperation::WasmLoad {
        digest_sha256_hex: sha256_hex(&wasm_bytes),
        module_id: module_id.to_string(),
        wasm_bytes,
        fuel: 1_000_000,
        memory_pages: Some(16),
        timeout_ms: 5_000,
        capabilities: hook_caps(),
    }
}

const PROBE_RULES: &str = r#"
rule jail_probe {
    meta:
        category = "test"
        severity = "low"
        description = "jail round-trip probe"
    strings:
        $a = "synvoid-jail-probe-string"
    condition:
        $a
}
"#;

fn yara_load_op(rules_id: &str) -> JailOperation {
    JailOperation::YaraLoadRules {
        digest_sha256_hex: sha256_hex(PROBE_RULES.as_bytes()),
        rules_id: rules_id.to_string(),
        rules_text: PROBE_RULES.to_string(),
    }
}

// ─── A. Static policy ───────────────────────────────────────────────────────

#[test]
fn jail_protocol_has_no_generic_exec_surface() {
    let text = strip_comments_and_strings(&read_source("crates/synvoid-ipc/src/jail_protocol.rs"));
    for forbidden in [
        "std::process::Command",
        "Command::new",
        "/bin/sh",
        "cmd.exe",
        "shell",
        "execve",
        "system(",
    ] {
        assert!(
            !text.contains(forbidden),
            "jail protocol must not expose generic execution: found {forbidden:?}"
        );
    }
    // The operation set is closed: every variant is an explicit narrow op.
    for required in [
        "WasmLoad",
        "WasmInvoke",
        "WasmUnload",
        "YaraLoadRules",
        "YaraScan",
        "YaraUnload",
        "Ping",
        "Shutdown",
    ] {
        assert!(text.contains(required), "missing narrow op {required}");
    }
}

#[test]
fn jail_spawn_argv_carries_no_payload_or_secrets() {
    let text = strip_comments_and_strings(&read_source("crates/synvoid-ipc/src/jail_process.rs"));
    // Argv is built from the mode flag only.
    assert!(
        text.contains("kind.cli_flag()"),
        "spawn must use cli_flag argv"
    );
    // No secret/payload material is placed into argv or env by the parent.
    for forbidden in [
        "wasm_bytes",
        "digest_sha256",
        "rules_text",
        "SYNVOID_IPC_KEY",
        "token",
        "secret",
        "password",
        "private_key",
    ] {
        assert!(
            !text.to_lowercase().contains(&forbidden.to_lowercase()),
            "jail spawn path must not handle {forbidden:?}"
        );
    }
    // Deterministic exe-dir resolution (Phase 29): no CWD/PATH/plugin-dir
    // search in the resolver. Absence checks use stripped code (no comments
    // or strings); presence checks use raw source because the local
    // strip helper treats `'static` lifetimes as char literals and string
    // literals (binary names) are stripped by design.
    let resolver_stripped =
        strip_comments_and_strings(&read_source("crates/synvoid-ipc/src/jail_binary.rs"));
    for forbidden in [
        "current_dir",
        "var(\"PATH\")",
        "var(\"Path\")",
        "search_path",
        "which(",
        "plugin_dir",
        "PLUGINS_DIR",
    ] {
        assert!(
            !resolver_stripped.contains(forbidden),
            "jail resolver must not search {forbidden:?}"
        );
    }
    let resolver_raw = read_source("crates/synvoid-ipc/src/jail_binary.rs");
    assert!(
        resolver_raw.contains("current_exe"),
        "resolver must anchor on current_exe dir"
    );
    assert!(
        resolver_raw.contains("synvoid-wasm-jail") && resolver_raw.contains("synvoid-yara-jail"),
        "resolver must name both dedicated binaries"
    );
}

#[test]
fn jail_parent_never_sets_test_hatch() {
    // The child reads the hatch; nothing in the parent/supervision path may
    // set it (production spawn must fail closed, never bypass).
    for file in [
        "crates/synvoid-ipc/src/jail_process.rs",
        "crates/synvoid-ipc/src/jail_protocol.rs",
        "crates/synvoid-ipc/src/jail_binary.rs",
        "src/sandbox/policy.rs",
        "src/sandbox/wasm_service.rs",
        "src/sandbox/yara_service.rs",
        "crates/synvoid-jail-runtime/src/wasm_service.rs",
        "crates/synvoid-jail-runtime/src/yara_service.rs",
        "crates/synvoid-jail-runtime/src/headers.rs",
    ] {
        let text = read_source(file);
        assert!(
            !text.contains(JAIL_PERMIT_NO_SANDBOX_ENV),
            "{file} must not reference the test hatch"
        );
    }
    // Canonical child entry owns the hatch literal; the root facade
    // re-exports the const (name only, no literal).
    let child = read_source("crates/synvoid-jail-runtime/src/sandbox_entry.rs");
    assert!(
        child.contains(JAIL_PERMIT_NO_SANDBOX_ENV),
        "jail-runtime sandbox entry must document the hatch"
    );
    assert!(
        !strip_comments_and_strings(&child).contains("set_var"),
        "jail-runtime must never set environment variables"
    );
    let facade = read_source("src/sandbox/mod.rs");
    assert!(
        facade.contains("JAIL_PERMIT_NO_SANDBOX_ENV"),
        "root sandbox facade must re-export the hatch const"
    );
    assert!(
        !strip_comments_and_strings(&facade).contains("set_var"),
        "src/sandbox must never set environment variables"
    );
}

#[test]
fn jail_code_owns_its_children_without_forget() {
    for file in [
        "crates/synvoid-ipc/src/jail_process.rs",
        "crates/synvoid-ipc/src/jail_protocol.rs",
        "crates/synvoid-ipc/src/jail_binary.rs",
        "src/sandbox/mod.rs",
        "src/sandbox/policy.rs",
        "src/sandbox/wasm_service.rs",
        "src/sandbox/yara_service.rs",
        "crates/synvoid-jail-runtime/src/lib.rs",
        "crates/synvoid-jail-runtime/src/sandbox_entry.rs",
        "crates/synvoid-jail-runtime/src/wasm_service.rs",
        "crates/synvoid-jail-runtime/src/yara_service.rs",
        "crates/synvoid-jail-runtime/src/headers.rs",
    ] {
        let text = strip_comments_and_strings(&read_source(file));
        assert!(
            !text.contains("mem::forget"),
            "{file}: mem::forget forbidden"
        );
        assert!(
            !text.contains("ManuallyDrop"),
            "{file}: ManuallyDrop forbidden"
        );
    }
    // Shutdown path is deterministic: shutdown request, then kill, then reap.
    let text = read_source("crates/synvoid-ipc/src/jail_process.rs");
    assert!(
        text.contains("JailOperation::Shutdown"),
        "missing shutdown send"
    );
    assert!(text.contains(".kill()"), "missing kill fallback");
    assert!(text.contains(".wait()"), "missing reap");
}

#[test]
fn jail_respects_composition_boundary() {
    // Request-path-adjacent jail code consumes narrow traits/services only:
    // no mesh/DHT/Raft, block-store mutation, or admin authority imports.
    // The jail runtime must additionally never import root/supervisor paths.
    for file in [
        "src/sandbox/mod.rs",
        "src/sandbox/policy.rs",
        "src/sandbox/wasm_service.rs",
        "src/sandbox/yara_service.rs",
        "crates/synvoid-ipc/src/jail_process.rs",
        "crates/synvoid-ipc/src/jail_protocol.rs",
        "crates/synvoid-ipc/src/jail_binary.rs",
        "crates/synvoid-jail-runtime/src/lib.rs",
        "crates/synvoid-jail-runtime/src/sandbox_entry.rs",
        "crates/synvoid-jail-runtime/src/wasm_service.rs",
        "crates/synvoid-jail-runtime/src/yara_service.rs",
        "crates/synvoid-jail-runtime/src/headers.rs",
    ] {
        let text = strip_comments_and_strings(&read_source(file));
        for forbidden in [
            "synvoid_mesh",
            "block_store",
            "is_mesh_id_blocked",
            "ThreatIntelligenceManager",
            "admin_mutation",
            "AdminMutationAuthority",
        ] {
            assert!(
                !text.contains(forbidden),
                "{file}: forbidden composition import {forbidden:?}"
            );
        }
    }
    for file in [
        "crates/synvoid-jail-runtime/src/lib.rs",
        "crates/synvoid-jail-runtime/src/sandbox_entry.rs",
        "crates/synvoid-jail-runtime/src/wasm_service.rs",
        "crates/synvoid-jail-runtime/src/yara_service.rs",
        "crates/synvoid-jail-runtime/src/headers.rs",
        "crates/synvoid-jail-runtime/src/bin/synvoid-wasm-jail.rs",
        "crates/synvoid-jail-runtime/src/bin/synvoid-yara-jail.rs",
    ] {
        let text = strip_comments_and_strings(&read_source(file));
        for forbidden in [
            "synvoid::supervisor",
            "synvoid::admin",
            "synvoid::mesh",
            "crate::supervisor",
            "crate::admin",
            "use synvoid::",
        ] {
            assert!(
                !text.contains(forbidden),
                "{file}: jail runtime must not import root implementation {forbidden:?}"
            );
        }
    }
}

#[test]
fn jail_stdout_carries_frames_only() {
    // A stdout log line would corrupt the length-delimited frame stream, so
    // jail modes must initialize stderr logging and never print to stdout.
    let launch = read_source("src/commands/runtime_launch.rs");
    assert!(
        launch.contains("init_logging_simple_stderr"),
        "jail launch arms must use stderr logging"
    );
    for file in [
        "src/sandbox/mod.rs",
        "src/sandbox/policy.rs",
        "src/sandbox/wasm_service.rs",
        "src/sandbox/yara_service.rs",
        "crates/synvoid-jail-runtime/src/lib.rs",
        "crates/synvoid-jail-runtime/src/sandbox_entry.rs",
        "crates/synvoid-jail-runtime/src/wasm_service.rs",
        "crates/synvoid-jail-runtime/src/yara_service.rs",
        "crates/synvoid-jail-runtime/src/headers.rs",
        "crates/synvoid-jail-runtime/src/bin/synvoid-wasm-jail.rs",
        "crates/synvoid-jail-runtime/src/bin/synvoid-yara-jail.rs",
    ] {
        // `eprintln!` (stderr) is allowed for diagnostics; only stdout
        // prints corrupt the frame stream. Strip the `e` prefix before
        // asserting so `eprintln!` does not false-positive on `println!`.
        let text = strip_comments_and_strings(&read_source(file));
        let text = text.replace("eprintln!", "").replace("eprint!", "");
        assert!(
            !text.contains("println!"),
            "{file}: println! forbidden (stdout is framed IPC; use tracing/eprintln)"
        );
        assert!(
            !text.contains("print!"),
            "{file}: print! forbidden (stdout is framed IPC)"
        );
    }
}

#[test]
fn jail_bounds_are_explicit_consts() {
    assert_eq!(JAIL_MAX_FRAME_BYTES, 8 * 1024 * 1024);
    assert_eq!(JAIL_MAX_INVOKE_INPUT_BYTES, 1024 * 1024);
    assert_eq!(JAIL_MAX_SCAN_INPUT_BYTES, 4 * 1024 * 1024);
    assert_eq!(JAIL_MAX_MODULES, 16);
    assert_eq!(JAIL_MAX_RULESETS, 16);
    assert_eq!(JAIL_MAX_MATCHES, 256);
    assert_eq!(JAIL_PROTOCOL_VERSION, 1);
}

// ─── B. Policy routing ──────────────────────────────────────────────────────

#[test]
fn required_policy_without_handle_fails_closed() {
    let client = JailClient::from_handles(
        IsolationPolicy::Required,
        IsolationPolicy::Required,
        None,
        None,
    );
    assert!(matches!(client.wasm_route(), JailRoute::FailClosed(_)));
    assert!(matches!(client.yara_route(), JailRoute::FailClosed(_)));
    // No silent fallback: calls without a handle are hard errors, never
    // in-process execution.
    let err = client
        .call_wasm(&JailOperation::Ping)
        .expect_err("must fail closed");
    assert!(matches!(err, JailError::Unavailable(_)));
    let err = client
        .call_yara(&JailOperation::Ping)
        .expect_err("must fail closed");
    assert!(matches!(err, JailError::Unavailable(_)));
}

#[test]
fn preferred_policy_with_fallback_routes_in_process_when_down() {
    let client = JailClient::from_handles(
        IsolationPolicy::Preferred {
            fallback_in_process: true,
        },
        IsolationPolicy::Preferred {
            fallback_in_process: false,
        },
        None,
        None,
    );
    assert_eq!(client.wasm_route(), JailRoute::ExecuteInProcess);
    assert!(matches!(client.yara_route(), JailRoute::FailClosed(_)));
}

#[test]
fn headers_encode_identically_for_comparison_paths() {
    let headers = vec![
        ("Host".to_string(), "example.com".to_string()),
        ("X-Dup".to_string(), "first".to_string()),
        ("X-Dup".to_string(), "second".to_string()),
    ];
    let json = headers_to_guest_json(&headers).unwrap();
    let map: std::collections::HashMap<String, String> = serde_json::from_str(&json).unwrap();
    assert_eq!(map.get("Host").map(String::as_str), Some("example.com"));
    assert_eq!(map.get("X-Dup").map(String::as_str), Some("second"));
    let too_many = vec![("h".to_string(), "v".to_string()); 65];
    assert!(headers_to_guest_json(&too_many).is_err());
}

// ─── C. WASM service ────────────────────────────────────────────────────────

#[test]
fn wasm_service_round_trip_matches_in_process() {
    let wasm_bytes = minimal_handler_wasm();
    let mut service = WasmJailService::new();
    let loaded = service.handle(&wasm_load_op("round-trip", wasm_bytes.clone()));
    assert_eq!(loaded, JailResult::Ok(JailOutput::WasmLoaded));

    let result = service.handle(&JailOperation::WasmInvoke {
        module_id: "round-trip".to_string(),
        method: "GET".to_string(),
        uri: "/probe".to_string(),
        headers: vec![("host".to_string(), "example.com".to_string())],
        body: b"input".to_vec(),
    });
    let JailResult::Ok(JailOutput::WasmResult { status, body, .. }) = result else {
        panic!("expected wasm result, got {result:?}");
    };
    assert_eq!(status, 200);
    assert!(body.is_empty());

    // In-process comparison on a deterministic fixture: identical output.
    let caps = synvoid_plugin_runtime::PluginCapabilities {
        request_inspect: true,
        ..Default::default()
    };
    let limits = synvoid_plugin_runtime::WasmResourceLimits {
        max_cpu_fuel: 1_000_000,
        timeout: Duration::from_millis(5_000),
        capabilities: std::sync::Arc::new(caps),
        ..Default::default()
    };
    let runtime = synvoid_plugin_runtime::WasmRuntime::load_from_bytes_with_priority(
        "in-process-compare",
        &wasm_bytes,
        limits,
        0,
    )
    .unwrap();
    let response = runtime
        .invoke_handler(
            "GET",
            "/probe",
            r#"{"host":"example.com"}"#,
            b"input",
            Default::default(),
        )
        .unwrap();
    assert_eq!(response.status().as_u16(), status);
    assert_eq!(response.into_body().as_ref(), body.as_slice());
}

#[test]
fn wasm_service_rejects_digest_mismatch() {
    let wasm_bytes = minimal_handler_wasm();
    let mut op = wasm_load_op("bad-digest", wasm_bytes);
    let JailOperation::WasmLoad {
        ref mut digest_sha256_hex,
        ..
    } = op
    else {
        unreachable!()
    };
    *digest_sha256_hex = "0".repeat(64);
    let mut service = WasmJailService::new();
    let result = service.handle(&op);
    assert!(
        matches!(
            result,
            JailResult::Err(ref dto) if dto.code == JailErrorCode::DigestMismatch
        ),
        "got {result:?}"
    );
    assert_eq!(service.loaded_count(), 0);
}

#[test]
fn wasm_service_rejects_wrong_kind_and_unknown_module() {
    let mut service = WasmJailService::new();
    let result = service.handle(&yara_load_op("x"));
    assert!(
        matches!(
            result,
            JailResult::Err(ref dto) if dto.code == JailErrorCode::PolicyDenied
        ),
        "got {result:?}"
    );
    let result = service.handle(&JailOperation::WasmInvoke {
        module_id: "missing".to_string(),
        method: "GET".to_string(),
        uri: "/".to_string(),
        headers: vec![],
        body: vec![],
    });
    assert!(
        matches!(
            result,
            JailResult::Err(ref dto) if dto.code == JailErrorCode::NotFound
        ),
        "got {result:?}"
    );
    let result = service.handle(&JailOperation::WasmUnload {
        module_id: "missing".to_string(),
    });
    assert!(
        matches!(
            result,
            JailResult::Err(ref dto) if dto.code == JailErrorCode::NotFound
        ),
        "got {result:?}"
    );
}

#[test]
fn wasm_service_enforces_module_cap() {
    let wasm_bytes = minimal_handler_wasm();
    let mut service = WasmJailService::new();
    for i in 0..JAIL_MAX_MODULES {
        let result = service.handle(&wasm_load_op(&format!("mod-{i}"), wasm_bytes.clone()));
        assert_eq!(result, JailResult::Ok(JailOutput::WasmLoaded), "load {i}");
    }
    let result = service.handle(&wasm_load_op("mod-overflow", wasm_bytes));
    assert!(
        matches!(
            result,
            JailResult::Err(ref dto) if dto.code == JailErrorCode::ResourceExhausted
        ),
        "got {result:?}"
    );
    // Unload frees a slot.
    assert_eq!(
        service.handle(&JailOperation::WasmUnload {
            module_id: "mod-0".to_string()
        }),
        JailResult::Ok(JailOutput::WasmUnloaded)
    );
    assert_eq!(service.loaded_count(), JAIL_MAX_MODULES - 1);
}

// ─── D. YARA service ────────────────────────────────────────────────────────

#[test]
fn yara_service_round_trip_match_and_clean() {
    let mut service = YaraJailService::new().unwrap();
    assert_eq!(
        service.handle(&yara_load_op("probe")),
        JailResult::Ok(JailOutput::YaraRulesLoaded)
    );
    let hit = service.handle(&JailOperation::YaraScan {
        rules_id: "probe".to_string(),
        data: b"prefix synvoid-jail-probe-string suffix".to_vec(),
    });
    let JailResult::Ok(JailOutput::YaraScanResult { matches }) = hit else {
        panic!("expected scan result, got {hit:?}");
    };
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_name, "jail_probe");
    assert_eq!(matches[0].category, "test");

    let clean = service.handle(&JailOperation::YaraScan {
        rules_id: "probe".to_string(),
        data: b"nothing suspicious here".to_vec(),
    });
    let JailResult::Ok(JailOutput::YaraScanResult { matches }) = clean else {
        panic!("expected scan result, got {clean:?}");
    };
    assert!(matches.is_empty());
}

#[test]
fn yara_service_rejects_bad_rules_and_digest() {
    let mut service = YaraJailService::new().unwrap();
    // Uncompilable rules: typed error, jail survives for the next load.
    let bad = JailOperation::YaraLoadRules {
        rules_id: "bad".to_string(),
        digest_sha256_hex: sha256_hex(b"rule { broken ((("),
        rules_text: "rule { broken (((".to_string(),
    };
    let result = service.handle(&bad);
    assert!(
        matches!(
            result,
            JailResult::Err(ref dto) if dto.code == JailErrorCode::ExecutionFailed
        ),
        "got {result:?}"
    );
    assert_eq!(service.loaded_count(), 0);
    // Digest mismatch is distinguished from compile failure.
    let mut op = yara_load_op("digest");
    let JailOperation::YaraLoadRules {
        ref mut digest_sha256_hex,
        ..
    } = op
    else {
        unreachable!()
    };
    *digest_sha256_hex = "f".repeat(64);
    let result = service.handle(&op);
    assert!(
        matches!(
            result,
            JailResult::Err(ref dto) if dto.code == JailErrorCode::DigestMismatch
        ),
        "got {result:?}"
    );
    // After failures the service still loads valid rules.
    assert_eq!(
        service.handle(&yara_load_op("good")),
        JailResult::Ok(JailOutput::YaraRulesLoaded)
    );
}

#[test]
fn yara_service_rejects_wrong_kind_and_enforces_cap() {
    let mut service = WasmJailService::new();
    let result = service.handle(&yara_load_op("x"));
    assert!(
        matches!(
            result,
            JailResult::Err(ref dto) if dto.code == JailErrorCode::PolicyDenied
        ),
        "wasm jail must reject yara ops, got {result:?}"
    );

    let mut service = YaraJailService::new().unwrap();
    let result = service.handle(&wasm_load_op("x", minimal_handler_wasm()));
    assert!(
        matches!(
            result,
            JailResult::Err(ref dto) if dto.code == JailErrorCode::PolicyDenied
        ),
        "yara jail must reject wasm ops, got {result:?}"
    );
    for i in 0..JAIL_MAX_RULESETS {
        let op = JailOperation::YaraLoadRules {
            digest_sha256_hex: sha256_hex(PROBE_RULES.as_bytes()),
            rules_id: format!("rules-{i}"),
            rules_text: PROBE_RULES.to_string(),
        };
        assert_eq!(
            service.handle(&op),
            JailResult::Ok(JailOutput::YaraRulesLoaded),
            "load {i}"
        );
    }
    let overflow = JailOperation::YaraLoadRules {
        digest_sha256_hex: sha256_hex(PROBE_RULES.as_bytes()),
        rules_id: "rules-overflow".to_string(),
        rules_text: PROBE_RULES.to_string(),
    };
    let result = service.handle(&overflow);
    assert!(
        matches!(
            result,
            JailResult::Err(ref dto) if dto.code == JailErrorCode::ResourceExhausted
        ),
        "got {result:?}"
    );
    let result = service.handle(&JailOperation::YaraScan {
        rules_id: "missing".to_string(),
        data: b"x".to_vec(),
    });
    assert!(
        matches!(
            result,
            JailResult::Err(ref dto) if dto.code == JailErrorCode::NotFound
        ),
        "got {result:?}"
    );
}

// ─── E. Framed loop over real services ──────────────────────────────────────

/// In-memory duplex over loopback TCP (framing is transport-agnostic; std has
/// no portable duplex pipe).
fn loopback_pair() -> (std::net::TcpStream, std::net::TcpStream) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let client = std::net::TcpStream::connect(addr).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

fn transact(stream: &mut (impl Read + Write), id: u64, op: JailOperation) -> JailResponse {
    let frame = encode_request(&JailRequest::new(id, op)).unwrap();
    write_frame(stream, &frame).unwrap();
    match read_frame(stream, JAIL_MAX_FRAME_BYTES).unwrap() {
        FrameRead::Frame(payload) => decode_response(&payload).unwrap(),
        FrameRead::CleanEof => panic!("expected response frame"),
    }
}

#[test]
fn framed_wasm_round_trip_through_serve_loop() {
    let (mut parent, child) = loopback_pair();
    let mut child_reader = child.try_clone().unwrap();
    let mut child_writer = child;
    let server = std::thread::spawn(move || {
        let mut service = WasmJailService::new();
        serve_jail_connection(
            JailKind::Wasm,
            &mut child_reader,
            &mut child_writer,
            &mut service,
        )
    });
    let wasm_bytes = minimal_handler_wasm();
    let res = transact(&mut parent, 1, wasm_load_op("loop", wasm_bytes));
    assert_eq!(res.id, 1);
    assert_eq!(res.result, JailResult::Ok(JailOutput::WasmLoaded));

    let res = transact(
        &mut parent,
        2,
        JailOperation::WasmInvoke {
            module_id: "loop".to_string(),
            method: "POST".to_string(),
            uri: "/x".to_string(),
            headers: vec![],
            body: b"data".to_vec(),
        },
    );
    assert!(
        matches!(
            res.result,
            JailResult::Ok(JailOutput::WasmResult { status: 200, .. })
        ),
        "got {:?}",
        res.result
    );

    // Oversized invoke is rejected at validation without desync.
    let big = JailOperation::WasmInvoke {
        module_id: "loop".to_string(),
        method: "GET".to_string(),
        uri: "/".to_string(),
        headers: vec![],
        body: vec![0u8; JAIL_MAX_INVOKE_INPUT_BYTES + 1],
    };
    assert!(big.validate().is_err());
    let res = transact(&mut parent, 3, JailOperation::Ping);
    assert_eq!(res.result, JailResult::Ok(JailOutput::Pong));

    let res = transact(&mut parent, 4, JailOperation::Shutdown);
    assert_eq!(res.result, JailResult::Ok(JailOutput::ShutdownAck));
    assert_eq!(
        server.join().unwrap(),
        synvoid_ipc::ServeOutcome::CleanShutdown
    );
}

#[test]
fn framed_yara_round_trip_through_serve_loop() {
    let (mut parent, child) = loopback_pair();
    let mut child_reader = child.try_clone().unwrap();
    let mut child_writer = child;
    let server = std::thread::spawn(move || {
        let mut service = YaraJailService::new().unwrap();
        serve_jail_connection(
            JailKind::Yara,
            &mut child_reader,
            &mut child_writer,
            &mut service,
        )
    });
    let res = transact(&mut parent, 1, yara_load_op("loop"));
    assert_eq!(res.result, JailResult::Ok(JailOutput::YaraRulesLoaded));
    let res = transact(
        &mut parent,
        2,
        JailOperation::YaraScan {
            rules_id: "loop".to_string(),
            data: b"synvoid-jail-probe-string".to_vec(),
        },
    );
    let JailResult::Ok(JailOutput::YaraScanResult { matches }) = res.result else {
        panic!("expected scan result");
    };
    assert_eq!(matches.len(), 1);
    let res = transact(&mut parent, 3, JailOperation::Shutdown);
    assert_eq!(res.result, JailResult::Ok(JailOutput::ShutdownAck));
    assert_eq!(
        server.join().unwrap(),
        synvoid_ipc::ServeOutcome::CleanShutdown
    );
}

#[test]
fn framed_parent_eof_ends_child_loop() {
    let (parent, child) = loopback_pair();
    drop(parent);
    let mut child_reader = child.try_clone().unwrap();
    let mut child_writer = child;
    let mut service = WasmJailService::new();
    assert_eq!(
        serve_jail_connection(
            JailKind::Wasm,
            &mut child_reader,
            &mut child_writer,
            &mut service
        ),
        synvoid_ipc::ServeOutcome::ConnectionClosed
    );
}

#[test]
fn framed_unknown_version_is_rejected_without_hang() {
    // A bad-version peer cannot be answered on-stream (envelope rejected at
    // decode), so the loop exits instead of hanging: the parent observes EOF
    // and restarts the jail.
    let (mut parent, child) = loopback_pair();
    let mut child_reader = child.try_clone().unwrap();
    let mut child_writer = child;
    let server = std::thread::spawn(move || {
        let mut service = WasmJailService::new();
        serve_jail_connection(
            JailKind::Wasm,
            &mut child_reader,
            &mut child_writer,
            &mut service,
        )
    });
    let mut req = JailRequest::new(1, JailOperation::Ping);
    req.version = JAIL_PROTOCOL_VERSION + 1;
    let payload = synvoid_utils::serialization::serialize(&req).unwrap();
    let mut raw = (payload.len() as u32).to_be_bytes().to_vec();
    raw.extend_from_slice(&payload);
    parent.write_all(&raw).unwrap();
    parent.flush().unwrap();
    assert_eq!(
        server.join().unwrap(),
        synvoid_ipc::ServeOutcome::ProtocolFatal
    );
}

#[test]
fn request_decode_round_trip_and_match_bound() {
    let req = JailRequest::new(9, JailOperation::Ping);
    let frame = encode_request(&req).unwrap();
    let mut slice: &[u8] = &frame;
    match read_frame(&mut slice, JAIL_MAX_FRAME_BYTES).unwrap() {
        FrameRead::Frame(payload) => {
            let decoded = decode_request(&payload).unwrap();
            assert_eq!(decoded, req);
        }
        FrameRead::CleanEof => panic!("expected frame"),
    }
    // Match output is always within the bound.
    let mut service = YaraJailService::new().unwrap();
    service.handle(&yara_load_op("bound"));
    let result = service.handle(&JailOperation::YaraScan {
        rules_id: "bound".to_string(),
        data: b"synvoid-jail-probe-string".to_vec(),
    });
    let JailResult::Ok(JailOutput::YaraScanResult { matches }) = result else {
        panic!("expected scan result");
    };
    assert!(matches.len() <= JAIL_MAX_MATCHES);
}

#[test]
fn yara_service_scan_input_bound_checked_in_depth() {
    let mut service = YaraJailService::new().unwrap();
    service.handle(&yara_load_op("bound"));
    // Even calling the service directly (bypassing frame validation), the
    // service enforces the input bound itself.
    let result = service.handle(&JailOperation::YaraScan {
        rules_id: "bound".to_string(),
        data: vec![0u8; JAIL_MAX_SCAN_INPUT_BYTES + 1],
    });
    assert!(
        matches!(
            result,
            JailResult::Err(ref dto) if dto.code == JailErrorCode::Oversized
        ),
        "got {result:?}"
    );
}

// ─── F. Live child processes ────────────────────────────────────────────────

fn synvoid_binary() -> Option<PathBuf> {
    // Prefer the compile-time binary path (profile-correct under cargo and
    // nextest), then fall back to profile output directories. A stale binary
    // from another profile still speaks an older protocol, so order matters:
    // the first existing candidate wins.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut candidates = Vec::new();
    if let Some(path) = option_env!("CARGO_BIN_EXE_synvoid") {
        candidates.push(PathBuf::from(path));
    }
    candidates.push(root.join("target/ci/synvoid"));
    candidates.push(root.join("target/debug/synvoid"));
    candidates.into_iter().find(|path| path.exists())
}

fn live_config() -> JailHandleConfig {
    JailHandleConfig {
        call_timeout: Duration::from_secs(20),
        shutdown_grace: Duration::from_secs(5),
        max_restarts: 2,
        base_backoff_ms: 10,
        max_backoff_ms: 100,
    }
}

fn hatch_env() -> Vec<(String, String)> {
    vec![(JAIL_PERMIT_NO_SANDBOX_ENV.to_string(), "1".to_string())]
}

#[test]
fn live_wasm_jail_round_trip_and_reap() {
    let Some(binary) = synvoid_binary() else {
        eprintln!("SKIP: synvoid binary not built; run via cargo test");
        return;
    };
    let handle = JailHandle::spawn(
        JailSpawnSpec {
            program: binary,
            args: vec![JailKind::Wasm.cli_flag().to_string()],
            env: hatch_env(),
            kind: JailKind::Wasm,
        },
        live_config(),
    )
    .unwrap();
    assert!(handle.is_alive());

    let wasm_bytes = minimal_handler_wasm();
    let loaded = handle.call(&wasm_load_op("live", wasm_bytes)).unwrap();
    assert_eq!(loaded, JailOutput::WasmLoaded);
    let output = handle
        .call(&JailOperation::WasmInvoke {
            module_id: "live".to_string(),
            method: "GET".to_string(),
            uri: "/live".to_string(),
            headers: vec![("host".to_string(), "example.com".to_string())],
            body: b"live-input".to_vec(),
        })
        .unwrap();
    let JailOutput::WasmResult { status, body, .. } = output else {
        panic!("expected wasm result, got {output:?}");
    };
    assert_eq!(status, 200);
    assert!(body.is_empty());

    handle.shutdown();
    assert!(!handle.is_alive(), "shutdown must reap the jail child");
}

#[test]
fn live_yara_jail_round_trip_and_reap() {
    let Some(binary) = synvoid_binary() else {
        eprintln!("SKIP: synvoid binary not built; run via cargo test");
        return;
    };
    let handle = JailHandle::spawn(
        JailSpawnSpec {
            program: binary,
            args: vec![JailKind::Yara.cli_flag().to_string()],
            env: hatch_env(),
            kind: JailKind::Yara,
        },
        live_config(),
    )
    .unwrap();

    assert_eq!(
        handle.call(&yara_load_op("live")).unwrap(),
        JailOutput::YaraRulesLoaded
    );
    let output = handle
        .call(&JailOperation::YaraScan {
            rules_id: "live".to_string(),
            data: b"contains synvoid-jail-probe-string here".to_vec(),
        })
        .unwrap();
    let JailOutput::YaraScanResult { matches } = output else {
        panic!("expected scan result, got {output:?}");
    };
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_name, "jail_probe");

    handle.shutdown();
    assert!(!handle.is_alive(), "shutdown must reap the jail child");
}

#[test]
fn live_jail_spawn_failure_fails_closed() {
    // Nonexistent binary: hard error, never a fallback to in-process.
    let err = JailHandle::spawn(
        JailSpawnSpec {
            program: PathBuf::from("/nonexistent/synvoid-test-binary"),
            args: vec![JailKind::Wasm.cli_flag().to_string()],
            env: hatch_env(),
            kind: JailKind::Wasm,
        },
        live_config(),
    )
    .expect_err("spawn must fail closed");
    assert!(matches!(err, JailError::Unavailable(_)));
    // And the policy layer agrees: required + unavailable ⇒ FailClosed.
    assert!(matches!(
        resolve_route(IsolationPolicy::Required, false),
        JailRoute::FailClosed(_)
    ));
}

fn wait_until_dead(handle: &JailHandle, timeout: Duration) {
    let start = Instant::now();
    while handle.is_alive() && start.elapsed() < timeout {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!handle.is_alive(), "child did not exit promptly");
}

#[test]
fn live_jail_transparent_restart_after_child_exit() {
    let Some(binary) = synvoid_binary() else {
        eprintln!("SKIP: synvoid binary not built; run via cargo test");
        return;
    };
    let handle = JailHandle::spawn(
        JailSpawnSpec {
            program: binary,
            args: vec![JailKind::Wasm.cli_flag().to_string()],
            env: hatch_env(),
            kind: JailKind::Wasm,
        },
        live_config(),
    )
    .unwrap();
    // Orderly shutdown kills the child; the next call must transparently
    // restart within budget (restart_count 1) and serve again.
    let _ = handle.call(&JailOperation::Shutdown);
    wait_until_dead(&handle, Duration::from_secs(10));
    let output = handle.call(&JailOperation::Ping).unwrap();
    assert_eq!(output, JailOutput::Pong);
    assert_eq!(handle.restart_count(), 1);
    handle.shutdown();
}

#[test]
fn live_jail_restart_budget_exhaustion_fails_closed() {
    let Some(binary) = synvoid_binary() else {
        eprintln!("SKIP: synvoid binary not built; run via cargo test");
        return;
    };
    let config = JailHandleConfig {
        max_restarts: 0,
        ..live_config()
    };
    let handle = JailHandle::spawn(
        JailSpawnSpec {
            program: binary,
            args: vec![JailKind::Wasm.cli_flag().to_string()],
            env: hatch_env(),
            kind: JailKind::Wasm,
        },
        config,
    )
    .unwrap();
    let _ = handle.call(&JailOperation::Shutdown);
    wait_until_dead(&handle, Duration::from_secs(10));
    let err = handle.call(&JailOperation::Ping).expect_err("budget spent");
    assert!(
        matches!(err, JailError::RestartBudgetExhausted(_)),
        "got {err:?}"
    );
    assert_eq!(handle.restart_count(), 0);
}

// ─── G. Timeout and crash isolation (POSIX helpers; see protocol doc) ───────

#[test]
#[cfg(unix)]
fn silent_child_handshake_times_out_without_hang() {
    // A child that never speaks must surface Timeout/HandshakeFailed within
    // the deadline — never hang the parent, never crash it.
    let config = JailHandleConfig {
        call_timeout: Duration::from_millis(500),
        shutdown_grace: Duration::from_secs(2),
        max_restarts: 0,
        base_backoff_ms: 1,
        max_backoff_ms: 10,
    };
    let start = Instant::now();
    let err = JailHandle::spawn(
        JailSpawnSpec {
            program: PathBuf::from("/bin/sh"),
            args: vec!["-c".to_string(), "sleep 30".to_string()],
            env: Vec::new(),
            kind: JailKind::Wasm,
        },
        config,
    )
    .expect_err("silent child must fail the handshake");
    assert!(
        matches!(err, JailError::HandshakeFailed(_) | JailError::Timeout(_)),
        "got {err:?}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(15),
        "handshake must be deadline-bounded"
    );
}

#[test]
#[cfg(unix)]
fn instantly_exiting_child_fails_closed_without_panic() {
    let config = JailHandleConfig {
        call_timeout: Duration::from_secs(5),
        shutdown_grace: Duration::from_secs(2),
        max_restarts: 0,
        base_backoff_ms: 1,
        max_backoff_ms: 10,
    };
    let err = JailHandle::spawn(
        JailSpawnSpec {
            program: PathBuf::from("/bin/sh"),
            args: vec!["-c".to_string(), "exit 3".to_string()],
            env: Vec::new(),
            kind: JailKind::Yara,
        },
        config,
    )
    .expect_err("exited child must fail closed");
    // Any of these is fail-closed: the underlying exit/handshake cause, or
    // the spent restart budget (max_restarts = 0 surfaces the budget error
    // on the first recovery attempt).
    assert!(
        matches!(
            err,
            JailError::HandshakeFailed(_)
                | JailError::ChildExited(_)
                | JailError::RestartBudgetExhausted(_)
        ),
        "got {err:?}"
    );
}
