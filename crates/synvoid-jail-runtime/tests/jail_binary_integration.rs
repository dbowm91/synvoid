//! Phase 29 Part F: packaged child-binary round trips.
//!
//! Spawns the real `synvoid-wasm-jail` / `synvoid-yara-jail` binaries (not
//! in-process handlers) and completes load/invoke/scan/unload round trips
//! over the Phase 22 framed protocol. Uses the test-only
//! `SYNVOID_JAIL_PERMIT_NO_SANDBOX=1` hatch so hermetic CI hosts without a
//! strict backend still exercise framing, digests, limits, and supervision
//! for real. Production spawn paths never set the hatch.

use std::path::PathBuf;
use std::time::Duration;

use synvoid_ipc::{
    sha256_hex, JailHandle, JailHandleConfig, JailHookCapabilities, JailKind, JailOperation,
    JailOutput, JailSpawnSpec,
};

fn wasm_binary() -> Option<PathBuf> {
    if let Some(path) = option_env!("CARGO_BIN_EXE_synvoid-wasm-jail") {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // Workspace target dirs (profile-correct first).
    for candidate in [
        root.join("../../target/ci/synvoid-wasm-jail"),
        root.join("../../target/debug/synvoid-wasm-jail"),
    ] {
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn yara_binary() -> Option<PathBuf> {
    if let Some(path) = option_env!("CARGO_BIN_EXE_synvoid-yara-jail") {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for candidate in [
        root.join("../../target/ci/synvoid-yara-jail"),
        root.join("../../target/debug/synvoid-yara-jail"),
    ] {
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
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
    vec![(
        synvoid_jail_runtime::JAIL_PERMIT_NO_SANDBOX_ENV.to_string(),
        "1".to_string(),
    )]
}

fn hook_caps() -> JailHookCapabilities {
    JailHookCapabilities {
        request_inspect: true,
        request_mutate: false,
        response_inspect: false,
        response_mutate: false,
    }
}

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

#[test]
fn packaged_wasm_jail_load_invoke_unload_round_trip() {
    let Some(binary) = wasm_binary() else {
        eprintln!("SKIP: synvoid-wasm-jail binary not built; run via cargo test");
        return;
    };
    // Dedicated binaries take no payload argv (identity implies kind).
    let handle = JailHandle::spawn(
        JailSpawnSpec {
            program: binary,
            args: Vec::new(),
            env: hatch_env(),
            kind: JailKind::Wasm,
        },
        live_config(),
    )
    .unwrap();
    assert!(handle.is_alive());

    let wasm_bytes = minimal_handler_wasm();
    let loaded = handle
        .call(&JailOperation::WasmLoad {
            module_id: "pkg-live".to_string(),
            digest_sha256_hex: sha256_hex(&wasm_bytes),
            wasm_bytes,
            fuel: 1_000_000,
            memory_pages: Some(16),
            timeout_ms: 5_000,
            capabilities: hook_caps(),
        })
        .unwrap();
    assert_eq!(loaded, JailOutput::WasmLoaded);

    let output = handle
        .call(&JailOperation::WasmInvoke {
            module_id: "pkg-live".to_string(),
            method: "GET".to_string(),
            uri: "/pkg".to_string(),
            headers: vec![("host".to_string(), "example.com".to_string())],
            body: b"pkg-input".to_vec(),
        })
        .unwrap();
    let JailOutput::WasmResult { status, body, .. } = output else {
        panic!("expected wasm result, got {output:?}");
    };
    assert_eq!(status, 200);
    assert!(body.is_empty());

    assert_eq!(
        handle
            .call(&JailOperation::WasmUnload {
                module_id: "pkg-live".to_string(),
            })
            .unwrap(),
        JailOutput::WasmUnloaded
    );

    handle.shutdown();
    assert!(!handle.is_alive(), "shutdown must reap the jail child");
}

#[test]
fn packaged_yara_jail_load_scan_unload_round_trip() {
    let Some(binary) = yara_binary() else {
        eprintln!("SKIP: synvoid-yara-jail binary not built; run via cargo test");
        return;
    };
    let handle = JailHandle::spawn(
        JailSpawnSpec {
            program: binary,
            args: Vec::new(),
            env: hatch_env(),
            kind: JailKind::Yara,
        },
        live_config(),
    )
    .unwrap();

    assert_eq!(
        handle
            .call(&JailOperation::YaraLoadRules {
                rules_id: "pkg-live".to_string(),
                digest_sha256_hex: sha256_hex(PROBE_RULES.as_bytes()),
                rules_text: PROBE_RULES.to_string(),
            })
            .unwrap(),
        JailOutput::YaraRulesLoaded
    );
    let output = handle
        .call(&JailOperation::YaraScan {
            rules_id: "pkg-live".to_string(),
            data: b"contains synvoid-jail-probe-string here".to_vec(),
        })
        .unwrap();
    let JailOutput::YaraScanResult { matches } = output else {
        panic!("expected scan result, got {output:?}");
    };
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_name, "jail_probe");

    assert_eq!(
        handle
            .call(&JailOperation::YaraUnload {
                rules_id: "pkg-live".to_string(),
            })
            .unwrap(),
        JailOutput::YaraUnloaded
    );

    handle.shutdown();
    assert!(!handle.is_alive(), "shutdown must reap the jail child");
}

#[test]
fn packaged_jail_binaries_reject_wrong_kind() {
    let Some(wasm) = wasm_binary() else {
        eprintln!("SKIP: synvoid-wasm-jail binary not built");
        return;
    };
    let Some(yara) = yara_binary() else {
        eprintln!("SKIP: synvoid-yara-jail binary not built");
        return;
    };
    // WASM binary must reject YARA ops; YARA binary must reject WASM ops.
    // Spawn both and assert PolicyDenied without desync (next call still works).
    let wasm_handle = JailHandle::spawn(
        JailSpawnSpec {
            program: wasm,
            args: Vec::new(),
            env: hatch_env(),
            kind: JailKind::Wasm,
        },
        live_config(),
    )
    .unwrap();
    let err = wasm_handle
        .call(&JailOperation::YaraLoadRules {
            rules_id: "x".to_string(),
            digest_sha256_hex: sha256_hex(PROBE_RULES.as_bytes()),
            rules_text: PROBE_RULES.to_string(),
        })
        .unwrap_err();
    assert!(matches!(err, synvoid_ipc::JailError::PolicyDenied(_)));
    assert_eq!(
        wasm_handle.call(&JailOperation::Ping).unwrap(),
        JailOutput::Pong
    );
    wasm_handle.shutdown();

    let yara_handle = JailHandle::spawn(
        JailSpawnSpec {
            program: yara,
            args: Vec::new(),
            env: hatch_env(),
            kind: JailKind::Yara,
        },
        live_config(),
    )
    .unwrap();
    let err = yara_handle
        .call(&JailOperation::WasmUnload {
            module_id: "x".to_string(),
        })
        .unwrap_err();
    assert!(matches!(err, synvoid_ipc::JailError::PolicyDenied(_)));
    assert_eq!(
        yara_handle.call(&JailOperation::Ping).unwrap(),
        JailOutput::Pong
    );
    yara_handle.shutdown();
}
