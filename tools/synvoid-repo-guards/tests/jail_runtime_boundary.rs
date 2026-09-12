//! Phase 29 jail runtime package/process-split boundary guards.
//!
//! Pins the process-authority split: child execution lives in
//! `synvoid-jail-runtime` (never root), sandbox backends live in
//! `synvoid-platform` (never root-only), the wire/supervision vocabulary
//! lives in `synvoid-ipc`, and root `src/sandbox` + `src/platform/sandbox`
//! are pure parent-composition facades.

use std::fs;
use synvoid_repo_guards::{prepare_for_scanning, workspace_root, Violations};

fn read_repo(rel: &str) -> String {
    let repo = workspace_root();
    fs::read_to_string(repo.join(rel)).unwrap_or_else(|_| panic!("read {rel}"))
}

#[test]
fn jail_runtime_never_imports_root_implementation() {
    let mut violations = Violations::new();
    for rel in [
        "crates/synvoid-jail-runtime/src/lib.rs",
        "crates/synvoid-jail-runtime/src/headers.rs",
        "crates/synvoid-jail-runtime/src/sandbox_entry.rs",
        "crates/synvoid-jail-runtime/src/wasm_service.rs",
        "crates/synvoid-jail-runtime/src/yara_service.rs",
        "crates/synvoid-jail-runtime/src/bin/synvoid-wasm-jail.rs",
        "crates/synvoid-jail-runtime/src/bin/synvoid-yara-jail.rs",
    ] {
        let content = read_repo(rel);
        let code = prepare_for_scanning(&content);
        for forbidden in [
            "synvoid::supervisor",
            "synvoid::admin",
            "synvoid::mesh",
            "crate::supervisor",
            "use synvoid::",
            "synvoid_mesh",
            "AdminMutationAuthority",
            "ThreatIntelligenceManager",
            "is_mesh_id_blocked",
            "mem::forget",
            "ManuallyDrop",
        ] {
            if code.contains(forbidden) {
                violations.push(format!(
                    "{rel} imports root/supervisor/mesh impl: {forbidden}"
                ));
            }
        }
    }
    violations.assert_ok("jail-runtime root-import violations");
}

#[test]
fn jail_runtime_child_never_exposes_generic_exec_or_stdout_logs() {
    let mut violations = Violations::new();
    for rel in [
        "crates/synvoid-jail-runtime/src/sandbox_entry.rs",
        "crates/synvoid-jail-runtime/src/wasm_service.rs",
        "crates/synvoid-jail-runtime/src/yara_service.rs",
        "crates/synvoid-jail-runtime/src/bin/synvoid-wasm-jail.rs",
        "crates/synvoid-jail-runtime/src/bin/synvoid-yara-jail.rs",
    ] {
        let content = read_repo(rel);
        let code = prepare_for_scanning(&content);
        // Strip stderr macros before checking stdout prints (eprintln contains
        // println as a substring).
        let code = code.replace("eprintln!", "").replace("eprint!", "");
        for forbidden in [
            "Command::new",
            "std::process::Command",
            "/bin/sh",
            "cmd.exe",
            "execve",
            "println!",
        ] {
            if code.contains(forbidden) {
                violations.push(format!("{rel} exposes generic exec/stdout: {forbidden}"));
            }
        }
        if code.contains("set_var") {
            violations.push(format!("{rel} must never set env vars"));
        }
    }
    violations.assert_ok("jail-runtime exec/stdout violations");
}

#[test]
fn root_sandbox_services_remain_pure_facades() {
    for (rel, expected) in [
        (
            "src/sandbox/wasm_service.rs",
            "synvoid_jail_runtime::WasmJailService",
        ),
        (
            "src/sandbox/yara_service.rs",
            "synvoid_jail_runtime::YaraJailService",
        ),
    ] {
        let content = read_repo(rel);
        let code = prepare_for_scanning(&content);
        assert!(
            code.contains(expected),
            "{rel} must re-export {expected} (Phase 29 facade)"
        );
        for forbidden in [
            "WasmRuntime::",
            "YaraScanner::",
            "synvoid_plugin_runtime",
            "synvoid_yara",
            "serve_jail_connection",
            "ProcessSandbox",
            "impl JailHandler",
        ] {
            assert!(
                !code.contains(forbidden),
                "{rel} must not reintroduce engine implementation: found {forbidden}"
            );
        }
    }
    // Root sandbox entry retains only parent composition + forwarding shims.
    let entry = prepare_for_scanning(&read_repo("src/sandbox/mod.rs"));
    assert!(
        entry.contains("run_wasm_jail_main") && entry.contains("run_yara_jail_main"),
        "src/sandbox/mod.rs must forward to synvoid-jail-runtime entry points"
    );
    for forbidden in [
        "serve_jail_connection",
        "ProcessSandbox::with_paths",
        "WasmJailService::new",
        "YaraJailService::new",
    ] {
        assert!(
            !entry.contains(forbidden),
            "src/sandbox/mod.rs must not own child execution: found {forbidden}"
        );
    }
}

#[test]
fn root_platform_sandbox_remains_facade_over_crate() {
    let facade = read_repo("src/platform/sandbox.rs");
    let code = prepare_for_scanning(&facade);
    assert!(
        code.contains("synvoid_platform::sandbox"),
        "src/platform/sandbox.rs must re-export synvoid-platform (Phase 29)"
    );
    for forbidden in [
        "LandlockSandbox",
        "CapsicumSandbox",
        "PledgeSandbox",
        "WindowsSandbox",
        "SeatbeltSandbox",
        "landlock_create_ruleset",
        "sandbox_init",
    ] {
        assert!(
            !code.contains(forbidden),
            "src/platform/sandbox.rs must not own backends: found {forbidden}"
        );
    }
    let canonical = read_repo("crates/synvoid-platform/src/sandbox.rs");
    let canonical_code = prepare_for_scanning(&canonical);
    for required in [
        "LandlockSandbox",
        "ProcessSandbox",
        "with_paths",
        "SandboxLevel::Strict",
    ] {
        assert!(
            canonical_code.contains(required),
            "synvoid-platform sandbox must own backends: missing {required}"
        );
    }
}

#[test]
fn jail_binary_resolution_is_deterministic() {
    let resolver = read_repo("crates/synvoid-ipc/src/jail_binary.rs");
    let code = prepare_for_scanning(&resolver);
    for forbidden in ["current_dir", "search_path", "plugin_dir"] {
        assert!(
            !code.contains(forbidden),
            "jail resolver must not search writable dirs: found {forbidden}"
        );
    }
    let raw = read_repo("crates/synvoid-ipc/src/jail_binary.rs");
    assert!(
        raw.contains("current_exe"),
        "resolver must anchor on current_exe"
    );
    assert!(
        raw.contains("synvoid-wasm-jail") && raw.contains("synvoid-yara-jail"),
        "resolver must name both dedicated binaries"
    );
}

#[test]
fn workspace_registers_jail_runtime_crate() {
    let manifest = read_repo("Cargo.toml");
    assert!(
        manifest.contains("crates/synvoid-jail-runtime"),
        "workspace members must include crates/synvoid-jail-runtime"
    );
    assert!(
        manifest.contains("synvoid-jail-runtime"),
        "root dependencies must include synvoid-jail-runtime for facades/shims"
    );
    for bin in [
        "crates/synvoid-jail-runtime/src/bin/synvoid-wasm-jail.rs",
        "crates/synvoid-jail-runtime/src/bin/synvoid-yara-jail.rs",
    ] {
        assert!(
            workspace_root().join(bin).exists(),
            "missing dedicated jail binary source: {bin}"
        );
    }
}
