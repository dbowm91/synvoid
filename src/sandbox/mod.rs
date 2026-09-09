//! Sandbox module: supervised jail processes for WASM/YARA isolation.
//!
//! The `--wasm-jail` / `--yara-jail` entry points run below. Each jail:
//!
//! 1. captures its inherited stdio handles (parent-created pipes; no socket
//!    bind or connect is ever needed, so IPC works after sandboxing),
//! 2. applies `SandboxLevel::Strict` OS restrictions,
//! 3. enters the versioned, length-bounded framed request loop
//!    ([`synvoid_ipc::serve_jail_connection`]).
//!
//! Parent crash (stdin EOF) terminates the child; child protocol violations
//! terminate the child so the parent restarts a fresh instance. Unsupported
//! platforms fail closed unless the test-only escape hatch
//! `SYNVOID_JAIL_PERMIT_NO_SANDBOX=1` is set (production spawn paths never set
//! it; asserted by `tests/jail_isolation_guard.rs`).
//!
//! Normative spec: `architecture/sandbox_jail_protocol.md`.

pub mod policy;
pub mod wasm_service;
pub mod yara_service;

pub use policy::{headers_to_guest_json, JailClient};
pub use wasm_service::WasmJailService;
pub use yara_service::YaraJailService;

use std::io::{Read, Write};

use synvoid_ipc::{serve_jail_connection, JailHandler, JailKind, ServeOutcome};

use crate::platform::sandbox::{ProcessSandbox, SandboxLevel, SandboxPaths};

/// Test-only escape hatch permitting jail execution without OS sandbox
/// enforcement (hermetic tests on platforms without a strict backend).
/// Production spawn paths must never set this.
pub const JAIL_PERMIT_NO_SANDBOX_ENV: &str = "SYNVOID_JAIL_PERMIT_NO_SANDBOX";

pub fn run_wasm_jail_mode() {
    tracing::info!("Starting WASM plugin execution jail");
    std::process::exit(run_jail_main(JailKind::Wasm));
}

pub fn run_yara_jail_mode() {
    tracing::info!("Starting YARA rule evaluation jail");
    std::process::exit(run_jail_main(JailKind::Yara));
}

/// Exit codes: 0 = orderly shutdown or parent EOF (nothing left to serve),
/// 1 = fail-closed error (sandbox failure, protocol fatal, service setup).
fn run_jail_main(kind: JailKind) -> i32 {
    // Capture inherited stdio handles BEFORE sandboxing: the transport already
    // exists (parent-created pipes), so restriction order cannot break IPC.
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    if let Err(code) = apply_jail_sandbox(kind) {
        return code;
    }

    match kind {
        JailKind::Wasm => {
            let mut service = WasmJailService::new();
            serve(kind, &mut reader, &mut writer, &mut service)
        }
        JailKind::Yara => match YaraJailService::new() {
            Ok(mut service) => serve(kind, &mut reader, &mut writer, &mut service),
            Err(e) => {
                tracing::error!("Failed to initialize YARA jail service: {}", e);
                1
            }
        },
    }
}

fn serve(
    kind: JailKind,
    reader: &mut impl Read,
    writer: &mut impl Write,
    service: &mut impl JailHandler,
) -> i32 {
    match serve_jail_connection(kind, reader, writer, service) {
        ServeOutcome::CleanShutdown | ServeOutcome::ConnectionClosed => 0,
        ServeOutcome::ProtocolFatal => 1,
    }
}

fn apply_jail_sandbox(kind: JailKind) -> Result<(), i32> {
    let level = SandboxLevel::Strict;
    // Minimal read-only system library paths for the dynamic loader. The jail
    // needs no other filesystem access: modules and rules arrive over IPC.
    let paths = SandboxPaths::new()
        .add_read_path("/usr/lib")
        .add_read_path("/lib");

    match ProcessSandbox::with_paths(level, paths) {
        Ok(sandbox) => {
            tracing::info!(
                "Jail sandbox applied (kind: {}, backend: {}, level: {})",
                kind.as_str(),
                sandbox.feature_name(),
                sandbox.level().as_str(),
            );
            Ok(())
        }
        Err(e) => {
            if std::env::var(JAIL_PERMIT_NO_SANDBOX_ENV).as_deref() == Ok("1") {
                tracing::warn!(
                    "JAIL SANDBOX BYPASSED via {} (test-only; refusing this in production): {}",
                    JAIL_PERMIT_NO_SANDBOX_ENV,
                    e
                );
                return Ok(());
            }
            tracing::error!(
                "Failed to initialize {:?} jail sandbox, failing closed: {}",
                kind,
                e
            );
            Err(1)
        }
    }
}
