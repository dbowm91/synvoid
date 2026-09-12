//! Child-side sandbox entry sequencing (Phase 29 canonical owner).
//!
//! Preserves the Phase 22 startup order exactly:
//!
//! 1. parent opens pipes and spawns child;
//! 2. child initializes only resources that must exist before sandbox
//!    (captures inherited stdio handles; no I/O yet);
//! 3. child applies OS isolation (`SandboxLevel::Strict`);
//! 4. child enters the framed request loop;
//! 5. engine operations execute only after isolation when `Required`;
//! 6. any isolation setup failure terminates/fails closed before workload
//!    handling.
//!
//! Linux remains the primary verified target (Landlock). macOS/Windows
//! behavior is classified in `architecture/sandbox_jail_protocol.md` §8:
//! enforced where the backend supports strict mode, otherwise fail-closed
//! unless the test-only `SYNVOID_JAIL_PERMIT_NO_SANDBOX=1` hatch is set.
//! Production spawn paths never set the hatch.

use std::io::{Read, Write};

use synvoid_ipc::{serve_jail_connection, JailHandler, JailKind, ServeOutcome};
use synvoid_platform::{ProcessSandbox, SandboxLevel, SandboxPaths};

/// Test-only escape hatch permitting jail execution without OS sandbox
/// enforcement (hermetic tests on platforms without a strict backend).
/// Production spawn paths must never set this.
pub const JAIL_PERMIT_NO_SANDBOX_ENV: &str = "SYNVOID_JAIL_PERMIT_NO_SANDBOX";

/// Crate version of the jail runtime (packaging identity, not wire compat).
/// Wire compatibility is governed by `synvoid_ipc::JAIL_PROTOCOL_VERSION`.
pub const JAIL_RUNTIME_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Minimal stderr logging for jail children: stdout is the framed IPC
/// channel and must never carry logs.
pub fn init_jail_logging_stderr() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .try_init();
}

#[cfg(feature = "wasm")]
pub fn run_wasm_jail_main() -> ! {
    init_jail_logging_stderr();
    tracing::info!("Starting WASM plugin execution jail");
    std::process::exit(run_jail_main(JailKind::Wasm));
}

#[cfg(feature = "yara")]
pub fn run_yara_jail_main() -> ! {
    init_jail_logging_stderr();
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
        #[cfg(feature = "wasm")]
        JailKind::Wasm => {
            let mut service = crate::WasmJailService::new();
            serve(kind, &mut reader, &mut writer, &mut service)
        }
        #[cfg(not(feature = "wasm"))]
        JailKind::Wasm => {
            tracing::error!(
                "WASM jail requested but this binary was built without the `wasm` feature"
            );
            1
        }
        #[cfg(feature = "yara")]
        JailKind::Yara => match crate::YaraJailService::new() {
            Ok(mut service) => serve(kind, &mut reader, &mut writer, &mut service),
            Err(e) => {
                tracing::error!("Failed to initialize YARA jail service: {}", e);
                1
            }
        },
        #[cfg(not(feature = "yara"))]
        JailKind::Yara => {
            tracing::error!(
                "YARA jail requested but this binary was built without the `yara` feature"
            );
            1
        }
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
                "Jail sandbox applied (kind: {}, backend: {}, level: {}, runtime: {})",
                kind.as_str(),
                sandbox.feature_name(),
                sandbox.level().as_str(),
                JAIL_RUNTIME_VERSION,
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
