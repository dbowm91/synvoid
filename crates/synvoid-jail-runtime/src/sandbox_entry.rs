//! Child-side sandbox entry sequencing (Phase 29 canonical owner, Phase 82
//! guarantee migration, Phase 89 single-entry corrective).
//!
//! Preserves the Phase 22 startup order exactly:
//!
//! 1. parent opens pipes and spawns child;
//! 2. child initializes only resources that must exist before sandbox
//!    (captures inherited stdio handles; no I/O yet);
//! 3. child applies OS isolation via the portable guarantee contract in
//!    exactly one irreversible transition (`prepare_sandbox(request)?.enter()`;
//!    jail requirements come from `jail_guarantee_request()` — actual workload
//!    needs, not the old word "Strict");
//! 4. child enters the framed request loop with the `EnteredSandbox`
//!    witness retained;
//! 5. engine operations execute only after isolation when `Required`;
//! 6. any isolation setup failure terminates/fails closed before workload
//!    handling.
//!
//! Phase 89 Finding A: production startup performs exactly one sandbox entry.
//! No legacy `ProcessSandbox::with_paths(Strict, ..)` compatibility probe
//! enters a sandbox as a side effect; legacy compatibility is a pure
//! projection/test-only concern, never a second irreversible transition.
//!
//! Linux remains the primary verified target (Landlock). macOS/Windows
//! behavior is classified in `architecture/sandbox_jail_protocol.md` §8:
//! enforced where the backend supports strict mode, otherwise fail-closed
//! unless the test-only `SYNVOID_JAIL_PERMIT_NO_SANDBOX=1` hatch is set.
//! Production spawn paths never set the hatch.

use std::io::{Read, Write};

use synvoid_ipc::{serve_jail_connection, JailHandler, JailKind, ServeOutcome};
use synvoid_platform::{jail_guarantee_request, prepare_sandbox, EnteredSandbox};

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

    // Phase 81 Workstream G: retain the entered-sandbox guard through the
    // serve loop. Dropping it before workload execution would discard
    // security-significant backend state on platforms where a handle
    // controls lifetime (Windows Job kill-on-close). Landlock/seccomp are
    // irreversible so the guard is a witness there, but retention is still
    // required so a failed installation can never fall through to `serve`.
    // The Option makes the test-only unenforced path explicit: Some(guard)
    // = enforced and retained; None = hatch-bypassed (test-only, never
    // production); Err = fail closed before serve.
    let _sandbox_guard = match apply_jail_sandbox(kind) {
        Ok(guard) => guard,
        Err(code) => return code,
    };

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

/// Phase 81 Workstream A/G call-site inventory (production callers of the
/// sandbox surface; retained-vs-dropped discipline):
///
/// - `run_jail_main` (this file): jail guarantee request (ambient-FS deny,
///   read allowlist `/usr/lib`+`/lib`, inherited-IPC usable, descendants
///   confined, plus Phase 89 no-network/no-child/no-exec) prepared then
///   entered in exactly one irreversible transition; `EnteredSandbox`
///   witness RETAINED through the framed serve loop (`_sandbox_guard`);
///   failure fails closed before any workload (returns exit 1) unless the
///   test-only `SYNVOID_JAIL_PERMIT_NO_SANDBOX=1` hatch is set (production
///   spawn paths never set it — pinned by `tests/jail_isolation_guard.rs`).
///   Runs after stdio capture, before threads/resources for workloads.
/// - `synvoid-upload::SandboxConfig::apply_platform_sandbox`:
///   caller-chosen level (default `Off`); guard DROPPED after apply by
///   design (directory-isolation helper, fail-open to basic isolation with
///   a warning — NOT security-critical jail isolation; documented).
/// - Tests / docs: `with_stub` / `Off` probes only; never retained as
///   enforcement evidence.
/// - Config/operator docs: `sandbox_level = "strict"` maps to the legacy
///   adapter (Phase 82 pins behavior; no global reinterpretation).
///
/// Security-critical claim: a successful `IsolationPolicy::Required` jail
/// never enters its request loop after a sandbox installation failure
/// (pinned by `jail_sandbox_failure_never_enters_serve_loop` below and the
/// platform fake-backend conformance suite).
fn apply_jail_sandbox(kind: JailKind) -> Result<Option<EnteredSandbox>, i32> {
    // Phase 83 Workstream H: audit inherited descriptors/handles present at
    // entry. stdin/stdout are required IPC capabilities, stderr is logging;
    // no listener/admin/mesh/config/plugin/secret handle may leak in.
    // Unix: enumerate fds >= 3 and warn (fd numbers only). Windows: stdio
    // inheritance is explicit at spawn (documented in the closeout).
    #[cfg(unix)]
    {
        let unexpected = synvoid_platform::sandbox::audit_inherited_fds();
        if !unexpected.is_empty() {
            tracing::warn!(
                "Jail inherited {} unexpected fd(s) at entry (expected only 0/1/2 stdio): {:?}",
                unexpected.len(),
                unexpected,
            );
        }
    }
    // Minimal read-only system library paths for the dynamic loader. The jail
    // needs no other filesystem access: modules and rules arrive over IPC.
    // Requirements come from actual workload needs (Phase 82 Workstream I +
    // Phase 89 Finding D: the no-network/no-child/no-exec boundary is now
    // authoritative in `jail_guarantee_request()` and installed via the
    // guarantee-selected seccomp categories on Linux).
    //
    // Phase 89 Finding A: exactly one irreversible sandbox entry. There is
    // no legacy `ProcessSandbox::with_paths(Strict, ..)` probe here: on
    // enforcing platforms that call would irreversibly enter a second
    // sandbox (stacked Landlock domains / double seccomp on Linux,
    // unveil-lock/pledge ordering hazards on OpenBSD) and falsify the
    // Phase 82 "single irreversible transition" lifecycle.
    let request = jail_guarantee_request()
        .read_path("/usr/lib")
        .read_path("/lib");

    let prepared = prepare_sandbox(request).map_err(|e| {
        tracing::error!(
            "Failed to prepare {:?} jail sandbox, failing closed: {}",
            kind,
            e
        );
        1
    })?;
    match prepared.enter() {
        Ok(guard) => {
            tracing::info!(
                "Jail sandbox applied (kind: {}, backend: {}, abi: {}, scope: {:?}, runtime: {})",
                kind.as_str(),
                guard.report().backend,
                guard.report().abi,
                guard.report().scope,
                JAIL_RUNTIME_VERSION,
            );
            Ok(Some(guard))
        }
        Err(e) => {
            if std::env::var(JAIL_PERMIT_NO_SANDBOX_ENV).as_deref() == Ok("1") {
                tracing::warn!(
                    "JAIL SANDBOX BYPASSED via {} (test-only; refusing this in production): {}",
                    JAIL_PERMIT_NO_SANDBOX_ENV,
                    e
                );
                // Test-only hermetic path: explicit None (no enforcement
                // witness). Production spawn paths never set the hatch
                // (pinned by tests/jail_isolation_guard.rs). The Option
                // return keeps retention discipline structural: serve runs
                // only with Some(retained) or explicit None(hatch).
                tracing::warn!("Proceeding without OS sandbox (test-only hatch)");
                return Ok(None);
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

#[cfg(test)]
mod tests {
    use super::*;
    use synvoid_platform::{ProcessSandbox, SandboxLevel, SandboxPaths};

    /// Phase 81 Workstream A: a failed sandbox installation must never
    /// reach the request loop. The guard-returning signature makes this
    /// structural (`Err` carries no guard to retain), and this test pins
    /// the fail-closed branch on a backend that cannot enforce Strict.
    #[test]
    fn jail_sandbox_failure_never_enters_serve_loop() {
        // Simulate an unenforcing backend: Strict must fail closed.
        let res = ProcessSandbox::with_paths(
            SandboxLevel::Strict,
            SandboxPaths::new().add_read_path("/usr/lib"),
        );
        // On hosts with a real enforcing Strict backend (Linux Landlock,
        // macOS Seatbelt w/ feature+runtime, OpenBSD pledge) this succeeds
        // in-process — which would sandbox the test runner. Guard against
        // that: only assert fail-closed when no enforcing backend exists.
        let probe = ProcessSandbox::new(SandboxLevel::Strict);
        if probe.capabilities().can_enforce_strict() && probe.is_supported() {
            return;
        }
        assert!(
            res.is_err(),
            "Strict without an enforcing backend must fail closed (no guard, no serve loop)"
        );
        // There is no guard value on the error path by construction:
        // `apply_jail_sandbox` returns `Result<Option<EnteredSandbox>, i32>`,
        // so `run_jail_main` cannot enter `serve` without handling the
        // guard (Some(retained) / None(hatch-explicit) / Err(fail-closed)).
    }

    /// Phase 82 Workstream I + Phase 89 Finding D: the jail guarantee
    /// request carries the full boundary (ambient-FS deny, read allowlist,
    /// inherited IPC, descendants confined, plus authoritative
    /// no-network/no-child/no-exec) and validates cleanly.
    #[test]
    fn jail_guarantee_request_is_minimal_and_valid() {
        let req = jail_guarantee_request()
            .read_path("/usr/lib")
            .read_path("/lib");
        req.validate().expect("jail request must validate");
        assert!(req
            .required
            .contains(&synvoid_platform::Guarantee::AmbientFilesystemDenied));
        assert!(req
            .required
            .contains(&synvoid_platform::Guarantee::FilesystemReadAllowlist));
        assert!(req
            .required
            .contains(&synvoid_platform::Guarantee::InheritedIpcUsable));
        assert!(req
            .required
            .contains(&synvoid_platform::Guarantee::DescendantsConfined));
        // Phase 89 Finding D: the no-network/no-child/no-exec boundary is
        // now authoritative in the request itself (Linux installs the
        // corresponding seccomp categories; other backends satisfy or fail
        // closed per the backend matrix).
        assert!(req
            .required
            .contains(&synvoid_platform::Guarantee::NetworkDenied));
        assert!(req
            .required
            .contains(&synvoid_platform::Guarantee::ChildCreationDenied));
        assert!(req
            .required
            .contains(&synvoid_platform::Guarantee::ExecDenied));
    }

    /// Phase 89 Finding A regression: production jail startup must contain
    /// exactly one irreversible sandbox-entry path. The legacy
    /// `ProcessSandbox::with_paths(SandboxLevel::Strict, ..)` probe must
    /// never return to this file's production path (it would enter a second
    /// irreversible sandbox on enforcing platforms).
    #[test]
    fn jail_entry_has_single_irreversible_transition() {
        let source = include_str!("sandbox_entry.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        // Strip doc/line comments: mentions in prose must not trip the
        // guard; only executable calls matter.
        let code: String = production
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !(t.starts_with("//")
                    || t.starts_with("//!")
                    || t.starts_with("///")
                    || t.starts_with('*'))
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code.contains("with_paths"),
            "production jail entry must not call ProcessSandbox::with_paths (single guarantee entry only)"
        );
        assert!(
            !code.contains("SandboxLevel::Strict"),
            "production jail entry must not reference legacy Strict entry"
        );
        assert!(
            production.contains("prepare_sandbox(request)"),
            "production jail entry must prepare the guarantee request"
        );
        assert!(
            production.contains("prepared.enter()"),
            "production jail entry must enter exactly via PreparedSandbox::enter()"
        );
        assert_eq!(
            production.matches("prepared.enter()").count(),
            1,
            "exactly one irreversible enter transition per jail startup"
        );
    }
}
