//! Native macOS Seatbelt enforcement tests (Phase 46, Workstream E).
//!
//! Sandboxing the test process is irreversible, so every enforcement case
//! runs in a child process (the test binary re-executed with
//! `SYNVOID_SANDBOX_PROBE` set). The child applies the sandbox first, then
//! attempts one operation and exits with a machine-readable code:
//! 0 = enforced-as-expected, 2 = sandbox did NOT enforce, 1 = harness error.
//!
//! Linux CI compiles this file to an empty target (`#![cfg(target_os =
//! "macos")]`); native evidence must come from a macOS host with
//! `--features macos-sandbox`. Cross-compiling alone is not evidence.

#![cfg(target_os = "macos")]

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

const PROBE_ENV: &str = "SYNVOID_SANDBOX_PROBE";
const ALLOWED_ENV: &str = "SYNVOID_SANDBOX_ALLOWED";
const DENIED_ENV: &str = "SYNVOID_SANDBOX_DENIED";
const WRITE_ENV: &str = "SYNVOID_SANDBOX_WRITE";
const PORT_ENV: &str = "SYNVOID_SANDBOX_PORT";

fn current_exe() -> PathBuf {
    std::env::current_exe().expect("test binary path")
}

fn run_probe(
    mode: &str,
    allowed: &std::path::Path,
    denied: &std::path::Path,
    write: &std::path::Path,
    port: Option<u16>,
) -> i32 {
    let mut cmd = Command::new(current_exe());
    cmd.env(PROBE_ENV, mode)
        .env(ALLOWED_ENV, allowed)
        .env(DENIED_ENV, denied)
        .env(WRITE_ENV, write)
        .env_remove("SYNVOID_JAIL_PERMIT_NO_SANDBOX");
    if let Some(p) = port {
        cmd.env(PORT_ENV, p.to_string());
    }
    // Probes must not inherit a bypass hatch.
    let status = cmd.status().expect("spawn probe child");
    status.code().unwrap_or(1)
}

// --- child entrypoint (runs inside #[test] binary when env is set) ---

fn child_main() -> i32 {
    let mode = std::env::var(PROBE_ENV).unwrap_or_default();
    let allowed = PathBuf::from(std::env::var(ALLOWED_ENV).unwrap_or_default());
    let denied = PathBuf::from(std::env::var(DENIED_ENV).unwrap_or_default());
    let write_dir = PathBuf::from(std::env::var(WRITE_ENV).unwrap_or_default());
    let port: Option<u16> = std::env::var(PORT_ENV).ok().and_then(|s| s.parse().ok());

    match mode.as_str() {
        "strict-allowed-read" => {
            if apply_strict(&allowed, &write_dir, &denied).is_err() {
                return 1;
            }
            let target = allowed.join("read.txt");
            match std::fs::read(&target) {
                Ok(_) => 0,
                Err(_) => 1,
            }
        }
        "strict-denied-read" => {
            if apply_strict(&allowed, &write_dir, &denied).is_err() {
                return 1;
            }
            let target = denied.join("secret.txt");
            match std::fs::read(&target) {
                Ok(_) => 2,  // NOT enforced
                Err(_) => 0, // enforced
            }
        }
        "strict-allowed-write" => {
            if apply_strict(&allowed, &write_dir, &denied).is_err() {
                return 1;
            }
            let target = write_dir.join("child_ok.txt");
            match std::fs::write(&target, b"probe") {
                Ok(()) => 0,
                Err(_) => 1,
            }
        }
        "strict-denied-write" => {
            if apply_strict(&allowed, &write_dir, &denied).is_err() {
                return 1;
            }
            let target = denied.join("child_evil.txt");
            match std::fs::write(&target, b"probe") {
                Ok(_) => {
                    let _ = std::fs::remove_file(&target);
                    2 // NOT enforced
                }
                Err(_) => 0, // enforced
            }
        }
        "strict-network" => {
            if apply_strict(&allowed, &write_dir, &denied).is_err() {
                return 1;
            }
            let port = match port {
                Some(p) => p,
                None => return 1,
            };
            let addr = format!("127.0.0.1:{port}");
            match std::net::TcpStream::connect_timeout(
                &addr.parse().unwrap(),
                Duration::from_secs(3),
            ) {
                Ok(_) => 2, // NOT enforced (connected)
                Err(_) => 0, // enforced (blocked) or refused — parent asserts
                             // with a live listener so refused cannot happen
            }
        }
        "strict-spawn" => {
            if apply_strict(&allowed, &write_dir, &denied).is_err() {
                return 1;
            }
            match Command::new("/bin/true").status() {
                Ok(_) => 2,  // NOT enforced (spawn succeeded)
                Err(_) => 0, // enforced (spawn blocked)
            }
        }
        "basic-allowed-read" => {
            if apply_basic(&allowed, &write_dir, &denied).is_err() {
                return 1;
            }
            let target = allowed.join("read.txt");
            match std::fs::read(&target) {
                Ok(_) => 0,
                Err(_) => 1,
            }
        }
        _ => 1,
    }
}

fn apply_strict(
    allowed: &std::path::Path,
    write: &std::path::Path,
    denied: &std::path::Path,
) -> Result<(), String> {
    use synvoid_platform::sandbox::{ProcessSandbox, SandboxLevel, SandboxPaths};
    let paths = SandboxPaths::new()
        .add_read_path(allowed)
        .add_read_path("/usr/lib")
        .add_read_path("/System/Library")
        .add_read_path("/bin")
        .add_write_path(write)
        .add_no_access_path(denied);
    ProcessSandbox::with_paths(SandboxLevel::Strict, paths)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn apply_basic(
    allowed: &std::path::Path,
    write: &std::path::Path,
    denied: &std::path::Path,
) -> Result<(), String> {
    use synvoid_platform::sandbox::{ProcessSandbox, SandboxLevel, SandboxPaths};
    let paths = SandboxPaths::new()
        .add_read_path(allowed)
        .add_write_path(write)
        .add_no_access_path(denied);
    ProcessSandbox::with_paths(SandboxLevel::Basic, paths)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

// If this binary was spawned as a probe child, run the probe instead of tests.
#[test]
fn probe_child_dispatch() {
    if std::env::var(PROBE_ENV).is_ok() {
        std::process::exit(child_main());
    }
}

fn requires_seatbelt() -> bool {
    if !cfg!(feature = "macos-sandbox") {
        eprintln!("SKIP: macos-sandbox feature not enabled (compile without enforcement)");
        return false;
    }
    use synvoid_platform::sandbox::{ProcessSandbox, SandboxLevel};
    let probe = ProcessSandbox::new(SandboxLevel::Basic);
    if !probe.is_supported() {
        eprintln!("SKIP: Seatbelt runtime unavailable (sandbox_init symbol missing)");
        return false;
    }
    true
}

fn fixture_dirs() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let tmp = tempfile::TempDir::new().unwrap();
    // Canonicalize up front: /var is a symlink to /private/var on macOS and
    // SBPL (subpath) matches the canonical location. Using the canonical
    // base for both profile generation and child file ops avoids a false
    // deny on the symlink form.
    let base = std::fs::canonicalize(tmp.path()).unwrap_or_else(|_| tmp.path().to_path_buf());
    let allowed = base.join("allowed");
    let denied = base.join("denied");
    let write = base.join("write");
    std::fs::create_dir_all(&allowed).unwrap();
    std::fs::create_dir_all(&denied).unwrap();
    std::fs::create_dir_all(&write).unwrap();
    std::fs::write(allowed.join("read.txt"), b"allowed").unwrap();
    std::fs::write(denied.join("secret.txt"), b"secret").unwrap();
    (tmp, allowed, denied, write)
}

#[test]
fn macos_strict_allowed_read_succeeds() {
    if std::env::var(PROBE_ENV).is_ok() {
        return;
    }
    if !requires_seatbelt() {
        return;
    }
    let (_tmp, allowed, denied, write) = fixture_dirs();
    assert_eq!(
        run_probe("strict-allowed-read", &allowed, &denied, &write, None),
        0
    );
}

#[test]
fn macos_strict_denied_read_fails() {
    if std::env::var(PROBE_ENV).is_ok() {
        return;
    }
    if !requires_seatbelt() {
        return;
    }
    let (_tmp, allowed, denied, write) = fixture_dirs();
    assert_eq!(
        run_probe("strict-denied-read", &allowed, &denied, &write, None),
        0
    );
}

#[test]
fn macos_strict_allowed_write_succeeds() {
    if std::env::var(PROBE_ENV).is_ok() {
        return;
    }
    if !requires_seatbelt() {
        return;
    }
    let (_tmp, allowed, denied, write) = fixture_dirs();
    assert_eq!(
        run_probe("strict-allowed-write", &allowed, &denied, &write, None),
        0
    );
}

#[test]
fn macos_strict_denied_write_fails() {
    if std::env::var(PROBE_ENV).is_ok() {
        return;
    }
    if !requires_seatbelt() {
        return;
    }
    let (_tmp, allowed, denied, write) = fixture_dirs();
    assert_eq!(
        run_probe("strict-denied-write", &allowed, &denied, &write, None),
        0
    );
}

#[test]
fn macos_strict_network_matches_capability() {
    if std::env::var(PROBE_ENV).is_ok() {
        return;
    }
    if !requires_seatbelt() {
        return;
    }
    use synvoid_platform::sandbox::{ProcessSandbox, SandboxLevel};
    let caps = ProcessSandbox::new(SandboxLevel::Strict).capabilities();
    assert!(
        caps.network_restrictions,
        "Strict must claim network restrictions (explicit deny network*)"
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (_tmp, allowed, denied, write) = fixture_dirs();
    // Keep the listener alive while the child attempts connect.
    let code = run_probe("strict-network", &allowed, &denied, &write, Some(port));
    assert_eq!(
        code, 0,
        "Strict must block outbound connect (listener was live)"
    );
    drop(listener);
}

#[test]
fn macos_strict_spawn_matches_capability() {
    if std::env::var(PROBE_ENV).is_ok() {
        return;
    }
    if !requires_seatbelt() {
        return;
    }
    use synvoid_platform::sandbox::{ProcessSandbox, SandboxLevel};
    let caps = ProcessSandbox::new(SandboxLevel::Strict).capabilities();
    assert!(
        caps.child_process_restrictions,
        "Strict must claim child-process restrictions (no job-creation allow)"
    );
    let (_tmp, allowed, denied, write) = fixture_dirs();
    assert_eq!(
        run_probe("strict-spawn", &allowed, &denied, &write, None),
        0
    );
}

#[test]
fn macos_basic_capabilities_claim_no_network_or_child_limits() {
    if std::env::var(PROBE_ENV).is_ok() {
        return;
    }
    if !requires_seatbelt() {
        return;
    }
    use synvoid_platform::sandbox::{ProcessSandbox, SandboxLevel};
    let caps = ProcessSandbox::new(SandboxLevel::Basic).capabilities();
    assert!(
        !caps.network_restrictions,
        "Basic must not claim network limits"
    );
    assert!(
        !caps.child_process_restrictions,
        "Basic must not claim child limits"
    );
    assert!(!caps.process_limits, "SBPL sets no numeric resource limits");
}

#[test]
fn macos_strict_fails_closed_without_runtime() {
    if std::env::var(PROBE_ENV).is_ok() {
        return;
    }
    // When the feature is off (or the symbol is missing), Strict must fail
    // closed rather than report success unenforced.
    if cfg!(feature = "macos-sandbox") {
        use synvoid_platform::sandbox::{ProcessSandbox, SandboxLevel};
        if ProcessSandbox::new(SandboxLevel::Strict).is_supported() {
            return; // runtime present — fail-closed path covered elsewhere
        }
    }
    use synvoid_platform::sandbox::{ProcessSandbox, SandboxLevel, SandboxPaths};
    let res = ProcessSandbox::with_paths(
        SandboxLevel::Strict,
        SandboxPaths::new().add_read_path("/usr/lib"),
    );
    assert!(
        res.is_err(),
        "Strict without Seatbelt runtime must fail closed"
    );
}
