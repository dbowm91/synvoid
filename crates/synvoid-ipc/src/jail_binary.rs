//! Deterministic jail binary resolution (Phase 29 Part C).
//!
//! Parent processes must resolve the dedicated jail binaries
//! (`synvoid-wasm-jail`, `synvoid-yara-jail`) without searching the current
//! working directory, `PATH`, or writable plugin directories. Lookup order:
//!
//! 1. the directory containing the current executable (`current_exe` parent),
//!    joined with the fixed binary name (`synvoid-wasm-jail` /
//!    `synvoid-yara-jail`, plus `.exe` on Windows). When that file exists and
//!    is a regular file, it is used with empty argv (binary identity implies
//!    kind; no payloads/secrets in argv or env, ever).
//! 2. fallback to the current executable with the legacy compat flag
//!    (`--wasm-jail` / `--yara-jail`). This preserves hermetic tests and
//!    dev builds where the dedicated binaries have not been installed yet.
//!    The fallback is a forwarding shim only: it runs the same
//!    `synvoid-jail-runtime` child entry sequencing, never an unisolated
//!    execution path. Removal target: require dedicated binaries once
//!    installers ship them atomically (see Part G).
//!
//! Parent creates IPC pipes before sandbox entry (see `jail_process`); the
//! child receives only explicit minimal argv/env and cannot bind/connect
//! after sandbox when policy forbids it. Stderr remains diagnostic only;
//! stdout remains protocol frames.

use std::path::{Path, PathBuf};

use super::jail_protocol::{JailError, JailKind};

/// Fixed executable name for the WASM jail child (plus `.exe` on Windows).
pub const JAIL_WASM_BINARY_NAME: &str = "synvoid-wasm-jail";
/// Fixed executable name for the YARA jail child (plus `.exe` on Windows).
pub const JAIL_YARA_BINARY_NAME: &str = "synvoid-yara-jail";

/// Fixed binary name for a jail kind (without extension).
pub fn jail_binary_name(kind: JailKind) -> &'static str {
    match kind {
        JailKind::Wasm => JAIL_WASM_BINARY_NAME,
        JailKind::Yara => JAIL_YARA_BINARY_NAME,
    }
}

fn binary_file_name(kind: JailKind) -> String {
    let base = jail_binary_name(kind);
    #[cfg(windows)]
    {
        format!("{base}.exe")
    }
    #[cfg(not(windows))]
    {
        base.to_string()
    }
}

/// Directory containing the current executable, when determinable.
fn current_exe_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()?
        .parent()
        .map(|p| p.to_path_buf())
}

/// Dedicated binary path for a jail kind when installed alongside the
/// current executable. Returns `None` when the file does not exist or is
/// not a regular file. Never searches CWD, `PATH`, or plugin directories.
pub fn dedicated_jail_binary_path(kind: JailKind) -> Option<PathBuf> {
    let dir = current_exe_dir()?;
    let candidate = dir.join(binary_file_name(kind));
    match std::fs::metadata(&candidate) {
        Ok(meta) if meta.is_file() => Some(candidate),
        _ => None,
    }
}

/// Resolve the jail child program for a kind: dedicated binary when
/// installed alongside the current executable, otherwise the current
/// executable itself (legacy compat shim with `--wasm-jail`/`--yara-jail`).
pub fn resolve_jail_binary(kind: JailKind) -> PathBuf {
    if let Some(dedicated) = dedicated_jail_binary_path(kind) {
        return dedicated;
    }
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("synvoid"))
}

/// Whether the resolved program is the dedicated binary (as opposed to the
/// legacy compat fallback).
pub fn is_dedicated_jail_binary(program: &Path, kind: JailKind) -> bool {
    program
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == binary_file_name(kind))
}

/// Argv for a resolved jail program: empty for dedicated binaries (identity
/// implies kind), legacy flag for the compat fallback. Never carries
/// payloads, digests, or secrets.
pub fn jail_spawn_args(program: &Path, kind: JailKind) -> Vec<String> {
    if is_dedicated_jail_binary(program, kind) {
        Vec::new()
    } else {
        vec![kind.cli_flag().to_string()]
    }
}

/// Build a `JailSpawnSpec` using deterministic resolution. Production call
/// sites should use this instead of hand-constructing program paths.
pub fn resolved_jail_spawn_spec(
    kind: JailKind,
    extra_env: Vec<(String, String)>,
) -> super::jail_process::JailSpawnSpec {
    let program = resolve_jail_binary(kind);
    let args = jail_spawn_args(&program, kind);
    super::jail_process::JailSpawnSpec {
        program,
        args,
        env: extra_env,
        kind,
    }
}

/// Verify a jail binary path where practical: must exist, be a regular file,
/// and be non-empty. On Unix, also require an executable bit (owner/group/
/// other execute). Returns a typed fail-closed error otherwise.
pub fn verify_jail_binary(program: &Path, kind: JailKind) -> Result<(), JailError> {
    let meta = std::fs::metadata(program).map_err(|e| {
        JailError::Unavailable(format!(
            "jail binary for {} missing at {}: {e}",
            kind.as_str(),
            program.display()
        ))
    })?;
    if !meta.is_file() {
        return Err(JailError::Unavailable(format!(
            "jail binary for {} is not a regular file: {}",
            kind.as_str(),
            program.display()
        )));
    }
    if meta.len() == 0 {
        return Err(JailError::Unavailable(format!(
            "jail binary for {} is empty: {}",
            kind.as_str(),
            program.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 {
            return Err(JailError::Unavailable(format!(
                "jail binary for {} is not executable: {}",
                kind.as_str(),
                program.display()
            )));
        }
    }
    Ok(())
}

/// Startup preflight for jail-required configurations: both dedicated
/// binaries must resolve to installed files alongside the current
/// executable. Returns a human-readable error listing what is missing so
/// installers cannot silently omit helpers. Call at supervisor startup when
/// any `IsolationPolicy::Required` jail is configured.
pub fn ensure_dedicated_jail_binaries_available() -> Result<(), String> {
    let mut missing = Vec::new();
    for kind in [JailKind::Wasm, JailKind::Yara] {
        match dedicated_jail_binary_path(kind) {
            Some(path) => {
                if let Err(e) = verify_jail_binary(&path, kind) {
                    missing.push(format!("{} ({e})", path.display()));
                }
            }
            None => missing.push(format!(
                "{} (not found beside current executable; expected {})",
                jail_binary_name(kind),
                current_exe_dir()
                    .map(|d| d.join(binary_file_name(kind)).display().to_string())
                    .unwrap_or_else(|| binary_file_name(kind))
            )),
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "jail-required configuration but dedicated jail binaries missing/invalid: {}",
            missing.join("; ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_names_are_fixed() {
        assert_eq!(jail_binary_name(JailKind::Wasm), "synvoid-wasm-jail");
        assert_eq!(jail_binary_name(JailKind::Yara), "synvoid-yara-jail");
    }

    #[test]
    fn resolve_never_searches_cwd_or_path() {
        // Resolution depends only on current_exe dir + fallback, never on
        // CWD or PATH. Mutating CWD must not change the result.
        let before = resolve_jail_binary(JailKind::Wasm);
        let tmp = std::env::temp_dir();
        let old = std::env::current_dir().ok();
        let _ = std::env::set_current_dir(&tmp);
        let after = resolve_jail_binary(JailKind::Wasm);
        if let Some(old) = old {
            let _ = std::env::set_current_dir(old);
        }
        assert_eq!(before, after);
    }

    #[test]
    fn dedicated_args_are_empty_fallback_uses_flag() {
        let dedicated = PathBuf::from("/opt/synvoid/bin/synvoid-wasm-jail");
        assert!(jail_spawn_args(&dedicated, JailKind::Wasm).is_empty());
        let fallback = PathBuf::from("/opt/synvoid/bin/synvoid");
        assert_eq!(
            jail_spawn_args(&fallback, JailKind::Wasm),
            vec!["--wasm-jail".to_string()]
        );
        let dedicated_yara = PathBuf::from("/opt/synvoid/bin/synvoid-yara-jail");
        assert!(jail_spawn_args(&dedicated_yara, JailKind::Yara).is_empty());
    }

    #[test]
    fn verify_rejects_missing_and_dir() {
        let err = verify_jail_binary(
            Path::new("/nonexistent/synvoid-wasm-jail-test-binary"),
            JailKind::Wasm,
        )
        .unwrap_err();
        assert!(matches!(err, JailError::Unavailable(_)));
        let err = verify_jail_binary(Path::new("/tmp"), JailKind::Wasm).unwrap_err();
        assert!(matches!(err, JailError::Unavailable(_)));
    }
}
