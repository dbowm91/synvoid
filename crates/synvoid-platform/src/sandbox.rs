//! Sandbox primitives for process isolation.
//!
//! Canonical owner of OS-level sandbox backends (Phase 29, Phase 46
//! truthfulness, Phases 81-84 corrective): Landlock via the maintained
//! `landlock` crate (Linux, supported), Capsicum (FreeBSD,
//! experimental), Pledge/Unveil (OpenBSD, experimental), Job Objects
//! (Windows, limited: process limits only), Seatbelt (macOS, experimental
//! opt-in behind the `macos-sandbox` feature, deprecated `sandbox_init`).
//! The root `src/platform/sandbox.rs` is a thin facade re-exporting this
//! module so the jail runtime (`synvoid-jail-runtime`) can enforce isolation
//! without importing root paths.
//!
//! Support-tier contract (Phase 46, binding details in
//! `docs/SANDBOXING.md` and `architecture/platform.md` §6):
//! Linux is the production recommendation for strict jail isolation.
//! macOS Seatbelt is an opt-in experimental CLI-hardening backend using the
//! deprecated `sandbox_init` API (not Apple App Sandbox entitlements).
//! `SandboxCapabilities::process_limits` means numeric resource bounds
//! (memory/process-count, Job-Objects style), not generic syscall filtering.
//!
//! Phase 81 corrective notes (backend correctness):
//! - Linux uses ABI-aware `landlock` crate construction with
//!   `CompatLevel::HardRequirement` for required guarantees; production
//!   inspects `RestrictionStatus` and rejects `PartiallyEnforced` /
//!   `NotEnforced` on required paths. No kernel-release-text gate; the
//!   Landlock ABI/capability result is the availability signal.
//! - `no_new_privs` is established and verified for unprivileged
//!   enforcement; rule fds are RAII-owned (no leaks).
//! - Windows uses generated `windows-sys` Job Object / mitigation
//!   definitions (class 9 extended limits, correct limit flags), queries
//!   back effective state, owns the Job handle for the confinement
//!   lifetime, and performs no host-global DACL mutation.
//! - OpenBSD uses OS-native path bytes with interior-NUL rejection and
//!   locks unveil after policy construction.
//!
//! Phase 82 adds the portable guarantee contract (`Guarantee`,
//! `SandboxRequest`, `EnforcementReport`, `EnteredSandbox`) alongside the
//! legacy `SandboxLevel` adapter. Phase 83 wires the Linux syscall-filter
//! layer, Capsicum descriptor custody, and the Windows launch gate.
//! See `architecture/process_sandbox_corrective_closeout.md`.
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("Platform not supported: {0}")]
    NotSupported(String),

    #[error("Landlock not available (kernel < 5.13 or syscall unavailable)")]
    LandlockUnavailable,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Syscall failed: {0}")]
    Syscall(String),

    #[error("Invalid sandbox path: {0}")]
    InvalidPath(String),

    #[error("Strict sandbox requested but backend cannot enforce it: {0}")]
    InsufficientCapabilities(String),

    #[error("Sandbox guarantee unsupported by this backend: {0}")]
    Unsupported(String),

    #[error("Sandbox backend conflict (e.g. outer Job Object): {0}")]
    BackendConflict(String),

    #[error("Required sandbox guarantee partially enforced or unverified: {0}")]
    PartialEnforcement(String),

    #[error("Invalid sandbox policy: {0}")]
    InvalidPolicy(String),

    #[error("Sandbox entry failed after preparation: {0}")]
    EntryFailed(String),
}

/// Escape a path as an SBPL double-quoted string literal (Phase 46,
/// Workstream B).
///
/// Policy: backslash and double-quote are escaped (`\\`, `\"`); any ASCII
/// control byte (`< 0x20`, `0x7F`), including newline/CR/NUL, rejects the
/// path; non-UTF-8 paths are rejected. The caller must pass the returned
/// string inside double quotes — never interpolate `Path::display()`
/// directly. A closing parenthesis inside the quoted literal cannot gain an
/// extra SBPL expression once quoting is correct (covered by tests).
///
/// Compiled on macOS (production caller) and under `test` on all platforms
/// (profile-structure unit tests); absent from non-test Linux builds.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn escape_sbpl_string_literal(path: &Path) -> Result<String, SandboxError> {
    let s = path.to_str().ok_or_else(|| {
        SandboxError::InvalidPath(format!("non-UTF-8 path rejected: {}", path.display()))
    })?;
    if s.is_empty() {
        return Err(SandboxError::InvalidPath("empty path rejected".into()));
    }
    for c in s.chars() {
        if c.is_control() {
            return Err(SandboxError::InvalidPath(format!(
                "control character rejected in sandbox path: {}",
                path.display()
            )));
        }
        if c == '\u{7f}' {
            return Err(SandboxError::InvalidPath(format!(
                "DEL character rejected in sandbox path: {}",
                path.display()
            )));
        }
    }
    // Escape backslash first, then double-quote.
    Ok(s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Canonicalize a sandbox path when possible (Phase 46, Workstream B).
///
/// Symlinks are resolved via `std::fs::canonicalize` so the SBPL `(subpath)`
/// rule matches the real location. When canonicalization fails (missing
/// path, permission error, non-existent jail-time path), the original path
/// is kept and still passed through [`escape_sbpl_string_literal`]; the
/// caller logs at debug level. This keeps jail startup order safe: the jail
/// captures stdio handles first, then sandboxes, so a missing optional path
/// must not abort profile generation.
///
/// Compiled on macOS (production caller) and under `test` on all platforms.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn canonicalize_sbpl_path(path: &Path) -> std::path::PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SandboxLevel {
    #[default]
    Off,
    Basic,
    Strict,
}

impl SandboxLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            SandboxLevel::Off => "off",
            SandboxLevel::Basic => "basic",
            SandboxLevel::Strict => "strict",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SandboxCapabilities {
    pub read_path_allowlist: bool,
    pub write_path_allowlist: bool,
    pub deny_paths: bool,
    pub process_limits: bool,
    pub network_restrictions: bool,
    pub child_process_restrictions: bool,
}

impl SandboxCapabilities {
    pub fn can_enforce_strict(&self) -> bool {
        self.read_path_allowlist
    }
}

pub trait SandboxBackend: Send + Sync {
    fn apply(
        &self,
        read_paths: &[&Path],
        write_paths: &[&Path],
        denied_paths: &[&Path],
    ) -> Result<(), SandboxError>;
    fn is_supported(&self) -> bool;
    fn feature_name(&self) -> &'static str;
    fn level(&self) -> SandboxLevel;
    fn capabilities(&self) -> SandboxCapabilities;
}

#[derive(Debug, Clone, Default)]
pub struct SandboxPaths {
    read_paths: Vec<std::path::PathBuf>,
    write_paths: Vec<std::path::PathBuf>,
    no_access_paths: Vec<std::path::PathBuf>,
}

impl SandboxPaths {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_read_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.read_paths.push(path.into());
        self
    }

    pub fn add_write_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.write_paths.push(path.into());
        self
    }

    pub fn add_no_access_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.no_access_paths.push(path.into());
        self
    }

    pub fn read_paths(&self) -> &[std::path::PathBuf] {
        &self.read_paths
    }

    pub fn write_paths(&self) -> &[std::path::PathBuf] {
        &self.write_paths
    }

    pub fn no_access_paths(&self) -> &[std::path::PathBuf] {
        &self.no_access_paths
    }
}

pub struct ProcessSandbox {
    backend: Box<dyn SandboxBackend>,
}

impl ProcessSandbox {
    pub fn new(level: SandboxLevel) -> Self {
        let backend: Box<dyn SandboxBackend> = if level == SandboxLevel::Off {
            Box::new(StubSandbox::new(level, "disabled"))
        } else {
            #[cfg(target_os = "linux")]
            {
                Box::new(crate::sandbox::linux::LandlockSandbox::new(level))
            }
            #[cfg(target_os = "freebsd")]
            {
                Box::new(crate::sandbox::capsicum::CapsicumSandbox::new(level))
            }
            #[cfg(target_os = "openbsd")]
            {
                Box::new(crate::sandbox::pledge::PledgeSandbox::new(level))
            }
            #[cfg(target_os = "windows")]
            {
                Box::new(crate::sandbox::windows::WindowsSandbox::new(level))
            }
            #[cfg(target_os = "macos")]
            {
                Box::new(crate::sandbox::darwin::SeatbeltSandbox::new(level))
            }
            #[cfg(not(any(
                target_os = "linux",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "windows",
                target_os = "macos"
            )))]
            {
                let feature = match level {
                    SandboxLevel::Off => "disabled",
                    SandboxLevel::Basic => "basic (stub)",
                    SandboxLevel::Strict => "strict (stub)",
                };
                Box::new(StubSandbox::new(level, feature))
            }
        };
        Self { backend }
    }

    /// Creates a sandbox with the given backend (tests, custom composition).
    pub fn with_backend(backend: Box<dyn SandboxBackend>) -> Self {
        Self { backend }
    }

    pub fn with_stub(level: SandboxLevel) -> Self {
        let backend: Box<dyn SandboxBackend> = Box::new(StubSandbox::new(level, "disabled"));
        Self { backend }
    }

    pub fn with_paths(level: SandboxLevel, paths: SandboxPaths) -> Result<Self, SandboxError> {
        let sandbox = Self::new(level);

        if level == SandboxLevel::Off {
            return Ok(sandbox);
        }

        if level == SandboxLevel::Strict {
            let caps = sandbox.backend.capabilities();
            if !caps.can_enforce_strict() {
                return Err(SandboxError::InsufficientCapabilities(format!(
                    "backend '{}' has no read-path allowlist support",
                    sandbox.backend.feature_name(),
                )));
            }
        }

        let read_refs: Vec<&Path> = paths.read_paths.iter().map(|p| p.as_path()).collect();
        let write_refs: Vec<&Path> = paths.write_paths.iter().map(|p| p.as_path()).collect();
        let denied_refs: Vec<&Path> = paths.no_access_paths.iter().map(|p| p.as_path()).collect();

        sandbox
            .backend
            .apply(&read_refs, &write_refs, &denied_refs)?;

        Ok(sandbox)
    }

    pub fn is_supported(&self) -> bool {
        self.backend.is_supported()
    }

    pub fn level(&self) -> SandboxLevel {
        self.backend.level()
    }

    pub fn feature_name(&self) -> &'static str {
        self.backend.feature_name()
    }

    pub fn capabilities(&self) -> SandboxCapabilities {
        self.backend.capabilities()
    }
}

pub struct StubSandbox {
    level: SandboxLevel,
    feature: &'static str,
}

impl StubSandbox {
    pub fn new(level: SandboxLevel, feature: &'static str) -> Self {
        Self { level, feature }
    }
}

impl SandboxBackend for StubSandbox {
    fn apply(
        &self,
        _read_paths: &[&Path],
        _write_paths: &[&Path],
        _denied_paths: &[&Path],
    ) -> Result<(), SandboxError> {
        if self.level == SandboxLevel::Off {
            tracing::debug!("Sandbox disabled - no restrictions applied");
            return Ok(());
        }

        tracing::warn!(
            "OS-level sandboxing is not available on this platform ({}). \
             Using basic directory isolation instead. For full sandboxing, \
             use Linux with kernel 5.13+, FreeBSD with capsicum, OpenBSD with pledge, \
             Windows with Job Objects, or macOS with Seatbelt.",
            std::env::consts::OS
        );

        Ok(())
    }

    fn is_supported(&self) -> bool {
        false
    }

    fn feature_name(&self) -> &'static str {
        self.feature
    }

    fn level(&self) -> SandboxLevel {
        self.level
    }

    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities {
            read_path_allowlist: false,
            write_path_allowlist: false,
            deny_paths: false,
            process_limits: false,
            network_restrictions: false,
            child_process_restrictions: false,
        }
    }
}

#[cfg(target_os = "linux")]
pub mod linux {
    //! Linux Landlock backend (Phase 81 corrective).
    //!
    //! Uses the maintained `landlock` crate (0.4.x, ABI-9 surface) instead
    //! of handwritten UAPI structures. Required filesystem restrictions use
    //! `CompatLevel::HardRequirement`; production inspects the returned
    //! `RestrictionStatus` and rejects `PartiallyEnforced` / `NotEnforced`
    //! on required paths. `no_new_privs` is established via the crate's
    //! atomic restrict path and verified from the enforcement report.
    //! Availability is the Landlock ABI/capability result, never kernel
    //! release text. Rule fds are RAII-owned by the crate (no leaks).
    //!
    //! Dependency gate (Phase 81 Workstream B, measured 2026-09-26):
    //! `landlock 0.4.7`, deps `enumflags2` + `libc` + `thiserror` (all
    //! pre-existing in the workspace graph), no optional features required
    //! for the filesystem API used here, MSRV 1.71 (workspace MSRV 1.81),
    //! Linux x86_64/aarch64/riscv64 via syscalls. Linux-only dependency:
    //! no effect on macOS/Windows builds. ADOPTED (raw UAPI deleted).
    use super::{SandboxBackend, SandboxCapabilities, SandboxError, SandboxLevel};
    use std::path::Path;

    /// Vetted Landlock ABI for filesystem allowlists (Phase 81).
    ///
    /// V1 covers the full read/write file/dir/create/remove/make set used
    /// by the jail allowlist. Newer rights (Refer/Truncate/IoctlDev/
    /// ResolveUnix, network scopes, all-threads) are not silently claimed:
    /// if a caller requires them they must go through the Phase 82
    /// guarantee request as explicit required guarantees (currently
    /// reported unsupported until the syscall-filter layer qualifies
    /// them), never as best-effort filesystem success.
    #[cfg(target_os = "linux")]
    pub const VETTED_ABI: landlock::ABI = landlock::ABI::V1;

    pub struct LandlockSandbox {
        level: SandboxLevel,
    }

    impl LandlockSandbox {
        pub fn new(level: SandboxLevel) -> Self {
            Self { level }
        }

        /// Truthful availability probe: attempt to create a real ruleset
        /// with the vetted handled access. This is the ABI/capability
        /// result (fd creation is side-effect free; the fd is dropped).
        /// No kernel-release-text gate.
        fn probe_landlock_available() -> bool {
            use landlock::{Access, AccessFs, Compatible, Ruleset, RulesetAttr};
            let access_all = AccessFs::from_all(VETTED_ABI);
            match Ruleset::default()
                .set_compatibility(landlock::CompatLevel::HardRequirement)
                .handle_access(access_all)
            {
                Ok(rs) => rs.create().is_ok(),
                Err(_) => false,
            }
        }

        fn is_landlock_available() -> bool {
            Self::probe_landlock_available()
        }

        /// Describe the running backend ABI for reports (best-effort;
        /// never a security gate).
        pub fn backend_abi_description() -> &'static str {
            "landlock/abi-v1-vetted (crate ABI-9 surface)"
        }

        fn build_and_enforce(
            &self,
            read_paths: &[&Path],
            write_paths: &[&Path],
        ) -> Result<landlock::RestrictionStatus, SandboxError> {
            use landlock::{
                Access, AccessFs, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
                RulesetCreatedAttr, RulesetStatus,
            };
            let access_all = AccessFs::from_all(VETTED_ABI);
            let access_read = AccessFs::from_read(VETTED_ABI);
            let access_write = AccessFs::from_read(VETTED_ABI) | AccessFs::from_write(VETTED_ABI);

            let mut created = Ruleset::default()
                .set_compatibility(landlock::CompatLevel::HardRequirement)
                .handle_access(access_all)
                .map_err(|e| SandboxError::Unsupported(format!("landlock handle_access: {e}")))?
                .create()
                .map_err(|e| {
                    // Creation failure under HardRequirement means the
                    // running kernel cannot supply even the vetted set:
                    // report unsupported, never best-effort success.
                    SandboxError::Unsupported(format!("landlock create: {e}"))
                })?;
            // Harden the created ruleset too: any rule using a right the
            // running ABI lacks must fail rather than silently narrow.
            created = created.set_compatibility(landlock::CompatLevel::HardRequirement);

            for path in read_paths {
                let fd = PathFd::new(path).map_err(|e| {
                    SandboxError::InvalidPath(format!("landlock open {}: {e}", path.display()))
                })?;
                created = created
                    .add_rule(PathBeneath::new(fd, access_read))
                    .map_err(|e| {
                        SandboxError::EntryFailed(format!("landlock add read rule: {e}"))
                    })?;
            }
            for path in write_paths {
                let fd = PathFd::new(path).map_err(|e| {
                    SandboxError::InvalidPath(format!("landlock open {}: {e}", path.display()))
                })?;
                created = created
                    .add_rule(PathBeneath::new(fd, access_write))
                    .map_err(|e| {
                        SandboxError::EntryFailed(format!("landlock add write rule: {e}"))
                    })?;
            }

            // Establish no_new_privs atomically with enforcement; request
            // calling-thread + descendants scope (the jail enters before
            // workload threads, satisfying the call-site invariant; the
            // generic all-threads requirement is a Phase 82 explicit
            // guarantee, not silently assumed here).
            let created = created.no_new_privs(true);
            let status = created
                .restrict_self()
                .map_err(|e| SandboxError::EntryFailed(format!("landlock restrict_self: {e}")))?;
            // Required restrictions must be fully enforced with
            // no_new_privs verified; PartiallyEnforced / NotEnforced never
            // translate into success on this path.
            if status.ruleset != RulesetStatus::FullyEnforced {
                return Err(SandboxError::PartialEnforcement(format!(
                    "landlock ruleset status {:?} (required fully enforced)",
                    status.ruleset
                )));
            }
            if !status.no_new_privs {
                return Err(SandboxError::PartialEnforcement(
                    "landlock no_new_privs not established".into(),
                ));
            }
            Ok(status)
        }
    }

    impl SandboxBackend for LandlockSandbox {
        fn apply(
            &self,
            read_paths: &[&Path],
            write_paths: &[&Path],
            denied_paths: &[&Path],
        ) -> Result<(), SandboxError> {
            if !Self::is_landlock_available() {
                tracing::warn!(
                    "Landlock not available (ABI probe failed). \
                     OS-level sandboxing is not active."
                );
                return Err(SandboxError::LandlockUnavailable);
            }

            // Landlock has no explicit deny-path primitive: a requested
            // deny overlapping an allowed ancestor cannot be represented.
            // Claiming success would be a silent downgrade, so fail closed
            // with a typed reason instead of logging-and-continuing.
            if !denied_paths.is_empty() {
                return Err(SandboxError::Unsupported(format!(
                    "landlock cannot represent {} explicit deny path(s) under an allowed ancestor",
                    denied_paths.len()
                )));
            }

            let status = self.build_and_enforce(read_paths, write_paths)?;

            // Phase 83 Workstream B: categorical syscall-filter denial for
            // the jail's no-network/no-child/no-exec needs (deny-list, not
            // an allowlist). Installed after all startup resources exist
            // (fds for Landlock rules are already consumed) and before any
            // untrusted work. Failure fails closed: the backend documents
            // these guarantees, so a filter that cannot install must not
            // report them as enforced.
            seccomp::apply_jail_filter()?;

            tracing::info!(
                "Applied landlock sandbox (level: {:?}, abi: {}, no_new_privs: {}, seccomp: {}) with {} read paths, {} write paths",
                self.level,
                Self::backend_abi_description(),
                status.no_new_privs,
                seccomp::JAIL_FILTER_DESCRIPTION,
                read_paths.len(),
                write_paths.len()
            );

            Ok(())
        }

        fn is_supported(&self) -> bool {
            Self::is_landlock_available()
        }

        fn feature_name(&self) -> &'static str {
            "landlock"
        }

        fn level(&self) -> SandboxLevel {
            self.level
        }

        fn capabilities(&self) -> SandboxCapabilities {
            SandboxCapabilities {
                read_path_allowlist: true,
                write_path_allowlist: true,
                deny_paths: false,
                process_limits: false,
                network_restrictions: false,
                child_process_restrictions: false,
            }
        }
    }

    /// Phase 83 Workstream B: Linux syscall-filter layer for the jail's
    /// categorical no-network / no-child / no-exec needs.
    ///
    /// Preferred mechanism: `seccompiler` (pure Rust, x86_64/aarch64/
    /// riscv64, no system `libseccomp` dependency — no C/system library
    /// added by accident). Dependency gate (2026-09-26): `seccompiler 0.5`,
    /// deps `libc` only (no default features; `json`/`serde` not enabled),
    /// Linux-only. ADOPTED; `libseccomp` remains the comparison baseline
    /// (rejected: native library requirement with no narrower benefit);
    /// a minimal raw-seccomp fallback was not needed.
    ///
    /// Scope is deliberately a categorical DENY-list, not a full syscall
    /// allowlist (a giant allowlist without workload qualification is a
    /// Phase 83 rejection criterion):
    /// - new network authority: `socket`, `socketpair`, `connect` → EPERM;
    /// - child creation: `fork`, `vfork` (x86_64 only) → EPERM; `clone`
    ///   without `CLONE_THREAD` → EPERM (thread creation preserved);
    ///   `clone3` → ENOSYS (transparent glibc fallback to filtered `clone`;
    ///   raw clone3 process creation fails);
    /// - new programs: `execve`, `execveat` → EPERM.
    /// - preserved: inherited stdio pipe ops and the Wasmtime/YARA runtime
    ///   syscalls (default Allow — the filter only denies the categories
    ///   above, proven by real WASM/YARA round trips under the filter on
    ///   Linux, i.e. `jail_binary_integration` without the hatch).
    ///
    /// Deterministic denial contract: EPERM for the main filter, ENOSYS
    /// for clone3 (fallback, not failure). Never Kill (a trap would turn
    /// an unexpected-but-benign runtime syscall into a fatality). The
    /// denied set is hardcoded — security-sensitive bypass is not
    /// configurable from untrusted input.
    ///
    /// Installed after all required startup resources are created and
    /// before untrusted work, via TSYNC/all-threads where available. The
    /// jail enters single-threaded; that precondition is encoded (TSYNC on
    /// a single-threaded process succeeds and covers future threads,
    /// including Wasmtime worker threads inheriting the filter).
    pub mod seccomp {
        use super::super::SandboxError;

        /// Fixed filter description for reports/logs (no untrusted input).
        pub const JAIL_FILTER_DESCRIPTION: &str =
            "seccomp-errno(EPERM)+enosys(clone3)/tsync categorical jail filter";

        /// Syscalls denied with EPERM by the main filter (unconditional).
        /// fork/vfork exist only on x86_64 (aarch64/riscv64 create
        /// processes solely via clone/clone3, both filtered).
        #[cfg(target_arch = "x86_64")]
        const DENY_EPERM: &[&str] = &[
            "socket",
            "socketpair",
            "connect",
            "fork",
            "vfork",
            "execve",
            "execveat",
        ];
        #[cfg(not(target_arch = "x86_64"))]
        const DENY_EPERM: &[&str] = &["socket", "socketpair", "connect", "execve", "execveat"];

        /// Pure availability check: the filter compiles for this arch.
        /// Used by the guarantee projection (no side effects, no install).
        pub fn filter_compiles() -> bool {
            build_main_filter().is_ok() && build_clone3_filter().is_ok()
        }

        /// Portable hook for the guarantee projection: true on Linux where
        /// the categorical filter compiles (x86_64/aarch64/riscv64).
        pub fn projected_enforcement() -> bool {
            filter_compiles()
        }

        fn target_arch() -> Result<seccompiler::TargetArch, SandboxError> {
            std::env::consts::ARCH
                .try_into()
                .map_err(|_| SandboxError::Unsupported("seccomp arch unsupported".into()))
        }

        fn build_main_filter() -> Result<seccompiler::BpfProgram, SandboxError> {
            use seccompiler::{
                SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
                SeccompRule,
            };
            use std::collections::BTreeMap;
            let arch = target_arch()?;
            let mut rules = BTreeMap::new();
            // Unconditional categorical denies. fork/vfork only exist on
            // x86_64; elsewhere clone/clone3 (filtered below) are the sole
            // process-creation primitives.
            #[cfg(target_arch = "x86_64")]
            let unconditional = [
                "socket",
                "socketpair",
                "connect",
                "fork",
                "vfork",
                "execve",
                "execveat",
            ];
            #[cfg(not(target_arch = "x86_64"))]
            let unconditional = ["socket", "socketpair", "connect", "execve", "execveat"];
            for name in unconditional {
                let nr = syscall_nr(name)?;
                rules.insert(nr, vec![]);
            }
            // clone without CLONE_THREAD (0x00010000) = process creation
            // (fork-like, vfork-like incl. CLONE_VM-without-THREAD). Thread
            // creation (CLONE_THREAD set) must keep working for the
            // Wasmtime/YARA runtimes after entry. MaskedEq(mask) matches
            // when (flags & mask) == (value & mask); value 0 denies exactly
            // the no-THREAD case.
            const CLONE_THREAD: u64 = 0x0001_0000;
            let clone_cond = SeccompCondition::new(
                0,
                SeccompCmpArgLen::Qword,
                SeccompCmpOp::MaskedEq(CLONE_THREAD),
                0,
            )
            .map_err(|e| SandboxError::InvalidPolicy(format!("seccomp clone cond: {e:?}")))?;
            let clone_rule = SeccompRule::new(vec![clone_cond])
                .map_err(|e| SandboxError::InvalidPolicy(format!("seccomp clone rule: {e:?}")))?;
            rules.insert(libc::SYS_clone, vec![clone_rule]);
            let filter = SeccompFilter::new(
                rules,
                SeccompAction::Allow,
                SeccompAction::Errno(libc::EPERM as u32),
                arch,
            )
            .map_err(|e| SandboxError::InvalidPolicy(format!("seccomp build: {e:?}")))?;
            filter
                .try_into()
                .map_err(|e| SandboxError::InvalidPolicy(format!("seccomp compile: {e:?}")))
        }

        fn build_clone3_filter() -> Result<seccompiler::BpfProgram, SandboxError> {
            use seccompiler::SeccompFilter;
            use std::collections::BTreeMap;
            let arch = target_arch()?;
            // ENOSYS (not EPERM): glibc thread creation transparently falls
            // back to clone (which is flag-filtered above); raw clone3
            // process creation fails with ENOSYS. A Kill/EPERM here would
            // break legitimate runtime thread creation on clone3-first
            // libcs — explicitly rejected.
            let mut rules = BTreeMap::new();
            rules.insert(libc::SYS_clone3, vec![]);
            let filter = SeccompFilter::new(
                rules,
                seccompiler::SeccompAction::Allow,
                seccompiler::SeccompAction::Errno(libc::ENOSYS as u32),
                arch,
            )
            .map_err(|e| SandboxError::InvalidPolicy(format!("seccomp clone3 build: {e:?}")))?;
            filter
                .try_into()
                .map_err(|e| SandboxError::InvalidPolicy(format!("seccomp clone3 compile: {e:?}")))
        }

        fn syscall_nr(name: &str) -> Result<i64, SandboxError> {
            Ok(match name {
                "socket" => libc::SYS_socket,
                "socketpair" => libc::SYS_socketpair,
                "connect" => libc::SYS_connect,
                // fork/vfork exist only on x86_64 (removed on aarch64/
                // riscv64 where clone/clone3 are the only process-creation
                // primitives — both filtered). Callers insert these only
                // where the constants exist (see build_main_filter).
                #[cfg(target_arch = "x86_64")]
                "fork" => libc::SYS_fork,
                #[cfg(target_arch = "x86_64")]
                "vfork" => libc::SYS_vfork,
                "execve" => libc::SYS_execve,
                "execveat" => libc::SYS_execveat,
                _ => return Err(SandboxError::InvalidPolicy("unknown syscall".into())),
            })
        }

        /// Install the categorical jail filter (irreversible). Uses
        /// TSYNC/all-threads: succeeds on the single-threaded jail entry
        /// and covers future (runtime/worker) threads. Any install failure
        /// fails closed (never silent).
        pub fn apply_jail_filter() -> Result<(), SandboxError> {
            let main = build_main_filter()?;
            let clone3 = build_clone3_filter()?;
            seccompiler::apply_filter_all_threads(&main).map_err(|e| {
                SandboxError::EntryFailed(format!("seccomp main install (tsync): {e:?}"))
            })?;
            seccompiler::apply_filter_all_threads(&clone3).map_err(|e| {
                SandboxError::EntryFailed(format!("seccomp clone3 install (tsync): {e:?}"))
            })?;
            tracing::info!("Applied {}", JAIL_FILTER_DESCRIPTION);
            Ok(())
        }

        /// Denied-syscall inventory for tests/docs (fixed, deterministic).
        pub fn denied_inventory() -> Vec<&'static str> {
            let mut v: Vec<&'static str> = DENY_EPERM.to_vec();
            v.push("clone(non-thread)");
            v.push("clone3(ENOSYS-fallback)");
            v
        }
    }
}

#[cfg(target_os = "freebsd")]
pub mod capsicum {
    use super::{SandboxBackend, SandboxCapabilities, SandboxError, SandboxLevel};
    use std::ffi::CStr;
    use std::path::Path;

    pub struct CapsicumSandbox {
        level: SandboxLevel,
    }

    impl CapsicumSandbox {
        pub fn new(level: SandboxLevel) -> Self {
            Self { level }
        }

        /// Phase 46 (Workstream G): `cap_getmode` reports the *current*
        /// capability mode, not availability. Availability means the syscall
        /// exists (returns 0). Requiring `mode != 0` reported "unsupported"
        /// on every host that was not already sandboxed — backwards.
        fn is_capsicum_available() -> bool {
            let mut mode: u32 = 0;
            // SAFETY: cap_getmode writes a u32 through a valid out-pointer;
            // no lifetime or ownership transfer.
            let result = unsafe { libc::cap_getmode(&mut mode) };
            result == 0
        }

        /// Phase 83 Workstream C: narrow inherited stdio to least rights
        /// before entering capability mode. stdin: read-only (+seek for
        /// pipes as needed by the stdio transport); stdout/stderr:
        /// write-only. fcntl/ioctl limits are not widened (no added
        /// ioctls/fcntls beyond the transport minimum).
        fn limit_stdio_rights() -> Result<(), SandboxError> {
            // SAFETY: __cap_rights_init is a C variadic rights constructor;
            // called with (version, &mut zeroed rights, <u64 rights...>, 0
            // terminator). The rights pointer is a valid stack allocation
            // alive for both calls; return value (same pointer) is checked
            // for null. Then cap_rights_limit applies to the live fd.
            //
            // # Safety contract (unsafe fn): `fd` must be a valid open file
            // descriptor owned by this process; `rights` must hold 1-2
            // valid CAP_* tokens. Callers pass only stdio fds 0/1/2 with
            // fixed tokens — never attacker-controlled values.
            unsafe fn limit_fd(fd: i32, rights: &[u64]) -> Result<(), SandboxError> {
                let mut cr: libc::cap_rights_t = std::mem::zeroed();
                // Build the varargs call for 1-2 rights explicitly (no
                // dynamic varargs construction): init then set each right
                // via __cap_rights_set (also variadic, single-right form).
                let init_ok = match rights.len() {
                    1 => {
                        libc::__cap_rights_init(libc::CAP_RIGHTS_VERSION, &mut cr, rights[0], 0u64)
                    }
                    2 => libc::__cap_rights_init(
                        libc::CAP_RIGHTS_VERSION,
                        &mut cr,
                        rights[0],
                        rights[1],
                        0u64,
                    ),
                    _ => std::ptr::null_mut(),
                };
                if init_ok.is_null() {
                    return Err(SandboxError::EntryFailed("cap_rights_init failed".into()));
                }
                if libc::cap_rights_limit(fd, &cr) != 0 {
                    return Err(SandboxError::EntryFailed(format!(
                        "cap_rights_limit failed for fd {fd}"
                    )));
                }
                Ok(())
            }
            unsafe {
                // stdin (0): read (+seek covers pipe pread/poll transport).
                limit_fd(0, &[libc::CAP_READ, libc::CAP_SEEK])?;
                // stdout/stderr (1,2): write (+seek for pipe semantics).
                limit_fd(1, &[libc::CAP_WRITE, libc::CAP_SEEK])?;
                limit_fd(2, &[libc::CAP_WRITE, libc::CAP_SEEK])?;
                // Close accidental inherited descriptors (fd >= 3): the
                // jail legitimately needs only 0/1/2 (stdio IPC + log).
                // Preopened directory capabilities (Phase 83 future) would
                // be exempted here by explicit fd number; none exist yet,
                // so closefrom(3) is the correct hygiene default.
                libc::closefrom(3);
            }
            Ok(())
        }

        fn enter_sandbox(&self) -> Result<(), SandboxError> {
            Self::limit_stdio_rights()?;
            // SAFETY: cap_enter takes no pointers and only confines the
            // calling process (irreversible); errno inspected on failure.
            let result = unsafe { libc::cap_enter() };
            if result < 0 {
                return Err(SandboxError::Syscall("cap_enter failed".into()));
            }
            // Verify capability mode actually entered (not merely "called").
            let mut mode: u32 = 0;
            // SAFETY: valid out-pointer, no ownership transfer.
            let got = unsafe { libc::cap_getmode(&mut mode) };
            if got != 0 || mode == 0 {
                return Err(SandboxError::PartialEnforcement(
                    "cap_enter returned but cap_getmode denies capability mode".into(),
                ));
            }
            Ok(())
        }
    }

    impl SandboxBackend for CapsicumSandbox {
        fn apply(
            &self,
            read_paths: &[&Path],
            write_paths: &[&Path],
            denied_paths: &[&Path],
        ) -> Result<(), SandboxError> {
            if !Self::is_capsicum_available() {
                tracing::warn!(
                    "Capsicum not available on this FreeBSD system. \
                     OS-level sandboxing is not active."
                );
                return Err(SandboxError::NotSupported("Capsicum not available".into()));
            }

            // Phase 83 Workstream C: a pathname vector is NOT a Capsicum
            // allowlist. Pretending it is would be a silent downgrade.
            // Generic path requests must arrive as preopened directory
            // capabilities (future descriptor-relative contract) — until
            // then, report the path-policy form unsupported (fail closed)
            // rather than entering cap mode while ignoring the paths.
            // (`capsicum` crate gate, 2026-09-26: kept libc calls with the
            // rights-limiting coverage above; the crate adds no narrower
            // mechanism for our stdio-custody needs and would add a
            // FreeBSD-only dependency edge. Documented, not accidental.)
            if !(read_paths.is_empty() && write_paths.is_empty() && denied_paths.is_empty()) {
                return Err(SandboxError::Unsupported(
                    "capsicum path-vector policy unsupported: preopen requested roots into directory capabilities (no raw-path allowlist)".into(),
                ));
            }

            self.enter_sandbox()?;

            tracing::info!(
                "Applied capsicum sandbox (level: {:?}, stdio rights-limited, cap mode verified)",
                self.level,
            );

            Ok(())
        }

        fn is_supported(&self) -> bool {
            Self::is_capsicum_available()
        }

        fn feature_name(&self) -> &'static str {
            "capsicum"
        }

        fn level(&self) -> SandboxLevel {
            self.level
        }

        fn capabilities(&self) -> SandboxCapabilities {
            // Phase 46 truthfulness: Capsicum is FD-based capability mode —
            // no path allowlists. `process_limits` is numeric resource bounds
            // (Job-Objects style); capability-mode syscall confinement is not
            // a numeric limit, so false. Network/child confinement follows
            // from capability mode (no new global-namespace opens), so true.
            // Strict (which requires a read allowlist) always fails closed
            // on this backend by design.
            SandboxCapabilities {
                read_path_allowlist: false,
                write_path_allowlist: false,
                deny_paths: false,
                process_limits: false,
                network_restrictions: true,
                child_process_restrictions: true,
            }
        }
    }
}

#[cfg(target_os = "openbsd")]
pub mod pledge {
    use super::{SandboxBackend, SandboxCapabilities, SandboxError, SandboxLevel};
    use std::ffi::CStr;
    use std::path::Path;

    pub struct PledgeSandbox {
        level: SandboxLevel,
    }

    impl PledgeSandbox {
        pub fn new(level: SandboxLevel) -> Self {
            Self { level }
        }

        fn is_pledge_available() -> bool {
            true
        }

        fn pledge(&self, promises: &str) -> Result<(), SandboxError> {
            let promises_cstr = CStr::from_bytes_with_nul(format!("{}\0", promises).as_bytes())
                .map_err(|_| SandboxError::Syscall("Invalid pledge promises".into()))?;

            let result = unsafe { libc::pledge(promises_cstr.as_ptr(), std::ptr::null()) };

            if result < 0 {
                return Err(SandboxError::Syscall("pledge failed".into()));
            }

            Ok(())
        }

        /// Phase 81/83: OS-native path bytes with explicit interior-NUL
        /// rejection. `Path::display()` is lossy (replaces non-UTF-8) and
        /// must never cross an OS security boundary; encoded bytes are
        /// exact. Empty paths and interior NULs are rejected.
        fn unveil(&self, path: &Path, permissions: &str) -> Result<(), SandboxError> {
            use std::os::unix::ffi::OsStrExt;
            let bytes = path.as_os_str().as_encoded_bytes();
            if bytes.is_empty() {
                return Err(SandboxError::InvalidPath("empty unveil path".into()));
            }
            if bytes.contains(&0) {
                return Err(SandboxError::InvalidPath(format!(
                    "interior NUL rejected in unveil path: {}",
                    path.display()
                )));
            }
            // SAFETY: bytes contain no interior NUL (checked); we append
            // exactly one NUL terminator. The buffer outlives the syscall.
            let mut terminated = Vec::with_capacity(bytes.len() + 1);
            terminated.extend_from_slice(bytes);
            terminated.push(0);
            let path_cstr = CStr::from_bytes_with_nul(&terminated)
                .map_err(|_| SandboxError::Syscall("Invalid path".into()))?;

            let perms_cstr = CStr::from_bytes_with_nul(format!("{}\0", permissions).as_bytes())
                .map_err(|_| SandboxError::Syscall("Invalid permissions".into()))?;

            // SAFETY: both pointers are valid NUL-terminated strings alive
            // for the call; unveil copies them. errno inspected on failure.
            let result = unsafe { libc::unveil(path_cstr.as_ptr(), perms_cstr.as_ptr()) };

            if result < 0 {
                return Err(SandboxError::Syscall("unveil failed".into()));
            }

            Ok(())
        }

        /// Phase 83: lock unveil after policy construction so no later
        /// path can widen the filesystem view. `unveil(NULL, NULL)` is the
        /// documented lock; failure to lock is a hard error (fail closed).
        fn lock_unveil(&self) -> Result<(), SandboxError> {
            // SAFETY: both args NULL is the documented unveil-lock
            // operation; no pointer dereference.
            let result = unsafe { libc::unveil(std::ptr::null(), std::ptr::null()) };
            if result < 0 {
                return Err(SandboxError::Syscall("unveil lock failed".into()));
            }
            Ok(())
        }

        /// Phase 83: minimal jail promises derived from actual workload
        /// needs (stdio + rpath/wpath/cpath covered by unveil rules).
        /// `stdio` omits `inet`, `proc`, and `exec`: network, child
        /// creation, and exec are denied rather than inherited. `prot_exec`
        /// is NOT added casually (Wasmtime/JIT executable-memory needs on
        /// OpenBSD are a backend-specific requirement to be proven by
        /// native workload tests, never silently broadened here).
        fn commit_pledge(&self) -> Result<(), SandboxError> {
            self.pledge("stdio")
        }
    }

    impl SandboxBackend for PledgeSandbox {
        fn apply(
            &self,
            read_paths: &[&Path],
            write_paths: &[&Path],
            denied_paths: &[&Path],
        ) -> Result<(), SandboxError> {
            if !Self::is_pledge_available() {
                tracing::warn!(
                    "Pledge not available on this OpenBSD system. \
                     OS-level sandboxing is not active."
                );
                return Err(SandboxError::NotSupported("Pledge not available".into()));
            }

            for path in read_paths {
                self.unveil(path, "r")?;
            }

            for path in write_paths {
                self.unveil(path, "rwc")?;
            }

            for path in denied_paths {
                self.unveil(path, "")?;
            }

            // Lock the filesystem view before dropping syscall authority.
            self.lock_unveil()?;
            self.commit_pledge()?;

            tracing::info!(
                "Applied pledge sandbox (level: {:?}) with {} read paths, {} write paths",
                self.level,
                read_paths.len(),
                write_paths.len()
            );

            Ok(())
        }

        fn is_supported(&self) -> bool {
            Self::is_pledge_available()
        }

        fn feature_name(&self) -> &'static str {
            "pledge"
        }

        fn level(&self) -> SandboxLevel {
            self.level
        }

        fn capabilities(&self) -> SandboxCapabilities {
            // Phase 46 truthfulness: unveil provides path allowlists and
            // explicit empty-perm denies; pledge("stdio") denies inet/proc/
            // exec, hence network/child true. `process_limits` is numeric
            // resource bounds only — pledge syscall filtering is not a
            // memory/CPU limit, so false.
            SandboxCapabilities {
                read_path_allowlist: true,
                write_path_allowlist: true,
                deny_paths: true,
                process_limits: false,
                network_restrictions: true,
                child_process_restrictions: true,
            }
        }
    }
}

#[cfg(target_os = "windows")]
pub mod windows {
    use super::{SandboxBackend, SandboxCapabilities, SandboxError, SandboxLevel};
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    /// Preserved Job Object defaults (Phase 81: unchanged unless a separate
    /// config decision changes them).
    pub const WINDOWS_PROCESS_MEMORY_LIMIT: usize = 256 * 1024 * 1024;
    pub const WINDOWS_JOB_MEMORY_LIMIT: usize = 512 * 1024 * 1024;

    pub struct WindowsSandbox {
        level: SandboxLevel,
        applied: AtomicBool,
        /// Owned Job handle (Phase 81 Workstream G).
        ///
        /// The handle must live as long as confinement: with
        /// `KILL_ON_JOB_CLOSE`, closing the last job handle terminates
        /// associated processes. It is stored here (retained via the owning
        /// `ProcessSandbox`) and closed exactly once on drop at process
        /// teardown — never converted into a short-lived RAII local that
        /// is dropped right after assignment while the process still runs.
        /// Dropping `EnteredSandbox`/`ProcessSandbox` early on Windows is
        /// therefore loud (process termination), never a silent removal
        /// of limits; long-lived jails retain the token through the serve
        /// loop. No raw-handle leak is used as lifetime management.
        job: Mutex<Option<isize>>,
    }

    // SAFETY: the stored job handle is an opaque kernel handle value
    // (isize); it is only closed once via CloseHandle on drop. Send+Sync
    // via the Mutex; no handle is duplicated or shared across threads
    // without the lock.
    unsafe impl Send for WindowsSandbox {}
    unsafe impl Sync for WindowsSandbox {}

    impl Drop for WindowsSandbox {
        fn drop(&mut self) {
            #[cfg(target_os = "windows")]
            {
                if let Ok(mut guard) = self.job.lock() {
                    if let Some(handle) = guard.take() {
                        // SAFETY: handle was returned by CreateJobObjectW
                        // and stored exactly once; CloseHandle exactly once
                        // here. With KILL_ON_JOB_CLOSE this terminates the
                        // job at teardown, which is the documented
                        // lifecycle (never drop while confined work runs).
                        unsafe {
                            windows_sys::Win32::Foundation::CloseHandle(
                                handle as windows_sys::Win32::Foundation::HANDLE,
                            );
                        }
                    }
                }
            }
        }
    }

    impl WindowsSandbox {
        pub fn new(level: SandboxLevel) -> Self {
            Self {
                level,
                applied: AtomicBool::new(false),
                job: Mutex::new(None),
            }
        }

        fn is_supported() -> bool {
            true
        }

        /// Phase 81 Workstream F: host-global DACL mutation is NOT process
        /// sandboxing (it changes ACLs on filesystem objects themselves and
        /// can affect other processes/users). It has been removed from
        /// `WindowsSandbox::apply` and from all capability claims. If
        /// another subsystem needs durable ACL hardening it must live in an
        /// explicitly named filesystem-hardening API with separate
        /// ownership/tests — never behind sandbox method names.
        /// Windows `Strict` remains fail-closed for filesystem/access-control
        /// isolation (no read allowlist on this backend by design).

        /// Phase 81 Workstream D: canonical Job Object ABI via generated
        /// `windows-sys` definitions (`Win32_System_JobObjects`), class 9
        /// extended-limit information, and correct limit flags. Queries the
        /// object back after `SetInformationJobObject` and verifies the
        /// effective flags/limits. A nested-job assignment failure returns a
        /// typed conflict (never "limits installed").
        fn apply_job_object(&self) -> Result<(), SandboxError> {
            use windows_sys::Win32::System::JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
                QueryInformationJobObject, SetInformationJobObject,
                JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOB_OBJECT_LIMIT_PROCESS_MEMORY,
            };
            use windows_sys::Win32::System::Threading::{GetCurrentProcess, IO_COUNTERS};

            // SAFETY: CreateJobObjectW with null attributes/name creates an
            // unnamed job owned by us; null return means failure (GetLastError
            // inspected by caller via typed error). No string lifetime issues.
            let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if job.is_null() {
                return Err(SandboxError::Syscall("CreateJobObjectW failed".into()));
            }
            // From here the raw handle is owned by this function until
            // stored in `self.job`; every error path closes it exactly once
            // (no leak-as-lifetime, no double close).
            let close_job = |h: isize| unsafe {
                windows_sys::Win32::Foundation::CloseHandle(
                    h as windows_sys::Win32::Foundation::HANDLE,
                );
            };

            let mut limit_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
                BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                    PerProcessUserTimeLimit: 0,
                    PerJobUserTimeLimit: 0,
                    LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
                        | JOB_OBJECT_LIMIT_JOB_MEMORY,
                    MinimumWorkingSetSize: 0,
                    MaximumWorkingSetSize: 0,
                    ActiveProcessLimit: 0,
                    Affinity: 0,
                    PriorityClass: 0,
                    SchedulingClass: 0,
                },
                IoInfo: IO_COUNTERS {
                    ReadOperationCount: 0,
                    WriteOperationCount: 0,
                    OtherOperationCount: 0,
                    ReadTransferCount: 0,
                    WriteTransferCount: 0,
                    OtherTransferCount: 0,
                },
                ProcessMemoryLimit: WINDOWS_PROCESS_MEMORY_LIMIT,
                JobMemoryLimit: WINDOWS_JOB_MEMORY_LIMIT,
                PeakProcessMemoryUsed: 0,
                PeakJobMemoryUsed: 0,
            };

            // SAFETY: limit_info is a valid generated extended-limit struct
            // alive for the call; class 9 matches its layout; size is the
            // generated size. Nonzero return means installed.
            let set_ok = unsafe {
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    &mut limit_info as *mut _ as *const core::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if set_ok == 0 {
                close_job(job as isize);
                return Err(SandboxError::Syscall(
                    "SetInformationJobObject failed".into(),
                ));
            }

            // Query back and verify effective flags/limits (Phase 81).
            let mut queried =
                std::mem::MaybeUninit::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>::zeroed();
            let mut ret_len: u32 = 0;
            // SAFETY: queried is zeroed storage of the exact generated type
            // with matching class/size; Query writes at most size bytes and
            // reports actual length. Checked for success before assume_init.
            let query_ok = unsafe {
                QueryInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    queried.as_mut_ptr() as *mut core::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                    &mut ret_len,
                )
            };
            if query_ok == 0 {
                close_job(job as isize);
                return Err(SandboxError::Syscall(
                    "QueryInformationJobObject failed".into(),
                ));
            }
            let queried = unsafe { queried.assume_init() };
            let expected_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | JOB_OBJECT_LIMIT_PROCESS_MEMORY
                | JOB_OBJECT_LIMIT_JOB_MEMORY;
            if queried.BasicLimitInformation.LimitFlags & expected_flags != expected_flags
                || queried.ProcessMemoryLimit != WINDOWS_PROCESS_MEMORY_LIMIT
                || queried.JobMemoryLimit != WINDOWS_JOB_MEMORY_LIMIT
            {
                close_job(job as isize);
                return Err(SandboxError::PartialEnforcement(format!(
                    "job limits query mismatch (flags {:#x}, proc {} job {})",
                    queried.BasicLimitInformation.LimitFlags,
                    queried.ProcessMemoryLimit,
                    queried.JobMemoryLimit
                )));
            }

            // SAFETY: GetCurrentProcess returns a pseudo-handle (no close).
            // Assign may fail when already constrained by an incompatible
            // outer job: report a typed conflict, never "installed".
            let current = unsafe { GetCurrentProcess() };
            let assigned = unsafe { AssignProcessToJobObject(job, current) };
            if assigned == 0 {
                let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                close_job(job as isize);
                return Err(SandboxError::BackendConflict(format!(
                    "AssignProcessToJobObject failed (outer-job conflict likely, win32 {code})"
                )));
            }

            // Store the owned handle for the confinement lifetime.
            if let Ok(mut guard) = self.job.lock() {
                *guard = Some(job as isize);
            } else {
                close_job(job as isize);
                return Err(SandboxError::Syscall("job handle store poisoned".into()));
            }

            tracing::info!(
                "Applied Windows Job Object sandbox (level: {:?}, verified flags {:#x})",
                self.level,
                expected_flags
            );
            Ok(())
        }

        /// Phase 81 Workstream E: real mitigation structures via generated
        /// `windows-sys` definitions (`Win32_System_SystemServices`).
        /// Never passes creation-policy scalars to
        /// `SetProcessMitigationPolicy`. Queries effective policy where the
        /// API permits; an already-mandatory mitigation reports
        /// "already enforced", never "newly applied" after a setter failure.
        fn apply_mitigation_policies(&self) -> Result<(), SandboxError> {
            use windows_sys::Win32::System::SystemServices::{
                PROCESS_MITIGATION_ASLR_POLICY, PROCESS_MITIGATION_DEP_POLICY,
            };
            use windows_sys::Win32::System::Threading::{
                GetProcessMitigationPolicy, ProcessASLRPolicy, ProcessDEPPolicy,
                SetProcessMitigationPolicy,
            };

            // DEP: Enable (Flags bit0). Permanent=false (do not lock for
            // the test host; production hardening does not require
            // permanence for the jail's lifetime).
            let mut dep = PROCESS_MITIGATION_DEP_POLICY {
                Anonymous: unsafe { std::mem::zeroed() },
                Permanent: 0,
            };
            // SAFETY: generated union; Flags aliases the bitfield storage.
            // Setting Flags=1 enables DEP without touching reserved bits.
            dep.Anonymous.Flags = 1;
            // SAFETY: dep is a valid generated struct alive for the call;
            // size is the generated size; policy class matches the struct.
            let dep_ok = unsafe {
                SetProcessMitigationPolicy(
                    ProcessDEPPolicy,
                    &dep as *const _ as *const core::ffi::c_void,
                    std::mem::size_of::<PROCESS_MITIGATION_DEP_POLICY>(),
                )
            };
            // Query back where permitted to distinguish newly-applied from
            // already-enforced.
            let mut dep_q = PROCESS_MITIGATION_DEP_POLICY {
                Anonymous: unsafe { std::mem::zeroed() },
                Permanent: 0,
            };
            let dep_query_ok = unsafe {
                GetProcessMitigationPolicy(
                    windows_sys::Win32::System::Threading::GetCurrentProcess(),
                    ProcessDEPPolicy,
                    &mut dep_q as *mut _ as *mut core::ffi::c_void,
                    std::mem::size_of::<PROCESS_MITIGATION_DEP_POLICY>(),
                )
            };
            if dep_ok == 0 {
                // SAFETY: reading the generated union Flags aliases the
                // bitfield storage written by the kernel query above; the
                // struct outlived the GetProcessMitigationPolicy call.
                let already = dep_query_ok != 0 && unsafe { dep_q.Anonymous.Flags } & 1 == 1;
                if already {
                    tracing::debug!("DEP mitigation already enforced (setter no-op)");
                } else {
                    tracing::warn!("Failed to enable DEP mitigation");
                }
            } else {
                tracing::debug!("DEP mitigation enabled");
            }

            // ASLR: bottom-up + force-relocate + high-entropy (bits 0-2).
            let mut aslr = PROCESS_MITIGATION_ASLR_POLICY {
                Anonymous: unsafe { std::mem::zeroed() },
            };
            // SAFETY: generated union; Flags=0b111 enables the standard
            // ASLR triple without reserved bits.
            aslr.Anonymous.Flags = 0b111;
            // SAFETY: aslr is a valid generated struct alive for the call.
            let aslr_ok = unsafe {
                SetProcessMitigationPolicy(
                    ProcessASLRPolicy,
                    &aslr as *const _ as *const core::ffi::c_void,
                    std::mem::size_of::<PROCESS_MITIGATION_ASLR_POLICY>(),
                )
            };
            let mut aslr_q = PROCESS_MITIGATION_ASLR_POLICY {
                Anonymous: unsafe { std::mem::zeroed() },
            };
            let aslr_query_ok = unsafe {
                GetProcessMitigationPolicy(
                    windows_sys::Win32::System::Threading::GetCurrentProcess(),
                    ProcessASLRPolicy,
                    &mut aslr_q as *mut _ as *mut core::ffi::c_void,
                    std::mem::size_of::<PROCESS_MITIGATION_ASLR_POLICY>(),
                )
            };
            if aslr_ok == 0 {
                // SAFETY: reading the generated union Flags aliases the
                // bitfield storage written by the kernel query above.
                let already =
                    aslr_query_ok != 0 && unsafe { aslr_q.Anonymous.Flags } & 0b111 == 0b111;
                if already {
                    tracing::debug!("ASLR mitigation already enforced (setter no-op)");
                } else {
                    tracing::warn!("Failed to enable ASLR mitigation");
                }
            } else {
                tracing::debug!("ASLR mitigation enabled");
            }
            Ok(())
        }
    }

    impl SandboxBackend for WindowsSandbox {
        fn apply(
            &self,
            read_paths: &[&Path],
            write_paths: &[&Path],
            denied_paths: &[&Path],
        ) -> Result<(), SandboxError> {
            if self.applied.load(Ordering::SeqCst) {
                tracing::warn!("Windows sandbox already applied");
                return Ok(());
            }

            self.apply_job_object()?;

            if self.level == SandboxLevel::Strict {
                // Phase 81 Workstream F: no host-global DACL mutation here
                // (removed). Strict stays fail-closed for filesystem isolation
                // via with_paths' read-allowlist gate; mitigation hardening
                // below is process-local only.
                self.apply_mitigation_policies()?;
                let _ = (read_paths, write_paths, denied_paths);
            }

            self.applied.store(true, Ordering::SeqCst);

            tracing::info!(
                "Applied windows sandbox (level: {:?}) with {} read paths, {} write paths, {} denied paths",
                self.level,
                read_paths.len(),
                write_paths.len(),
                denied_paths.len()
            );

            Ok(())
        }

        fn is_supported(&self) -> bool {
            Self::is_supported()
        }

        fn feature_name(&self) -> &'static str {
            "windows-job-object"
        }

        fn level(&self) -> SandboxLevel {
            self.level
        }

        fn capabilities(&self) -> SandboxCapabilities {
            // Phase 46 truthfulness + Phase 81 Workstream F: no DACL-based
            // filesystem claims remain (DACL mutation removed from sandbox
            // semantics). There is no deny-by-default for the rest of the
            // filesystem, no network restriction, and no child-process
            // restriction from Job Objects as configured (active_process_limit
            // is 0 = unlimited). Only numeric process/job memory limits plus
            // kill-on-close are enforced, hence process_limits true and all
            // path flags false. Consequence: Strict (which requires a read
            // allowlist) fails closed on this backend by design; Basic gets
            // Job-Object limits only. Matches docs/SANDBOXING.md.
            SandboxCapabilities {
                read_path_allowlist: false,
                write_path_allowlist: false,
                deny_paths: false,
                process_limits: true,
                network_restrictions: false,
                child_process_restrictions: false,
            }
        }
    }
}

/// Phase 82: portable process-sandbox guarantee contract.
///
/// Replaces the platform-relative `SandboxLevel::Strict` capability
/// decision (`can_enforce_strict() == read_path_allowlist`) with explicit
/// required/optional guarantees and a machine-readable enforcement report.
/// Application-neutral: no root `synvoid`, config, mesh, metrics, or jail
/// protocol types leak into these policy types.
///
/// Lifecycle: validate policy/resource inputs → probe backend and lower
/// portable requirements → prepared plan + pre-entry projection (no
/// irreversible side effect) → establish inherited resources → `enter`
/// (single irreversible boundary) → owned `EnteredSandbox` witness → begin
/// untrusted workload.
///
/// Legacy `SandboxLevel`/`SandboxPaths`/`ProcessSandbox::new`/`with_paths`
/// remain as a narrow compatibility adapter over this mechanism (pinned
/// behavior; new production code must use the guarantee contract and must
/// not gate on `can_enforce_strict()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Guarantee {
    /// Ambient filesystem namespace denied/restricted (deny-by-default for
    /// handled classes).
    AmbientFilesystemDenied,
    /// Read allowlist enforced for the requested read roots.
    FilesystemReadAllowlist,
    /// Write allowlist enforced for the requested write roots.
    FilesystemWriteAllowlist,
    /// Explicit deny path enforced (distinct from allowlist absence).
    ExplicitDenyPath,
    /// Only inherited/preopened resources usable (no new ambient opens).
    InheritedResourcesOnly,
    /// Creation/use of new external network sockets denied.
    NetworkDenied,
    /// Outbound TCP restricted.
    NetworkTcpRestricted,
    /// Outbound UDP restricted.
    NetworkUdpRestricted,
    /// Inherited IPC descriptors (e.g. parent-created stdio pipes) remain usable.
    InheritedIpcUsable,
    /// Child process creation denied (distinct from inheritance).
    ChildCreationDenied,
    /// Exec / new-program execution denied.
    ExecDenied,
    /// Descendants inherit confinement (distinct from creation denial).
    DescendantsConfined,
    /// Process memory bound enforced.
    ProcessMemoryBound,
    /// Aggregate job/process-tree memory bound enforced.
    JobMemoryBound,
    /// Confinement ends/terminates with the owning supervisor/job handle.
    TerminatesWithOwner,
}

/// Enforcement thread/process scope (Phase 82 Workstream F).
///
/// Landlock before ABI 8 restricts the calling thread and descendants
/// without synchronizing sibling threads; newer Landlock can request
/// all-thread enforcement. A reusable API cannot assume the jail's
/// enter-before-threads ordering, so the scope is explicit and a caller
/// requiring all-current-thread enforcement fails when the backend cannot
/// provide it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ThreadScope {
    /// Current thread + future descendants (Landlock pre-ABI-8 semantics;
    /// sufficient for the jail's enter-before-workload-threads ordering).
    #[default]
    CurrentThreadPlusDescendants,
    /// All current threads + future descendants (Landlock ABI-8+
    /// all-threads, seccomp TSYNC where available and required).
    AllThreadsPlusDescendants,
    /// Process-tree / job containment (Windows Job Objects, pledge scope).
    ProcessTree,
}

/// Per-guarantee enforcement status (Phase 82 Workstream D).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuaranteeStatus {
    Enforced,
    Unsupported,
    /// Partially/degraded enforcement (never acceptable for a required
    /// guarantee in a successful `EnteredSandbox`).
    DegradedPartial,
    NotRequested,
}

/// One guarantee decision inside an enforcement report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuaranteeDecision {
    pub guarantee: Guarantee,
    pub status: GuaranteeStatus,
    /// Fixed mechanism identifier (no secret paths; suitable for metrics).
    pub mechanism: &'static str,
    /// Bounded human detail (version/host condition limiting the result).
    pub detail: String,
}

/// Immutable enforcement report (Phase 82 Workstream D).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementReport {
    pub backend: &'static str,
    pub abi: String,
    pub scope: ThreadScope,
    pub decisions: Vec<GuaranteeDecision>,
}

impl EnforcementReport {
    pub fn status_of(&self, guarantee: Guarantee) -> GuaranteeStatus {
        self.decisions
            .iter()
            .find(|d| d.guarantee == guarantee)
            .map(|d| d.status)
            .unwrap_or(GuaranteeStatus::NotRequested)
    }

    /// Fail-closed check: every required guarantee must be `Enforced`.
    /// Degraded/unsupported on a required path is always an error.
    pub fn require_all(&self, required: &[Guarantee]) -> Result<(), SandboxError> {
        for g in required {
            match self.status_of(*g) {
                GuaranteeStatus::Enforced => {}
                GuaranteeStatus::Unsupported => {
                    return Err(SandboxError::Unsupported(format!(
                        "backend '{}' cannot enforce required guarantee {g:?}",
                        self.backend
                    )));
                }
                GuaranteeStatus::DegradedPartial => {
                    return Err(SandboxError::PartialEnforcement(format!(
                        "backend '{}' partially enforces required guarantee {g:?}",
                        self.backend
                    )));
                }
                GuaranteeStatus::NotRequested => {
                    return Err(SandboxError::InvalidPolicy(format!(
                        "required guarantee {g:?} missing from {} report",
                        self.backend
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Application-neutral inherited/preopened resource description (Phase 82
/// Workstream G). Needed for Capsicum (descriptor capabilities) and for
/// documenting the jail's inherited stdin/stdout transport. Path-based
/// backends lower path policy directly while still reporting inherited
/// resources separately. No generic command-spawn API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceIntent {
    Read,
    Write,
    ReadWrite,
    Metadata,
    Ipc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreopenedResource {
    /// Fixed diagnostic identifier (never a secret path in metrics).
    pub name: String,
    pub intent: ResourceIntent,
}

impl PreopenedResource {
    pub fn new(name: impl Into<String>, intent: ResourceIntent) -> Self {
        Self {
            name: name.into(),
            intent,
        }
    }
}

/// Portable sandbox request: required guarantees abort before untrusted
/// work when unsupported/degraded; optional guarantees are opportunistic
/// and reported honestly (Phase 82 Workstream B).
#[derive(Debug, Clone, Default)]
pub struct SandboxRequest {
    pub required: Vec<Guarantee>,
    pub optional: Vec<Guarantee>,
    pub read_paths: Vec<std::path::PathBuf>,
    pub write_paths: Vec<std::path::PathBuf>,
    pub denied_paths: Vec<std::path::PathBuf>,
    pub scope: ThreadScope,
    pub resources: Vec<PreopenedResource>,
}

impl SandboxRequest {
    pub fn new() -> Self {
        Self {
            scope: ThreadScope::CurrentThreadPlusDescendants,
            ..Self::default()
        }
    }

    pub fn require(mut self, g: Guarantee) -> Self {
        if !self.required.contains(&g) {
            self.required.push(g);
        }
        self
    }

    pub fn optional(mut self, g: Guarantee) -> Self {
        if !self.optional.contains(&g) && !self.required.contains(&g) {
            self.optional.push(g);
        }
        self
    }

    pub fn read_path(mut self, p: impl Into<std::path::PathBuf>) -> Self {
        self.read_paths.push(p.into());
        self
    }

    pub fn write_path(mut self, p: impl Into<std::path::PathBuf>) -> Self {
        self.write_paths.push(p.into());
        self
    }

    pub fn deny_path(mut self, p: impl Into<std::path::PathBuf>) -> Self {
        self.denied_paths.push(p.into());
        self
    }

    pub fn scope(mut self, scope: ThreadScope) -> Self {
        self.scope = scope;
        self
    }

    pub fn resource(mut self, r: PreopenedResource) -> Self {
        self.resources.push(r);
        self
    }

    /// Validate policy/resource inputs (no irreversible side effect).
    /// Conflicting allow/deny entries and empty-path inputs are rejected
    /// here, before any backend probing.
    pub fn validate(&self) -> Result<(), SandboxError> {
        for p in self
            .read_paths
            .iter()
            .chain(self.write_paths.iter())
            .chain(self.denied_paths.iter())
        {
            if p.as_os_str().is_empty() {
                return Err(SandboxError::InvalidPolicy("empty sandbox path".into()));
            }
        }
        // Conflicting allow/deny policy narrows nothing: reject denoys
        // that equal an allowed root (explicit deny under an allowed
        // Landlock ancestor cannot be represented — fail at validation so
        // composition only narrows guarantee sets.
        for denied in &self.denied_paths {
            if self.read_paths.iter().any(|a| a == denied)
                || self.write_paths.iter().any(|a| a == denied)
            {
                return Err(SandboxError::InvalidPolicy(format!(
                    "conflicting allow/deny policy for {}",
                    denied.display()
                )));
            }
        }
        Ok(())
    }

    /// Guarantee sets only narrow when composed/intersected.
    pub fn intersect(&self, other: &SandboxRequest) -> SandboxRequest {
        let required = self
            .required
            .iter()
            .filter(|g| other.required.contains(g))
            .copied()
            .collect();
        let optional = self
            .optional
            .iter()
            .chain(other.optional.iter())
            .filter(|g| !self.required.contains(g) && !other.required.contains(g))
            .copied()
            .collect::<Vec<_>>();
        SandboxRequest {
            required,
            optional,
            read_paths: self.read_paths.clone(),
            write_paths: self.write_paths.clone(),
            denied_paths: self.denied_paths.clone(),
            scope: self.scope,
            resources: self.resources.clone(),
        }
    }
}

/// Prepared (pre-entry) sandbox plan: policy validated, backend probed,
/// enforcement projected. Preparation has no irreversible host/process
/// side effect; `enter` is the single irreversible boundary (Phase 82
/// Workstream C).
#[derive(Debug, Clone)]
pub struct PreparedSandbox {
    pub backend: &'static str,
    pub projection: EnforcementReport,
    request: SandboxRequest,
}

impl PreparedSandbox {
    pub fn projection(&self) -> &EnforcementReport {
        &self.projection
    }

    pub fn request(&self) -> &SandboxRequest {
        &self.request
    }

    /// Irreversible entry: applies the backend mechanism for the requested
    /// paths, re-checks the final report, and returns the owned witness.
    /// Required-guarantee failures abort before untrusted work.
    pub fn enter(self) -> Result<EnteredSandbox, SandboxError> {
        // Re-verify the projection fail-closed before touching the backend.
        self.projection.require_all(&self.request.required)?;
        // Legacy adapter path: the calibrated backend `apply` for this
        // platform. (Long-lived jails retain the returned witness through
        // the serve loop; see sandbox_entry.rs.)
        let read_refs: Vec<&Path> = self
            .request
            .read_paths
            .iter()
            .map(|p| p.as_path())
            .collect();
        let write_refs: Vec<&Path> = self
            .request
            .write_paths
            .iter()
            .map(|p| p.as_path())
            .collect();
        let denied_refs: Vec<&Path> = self
            .request
            .denied_paths
            .iter()
            .map(|p| p.as_path())
            .collect();
        // Level is advisory here; the guarantee report is authoritative.
        // Use Basic to avoid re-triggering the legacy Strict gate inside
        // apply (the required-guarantee check above already enforced it).
        let sandbox = ProcessSandbox::new(SandboxLevel::Basic);
        sandbox
            .backend
            .apply(&read_refs, &write_refs, &denied_refs)?;
        // Post-entry: required guarantees must still hold (a backend that
        // reports partial after entry fails closed here).
        let final_report = project_report_for_current_backend(&self.request, self.request.scope);
        final_report.require_all(&self.request.required)?;
        Ok(EnteredSandbox {
            report: final_report,
            _sandbox: sandbox,
        })
    }
}

/// Owned entered-sandbox witness (Phase 82 Workstream E).
///
/// 1. Typed evidence that the irreversible transition succeeded (holds the
///    final `EnforcementReport`; a required guarantee is never
///    degraded/unsupported inside a live witness).
/// 2. Ownership of backend state that must live as long as confinement
///    (via the retained `ProcessSandbox`, notably the Windows Job handle).
///
/// Non-cloneable by design. Dropping the token does not silently remove
/// restrictions where restriction is irreversible (Landlock/seccomp,
/// Capsicum, pledge): those remain. Where a handle controls
/// lifetime/kill-on-close (Windows Job), dropping closes the last handle
/// and terminates the job — documented loud semantics; retain through the
/// serve loop. Long-lived jails must not create this in a helper and
/// discard it before processing work.
pub struct EnteredSandbox {
    report: EnforcementReport,
    _sandbox: ProcessSandbox,
}

impl EnteredSandbox {
    pub fn report(&self) -> &EnforcementReport {
        &self.report
    }

    /// Test/fake-backend constructor: builds a witness from an explicit
    /// report without touching a real backend. Required guarantees must be
    /// enforced in the supplied report (fail-closed otherwise). Production
    /// `enter` never uses this path.
    pub fn from_test_report(report: EnforcementReport) -> Result<Self, SandboxError> {
        let required: Vec<Guarantee> = report
            .decisions
            .iter()
            .filter(|d| d.status == GuaranteeStatus::Enforced)
            .map(|d| d.guarantee)
            .collect();
        // An empty witness evidences nothing: reject it (a caller that
        // "succeeds" with zero enforced guarantees has a silent-downgrade
        // bug, not a sandbox).
        if required.is_empty() {
            return Err(SandboxError::InvalidPolicy(
                "test witness requires at least one enforced guarantee".into(),
            ));
        }
        report.require_all(&required)?;
        Ok(Self {
            report,
            _sandbox: ProcessSandbox::with_stub(SandboxLevel::Basic),
        })
    }
}

/// Probe the current backend and lower portable requirements into a
/// prepared plan + pre-entry projection (no side effects).
pub fn prepare_sandbox(request: SandboxRequest) -> Result<PreparedSandbox, SandboxError> {
    request.validate()?;
    let backend = current_backend_name();
    let projection = project_report_for_current_backend(&request, request.scope);
    // Backend selection produces a typed unsupported/degraded reason via
    // the projection + require_all at enter; preparation itself never
    // silently lowers a required guarantee (it only projects honestly).
    Ok(PreparedSandbox {
        backend,
        projection,
        request,
    })
}

fn current_backend_name() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "landlock"
    }
    #[cfg(target_os = "freebsd")]
    {
        "capsicum"
    }
    #[cfg(target_os = "openbsd")]
    {
        "pledge"
    }
    #[cfg(target_os = "windows")]
    {
        "windows-job-object"
    }
    #[cfg(target_os = "macos")]
    {
        "seatbelt"
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "windows",
        target_os = "macos"
    )))]
    {
        "stub"
    }
}

/// Project the enforcement report for the current backend WITHOUT applying
/// anything (pure projection for prepare/enter pre-checks and tests).
fn project_report_for_current_backend(
    request: &SandboxRequest,
    scope: ThreadScope,
) -> EnforcementReport {
    project_report_for_backend(current_backend_name(), request, scope)
}

/// Portable syscall-filter projection hook (Phase 83).
///
/// On Linux reports whether the categorical seccomp jail filter compiles
/// for this arch (pure check, no install). Elsewhere always false: no
/// other backend supplies syscall-filter guarantees in this campaign.
#[cfg(target_os = "linux")]
fn syscall_filter_projected() -> bool {
    linux::seccomp::projected_enforcement()
}
#[cfg(not(target_os = "linux"))]
fn syscall_filter_projected() -> bool {
    false
}

/// Backend guarantee mapping (single source of truth for docs + code;
/// Phase 84 Workstream A generates the matrix from this vocabulary).
/// Distinguishes child-creation denial from descendant confinement, and
/// resource limits from access-control guarantees. Resource limits are
/// never presented as access-control isolation.
fn project_report_for_backend(
    backend: &'static str,
    request: &SandboxRequest,
    scope: ThreadScope,
) -> EnforcementReport {
    use Guarantee::*;
    // All guarantees in vocabulary order; each backend marks Enforced /
    // Unsupported / DegradedPartial; unrequested ones stay NotRequested.
    let all = [
        AmbientFilesystemDenied,
        FilesystemReadAllowlist,
        FilesystemWriteAllowlist,
        ExplicitDenyPath,
        InheritedResourcesOnly,
        NetworkDenied,
        NetworkTcpRestricted,
        NetworkUdpRestricted,
        InheritedIpcUsable,
        ChildCreationDenied,
        ExecDenied,
        DescendantsConfined,
        ProcessMemoryBound,
        JobMemoryBound,
        TerminatesWithOwner,
    ];
    let mut decisions = Vec::with_capacity(all.len());
    for g in all {
        let (status, mechanism, detail) = match (backend, g) {
            // ── Landlock (Linux): ambient FS + path allowlists; explicit
            // deny unsupported (fail-closed in apply); network/child/exec
            // unsupported until the Phase 83 syscall-filter qualifies them;
            // descendants inherit the domain; no numeric memory bounds.
            ("landlock", AmbientFilesystemDenied) => (
                GuaranteeStatus::Enforced,
                "landlock-ruleset",
                "deny-by-default for handled FS classes (abi-v1-vetted)".to_string(),
            ),
            ("landlock", FilesystemReadAllowlist) => (
                GuaranteeStatus::Enforced,
                "landlock-ruleset",
                "read rules for read roots".to_string(),
            ),
            ("landlock", FilesystemWriteAllowlist) => (
                GuaranteeStatus::Enforced,
                "landlock-ruleset",
                "read+write rules for write roots".to_string(),
            ),
            ("landlock", ExplicitDenyPath) => (
                GuaranteeStatus::Unsupported,
                "landlock-ruleset",
                "no explicit deny primitive; deny under allowed ancestor unrepresentable".to_string(),
            ),
            ("landlock", InheritedResourcesOnly) => (
                GuaranteeStatus::Enforced,
                "landlock-fd-inheritance",
                "pre-existing fds remain usable; new ambient opens denied".to_string(),
            ),
            ("landlock", InheritedIpcUsable) => (
                GuaranteeStatus::Enforced,
                "landlock-fd-inheritance",
                "parent-created stdio pipes pre-date entry".to_string(),
            ),
            ("landlock", DescendantsConfined) => (
                GuaranteeStatus::Enforced,
                "landlock-inherit",
                "domain inherited by descendants; scope per ThreadScope".to_string(),
            ),
            ("landlock", NetworkDenied)
            | ("landlock", NetworkTcpRestricted)
            | ("landlock", NetworkUdpRestricted)
            | ("landlock", ChildCreationDenied)
            | ("landlock", ExecDenied) => {
                // Phase 83: supplied by the categorical seccomp layer where
                // it compiles/installs (verified post-entry by fail-closed
                // install in apply); otherwise honestly unsupported.
                if syscall_filter_projected() {
                    (
                        GuaranteeStatus::Enforced,
                        "seccomp-errno",
                        "categorical deny (socket/connect, non-thread clone, exec); EPERM/ENOSYS-clone3, tsync"
                            .to_string(),
                    )
                } else {
                    (
                        GuaranteeStatus::Unsupported,
                        "landlock-ruleset",
                        "filesystem LSM only; syscall-filter unavailable on this host"
                            .to_string(),
                    )
                }
            }
            ("landlock", ProcessMemoryBound)
            | ("landlock", JobMemoryBound)
            | ("landlock", TerminatesWithOwner) => (
                GuaranteeStatus::Unsupported,
                "landlock-ruleset",
                "resource/lifecycle is not filesystem access control".to_string(),
            ),
            // ── Capsicum (FreeBSD): descriptor-capability mode; path
            // vectors are NOT allowlists (preopen required — Phase 83);
            // descendants inherit capability mode (not child-denial).
            ("capsicum", AmbientFilesystemDenied) => (
                GuaranteeStatus::Enforced,
                "capsicum-cap-mode",
                "global namespaces denied after cap_enter".to_string(),
            ),
            ("capsicum", InheritedResourcesOnly) => (
                GuaranteeStatus::Enforced,
                "capsicum-descriptors",
                "retained descriptors usable; new global opens denied".to_string(),
            ),
            ("capsicum", InheritedIpcUsable) => (
                GuaranteeStatus::Enforced,
                "capsicum-descriptors",
                "rights-limited stdio retained".to_string(),
            ),
            ("capsicum", DescendantsConfined) => (
                GuaranteeStatus::Enforced,
                "capsicum-inherit",
                "forked descendants remain in capability mode".to_string(),
            ),
            ("capsicum", FilesystemReadAllowlist)
            | ("capsicum", FilesystemWriteAllowlist)
            | ("capsicum", ExplicitDenyPath) => (
                GuaranteeStatus::Unsupported,
                "capsicum-cap-mode",
                "pathname vectors are not Capsicum allowlists; preopened directory capabilities required"
                    .to_string(),
            ),
            ("capsicum", ChildCreationDenied) | ("capsicum", ExecDenied) => (
                GuaranteeStatus::Unsupported,
                "capsicum-cap-mode",
                "capability mode confines descendants; it does not deny child creation/exec"
                    .to_string(),
            ),
            ("capsicum", NetworkDenied)
            | ("capsicum", NetworkTcpRestricted)
            | ("capsicum", NetworkUdpRestricted) => (
                GuaranteeStatus::Enforced,
                "capsicum-cap-mode",
                "new global network endpoints/namespaces denied; retained descriptors usable"
                    .to_string(),
            ),
            ("capsicum", ProcessMemoryBound)
            | ("capsicum", JobMemoryBound)
            | ("capsicum", TerminatesWithOwner) => (
                GuaranteeStatus::Unsupported,
                "capsicum-cap-mode",
                "capability confinement is not a numeric resource bound".to_string(),
            ),
            // ── Pledge/Unveil (OpenBSD): path allowlists + empty-perm
            // denies; stdio pledge denies inet/proc/exec; unveil locked.
            ("pledge", AmbientFilesystemDenied)
            | ("pledge", FilesystemReadAllowlist)
            | ("pledge", FilesystemWriteAllowlist)
            | ("pledge", ExplicitDenyPath)
            | ("pledge", NetworkDenied)
            | ("pledge", NetworkTcpRestricted)
            | ("pledge", NetworkUdpRestricted)
            | ("pledge", ChildCreationDenied)
            | ("pledge", ExecDenied)
            | ("pledge", DescendantsConfined) => (
                GuaranteeStatus::Enforced,
                "pledge-unveil",
                "unveil view (locked) + stdio pledge (omits inet/proc/exec)".to_string(),
            ),
            ("pledge", InheritedResourcesOnly) | ("pledge", InheritedIpcUsable) => (
                GuaranteeStatus::Enforced,
                "pledge-unveil",
                "inherited stdio pre-dates unveil lock + pledge".to_string(),
            ),
            ("pledge", ProcessMemoryBound)
            | ("pledge", JobMemoryBound)
            | ("pledge", TerminatesWithOwner) => (
                GuaranteeStatus::Unsupported,
                "pledge-unveil",
                "syscall filtering is not a numeric resource bound".to_string(),
            ),
            // ── Seatbelt (macOS): existing strict profile mapped without
            // redesign (Phase 83 F); exec denial NOT proven (process*
            // retained) → Unsupported; no numeric memory bound.
            ("seatbelt", AmbientFilesystemDenied)
            | ("seatbelt", FilesystemReadAllowlist)
            | ("seatbelt", FilesystemWriteAllowlist)
            | ("seatbelt", ExplicitDenyPath)
            | ("seatbelt", NetworkDenied)
            | ("seatbelt", ChildCreationDenied)
            | ("seatbelt", DescendantsConfined) => (
                GuaranteeStatus::Enforced,
                "seatbelt-strict-profile",
                "deny-default + explicit file/network rules, no job-creation allow (experimental/deprecated sandbox_init)"
                    .to_string(),
            ),
            ("seatbelt", NetworkTcpRestricted) | ("seatbelt", NetworkUdpRestricted) => (
                GuaranteeStatus::Enforced,
                "seatbelt-strict-profile",
                "deny network* covers TCP+UDP".to_string(),
            ),
            ("seatbelt", InheritedIpcUsable) | ("seatbelt", InheritedResourcesOnly) => (
                GuaranteeStatus::Enforced,
                "seatbelt-strict-profile",
                "inherited stdio pre-dates profile install".to_string(),
            ),
            ("seatbelt", ExecDenied) => (
                GuaranteeStatus::Unsupported,
                "seatbelt-strict-profile",
                "allow process* lifecycle primitive retained; exec denial not proven"
                    .to_string(),
            ),
            ("seatbelt", ProcessMemoryBound)
            | ("seatbelt", JobMemoryBound)
            | ("seatbelt", TerminatesWithOwner) => (
                GuaranteeStatus::Unsupported,
                "seatbelt-strict-profile",
                "SBPL sets no numeric resource bounds".to_string(),
            ),
            // ── Windows Job Objects: resource/lifecycle containment only.
            // Access-control guarantees unsupported (fail closed; Phase 83
            // gate decides on a dedicated launch backend separately).
            ("windows-job-object", ProcessMemoryBound)
            | ("windows-job-object", JobMemoryBound)
            | ("windows-job-object", TerminatesWithOwner) => (
                GuaranteeStatus::Enforced,
                "windows-job-object",
                "256MiB proc / 512MiB job / kill-on-close (verified query-back)".to_string(),
            ),
            ("windows-job-object", _) => (
                GuaranteeStatus::Unsupported,
                "windows-job-object",
                "job objects constrain a process tree; not an access-control sandbox"
                    .to_string(),
            ),
            // ── Stub / unknown: everything unsupported.
            _ => (
                GuaranteeStatus::Unsupported,
                "stub",
                "no OS enforcement on this platform".to_string(),
            ),
        };
        let requested = request.required.contains(&g) || request.optional.contains(&g);
        decisions.push(GuaranteeDecision {
            guarantee: g,
            status: if requested {
                status
            } else {
                GuaranteeStatus::NotRequested
            },
            mechanism,
            detail,
        });
    }
    // Scope truth: Landlock pre-ABI-8 cannot provide all-threads; if the
    // caller requires it on an incapable backend the projection marks the
    // scope-dependent guarantees degraded (fail-closed at require_all).
    // For now the scope is recorded honestly; all-threads enforcement is
    // supplied by the Phase 83 seccomp TSYNC / Landlock ABI-8 path where
    // available, otherwise the caller must run single-threaded-at-entry
    // (the jail invariant) or fail.
    let abi = match backend {
        "landlock" => {
            #[cfg(target_os = "linux")]
            {
                linux::LandlockSandbox::backend_abi_description().to_string()
            }
            #[cfg(not(target_os = "linux"))]
            {
                "landlock/abi-v1-vetted (crate ABI-9 surface)".to_string()
            }
        }
        "capsicum" => "capsicum/cap_enter".to_string(),
        "pledge" => "pledge-stdio/unveil-locked".to_string(),
        "seatbelt" => "seatbelt/sandbox_init-deprecated".to_string(),
        "windows-job-object" => "jobobject/class-9-verified".to_string(),
        _ => "none".to_string(),
    };
    EnforcementReport {
        backend,
        abi,
        scope,
        decisions,
    }
}

/// Jail guarantee policy (Phase 82 Workstream I): requirements derived
/// from actual workload needs (inherited stdio IPC; modules/rules arrive
/// over IPC; no new network authority; no child programs), not from the
/// old word "Strict". Missing desired guarantees stay explicit
/// unsupported findings (Phase 83 work); if the current backend cannot
/// supply the minimum security boundary, required jail routing stays
/// fail-closed until Phase 83 supplies it.
pub fn jail_guarantee_request() -> SandboxRequest {
    SandboxRequest::new()
        .require(Guarantee::AmbientFilesystemDenied)
        .require(Guarantee::FilesystemReadAllowlist)
        .require(Guarantee::InheritedIpcUsable)
        .require(Guarantee::DescendantsConfined)
        .scope(ThreadScope::CurrentThreadPlusDescendants)
        .resource(PreopenedResource::new("stdin-ipc", ResourceIntent::Ipc))
        .resource(PreopenedResource::new("stdout-ipc", ResourceIntent::Ipc))
        .resource(PreopenedResource::new("stderr-log", ResourceIntent::Write))
}

/// Legacy compatibility: the old `SandboxLevel::Strict` gate expressed as
/// a guarantee check (adapter, not a new security decision). Pinned
/// behavior: Strict requires a read allowlist-capable backend.
pub fn legacy_strict_satisfied_by(report: &EnforcementReport) -> bool {
    report.status_of(Guarantee::FilesystemReadAllowlist) == GuaranteeStatus::Enforced
}

/// Phase 83 Workstream H: inherited-resource hygiene audit (Unix).
///
/// Returns fds >= 3 open at call time (unexpected for a jail child whose
/// only legitimate inheritance is stdin/stdout/stderr IPC+log). The jail
/// entry logs these at warn (fd numbers only, never content/paths) so a
/// leaked listener/admin/mesh/config/secret handle cannot enter silently.
/// No CLOEXEC/close side effects here (the caller owns lifecycle); Capsicum
/// closes >= 3 via closefrom at entry, Landlock/seccomp rely on this audit
/// plus fd-inheritance reporting. Windows handle inheritance is explicit at
/// spawn time (stdio pipes only; see the closeout).
///
/// Portable: iterates 3..1024 with F_GETFD (works on Linux/macOS/BSDs
/// without /proc). For huge fd tables this is bounded and fast enough at
/// jail startup (one-time, before untrusted work).
#[cfg(unix)]
pub fn audit_inherited_fds() -> Vec<i32> {
    let mut unexpected = Vec::new();
    for fd in 3..1024 {
        // SAFETY: fcntl(F_GETFD) on a possibly-closed fd is side-effect
        // free; it returns -1 with EBADF for closed fds, flags otherwise.
        // No pointer, no ownership change.
        let r = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if r >= 0 {
            unexpected.push(fd);
        }
    }
    unexpected
}

/// SBPL profile builder shared by the macOS backend and unit tests.
///
/// Compiled on macOS (production caller) and under `test` on all platforms
/// so Linux CI can verify profile structure without a macOS host. The macOS
/// backend (`darwin`, below) is the only production caller; native
/// enforcement evidence comes from the macOS child-process tests, not from
/// these string assertions alone.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn compile_sbpl_profile(
    read_paths: &[&Path],
    write_paths: &[&Path],
    denied_paths: &[&Path],
    level: SandboxLevel,
) -> Result<String, SandboxError> {
    let mut profile = String::new();
    profile.push_str("(version 1)\n");

    // Phase 46 (Workstream C): explicit, non-contradictory defaults.
    //
    // Basic = permissive: allow-by-default; only `denied_paths` are blocked.
    // Read/write lists are emitted as explicit allows for documentation but
    // do not restrict (allow default permits everything else). No network /
    // child / resource limits are claimed in Basic.
    //
    // Strict = restrictive jail policy: deny-by-default; explicit file
    // allows for the caller-provided allowlists; explicit denies for
    // `denied_paths`; explicit `(deny network*)` so the network claim does
    // not rest on an assumed `deny default` reading; NO `(allow
    // job-creation)` so child-process creation stays denied by default
    // (jail helpers must not spawn children). `(allow process*)` +
    // `(allow signal)` are retained as the minimal lifecycle primitives for
    // the WASM/YARA jail loop; narrowing them further requires native proof
    // the jail still runs (documented experimental, see docs/SANDBOXING.md).
    //
    // Seatbelt `default` is a fallback: explicit file/network rules override
    // it for matching operations. Explicit denies are emitted after allows
    // so overlapping configuration reads as denied in the profile text;
    // callers must keep allow/deny lists disjoint. Operation wildcards
    // (`process*`, `file-read*`, `network*`) are required: bare `process`
    // is an unbound variable (proven by native sandbox_init failure).
    match level {
        SandboxLevel::Basic => {
            profile.push_str("(allow default)\n");
        }
        SandboxLevel::Strict => {
            profile.push_str("(deny default)\n");
            profile.push_str("(allow process*)\n");
            profile.push_str("(allow signal)\n");
            profile.push_str("(deny network*)\n");
        }
        SandboxLevel::Off => {
            profile.push_str("(allow default)\n");
            return Ok(profile);
        }
    }

    for path in read_paths {
        let canon = canonicalize_sbpl_path(path);
        let lit = escape_sbpl_string_literal(&canon)?;
        profile.push_str(&format!("(allow file-read* (subpath \"{lit}\"))\n"));
    }

    for path in write_paths {
        let canon = canonicalize_sbpl_path(path);
        let lit = escape_sbpl_string_literal(&canon)?;
        profile.push_str(&format!("(allow file-read* (subpath \"{lit}\"))\n"));
        profile.push_str(&format!("(allow file-write* (subpath \"{lit}\"))\n"));
    }

    for path in denied_paths {
        let canon = canonicalize_sbpl_path(path);
        let lit = escape_sbpl_string_literal(&canon)?;
        profile.push_str(&format!("(deny file-read* (subpath \"{lit}\"))\n"));
        profile.push_str(&format!("(deny file-write* (subpath \"{lit}\"))\n"));
    }

    Ok(profile)
}

#[cfg(target_os = "macos")]
pub mod darwin {
    use super::{
        compile_sbpl_profile, SandboxBackend, SandboxCapabilities, SandboxError, SandboxLevel,
    };
    use std::path::Path;

    /// macOS Seatbelt backend (Phase 46: experimental, deprecated API).
    ///
    /// Uses the deprecated `sandbox_init` CLI/jail interface, NOT Apple App
    /// Sandbox entitlements. Requires the `macos-sandbox` Cargo feature at
    /// compile time AND a runtime `sandbox_init` symbol (probed via `dlsym`).
    /// "Compiled with feature" != "runtime backend available": `capabilities`
    /// describes compiled-in enforcement potential; `is_supported` is the
    /// runtime gate; `apply` fails closed when the runtime is absent.
    /// Linux remains the production recommendation for strict isolation.
    pub struct SeatbeltSandbox {
        level: SandboxLevel,
    }

    impl SeatbeltSandbox {
        pub fn new(level: SandboxLevel) -> Self {
            Self { level }
        }

        fn is_supported() -> bool {
            #[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
            {
                use libc::dlsym;

                // SAFETY: dlsym with RTLD_DEFAULT and a static C-string
                // literal; returns a possibly-null symbol address, no
                // ownership transfer, no dereference.
                let sym = unsafe { dlsym(libc::RTLD_DEFAULT, c"sandbox_init".as_ptr().cast()) };
                !sym.is_null()
            }
            #[cfg(not(all(target_os = "macos", feature = "macos-sandbox")))]
            {
                false
            }
        }

        fn compile_sandbox_profile(
            read_paths: &[&Path],
            write_paths: &[&Path],
            denied_paths: &[&Path],
            level: SandboxLevel,
        ) -> Result<String, SandboxError> {
            compile_sbpl_profile(read_paths, write_paths, denied_paths, level)
        }

        fn apply_sandbox_impl(&self, profile: &str) -> Result<(), SandboxError> {
            #[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
            {
                use std::ffi::CStr;

                if !Self::is_supported() {
                    tracing::warn!(
                        "macOS Seatbelt sandbox not available at runtime. \
                         OS-level sandboxing is not active."
                    );
                    return Err(SandboxError::NotSupported("Seatbelt not available".into()));
                }

                let profile_with_nul = format!("{profile}\0");
                let profile_cstr = CStr::from_bytes_with_nul(profile_with_nul.as_bytes())
                    .map_err(|_| SandboxError::Syscall("Invalid sandbox profile".into()))?;

                #[link(name = "sandbox")]
                extern "C" {
                    fn sandbox_init(
                        profile: *const libc::c_char,
                        flags: libc::c_int,
                        error: *mut *mut libc::c_char,
                    ) -> libc::c_int;
                    fn sandbox_free_error(error: *mut libc::c_char);
                }

                // SAFETY: profile_cstr is a valid NUL-terminated string alive
                // for the call; flags=0 requests no options; errorbuf points
                // to a stack `*mut c_char` initialized to null. On failure the
                // API writes a malloc'd message we must free with
                // sandbox_free_error exactly once; on success the buffer is
                // untouched. No other pointer is retained after return.
                let mut errorbuf: *mut libc::c_char = std::ptr::null_mut();
                let result = unsafe {
                    sandbox_init(
                        profile_cstr.as_ptr(),
                        0,
                        &mut errorbuf as *mut *mut libc::c_char,
                    )
                };

                if result != 0 {
                    // SAFETY: errorbuf is either null (no API message — fall
                    // back to errno) or a valid NUL-terminated malloc'd
                    // string owned by us; convert then free exactly once.
                    let err_msg = unsafe {
                        if errorbuf.is_null() {
                            std::io::Error::last_os_error().to_string()
                        } else {
                            let msg = CStr::from_ptr(errorbuf).to_string_lossy().into_owned();
                            sandbox_free_error(errorbuf);
                            msg
                        }
                    };
                    return Err(SandboxError::Syscall(format!(
                        "sandbox_init failed: {err_msg}"
                    )));
                }

                Ok(())
            }

            #[cfg(not(all(target_os = "macos", feature = "macos-sandbox")))]
            {
                let _ = profile;
                tracing::warn!(
                    "macOS seatbelt sandbox compiled but disabled - enable 'macos-sandbox' feature for actual enforcement"
                );
                Err(SandboxError::NotSupported(
                    "Seatbelt sandbox disabled".into(),
                ))
            }
        }

        fn apply_sandbox(&self, profile: &str) -> Result<(), SandboxError> {
            self.apply_sandbox_impl(profile)
        }
    }

    impl SandboxBackend for SeatbeltSandbox {
        fn apply(
            &self,
            read_paths: &[&Path],
            write_paths: &[&Path],
            denied_paths: &[&Path],
        ) -> Result<(), SandboxError> {
            if self.level == SandboxLevel::Off {
                return Ok(());
            }

            let profile =
                Self::compile_sandbox_profile(read_paths, write_paths, denied_paths, self.level)?;

            self.apply_sandbox(&profile)?;

            tracing::info!(
                "Applied seatbelt sandbox (level: {:?}) with {} read paths, {} write paths, {} denied paths",
                self.level,
                read_paths.len(),
                write_paths.len(),
                denied_paths.len()
            );

            Ok(())
        }

        fn is_supported(&self) -> bool {
            Self::is_supported()
        }

        fn feature_name(&self) -> &'static str {
            "seatbelt"
        }

        fn level(&self) -> SandboxLevel {
            self.level
        }

        fn capabilities(&self) -> SandboxCapabilities {
            #[cfg(feature = "macos-sandbox")]
            {
                // Phase 46 truthfulness (Workstream C/G): level-dependent.
                // Basic is allow-default (no network/child limits claimed).
                // Strict denies network explicitly and denies spawn by
                // omitting job-creation. `process_limits` is numeric bounds
                // only — SBPL sets none, so always false.
                match self.level {
                    SandboxLevel::Strict => SandboxCapabilities {
                        read_path_allowlist: true,
                        write_path_allowlist: true,
                        deny_paths: true,
                        process_limits: false,
                        network_restrictions: true,
                        child_process_restrictions: true,
                    },
                    SandboxLevel::Basic => SandboxCapabilities {
                        read_path_allowlist: true,
                        write_path_allowlist: true,
                        deny_paths: true,
                        process_limits: false,
                        network_restrictions: false,
                        child_process_restrictions: false,
                    },
                    SandboxLevel::Off => SandboxCapabilities {
                        read_path_allowlist: false,
                        write_path_allowlist: false,
                        deny_paths: false,
                        process_limits: false,
                        network_restrictions: false,
                        child_process_restrictions: false,
                    },
                }
            }
            #[cfg(not(feature = "macos-sandbox"))]
            {
                SandboxCapabilities {
                    read_path_allowlist: false,
                    write_path_allowlist: false,
                    deny_paths: false,
                    process_limits: false,
                    network_restrictions: false,
                    child_process_restrictions: false,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_strict_sandbox_fails_on_stub_backend() {
        let stub = StubSandbox::new(SandboxLevel::Basic, "test-stub");
        let caps = stub.capabilities();
        assert!(!caps.can_enforce_strict());

        let sandbox = ProcessSandbox::with_stub(SandboxLevel::Strict);
        let caps = sandbox.capabilities();
        assert!(
            !caps.can_enforce_strict(),
            "stub backend should not support strict"
        );
    }

    #[test]
    fn test_strict_sandbox_fails_on_insufficient_capabilities() {
        let level = SandboxLevel::Strict;
        let sandbox = ProcessSandbox::new(level);

        let caps = sandbox.capabilities();
        if !caps.can_enforce_strict() {
            let result = sandbox.backend.capabilities().can_enforce_strict();
            assert!(!result, "stub backend should not support strict");
        }
    }

    #[test]
    fn test_sandbox_off_always_succeeds() {
        let result = ProcessSandbox::with_paths(SandboxLevel::Off, SandboxPaths::new());
        assert!(result.is_ok());
    }

    #[test]
    fn test_basic_sandbox_succeeds_with_stub() {
        let sandbox = ProcessSandbox::with_stub(SandboxLevel::Basic);
        assert_eq!(sandbox.level(), SandboxLevel::Basic);
        assert!(!sandbox.capabilities().can_enforce_strict());
    }

    // Phase 46 (Workstream B): SBPL literal escaping. A path value must
    // never gain an extra SBPL expression.
    #[test]
    fn test_sbpl_escape_plain_and_unicode() {
        assert_eq!(
            escape_sbpl_string_literal(Path::new("/usr/lib")).unwrap(),
            "/usr/lib"
        );
        assert_eq!(
            escape_sbpl_string_literal(Path::new("/tmp/ünicode-日本語")).unwrap(),
            "/tmp/ünicode-日本語"
        );
    }

    #[test]
    fn test_sbpl_escape_quote_and_backslash() {
        assert_eq!(
            escape_sbpl_string_literal(Path::new("/tmp/a\"b")).unwrap(),
            "/tmp/a\\\"b"
        );
        assert_eq!(
            escape_sbpl_string_literal(Path::new("/tmp/a\\b")).unwrap(),
            "/tmp/a\\\\b"
        );
    }

    #[test]
    fn test_sbpl_escape_closing_paren_stays_inside_literal() {
        // A `)` inside a quoted literal must not terminate the expression:
        // the escaped literal stays on one line with balanced quotes.
        let lit = escape_sbpl_string_literal(Path::new("/tmp/a)b")).unwrap();
        assert_eq!(lit, "/tmp/a)b");
        let profile =
            compile_sbpl_profile(&[Path::new("/tmp/a)b")], &[], &[], SandboxLevel::Strict);
        // Canonicalization falls back to the original when the path does not
        // exist; the literal must still appear quoted exactly once.
        if let Ok(profile) = profile {
            assert_eq!(profile.matches("(allow file-read*").count(), 1);
            assert!(profile.contains("(subpath \"/tmp/a)b\")"));
        }
    }

    #[test]
    fn test_sbpl_rejects_newline_and_controls() {
        assert!(escape_sbpl_string_literal(Path::new("/tmp/a\nb")).is_err());
        assert!(escape_sbpl_string_literal(Path::new("/tmp/a\rb")).is_err());
        assert!(escape_sbpl_string_literal(Path::new("/tmp/a\tb")).is_err());
        assert!(escape_sbpl_string_literal(Path::new("/tmp/a\x7fb")).is_err());
        assert!(escape_sbpl_string_literal(Path::new("")).is_err());
    }

    #[test]
    fn test_sbpl_rejects_semicolon_paren_injection_shape() {
        // Even though `)`/`;` inside quotes are inert, a profile built from
        // an adversarial path must remain a fixed number of expressions:
        // version + defaults + file rules, one rule per line, no extra lines
        // smuggled via the path value.
        let evil = "/tmp/evil\"))\n(allow file-write* (subpath \"/\"";
        assert!(escape_sbpl_string_literal(Path::new(evil)).is_err());
    }

    #[test]
    fn test_sbpl_canonicalizes_symlink() {
        let dir = tempfile::TempDir::new().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, dir.path().join("link")).unwrap();
        #[cfg(unix)]
        {
            let canon = canonicalize_sbpl_path(&dir.path().join("link"));
            assert!(canon.ends_with("real"));
        }
    }

    // Phase 46 (Workstream C): Basic/Strict profile semantics.
    #[test]
    fn test_sbpl_basic_has_no_contradictory_default() {
        let profile = compile_sbpl_profile(&[], &[], &[], SandboxLevel::Basic).unwrap();
        assert!(profile.contains("(allow default)"));
        assert!(
            !profile.contains("(deny default)"),
            "Basic must not emit contradictory deny default"
        );
    }

    #[test]
    fn test_sbpl_strict_denies_default_and_network_without_job_creation() {
        let profile = compile_sbpl_profile(&[], &[], &[], SandboxLevel::Strict).unwrap();
        assert!(profile.contains("(deny default)"));
        assert!(!profile.contains("(allow default)"));
        assert!(profile.contains("(deny network*)"));
        assert!(
            !profile.contains("job-creation"),
            "Strict must not allow job-creation (child creation stays denied)"
        );
        assert!(profile.contains("(allow process*)"));
        assert!(profile.contains("(allow signal)"));
    }

    #[test]
    fn test_sbpl_strict_file_rules_use_subpath() {
        let profile = compile_sbpl_profile(
            &[Path::new("/usr/lib")],
            &[Path::new("/tmp/work")],
            &[Path::new("/etc/shadow")],
            SandboxLevel::Strict,
        )
        .unwrap();
        assert!(profile.contains("(allow file-read*"));
        assert!(profile.contains("(allow file-write*"));
        assert!(profile.contains("(deny file-read*"));
        assert!(profile.contains("(deny file-write*"));
        // Denies are emitted after allows (explicit deny is the final word
        // on overlap; callers must keep lists disjoint).
        let last_allow = profile.rfind("(allow file-").unwrap();
        let first_deny = profile.find("(deny file-").unwrap();
        assert!(last_allow < first_deny);
    }

    #[test]
    fn test_sbpl_off_is_allow_default_only() {
        let profile = compile_sbpl_profile(&[], &[], &[], SandboxLevel::Off).unwrap();
        assert!(profile.contains("(allow default)"));
        assert!(!profile.contains("(deny"));
    }

    #[test]
    fn test_sbpl_invalid_path_propagates() {
        let profile =
            compile_sbpl_profile(&[Path::new("/tmp/a\nb")], &[], &[], SandboxLevel::Strict);
        assert!(matches!(profile, Err(SandboxError::InvalidPath(_))));
    }
}
