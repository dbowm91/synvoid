//! Sandbox primitives for process isolation.
//!
//! Provides the core types and traits for OS-level sandboxing.
//! Platform-specific backends (Landlock, Seatbelt, etc.) are provided by the
//! root crate which re-exports these types.

use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("Platform not supported: {0}")]
    NotSupported(String),

    #[error("Landlock not available (kernel < 5.13)")]
    LandlockUnavailable,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Syscall failed: {0}")]
    Syscall(String),

    #[error("Strict sandbox requested but backend cannot enforce it: {0}")]
    InsufficientCapabilities(String),
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

/// ProcessSandbox applies OS-level sandbox restrictions.
///
/// Use [`ProcessSandbox::new`] to create with automatic backend selection,
/// or [`ProcessSandbox::with_backend`] to provide a specific backend.
pub struct ProcessSandbox {
    backend: Box<dyn SandboxBackend>,
}

impl ProcessSandbox {
    /// Creates a sandbox with the given backend.
    pub fn with_backend(backend: Box<dyn SandboxBackend>) -> Self {
        Self { backend }
    }

    /// Creates a sandbox with the given level using automatic backend selection.
    ///
    /// The root crate provides a `new` method that selects the appropriate
    /// platform backend. This method is available when a default stub is sufficient.
    pub fn with_stub(level: SandboxLevel) -> Self {
        let backend: Box<dyn SandboxBackend> = Box::new(StubSandbox::new(level, "disabled"));
        Self { backend }
    }

    pub fn with_paths(level: SandboxLevel, paths: SandboxPaths) -> Result<Self, SandboxError> {
        let sandbox = Self::with_stub(level);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_sandbox_fails_on_stub_backend() {
        let stub = StubSandbox::new(SandboxLevel::Basic, "test-stub");
        let caps = stub.capabilities();
        assert!(!caps.can_enforce_strict());

        let result = ProcessSandbox::with_paths(SandboxLevel::Strict, SandboxPaths::new());
        assert!(result.is_err());
        if let Err(SandboxError::InsufficientCapabilities(_)) = result {
        } else {
            panic!("expected InsufficientCapabilities error");
        }
    }

    #[test]
    fn test_strict_sandbox_fails_on_insufficient_capabilities() {
        let level = SandboxLevel::Strict;
        let sandbox = ProcessSandbox::with_stub(level);

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
        let result = ProcessSandbox::with_paths(SandboxLevel::Basic, SandboxPaths::new());
        assert!(result.is_ok());
    }
}
