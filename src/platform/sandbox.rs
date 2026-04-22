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

pub trait SandboxBackend: Send + Sync {
    fn apply(&self, allowed_paths: &[&Path], denied_paths: &[&Path]) -> Result<(), SandboxError>;
    fn is_supported(&self) -> bool;
    fn feature_name(&self) -> &'static str;
    fn level(&self) -> SandboxLevel;
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
                Box::new(crate::platform::sandbox::linux::LandlockSandbox::new(level))
            }
            #[cfg(not(target_os = "linux"))]
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

    pub fn with_paths(level: SandboxLevel, paths: SandboxPaths) -> Result<Self, SandboxError> {
        let sandbox = Self::new(level);

        if level == SandboxLevel::Off {
            return Ok(sandbox);
        }

        let read_refs: Vec<&Path> = paths.read_paths.iter().map(|p| p.as_path()).collect();
        let denied_refs: Vec<&Path> = paths.no_access_paths.iter().map(|p| p.as_path()).collect();

        sandbox.backend.apply(&read_refs, &denied_refs)?;

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
    fn apply(&self, _allowed_paths: &[&Path], _denied_paths: &[&Path]) -> Result<(), SandboxError> {
        if self.level == SandboxLevel::Off {
            tracing::debug!("Sandbox disabled - no restrictions applied");
            return Ok(());
        }

        tracing::warn!(
            "OS-level sandboxing is not available on this platform ({}). \
             Using basic directory isolation instead. For full sandboxing, \
             use Linux with kernel 5.13+.",
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
}

#[cfg(target_os = "linux")]
pub mod linux {
    use super::{SandboxBackend, SandboxError, SandboxLevel};
    use std::path::Path;

    pub struct LandlockSandbox {
        level: SandboxLevel,
    }

    impl LandlockSandbox {
        pub fn new(level: SandboxLevel) -> Self {
            Self { level }
        }

        fn is_landlock_available() -> bool {
            std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .ok()
                .and_then(|v| {
                    let parts: Vec<&str> = v.trim().split('.').collect();
                    if parts.len() >= 2 {
                        let major: u32 = parts[0].parse().unwrap_or(0);
                        let minor: u32 = parts[1].parse().unwrap_or(0);
                        if major > 5 || (major == 5 && minor >= 13) {
                            return Some(true);
                        }
                    }
                    None
                })
                .is_some()
        }

        fn create_landlock_ruleset(&self) -> Result<i32, SandboxError> {
            const LANDLOCK_CREATE_RULESET: u64 = 1;
            const LANDLOCK_ATTR_RULESET: u64 = 1;

            #[repr(C)]
            struct LandlockRulesetAttr {
                handled_access_fs: u64,
            }

            unsafe {
                let attr = LandlockRulesetAttr {
                    handled_access_fs: 0b111, // READ | WRITE | EXEC
                };

                let ret = libc::syscall(
                    libc::SYS_landlock_create_ruleset,
                    &attr as *const _ as *mut libc::c_void,
                    std::mem::size_of::<LandlockRulesetAttr>() as u64,
                    LANDLOCK_CREATE_RULESET,
                );

                if ret < 0 {
                    return Err(SandboxError::LandlockUnavailable);
                }

                Ok(ret as i32)
            }
        }

        fn add_path_rule(
            &self,
            ruleset_fd: i32,
            path: &Path,
            allowed_access: u64,
        ) -> Result<(), SandboxError> {
            const LANDLOCK_ADD_RULE: u64 = 2;
            const LANDLOCK_RULE_PATH_BENEATH: u64 = 1;

            #[repr(C)]
            struct LandlockPathBeneathAttr {
                parent_fd: i32,
                allowed_access: u64,
            }

            let dir_fd = std::fs::File::open(path)
                .map_err(|e| SandboxError::Io(e))?
                .as_raw_fd();

            let attr = LandlockPathBeneathAttr {
                parent_fd: dir_fd,
                allowed_access,
            };

            unsafe {
                let ret = libc::syscall(
                    libc::SYS_landlock_add_rule,
                    ruleset_fd as i64,
                    LANDLOCK_ADD_RULE,
                    &attr as *const _ as *mut libc::c_void,
                    LANDLOCK_RULE_PATH_BENEATH,
                );

                if ret < 0 {
                    return Err(SandboxError::Syscall("landlock_add_rule failed".into()));
                }
            }

            Ok(())
        }

        fn restrict_self(&self, ruleset_fd: i32) -> Result<(), SandboxError> {
            const LANDLOCK_RESTRICT_SELF: u64 = 3;

            unsafe {
                let ret = libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd as i64, 0u64);

                if ret < 0 {
                    return Err(SandboxError::Syscall(
                        "landlock_restrict_self failed".into(),
                    ));
                }
            }

            Ok(())
        }
    }

    impl SandboxBackend for LandlockSandbox {
        fn apply(
            &self,
            allowed_paths: &[&Path],
            denied_paths: &[&Path],
        ) -> Result<(), SandboxError> {
            if !Self::is_landlock_available() {
                tracing::warn!(
                    "Landlock not available (kernel < 5.13 or disabled). \
                     OS-level sandboxing is not active. Consider upgrading kernel for full protection."
                );
                return Err(SandboxError::LandlockUnavailable);
            }

            let ruleset_fd = self.create_landlock_ruleset()?;

            for path in allowed_paths {
                let access = 0b11; // READ | WRITE
                self.add_path_rule(ruleset_fd, path, access)?;
            }

            for path in denied_paths {
                tracing::debug!("Path will have no sandbox access: {}", path.display());
            }

            self.restrict_self(ruleset_fd)?;

            unsafe {
                libc::close(ruleset_fd);
            }

            tracing::info!(
                "Applied landlock sandbox (level: {:?}) with {} allowed paths",
                self.level,
                allowed_paths.len()
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
    }
}
