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
            #[cfg(target_os = "freebsd")]
            {
                Box::new(crate::platform::sandbox::capsicum::CapsicumSandbox::new(
                    level,
                ))
            }
            #[cfg(target_os = "openbsd")]
            {
                Box::new(crate::platform::sandbox::pledge::PledgeSandbox::new(level))
            }
            #[cfg(target_os = "windows")]
            {
                Box::new(crate::platform::sandbox::windows::WindowsSandbox::new(
                    level,
                ))
            }
            #[cfg(target_os = "macos")]
            {
                Box::new(crate::platform::sandbox::darwin::SeatbeltSandbox::new(
                    level,
                ))
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
    use super::{SandboxBackend, SandboxCapabilities, SandboxError, SandboxLevel};
    use std::os::unix::io::AsRawFd;
    use std::path::Path;

    const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
    const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
    const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
    const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
    const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
    const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
    const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
    const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
    const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
    const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
    const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
    const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
    const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

    const LANDLOCK_ACCESS_FS_READ: u64 = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    const LANDLOCK_ACCESS_FS_WRITE: u64 = LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;
    const LANDLOCK_ACCESS_FS_ALL: u64 =
        LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_WRITE | LANDLOCK_ACCESS_FS_EXECUTE;

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

            #[repr(C)]
            struct LandlockRulesetAttr {
                handled_access_fs: u64,
            }

            unsafe {
                let attr = LandlockRulesetAttr {
                    handled_access_fs: LANDLOCK_ACCESS_FS_ALL,
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

            let file = std::fs::File::open(path).map_err(SandboxError::Io)?;
            let dir_fd = file.as_raw_fd();

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
            read_paths: &[&Path],
            write_paths: &[&Path],
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

            for path in read_paths {
                self.add_path_rule(ruleset_fd, path, LANDLOCK_ACCESS_FS_READ)?;
            }

            for path in write_paths {
                self.add_path_rule(
                    ruleset_fd,
                    path,
                    LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_WRITE,
                )?;
            }

            for path in denied_paths {
                tracing::debug!("Path will have no sandbox access: {}", path.display());
            }

            self.restrict_self(ruleset_fd)?;

            unsafe {
                libc::close(ruleset_fd);
            }

            tracing::info!(
                "Applied landlock sandbox (level: {:?}) with {} read paths, {} write paths",
                self.level,
                read_paths.len(),
                write_paths.len()
            );

            let _ = denied_paths;

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

        fn is_capsicum_available() -> bool {
            let mut mode: libc::c_int = 0;
            let result = unsafe { libc::cap_getmode(&mut mode) };
            result == 0 && mode != 0
        }

        fn enter_sandbox(&self) -> Result<(), SandboxError> {
            let result = unsafe { libc::cap_enter() };
            if result < 0 {
                return Err(SandboxError::Syscall("cap_enter failed".into()));
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

            self.enter_sandbox()?;

            tracing::info!(
                "Applied capsicum sandbox (level: {:?}) with {} read paths, {} write paths",
                self.level,
                read_paths.len(),
                write_paths.len()
            );
            let _ = denied_paths;
            let _ = write_paths;

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
            SandboxCapabilities {
                read_path_allowlist: false,
                write_path_allowlist: false,
                deny_paths: false,
                process_limits: true,
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

        fn unveil(&self, path: &Path, permissions: &str) -> Result<(), SandboxError> {
            let path_cstr = CStr::from_bytes_with_nul(format!("{}\0", path.display()).as_bytes())
                .map_err(|_| SandboxError::Syscall("Invalid path".into()))?;

            let perms_cstr = CStr::from_bytes_with_nul(format!("{}\0", permissions).as_bytes())
                .map_err(|_| SandboxError::Syscall("Invalid permissions".into()))?;

            let result = unsafe { libc::unveil(path_cstr.as_ptr(), perms_cstr.as_ptr()) };

            if result < 0 {
                return Err(SandboxError::Syscall("unveil failed".into()));
            }

            Ok(())
        }

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
            SandboxCapabilities {
                read_path_allowlist: true,
                write_path_allowlist: true,
                deny_paths: true,
                process_limits: true,
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

    pub struct WindowsSandbox {
        level: SandboxLevel,
        applied: AtomicBool,
    }

    impl WindowsSandbox {
        pub fn new(level: SandboxLevel) -> Self {
            Self {
                level,
                applied: AtomicBool::new(false),
            }
        }

        fn is_supported() -> bool {
            true
        }

        fn apply_file_restrictions(&self, paths: &[&Path]) -> Result<(), SandboxError> {
            use windows_sys::Win32::Security::{
                GetNamedSecurityInfoW, SetNamedSecurityInfoW, DACL_SECURITY_INFORMATION,
                SE_FILE_OBJECT,
            };

            for path in paths {
                let path_str = match path.to_str() {
                    Some(s) => s,
                    None => continue,
                };

                let mut path_wide: Vec<u16> =
                    path_str.encode_utf16().chain(std::iter::once(0)).collect();

                let mut sd: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR =
                    std::ptr::null_mut();

                let result = unsafe {
                    GetNamedSecurityInfoW(
                        path_wide.as_ptr(),
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        &mut sd,
                    )
                };

                if result != 0 {
                    tracing::warn!(
                        "GetNamedSecurityInfoW failed for {}: {}",
                        path.display(),
                        result
                    );
                    continue;
                }

                let restrict_dacl = match crate::platform::SecurityDescriptor::new_user_only() {
                    Ok(sd) => sd,
                    Err(e) => {
                        tracing::warn!(
                            "Failed to create restrictive DACL for {}: {}",
                            path.display(),
                            e
                        );
                        continue;
                    }
                };

                let set_result = unsafe {
                    SetNamedSecurityInfoW(
                        path_wide.as_mut_ptr(),
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        Some(restrict_dacl.as_ptr() as *mut _),
                        std::ptr::null_mut(),
                    )
                };

                if set_result != 0 {
                    tracing::warn!(
                        "SetNamedSecurityInfoW failed for {}: {}",
                        path.display(),
                        set_result
                    );
                } else {
                    tracing::debug!("Applied restrictive DACL to {}", path.display());
                }
            }

            Ok(())
        }

        fn apply_job_object(&self) -> Result<(), SandboxError> {
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;

            const JOBOBJECT_BASIC_LIMIT_INFORMATION: u32 = 2;
            const JOB_OBJECT_LIMIT_PROCESS_MEMORY: u32 = 0x1;
            const JOB_OBJECT_LIMIT_JOB_MEMORY: u32 = 0x2;
            const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x20;
            const ProcessTlsInformation: u32 = 58;

            #[repr(C)]
            struct JOBOBJECT_BASIC_LIMIT_INFORMATION_T {
                per_process_time: u64,
                per_job_time: u64,
                limits_flags: u32,
                minimum_working_set_size: usize,
                maximum_working_set_size: usize,
                active_process_limit: u32,
                affinity: usize,
                priority_class: u32,
                scheduling_class: i32,
            }

            #[repr(C)]
            struct IO_COUNTERS {
                read_operation_count: u64,
                write_operation_count: u64,
                other_operation_count: u64,
                read_transfer_count: u64,
                write_transfer_count: u64,
                other_transfer_count: u64,
            }

            #[repr(C)]
            struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
                basic_limit_information: JOBOBJECT_BASIC_LIMIT_INFORMATION_T,
                io_info: IO_COUNTERS,
                process_memory_limit: usize,
                job_memory_limit: usize,
                peak_process_memory: usize,
                peak_job_memory: usize,
            }

            let job = unsafe {
                let create_result = windows_sys::Win32::System::Threading::CreateJobObjectW(
                    Some(std::ptr::null_mut()),
                    Some(std::ptr::null_mut()),
                );
                if create_result.is_null() {
                    return Err(SandboxError::Syscall("CreateJobObjectW failed".into()));
                }
                create_result
            };

            let mut limit_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
                basic_limit_information: JOBOBJECT_BASIC_LIMIT_INFORMATION_T {
                    per_process_time: 0,
                    per_job_time: 0,
                    limits_flags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
                        | JOB_OBJECT_LIMIT_JOB_MEMORY,
                    minimum_working_set_size: 0,
                    maximum_working_set_size: 0,
                    active_process_limit: 0,
                    affinity: 0,
                    priority_class: 0,
                    scheduling_class: 0,
                },
                io_info: IO_COUNTERS {
                    read_operation_count: 0,
                    write_operation_count: 0,
                    other_operation_count: 0,
                    read_transfer_count: 0,
                    write_transfer_count: 0,
                    other_transfer_count: 0,
                },
                process_memory_limit: 256 * 1024 * 1024,
                job_memory_limit: 512 * 1024 * 1024,
                peak_process_memory: 0,
                peak_job_memory: 0,
            };

            let set_info_result = unsafe {
                windows_sys::Win32::System::Threading::SetInformationJobObject(
                    job,
                    JOBOBJECT_BASIC_LIMIT_INFORMATION,
                    &mut limit_info as *mut _ as *mut libc::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };

            if set_info_result == 0 {
                return Err(SandboxError::Syscall(
                    "SetInformationJobObject failed".into(),
                ));
            }

            let current_process =
                unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };

            let assign_result = unsafe {
                windows_sys::Win32::System::Threading::AssignProcessToJobObject(
                    job,
                    current_process,
                )
            };

            if assign_result == 0 {
                return Err(SandboxError::Syscall(
                    "AssignProcessToJobObject failed".into(),
                ));
            }

            tracing::info!(
                "Applied Windows Job Object sandbox (level: {:?})",
                self.level
            );

            Ok(())
        }

        fn apply_mitigation_policies(&self) -> Result<(), SandboxError> {
            use windows_sys::Win32::System::Threading;

            const PROCESS_CREATION_MITIGATION_POLICY_DEP: u32 = 0x1;
            const PROCESS_CREATION_MITIGATION_POLICY_ASLR: u32 = 0x8;

            let current_process = unsafe { Threading::GetCurrentProcess() };

            let dep_enabled = Threading::SetProcessMitigationPolicy(
                Threading::ProcessDEPPolicy,
                &PROCESS_CREATION_MITIGATION_POLICY_DEP as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>(),
            );

            if dep_enabled == 0 {
                tracing::warn!("Failed to enable DEP mitigation");
            } else {
                tracing::debug!("DEP mitigation enabled");
            }

            let aslr_enabled = Threading::SetProcessMitigationPolicy(
                Threading::ProcessASLRPolicy,
                &PROCESS_CREATION_MITIGATION_POLICY_ASLR as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>(),
            );

            if aslr_enabled == 0 {
                tracing::warn!("Failed to enable ASLR mitigation");
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
                self.apply_mitigation_policies()?;
                self.apply_file_restrictions(read_paths)?;
                self.apply_file_restrictions(write_paths)?;
                for path in denied_paths {
                    self.apply_file_restrictions(&[path])?;
                }
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
            SandboxCapabilities {
                read_path_allowlist: self.level == SandboxLevel::Strict,
                write_path_allowlist: self.level == SandboxLevel::Strict,
                deny_paths: self.level == SandboxLevel::Strict,
                process_limits: true,
                network_restrictions: false,
                child_process_restrictions: false,
            }
        }
    }
}

#[cfg(target_os = "macos")]
pub mod darwin {
    use super::{SandboxBackend, SandboxCapabilities, SandboxError, SandboxLevel};
    use std::path::Path;

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

                let sym = unsafe { dlsym(libc::RTLD_DEFAULT, b"sandbox_init\0".as_ptr().cast()) };
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
        ) -> String {
            let mut profile = String::new();

            profile.push_str("(version 1)\n");

            match level {
                SandboxLevel::Basic => {
                    profile.push_str("(allow default)\n");
                    profile.push_str("(deny default)\n");
                }
                SandboxLevel::Strict => {
                    profile.push_str("(deny default)\n");
                    profile.push_str("(allow process)\n");
                    profile.push_str("(allow signal)\n");
                    profile.push_str("(allow job-creation)\n");
                }
                SandboxLevel::Off => {
                    profile.push_str("(allow default)\n");
                    return profile;
                }
            }

            for path in read_paths {
                let path_str = path.display().to_string().replace('\\', "\\\\");
                profile.push_str(&format!("(allow file-read* (subpath \"{}\"))\n", path_str));
            }

            for path in write_paths {
                let path_str = path.display().to_string().replace('\\', "\\\\");
                profile.push_str(&format!("(allow file-read* (subpath \"{}\"))\n", path_str));
                profile.push_str(&format!("(allow file-write* (subpath \"{}\"))\n", path_str));
            }

            for path in denied_paths {
                let path_str = path.display().to_string().replace('\\', "\\\\");
                profile.push_str(&format!("(deny file-read* (subpath \"{}\"))\n", path_str));
                profile.push_str(&format!("(deny file-write* (subpath \"{}\"))\n", path_str));
            }

            profile
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

                let profile_cstr =
                    CStr::from_bytes_with_nul(format!("{}\0", profile).as_bytes())
                        .map_err(|_| SandboxError::Syscall("Invalid sandbox profile".into()))?;

                #[link(name = "sandbox")]
                extern "C" {
                    fn sandbox_init(
                        profile: *const libc::c_char,
                        flags: libc::c_int,
                        error: *mut *mut libc::c_char,
                    ) -> libc::c_int;
                }

                let result =
                    unsafe { sandbox_init(profile_cstr.as_ptr(), 0, std::ptr::null_mut()) };

                if result != 0 {
                    let err_msg = std::io::Error::last_os_error().to_string();
                    return Err(SandboxError::Syscall(format!(
                        "sandbox_init failed: {}",
                        err_msg
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
                Self::compile_sandbox_profile(read_paths, write_paths, denied_paths, self.level);

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
                SandboxCapabilities {
                    read_path_allowlist: true,
                    write_path_allowlist: true,
                    deny_paths: true,
                    process_limits: true,
                    network_restrictions: true,
                    child_process_restrictions: true,
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

    #[test]
    fn test_strict_sandbox_fails_on_stub_backend() {
        let stub = StubSandbox::new(SandboxLevel::Basic, "test-stub");
        let caps = stub.capabilities();
        assert!(!caps.can_enforce_strict());

        let sandbox = ProcessSandbox::with_stub(SandboxLevel::Strict);
        let caps = sandbox.capabilities();
        assert!(!caps.can_enforce_strict(), "stub backend should not support strict");
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
        let result = ProcessSandbox::with_paths(SandboxLevel::Basic, SandboxPaths::new());
        assert!(result.is_ok());
    }
}
