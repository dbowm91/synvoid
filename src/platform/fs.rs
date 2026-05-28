use std::io;
use std::path::{Path, PathBuf};

use super::Platform;

#[derive(Debug, Clone)]
pub struct SecureDir {
    path: PathBuf,
    mode: Option<u32>,
}

impl SecureDir {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let mode = if cfg!(unix) { Some(0o700) } else { None };
        Self {
            path: path.into(),
            mode,
        }
    }

    pub fn with_mode(path: impl Into<PathBuf>, mode: u32) -> Self {
        Self {
            path: path.into(),
            mode: Some(mode),
        }
    }

    pub fn create(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.path)?;
        self.apply_permissions()
    }

    #[cfg(unix)]
    fn apply_permissions(&self) -> io::Result<()> {
        if let Some(mode) = self.mode {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(mode))?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn apply_permissions(&self) -> io::Result<()> {
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }
}

pub struct PlatformPaths {
    data_dir: PathBuf,
    config_dir: PathBuf,
    log_dir: PathBuf,
    cache_dir: PathBuf,
    runtime_dir: PathBuf,
}

impl PlatformPaths {
    pub fn new() -> Self {
        let platform = Platform::current();

        let (data_dir, config_dir, log_dir, cache_dir, runtime_dir) = match platform {
            Platform::Linux | Platform::LinuxMusl => {
                let data = std::env::var_os("XDG_DATA_DIRS")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("/var/lib/synvoid"));

                let config = std::env::var_os("XDG_CONFIG_DIRS")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("/etc/synvoid"));

                let log = std::env::var_os("XDG_LOG_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("/var/log/synvoid"));

                let cache = std::env::var_os("XDG_CACHE_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("/var/cache/synvoid"));

                let runtime = std::env::var_os("XDG_RUNTIME_DIR")
                    .map(|s| PathBuf::from(s).join("synvoid"))
                    .unwrap_or_else(|| PathBuf::from("/run/synvoid"));

                (data, config, log, cache, runtime)
            }

            Platform::Macos => {
                let home = std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("/tmp"));

                (
                    home.join(".local/share/synvoid"),
                    home.join(".config/synvoid"),
                    home.join(".local/log/synvoid"),
                    home.join(".cache/synvoid"),
                    std::env::var_os("TMPDIR")
                        .map(PathBuf::from)
                        .unwrap_or_else(|| PathBuf::from("/tmp"))
                        .join("synvoid-runtime"),
                )
            }

            Platform::FreeBSD | Platform::OpenBSD | Platform::NetBSD => (
                PathBuf::from("/var/db/synvoid"),
                PathBuf::from("/usr/local/etc/synvoid"),
                PathBuf::from("/var/log/synvoid"),
                PathBuf::from("/var/cache/synvoid"),
                PathBuf::from("/var/run/synvoid"),
            ),

            Platform::Windows => {
                let app_data = std::env::var_os("LOCALAPPDATA")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("."));

                let program_data = std::env::var_os("PROGRAMDATA")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("."));

                (
                    program_data.join("synvoid"),
                    program_data.join("synvoid").join("config"),
                    program_data.join("synvoid").join("logs"),
                    app_data.join("synvoid").join("cache"),
                    app_data.join("synvoid").join("runtime"),
                )
            }

            Platform::Unknown => (
                PathBuf::from("/var/lib/synvoid"),
                PathBuf::from("/etc/synvoid"),
                PathBuf::from("/var/log/synvoid"),
                PathBuf::from("/var/cache/synvoid"),
                PathBuf::from("/run/synvoid"),
            ),
        };

        Self {
            data_dir,
            config_dir,
            log_dir,
            cache_dir,
            runtime_dir,
        }
    }

    pub fn with_base(base: impl Into<PathBuf>) -> Self {
        let base = base.into();
        Self {
            data_dir: base.join("data"),
            config_dir: base.join("config"),
            log_dir: base.join("logs"),
            cache_dir: base.join("cache"),
            runtime_dir: base.join("run"),
        }
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }
    pub fn log_dir(&self) -> &Path {
        &self.log_dir
    }
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }
    pub fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    pub fn connections_shm_path(&self) -> PathBuf {
        self.runtime_dir.join("connections.shm")
    }

    pub fn ratelimit_shm_path(&self) -> PathBuf {
        self.runtime_dir.join("ratelimit.shm")
    }

    pub fn ensure_all(&self) -> io::Result<()> {
        for dir in &[
            &self.data_dir,
            &self.config_dir,
            &self.log_dir,
            &self.cache_dir,
            &self.runtime_dir,
        ] {
            SecureDir::new(dir).create()?;
        }
        Ok(())
    }

    pub fn pid_file(&self) -> PathBuf {
        self.runtime_dir.join("synvoid.pid")
    }

    pub fn socket_path(&self) -> PathBuf {
        self.runtime_dir.join("synvoid.sock")
    }

    pub fn ipc_path(&self, name: &str) -> PathBuf {
        self.runtime_dir.join(name)
    }

    pub fn supervisor_socket_path(&self) -> PathBuf {
        self.runtime_dir.join("synvoid-supervisor.sock")
    }

    pub fn static_worker_socket_path(&self) -> PathBuf {
        self.runtime_dir.join("synvoid-static-worker.sock")
    }

    pub fn unified_worker_socket_path(&self, worker_id: usize) -> PathBuf {
        self.runtime_dir
            .join(format!("synvoid-unified-{}.sock", worker_id))
    }

    pub fn panic_log_path(&self, name: &str) -> PathBuf {
        self.runtime_dir.join(format!("{}-panic.log", name))
    }
}

impl Default for PlatformPaths {
    fn default() -> Self {
        Self::new()
    }
}

pub fn set_file_permissions(path: &Path, read_only: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if read_only { 0o400 } else { 0o600 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }

    #[cfg(windows)]
    {
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_readonly(read_only);
        std::fs::set_permissions(path, perms)?;
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, read_only);
    }

    Ok(())
}

pub fn set_dir_permissions(path: &Path, private: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if private { 0o700 } else { 0o755 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }

    #[cfg(not(unix))]
    {
        let _ = (path, private);
    }

    Ok(())
}
