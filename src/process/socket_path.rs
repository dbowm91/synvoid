use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

static MASTER_GENERATION: AtomicU32 = AtomicU32::new(0);

#[cfg(unix)]
fn create_secure_dir_atomic(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    match std::fs::create_dir(path) {
        Ok(()) => {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(path)?;
            let file_type = metadata.file_type();

            if file_type.is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "socket path is a symlink, refusing for security",
                ));
            }

            if !file_type.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "path exists but is not a directory",
                ));
            }

            let dir_uid = metadata.uid();
            let my_uid = unsafe { libc::geteuid() };

            if dir_uid != 0 && dir_uid != my_uid {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "directory owned by untrusted user",
                ));
            }

            if metadata.permissions().mode() & 0o777 != 0o700 {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

#[cfg(not(unix))]
fn create_secure_dir_atomic(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

pub fn get_secure_socket_path(name: &str) -> PathBuf {
    #[cfg(unix)]
    {
        if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
            let path = PathBuf::from(runtime_dir).join("synvoid");
            if create_secure_dir_atomic(&path).is_ok() {
                return path.join(name);
            }
        }

        let var_run = PathBuf::from("/var/run");
        if var_run.exists() {
            let path = var_run.join("synvoid");
            if create_secure_dir_atomic(&path).is_ok() {
                return path.join(name);
            }
        }

        get_user_socket_dir().join(name)
    }

    #[cfg(windows)]
    {
        use std::env;
        let local_app_data = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let path = local_app_data.join("synvoid");
        let _ = std::fs::create_dir_all(&path);
        path.join(name)
    }

    #[cfg(not(any(unix, windows)))]
    {
        let path = PathBuf::from("/tmp").join("synvoid");
        let _ = std::fs::create_dir_all(&path);
        path.join(name)
    }
}

#[cfg(unix)]
pub fn get_user_socket_dir() -> PathBuf {
    let uid = unsafe { libc::geteuid() };
    let path = PathBuf::from("/tmp").join(format!("synvoid-{}", uid));
    let _ = create_secure_dir_atomic(&path);
    path
}

pub fn get_supervisor_socket_path() -> PathBuf {
    get_secure_socket_path("supervisor.sock")
}

pub fn get_cpu_worker_socket_path() -> PathBuf {
    get_static_worker_socket_path()
}

pub fn get_static_worker_socket_path() -> PathBuf {
    get_secure_socket_path("static-worker.sock")
}

pub fn get_versioned_supervisor_socket_path(generation: u32) -> PathBuf {
    get_secure_socket_path(&format!("supervisor-{}.sock", generation))
}

pub fn get_current_supervisor_generation() -> u32 {
    MASTER_GENERATION.load(Ordering::SeqCst)
}

pub fn set_supervisor_generation(generation: u32) {
    MASTER_GENERATION.store(generation, Ordering::SeqCst);
}

pub fn next_supervisor_generation() -> u32 {
    MASTER_GENERATION.fetch_add(1, Ordering::SeqCst) + 1
}

pub fn resolve_supervisor_socket_for_upgrade(
    upgrade_mode: bool,
    generation: Option<u32>,
) -> PathBuf {
    if upgrade_mode {
        if let Some(gen) = generation {
            get_versioned_supervisor_socket_path(gen)
        } else {
            let gen = next_supervisor_generation();
            get_versioned_supervisor_socket_path(gen)
        }
    } else {
        get_supervisor_socket_path()
    }
}

fn parse_supervisor_generation(name: &str) -> Option<u32> {
    if name.starts_with("supervisor-") && name.ends_with(".sock") {
        let gen_str = name
            .trim_start_matches("supervisor-")
            .trim_end_matches(".sock");
        gen_str.parse::<u32>().ok()
    } else {
        None
    }
}

pub fn find_active_supervisor_socket() -> Option<PathBuf> {
    let base_path = get_supervisor_socket_path();
    if base_path.exists() {
        return Some(base_path);
    }

    let socket_dir = base_path.parent()?;
    match std::fs::read_dir(socket_dir) {
        Ok(entries) => {
            let mut sockets: Vec<(u32, PathBuf)> = entries
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    parse_supervisor_generation(&name).map(|gen| (gen, e.path()))
                })
                .collect();

            sockets.sort_by_key(|(gen, _)| std::cmp::Reverse(*gen));
            sockets.into_iter().map(|(_, path)| path).next()
        }
        _ => None,
    }
}

pub fn cleanup_old_supervisor_sockets(keep_generation: u32) {
    let base_path = get_supervisor_socket_path();
    if let Some(socket_dir) = base_path.parent() {
        if let Ok(entries) = std::fs::read_dir(socket_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Some(gen) = parse_supervisor_generation(&name) {
                    if gen < keep_generation {
                        let _ = std::fs::remove_file(entry.path());
                        tracing::debug!("Cleaned up old supervisor socket: {}", name);
                    }
                }
            }
        }
    }
}

#[cfg(unix)]
pub fn set_socket_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
pub fn set_socket_permissions(_path: &std::path::Path) -> std::io::Result<()> {
    // No-op on non-Unix
    Ok(())
}

fn get_platform_dir_impl(env_var: &str, default: &str, suffix: Option<&str>) -> PathBuf {
    #[cfg(unix)]
    {
        std::env::var_os(env_var)
            .map(|s| {
                let mut p = PathBuf::from(s).join("synvoid");
                if let Some(s) = suffix {
                    p = p.join(s);
                }
                p
            })
            .unwrap_or_else(|| {
                let mut p = PathBuf::from(default);
                if let Some(s) = suffix {
                    p = p.join(s);
                }
                p
            })
    }

    #[cfg(windows)]
    {
        std::env::var_os("PROGRAMDATA")
            .or_else(|| std::env::var_os("LOCALAPPDATA"))
            .map(|s| {
                let mut p = PathBuf::from(s).join("synvoid");
                if let Some(s) = suffix {
                    p = p.join(s);
                }
                p
            })
            .unwrap_or_else(|| {
                let mut p = PathBuf::from(".").join(suffix.unwrap_or("data"));
                if suffix.is_none() {
                    p = PathBuf::from(".");
                }
                p
            })
    }

    #[cfg(not(any(unix, windows)))]
    {
        let mut p = PathBuf::from(default);
        if let Some(s) = suffix {
            p = p.join(s);
        }
        p
    }
}

pub fn get_platform_data_dir() -> PathBuf {
    get_platform_dir_impl("XDG_DATA_DIRS", "/var/lib/synvoid", None)
}

pub fn get_platform_log_dir() -> PathBuf {
    get_platform_dir_impl("XDG_LOG_DIR", "/var/log/synvoid", Some("logs"))
}

pub fn get_platform_cache_dir() -> PathBuf {
    get_platform_dir_impl("XDG_CACHE_DIR", "/var/cache/synvoid", Some("cache"))
}
