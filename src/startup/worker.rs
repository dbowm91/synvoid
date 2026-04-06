use std::path::PathBuf;

use crate::platform::fs::PlatformPaths;
use crate::worker::{StaticWorkerArgs, UnifiedServerWorkerArgs, WorkerArgs};

pub fn build_worker_args(
    worker_id: Option<usize>,
    port: Option<u16>,
    config_path: Option<PathBuf>,
    master_socket: Option<PathBuf>,
    test_mode: Option<Vec<String>>,
    log_level: Option<String>,
) -> WorkerArgs {
    let paths = PlatformPaths::new();
    WorkerArgs {
        worker_id: worker_id.unwrap_or(0),
        port: port.unwrap_or(9000),
        config_path: config_path.unwrap_or_else(|| PathBuf::from("config")),
        master_socket: master_socket.unwrap_or_else(|| paths.master_socket_path()),
        test_mode,
        log_level,
        upgrade_mode: false,
        reuse_port: false,
        ipc_key: None,
    }
}

pub fn build_static_worker_args(
    static_worker_id: Option<usize>,
    config_path: Option<PathBuf>,
    master_socket: Option<PathBuf>,
    log_level: Option<String>,
) -> StaticWorkerArgs {
    let paths = PlatformPaths::new();
    StaticWorkerArgs {
        worker_id: static_worker_id.unwrap_or(0),
        config_path: config_path.unwrap_or_else(|| PathBuf::from("config")),
        master_socket: master_socket.unwrap_or_else(|| paths.master_socket_path()),
        static_worker_socket: paths.static_worker_socket_path(),
        log_level,
        ipc_key: None,
    }
}

pub fn build_unified_server_worker_args(
    unified_worker_id: Option<usize>,
    config_path: Option<PathBuf>,
    master_socket: Option<PathBuf>,
    log_level: Option<String>,
    worker_threads: usize,
) -> UnifiedServerWorkerArgs {
    let paths = PlatformPaths::new();
    UnifiedServerWorkerArgs {
        worker_id: unified_worker_id.unwrap_or(0),
        config_path: config_path.unwrap_or_else(|| PathBuf::from("config")),
        master_socket: master_socket.unwrap_or_else(|| paths.master_socket_path()),
        log_level,
        upgrade_mode: false,
        reuse_port: false,
        worker_threads,
    }
}
