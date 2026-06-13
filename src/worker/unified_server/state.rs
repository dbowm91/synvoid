// Submodule: UnifiedServerWorkerState, UnifiedServerWorkerArgs, and the
// small lifecycle helpers (drain wait, panic handler) that live alongside
// the worker state.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, Mutex as TokioMutex, RwLock};
use tokio::task::JoinHandle;

use super::super::connect::connect_to_supervisor_async;
use super::super::context::RequestServices;
use super::super::drain_state::WorkerDrainState;
use super::super::metrics::WorkerMetrics;
use crate::common::setup_panic_handler;
use crate::platform::fs::PlatformPaths;
use crate::server::UnifiedServer;
use crate::{DrainFlag, RunningFlag};
use synvoid_app_server::GranianSupervisor;
use synvoid_config::ConfigManager;
use synvoid_ipc::ipc_transport::IpcStream as AsyncIpcStream;
use synvoid_ipc::{check_ports_available, WorkerId};

#[derive(Clone)]
pub struct UnifiedServerWorkerArgs {
    pub worker_id: usize,
    pub config_path: std::path::PathBuf,
    pub supervisor_socket: std::path::PathBuf,
    pub log_level: Option<String>,
    pub upgrade_mode: bool,
    pub reuse_port: bool,
    pub worker_threads: usize,
    pub cpu_affinity: Option<usize>,
    pub total_workers: usize,
}

pub fn setup_unified_server_panic_handler() {
    let paths = PlatformPaths::new();
    let panic_path = paths
        .unified_worker_socket_path(0)
        .to_string_lossy()
        .replace(".sock", "-panic.log");
    setup_panic_handler("UNIFIED SERVER WORKER", Some(&panic_path));
}

pub fn should_skip_prebind_port_check(total_workers: usize, reuse_port: bool) -> bool {
    total_workers > 1 && reuse_port
}

pub async fn setup_worker_ipc(
    supervisor_socket: &std::path::Path,
    worker_id: &WorkerId,
) -> Result<Arc<TokioMutex<AsyncIpcStream>>, Box<dyn std::error::Error + Send + Sync>> {
    // Read IPC session key from environment (passed via temp file by supervisor)
    let signer = if let Ok(key_file) = std::env::var("SYNVOID_IPC_KEY_FILE") {
        crate::process::ipc_signed::read_ipc_key_file(&key_file)
    } else if let Ok(key_hex) = std::env::var("SYNVOID_IPC_KEY") {
        if key_hex.len() == 64 {
            let mut key = [0u8; 32];
            let mut valid = true;
            for (i, chunk) in key_hex.as_bytes().chunks(2).enumerate() {
                if chunk.len() != 2 {
                    valid = false;
                    break;
                }
                let Ok(s) = std::str::from_utf8(chunk) else {
                    valid = false;
                    break;
                };
                match u8::from_str_radix(s, 16) {
                    Ok(b) => key[i] = b,
                    Err(_) => {
                        valid = false;
                        break;
                    }
                }
            }
            if valid {
                Some(std::sync::Arc::new(crate::process::IpcSigner::new(&key)))
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    let mut stream = if let Some(signer) = signer {
        crate::process::connect_to_supervisor_signed(signer).await?
    } else {
        connect_to_supervisor_async(
            supervisor_socket,
            5,
            std::time::Duration::from_secs(2),
            "Unified server worker",
        )
        .await?
    };

    stream
        .send(&crate::process::Message::UnifiedServerWorkerStarted {
            id: *worker_id,
            pid: std::process::id(),
            timestamp: crate::process::current_timestamp(),
        })
        .await?;

    Ok(Arc::new(TokioMutex::new(stream)))
}

pub async fn setup_config(config_path: &std::path::Path) -> Arc<RwLock<ConfigManager>> {
    let mut config_manager = ConfigManager::new(config_path.to_path_buf());
    let main_config_path = config_path.join("main.toml");

    if let Err(e) = config_manager.load_main(&main_config_path) {
        tracing::warn!("Failed to load main config: {}, using defaults", e);
    }

    config_manager.discover_sites();

    Arc::new(RwLock::new(config_manager))
}

pub async fn extract_bandwidth_config(
    config: &Arc<RwLock<ConfigManager>>,
) -> (
    Option<String>,
    u32,
    bool,
    crate::metrics::bandwidth::MonthlyResetConfig,
) {
    let config_guard = config.read().await;
    let bandwidth = &config_guard.main.traffic_shaping.bandwidth;
    let reset_cfg_external = bandwidth.monthly_reset.clone();
    let reset_cfg_internal: crate::metrics::bandwidth::MonthlyResetConfig =
        serde_json::from_str(&serde_json::to_string(&reset_cfg_external).unwrap()).unwrap();
    (
        bandwidth.data_dir.clone(),
        bandwidth.retention_days,
        bandwidth.mesh_excluded_from_total,
        reset_cfg_internal,
    )
}

pub fn apply_cpu_affinity(cpu_affinity: Option<usize>, worker_id: WorkerId) {
    // Apply CPU affinity if specified
    if let Some(core) = cpu_affinity {
        #[cfg(target_os = "linux")]
        {
            use nix::sched::{sched_setaffinity, CpuSet};
            use nix::unistd::Pid;

            let mut cpuset = CpuSet::new();
            if let Err(e) = cpuset.set(core) {
                tracing::warn!("Failed to set CPU core {} in CpuSet: {}", core, e);
            } else {
                let pid = Pid::from_raw(0); // Current process
                if let Err(e) = sched_setaffinity(pid, &cpuset) {
                    tracing::warn!("Failed to set CPU affinity to core {}: {}", core, e);
                } else {
                    tracing::info!(
                        "Unified Server Worker {} pinned to CPU core {}",
                        worker_id,
                        core
                    );
                }
            }
        }
        #[cfg(all(unix, not(target_os = "linux")))]
        {
            tracing::info!(
                "CPU affinity pinning requested for core {}, but not supported on this Unix platform",
                core
            );
        }
        #[cfg(not(unix))]
        {
            tracing::warn!("CPU affinity pinning is not supported on this platform");
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (cpu_affinity, worker_id);
    }
}

pub fn start_shared_connection_heartbeat(worker_id_raw: usize) {
    // Start background heartbeat task for shared connection table
    if let Some(table) = crate::upstream::shared_state::SharedConnectionTable::get_global() {
        tokio::spawn(async move {
            loop {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                table.record_heartbeat(worker_id_raw, now);
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
    }
}

pub async fn validate_ports_or_skip_for_shared_port(
    args: &UnifiedServerWorkerArgs,
    config: &Arc<RwLock<ConfigManager>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config_guard = config.read().await;
    let main_config = &config_guard.main;

    let mut ports_to_check = Vec::new();
    let mut port_labels = std::collections::HashMap::new();

    ports_to_check.push(main_config.server.port);
    port_labels.insert(main_config.server.port, "HTTP");

    if main_config.tls.enabled {
        ports_to_check.push(main_config.tls.port);
        port_labels.insert(main_config.tls.port, "TLS");
    }

    if main_config.http3.enabled {
        ports_to_check.push(main_config.http3.port);
        port_labels.insert(main_config.http3.port, "HTTP3");
    }

    if main_config.admin.enabled {
        ports_to_check.push(main_config.admin.port);
        port_labels.insert(main_config.admin.port, "Admin");
    }

    #[cfg(feature = "mesh")]
    if let Some(ref mesh_config) = main_config.mesh {
        if mesh_config.enabled {
            ports_to_check.push(mesh_config.port);
            port_labels.insert(mesh_config.port, "Mesh");
        }
    }

    // For multi-unified-worker mode, listener creation must be the source of truth.
    // A pre-bind check can incorrectly reject valid SO_REUSEPORT shared-port startup.
    if should_skip_prebind_port_check(args.total_workers, args.reuse_port) {
        tracing::info!(
            "Skipping pre-bind port conflict check for shared-port multi-worker mode (total_workers={}, reuse_port={})",
            args.total_workers,
            args.reuse_port
        );
        return Ok(());
    }

    if let Err(e) = check_ports_available(&ports_to_check) {
        let error_msg = e.to_string();
        let unavailable: Vec<u16> = error_msg
            .split(['[', ']', ' '])
            .filter_map(|s| s.trim().parse().ok())
            .collect();

        let conflicts: Vec<String> = unavailable
            .iter()
            .map(|port| {
                port_labels
                    .get(port)
                    .map(|label| format!("{} (port {})", label, port))
                    .unwrap_or_else(|| format!("port {}", port))
            })
            .collect();

        if conflicts.is_empty() {
            tracing::error!("Port conflict detected: {}", e);
        } else {
            tracing::error!(
                "Port conflicts detected between services: {}. Other services may be affected.",
                conflicts.join(", ")
            );
        }
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            if conflicts.is_empty() {
                format!("Port conflict: {}", e)
            } else {
                conflicts.join(", ")
            },
        )));
    }
    Ok(())
}

#[derive(Clone)]
pub struct UnifiedServerWorkerState {
    pub worker_id: WorkerId,
    pub metrics: Arc<WorkerMetrics>,
    pub start_time: Instant,
    pub ipc: Arc<TokioMutex<AsyncIpcStream>>,
    pub running: RunningFlag,
    pub master_dead: RunningFlag,
    pub app_servers: Arc<RwLock<HashMap<String, Arc<GranianSupervisor>>>>,
    pub draining: DrainFlag,
    pub drain_id: Arc<std::sync::atomic::AtomicU64>,
    pub stopped_accepting: DrainFlag,
    pub drain_state: Arc<WorkerDrainState>,
    pub stop_accepting_tx: Arc<TokioMutex<Option<broadcast::Sender<()>>>>,
    pub unified_server: Arc<UnifiedServer>,
    pub task_handles: Arc<TokioMutex<Vec<JoinHandle<()>>>>,
    pub request_services: Arc<RequestServices>,
    /// Bundled data-plane services for live policy context refresh.
    pub data_plane: std::sync::Arc<super::services::DataPlaneServices>,
    /// Latest canonical trust snapshot received from Supervisor.
    #[cfg(feature = "mesh")]
    pub canonical_snapshot: std::sync::Arc<
        tokio::sync::RwLock<Option<synvoid_mesh::canonical::CanonicalTrustSnapshot>>,
    >,
    /// Task registry for structured concurrency (Iteration 62).
    pub task_registry: Arc<tokio::sync::Mutex<crate::worker::task_registry::WorkerTaskRegistry>>,
}

impl UnifiedServerWorkerState {
    /// Get the latest canonical trust snapshot, if available.
    #[cfg(feature = "mesh")]
    pub async fn get_canonical_snapshot(
        &self,
    ) -> Option<synvoid_mesh::canonical::CanonicalTrustSnapshot> {
        self.canonical_snapshot.read().await.clone()
    }
}

pub async fn wait_for_drain(
    drain_state: &WorkerDrainState,
    timeout_secs: u64,
    worker_id: &WorkerId,
    reason: &str,
) -> u64 {
    let start = Instant::now();
    let drain_timeout = Duration::from_secs(timeout_secs);
    let poll_interval = Duration::from_millis(100);

    loop {
        if start.elapsed() >= drain_timeout {
            tracing::warn!(
                "Unified Server Worker {} drain timeout reached for {}",
                worker_id,
                reason
            );
            break;
        }

        let active = drain_state.get_active_connections();
        if active == 0 {
            tracing::info!(
                "Unified Server Worker {} all connections drained for {}",
                worker_id,
                reason
            );
            break;
        }

        tracing::debug!(
            "Unified Server Worker {} waiting for {} connections to drain for {}",
            worker_id,
            active,
            reason
        );

        tokio::time::sleep(poll_interval).await;
    }

    drain_state.get_active_connections()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_wait_for_drain_immediate() {
        let drain_state = WorkerDrainState::new();
        assert_eq!(drain_state.get_active_connections(), 0);

        let worker_id = WorkerId(1);
        let remaining = wait_for_drain(&drain_state, 10, &worker_id, "test").await;
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn test_wait_for_drain_with_connections() {
        let drain_state = WorkerDrainState::new();
        drain_state.increment_active();
        drain_state.increment_active();
        drain_state.increment_active();
        drain_state.increment_active();
        drain_state.increment_active();
        assert_eq!(drain_state.get_active_connections(), 5);

        let worker_id = WorkerId(1);
        let remaining = wait_for_drain(&drain_state, 1, &worker_id, "test").await;
        assert_eq!(remaining, 5);
    }

    #[test]
    fn test_unified_server_worker_args_clone() {
        let args = UnifiedServerWorkerArgs {
            worker_id: 2,
            config_path: PathBuf::from("/custom/config"),
            supervisor_socket: PathBuf::from("/var/run/supervisor.sock"),
            log_level: Some("debug".to_string()),
            upgrade_mode: true,
            reuse_port: false,
            worker_threads: 8,
            cpu_affinity: None,
            total_workers: 1,
        };

        let cloned = args.clone();

        assert_eq!(cloned.worker_id, args.worker_id);
        assert_eq!(cloned.config_path, args.config_path);
        assert_eq!(cloned.supervisor_socket, args.supervisor_socket);
        assert_eq!(cloned.log_level, args.log_level);
        assert_eq!(cloned.upgrade_mode, args.upgrade_mode);
        assert_eq!(cloned.reuse_port, args.reuse_port);
        assert_eq!(cloned.worker_threads, args.worker_threads);
    }

    #[test]
    fn test_unified_server_worker_args_with_log_level() {
        let args = UnifiedServerWorkerArgs {
            worker_id: 3,
            config_path: PathBuf::from("config"),
            supervisor_socket: PathBuf::from("/tmp/supervisor.sock"),
            log_level: Some("trace".to_string()),
            upgrade_mode: false,
            reuse_port: true,
            worker_threads: 2,
            cpu_affinity: None,
            total_workers: 1,
        };

        assert!(args.log_level.is_some());
        assert_eq!(args.log_level.unwrap(), "trace");
    }

    #[test]
    fn test_unified_server_worker_args_thread_values() {
        let single_thread = UnifiedServerWorkerArgs {
            worker_id: 1,
            config_path: PathBuf::from("config"),
            supervisor_socket: PathBuf::from("/tmp/supervisor.sock"),
            log_level: None,
            upgrade_mode: false,
            reuse_port: true,
            worker_threads: 1,
            cpu_affinity: None,
            total_workers: 1,
        };

        let multi_thread = UnifiedServerWorkerArgs {
            worker_id: 2,
            config_path: PathBuf::from("config"),
            supervisor_socket: PathBuf::from("/tmp/supervisor.sock"),
            log_level: None,
            upgrade_mode: false,
            reuse_port: true,
            worker_threads: 16,
            cpu_affinity: None,
            total_workers: 4,
        };

        assert_eq!(single_thread.worker_threads, 1);
        assert_eq!(multi_thread.worker_threads, 16);
    }

    #[test]
    fn test_should_skip_prebind_port_check_single_worker() {
        assert!(!should_skip_prebind_port_check(1, false));
        assert!(!should_skip_prebind_port_check(1, true));
    }

    #[test]
    fn test_should_skip_prebind_port_check_multi_worker() {
        assert!(!should_skip_prebind_port_check(2, false));
        assert!(should_skip_prebind_port_check(2, true));
        assert!(should_skip_prebind_port_check(8, true));
    }
}
