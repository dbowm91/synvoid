// Submodule: CpuWorkerState, CpuTaskLimiter, CompressionTask, CpuTaskPermit.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::Mutex as TokioMutex;

use crate::{DrainFlag, RunningFlag};
use synvoid_config::ConfigManager;
use synvoid_ipc::ipc_transport::IpcStream as AsyncIpcStream;
use synvoid_static_files::minifier;
use synvoid_upload::yara_scanner::YaraScanner;

#[derive(Clone)]
pub struct CpuWorkerArgs {
    pub worker_id: usize,
    pub config_path: std::path::PathBuf,
    pub supervisor_socket: std::path::PathBuf,
    pub cpu_worker_socket: std::path::PathBuf,
    pub log_level: Option<String>,
    pub ipc_key: Option<String>,
}

#[derive(Clone)]
pub struct CpuWorkerState {
    pub worker_id: usize,
    pub running: RunningFlag,
    pub stop_background_tasks: DrainFlag,
    pub ipc: Arc<TokioMutex<AsyncIpcStream>>,
    pub config_manager: Arc<std::sync::RwLock<ConfigManager>>,
    pub minifier_caches: Arc<std::sync::RwLock<HashMap<String, Arc<minifier::MinifierCache>>>>,
    pub compression_queue: Arc<std::sync::RwLock<Vec<CompressionTask>>>,
    pub cpu_task_limiter: Arc<CpuTaskLimiter>,
    pub yara_scanner: Option<Arc<YaraScanner>>,
}

impl CpuWorkerState {
    pub fn get_cache_stats(&self) -> (u64, u64) {
        let mut total_hits = 0u64;
        let mut total_misses = 0u64;

        if let Ok(caches) = self.minifier_caches.read() {
            for cache in caches.values() {
                total_hits += cache.cache_hits();
                total_misses += cache.cache_misses();
            }
        }

        (total_hits, total_misses)
    }
}

#[derive(Clone)]
pub struct CompressionTask {
    pub site_id: String,
    pub path: String,
    pub encoding: String,
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    pub queued_at: Instant,
}

#[derive(Debug, Clone, Copy)]
pub struct CpuTaskLimits {
    pub max_active_global: usize,
    pub max_queue_global: usize,
    pub max_active_per_site: usize,
    pub max_queue_per_site: usize,
    pub max_payload_bytes: usize,
    pub max_output_bytes: usize,
}

#[derive(Default)]
pub struct CpuTaskBackpressureState {
    pub active_global: usize,
    pub queued_global: usize,
    pub active_by_site: HashMap<String, usize>,
    pub queued_by_site: HashMap<String, usize>,
}

pub struct CpuTaskLimiter {
    pub limits: CpuTaskLimits,
    pub state: Mutex<CpuTaskBackpressureState>,
}

pub struct CpuTaskPermit {
    pub limiter: Arc<CpuTaskLimiter>,
    pub site_id: Option<String>,
}

impl Drop for CpuTaskPermit {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.limiter.state.lock() {
            guard.active_global = guard.active_global.saturating_sub(1);
            if let Some(site_id) = self.site_id.as_ref() {
                if let Some(site_active) = guard.active_by_site.get_mut(site_id) {
                    *site_active = site_active.saturating_sub(1);
                    if *site_active == 0 {
                        guard.active_by_site.remove(site_id);
                    }
                }
            }
        }
    }
}

impl CpuTaskLimiter {
    pub fn new(limits: CpuTaskLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(CpuTaskBackpressureState::default()),
        }
    }

    pub fn try_acquire(&self, site_id: Option<&str>) -> Result<(), &'static str> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| "CPU task limiter lock poisoned")?;

        guard.queued_global = guard.queued_global.saturating_add(1);
        if guard.queued_global > self.limits.max_queue_global {
            guard.queued_global = guard.queued_global.saturating_sub(1);
            return Err("Global CPU task queue limit exceeded");
        }

        if let Some(site) = site_id {
            let site_queued = guard.queued_by_site.entry(site.to_string()).or_default();
            *site_queued = site_queued.saturating_add(1);
            if *site_queued > self.limits.max_queue_per_site {
                *site_queued = site_queued.saturating_sub(1);
                if *site_queued == 0 {
                    guard.queued_by_site.remove(site);
                }
                guard.queued_global = guard.queued_global.saturating_sub(1);
                return Err("Per-site CPU task queue limit exceeded");
            }
        }

        if guard.active_global >= self.limits.max_active_global {
            if let Some(site) = site_id {
                if let Some(site_queued) = guard.queued_by_site.get_mut(site) {
                    *site_queued = site_queued.saturating_sub(1);
                    if *site_queued == 0 {
                        guard.queued_by_site.remove(site);
                    }
                }
            }
            guard.queued_global = guard.queued_global.saturating_sub(1);
            return Err("Global CPU task active limit exceeded");
        }

        if let Some(site) = site_id {
            if guard.active_by_site.get(site).copied().unwrap_or(0)
                >= self.limits.max_active_per_site
            {
                if let Some(site_queued) = guard.queued_by_site.get_mut(site) {
                    *site_queued = site_queued.saturating_sub(1);
                    if *site_queued == 0 {
                        guard.queued_by_site.remove(site);
                    }
                }
                guard.queued_global = guard.queued_global.saturating_sub(1);
                return Err("Per-site CPU task active limit exceeded");
            }
        }

        guard.active_global = guard.active_global.saturating_add(1);
        if let Some(site) = site_id {
            let site_active = guard.active_by_site.entry(site.to_string()).or_default();
            *site_active = site_active.saturating_add(1);
            if let Some(site_queued) = guard.queued_by_site.get_mut(site) {
                *site_queued = site_queued.saturating_sub(1);
                if *site_queued == 0 {
                    guard.queued_by_site.remove(site);
                }
            }
        }
        guard.queued_global = guard.queued_global.saturating_sub(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_cpu_worker_args_creation() {
        let args = CpuWorkerArgs {
            worker_id: 1,
            config_path: PathBuf::from("/etc/synvoid"),
            supervisor_socket: PathBuf::from("/tmp/supervisor.sock"),
            cpu_worker_socket: PathBuf::from("/tmp/static.sock"),
            log_level: Some("debug".to_string()),
            ipc_key: Some("test-key".to_string()),
        };

        assert_eq!(args.worker_id, 1);
        assert_eq!(args.config_path, PathBuf::from("/etc/synvoid"));
        assert_eq!(
            args.supervisor_socket,
            PathBuf::from("/tmp/supervisor.sock")
        );
        assert_eq!(args.cpu_worker_socket, PathBuf::from("/tmp/static.sock"));
        assert_eq!(args.log_level, Some("debug".to_string()));
        assert_eq!(args.ipc_key, Some("test-key".to_string()));
    }

    #[test]
    fn test_cpu_worker_args_default_log_level() {
        let args = CpuWorkerArgs {
            worker_id: 0,
            config_path: PathBuf::from("/etc/synvoid"),
            supervisor_socket: PathBuf::from("/tmp/supervisor.sock"),
            cpu_worker_socket: PathBuf::from("/tmp/static.sock"),
            log_level: None,
            ipc_key: None,
        };

        assert!(args.log_level.is_none());
        assert!(args.ipc_key.is_none());
    }

    #[test]
    fn test_compression_task_creation() {
        let task = CompressionTask {
            site_id: "test-site".to_string(),
            path: "/index.html".to_string(),
            encoding: "gzip".to_string(),
            queued_at: Instant::now(),
        };

        assert_eq!(task.site_id, "test-site");
        assert_eq!(task.path, "/index.html");
        assert_eq!(task.encoding, "gzip");
    }
}
