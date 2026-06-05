use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use sysinfo::System;

use crate::config::ConfigManager;
use crate::process::{
    connect_to_supervisor, current_timestamp, IpcStream, Message, RequestLogPayload, WorkerId,
    WorkerMetricsPayload,
};
use crate::{DrainFlag, RunningFlag};

pub use crate::common::setup_panic_handler;

pub fn collect_current_process_usage() -> (u64, f64) {
    let mut system = System::new_all();
    system.refresh_all();

    let Some(pid) = sysinfo::get_current_pid().ok() else {
        return (0, 0.0);
    };

    let Some(process) = system.process(pid) else {
        return (0, 0.0);
    };

    (process.memory(), process.cpu_usage() as f64)
}

pub struct IpcConnection {
    stream: Arc<Mutex<IpcStream>>,
}

impl IpcConnection {
    /// Connect to the supervisor IPC endpoint.
    ///
    /// **WARNING:** This creates an unsigned connection. The caller must ensure
    /// this is not used for privileged operations. Prefer the async transport
    /// with `connect_to_supervisor_async_signed` for new code.
    pub fn connect(socket_path: &Path) -> Result<Self, std::io::Error> {
        let stream = connect_to_supervisor(socket_path)?;
        Ok(Self {
            stream: Arc::new(Mutex::new(stream)),
        })
    }

    pub fn send(&self, msg: &Message) -> Result<(), std::io::Error> {
        let mut stream = self.stream.lock();
        stream.send(msg)
    }

    pub fn try_recv(&self) -> Result<Option<Message>, std::io::Error> {
        let mut stream = self.stream.lock();
        stream.try_recv()
    }

    pub fn stream(&self) -> Arc<Mutex<IpcStream>> {
        self.stream.clone()
    }
}

pub struct WorkerLifecycle {
    worker_id: WorkerId,
    ipc: Arc<Mutex<IpcStream>>,
    running: RunningFlag,
    start_time: Instant,
}

impl WorkerLifecycle {
    pub fn new(worker_id: WorkerId, ipc: Arc<Mutex<IpcStream>>, running: RunningFlag) -> Self {
        Self {
            worker_id,
            ipc,
            running,
            start_time: Instant::now(),
        }
    }

    pub fn with_running_flag(worker_id: WorkerId, ipc: Arc<Mutex<IpcStream>>) -> Self {
        Self {
            worker_id,
            ipc,
            running: RunningFlag::new(),
            start_time: Instant::now(),
        }
    }

    pub fn send_started(&self, pid: u32, port: Option<u16>) -> Result<(), std::io::Error> {
        let mut ipc = self.ipc.lock();
        ipc.send(&Message::WorkerStarted {
            id: self.worker_id,
            pid,
            port: port.unwrap_or(0),
            timestamp: current_timestamp(),
        })
    }

    pub fn send_ready(&self) -> Result<(), std::io::Error> {
        let mut ipc = self.ipc.lock();
        ipc.send(&Message::WorkerReady { id: self.worker_id })
    }

    pub fn send_heartbeat(&self, metrics: &WorkerMetricsPayload) -> Result<(), std::io::Error> {
        let mut ipc = self.ipc.lock();
        ipc.send(&Message::WorkerHeartbeat {
            id: self.worker_id,
            timestamp: current_timestamp(),
            metrics: metrics.clone(),
        })
    }

    pub fn send_request_log(&self, log: RequestLogPayload) -> Result<(), std::io::Error> {
        let mut ipc = self.ipc.lock();
        ipc.send(&Message::WorkerRequestLog {
            id: self.worker_id,
            log,
        })
    }

    pub fn send_shutdown_complete(&self) -> Result<(), std::io::Error> {
        let mut ipc = self.ipc.lock();
        ipc.send(&Message::WorkerShutdownComplete { id: self.worker_id })
    }

    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    pub fn is_running(&self) -> bool {
        self.running.is_running()
    }

    pub fn stop(&self) {
        self.running.stop();
    }

    pub fn running_flag(&self) -> &RunningFlag {
        &self.running
    }

    pub fn try_recv_message(&self) -> Result<Option<Message>, std::io::Error> {
        let mut ipc = self.ipc.lock();
        ipc.try_recv()
    }
}

pub fn spawn_heartbeat_loop(
    lifecycle: WorkerLifecycle,
    metrics: Arc<super::metrics::WorkerMetrics>,
    interval_secs: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let heartbeat_interval = Duration::from_secs(interval_secs);
        let mut interval = tokio::time::interval(heartbeat_interval);
        let mut next_heartbeat_at = Instant::now() + heartbeat_interval;

        loop {
            interval.tick().await;

            if !lifecycle.is_running() {
                break;
            }

            let lag_ms = Instant::now()
                .saturating_duration_since(next_heartbeat_at)
                .as_millis() as u64;
            metrics.record_event_loop_lag_ms(lag_ms);
            let (memory_bytes, cpu_percent) = collect_current_process_usage();
            metrics.record_process_usage(memory_bytes, cpu_percent);
            next_heartbeat_at += heartbeat_interval;

            let uptime = lifecycle.uptime_secs();
            let payload = metrics.to_payload(uptime);

            if let Err(e) = lifecycle.send_heartbeat(&payload) {
                tracing::warn!("Failed to send heartbeat: {}", e);
            }
        }
    })
}

pub fn handle_shutdown_message(
    message: &Message,
    lifecycle: &WorkerLifecycle,
    on_shutdown: Option<&dyn Fn()>,
) -> bool {
    match message {
        Message::MasterShutdown {
            graceful,
            timeout_secs,
        } => {
            tracing::info!(
                "Worker {} received shutdown signal (graceful: {}, timeout: {}s)",
                lifecycle.worker_id,
                graceful,
                timeout_secs
            );

            if let Some(callback) = on_shutdown {
                callback();
            }

            lifecycle.stop();

            if let Err(e) = lifecycle.send_shutdown_complete() {
                tracing::warn!(
                    "Worker {} failed to send shutdown complete: {}",
                    lifecycle.worker_id,
                    e
                );
            }
            true
        }
        Message::MasterHealthCheck { timestamp } => {
            let now = current_timestamp();
            const MAX_AGE_SECS: u64 = 30;
            const MAX_FUTURE_SECS: u64 = 5;
            if *timestamp > now.saturating_sub(MAX_AGE_SECS) && *timestamp <= now + MAX_FUTURE_SECS
            {
                if let Err(e) = lifecycle.ipc.lock().send(&Message::HealthCheckAck {
                    timestamp: *timestamp,
                }) {
                    tracing::warn!(
                        "Worker {} failed to send health check ack: {}",
                        lifecycle.worker_id,
                        e
                    );
                }
            } else {
                tracing::warn!(
                    "Worker {} rejected health check with invalid timestamp: {} (now: {})",
                    lifecycle.worker_id,
                    timestamp,
                    now
                );
            }
            false
        }
        Message::MasterConfigReload { config_path } => {
            tracing::info!(
                "Worker {} received config reload: {} (restart required for this worker type)",
                lifecycle.worker_id,
                config_path
            );
            false
        }
        _ => false,
    }
}

use crate::process::ipc_transport::IpcStream as AsyncIpcStream;
use tokio::sync::Mutex as TokioMutex;

#[derive(Clone)]
pub struct AsyncWorkerState {
    pub worker_id: WorkerId,
    pub ipc: Arc<TokioMutex<AsyncIpcStream>>,
    pub running: RunningFlag,
    pub draining: DrainFlag,
    pub start_time: Instant,
}

impl AsyncWorkerState {
    pub fn new(worker_id: WorkerId, ipc: Arc<TokioMutex<AsyncIpcStream>>) -> Self {
        Self {
            worker_id,
            ipc,
            running: RunningFlag::new(),
            draining: DrainFlag::new(),
            start_time: Instant::now(),
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
}

pub fn load_config(config_path: &std::path::Path) -> ConfigManager {
    let mut config_manager = ConfigManager::new(config_path.to_path_buf());
    let main_config_path = config_path.join("main.toml");

    if let Err(e) = config_manager.load_main(&main_config_path) {
        tracing::warn!("Failed to load main config: {}, using defaults", e);
    }

    config_manager.discover_sites();
    config_manager
}
