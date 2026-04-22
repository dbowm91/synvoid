#![allow(dead_code)]
// SAFETY_REASON: Connection tracking for observability - reserved for debugging

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;

use crate::drain::DrainStatus;
use crate::process::ipc::WorkerId;

pub use crate::drain::WorkerConnectionInfo;

#[derive(Debug, Clone)]
pub struct ConnectionTracker {
    total_active: Arc<AtomicU64>,
    total_idle: Arc<AtomicU64>,
    by_worker: DashMap<WorkerId, WorkerConnections>,
    drain_start_time: Arc<Mutex<Option<Instant>>>,
    drain_timeout_secs: Arc<AtomicU64>,
}

#[derive(Debug, Clone)]
pub struct WorkerConnections {
    pub active: u64,
    pub idle: u64,
    pub last_updated: Instant,
}

impl Default for WorkerConnections {
    fn default() -> Self {
        Self {
            active: 0,
            idle: 0,
            last_updated: Instant::now(),
        }
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            total_active: Arc::new(AtomicU64::new(0)),
            total_idle: Arc::new(AtomicU64::new(0)),
            by_worker: DashMap::new(),
            drain_start_time: Arc::new(Mutex::new(None)),
            drain_timeout_secs: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn increment_active(&self) {
        self.total_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement_active(&self) {
        let _ = self
            .total_active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
    }

    pub fn increment_idle(&self) {
        self.total_idle.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement_idle(&self) {
        let _ = self
            .total_idle
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
    }

    pub fn update_worker_connections(&self, worker_id: WorkerId, active: u64, idle: u64) {
        let old_values = self.by_worker.insert(
            worker_id,
            WorkerConnections {
                active,
                idle,
                last_updated: Instant::now(),
            },
        );

        if let Some(old) = old_values {
            let delta_active = active as i64 - old.active as i64;
            let delta_idle = idle as i64 - old.idle as i64;

            if delta_active != 0 {
                if delta_active > 0 {
                    self.total_active
                        .fetch_add(delta_active as u64, Ordering::Relaxed);
                } else {
                    let _ =
                        self.total_active
                            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                                v.checked_sub((-delta_active) as u64)
                            });
                }
            }

            if delta_idle != 0 {
                if delta_idle > 0 {
                    self.total_idle
                        .fetch_add(delta_idle as u64, Ordering::Relaxed);
                } else {
                    let _ =
                        self.total_idle
                            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                                v.checked_sub((-delta_idle) as u64)
                            });
                }
            }
        } else {
            self.total_active.fetch_add(active, Ordering::Relaxed);
            self.total_idle.fetch_add(idle, Ordering::Relaxed);
        }
    }

    pub fn remove_worker(&self, worker_id: &WorkerId) {
        if let Some((_, connections)) = self.by_worker.remove(worker_id) {
            let _ = self
                .total_active
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    v.checked_sub(connections.active)
                });
            let _ = self
                .total_idle
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    v.checked_sub(connections.idle)
                });
        }
    }

    fn recalculate_totals(&self) {
        let mut total_active: u64 = 0;
        let mut total_idle: u64 = 0;

        for entry in self.by_worker.iter() {
            total_active += entry.active;
            total_idle += entry.idle;
        }

        self.total_active.store(total_active, Ordering::Relaxed);
        self.total_idle.store(total_idle, Ordering::Relaxed);
    }

    pub fn start_drain(&self, timeout_secs: u64) {
        let mut drain_start = self.drain_start_time.lock();
        *drain_start = Some(Instant::now());
        self.drain_timeout_secs
            .store(timeout_secs, Ordering::Relaxed);
    }

    pub fn stop_drain(&self) {
        let mut drain_start = self.drain_start_time.lock();
        *drain_start = None;
        self.drain_timeout_secs.store(0, Ordering::Relaxed);
    }

    pub fn is_draining(&self) -> bool {
        let drain_start = self.drain_start_time.lock();
        drain_start.is_some()
    }

    pub fn get_active_count(&self) -> u64 {
        self.total_active.load(Ordering::Relaxed)
    }

    pub fn get_idle_count(&self) -> u64 {
        self.total_idle.load(Ordering::Relaxed)
    }

    pub fn get_drain_status(&self) -> DrainStatus {
        let drain_start = self.drain_start_time.lock();
        let drain_timeout = self.drain_timeout_secs.load(Ordering::Relaxed);

        let (is_draining, drain_elapsed_secs) = match *drain_start {
            Some(start) => (true, Some(start.elapsed().as_secs())),
            None => (false, None),
        };

        let _drain_remaining_secs = if is_draining {
            drain_elapsed_secs.map(|elapsed| drain_timeout.saturating_sub(elapsed))
        } else {
            None
        };

        let by_worker: HashMap<usize, WorkerConnectionInfo> = self
            .by_worker
            .iter()
            .map(|entry| {
                (
                    entry.key().as_usize(),
                    WorkerConnectionInfo {
                        active: entry.active,
                        idle: entry.idle,
                    },
                )
            })
            .collect();

        DrainStatus::default()
            .with_draining(is_draining)
            .with_connections(
                self.total_active.load(Ordering::Relaxed),
                self.total_idle.load(Ordering::Relaxed),
            )
            .with_drain_start(*drain_start, drain_timeout)
            .with_worker_breakdown(by_worker)
    }

    pub fn wait_for_drain(&self, timeout_secs: u64) -> bool {
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout {
            if self.total_active.load(Ordering::Relaxed) == 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        false
    }

    pub fn get_worker_connection_count(&self, worker_id: &WorkerId) -> Option<(u64, u64)> {
        self.by_worker.get(worker_id).map(|wc| (wc.active, wc.idle))
    }

    pub fn get_all_worker_counts(&self) -> Vec<(WorkerId, u64, u64)> {
        self.by_worker
            .iter()
            .map(|entry| (*entry.key(), entry.active, entry.idle))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_tracking() {
        let tracker = ConnectionTracker::new();

        assert_eq!(tracker.get_active_count(), 0);

        tracker.increment_active();
        assert_eq!(tracker.get_active_count(), 1);

        tracker.decrement_active();
        assert_eq!(tracker.get_active_count(), 0);
    }

    #[test]
    fn test_worker_connections() {
        let tracker = ConnectionTracker::new();
        let worker_id = WorkerId(1);

        tracker.update_worker_connections(worker_id.clone(), 5, 2);

        assert_eq!(tracker.get_active_count(), 5);
        assert_eq!(tracker.get_idle_count(), 2);

        let (active, idle) = tracker.get_worker_connection_count(&worker_id).unwrap();
        assert_eq!(active, 5);
        assert_eq!(idle, 2);
    }

    #[test]
    fn test_drain_status() {
        let tracker = ConnectionTracker::new();

        assert!(!tracker.is_draining());

        tracker.start_drain(30);
        assert!(tracker.is_draining());

        let status = tracker.get_drain_status();
        assert!(status.is_draining);
        assert_eq!(status.drain_remaining_secs, Some(30));

        tracker.stop_drain();
        assert!(!tracker.is_draining());
    }
}
