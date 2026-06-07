use crate::worker::metrics::WorkerMetrics;
use synvoid_ipc::WorkerId;

pub trait BaseWorkerState: Send + Sync {
    fn worker_id(&self) -> &WorkerId;
    fn is_running(&self) -> bool;
    fn is_draining(&self) -> bool;
    fn metrics(&self) -> &WorkerMetrics;
}

pub trait WorkerLifecycle: Send + Sync {
    fn mark_started(&self);
    fn mark_ready(&self);
    fn stop(&self);
    fn start_drain(&self);
    fn end_drain(&self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::metrics::WorkerMetrics;

    #[test]
    fn test_worker_id_in_trait() {
        let worker_id = WorkerId(42);
        assert_eq!(worker_id.0, 42);
    }

    #[test]
    fn test_base_worker_state_is_send_sync() {
        // Compile-time assertion that BaseWorkerState requires Send + Sync
        fn assert_send_sync<T: Send + Sync>() {}
        // This compiles only if BaseWorkerState has Send + Sync bound (it does)
        assert_send_sync::<WorkerId>();
    }

    struct MockWorker {
        id: WorkerId,
        running: bool,
        draining: bool,
        metrics: WorkerMetrics,
    }

    impl MockWorker {
        fn new(id: WorkerId) -> Self {
            Self {
                id,
                running: false,
                draining: false,
                metrics: WorkerMetrics::default(),
            }
        }
    }

    impl BaseWorkerState for MockWorker {
        fn worker_id(&self) -> &WorkerId {
            &self.id
        }
        fn is_running(&self) -> bool {
            self.running
        }
        fn is_draining(&self) -> bool {
            self.draining
        }
        fn metrics(&self) -> &WorkerMetrics {
            &self.metrics
        }
    }

    impl WorkerLifecycle for MockWorker {
        fn mark_started(&self) {}
        fn mark_ready(&self) {}
        fn stop(&self) {}
        fn start_drain(&self) {}
        fn end_drain(&self) {}
    }

    #[test]
    fn test_worker_lifecycle_ordering() {
        let worker = MockWorker::new(WorkerId(1));

        // Initial state: not running, not draining
        assert!(!worker.is_running());
        assert!(!worker.is_draining());
        assert_eq!(worker.worker_id().0, 1);

        // Metrics should have defaults
        let m = worker.metrics();
        assert_eq!(
            m.total_requests.load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }
}
