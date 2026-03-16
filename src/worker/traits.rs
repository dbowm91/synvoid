use crate::process::WorkerId;
use crate::worker::metrics::WorkerMetrics;

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

    #[test]
    fn test_worker_id_in_trait() {
        let worker_id = WorkerId(42);
        assert_eq!(worker_id.0, 42);
    }
}
