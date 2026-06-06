use std::sync::Arc;
use std::time::Duration;

use synvoid_core::metrics::MetricsSink;

use crate::types::WorkerMetrics;

#[derive(Debug, Clone)]
pub struct WorkerMetricsSink {
    inner: Arc<WorkerMetrics>,
}

impl WorkerMetricsSink {
    pub fn new(metrics: Arc<WorkerMetrics>) -> Self {
        Self { inner: metrics }
    }

    pub fn inner(&self) -> &Arc<WorkerMetrics> {
        &self.inner
    }
}

impl MetricsSink for WorkerMetricsSink {
    fn record_request_started(&self) {
        self.inner.record_request_start();
    }

    fn record_request_finished(&self, _status: u16, elapsed: Duration) {
        let latency_ms = elapsed.as_millis() as u64;
        self.inner.record_request_end(latency_ms);
    }

    fn record_request_body_bytes(&self, _bytes: usize) {
        // WorkerMetrics does not track per-call body bytes yet
    }

    fn record_response_body_bytes(&self, _bytes: usize) {
        // WorkerMetrics does not track per-call body bytes yet
    }

    fn record_upstream_error(&self, _kind: &str) {
        self.inner.record_error();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_metrics_sink_start_increments_total() {
        let wm = Arc::new(WorkerMetrics::default());
        let sink = WorkerMetricsSink::new(wm.clone());

        sink.record_request_started();

        assert_eq!(
            wm.total_requests.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            wm.current_concurrent
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn worker_metrics_sink_finish_decrements_concurrent() {
        let wm = Arc::new(WorkerMetrics::default());
        let sink = WorkerMetricsSink::new(wm.clone());

        sink.record_request_started();
        sink.record_request_finished(200, Duration::from_millis(42));

        assert_eq!(
            wm.current_concurrent
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            wm.total_latency_ms
                .load(std::sync::atomic::Ordering::Relaxed),
            42
        );
        assert_eq!(
            wm.request_count.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn worker_metrics_sink_upstream_error_increments_errors() {
        let wm = Arc::new(WorkerMetrics::default());
        let sink = WorkerMetricsSink::new(wm.clone());

        sink.record_upstream_error("timeout");

        assert_eq!(wm.errors.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn worker_metrics_sink_body_bytes_are_noop() {
        let wm = Arc::new(WorkerMetrics::default());
        let sink = WorkerMetricsSink::new(wm.clone());

        sink.record_request_body_bytes(1024);
        sink.record_response_body_bytes(2048);

        assert_eq!(
            wm.body_buffering_bytes_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn worker_metrics_sink_clones_share_state() {
        let wm = Arc::new(WorkerMetrics::default());
        let sink1 = WorkerMetricsSink::new(wm.clone());
        let sink2 = sink1.clone();

        sink1.record_request_started();
        sink2.record_upstream_error("conn_refused");

        assert_eq!(
            wm.total_requests.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(wm.errors.load(std::sync::atomic::Ordering::Relaxed), 1);
    }
}
