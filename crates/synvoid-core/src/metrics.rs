use std::time::Duration;

pub trait MetricsSink: Send + Sync + 'static {
    fn record_request_started(&self) {}
    fn record_request_finished(&self, _status: u16, _elapsed: Duration) {}
    fn record_request_body_bytes(&self, _bytes: usize) {}
    fn record_response_body_bytes(&self, _bytes: usize) {}
    fn record_upstream_error(&self, _kind: &str) {}
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoopMetricsSink;

impl MetricsSink for NoopMetricsSink {}
