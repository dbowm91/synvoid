pub mod bandwidth;
pub mod collection;
pub mod health;
pub mod payloads;
pub mod types;

pub use bandwidth::{
    get_global_bandwidth_tracker, BandwidthPayload, BandwidthProtocol, BandwidthTracker,
    EgressDirection,
};
pub use collection::*;
pub use payloads::*;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_cache_counter_increments() {
        let initial_hits = get_proxy_cache_hits();
        let initial_misses = get_proxy_cache_misses();

        record_proxy_cache_hit();
        record_proxy_cache_hit();
        record_proxy_cache_miss();

        assert_eq!(get_proxy_cache_hits(), initial_hits + 2);
        assert_eq!(get_proxy_cache_misses(), initial_misses + 1);
    }

    #[test]
    fn test_static_cache_counter_increments() {
        let initial_hits = get_static_cache_hits();
        let initial_misses = get_static_cache_misses();

        record_static_cache_hit();
        record_static_cache_miss();
        record_static_cache_miss();

        assert_eq!(get_static_cache_hits(), initial_hits + 1);
        assert_eq!(get_static_cache_misses(), initial_misses + 2);
    }

    #[test]
    fn test_dropped_events_counter_increments() {
        let initial_tls = get_dropped_tls_reload_events();
        let initial_threat = get_dropped_threat_level_events();
        let initial_process = get_dropped_process_events();
        let initial_worker = get_dropped_worker_events();

        record_dropped_tls_reload_event();
        record_dropped_threat_level_event();
        record_dropped_process_event();
        record_dropped_worker_event();

        assert_eq!(get_dropped_tls_reload_events(), initial_tls + 1);
        assert_eq!(get_dropped_threat_level_events(), initial_threat + 1);
        assert_eq!(get_dropped_process_events(), initial_process + 1);
        assert_eq!(get_dropped_worker_events(), initial_worker + 1);
    }

    #[test]
    fn test_site_metrics_counter_increments() {
        let metrics = SiteMetrics::default();
        metrics.record_request_start();
        metrics.record_request_end(100);
        metrics.record_blocked();
        metrics.record_error();

        assert_eq!(
            metrics
                .total_requests
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics
                .request_count
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics.blocked.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(metrics.errors.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn test_worker_metrics_request_lifecycle() {
        let metrics = WorkerMetrics::default();
        metrics.record_request_start();
        metrics.record_request_end(150);
        metrics.record_request_queue_time_ms(12);
        metrics.record_inline_cpu_phase_time_ms(WorkerInlineCpuPhase::RequestPreparation, 8);
        metrics.record_body_buffering_bytes(2048);
        metrics.set_active_connections(7);
        metrics.set_offload_counters(11, 13, 17);
        metrics.set_offload_fallbacks(19);
        let initial_static_cache_hits = get_static_cache_hits();
        let initial_static_cache_misses = get_static_cache_misses();
        record_static_cache_hit();
        record_static_cache_miss();
        metrics.record_process_usage(123_456, 37.5);

        let payload = metrics.to_payload(42);

        assert_eq!(metrics.total_requests(), 1);
        assert_eq!(metrics.avg_latency_ms(), 150.0);
        assert_eq!(payload.request_queue_time_ms.avg_ms, 12.0);
        assert_eq!(
            payload.inline_cpu_phase_times_ms["request_preparation"].avg_ms,
            8.0
        );
        assert_eq!(payload.body_buffering_bytes_total, 2048);
        assert_eq!(payload.active_connections, 7);
        assert_eq!(payload.offload_submissions_total, 11);
        assert_eq!(payload.offload_timeouts_total, 13);
        assert_eq!(payload.offload_rejections_total, 17);
        assert_eq!(payload.offload_fallbacks_total, 19);
        assert_eq!(payload.static_cache_hits, initial_static_cache_hits + 1);
        assert_eq!(payload.static_cache_misses, initial_static_cache_misses + 1);
        assert_eq!(payload.memory_bytes, 123_456);
        assert_eq!(payload.cpu_percent, 37.5);
    }
}
