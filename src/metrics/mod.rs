pub mod bandwidth;
pub mod payloads;
pub mod collection;
pub mod types;

pub use bandwidth::{
    get_global_bandwidth_tracker, BandwidthPayload, BandwidthProtocol, BandwidthTracker,
    EgressDirection,
};
pub use payloads::*;
pub use types::*;
pub use collection::*;

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

        assert_eq!(metrics.total_requests.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(metrics.request_count.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(metrics.blocked.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(metrics.errors.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn test_worker_metrics_request_lifecycle() {
        let metrics = WorkerMetrics::default();
        metrics.record_request_start();
        metrics.record_request_end(150);
        
        assert_eq!(metrics.total_requests(), 1);
        assert_eq!(metrics.avg_latency_ms(), 150.0);
    }
}
