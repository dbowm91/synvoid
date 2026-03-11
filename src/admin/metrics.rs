use crate::admin::alerting::AlertManager;
use crate::admin::state::{AdminState, AggregatedMetrics, SystemResources};
use crate::process::{ProcessManager, SiteMetricsPayload};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::System;
use tokio::time::interval;

const LATENCY_SAMPLE_SIZE: usize = 1000;

fn calculate_percentile(sorted: &[f64], percentile: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 * percentile) as usize).min(sorted.len() - 1);
    sorted[idx]
}

pub async fn start_metrics_publisher(
    admin_state: Arc<AdminState>,
    process_manager: Arc<ProcessManager>,
    alert_manager: Option<Arc<AlertManager>>,
    mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
) {
    let mut ticker = interval(Duration::from_secs(1));
    let mut alert_ticker = interval(Duration::from_secs(60));
    let mut last_total_requests: u64 = 0;
    let mut last_total_blocked: u64 = 0;
    let mut last_update = Instant::now();
    
    let mut sys = System::new_all();
    let mut last_sys_refresh = Instant::now();
    let mut latest_metrics: Option<AggregatedMetrics> = None;

    tokio::select! {
        _ = shutdown_rx.recv() => {
            tracing::info!("Metrics publisher received shutdown signal");
            return;
        }
        _ = async {
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        // Existing 1-second metrics collection
                    }
                    _ = alert_ticker.tick() => {
                        if let Some(ref am) = alert_manager {
                            if let Some(ref metrics) = latest_metrics {
                                let events = am.check_and_notify(metrics).await;
                                for event in events {
                                    tracing::info!("Alert triggered: {} - {}", event.rule_name, event.message);
                                }
                            }
                        }
                        continue;
                    }
                }

                let worker_metrics = process_manager.get_worker_metrics();
                
                let mut total_requests: u64 = 0;
                let mut total_blocked: u64 = 0;
                let mut total_challenged: u64 = 0;
                let mut total_proxied: u64 = 0;
                let mut total_errors: u64 = 0;
                let mut current_concurrent: u64 = 0;
                let mut peak_concurrent: u64 = 0;
                let mut total_latency_ms: f64 = 0.0;
                let mut request_count: u64 = 0;
                let mut all_latency_samples: Vec<f64> = Vec::new();
                let mut total_memory_bytes: u64 = 0;
                let mut total_cpu_percent: f64 = 0.0;
                let mut _total_static_cache_hits: u64 = 0;
                let mut _total_static_cache_misses: u64 = 0;

                let mut blocked_by_type: std::collections::HashMap<String, u64> = std::collections::HashMap::new();

                for (_worker_id, metrics) in &worker_metrics {
                    total_requests += metrics.total_requests;
                    total_blocked += metrics.blocked;
                    total_challenged += metrics.challenged;
                    total_proxied += metrics.proxied;
                    total_errors += metrics.errors;
                    current_concurrent += metrics.current_concurrent;
                    peak_concurrent = peak_concurrent.max(metrics.peak_concurrent);
                    total_latency_ms += metrics.avg_latency_ms * metrics.total_requests as f64;
                    request_count += metrics.total_requests;
                    total_memory_bytes += metrics.memory_bytes;
                    total_cpu_percent += metrics.cpu_percent;
                    _total_static_cache_hits += metrics.static_cache_hits;
                    _total_static_cache_misses += metrics.static_cache_misses;

                    for (attack_type, count) in &metrics.blocked_by_type {
                        *blocked_by_type.entry(attack_type.clone()).or_insert(0) += count;
                    }

                    if metrics.p50_latency_ms > 0.0 {
                        all_latency_samples.push(metrics.p50_latency_ms);
                    }
                    if metrics.p95_latency_ms > 0.0 {
                        all_latency_samples.push(metrics.p95_latency_ms);
                    }
                    if metrics.p99_latency_ms > 0.0 {
                        all_latency_samples.push(metrics.p99_latency_ms);
                    }
                }
                
                let (static_cache_hits, static_cache_misses) = process_manager.get_static_worker_cache_stats();
                _total_static_cache_hits += static_cache_hits;
                _total_static_cache_misses += static_cache_misses;

                let elapsed = last_update.elapsed().as_secs_f64();
                last_update = Instant::now();

                let requests_delta = total_requests.saturating_sub(last_total_requests);
                let blocked_delta = total_blocked.saturating_sub(last_total_blocked);
                
                let requests_per_second = if elapsed > 0.0 { requests_delta as f64 / elapsed } else { 0.0 };
                let blocked_per_second = if elapsed > 0.0 { blocked_delta as f64 / elapsed } else { 0.0 };

                last_total_requests = total_requests;
                last_total_blocked = total_blocked;

                let avg_latency_ms = if request_count > 0 {
                    total_latency_ms / request_count as f64
                } else {
                    0.0
                };

                all_latency_samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                let p50_latency_ms = calculate_percentile(&all_latency_samples, 0.50);
                let p95_latency_ms = calculate_percentile(&all_latency_samples, 0.95);
                let p99_latency_ms = calculate_percentile(&all_latency_samples, 0.99);

                let healthy_backends = worker_metrics.len();
                let unhealthy_backends = 0;

                let uptime_secs = admin_state.uptime();

                let cpu_percent = if !worker_metrics.is_empty() {
                    total_cpu_percent / worker_metrics.len() as f64
                } else {
                    0.0
                };

                if last_sys_refresh.elapsed() > Duration::from_secs(5) {
                    sys.refresh_all();
                    last_sys_refresh = Instant::now();
                }
                let memory_used_mb = sys.used_memory() / 1024 / 1024;
                let memory_total_mb = sys.total_memory() / 1024 / 1024;
                let cpus = sys.cpus();
                let sys_cpu = if !cpus.is_empty() {
                    cpus.iter().map(|c| c.cpu_usage()).sum::<f32>() / cpus.len() as f32
                } else {
                    0.0
                };

                let metrics = AggregatedMetrics {
                    total_requests,
                    blocked: total_blocked,
                    challenged: total_challenged,
                    proxied: total_proxied,
                    errors: total_errors,
                    current_concurrent,
                    peak_concurrent,
                    avg_latency_ms,
                    p50_latency_ms,
                    p95_latency_ms,
                    p99_latency_ms,
                    uptime_secs,
                    memory_bytes: total_memory_bytes,
                    cpu_percent,
                    requests_per_second,
                    blocked_per_second,
                    healthy_backends,
                    unhealthy_backends,
                    blocked_by_type,
                };

                latest_metrics = Some(metrics.clone());

                admin_state.update_metrics(metrics.clone());
                admin_state.add_metrics_to_history(metrics.clone());

                let mut aggregated_site_metrics: std::collections::HashMap<String, SiteMetricsPayload> = std::collections::HashMap::new();

                for (_worker_id, worker_metrics) in &worker_metrics {
                    for (site_id, site_payload) in &worker_metrics.per_site {
                        let entry = aggregated_site_metrics.entry(site_id.clone()).or_insert_with(|| SiteMetricsPayload {
                            total_requests: 0,
                            blocked: 0,
                            challenged: 0,
                            proxied: 0,
                            errors: 0,
                            current_concurrent: 0,
                            peak_concurrent: 0,
                            avg_latency_ms: 0.0,
                            p50_latency_ms: 0.0,
                            p95_latency_ms: 0.0,
                            p99_latency_ms: 0.0,
                            blocked_by_type: std::collections::HashMap::new(),
                            upstream_healthy: true,
                            proxy_cache_hits: 0,
                            proxy_cache_misses: 0,
                            static_cache_hits: 0,
                            static_cache_misses: 0,
                        });
                        entry.total_requests += site_payload.total_requests;
                        entry.blocked += site_payload.blocked;
                        entry.challenged += site_payload.challenged;
                        entry.proxied += site_payload.proxied;
                        entry.errors += site_payload.errors;
                        entry.current_concurrent += site_payload.current_concurrent;
                        entry.peak_concurrent = entry.peak_concurrent.max(site_payload.peak_concurrent);
                        entry.upstream_healthy = entry.upstream_healthy && site_payload.upstream_healthy;
                        
                        if site_payload.total_requests > 0 {
                            let prev_weighted = entry.avg_latency_ms * (entry.total_requests - site_payload.total_requests) as f64;
                            entry.avg_latency_ms = if entry.total_requests > 0 {
                                (prev_weighted + site_payload.avg_latency_ms * site_payload.total_requests as f64) / entry.total_requests as f64
                            } else {
                                site_payload.avg_latency_ms
                            };
                        }

                        for (attack_type, count) in &site_payload.blocked_by_type {
                            *entry.blocked_by_type.entry(attack_type.clone()).or_insert(0) += count;
                        }
                    }
                }

                admin_state.update_site_metrics(aggregated_site_metrics);

                let time_validation_errors = crate::mesh::transport::get_time_validation_error_count();
                let resources = SystemResources {
                    memory_used_mb,
                    memory_total_mb,
                    cpu_usage_percent: sys_cpu,
                    time_validation_errors,
                };
                admin_state.update_system_resources(resources);

                let json = serde_json::to_string(&metrics).unwrap_or_default();
                let _ = admin_state.metrics_broadcaster.broadcast(json);

                crate::admin::state::set_current_connections(current_concurrent);
            }
        } => {}
    }
}
