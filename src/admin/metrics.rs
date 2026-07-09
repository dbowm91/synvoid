use crate::admin::alerting::AlertManager;
use crate::admin::state::{AdminState, AggregatedMetrics, SystemResources};
use crate::metrics::payloads::{HealthStatus, SiteMetricsPayload};
use crate::process::ProcessManager;
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::System;
use tokio::time::interval;

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
    let mut latest_system_resources: Option<SystemResources> = None;

    tokio::select! {
        _ = shutdown_rx.recv() => {
            tracing::info!("Metrics publisher received shutdown signal");
        }
        _ = async {
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                    }
                    _ = alert_ticker.tick() => {
                        admin_state.cleanup_expired_csrf_tokens();
                        crate::admin::auth::AUTH_RATE_LIMITER.cleanup_expired();
                        if let Some(ref am) = alert_manager {
                            if let (Some(metrics), Some(sys_res)) = (latest_metrics.as_ref(), latest_system_resources.as_ref()) {
                                let threat_level = admin_state.threat_level_manager().map(|m| m.get_level().as_u8());
                                let events = am.check_and_notify(metrics, sys_res, threat_level).await;
                                for event in events {
                                    tracing::info!("Alert triggered: {} - {}", event.rule_name, event.message);
                                }
                            }
                        }
                        continue;
                    }
                }

                let worker_metrics = process_manager.get_worker_metrics();
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);

                let mut total_requests: u64 = 0;
                let mut total_blocked: u64 = 0;
                let mut total_challenged: u64 = 0;
                let mut total_proxied: u64 = 0;
                let mut total_errors: u64 = 0;
                let mut current_concurrent: u64 = 0;
                let mut peak_concurrent: u64 = 0;
                let mut total_latency_ms: f64 = 0.0;
                let mut request_count: u64 = 0;
                let mut total_memory_bytes: u64 = 0;
                let mut total_cpu_percent: f64 = 0.0;
                let mut _total_static_cache_hits: u64 = 0;
                let mut _total_static_cache_misses: u64 = 0;
                let mut healthy_workers: usize = 0;
                let mut unhealthy_workers: usize = 0;

                let mut blocked_by_type: std::collections::HashMap<String, u64> = std::collections::HashMap::new();

                for (worker_id, metrics) in &worker_metrics {
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

                    if process_manager.is_worker_running(worker_id) {
                        healthy_workers += 1;
                    } else {
                        unhealthy_workers += 1;
                    }
                }

                let (static_cache_hits, static_cache_misses) = process_manager.get_cpu_worker_cache_stats();
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

                let mut p50_latency_ms = 0.0;
                let mut p95_latency_ms = 0.0;
                let mut p99_latency_ms = 0.0;
                if !worker_metrics.is_empty() {
                    let total_worker_latency_ms: f64 = worker_metrics
                        .iter()
                        .map(|(_, m)| m.avg_latency_ms * m.total_requests as f64)
                        .sum();
                    let total_worker_requests: u64 = worker_metrics
                        .iter()
                        .map(|(_, m)| m.total_requests)
                        .sum();
                    if total_worker_requests > 0 {
                        let global_avg = total_worker_latency_ms / total_worker_requests as f64;
                        p50_latency_ms = global_avg;
                        p95_latency_ms = global_avg * 1.2;
                        p99_latency_ms = global_avg * 1.5;
                    }
                }

                let mut total_healthy_backends: usize = 0;
                let mut total_unhealthy_backends: usize = 0;
                let mut total_backends: usize = 0;
                for (_worker_id, worker_metrics) in &worker_metrics {
                    for site_payload in worker_metrics.per_site.values() {
                        total_healthy_backends = total_healthy_backends.saturating_add(site_payload.healthy_backends);
                        total_unhealthy_backends = total_unhealthy_backends.saturating_add(site_payload.unhealthy_backends);
                        total_backends = total_backends.saturating_add(site_payload.total_backends);
                    }
                }

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
                    healthy_backends: total_healthy_backends,
                    unhealthy_backends: total_unhealthy_backends,
                    healthy_workers,
                    unhealthy_workers,
                    blocked_by_type,
                    metrics_timestamp_ms: now_ms,
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
                            blocked_by_type: std::collections::HashMap::<String, u64>::new(),
                            upstream_healthy: HealthStatus::Unknown,
                            proxy_cache_hits: 0,
                            proxy_cache_misses: 0,
                            static_cache_hits: 0,
                            static_cache_misses: 0,
                            bytes_received: 0,
                            bytes_sent: 0,
                            proxied_bytes_sent: 0,
                            proxied_bytes_received: 0,
                            mesh_bytes_sent: 0,
                            mesh_bytes_received: 0,
                            healthy_backends: 0,
                            unhealthy_backends: 0,
                            total_backends: 0,
                            metrics_timestamp_ms: now_ms,
                        });

                        let prev_total = entry.total_requests;
                        entry.total_requests += site_payload.total_requests;
                        entry.blocked += site_payload.blocked;
                        entry.challenged += site_payload.challenged;
                        entry.proxied += site_payload.proxied;
                        entry.errors += site_payload.errors;
                        entry.current_concurrent += site_payload.current_concurrent;
                        entry.peak_concurrent = entry.peak_concurrent.max(site_payload.peak_concurrent);

                        match site_payload.upstream_healthy {
                            HealthStatus::Healthy => {
                                entry.upstream_healthy = if entry.upstream_healthy == HealthStatus::Unknown {
                                    HealthStatus::Healthy
                                } else {
                                    entry.upstream_healthy
                                };
                            }
                            HealthStatus::Unhealthy => {
                                entry.upstream_healthy = HealthStatus::Unhealthy;
                            }
                            HealthStatus::Unknown => {}
                        }

                        if site_payload.total_requests > 0 && prev_total > 0 {
                            let prev_weighted = entry.avg_latency_ms * prev_total as f64;
                            entry.avg_latency_ms = if entry.total_requests > 0 {
                                (prev_weighted + site_payload.avg_latency_ms * site_payload.total_requests as f64) / entry.total_requests as f64
                            } else {
                                site_payload.avg_latency_ms
                            };
                        } else if site_payload.total_requests > 0 {
                            entry.avg_latency_ms = site_payload.avg_latency_ms;
                        }

                        entry.p50_latency_ms = site_payload.p50_latency_ms;
                        entry.p95_latency_ms = site_payload.p95_latency_ms;
                        entry.p99_latency_ms = site_payload.p99_latency_ms;

                        for (attack_type, count) in &site_payload.blocked_by_type {
                            *entry.blocked_by_type.entry(attack_type.clone()).or_insert(0) += count;
                        }

                        entry.bytes_received += site_payload.bytes_received;
                        entry.bytes_sent += site_payload.bytes_sent;
                        entry.proxied_bytes_sent += site_payload.proxied_bytes_sent;
                        entry.proxied_bytes_received += site_payload.proxied_bytes_received;
                        entry.mesh_bytes_sent += site_payload.mesh_bytes_sent;
                        entry.mesh_bytes_received += site_payload.mesh_bytes_received;

                        entry.healthy_backends = entry.healthy_backends.saturating_add(site_payload.healthy_backends);
                        entry.unhealthy_backends = entry.unhealthy_backends.saturating_add(site_payload.unhealthy_backends);
                        entry.total_backends = entry.total_backends.saturating_add(site_payload.total_backends);
                        entry.metrics_timestamp_ms = now_ms;
                    }
                }

                admin_state.update_site_metrics(aggregated_site_metrics);

                let time_validation_errors = {
                    #[cfg(feature = "mesh")]
                    {
                        crate::mesh::transport::get_time_validation_error_count()
                    }
                    #[cfg(not(feature = "mesh"))]
                    {
                        0
                    }
                };
                let resources = SystemResources {
                    memory_used_mb,
                    memory_total_mb,
                    cpu_usage_percent: sys_cpu,
                    time_validation_errors,
                };
                latest_system_resources = Some(resources.clone());
                admin_state.update_system_resources(resources);

                let json = serde_json::to_string(&metrics).unwrap_or_default();
                admin_state.metrics.metrics_broadcaster.broadcast(json);

                crate::admin::state::set_current_connections(current_concurrent);
            }
        } => {}
    }
}
