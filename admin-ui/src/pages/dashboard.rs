use std::collections::HashMap;
use yew::prelude::*;
use yew_router::prelude::*;

use crate::app::Route;
use crate::components::charts::{Gauge, MultiSeriesLineChart, StackedAreaChart};
use crate::components::realtime_header::RealtimeHeader;
use crate::hooks::use_websocket::{use_websocket_or_poll, UseWebSocketState};
use crate::services::ApiService;
use crate::types::{RealtimeMetrics, SiteStats, SystemStats};

fn export_to_json(data: &serde_json::Value, filename: &str) {
    let json = serde_json::to_string_pretty(data).unwrap_or_default();
    let blob = web_sys::Blob::new_with_str_sequence(&js_sys::Array::of1(&json.into())).unwrap();
    let url = web_sys::Url::create_object_url_with_blob(&blob).unwrap();
    let window = web_sys::window().unwrap();
    let document = window.document().unwrap();
    let a = document.create_element("a").unwrap();
    a.set_attribute("href", &url).unwrap();
    a.set_attribute("download", filename).unwrap();
    let _ = a.dispatch_event(&web_sys::MouseEvent::new("click").unwrap());
}

fn export_to_csv(headers: &[&str], rows: &[Vec<String>], filename: &str) {
    let mut csv = headers.join(",");
    csv.push('\n');
    for row in rows {
        csv.push_str(&row.join(","));
        csv.push('\n');
    }
    let blob = web_sys::Blob::new_with_str_sequence(&js_sys::Array::of1(&csv.into())).unwrap();
    let url = web_sys::Url::create_object_url_with_blob(&blob).unwrap();
    let window = web_sys::window().unwrap();
    let document = window.document().unwrap();
    let a = document.create_element("a").unwrap();
    a.set_attribute("href", &url).unwrap();
    a.set_attribute("download", filename).unwrap();
    let _ = a.dispatch_event(&web_sys::MouseEvent::new("click").unwrap());
}

fn format_number(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.1}B", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn format_bytes(n: u64) -> String {
    const TB: u64 = 1024 * 1024 * 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;
    const MB: u64 = 1024 * 1024;
    const KB: u64 = 1024;

    if n >= TB {
        format!("{:.2} TB", n as f64 / TB as f64)
    } else if n >= GB {
        format!("{:.2} GB", n as f64 / GB as f64)
    } else if n >= MB {
        format!("{:.2} MB", n as f64 / MB as f64)
    } else if n >= KB {
        format!("{:.2} KB", n as f64 / KB as f64)
    } else {
        format!("{} B", n)
    }
}

fn format_rate(n: u64) -> String {
    const GBPS: u64 = 1024 * 1024 * 1024;
    const MBPS: u64 = 1024 * 1024;
    const KBPS: u64 = 1024;

    if n >= GBPS {
        format!("{:.2} GB/s", n as f64 / GBPS as f64)
    } else if n >= MBPS {
        format!("{:.2} MB/s", n as f64 / MBPS as f64)
    } else if n >= KBPS {
        format!("{:.2} KB/s", n as f64 / KBPS as f64)
    } else {
        format!("{} B/s", n)
    }
}

fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    if days > 0 {
        format!("{}d {}h", days, hours)
    } else if hours > 0 {
        format!("{}h {}m", hours, minutes)
    } else {
        format!("{}m", minutes)
    }
}

fn window_to_seconds(window: &str) -> u64 {
    match window {
        "1m" => 60,
        "5m" => 300,
        "15m" => 900,
        "1h" => 3600,
        "6h" => 21600,
        "24h" => 86400,
        _ => 300,
    }
}

#[function_component]
pub fn Dashboard() -> Html {
    let selected_window = use_state(|| "5m".to_string());
    let show_custom_picker = use_state(|| false);
    let custom_start = use_state(|| String::new());
    let custom_end = use_state(|| String::new());
    let stats = use_state(|| None::<SystemStats>);
    let sites = use_state(|| Vec::<SiteStats>::new());
    let history = use_state(|| Vec::<RealtimeMetrics>::new());
    let historical_data = use_state(|| None::<Vec<RealtimeMetrics>>);
    let cache_stats = use_state(|| None::<crate::types::CacheStats>);
    let bandwidth = use_state(|| None::<crate::types::BandwidthPayload>);
    let blocking_history = use_state(|| Vec::<std::collections::HashMap<String, u64>>::new());

    let (ws_state, _) = use_websocket_or_poll::<RealtimeMetrics>(
        "ws://localhost:8081/api/ws/metrics",
        "/api/stats/summary",
        5000,
    );

    {
        let selected_window = selected_window.clone();
        let historical_data = historical_data.clone();
        use_effect_with(selected_window.clone(), move |window| {
            let historical_data = historical_data.clone();
            let window = (*window).clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let seconds = window_to_seconds(&window);
                match api.get_stats_history(Some(seconds)).await {
                    Ok(data) => historical_data.set(Some(data)),
                    Err(e) => tracing::error!("Failed to fetch history: {}", e),
                }
            });
            || {}
        });
    }

    if let UseWebSocketState::Connected(metrics) = &ws_state {
        let mut new_history = (*history).clone();
        new_history.push(metrics.clone());
        if new_history.len() > 60 {
            new_history.remove(0);
        }
        history.set(new_history);

        let mut new_blocking = (*blocking_history).clone();
        new_blocking.push(metrics.blocked_by_type.clone());
        if new_blocking.len() > 60 {
            new_blocking.remove(0);
        }
        blocking_history.set(new_blocking);
    }

    {
        let stats = stats.clone();
        let sites = sites.clone();
        let cache_stats = cache_stats.clone();
        let bandwidth = bandwidth.clone();
        use_effect_with((), move |_| {
            let stats = stats.clone();
            let sites = sites.clone();
            let cache_stats = cache_stats.clone();
            let bandwidth = bandwidth.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.get_stats_summary().await {
                    Ok(s) => stats.set(Some(s)),
                    Err(e) => tracing::error!("Failed to fetch stats: {}", e),
                }
                match api.get_stats_sites().await {
                    Ok(s) => sites.set(s),
                    Err(e) => tracing::error!("Failed to fetch sites: {}", e),
                }
                match api.get_cache_stats().await {
                    Ok(c) => cache_stats.set(Some(c)),
                    Err(e) => tracing::error!("Failed to fetch cache stats: {}", e),
                }
                match api.get_bandwidth().await {
                    Ok(b) => bandwidth.set(Some(b)),
                    Err(e) => tracing::error!("Failed to fetch bandwidth: {}", e),
                }
            });
            Box::new(|| {})
        });
    }

    let request_data: HashMap<String, Vec<f64>> = {
        let hist = (*historical_data).clone();
        let h = (*history).clone();

        let data_to_use = hist.unwrap_or(h);

        let mut map = HashMap::new();
        let requests: Vec<f64> = data_to_use.iter().map(|m| m.requests_per_second).collect();
        let blocked: Vec<f64> = data_to_use.iter().map(|m| m.blocked_per_second).collect();
        map.insert(
            "Requests".to_string(),
            if requests.is_empty() {
                vec![0.0; 12]
            } else {
                requests
            },
        );
        map.insert(
            "Blocked".to_string(),
            if blocked.is_empty() {
                vec![0.0; 12]
            } else {
                blocked
            },
        );
        map
    };

    let blocking_data: HashMap<String, Vec<f64>> = {
        let hist = (*historical_data).clone();
        let h = (*history).clone();
        let blocking = (*blocking_history).clone();

        let metrics_data = hist.unwrap_or(h);

        if !blocking.is_empty() {
            let mut by_type: std::collections::HashMap<String, Vec<u64>> =
                std::collections::HashMap::new();

            for snapshot in &blocking {
                for (attack_type, count) in snapshot {
                    by_type.entry(attack_type.clone()).or_default().push(*count);
                }
            }

            let mut map: HashMap<String, Vec<f64>> = HashMap::new();
            for (attack_type, counts) in by_type {
                let rates: Vec<f64> = counts
                    .windows(2)
                    .map(|w| (w[1] as i64 - w[0] as i64).max(0) as f64)
                    .collect();
                let display_data = if rates.len() < 12 {
                    let mut padded = vec![0.0; 12 - rates.len()];
                    padded.extend(rates);
                    padded
                } else {
                    rates
                };
                map.insert(attack_type, display_data);
            }
            map
        } else if !metrics_data.is_empty() {
            let mut by_type: std::collections::HashMap<String, Vec<u64>> =
                std::collections::HashMap::new();

            for metrics in &metrics_data {
                for (attack_type, count) in &metrics.blocked_by_type {
                    by_type.entry(attack_type.clone()).or_default().push(*count);
                }
            }

            let mut map: HashMap<String, Vec<f64>> = HashMap::new();
            for (attack_type, counts) in by_type {
                let rates: Vec<f64> = counts
                    .windows(2)
                    .map(|w| (w[1] as i64 - w[0] as i64).max(0) as f64)
                    .collect();
                let display_data = if rates.len() < 12 {
                    let mut padded = vec![0.0; 12 - rates.len()];
                    padded.extend(rates);
                    padded
                } else {
                    rates
                };
                map.insert(attack_type, display_data);
            }
            map
        } else {
            HashMap::new()
        }
    };

    let labels: Vec<String> = (1..=12).map(|i| format!("{}m", i)).collect();
    let current = stats.as_ref();
    let cpu = current.map(|s| s.cpu_usage_percent as f64).unwrap_or(0.0);
    let mem_pct = current
        .map(|s| (s.memory_used_mb as f64 / s.memory_total_mb as f64) * 100.0)
        .unwrap_or(0.0);

    let on_window_change = {
        let selected_window = selected_window.clone();
        Callback::from(move |window: String| {
            selected_window.set(window);
        })
    };

    let export_json = {
        let stats = stats.clone();
        Callback::from(move |_| {
            if let Some(s) = (*stats).as_ref() {
                let data = serde_json::json!({
                    "uptime_secs": s.uptime_secs,
                    "total_requests": s.total_requests,
                    "requests_per_second": s.requests_per_second,
                    "blocked_per_second": s.blocked_per_second,
                    "active_connections": s.active_connections,
                    "memory_used_mb": s.memory_used_mb,
                    "memory_total_mb": s.memory_total_mb,
                    "cpu_usage_percent": s.cpu_usage_percent,
                    "sites_loaded": s.sites_loaded,
                    "healthy_backends": s.healthy_backends,
                    "unhealthy_backends": s.unhealthy_backends,
                    "blocked_total": s.blocked_total,
                    "challenged_total": s.challenged_total,
                    "proxied_total": s.proxied_total,
                    "errors_total": s.errors_total,
                    "avg_latency_ms": s.avg_latency_ms,
                    "p50_latency_ms": s.p50_latency_ms,
                    "p95_latency_ms": s.p95_latency_ms,
                    "p99_latency_ms": s.p99_latency_ms,
                    "peak_concurrent": s.peak_concurrent,
                });
                export_to_json(&data, "maluwaf-stats.json");
            }
        })
    };

    let export_csv = {
        let stats = stats.clone();
        Callback::from(move |_| {
            if let Some(s) = (*stats).as_ref() {
                let headers = ["Metric", "Value"];
                let rows = vec![
                    vec!["Uptime (secs)".to_string(), s.uptime_secs.to_string()],
                    vec!["Total Requests".to_string(), s.total_requests.to_string()],
                    vec![
                        "Requests/sec".to_string(),
                        format!("{:.2}", s.requests_per_second),
                    ],
                    vec!["Blocked Total".to_string(), s.blocked_total.to_string()],
                    vec![
                        "Active Connections".to_string(),
                        s.active_connections.to_string(),
                    ],
                    vec!["Memory Used (MB)".to_string(), s.memory_used_mb.to_string()],
                    vec![
                        "Memory Total (MB)".to_string(),
                        s.memory_total_mb.to_string(),
                    ],
                    vec![
                        "CPU Usage (%)".to_string(),
                        format!("{:.1}", s.cpu_usage_percent),
                    ],
                    vec!["Sites Loaded".to_string(), s.sites_loaded.to_string()],
                    vec![
                        "Healthy Backends".to_string(),
                        s.healthy_backends.to_string(),
                    ],
                    vec![
                        "Unhealthy Backends".to_string(),
                        s.unhealthy_backends.to_string(),
                    ],
                    vec![
                        "Avg Latency (ms)".to_string(),
                        format!("{:.2}", s.avg_latency_ms),
                    ],
                    vec![
                        "p95 Latency (ms)".to_string(),
                        format!("{:.2}", s.p95_latency_ms),
                    ],
                    vec![
                        "p99 Latency (ms)".to_string(),
                        format!("{:.2}", s.p99_latency_ms),
                    ],
                    vec!["Peak Concurrent".to_string(), s.peak_concurrent.to_string()],
                ];
                export_to_csv(&headers, &rows, "maluwaf-stats.csv");
            }
        })
    };

    html! {
        <div>
            <h1 class="text-2xl font-bold mb-6">{ "Dashboard" }</h1>

            <RealtimeHeader />

            <div class="mb-6 flex justify-between items-center">
                <div class="flex gap-2">
                    <WindowButton label="1m" active={*selected_window == "1m"} on_click={on_window_change.clone()} />
                    <WindowButton label="5m" active={*selected_window == "5m"} on_click={on_window_change.clone()} />
                    <WindowButton label="15m" active={*selected_window == "15m"} on_click={on_window_change.clone()} />
                    <WindowButton label="1h" active={*selected_window == "1h"} on_click={on_window_change.clone()} />
                    <WindowButton label="6h" active={*selected_window == "6h"} on_click={on_window_change.clone()} />
                    <WindowButton label="24h" active={*selected_window == "24h"} on_click={on_window_change.clone()} />
                </div>
                <div class="flex gap-2">
                    <button
                        onclick={export_json}
                        class="px-3 py-2 bg-tertiary text-secondary rounded-lg hover:text-primary text-sm"
                    >
                        { "Export JSON" }
                    </button>
                    <button
                        onclick={export_csv}
                        class="px-3 py-2 bg-tertiary text-secondary rounded-lg hover:text-primary text-sm"
                    >
                        { "Export CSV" }
                    </button>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                <div class="bg-secondary rounded-lg p-6 border border-default">
                    <h3 class="text-lg font-semibold mb-4">{ "Request Traffic" }</h3>
                    <MultiSeriesLineChart
                        data_series={request_data.clone()}
                        labels={labels.clone()}
                        height="280px"
                        show_legend={true}
                        time_window={Some((*selected_window).clone())}
                    />
                </div>

                <div class="bg-secondary rounded-lg p-6 border border-default">
                    <h3 class="text-lg font-semibold mb-4">{ "Blocking by Type" }</h3>
                    <StackedAreaChart
                        data_series={blocking_data.clone()}
                        labels={labels.clone()}
                        height="280px"
                        time_window={Some((*selected_window).clone())}
                    />
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
                <div class="bg-secondary rounded-lg p-6 border border-default">
                    <h3 class="text-lg font-semibold mb-4">{ "Latency (ms)" }</h3>
                    <div class="space-y-3">
                        <StatRow label="Avg" value={format!("{:.1}", current.map(|s| s.avg_latency_ms).unwrap_or(0.0))} />
                        <StatRow label="p50" value={format!("{:.1}", current.map(|s| s.p50_latency_ms).unwrap_or(0.0))} />
                        <StatRow label="p95" value={format!("{:.1}", current.map(|s| s.p95_latency_ms).unwrap_or(0.0))} />
                        <StatRow label="p99" value={format!("{:.1}", current.map(|s| s.p99_latency_ms).unwrap_or(0.0))} />
                    </div>
                </div>

                <div class="bg-secondary rounded-lg p-6 border border-default">
                    <h3 class="text-lg font-semibold mb-4">{ "System Resources" }</h3>
                    <div class="flex justify-around">
                        <Gauge value={cpu} max={100.0} label="CPU" unit="%" />
                        <Gauge value={mem_pct} max={100.0} label="Memory" unit="%" />
                    </div>
                    <div class="mt-4 text-sm text-secondary">
                        <div class="flex justify-between">
                            <span>{ "Memory:" }</span>
                            <span>{ format!("{}/{} MB", current.map(|s| s.memory_used_mb).unwrap_or(0), current.map(|s| s.memory_total_mb).unwrap_or(0)) }</span>
                        </div>
                    </div>
                </div>

                <div class="bg-secondary rounded-lg p-6 border border-default">
                    <h3 class="text-lg font-semibold mb-4">{ "Quick Stats" }</h3>
                    <div class="space-y-3">
                        <StatRow label="Total Requests" value={format_number(current.map(|s| s.total_requests).unwrap_or(0))} />
                        <StatRow label="Blocked" value={format_number(current.map(|s| s.blocked_total).unwrap_or(0))} />
                        <StatRow label="Active Connections" value={current.map(|s| s.active_connections.to_string()).unwrap_or_else(|| "0".to_string())} />
                        <StatRow label="Uptime" value={format_uptime(current.map(|s| s.uptime_secs).unwrap_or(0))} />
                    </div>
                </div>

                <div class="bg-secondary rounded-lg p-6 border border-default">
                    <h3 class="text-lg font-semibold mb-4">{ "Cache Performance" }</h3>
                    <div class="space-y-3">
                        <StatRow label="Proxy Cache Hits" value={format_number(cache_stats.as_ref().map(|c| c.proxy_cache_hits).unwrap_or(0))} />
                        <StatRow label="Proxy Cache Misses" value={format_number(cache_stats.as_ref().map(|c| c.proxy_cache_misses).unwrap_or(0))} />
                        <div class="flex justify-between items-center py-2 border-b border-default">
                            <span class="text-secondary text-sm">{ "Proxy Cache Hit Rate" }</span>
                            <span class={if cache_stats.as_ref().map(|c| c.proxy_cache_hit_rate).unwrap_or(0.0) > 70.0 { "text-green-500 font-medium" } else if cache_stats.as_ref().map(|c| c.proxy_cache_hit_rate).unwrap_or(0.0) > 40.0 { "text-yellow-500 font-medium" } else { "text-red-500 font-medium" }}>
                                { format!("{:.1}%", cache_stats.as_ref().map(|c| c.proxy_cache_hit_rate).unwrap_or(0.0)) }
                            </span>
                        </div>
                        <StatRow label="Static Cache Hits" value={format_number(cache_stats.as_ref().map(|c| c.static_cache_hits).unwrap_or(0))} />
                        <StatRow label="Static Cache Misses" value={format_number(cache_stats.as_ref().map(|c| c.static_cache_misses).unwrap_or(0))} />
                        <div class="flex justify-between items-center py-2 border-b border-default">
                            <span class="text-secondary text-sm">{ "Static Cache Hit Rate" }</span>
                            <span class={if cache_stats.as_ref().map(|c| c.static_cache_hit_rate).unwrap_or(0.0) > 70.0 { "text-green-500 font-medium" } else if cache_stats.as_ref().map(|c| c.static_cache_hit_rate).unwrap_or(0.0) > 40.0 { "text-yellow-500 font-medium" } else { "text-red-500 font-medium" }}>
                                { format!("{:.1}%", cache_stats.as_ref().map(|c| c.static_cache_hit_rate).unwrap_or(0.0)) }
                            </span>
                        </div>
                    </div>
                </div>

                <div class="bg-secondary rounded-lg p-6 border border-default">
                    <h3 class="text-lg font-semibold mb-4">{ "Bandwidth Usage" }</h3>
                    <div class="space-y-3">
                        <StatRow label="Current Ingress" value={format_rate(bandwidth.as_ref().map(|b| b.ingress_rate_bps).unwrap_or(0))} />
                        <StatRow label="Current Egress" value={format_rate(bandwidth.as_ref().map(|b| b.egress_rate_bps).unwrap_or(0))} />
                        <div class="border-t border-default my-2"></div>
                        <div class="text-sm text-secondary mb-1">{ "This Month" }</div>
                        <StatRow label="Ingress" value={format_bytes(bandwidth.as_ref().map(|b| b.monthly_bytes_received).unwrap_or(0))} />
                        <StatRow label="Egress" value={format_bytes(bandwidth.as_ref().map(|b| b.monthly_bytes_sent).unwrap_or(0))} />
                        <div class="flex justify-between items-center py-2">
                            <span class="text-secondary text-sm">{ "Period" }</span>
                            <span class="text-primary text-sm">
                                { format!("{} days remaining", bandwidth.as_ref().map(|b| b.monthly_period.days_remaining).unwrap_or(0)) }
                            </span>
                        </div>
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div class="bg-secondary rounded-lg p-6 border border-default">
                    <h3 class="text-lg font-semibold mb-4">{ "Sites Status" }</h3>
                    <div class="space-y-3">
                        if sites.is_empty() {
                            <div class="text-secondary text-sm">{ "No sites configured" }</div>
                        } else {
                            { for sites.iter().map(|site| {
                                let site_id = site.site_id.clone();
                                html! {
                                    <Link<Route>
                                        to={Route::SiteDetail { id: site_id.clone() }}
                                        classes="block"
                                    >
                                        <SiteStatusItem
                                            domain={site.domains.first().unwrap_or(&site.site_id).clone()}
                                            healthy={site.upstream_healthy}
                                            requests={format_number((site.requests_per_second * 60.0) as u64)}
                                            blocked={format_number(site.blocked_requests)}
                                            bytes_received={site.bytes_received}
                                            bytes_sent={site.bytes_sent}
                                            proxied_bytes_sent={site.proxied_bytes_sent}
                                            proxied_bytes_received={site.proxied_bytes_received}
                                            mesh_bytes_sent={site.mesh_bytes_sent}
                                            mesh_bytes_received={site.mesh_bytes_received}
                                        />
                                    </Link<Route>>
                                }
                            })}
                        }
                    </div>
                </div>

                <div class="bg-secondary rounded-lg p-6 border border-default">
                    <h3 class="text-lg font-semibold mb-4">{ "Backend Health" }</h3>
                    <div class="space-y-3">
                        <div class="flex justify-between items-center py-2 border-b border-default">
                            <span class="text-secondary text-sm">{ "Healthy Backends" }</span>
                            <span class="text-green-500 font-medium">{ current.map(|s| s.healthy_backends.to_string()).unwrap_or_else(|| "0".to_string()) }</span>
                        </div>
                        <div class="flex justify-between items-center py-2 border-b border-default">
                            <span class="text-secondary text-sm">{ "Unhealthy Backends" }</span>
                            <span class="text-red-500 font-medium">{ current.map(|s| s.unhealthy_backends.to_string()).unwrap_or_else(|| "0".to_string()) }</span>
                        </div>
                        <div class="flex justify-between items-center py-2 border-b border-default">
                            <span class="text-secondary text-sm">{ "Sites Loaded" }</span>
                            <span class="text-primary font-medium">{ current.map(|s| s.sites_loaded.to_string()).unwrap_or_else(|| "0".to_string()) }</span>
                        </div>
                        <div class="flex justify-between items-center py-2 border-b border-default">
                            <span class="text-secondary text-sm">{ "Peak Concurrent" }</span>
                            <span class="text-primary font-medium">{ current.map(|s| s.peak_concurrent.to_string()).unwrap_or_else(|| "0".to_string()) }</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct WindowButtonProps {
    label: String,
    active: bool,
    on_click: Callback<String>,
}

#[function_component]
fn WindowButton(props: &WindowButtonProps) -> Html {
    let onclick = {
        let label = props.label.clone();
        let on_click = props.on_click.clone();
        Callback::from(move |_| {
            on_click.emit(label.clone());
        })
    };

    let class = if props.active {
        "px-4 py-2 bg-blue-600 text-white rounded-lg text-sm"
    } else {
        "px-4 py-2 bg-tertiary text-secondary rounded-lg hover:text-primary text-sm"
    };

    html! {
        <button onclick={onclick} class={class}>
            { &props.label }
        </button>
    }
}

#[derive(Properties, PartialEq)]
struct StatRowProps {
    label: String,
    value: String,
}

#[function_component]
fn StatRow(props: &StatRowProps) -> Html {
    html! {
        <div class="flex justify-between items-center py-2 border-b border-default last:border-b-0">
            <span class="text-secondary text-sm">{ &props.label }</span>
            <span class="text-primary font-medium">{ &props.value }</span>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct SiteStatusItemProps {
    domain: String,
    healthy: bool,
    requests: String,
    blocked: String,
    bytes_received: u64,
    bytes_sent: u64,
    proxied_bytes_sent: u64,
    proxied_bytes_received: u64,
    mesh_bytes_sent: u64,
    mesh_bytes_received: u64,
}

#[function_component]
fn SiteStatusItem(props: &SiteStatusItemProps) -> Html {
    let expanded = use_state(|| false);

    let toggle_expanded = {
        let expanded = expanded.clone();
        Callback::from(move |_| {
            expanded.set(!*expanded);
        })
    };

    let status_class = if props.healthy {
        "bg-green-500"
    } else {
        "bg-red-500"
    };
    let status_text = if props.healthy {
        "Healthy"
    } else {
        "Unhealthy"
    };

    let total_ingress =
        props.bytes_received + props.proxied_bytes_received + props.mesh_bytes_received;
    let total_egress = props.bytes_sent + props.proxied_bytes_sent + props.mesh_bytes_sent;

    html! {
        <div>
            <div class="flex items-center justify-between py-3 border-b border-default last:border-b-0 cursor-pointer" onclick={toggle_expanded}>
                <div class="flex items-center gap-3">
                    <span class={format!("w-2 h-2 rounded-full {}", status_class)} />
                    <span class="text-primary">{ &props.domain }</span>
                </div>
                <div class="flex items-center gap-4 text-sm">
                    <span class="text-secondary">{ format!("{} req", props.requests) }</span>
                    <span class="text-red-500">{ format!("{} blocked", props.blocked) }</span>
                    <span class="text-secondary text-xs">{ status_text }</span>
                </div>
            </div>
            if *expanded {
                <div class="bg-tertiary p-3 border-b border-default">
                    <div class="grid grid-cols-2 gap-4 text-sm">
                        <div>
                            <div class="text-secondary text-xs mb-1">{ "Ingress" }</div>
                            <div class="font-medium">{ format_bytes(total_ingress) }</div>
                            <div class="text-xs text-secondary mt-1 space-y-1">
                                <div class="flex justify-between">
                                    <span>{ "Client:" }</span>
                                    <span>{ format_bytes(props.bytes_received) }</span>
                                </div>
                                <div class="flex justify-between">
                                    <span>{ "Proxied:" }</span>
                                    <span>{ format_bytes(props.proxied_bytes_received) }</span>
                                </div>
                                <div class="flex justify-between">
                                    <span>{ "Mesh:" }</span>
                                    <span>{ format_bytes(props.mesh_bytes_received) }</span>
                                </div>
                            </div>
                        </div>
                        <div>
                            <div class="text-secondary text-xs mb-1">{ "Egress" }</div>
                            <div class="font-medium">{ format_bytes(total_egress) }</div>
                            <div class="text-xs text-secondary mt-1 space-y-1">
                                <div class="flex justify-between">
                                    <span>{ "Response:" }</span>
                                    <span>{ format_bytes(props.bytes_sent) }</span>
                                </div>
                                <div class="flex justify-between">
                                    <span>{ "Proxied:" }</span>
                                    <span>{ format_bytes(props.proxied_bytes_sent) }</span>
                                </div>
                                <div class="flex justify-between">
                                    <span>{ "Mesh:" }</span>
                                    <span>{ format_bytes(props.mesh_bytes_sent) }</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            }
        </div>
    }
}
