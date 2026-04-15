use std::collections::HashMap;
use yew::prelude::*;
use yew_router::prelude::*;

use crate::app::Route;
use crate::components::charts::Gauge;
use crate::hooks::use_websocket::{use_websocket_or_poll, UseWebSocketState};
use crate::services::ApiService;
use crate::types::{RealtimeMetrics, SiteStats};

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

#[derive(Properties, PartialEq)]
pub struct SiteDetailProps {
    pub id: String,
}

#[function_component]
pub fn SiteDetail(props: &SiteDetailProps) -> Html {
    let site_id = props.id.clone();
    let site_stats = use_state(|| None::<SiteStats>);
    let sites_list = use_state(|| Vec::<SiteStats>::new());
    let error = use_state(|| None as Option<String>);

    let (ws_state, _) = use_websocket_or_poll::<RealtimeMetrics>(
        "ws://localhost:8081/api/ws/metrics",
        "/api/stats/summary",
        5000,
    );

    {
        let site_stats = site_stats.clone();
        let sites_list = sites_list.clone();
        let error = error.clone();
        let site_id = site_id.clone();

        use_effect_with((), move |_| {
            let site_stats = site_stats.clone();
            let sites_list = sites_list.clone();
            let error = error.clone();
            let site_id = site_id.clone();

            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();

                match api.get_stats_sites().await {
                    Ok(sites) => {
                        sites_list.set(sites.clone());
                        if let Some(site) = sites.iter().find(|s| s.site_id == site_id) {
                            site_stats.set(Some(site.clone()));
                        }
                    }
                    Err(e) => error.set(Some(e)),
                }
            });

            || {}
        });
    }

    if let UseWebSocketState::Connected(_metrics) = &ws_state {
        let sites = (*sites_list).clone();
        if let Some(site) = sites.iter().find(|s| s.site_id == site_id) {
            site_stats.set(Some(site.clone()));
        }
    }

    let current = site_stats.as_ref();
    let primary_domain = current
        .and_then(|s| s.domains.first().cloned())
        .unwrap_or_else(|| site_id.clone());

    html! {
        <div>
            <div class="flex items-center gap-4 mb-6">
                <Link<Route>
                    to={Route::Sites}
                    classes="p-2 hover:bg-tertiary rounded-lg transition"
                >
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" />
                    </svg>
                </Link<Route>>
                <div>
                    <h1 class="text-2xl font-bold">{ primary_domain }</h1>
                    <p class="text-sm text-secondary">{ "Site Statistics" }</p>
                </div>
            </div>

            if let Some(err) = &*error {
                <div class="bg-red-500/10 border border-red-500 rounded-lg p-4 text-red-500 mb-6">
                    { err }
                </div>
            }

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                <div class="bg-secondary rounded-lg p-6 border border-default">
                    <h3 class="text-lg font-semibold mb-4">{ "Traffic Overview" }</h3>
                    <div class="space-y-3">
                        <div class="flex justify-between items-center py-2 border-b border-default">
                            <span class="text-secondary">{ "Requests/sec" }</span>
                            <span class="text-primary font-medium">
                                { format!("{:.1}", current.map(|s| s.requests_per_second).unwrap_or(0.0)) }
                            </span>
                        </div>
                        <div class="flex justify-between items-center py-2 border-b border-default">
                            <span class="text-secondary">{ "Blocked Requests" }</span>
                            <span class="text-red-500 font-medium">
                                { format_number(current.map(|s| s.blocked_requests).unwrap_or(0)) }
                            </span>
                        </div>
                        <div class="flex justify-between items-center py-2 border-b border-default">
                            <span class="text-secondary">{ "Challenged Requests" }</span>
                            <span class="text-yellow-500 font-medium">
                                { format_number(current.map(|s| s.challenged_requests).unwrap_or(0)) }
                            </span>
                        </div>
                        <div class="flex justify-between items-center py-2 border-b border-default">
                            <span class="text-secondary">{ "Proxied Requests" }</span>
                            <span class="text-green-500 font-medium">
                                { format_number(current.map(|s| s.proxied_requests).unwrap_or(0)) }
                            </span>
                        </div>
                        <div class="flex justify-between items-center py-2">
                            <span class="text-secondary">{ "Errors" }</span>
                            <span class="text-red-500 font-medium">
                                { format_number(current.map(|s| s.errors).unwrap_or(0)) }
                            </span>
                        </div>
                    </div>
                </div>

                <div class="bg-secondary rounded-lg p-6 border border-default">
                    <h3 class="text-lg font-semibold mb-4">{ "Latency Distribution" }</h3>
                    <div class="space-y-3">
                        <div class="flex justify-between items-center py-2 border-b border-default">
                            <span class="text-secondary">{ "Average" }</span>
                            <span class="text-primary font-medium">
                                { format!("{:.1} ms", current.map(|s| s.avg_response_time_ms).unwrap_or(0.0)) }
                            </span>
                        </div>
                        <div class="flex justify-between items-center py-2 border-b border-default">
                            <span class="text-secondary">{ "p50" }</span>
                            <span class="text-primary font-medium">
                                { format!("{:.1} ms", current.map(|s| s.p50_latency_ms).unwrap_or(0.0)) }
                            </span>
                        </div>
                        <div class="flex justify-between items-center py-2 border-b border-default">
                            <span class="text-secondary">{ "p95" }</span>
                            <span class="text-primary font-medium">
                                { format!("{:.1} ms", current.map(|s| s.p95_latency_ms).unwrap_or(0.0)) }
                            </span>
                        </div>
                        <div class="flex justify-between items-center py-2">
                            <span class="text-secondary">{ "p99" }</span>
                            <span class="text-primary font-medium">
                                { format!("{:.1} ms", current.map(|s| s.p99_latency_ms).unwrap_or(0.0)) }
                            </span>
                        </div>
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                <div class="bg-secondary rounded-lg p-6 border border-default">
                    <h3 class="text-lg font-semibold mb-4">{ "Connection Status" }</h3>
                    <div class="flex justify-around mb-4">
                        <Gauge
                            value={current.map(|s| s.active_connections as f64).unwrap_or(0.0)}
                            max={100.0}
                            label="Active"
                            unit=""
                        />
                        <div class="flex flex-col items-center">
                            <span class={format!("w-4 h-4 rounded-full mb-2 {}", if current.map(|s| s.upstream_healthy).unwrap_or(false) { "bg-green-500" } else { "bg-red-500" })} />
                            <span class="text-sm text-secondary">
                                { if current.map(|s| s.upstream_healthy).unwrap_or(false) { "Upstream Healthy" } else { "Upstream Unhealthy" } }
                            </span>
                        </div>
                    </div>
                </div>

                <div class="bg-secondary rounded-lg p-6 border border-default">
                    <h3 class="text-lg font-semibold mb-4">{ "Bandwidth" }</h3>
                    <div class="space-y-3">
                        <div class="flex justify-between items-center py-2 border-b border-default">
                            <span class="text-secondary">{ "Received" }</span>
                            <span class="text-primary font-medium">
                                { format_bytes(current.map(|s| s.bytes_received).unwrap_or(0)) }
                            </span>
                        </div>
                        <div class="flex justify-between items-center py-2 border-b border-default">
                            <span class="text-secondary">{ "Sent" }</span>
                            <span class="text-primary font-medium">
                                { format_bytes(current.map(|s| s.bytes_sent).unwrap_or(0)) }
                            </span>
                        </div>
                        <div class="flex justify-between items-center py-2 border-b border-default">
                            <span class="text-secondary">{ "Proxied Received" }</span>
                            <span class="text-primary font-medium">
                                { format_bytes(current.map(|s| s.proxied_bytes_received).unwrap_or(0)) }
                            </span>
                        </div>
                        <div class="flex justify-between items-center py-2">
                            <span class="text-secondary">{ "Proxied Sent" }</span>
                            <span class="text-primary font-medium">
                                { format_bytes(current.map(|s| s.proxied_bytes_sent).unwrap_or(0)) }
                            </span>
                        </div>
                    </div>
                </div>
            </div>

            <div class="bg-secondary rounded-lg p-6 border border-default">
                <h3 class="text-lg font-semibold mb-4">{ "Domains" }</h3>
                if let Some(site) = current {
                    <div class="flex flex-wrap gap-2">
                        { for site.domains.iter().map(|domain| {
                            html! {
                                <span class="px-3 py-1 bg-tertiary rounded-full text-sm">
                                    { domain }
                                </span>
                            }
                        })}
                    </div>
                } else {
                    <p class="text-secondary">{ "No domains configured" }</p>
                }
            </div>
        </div>
    }
}
