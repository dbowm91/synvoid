use crate::services::api::ApiService;
use crate::types::{MasterStatus, SystemInfo};
use yew::prelude::*;

#[function_component]
pub fn SystemStatus() -> Html {
    let system_info = use_state(|| None as Option<SystemInfo>);
    let master_status = use_state(|| None as Option<MasterStatus>);
    let error = use_state(|| None as Option<String>);

    {
        let system_info = system_info.clone();
        let master_status = master_status.clone();
        let error = error.clone();
        use_effect_with((), move |_| {
            let system_info = system_info.clone();
            let master_status = master_status.clone();
            let error = error.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.get_system_info().await {
                    Ok(info) => system_info.set(Some(info)),
                    Err(e) => error.set(Some(e)),
                }
                match api.get_master_status().await {
                    Ok(status) => master_status.set(Some(status)),
                    Err(e) => error.set(Some(e)),
                }
            });
        });
    }

    let format_uptime = |secs: Option<u64>| -> String {
        match secs {
            Some(s) => {
                let days = s / 86400;
                let hours = (s % 86400) / 3600;
                let minutes = (s % 3600) / 60;
                if days > 0 {
                    format!("{}d {}h {}m", days, hours, minutes)
                } else if hours > 0 {
                    format!("{}h {}m", hours, minutes)
                } else {
                    format!("{}m", minutes)
                }
            }
            None => "N/A".to_string(),
        }
    };

    html! {
        <div class="space-y-6">
            <div class="flex justify-between items-center">
                <h1 class="text-2xl font-bold">{ "System Status" }</h1>
            </div>

            if let Some(err) = &*error {
                <div class="bg-red-500/10 border border-red-500 rounded-lg p-4 text-red-500">
                    { err }
                </div>
            }

            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div class="bg-secondary rounded-lg border border-default p-6">
                    <h2 class="text-lg font-semibold mb-4">{ "System Information" }</h2>
                    if let Some(info) = &*system_info {
                        <div class="space-y-3">
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Version" }</span>
                                <span class="text-primary font-medium">{ &info.version }</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Build" }</span>
                                <span class="text-primary font-medium">{ &info.build_timestamp }</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Architecture" }</span>
                                <span class="text-primary font-medium">{ &info.architecture }</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Running Mode" }</span>
                                <span class="text-primary font-medium">{ &info.running_mode }</span>
                            </div>
                            <div class="mt-4">
                                <span class="text-secondary">{ "Features" }</span>
                                <div class="flex flex-wrap gap-2 mt-2">
                                    { for info.features.iter().map(|f| {
                                        html! {
                                            <span class="px-2 py-1 bg-tertiary rounded text-sm">
                                                { f }
                                            </span>
                                        }
                                    }) }
                                </div>
                            </div>
                        </div>
                    } else {
                        <div class="animate-pulse">
                            <div class="h-4 bg-tertiary rounded w-3/4 mb-2"></div>
                            <div class="h-4 bg-tertiary rounded w-1/2"></div>
                        </div>
                    }
                </div>

                <div class="bg-secondary rounded-lg border border-default p-6">
                    <h2 class="text-lg font-semibold mb-4">{ "Master Process" }</h2>
                    if let Some(status) = &*master_status {
                        <div class="space-y-3">
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Status" }</span>
                                <span class={if status.running { "text-green-500 font-medium" } else { "text-red-500 font-medium" }}>
                                    { if status.running { "Running" } else { "Stopped" } }
                                </span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "PID" }</span>
                                <span class="text-primary font-medium">
                                    { status.pid.map(|p| p.to_string()).unwrap_or_else(|| "N/A".to_string()) }
                                </span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Uptime" }</span>
                                <span class="text-primary font-medium">{ format_uptime(status.uptime_secs) }</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Mode" }</span>
                                <span class="text-primary font-medium">{ &status.mode }</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Worker Mode" }</span>
                                <span class="text-primary font-medium">{ &status.worker_mode }</span>
                            </div>
                        </div>
                    } else {
                        <div class="animate-pulse">
                            <div class="h-4 bg-tertiary rounded w-3/4 mb-2"></div>
                            <div class="h-4 bg-tertiary rounded w-1/2"></div>
                        </div>
                    }
                </div>
            </div>

            if let Some(status) = &*master_status {
                <div class="bg-secondary rounded-lg border border-default p-6">
                    <h2 class="text-lg font-semibold mb-4">{ "Request Statistics" }</h2>
                    <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div class="text-center">
                            <div class="text-2xl font-bold text-primary">{ status.metrics.total_requests }</div>
                            <div class="text-sm text-secondary">{ "Total Requests" }</div>
                        </div>
                        <div class="text-center">
                            <div class="text-2xl font-bold text-green-500">{ status.metrics.proxied }</div>
                            <div class="text-sm text-secondary">{ "Proxied" }</div>
                        </div>
                        <div class="text-center">
                            <div class="text-2xl font-bold text-red-500">{ status.metrics.blocked }</div>
                            <div class="text-sm text-secondary">{ "Blocked" }</div>
                        </div>
                        <div class="text-center">
                            <div class="text-2xl font-bold text-yellow-500">{ status.metrics.challenged }</div>
                            <div class="text-sm text-secondary">{ "Challenged" }</div>
                        </div>
                    </div>
                    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
                        <div class="text-center">
                            <div class="text-2xl font-bold text-primary">{ status.metrics.requests_per_second.round() }</div>
                            <div class="text-sm text-secondary">{ "Req/sec" }</div>
                        </div>
                        <div class="text-center">
                            <div class="text-2xl font-bold text-primary">{ status.metrics.current_concurrent }</div>
                            <div class="text-sm text-secondary">{ "Active Connections" }</div>
                        </div>
                        <div class="text-center">
                            <div class="text-2xl font-bold text-primary">{ status.metrics.peak_concurrent }</div>
                            <div class="text-sm text-secondary">{ "Peak Connections" }</div>
                        </div>
                        <div class="text-center">
                            <div class="text-2xl font-bold text-red-500">{ status.metrics.errors }</div>
                            <div class="text-sm text-secondary">{ "Errors" }</div>
                        </div>
                    </div>
                </div>
            }

            <div class="bg-secondary rounded-lg border border-default p-6">
                <h2 class="text-lg font-semibold mb-4">{ "Architecture" }</h2>
                <div class="flex items-center justify-center p-4">
                    <div class="flex items-center gap-8">
                        <div class="text-center">
                            <div class="w-24 h-24 rounded-full bg-blue-600 flex items-center justify-center text-white font-bold text-lg">
                                { "Overseer" }
                            </div>
                            <p class="text-sm text-secondary mt-2">{ "Supervisor" }</p>
                        </div>
                        <div class="w-16 h-1 bg-tertiary"></div>
                        <div class="text-center">
                            <div class="w-24 h-24 rounded-full bg-green-600 flex items-center justify-center text-white font-bold text-lg">
                                { "Master" }
                            </div>
                            <p class="text-sm text-secondary mt-2">{ "Process" }</p>
                        </div>
                        <div class="w-16 h-1 bg-tertiary"></div>
                        <div class="text-center">
                            <div class="w-24 h-24 rounded-full bg-purple-600 flex items-center justify-center text-white font-bold text-lg">
                                { "Workers" }
                            </div>
                            <p class="text-sm text-secondary mt-2">{ "Request Handler" }</p>
                        </div>
                    </div>
                </div>
                <p class="text-sm text-secondary text-center mt-4">
                    { "Overseer monitors Master, Master manages Workers, Workers handle requests" }
                </p>
            </div>
        </div>
    }
}
