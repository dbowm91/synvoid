use yew::prelude::*;
use crate::services::ApiService;
use crate::types::{WorkerStatus, OverseerStatus};

#[function_component]
pub fn Workers() -> Html {
    let workers = use_state(|| Vec::<WorkerStatus>::new());
    let overseer = use_state(|| None as Option<OverseerStatus>);
    let error = use_state(|| None as Option<String>);
    let restarting = use_state(|| None as Option<String>);

    {
        let workers = workers.clone();
        let overseer = overseer.clone();
        let error = error.clone();
        
        use_effect_with((), move |_| {
            let workers = workers.clone();
            let overseer = overseer.clone();
            let error = error.clone();
            
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                
                match api.get_workers_status().await {
                    Ok(w) => workers.set(w),
                    Err(e) => error.set(Some(e)),
                }
                
                match api.get_overseer_status().await {
                    Ok(o) => overseer.set(Some(o)),
                    Err(e) => error.set(Some(e)),
                }
            });
            
            || {}
        });
    }

    let on_restart = {
        let workers = workers.clone();
        let restarting = restarting.clone();
        let error = error.clone();
        
        Callback::from(move |worker_id: String| {
            let workers = workers.clone();
            let restarting = restarting.clone();
            let error = error.clone();
            let worker_id_clone = worker_id.clone();
            
            restarting.set(Some(worker_id_clone.clone()));
            
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                
                match api.restart_worker(&worker_id_clone).await {
                    Ok(_resp) => {
                        let workers = workers.clone();
                        let restarting = restarting.clone();
                        
                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                        restarting.set(None);
                        
                        if let Ok(w) = api.get_workers_status().await {
                            workers.set(w);
                        }
                    }
                    Err(e) => {
                        error.set(Some(e));
                        restarting.set(None);
                    }
                }
            });
        })
    };

    let format_uptime = |secs: u64| -> String {
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        let minutes = (secs % 3600) / 60;
        
        if days > 0 {
            format!("{}d {}h {}m", days, hours, minutes)
        } else if hours > 0 {
            format!("{}h {}m", hours, minutes)
        } else {
            format!("{}m", minutes)
        }
    };

    let format_number = |n: u64| -> String {
        if n >= 1_000_000 {
            format!("{:.1}M", n as f64 / 1_000_000.0)
        } else if n >= 1_000 {
            format!("{:.1}K", n as f64 / 1_000.0)
        } else {
            n.to_string()
        }
    };

    html! {
        <div class="space-y-6">
            <div class="flex justify-between items-center">
                <h1 class="text-2xl font-bold">{ "Workers & Overseer" }</h1>
            </div>

            if let Some(err) = &*error {
                <div class="bg-red-500/10 border border-red-500 rounded-lg p-4 text-red-500">
                    { err }
                </div>
            }

            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div class="bg-secondary rounded-lg border border-default p-6">
                    <h2 class="text-lg font-semibold mb-4">{ "Overseer Status" }</h2>
                    if let Some(status) = &*overseer {
                        <div class="space-y-3">
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Status" }</span>
                                <span class={if status.running { "text-green-500 font-medium" } else { "text-red-500 font-medium" }}>
                                    { if status.running { "Running" } else { "Stopped" } }
                                </span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Overseer PID" }</span>
                                <span class="text-primary font-medium">
                                    { status.pid.map(|p| p.to_string()).unwrap_or_else(|| "N/A".to_string()) }
                                </span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Master PID" }</span>
                                <span class="text-primary font-medium">
                                    { status.master_pid.map(|p| p.to_string()).unwrap_or_else(|| "N/A".to_string()) }
                                </span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Master Status" }</span>
                                <span class="text-primary font-medium">{ &status.master_status }</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Uptime" }</span>
                                <span class="text-primary font-medium">{ format_uptime(status.uptime_secs) }</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Upgrade Mode" }</span>
                                <span class="text-primary font-medium">{ &status.upgrade_mode }</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Drain Status" }</span>
                                <span class="text-primary font-medium">{ &status.drain_status }</span>
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
                    <h2 class="text-lg font-semibold mb-4">{ "Architecture" }</h2>
                    <div class="flex items-center justify-center p-4">
                        <div class="flex items-center gap-8">
                            <div class="text-center">
                                <div class="w-20 h-20 rounded-full bg-blue-600 flex items-center justify-center text-white font-bold text-sm">
                                    { "Overseer" }
                                </div>
                                <p class="text-xs text-secondary mt-2">{ "Supervisor" }</p>
                            </div>
                            <div class="w-12 h-1 bg-tertiary"></div>
                            <div class="text-center">
                                <div class="w-20 h-20 rounded-full bg-green-600 flex items-center justify-center text-white font-bold text-sm">
                                    { "Master" }
                                </div>
                                <p class="text-xs text-secondary mt-2">{ "Process" }</p>
                            </div>
                            <div class="w-12 h-1 bg-tertiary"></div>
                            <div class="text-center">
                                <div class="w-20 h-20 rounded-full bg-purple-600 flex items-center justify-center text-white font-bold text-sm">
                                    { "Workers" }
                                </div>
                                <p class="text-xs text-secondary mt-2">{ "Request Handler" }</p>
                            </div>
                        </div>
                    </div>
                    <p class="text-sm text-secondary text-center mt-2">
                        { format!("{} worker(s) running", workers.len()) }
                    </p>
                </div>
            </div>

            <div class="bg-secondary rounded-lg border border-default p-6">
                <h2 class="text-lg font-semibold mb-4">{ "Worker Processes" }</h2>
                
                if workers.is_empty() {
                    <p class="text-secondary">{ "No workers found" }</p>
                } else {
                    <div class="overflow-x-auto">
                        <table class="w-full">
                            <thead>
                                <tr class="border-b border-default">
                                    <th class="text-left py-3 px-4 text-secondary font-medium">{ "Worker ID" }</th>
                                    <th class="text-left py-3 px-4 text-secondary font-medium">{ "Type" }</th>
                                    <th class="text-left py-3 px-4 text-secondary font-medium">{ "PID" }</th>
                                    <th class="text-left py-3 px-4 text-secondary font-medium">{ "Status" }</th>
                                    <th class="text-left py-3 px-4 text-secondary font-medium">{ "Uptime" }</th>
                                    <th class="text-left py-3 px-4 text-secondary font-medium">{ "Requests" }</th>
                                    <th class="text-left py-3 px-4 text-secondary font-medium">{ "Blocked" }</th>
                                    <th class="text-left py-3 px-4 text-secondary font-medium">{ "Errors" }</th>
                                    <th class="text-left py-3 px-4 text-secondary font-medium">{ "Memory" }</th>
                                    <th class="text-left py-3 px-4 text-secondary font-medium">{ "CPU" }</th>
                                    <th class="text-left py-3 px-4 text-secondary font-medium">{ "Actions" }</th>
                                </tr>
                            </thead>
                            <tbody>
                                { for workers.iter().map(|w| {
                                    let status_class = match w.status.as_str() {
                                        "running" => "text-green-500",
                                        _ => "text-red-500",
                                    };
                                    
                                    let is_restarting = restarting.as_ref().map(|r| r == &w.id).unwrap_or(false);
                                    
                                    html! {
                                        <tr class="border-b border-default hover:bg-tertiary/30">
                                            <td class="py-3 px-4 text-primary font-medium">{ &w.id }</td>
                                            <td class="py-3 px-4 text-secondary">{ &w.worker_type }</td>
                                            <td class="py-3 px-4 text-primary">{ w.pid.map(|p| p.to_string()).unwrap_or_else(|| "N/A".to_string()) }</td>
                                            <td class={format!("py-3 px-4 font-medium {}", status_class)}>{ &w.status }</td>
                                            <td class="py-3 px-4 text-secondary">{ format_uptime(w.uptime_secs) }</td>
                                            <td class="py-3 px-4 text-primary">{ format_number(w.total_requests) }</td>
                                            <td class="py-3 px-4 text-red-500">{ format_number(w.blocked) }</td>
                                            <td class="py-3 px-4 text-yellow-500">{ format_number(w.errors) }</td>
                                            <td class="py-3 px-4 text-secondary">{ format!("{} MB", w.memory_mb) }</td>
                                            <td class="py-3 px-4 text-secondary">{ format!("{:.1}%", w.cpu_percent) }</td>
                                            <td class="py-3 px-4">
                                                <button 
                                                    onclick={{
                                                        let worker_id = w.id.clone();
                                                        let on_restart = on_restart.clone();
                                                        move |_| { on_restart.emit(worker_id.clone()); }
                                                    }}
                                                    disabled={is_restarting}
                                                    class="px-3 py-1 bg-tertiary text-secondary rounded hover:text-primary hover:bg-tertiary/80 disabled:opacity-50 text-sm"
                                                >
                                                    { if is_restarting { "Restarting..." } else { "Restart" } }
                                                </button>
                                            </td>
                                        </tr>
                                    }
                                })}
                            </tbody>
                        </table>
                    </div>
                }
            </div>
        </div>
    }
}
