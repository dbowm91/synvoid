use crate::components::forms::Input;
use crate::components::toast::{toast_error, toast_success};
use crate::services::ApiService;
use crate::types::{ProcessManagerConfig, StatusResponse, SupervisorConfig};
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct ProcessManagerSectionProps {
    pub config: Option<ProcessManagerConfig>,
    pub on_change: Callback<(String, String)>,
}

#[derive(Properties, PartialEq)]
pub struct SupervisorSectionProps {
    pub config: Option<SupervisorConfig>,
    pub on_change: Callback<(String, String)>,
}

#[function_component]
pub fn ProcessManagement() -> Html {
    let active_section = use_state(|| "supervisor".to_string());
    let saving = use_state(|| false);

    let process_manager_config = use_state(|| None as Option<ProcessManagerConfig>);
    let supervisor_config = use_state(|| None as Option<SupervisorConfig>);
    let error = use_state(|| None as Option<String>);

    let on_section_click = {
        let active_section = active_section.clone();
        Callback::from(move |section: String| {
            active_section.set(section);
        })
    };

    {
        let process_manager_config = process_manager_config.clone();
        let supervisor_config = supervisor_config.clone();
        let error = error.clone();

        use_effect_with((), move |_| {
            let process_manager_config = process_manager_config.clone();
            let supervisor_config = supervisor_config.clone();
            let error = error.clone();

            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();

                match api.get_process_manager_config().await {
                    Ok(resp) => {
                        if let Some(config) = resp.get("config") {
                            if let Ok(c) =
                                serde_json::from_value::<ProcessManagerConfig>(config.clone())
                            {
                                process_manager_config.set(Some(c));
                            }
                        }
                    }
                    Err(e) => error.set(Some(e)),
                }

                match api.get_supervisor_config().await {
                    Ok(resp) => {
                        if let Some(config) = resp.get("config") {
                            if let Ok(c) =
                                serde_json::from_value::<SupervisorConfig>(config.clone())
                            {
                                supervisor_config.set(Some(c));
                            }
                        }
                    }
                    Err(e) => error.set(Some(e)),
                }
            });

            || {}
        });
    }

    let on_save = {
        let saving = saving.clone();
        let process_manager_config = process_manager_config.clone();
        let supervisor_config = supervisor_config.clone();
        let active_section = active_section.clone();

        Callback::from(move |_| {
            let saving = saving.clone();
            let active_section = (*active_section).clone();
            let pm_config = (*process_manager_config).clone();
            let sup_config = (*supervisor_config).clone();

            saving.set(true);

            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();

                match active_section.as_str() {
                    "process" => {
                        if let Some(ref config) = pm_config {
                            let payload = serde_json::json!({ "config": config });
                            match api.update_process_manager_config(&payload).await {
                                Ok(resp) => {
                                    if let Ok(status) =
                                        serde_json::from_value::<StatusResponse>(resp.clone())
                                    {
                                        toast_success(&status.message);
                                    } else {
                                        toast_success("Process manager config updated.");
                                    }
                                }
                                Err(e) => toast_error(&format!("Failed to update: {}", e)),
                            }
                        }
                    }
                    "supervisor" => {
                        if let Some(ref config) = sup_config {
                            let payload = serde_json::json!({ "config": config });
                            match api.update_supervisor_config(&payload).await {
                                Ok(resp) => {
                                    if let Ok(status) =
                                        serde_json::from_value::<StatusResponse>(resp.clone())
                                    {
                                        toast_success(&status.message);
                                    } else {
                                        toast_success("Supervisor config updated.");
                                    }
                                }
                                Err(e) => toast_error(&format!("Failed to update: {}", e)),
                            }
                        }
                    }
                    _ => {}
                }

                saving.set(false);
            });
        })
    };

    let on_reset = {
        let active_section = active_section.clone();
        let process_manager_config = process_manager_config.clone();
        let supervisor_config = supervisor_config.clone();

        Callback::from(move |_| match (*active_section).as_str() {
            "process" => {
                process_manager_config.set(Some(ProcessManagerConfig::default()));
            }
            "supervisor" => {
                supervisor_config.set(Some(SupervisorConfig::default()));
            }
            _ => {}
        })
    };

    let handle_process_change = {
        let process_manager_config = process_manager_config.clone();
        Callback::from(move |(field, value): (String, String)| {
            if let Some(mut c) = (*process_manager_config).clone() {
                match field.as_str() {
                    "min_workers" => c.min_workers = value.parse().unwrap_or(2),
                    "max_workers" => c.max_workers = value.parse().unwrap_or(16),
                    "max_restart_attempts" => c.max_restart_attempts = value.parse().unwrap_or(5),
                    "restart_cooldown_secs" => {
                        c.restart_cooldown_secs = value.parse().unwrap_or(60)
                    }
                    "restart_backoff_max_secs" => {
                        c.restart_backoff_max_secs = value.parse().unwrap_or(300)
                    }
                    "heartbeat_timeout_secs" => {
                        c.heartbeat_timeout_secs = value.parse().unwrap_or(30)
                    }
                    "graceful_shutdown_timeout_secs" => {
                        c.graceful_shutdown_timeout_secs = value.parse().unwrap_or(30)
                    }
                    "worker_port_base" => c.worker_port_base = value.parse().unwrap_or(9000),
                    "pre_spawn_workers" => c.pre_spawn_workers = value.parse().unwrap_or(0),
                    "warm_workers_target" => c.warm_workers_target = value.parse().unwrap_or(2),
                    "health_check_interval_secs" => {
                        c.health_check_interval_secs = value.parse().unwrap_or(5)
                    }
                    _ => {}
                }
                process_manager_config.set(Some(c.clone()));
            }
        })
    };

    let handle_supervisor_change = {
        let supervisor_config = supervisor_config.clone();
        Callback::from(move |(field, value): (String, String)| {
            if let Some(mut c) = (*supervisor_config).clone() {
                match field.as_str() {
                    "min_workers" => c.min_workers = value.parse().unwrap_or(2),
                    "max_workers" => c.max_workers = value.parse().unwrap_or(16),
                    "scale_up_threshold" => c.scale_up_threshold = value.parse().unwrap_or(0.8),
                    "scale_down_threshold" => c.scale_down_threshold = value.parse().unwrap_or(0.2),
                    "scale_up_cooldown_secs" => {
                        c.scale_up_cooldown_secs = value.parse().unwrap_or(30)
                    }
                    "scale_down_cooldown_secs" => {
                        c.scale_down_cooldown_secs = value.parse().unwrap_or(60)
                    }
                    "max_restart_attempts" => c.max_restart_attempts = value.parse().unwrap_or(5),
                    "restart_cooldown_secs" => {
                        c.restart_cooldown_secs = value.parse().unwrap_or(300)
                    }
                    "health_check_interval_secs" => {
                        c.health_check_interval_secs = value.parse().unwrap_or(5)
                    }
                    "graceful_shutdown_timeout_secs" => {
                        c.graceful_shutdown_timeout_secs = value.parse().unwrap_or(30)
                    }
                    _ => {}
                }
                supervisor_config.set(Some(c.clone()));
            }
        })
    };

    html! {
        <div>
            <h1 class="text-2xl font-bold mb-6">{ "Process Management" }</h1>

            if let Some(err) = &*error {
                <div class="bg-red-500/10 border border-red-500 rounded-lg p-4 text-red-500 mb-4">
                    { err }
                </div>
            }

            <div class="flex gap-6">
                <nav class="w-48 flex-shrink-0">
                    <div class="bg-secondary rounded-lg border border-default">
                        <ProcessSectionButton
                            label="Supervisor"
                            section="supervisor"
                            active={*active_section == "supervisor"}
                            on_click={on_section_click.clone()}
                        />
                        <ProcessSectionButton
                            label="Process Manager"
                            section="process"
                            active={*active_section == "process"}
                            on_click={on_section_click.clone()}
                        />
                    </div>
                </nav>

                <div class="flex-1 bg-secondary rounded-lg border border-default">
                    <div class="p-6 border-b border-default">
                        <h2 class="text-lg font-semibold">
                        { match active_section.as_str() {
                            "process" => "Process Manager Configuration",
                            "supervisor" => "Supervisor (Auto-scaling) Configuration",
                            _ => "Process Management",
                        }}
                        </h2>
                    </div>

                    <div class="p-6">
                        { match active_section.as_str() {
                            "process" => html! { <ProcessManagerSection config={(*process_manager_config).clone()} on_change={handle_process_change.clone()} /> },
                            "supervisor" => html! { <SupervisorSection config={(*supervisor_config).clone()} on_change={handle_supervisor_change.clone()} /> },
                            _ => html! { <SupervisorSection config={(*supervisor_config).clone()} on_change={handle_supervisor_change.clone()} /> },
                        }}
                    </div>

                    <div class="p-4 border-t border-default flex justify-end gap-4">
                        <button onclick={on_reset} class="px-4 py-2 bg-tertiary text-primary rounded-lg hover:opacity-80">
                            { "Reset to Defaults" }
                        </button>
                        <button
                            onclick={on_save}
                            disabled={*saving}
                            class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                        >
                            { if *saving { "Saving..." } else { "Save Changes" } }
                        </button>
                    </div>
                </div>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct ProcessSectionButtonProps {
    label: String,
    section: String,
    active: bool,
    on_click: Callback<String>,
}

#[function_component]
fn ProcessSectionButton(props: &ProcessSectionButtonProps) -> Html {
    let onclick = {
        let section = props.section.clone();
        let on_click = props.on_click.clone();
        Callback::from(move |_| {
            on_click.emit(section.clone());
        })
    };

    let class = if props.active {
        "block w-full text-left px-4 py-3 text-primary bg-tertiary border-l-2 border-blue-500"
    } else {
        "block w-full text-left px-4 py-3 text-secondary hover:text-primary hover:bg-tertiary"
    };

    html! {
        <button onclick={onclick} class={class}>
            { &props.label }
        </button>
    }
}

#[function_component]
fn ProcessManagerSection(props: &ProcessManagerSectionProps) -> Html {
    let cfg = props.config.as_ref();
    let on_change = props.on_change.clone();

    html! {
        <div class="space-y-6">
            <h3 class="font-semibold text-primary">{ "Worker Pool" }</h3>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Min Workers"
                    name="min_workers"
                    input_type="number"
                    value={cfg.map(|c| c.min_workers.to_string()).unwrap_or_else(|| "2".to_string())}
                    help="Minimum number of worker processes"
                    on_change={on_change.reform(|s| ("min_workers".to_string(), s))}
                />
                <Input
                    label="Max Workers"
                    name="max_workers"
                    input_type="number"
                    value={cfg.map(|c| c.max_workers.to_string()).unwrap_or_else(|| "16".to_string())}
                    help="Maximum number of worker processes"
                    on_change={on_change.reform(|s| ("max_workers".to_string(), s))}
                />
            </div>

            <h3 class="font-semibold text-primary pt-4 border-t border-default">{ "Restart Behavior" }</h3>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Max Restart Attempts"
                    name="max_restart_attempts"
                    input_type="number"
                    value={cfg.map(|c| c.max_restart_attempts.to_string()).unwrap_or_else(|| "5".to_string())}
                    on_change={on_change.reform(|s| ("max_restart_attempts".to_string(), s))}
                />
                <Input
                    label="Restart Cooldown (secs)"
                    name="restart_cooldown_secs"
                    input_type="number"
                    value={cfg.map(|c| c.restart_cooldown_secs.to_string()).unwrap_or_else(|| "60".to_string())}
                    help="Seconds to wait after a restart"
                    on_change={on_change.reform(|s| ("restart_cooldown_secs".to_string(), s))}
                />
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Restart Backoff Max (secs)"
                    name="restart_backoff_max_secs"
                    input_type="number"
                    value={cfg.map(|c| c.restart_backoff_max_secs.to_string()).unwrap_or_else(|| "300".to_string())}
                    help="Maximum backoff time between restarts"
                    on_change={on_change.reform(|s| ("restart_backoff_max_secs".to_string(), s))}
                />
                <Input
                    label="Heartbeat Timeout (secs)"
                    name="heartbeat_timeout_secs"
                    input_type="number"
                    value={cfg.map(|c| c.heartbeat_timeout_secs.to_string()).unwrap_or_else(|| "30".to_string())}
                    help="Consider worker dead after this timeout"
                    on_change={on_change.reform(|s| ("heartbeat_timeout_secs".to_string(), s))}
                />
            </div>

            <h3 class="font-semibold text-primary pt-4 border-t border-default">{ "Worker Ports & Startup" }</h3>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Worker Port Base"
                    name="worker_port_base"
                    input_type="number"
                    value={cfg.map(|c| c.worker_port_base.to_string()).unwrap_or_else(|| "9000".to_string())}
                    help="Starting port for worker processes"
                    on_change={on_change.reform(|s| ("worker_port_base".to_string(), s))}
                />
                <Input
                    label="Pre-spawn Workers"
                    name="pre_spawn_workers"
                    input_type="number"
                    value={cfg.map(|c| c.pre_spawn_workers.to_string()).unwrap_or_else(|| "0".to_string())}
                    help="Workers to spawn at startup"
                    on_change={on_change.reform(|s| ("pre_spawn_workers".to_string(), s))}
                />
            </div>

            <Input
                label="Warm Workers Target"
                name="warm_workers_target"
                input_type="number"
                value={cfg.map(|c| c.warm_workers_target.to_string()).unwrap_or_else(|| "2".to_string())}
                help="Keep this many workers warm for fast response"
                on_change={on_change.reform(|s| ("warm_workers_target".to_string(), s))}
            />

            <h3 class="font-semibold text-primary pt-4 border-t border-default">{ "Health & Shutdown" }</h3>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Health Check Interval (secs)"
                    name="health_check_interval_secs"
                    input_type="number"
                    value={cfg.map(|c| c.health_check_interval_secs.to_string()).unwrap_or_else(|| "5".to_string())}
                    on_change={on_change.reform(|s| ("health_check_interval_secs".to_string(), s))}
                />
                <Input
                    label="Graceful Shutdown Timeout (secs)"
                    name="graceful_shutdown_timeout_secs"
                    input_type="number"
                    value={cfg.map(|c| c.graceful_shutdown_timeout_secs.to_string()).unwrap_or_else(|| "30".to_string())}
                    on_change={on_change.reform(|s| ("graceful_shutdown_timeout_secs".to_string(), s))}
                />
            </div>
        </div>
    }
}

#[function_component]
fn SupervisorSection(props: &SupervisorSectionProps) -> Html {
    let cfg = props.config.as_ref();
    let on_change = props.on_change.clone();

    html! {
        <div class="space-y-6">
            <div class="bg-blue-500/10 border border-blue-500 rounded-lg p-4 mb-4">
                <p class="text-sm text-blue-400">
                    { "The Supervisor enables automatic worker scaling based on load. " }
                    { "When enabled, it dynamically adjusts worker count between min and max values." }
                </p>
            </div>

            <h3 class="font-semibold text-primary">{ "Worker Range" }</h3>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Min Workers"
                    name="min_workers"
                    input_type="number"
                    value={cfg.map(|c| c.min_workers.to_string()).unwrap_or_else(|| "2".to_string())}
                    help="Minimum workers when auto-scaling"
                    on_change={on_change.reform(|s| ("min_workers".to_string(), s))}
                />
                <Input
                    label="Max Workers"
                    name="max_workers"
                    input_type="number"
                    value={cfg.map(|c| c.max_workers.to_string()).unwrap_or_else(|| "16".to_string())}
                    help="Maximum workers when auto-scaling"
                    on_change={on_change.reform(|s| ("max_workers".to_string(), s))}
                />
            </div>

            <h3 class="font-semibold text-primary pt-4 border-t border-default">{ "Scale Triggers" }</h3>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Scale Up Threshold"
                    name="scale_up_threshold"
                    input_type="number"
                    value={cfg.map(|c| c.scale_up_threshold.to_string()).unwrap_or_else(|| "0.8".to_string())}
                    help="CPU/memory % to trigger scale up (0.0-1.0)"
                    on_change={on_change.reform(|s| ("scale_up_threshold".to_string(), s))}
                />
                <Input
                    label="Scale Down Threshold"
                    name="scale_down_threshold"
                    input_type="number"
                    value={cfg.map(|c| c.scale_down_threshold.to_string()).unwrap_or_else(|| "0.2".to_string())}
                    help="CPU/memory % to trigger scale down (0.0-1.0)"
                    on_change={on_change.reform(|s| ("scale_down_threshold".to_string(), s))}
                />
            </div>

            <h3 class="font-semibold text-primary pt-4 border-t border-default">{ "Scale Cooldowns" }</h3>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Scale Up Cooldown (secs)"
                    name="scale_up_cooldown_secs"
                    input_type="number"
                    value={cfg.map(|c| c.scale_up_cooldown_secs.to_string()).unwrap_or_else(|| "30".to_string())}
                    help="Wait time after scaling up"
                    on_change={on_change.reform(|s| ("scale_up_cooldown_secs".to_string(), s))}
                />
                <Input
                    label="Scale Down Cooldown (secs)"
                    name="scale_down_cooldown_secs"
                    input_type="number"
                    value={cfg.map(|c| c.scale_down_cooldown_secs.to_string()).unwrap_or_else(|| "60".to_string())}
                    help="Wait time after scaling down"
                    on_change={on_change.reform(|s| ("scale_down_cooldown_secs".to_string(), s))}
                />
            </div>

            <h3 class="font-semibold text-primary pt-4 border-t border-default">{ "Restart Behavior" }</h3>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Max Restart Attempts"
                    name="max_restart_attempts"
                    input_type="number"
                    value={cfg.map(|c| c.max_restart_attempts.to_string()).unwrap_or_else(|| "5".to_string())}
                    on_change={on_change.reform(|s| ("max_restart_attempts".to_string(), s))}
                />
                <Input
                    label="Restart Cooldown (secs)"
                    name="restart_cooldown_secs"
                    input_type="number"
                    value={cfg.map(|c| c.restart_cooldown_secs.to_string()).unwrap_or_else(|| "300".to_string())}
                    on_change={on_change.reform(|s| ("restart_cooldown_secs".to_string(), s))}
                />
            </div>

            <h3 class="font-semibold text-primary pt-4 border-t border-default">{ "Health & Shutdown" }</h3>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Health Check Interval (secs)"
                    name="health_check_interval_secs"
                    input_type="number"
                    value={cfg.map(|c| c.health_check_interval_secs.to_string()).unwrap_or_else(|| "5".to_string())}
                    on_change={on_change.reform(|s| ("health_check_interval_secs".to_string(), s))}
                />
                <Input
                    label="Graceful Shutdown Timeout (secs)"
                    name="graceful_shutdown_timeout_secs"
                    input_type="number"
                    value={cfg.map(|c| c.graceful_shutdown_timeout_secs.to_string()).unwrap_or_else(|| "30".to_string())}
                    on_change={on_change.reform(|s| ("graceful_shutdown_timeout_secs".to_string(), s))}
                />
            </div>
        </div>
    }
}
