use crate::components::forms::Input;
use crate::components::toast::{toast_error, toast_success};
use crate::services::ApiService;
use crate::types::{OverseerConfig, ProcessManagerConfig, StatusResponse, SupervisorConfig};
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct OverseerSectionProps {
    pub config: Option<OverseerConfig>,
    pub on_change: Callback<(String, String)>,
}

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
    let active_section = use_state(|| "overseer".to_string());
    let saving = use_state(|| false);

    let overseer_config = use_state(|| None as Option<OverseerConfig>);
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
        let overseer_config = overseer_config.clone();
        let process_manager_config = process_manager_config.clone();
        let supervisor_config = supervisor_config.clone();
        let error = error.clone();

        use_effect_with((), move |_| {
            let overseer_config = overseer_config.clone();
            let process_manager_config = process_manager_config.clone();
            let supervisor_config = supervisor_config.clone();
            let error = error.clone();

            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();

                match api.get_overseer_config().await {
                    Ok(resp) => {
                        if let Some(config) = resp.get("config") {
                            if let Ok(c) = serde_json::from_value::<OverseerConfig>(config.clone())
                            {
                                overseer_config.set(Some(c));
                            }
                        }
                    }
                    Err(e) => error.set(Some(e)),
                }

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
        let overseer_config = overseer_config.clone();
        let process_manager_config = process_manager_config.clone();
        let supervisor_config = supervisor_config.clone();
        let active_section = active_section.clone();

        Callback::from(move |_| {
            let saving = saving.clone();
            let active_section = (*active_section).clone();
            let ov_config = (*overseer_config).clone();
            let pm_config = (*process_manager_config).clone();
            let sup_config = (*supervisor_config).clone();

            saving.set(true);

            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();

                match active_section.as_str() {
                    "overseer" => {
                        if let Some(ref config) = ov_config {
                            let payload = serde_json::json!({ "config": config });
                            match api.update_overseer_config(&payload).await {
                                Ok(resp) => {
                                    if let Ok(status) =
                                        serde_json::from_value::<StatusResponse>(resp.clone())
                                    {
                                        toast_success(&status.message);
                                    } else {
                                        toast_success("Overseer config updated.");
                                    }
                                }
                                Err(e) => toast_error(&format!("Failed to update: {}", e)),
                            }
                        }
                    }
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
        let overseer_config = overseer_config.clone();
        let process_manager_config = process_manager_config.clone();
        let supervisor_config = supervisor_config.clone();

        Callback::from(move |_| match (*active_section).as_str() {
            "overseer" => {
                overseer_config.set(Some(OverseerConfig::default()));
            }
            "process" => {
                process_manager_config.set(Some(ProcessManagerConfig::default()));
            }
            "supervisor" => {
                supervisor_config.set(Some(SupervisorConfig::default()));
            }
            _ => {}
        })
    };

    let handle_overseer_change = {
        let overseer_config = overseer_config.clone();
        Callback::from(move |(field, value): (String, String)| {
            if let Some(mut c) = (*overseer_config).clone() {
                match field.as_str() {
                    "restart_delay_secs" => c.restart_delay_secs = value.parse().unwrap_or(5),
                    "max_restart_attempts" => c.max_restart_attempts = value.parse().unwrap_or(5),
                    "health_check_interval_secs" => {
                        c.health_check_interval_secs = value.parse().unwrap_or(5)
                    }
                    "stable_uptime_secs" => c.stable_uptime_secs = value.parse().unwrap_or(60),
                    "upgrade_validation_timeout_secs" => {
                        c.upgrade_validation_timeout_secs = value.parse().unwrap_or(10)
                    }
                    "upgrade_drain_timeout_secs" => {
                        c.upgrade_drain_timeout_secs = value.parse().unwrap_or(30)
                    }
                    "upgrade_health_check_retries" => {
                        c.upgrade_health_check_retries = value.parse().unwrap_or(5)
                    }
                    "upgrade_health_check_interval_secs" => {
                        c.upgrade_health_check_interval_secs = value.parse().unwrap_or(2)
                    }
                    "ipc_read_timeout_ms" => c.ipc_read_timeout_ms = value.parse().unwrap_or(5000),
                    "ipc_write_timeout_ms" => {
                        c.ipc_write_timeout_ms = value.parse().unwrap_or(5000)
                    }
                    "master_startup_timeout_secs" => {
                        c.master_startup_timeout_secs = value.parse().unwrap_or(30)
                    }
                    _ => {}
                }
                overseer_config.set(Some(c.clone()));
            }
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

    let toggle_overseer_auto_restart = {
        let overseer_config = overseer_config.clone();
        Callback::from(move |_: yew::MouseEvent| {
            if let Some(mut c) = (*overseer_config).clone() {
                c.auto_restart = !c.auto_restart;
                overseer_config.set(Some(c.clone()));
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
                            label="Overseer"
                            section="overseer"
                            active={*active_section == "overseer"}
                            on_click={on_section_click.clone()}
                        />
                        <ProcessSectionButton
                            label="Process Manager"
                            section="process"
                            active={*active_section == "process"}
                            on_click={on_section_click.clone()}
                        />
                        <ProcessSectionButton
                            label="Supervisor"
                            section="supervisor"
                            active={*active_section == "supervisor"}
                            on_click={on_section_click.clone()}
                        />
                    </div>
                </nav>

                <div class="flex-1 bg-secondary rounded-lg border border-default">
                    <div class="p-6 border-b border-default">
                        <h2 class="text-lg font-semibold">
                        { match active_section.as_str() {
                            "overseer" => "Overseer Configuration",
                            "process" => "Process Manager Configuration",
                            "supervisor" => "Supervisor (Auto-scaling) Configuration",
                            _ => "Process Management",
                        }}
                        </h2>
                    </div>

                    <div class="p-6">
                        { match active_section.as_str() {
                            "overseer" => html! { <OverseerSection config={(*overseer_config).clone()} on_change={handle_overseer_change.clone()} /> },
                            "process" => html! { <ProcessManagerSection config={(*process_manager_config).clone()} on_change={handle_process_change.clone()} /> },
                            "supervisor" => html! { <SupervisorSection config={(*supervisor_config).clone()} on_change={handle_supervisor_change.clone()} /> },
                            _ => html! { <OverseerSection config={(*overseer_config).clone()} on_change={handle_overseer_change.clone()} /> },
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
fn OverseerSection(props: &OverseerSectionProps) -> Html {
    let cfg = props.config.as_ref();
    let on_change = props.on_change.clone();
    let toggle_auto_restart = props
        .on_change
        .reform(|_| ("auto_restart".to_string(), "toggle".to_string()));

    html! {
        <div class="space-y-6">
            <div class="flex items-center justify-between py-2 border-b border-default">
                <div>
                    <p class="text-primary font-medium">{ "Auto Restart" }</p>
                    <p class="text-sm text-secondary">{ "Automatically restart master on failure" }</p>
                </div>
                <button
                    onclick={toggle_auto_restart}
                    class={format!("relative w-10 h-6 rounded-full {}", if cfg.map(|c| c.auto_restart).unwrap_or(true) { "bg-blue-600" } else { "bg-tertiary" })}
                >
                    <span class={format!("absolute top-1 w-4 h-4 bg-white rounded-full transition-transform {}", if cfg.map(|c| c.auto_restart).unwrap_or(true) { "translate-x-5" } else { "left-1" })} />
                </button>
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Restart Delay (secs)"
                    name="restart_delay_secs"
                    input_type="number"
                    value={cfg.map(|c| c.restart_delay_secs.to_string()).unwrap_or_else(|| "5".to_string())}
                    help="Seconds to wait before restarting"
                    on_change={on_change.reform(|s| ("restart_delay_secs".to_string(), s))}
                />
                <Input
                    label="Max Restart Attempts"
                    name="max_restart_attempts"
                    input_type="number"
                    value={cfg.map(|c| c.max_restart_attempts.to_string()).unwrap_or_else(|| "5".to_string())}
                    help="Maximum restart attempts before giving up"
                    on_change={on_change.reform(|s| ("max_restart_attempts".to_string(), s))}
                />
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Health Check Interval (secs)"
                    name="health_check_interval_secs"
                    input_type="number"
                    value={cfg.map(|c| c.health_check_interval_secs.to_string()).unwrap_or_else(|| "5".to_string())}
                    help="How often to check master health"
                    on_change={on_change.reform(|s| ("health_check_interval_secs".to_string(), s))}
                />
                <Input
                    label="Stable Uptime (secs)"
                    name="stable_uptime_secs"
                    input_type="number"
                    value={cfg.map(|c| c.stable_uptime_secs.to_string()).unwrap_or_else(|| "60".to_string())}
                    help="Uptime required before marking as stable"
                    on_change={on_change.reform(|s| ("stable_uptime_secs".to_string(), s))}
                />
            </div>

            <h3 class="font-semibold text-primary pt-4 border-t border-default">{ "Upgrade Settings" }</h3>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Validation Timeout (secs)"
                    name="upgrade_validation_timeout_secs"
                    input_type="number"
                    value={cfg.map(|c| c.upgrade_validation_timeout_secs.to_string()).unwrap_or_else(|| "10".to_string())}
                    on_change={on_change.reform(|s| ("upgrade_validation_timeout_secs".to_string(), s))}
                />
                <Input
                    label="Drain Timeout (secs)"
                    name="upgrade_drain_timeout_secs"
                    input_type="number"
                    value={cfg.map(|c| c.upgrade_drain_timeout_secs.to_string()).unwrap_or_else(|| "30".to_string())}
                    on_change={on_change.reform(|s| ("upgrade_drain_timeout_secs".to_string(), s))}
                />
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Health Check Retries"
                    name="upgrade_health_check_retries"
                    input_type="number"
                    value={cfg.map(|c| c.upgrade_health_check_retries.to_string()).unwrap_or_else(|| "5".to_string())}
                    on_change={on_change.reform(|s| ("upgrade_health_check_retries".to_string(), s))}
                />
                <Input
                    label="Health Check Interval (secs)"
                    name="upgrade_health_check_interval_secs"
                    input_type="number"
                    value={cfg.map(|c| c.upgrade_health_check_interval_secs.to_string()).unwrap_or_else(|| "2".to_string())}
                    on_change={on_change.reform(|s| ("upgrade_health_check_interval_secs".to_string(), s))}
                />
            </div>

            <h3 class="font-semibold text-primary pt-4 border-t border-default">{ "IPC Settings" }</h3>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="IPC Read Timeout (ms)"
                    name="ipc_read_timeout_ms"
                    input_type="number"
                    value={cfg.map(|c| c.ipc_read_timeout_ms.to_string()).unwrap_or_else(|| "5000".to_string())}
                    on_change={on_change.reform(|s| ("ipc_read_timeout_ms".to_string(), s))}
                />
                <Input
                    label="IPC Write Timeout (ms)"
                    name="ipc_write_timeout_ms"
                    input_type="number"
                    value={cfg.map(|c| c.ipc_write_timeout_ms.to_string()).unwrap_or_else(|| "5000".to_string())}
                    on_change={on_change.reform(|s| ("ipc_write_timeout_ms".to_string(), s))}
                />
            </div>

            <Input
                label="Master Startup Timeout (secs)"
                name="master_startup_timeout_secs"
                input_type="number"
                value={cfg.map(|c| c.master_startup_timeout_secs.to_string()).unwrap_or_else(|| "30".to_string())}
                help="Maximum time to wait for master to start"
                on_change={on_change.reform(|s| ("master_startup_timeout_secs".to_string(), s))}
            />
        </div>
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
