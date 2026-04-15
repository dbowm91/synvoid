use crate::services::api::ApiService;
use crate::types::{
    BackupInfo, HistorySample, ThreatLevelBaseline, ThreatLevelHistory, ThreatLevelStatus,
};
use yew::prelude::*;

#[derive(Clone, PartialEq)]
enum ThreatTab {
    Status,
    History,
    Backups,
    Settings,
}

#[function_component]
pub fn ThreatLevel() -> Html {
    let active_tab = use_state(|| ThreatTab::Status);

    let tab_class = |tab: &ThreatTab| {
        if *active_tab == *tab {
            "px-4 py-2 bg-primary text-white rounded-t-lg border-b-2 border-primary"
        } else {
            "px-4 py-2 bg-secondary text-secondary hover:text-primary rounded-t-lg"
        }
    };

    html! {
        <div>
            <div class="flex justify-between items-center mb-6">
                <h1 class="text-2xl font-bold">{ "Threat Level Management" }</h1>
            </div>

            <div class="flex gap-2 mb-4">
                <button
                    class={tab_class(&ThreatTab::Status)}
                    onclick={let active_tab = active_tab.clone(); move |_| active_tab.set(ThreatTab::Status)}
                >
                    { "Status" }
                </button>
                <button
                    class={tab_class(&ThreatTab::History)}
                    onclick={let active_tab = active_tab.clone(); move |_| active_tab.set(ThreatTab::History)}
                >
                    { "History" }
                </button>
                <button
                    class={tab_class(&ThreatTab::Backups)}
                    onclick={let active_tab = active_tab.clone(); move |_| active_tab.set(ThreatTab::Backups)}
                >
                    { "Backups" }
                </button>
                <button
                    class={tab_class(&ThreatTab::Settings)}
                    onclick={let active_tab = active_tab.clone(); move |_| active_tab.set(ThreatTab::Settings)}
                >
                    { "Settings" }
                </button>
            </div>

            {
                match *active_tab {
                    ThreatTab::Status => html! { <ThreatStatusTab /> },
                    ThreatTab::History => html! { <ThreatHistoryTab /> },
                    ThreatTab::Backups => html! { <ThreatBackupsTab /> },
                    ThreatTab::Settings => html! { <ThreatSettingsTab /> },
                }
            }
        </div>
    }
}

#[function_component]
fn ThreatStatusTab() -> Html {
    let status = use_state(|| None as Option<ThreatLevelStatus>);
    let loading = use_state(|| true);
    let error = use_state(|| None as Option<String>);

    {
        let status = status.clone();
        let loading = loading.clone();
        let error = error.clone();
        use_effect_with((), move |_| {
            let status = status.clone();
            let loading = loading.clone();
            let error = error.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.get_threat_level_status().await {
                    Ok(s) => status.set(Some(s)),
                    Err(e) => error.set(Some(e)),
                }
                loading.set(false);
            });
        });
    }

    let level_color = |level: u8| -> &str {
        match level {
            1 => "text-green-500",
            2 => "text-yellow-500",
            3 => "text-orange-500",
            4 => "text-red-500",
            5 => "text-red-700",
            _ => "text-gray-500",
        }
    };

    let level_label = |level: u8| -> &str {
        match level {
            1 => "Low",
            2 => "Medium",
            3 => "High",
            4 => "Very High",
            5 => "Critical",
            _ => "Unknown",
        }
    };

    html! {
        <div class="bg-secondary rounded-lg border border-default p-6">
            if *loading {
                <div class="text-center py-8">{ "Loading..." }</div>
            } else if let Some(err) = &*error {
                <div class="text-red-500 text-center py-8">{ err }</div>
            } else if let Some(s) = &*status {
                <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div class="bg-tertiary rounded-lg p-4">
                        <h3 class="text-secondary text-sm mb-2">{ "Current Level" }</h3>
                        <div class={classes!("text-4xl", "font-bold", level_color(s.level))}>
                            { s.level }
                        </div>
                        <div class="text-secondary mt-1">{ level_label(s.level) }</div>
                    </div>

                    <div class="bg-tertiary rounded-lg p-4">
                        <h3 class="text-secondary text-sm mb-2">{ "Score" }</h3>
                        <div class="text-4xl font-bold text-primary">
                            { format!("{:.1}", s.score) }
                        </div>
                        <div class="text-secondary mt-1">
                            { format!("Request: {:.1}, Attack: {:.1}, RateLimit: {:.1}",
                                s.request_score, s.attack_score, s.rate_limit_score) }
                        </div>
                    </div>

                    <div class="bg-tertiary rounded-lg p-4">
                        <h3 class="text-secondary text-sm mb-2">{ "Throttling" }</h3>
                        <div class="text-4xl font-bold text-primary">
                            { format!("{:.0}%", s.throttling_multiplier * 100.0) }
                        </div>
                        <div class="text-secondary mt-1">{ "Request throttling multiplier" }</div>
                    </div>
                </div>

                <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6">
                    <div class="bg-tertiary rounded-lg p-4">
                        <div class="text-secondary text-sm">{ "Requests/sec" }</div>
                        <div class="text-xl font-bold text-primary">{ s.requests_per_second }</div>
                    </div>
                    <div class="bg-tertiary rounded-lg p-4">
                        <div class="text-secondary text-sm">{ "Attacks/min" }</div>
                        <div class="text-xl font-bold text-primary">{ s.attacks_per_minute }</div>
                    </div>
                    <div class="bg-tertiary rounded-lg p-4">
                        <div class="text-secondary text-sm">{ "Rate Limit Hits" }</div>
                        <div class="text-xl font-bold text-primary">{ s.rate_limit_hits }</div>
                    </div>
                    <div class="bg-tertiary rounded-lg p-4">
                        <div class="text-secondary text-sm">{ "Blocked" }</div>
                        <div class="text-xl font-bold text-primary">{ s.blocked }</div>
                    </div>
                </div>

                <div class="mt-6 flex items-center gap-4">
                    if s.is_learning {
                        <div class="flex items-center gap-2 text-secondary">
                            <div class="animate-spin w-4 h-4 border-2 border-primary border-t-transparent rounded-full"></div>
                            <span>{ format!("Learning... {:.0}%", s.learning_progress * 100.0) }</span>
                        </div>
                    }
                    if s.has_baseline {
                        <div class="text-green-500">{ "Baseline established" }</div>
                    } else {
                        <div class="text-yellow-500">{ "No baseline - learning mode" }</div>
                    }
                </div>
            }
        </div>
    }
}

#[function_component]
fn ThreatHistoryTab() -> Html {
    let history = use_state(|| None as Option<ThreatLevelHistory>);
    let loading = use_state(|| true);
    let error = use_state(|| None as Option<String>);

    {
        let history = history.clone();
        let loading = loading.clone();
        let error = error.clone();
        use_effect_with((), move |_| {
            let history = history.clone();
            let loading = loading.clone();
            let error = error.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.get_threat_level_history().await {
                    Ok(h) => history.set(Some(h)),
                    Err(e) => error.set(Some(e)),
                }
                loading.set(false);
            });
        });
    }

    let render_samples = |samples: Vec<HistorySample>| -> Html {
        html! {
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="border-b border-default">
                            <th class="text-left py-2 px-3 text-secondary">{ "Timestamp" }</th>
                            <th class="text-left py-2 px-3 text-secondary">{ "Level" }</th>
                            <th class="text-left py-2 px-3 text-secondary">{ "Score" }</th>
                            <th class="text-left py-2 px-3 text-secondary">{ "Req/min" }</th>
                            <th class="text-left py-2 px-3 text-secondary">{ "Attacks/min" }</th>
                            <th class="text-left py-2 px-3 text-secondary">{ "Blocked" }</th>
                        </tr>
                    </thead>
                    <tbody>
                        { for samples.iter().take(20).map(|s| {
                            html! {
                                <tr class="border-b border-default hover:bg-tertiary">
                                    <td class="py-2 px-3 text-primary">
                                        { chronoformat(s.timestamp) }
                                    </td>
                                    <td class="py-2 px-3">
                                        <span class={match s.level {
                                            1 => "text-green-500",
                                            2 => "text-yellow-500",
                                            3 => "text-orange-500",
                                            4 => "text-red-500",
                                            5 => "text-red-700",
                                            _ => "text-gray-500",
                                        }}>{ s.level }</span>
                                    </td>
                                    <td class="py-2 px-3 text-primary">{ format!("{:.1}", s.score) }</td>
                                    <td class="py-2 px-3 text-primary">{ s.requests_per_minute }</td>
                                    <td class="py-2 px-3 text-primary">{ s.attacks_per_minute }</td>
                                    <td class="py-2 px-3 text-primary">{ s.blocked }</td>
                                </tr>
                            }
                        })}
                    </tbody>
                </table>
            </div>
        }
    };

    html! {
        <div class="bg-secondary rounded-lg border border-default p-6">
            if *loading {
                <div class="text-center py-8">{ "Loading..." }</div>
            } else if let Some(err) = &*error {
                <div class="text-red-500 text-center py-8">{ err }</div>
            } else if let Some(h) = &*history {
                <div class="space-y-6">
                    <div>
                        <h3 class="text-lg font-semibold mb-3">{ "Last Hour" }</h3>
                        { render_samples(h.hour.clone()) }
                    </div>
                    <div>
                        <h3 class="text-lg font-semibold mb-3">{ "Last 24 Hours" }</h3>
                        { render_samples(h.day.clone()) }
                    </div>
                    <div>
                        <h3 class="text-lg font-semibold mb-3">{ "Last 7 Days" }</h3>
                        { render_samples(h.week.clone()) }
                    </div>
                </div>
            }
        </div>
    }
}

fn chronoformat(timestamp: i64) -> String {
    let secs = timestamp;
    let datetime = chrono::DateTime::from_timestamp(secs, 0);
    if let Some(dt) = datetime {
        dt.format("%Y-%m-%d %H:%M").to_string()
    } else {
        format!("{}", timestamp)
    }
}

#[function_component]
fn ThreatBackupsTab() -> Html {
    let backups = use_state(|| Vec::<BackupInfo>::new());
    let loading = use_state(|| true);
    let error = use_state(|| None as Option<String>);

    {
        let backups = backups.clone();
        let loading = loading.clone();
        let error = error.clone();
        use_effect_with((), move |_| {
            let backups = backups.clone();
            let loading = loading.clone();
            let error = error.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.list_threat_level_backups().await {
                    Ok(b) => backups.set(b.backups),
                    Err(e) => error.set(Some(e)),
                }
                loading.set(false);
            });
        });
    }

    let on_create_backup = {
        let backups = backups.clone();
        Callback::from(move |_| {
            let backups = backups.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                if let Ok(b) = api.create_threat_level_backup(None).await {
                    let mut current = (*backups).clone();
                    current.insert(0, b);
                    backups.set(current);
                }
            });
        })
    };

    let on_delete = {
        let backups = backups.clone();
        let error = error.clone();
        Callback::from(move |id: String| {
            let backups = backups.clone();
            let error = error.clone();
            let id_clone = id.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.delete_threat_level_backup(&id_clone).await {
                    Ok(true) | Ok(false) => {
                        let mut current = (*backups).clone();
                        current.retain(|b| b.id != id_clone);
                        backups.set(current);
                    }
                    Err(e) => error.set(Some(e)),
                }
            });
        })
    };

    html! {
        <div class="bg-secondary rounded-lg border border-default p-6">
            <div class="flex justify-between items-center mb-4">
                <h3 class="text-lg font-semibold">{ "Backups" }</h3>
                <button
                    onclick={on_create_backup}
                    class="px-4 py-2 bg-primary text-white rounded-lg hover:opacity-80"
                >
                    { "Create Backup" }
                </button>
            </div>

            if *loading {
                <div class="text-center py-8">{ "Loading..." }</div>
            } else if let Some(err) = &*error {
                <div class="text-red-500 text-center py-8">{ err }</div>
            } else if backups.is_empty() {
                <div class="text-secondary text-center py-8">{ "No backups yet" }</div>
            } else {
                <table class="w-full text-sm">
                    <thead>
                        <tr class="border-b border-default">
                            <th class="text-left py-2 px-3 text-secondary">{ "ID" }</th>
                            <th class="text-left py-2 px-3 text-secondary">{ "Timestamp" }</th>
                            <th class="text-left py-2 px-3 text-secondary">{ "Level" }</th>
                            <th class="text-left py-2 px-3 text-secondary">{ "Size" }</th>
                            <th class="text-right py-2 px-3 text-secondary">{ "Actions" }</th>
                        </tr>
                    </thead>
                    <tbody>
                        { for backups.iter().map(|b| {
                            html! {
                                <tr class="border-b border-default hover:bg-tertiary">
                                    <td class="py-2 px-3 text-primary font-mono text-xs">{ &b.id }</td>
                                    <td class="py-2 px-3 text-primary">{ chronoformat(b.timestamp) }</td>
                                    <td class="py-2 px-3 text-primary">{ b.level }</td>
                                    <td class="py-2 px-3 text-primary">{ format_bytes(b.size_bytes) }</td>
                                    <td class="py-2 px-3 text-right">
                                        <button
                                            onclick={let on_delete = on_delete.clone(); let id = b.id.clone(); move |_| on_delete.emit(id.clone())}
                                            class="text-red-500 hover:text-red-400"
                                        >
                                            { "Delete" }
                                        </button>
                                    </td>
                                </tr>
                            }
                        })}
                    </tbody>
                </table>
            }
        </div>
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

#[function_component]
fn ThreatSettingsTab() -> Html {
    let baseline = use_state(|| None as Option<ThreatLevelBaseline>);
    let current_status = use_state(|| None as Option<ThreatLevelStatus>);
    let loading = use_state(|| true);
    let error = use_state(|| None as Option<String>);

    {
        let baseline = baseline.clone();
        let current_status = current_status.clone();
        let loading = loading.clone();
        let error = error.clone();
        use_effect_with((), move |_| {
            let baseline = baseline.clone();
            let current_status = current_status.clone();
            let loading = loading.clone();
            let error = error.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.get_threat_level_baseline().await {
                    Ok(b) => baseline.set(Some(b)),
                    Err(e) => error.set(Some(e)),
                }
                match api.get_threat_level_status().await {
                    Ok(s) => current_status.set(Some(s)),
                    Err(e) => error.set(Some(e)),
                }
                loading.set(false);
            });
        });
    }

    let on_set_level = {
        let error = error.clone();
        let current_status = current_status.clone();
        Callback::from(move |level: u8| {
            let error = error.clone();
            let current_status = current_status.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.set_threat_level(level).await {
                    Ok(_) => {
                        if let Ok(s) = api.get_threat_level_status().await {
                            current_status.set(Some(s));
                        }
                    }
                    Err(e) => error.set(Some(e)),
                }
            });
        })
    };

    let on_toggle_auto = {
        let error = error.clone();
        let current_status = current_status.clone();
        Callback::from(move |enabled: bool| {
            let error = error.clone();
            let current_status = current_status.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.set_threat_level_auto(enabled).await {
                    Ok(_) => {
                        if let Ok(s) = api.get_threat_level_status().await {
                            current_status.set(Some(s));
                        }
                    }
                    Err(e) => error.set(Some(e)),
                }
            });
        })
    };

    let on_reset_baseline = {
        let baseline = baseline.clone();
        Callback::from(move |_| {
            let baseline = baseline.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                if api.reset_threat_level_baseline().await.is_ok() {
                    if let Ok(b) = api.get_threat_level_baseline().await {
                        baseline.set(Some(b));
                    }
                }
            });
        })
    };

    html! {
        <div class="bg-secondary rounded-lg border border-default p-6">
            if *loading {
                <div class="text-center py-8">{ "Loading..." }</div>
            } else if let Some(err) = &*error {
                <div class="text-red-500 text-center py-8">{ err }</div>
            } else {
                <div class="space-y-6">
                    <div>
                        <h3 class="text-lg font-semibold mb-4">{ "Manual Level Control" }</h3>
                        <div class="flex gap-2">
                            { for (1..=5).map(|level| {
                                let is_active = current_status.as_ref().map_or(false, |s| s.level == level);
                                let on_set = on_set_level.clone();
                                let base_class = if is_active { "bg-primary text-white border-primary" } else { "bg-tertiary text-primary border-default hover:border-primary" };
                                html! {
                                    <button
                                        onclick={move |_| on_set.emit(level)}
                                        class={classes!("px-4", "py-2", "rounded-lg", "border", base_class)}
                                    >
                                        { format!("Level {}", level) }
                                    </button>
                                }
                            })}
                        </div>
                        <p class="text-secondary text-sm mt-2">
                            { "Manually set threat level. This disables auto-scaling." }
                        </p>
                    </div>

                    <div class="border-t border-default pt-6">
                        <h3 class="text-lg font-semibold mb-4">{ "Auto-Scaling" }</h3>
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-primary font-medium">{ "Enable Auto-Scaling" }</p>
                                <p class="text-sm text-secondary">
                                    { "Automatically adjust threat level based on attack frequency" }
                                </p>
                            </div>
                            <button
                                onclick={let on_toggle = on_toggle_auto.clone(); let status = current_status.clone(); move |_| {
                                    let enabled = status.as_ref().map_or(false, |s| s.is_learning);
                                    on_toggle.emit(!enabled);
                                }}
                                class={classes!(
                                    "relative",
                                    "w-12",
                                    "h-6",
                                    "rounded-full",
                                    "transition-colors",
                                    if current_status.as_ref().map_or(false, |s| s.is_learning) { "bg-green-500" } else { "bg-gray-600" }
                                )}
                            >
                                <span class={classes!(
                                    "absolute",
                                    "top-1",
                                    "w-4",
                                    "h-4",
                                    "bg-white",
                                    "rounded-full",
                                    "transition-transform",
                                    if current_status.as_ref().map_or(false, |s| s.is_learning) { "translate-x-7" } else { "translate-x-1" }
                                )} />
                            </button>
                        </div>
                    </div>

                    <div class="border-t border-default pt-6">
                        <h3 class="text-lg font-semibold mb-4">{ "Baseline" }</h3>
                        if let Some(b) = &*baseline {
                            <div class="bg-tertiary rounded-lg p-4">
                                <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                                    <div>
                                        <div class="text-secondary text-sm">{ "Metrics" }</div>
                                        <div class="text-xl font-bold text-primary">{ b.baselines.len() }</div>
                                    </div>
                                    { for b.baselines.iter().take(3).map(|m| {
                                        html! {
                                            <div>
                                                <div class="text-secondary text-sm">{ &m.metric_name }</div>
                                                <div class="text-xl font-bold text-primary">{ format!("{:.1}", m.mean) }</div>
                                            </div>
                                        }
                                    }) }
                                </div>
                            </div>
                        } else {
                            <p class="text-secondary">{ "No baseline established yet" }</p>
                        }
                        <button
                            onclick={on_reset_baseline}
                            class="mt-4 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
                        >
                            { "Reset Baseline" }
                        </button>
                        <p class="text-secondary text-sm mt-2">
                            { "Reset baseline to start fresh learning. Current threat level will reset." }
                        </p>
                    </div>
                </div>
            }
        </div>
    }
}
