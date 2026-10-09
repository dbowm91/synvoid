use crate::components::toast::{toast_error, toast_success};
use crate::components::tooltip::HelpIcon;
use crate::services::ApiService;
use crate::types::{
    BlocklistHealthDiagnostics, FeaturesDiagnostics, PluginDiagnostics, RuntimeTasksDiagnostics,
    SecurityObservabilitySummary, ThreatIntelDiagnostics,
};
use yew::prelude::*;

/// Read-only runtime diagnostics.
///
/// Backs all six `/api/observability/*` endpoints, which had no UI at all:
/// every counter here was reachable only from the REST surface. All six are
/// always registered and carry no runtime feature gate, so this page is
/// ungated and safe to deep-link.
///
/// Counters are process-lifetime monotonic values. Nothing on this page
/// mutates state, so there is no confirm dialog — only a manual refresh.
#[function_component]
pub fn Observability() -> Html {
    let summary = use_state(|| None as Option<SecurityObservabilitySummary>);
    let tasks = use_state(|| None as Option<RuntimeTasksDiagnostics>);
    let blocklist = use_state(|| None as Option<BlocklistHealthDiagnostics>);
    let plugins = use_state(|| None as Option<PluginDiagnostics>);
    let features = use_state(|| None as Option<FeaturesDiagnostics>);
    let threat_intel = use_state(|| None as Option<ThreatIntelDiagnostics>);

    // One failure must not blank the page: each section keeps its own state so
    // a 404 on one endpoint still renders the other five.
    let failures = use_state(Vec::<String>::new);
    let loading = use_state(|| false);
    let loaded_once = use_state(|| false);

    {
        let summary = summary.clone();
        let tasks = tasks.clone();
        let blocklist = blocklist.clone();
        let plugins = plugins.clone();
        let features = features.clone();
        let threat_intel = threat_intel.clone();
        let failures = failures.clone();
        let loading = loading.clone();
        let loaded_once = loaded_once.clone();

        use_effect_with((), move |_| {
            let summary = summary.clone();
            let tasks = tasks.clone();
            let blocklist = blocklist.clone();
            let plugins = plugins.clone();
            let features = features.clone();
            let threat_intel = threat_intel.clone();
            let failures = failures.clone();
            let loading = loading.clone();
            let loaded_once = loaded_once.clone();

            wasm_bindgen_futures::spawn_local(async move {
                loading.set(true);
                let api = ApiService::new();
                let mut errors: Vec<String> = Vec::new();

                match api.get_security_observability_summary().await {
                    Ok(v) => summary.set(Some(v)),
                    Err(e) => errors.push(format!("Security summary: {}", e)),
                }
                match api.get_runtime_tasks_diagnostics().await {
                    Ok(v) => tasks.set(Some(v)),
                    Err(e) => errors.push(format!("Task registry: {}", e)),
                }
                match api.get_blocklist_health().await {
                    Ok(v) => blocklist.set(Some(v)),
                    Err(e) => errors.push(format!("Blocklist health: {}", e)),
                }
                match api.get_plugin_diagnostics().await {
                    Ok(v) => plugins.set(Some(v)),
                    Err(e) => errors.push(format!("Plugins: {}", e)),
                }
                match api.get_features_diagnostics().await {
                    Ok(v) => features.set(Some(v)),
                    Err(e) => errors.push(format!("Features: {}", e)),
                }
                match api.get_threat_intel_diagnostics().await {
                    Ok(v) => threat_intel.set(Some(v)),
                    Err(e) => errors.push(format!("Threat intel: {}", e)),
                }

                if !errors.is_empty() {
                    tracing::error!("observability: partial failure: {}", errors.join("; "));
                }
                failures.set(errors);
                loading.set(false);
                loaded_once.set(true);
            });

            || ()
        });
    }

    let on_refresh = {
        let summary = summary.clone();
        let tasks = tasks.clone();
        let blocklist = blocklist.clone();
        let plugins = plugins.clone();
        let features = features.clone();
        let threat_intel = threat_intel.clone();
        let failures = failures.clone();
        let loading = loading.clone();

        Callback::from(move |_: MouseEvent| {
            let summary = summary.clone();
            let tasks = tasks.clone();
            let blocklist = blocklist.clone();
            let plugins = plugins.clone();
            let features = features.clone();
            let threat_intel = threat_intel.clone();
            let failures = failures.clone();
            let loading = loading.clone();

            wasm_bindgen_futures::spawn_local(async move {
                loading.set(true);
                let api = ApiService::new();
                let mut errors: Vec<String> = Vec::new();

                match api.get_security_observability_summary().await {
                    Ok(v) => summary.set(Some(v)),
                    Err(e) => errors.push(format!("Security summary: {}", e)),
                }
                match api.get_runtime_tasks_diagnostics().await {
                    Ok(v) => tasks.set(Some(v)),
                    Err(e) => errors.push(format!("Task registry: {}", e)),
                }
                match api.get_blocklist_health().await {
                    Ok(v) => blocklist.set(Some(v)),
                    Err(e) => errors.push(format!("Blocklist health: {}", e)),
                }
                match api.get_plugin_diagnostics().await {
                    Ok(v) => plugins.set(Some(v)),
                    Err(e) => errors.push(format!("Plugins: {}", e)),
                }
                match api.get_features_diagnostics().await {
                    Ok(v) => features.set(Some(v)),
                    Err(e) => errors.push(format!("Features: {}", e)),
                }
                match api.get_threat_intel_diagnostics().await {
                    Ok(v) => threat_intel.set(Some(v)),
                    Err(e) => errors.push(format!("Threat intel: {}", e)),
                }

                if errors.is_empty() {
                    toast_success("Diagnostics refreshed");
                } else {
                    toast_error(&format!("{} of 6 endpoints failed", errors.len()));
                }
                failures.set(errors);
                loading.set(false);
            });
        })
    };

    let failed = (*failures).clone();

    html! {
        <div class="space-y-6">
            <header class="flex flex-wrap items-center justify-between gap-2">
                <div class="min-w-0">
                    <h1 class="text-2xl font-bold">{ "Observability" }</h1>
                    <p class="text-sm text-secondary">
                        { "Runtime counters for task registries, blocklist convergence and threat-intel enforcement." }
                    </p>
                </div>
                <button
                    onclick={on_refresh}
                    disabled={*loading}
                    class="px-4 py-2 rounded-lg bg-action-600 hover:bg-action-700 text-white disabled:opacity-50 transition expand-hit"
                >
                    { if *loading { "Refreshing…" } else { "Refresh" } }
                </button>
            </header>

            if !failed.is_empty() {
                <div class="p-4 rounded-lg bg-red-500/10 border border-red-500 flex items-start gap-3">
                    <div class="min-w-0">
                        <p class="text-sm text-red-400 font-medium">
                            { "Some diagnostic endpoints did not respond" }
                        </p>
                        <ul class="text-xs text-secondary mt-1 space-y-0.5 list-disc list-inside">
                            { for failed.iter().map(|e| html! { <li>{ e }</li> }) }
                        </ul>
                    </div>
                </div>
            }

            if !*loaded_once {
                <crate::components::skeleton::LoadingPage />
            } else {

            // ── Compile-time feature profile ──────────────────────────────
            <section class="bg-secondary rounded-lg border border-default p-4">
                <div class="flex items-center gap-2 mb-3">
                    <h2 class="text-lg font-semibold">{ "Feature Profile" }</h2>
                    <HelpIcon
                        content={"Compile-time cargo features this binary was built with. These are not runtime settings and cannot be toggled from the dashboard."}
                    />
                </div>
                {
                    match (*features).clone() {
                        Some(f) => html! {
                            <div class="flex flex-wrap gap-2">
                                <FeatureBadge name="Mesh" enabled={f.mesh_enabled} />
                                <FeatureBadge name="DNS" enabled={f.dns_enabled} />
                                <FeatureBadge name="Erased pool" enabled={f.erased_pool_enabled} />
                                <FeatureBadge name="Swagger UI" enabled={f.swagger_ui_enabled} />
                                <FeatureBadge name="Socket handoff" enabled={f.socket_handoff_enabled} />
                                <FeatureBadge name="ICMP filter" enabled={f.icmp_filter_enabled} />
                            </div>
                        },
                        None => html! { <Missing /> },
                    }
                }
            </section>

            // ── Security summary ──────────────────────────────────────────
            <section class="bg-secondary rounded-lg border border-default p-4">
                <div class="flex items-center gap-2 mb-3">
                    <h2 class="text-lg font-semibold">{ "Security Summary" }</h2>
                    <HelpIcon
                        content={"Bounded snapshot of security-relevant counters: live task registration, blocklist convergence, and whether mesh/DNS were compiled in."}
                    />
                </div>
                {
                    match (*summary).clone() {
                        Some(s) => html! {
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div>
                                    <h3 class="text-sm font-medium text-secondary mb-2">{ "Runtime tasks" }</h3>
                                    <MetricRow label="Unified servers registered" value={s.runtime_tasks.unified_server_registered} />
                                    <MetricRow label="Shutdowns" value={s.runtime_tasks.unified_server_shutdown_count} />
                                    <MetricRow
                                        label="Critical failures"
                                        value={s.runtime_tasks.unified_server_critical_failures}
                                        alert={s.runtime_tasks.unified_server_critical_failures > 0}
                                    />
                                </div>
                                <div>
                                    <h3 class="text-sm font-medium text-secondary mb-2">{ "Blocklist convergence" }</h3>
                                    <MetricRow label="Applied" value={s.blocklist_convergence.event_apply_applied} />
                                    <MetricRow label="Duplicates" value={s.blocklist_convergence.event_apply_duplicate} />
                                    <MetricRow label="Stale" value={s.blocklist_convergence.event_apply_stale} />
                                    <MetricRow
                                        label="Snapshot fallbacks"
                                        value={s.blocklist_convergence.snapshot_fallbacks}
                                        alert={s.blocklist_convergence.snapshot_fallbacks > 0}
                                    />
                                </div>
                            </div>
                        },
                        None => html! { <Missing /> },
                    }
                }
            </section>

            // ── Task registry ─────────────────────────────────────────────
            <section class="bg-secondary rounded-lg border border-default p-4">
                <div class="flex items-center gap-2 mb-3">
                    <h2 class="text-lg font-semibold">{ "Task Registry" }</h2>
                    <HelpIcon
                        content={"Live task counts per owner. Panics and critical failures here indicate tasks that did not shut down cleanly."}
                    />
                </div>
                {
                    match (*tasks).clone() {
                        Some(t) => html! {
                            <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
                                <div>
                                    <h3 class="text-sm font-medium text-secondary mb-2">{ "Unified server" }</h3>
                                    <MetricRow label="Registered" value={t.unified_server.registered} />
                                    <MetricRow label="Exit completed" value={t.unified_server.exit_completed} />
                                    <MetricRow label="Exit failed" value={t.unified_server.exit_failed} alert={t.unified_server.exit_failed > 0} />
                                    <MetricRow label="Exit aborted" value={t.unified_server.exit_aborted} alert={t.unified_server.exit_aborted > 0} />
                                    <MetricRow label="Exit timed out" value={t.unified_server.exit_timed_out} alert={t.unified_server.exit_timed_out > 0} />
                                    <MetricRow label="Critical failures" value={t.unified_server.critical_failures} alert={t.unified_server.critical_failures > 0} />
                                    <MetricRow label="Shutdowns" value={t.unified_server.shutdown_count} />
                                </div>
                                <div>
                                    <h3 class="text-sm font-medium text-secondary mb-2">{ "Worker" }</h3>
                                    <MetricRow label="Started" value={t.worker.tasks_started} />
                                    <MetricRow label="Completed cleanly" value={t.worker.tasks_completed_cleanly} />
                                    <MetricRow label="Cancelled" value={t.worker.tasks_cancelled} />
                                    <MetricRow label="Panicked" value={t.worker.tasks_panicked} alert={t.worker.tasks_panicked > 0} />
                                    <MetricRow label="Aborted" value={t.worker.tasks_aborted} />
                                    <MetricRow label="Errored" value={t.worker.tasks_errored} alert={t.worker.tasks_errored > 0} />
                                </div>
                                <div>
                                    <h3 class="text-sm font-medium text-secondary mb-2">{ "Supervisor" }</h3>
                                    <MetricRow label="Registered" value={t.supervisor.registered} />
                                    <MetricRow label="Completed" value={t.supervisor.completed} />
                                    <MetricRow label="Failed" value={t.supervisor.failed} alert={t.supervisor.failed > 0} />
                                    <MetricRow label="Aborted" value={t.supervisor.aborted} />
                                    <MetricRow label="Timed out" value={t.supervisor.timed_out} alert={t.supervisor.timed_out > 0} />
                                </div>
                            </div>
                        },
                        None => html! { <Missing /> },
                    }
                }
            </section>

            // ── Blocklist health ──────────────────────────────────────────
            <section class="bg-secondary rounded-lg border border-default p-4">
                <div class="flex items-center gap-2 mb-3">
                    <h2 class="text-lg font-semibold">{ "Blocklist Health" }</h2>
                    <HelpIcon
                        content={"Convergence counters for blocklist updates. A rising stale/invalid/snapshot-fallback count means nodes are not converging on the same blocklist."}
                    />
                </div>
                {
                    match (*blocklist).clone() {
                        Some(b) => html! {
                            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-x-6">
                                <MetricRow label="Events applied" value={b.event_apply_applied} />
                                <MetricRow label="Duplicates" value={b.event_apply_duplicate} />
                                <MetricRow label="Stale events" value={b.event_apply_stale} />
                                <MetricRow label="Invalid events" value={b.event_apply_invalid} alert={b.event_apply_invalid > 0} />
                                <MetricRow label="Stale replays ignored" value={b.stale_replay_ignored} />
                                <MetricRow label="Cursor updates" value={b.cursor_update} />
                                <MetricRow label="Cursor loads" value={b.cursor_load} />
                                <MetricRow label="Snapshot applies" value={b.snapshot_apply} />
                                <MetricRow label="Snapshot fallbacks" value={b.snapshot_fallback} alert={b.snapshot_fallback > 0} />
                                <MetricRow label="Ordering: source sequence" value={b.ordering_path_source_sequence} />
                                <MetricRow label="Ordering: timestamp" value={b.ordering_path_timestamp} />
                            </div>
                        },
                        None => html! { <Missing /> },
                    }
                }
            </section>

            // ── Threat intel ──────────────────────────────────────────────
            <section class="bg-secondary rounded-lg border border-default p-4">
                <div class="flex items-center gap-2 mb-3">
                    <h2 class="text-lg font-semibold">{ "Threat Intelligence" }</h2>
                    <HelpIcon
                        content={"DHT publish/lookup/sync counters plus the policy-shadow actionability split. Shadow counts are diagnostic only and never mutate block state."}
                    />
                </div>
                {
                    match (*threat_intel).clone() {
                        Some(t) => html! {
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div>
                                    <h3 class="text-sm font-medium text-secondary mb-2">{ "DHT" }</h3>
                                    <MetricRow label="Published" value={t.dht_publish_total} />
                                    <MetricRow label="Publish failures" value={t.dht_publish_failed} alert={t.dht_publish_failed > 0} />
                                    <MetricRow label="Lookup hits" value={t.dht_lookup_hits} />
                                    <MetricRow label="Lookup misses" value={t.dht_lookup_misses} />
                                    <MetricRow label="Syncs" value={t.dht_sync_total} />
                                    <MetricRow label="Sync successes" value={t.dht_sync_success} />
                                    <MetricRow label="Sync failures" value={t.dht_sync_failed} alert={t.dht_sync_failed > 0} />
                                    <MetricRow label="Indicators added" value={t.dht_sync_added} />
                                    <MetricRow label="Indicators removed" value={t.dht_sync_removed} />
                                </div>
                                <div>
                                    <h3 class="text-sm font-medium text-secondary mb-2">{ "Policy shadow" }</h3>
                                    <MetricRow label="Actionable" value={t.policy_shadow_actionable} />
                                    <MetricRow label="Advisory only" value={t.policy_shadow_advisory_only} />
                                    <MetricRow label="Not actionable" value={t.policy_shadow_not_actionable} />
                                    <MetricRow label="Deferred" value={t.policy_shadow_deferred} />
                                    <MetricRow label="Not configured" value={t.policy_shadow_not_configured} />
                                </div>
                            </div>
                        },
                        None => html! { <Missing /> },
                    }
                }
            </section>

            // ── Plugins ───────────────────────────────────────────────────
            <section class="bg-secondary rounded-lg border border-default p-4">
                <div class="flex items-center gap-2 mb-3">
                    <h2 class="text-lg font-semibold">{ "Plugin Runtime" }</h2>
                    <HelpIcon
                        content={"WASM plugin invocation and error counters. Reloading a plugin is a mutation and lives on the Plugins page."}
                    />
                </div>
                {
                    match (*plugins).clone() {
                        Some(p) if !p.plugins.is_empty() => html! {
                            <>
                                <p class="text-sm text-secondary mb-3">
                                    { format!("{} plugin(s) loaded", p.loaded_count) }
                                </p>
                                <div class="overflow-x-auto">
                                    <table class="w-full text-sm">
                                        <thead>
                                            <tr class="text-left text-secondary border-b border-default">
                                                <th class="py-2 pr-4 font-medium">{ "Plugin" }</th>
                                                <th class="py-2 pr-4 font-medium text-right">{ "Invocations" }</th>
                                                <th class="py-2 pr-4 font-medium text-right">{ "Errors" }</th>
                                                <th class="py-2 font-medium text-right">{ "Avg duration" }</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            { for p.plugins.iter().map(|plugin| html! {
                                                <tr class="border-b border-default/50">
                                                    <td class="py-2 pr-4 font-mono text-xs break-all">{ &plugin.name }</td>
                                                    <td class="py-2 pr-4 text-right font-mono">{ plugin.invocations }</td>
                                                    <td class={classes!(
                                                        "py-2",
                                                        "pr-4",
                                                        "text-right",
                                                        "font-mono",
                                                        if plugin.errors > 0 {
                                                            "text-red-400"
                                                        } else {
                                                            ""
                                                        }
                                                    )}>
                                                        { plugin.errors }
                                                    </td>
                                                    <td class="py-2 text-right font-mono">
                                                        { format_duration_ms(plugin.avg_duration_ms) }
                                                    </td>
                                                </tr>
                                            }) }
                                        </tbody>
                                    </table>
                                </div>
                            </>
                        },
                        Some(_) => html! {
                            <p class="text-sm text-secondary">
                                { "No plugins are loaded in this process." }
                            </p>
                        },
                        None => html! { <Missing /> },
                    }
                }
            </section>
            }
        </div>
    }
}

/// Formats a backend `f64` millisecond value.
///
/// The backend serialises `avg_duration_ms` as a bare `f64` with no non-finite
/// guard, so a `NaN` or `Infinity` would otherwise reach the DOM as a literal
/// "NaN" and `width: NaN%` style usage would be invalid.
fn format_duration_ms(value: f64) -> String {
    if !value.is_finite() {
        return "—".to_string();
    }
    if value < 0.01 {
        format!("{:.3} ms", value)
    } else if value < 10.0 {
        format!("{:.2} ms", value)
    } else {
        format!("{:.1} ms", value)
    }
}

#[derive(Properties, PartialEq)]
struct MetricRowProps {
    label: String,
    value: u64,
    #[prop_or_default]
    alert: bool,
}

#[function_component]
fn MetricRow(props: &MetricRowProps) -> Html {
    html! {
        <div class="flex items-baseline justify-between gap-3 py-1 border-b border-default/40 last:border-0">
            <span class="text-sm text-secondary min-w-0 truncate">{ &props.label }</span>
            <span class={classes!(
                "font-mono",
                "text-sm",
                "shrink-0",
                if props.alert { "text-red-400" } else { "text-primary" }
            )}>
                { props.value }
            </span>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct FeatureBadgeProps {
    name: String,
    enabled: bool,
}

#[function_component]
fn FeatureBadge(props: &FeatureBadgeProps) -> Html {
    html! {
        <span class={classes!(
            "px-3",
            "py-1",
            "rounded-full",
            "text-xs",
            "font-medium",
            "border",
            if props.enabled {
                "bg-green-500/10 text-green-400 border-green-500"
            } else {
                "bg-default/10 text-tertiary border-default"
            }
        )}>
            { props.name.clone() }
            { if props.enabled { " \u{2713}" } else { "" } }
        </span>
    }
}

#[function_component]
fn Missing() -> Html {
    html! { <p class="text-sm text-tertiary">{ "Unavailable." }</p> }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_finite_durations_never_reach_the_dom_as_nan() {
        // The backend emits a bare `f64` with no non-finite guard, so a NaN or
        // Infinity metric must render as a placeholder rather than "NaN".
        assert_eq!(format_duration_ms(f64::NAN), "—");
        assert_eq!(format_duration_ms(f64::INFINITY), "—");
        assert_eq!(format_duration_ms(f64::NEG_INFINITY), "—");
    }

    #[test]
    fn finite_durations_keep_sub_millisecond_precision() {
        assert_eq!(format_duration_ms(0.0), "0.000 ms");
        assert_eq!(format_duration_ms(0.0042), "0.004 ms");
        assert_eq!(format_duration_ms(1.5), "1.50 ms");
        assert_eq!(format_duration_ms(250.0), "250.0 ms");
    }
}
