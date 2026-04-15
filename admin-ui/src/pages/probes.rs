use crate::services::api::ApiService;
use yew::prelude::*;

#[derive(Clone, PartialEq)]
enum ProbeTab {
    Honeypot,
    SuspiciousWords,
    UpstreamErrors,
}

#[function_component]
pub fn Probes() -> Html {
    let active_tab = use_state(|| ProbeTab::Honeypot);

    let tab_class = |tab: &ProbeTab| {
        if *active_tab == *tab {
            "px-4 py-2 bg-primary text-white rounded-t-lg border-b-2 border-primary"
        } else {
            "px-4 py-2 bg-secondary text-secondary hover:text-primary rounded-t-lg"
        }
    };

    html! {
        <div>
            <div class="flex justify-between items-center mb-6">
                <h1 class="text-2xl font-bold">{ "Suspicious Probing Activity" }</h1>
            </div>

            <div class="flex gap-2 mb-4">
                <button
                    class={tab_class(&ProbeTab::Honeypot)}
                    onclick={let active_tab = active_tab.clone(); move |_| active_tab.set(ProbeTab::Honeypot)}
                >
                    { "Honeypot Hits" }
                </button>
                <button
                    class={tab_class(&ProbeTab::SuspiciousWords)}
                    onclick={let active_tab = active_tab.clone(); move |_| active_tab.set(ProbeTab::SuspiciousWords)}
                >
                    { "Suspicious Words" }
                </button>
                <button
                    class={tab_class(&ProbeTab::UpstreamErrors)}
                    onclick={let active_tab = active_tab.clone(); move |_| active_tab.set(ProbeTab::UpstreamErrors)}
                >
                    { "Upstream Errors" }
                </button>
            </div>

            {
                match *active_tab {
                    ProbeTab::Honeypot => html! { <HoneypotProbes /> },
                    ProbeTab::SuspiciousWords => html! { <SuspiciousWordsTab /> },
                    ProbeTab::UpstreamErrors => html! { <UpstreamErrorsTab /> },
                }
            }
        </div>
    }
}

#[derive(Clone, serde::Deserialize)]
struct HoneypotProbeStats {
    total_records: u64,
    active_records: u64,
    total_events: u64,
    top_endpoints: Vec<EndpointCount>,
}

#[derive(Clone, serde::Deserialize)]
struct EndpointCount {
    endpoint: String,
    count: u32,
}

#[derive(Clone, serde::Deserialize)]
struct HoneypotProbe {
    ip: String,
    event_count: u32,
    unique_endpoints: Vec<String>,
    last_seen: u64,
    user_agent: Option<String>,
}

#[function_component]
fn HoneypotProbes() -> Html {
    let probes = use_state(|| Vec::<HoneypotProbe>::new());
    let stats = use_state(|| None as Option<HoneypotProbeStats>);
    let loading = use_state(|| true);

    {
        let probes = probes.clone();
        let stats = stats.clone();
        let loading = loading.clone();
        use_effect_with((), move |_| {
            let probes = probes.clone();
            let stats = stats.clone();
            let loading = loading.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();

                if let Ok(data) = api.get::<serde_json::Value>("/probes").await {
                    if let Some(probes_arr) = data.get("probes").and_then(|v| v.as_array()) {
                        let parsed: Vec<HoneypotProbe> = probes_arr
                            .iter()
                            .filter_map(|p| serde_json::from_value(p.clone()).ok())
                            .collect();
                        probes.set(parsed);
                    }
                }

                if let Ok(data) = api.get::<serde_json::Value>("/probes/stats").await {
                    if let Ok(s) = serde_json::from_value(data) {
                        stats.set(Some(s));
                    }
                }

                loading.set(false);
            });
            || ()
        });
    }

    let format_timestamp = |ts: u64| {
        chrono::DateTime::from_timestamp(ts as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "Unknown".to_string())
    };

    if *loading {
        return html! {
            <div class="flex justify-center py-12">
                <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
            </div>
        };
    }

    let stats = (*stats).clone();

    html! {
        <div>
            if let Some(s) = stats {
                <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                    <div class="bg-secondary rounded-lg p-4 border border-default">
                        <p class="text-sm text-secondary">{ "Total Records" }</p>
                        <p class="text-2xl font-bold mt-1">{ s.total_records }</p>
                    </div>
                    <div class="bg-secondary rounded-lg p-4 border border-default">
                        <p class="text-sm text-secondary">{ "Active Records" }</p>
                        <p class="text-2xl font-bold mt-1">{ s.active_records }</p>
                    </div>
                    <div class="bg-secondary rounded-lg p-4 border border-default">
                        <p class="text-sm text-secondary">{ "Total Events" }</p>
                        <p class="text-2xl font-bold mt-1">{ s.total_events }</p>
                    </div>
                    <div class="bg-secondary rounded-lg p-4 border border-default">
                        <p class="text-sm text-secondary">{ "Top Endpoints" }</p>
                        <div class="mt-2 space-y-1">
                            { for s.top_endpoints.iter().take(3).map(|e| {
                                html! {
                                    <div class="flex justify-between text-sm">
                                        <span class="truncate max-w-[120px] text-secondary" title={e.endpoint.clone()}>
                                            { &e.endpoint }
                                        </span>
                                        <span class="text-primary">{ e.count }</span>
                                    </div>
                                }
                            })}
                        </div>
                    </div>
                </div>
            }

            <div class="bg-secondary rounded-lg border border-default overflow-hidden">
                <table class="w-full">
                    <thead class="bg-tertiary">
                        <tr>
                            <th class="px-4 py-3 text-left text-sm font-semibold text-secondary">{ "IP Address" }</th>
                            <th class="px-4 py-3 text-left text-sm font-semibold text-secondary">{ "Events" }</th>
                            <th class="px-4 py-3 text-left text-sm font-semibold text-secondary">{ "Unique Endpoints" }</th>
                            <th class="px-4 py-3 text-left text-sm font-semibold text-secondary">{ "Last Seen" }</th>
                            <th class="px-4 py-3 text-left text-sm font-semibold text-secondary">{ "User Agent" }</th>
                        </tr>
                    </thead>
                    <tbody>
                        { for probes.iter().map(|probe| {
                            html! {
                                <tr class="border-t border-default hover:bg-tertiary transition">
                                    <td class="px-4 py-3 font-mono text-sm">{ &probe.ip }</td>
                                    <td class="px-4 py-3">{ probe.event_count }</td>
                                    <td class="px-4 py-3">
                                        <div class="flex flex-wrap gap-1">
                                            { for probe.unique_endpoints.iter().take(3).map(|ep| {
                                                html! { <span class="px-2 py-0.5 bg-red-900/50 text-red-300 text-xs rounded">{ ep }</span> }
                                            })}
                                        </div>
                                    </td>
                                    <td class="px-4 py-3 text-sm text-secondary">{ format_timestamp(probe.last_seen) }</td>
                                    <td class="px-4 py-3 text-sm text-secondary truncate max-w-[200px]">
                                        { probe.user_agent.as_deref().unwrap_or("Unknown") }
                                    </td>
                                </tr>
                            }
                        })}
                    </tbody>
                </table>

                if probes.is_empty() {
                    <div class="p-8 text-center text-secondary">
                        { "No honeypot activity detected" }
                    </div>
                }
            </div>
        </div>
    }
}

#[derive(Clone, serde::Deserialize)]
struct SuspiciousWordStats {
    total_ips: usize,
    total_matches: u64,
    top_words: Vec<WordCount>,
}

#[derive(Clone, serde::Deserialize)]
struct WordCount {
    word: String,
    count: u32,
}

#[derive(Clone, serde::Deserialize)]
struct SuspiciousWordRecord {
    ip: String,
    matched_word: String,
    endpoint: String,
    timestamp: u64,
}

#[function_component]
fn SuspiciousWordsTab() -> Html {
    let records = use_state(|| Vec::<SuspiciousWordRecord>::new());
    let stats = use_state(|| None as Option<SuspiciousWordStats>);
    let loading = use_state(|| true);

    {
        let records = records.clone();
        let stats = stats.clone();
        let loading = loading.clone();
        use_effect_with((), move |_| {
            let records = records.clone();
            let stats = stats.clone();
            let loading = loading.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();

                if let Ok(data) = api.get::<serde_json::Value>("/probes/words").await {
                    if let Some(records_arr) = data.get("records").and_then(|v| v.as_array()) {
                        let parsed: Vec<SuspiciousWordRecord> = records_arr
                            .iter()
                            .filter_map(|r| serde_json::from_value(r.clone()).ok())
                            .collect();
                        records.set(parsed);
                    }
                }

                if let Ok(data) = api.get::<serde_json::Value>("/probes/words/stats").await {
                    if let Ok(s) = serde_json::from_value(data) {
                        stats.set(Some(s));
                    }
                }

                loading.set(false);
            });
            || ()
        });
    }

    let format_timestamp = |ts: u64| {
        chrono::DateTime::from_timestamp(ts as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "Unknown".to_string())
    };

    if *loading {
        return html! {
            <div class="flex justify-center py-12">
                <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
            </div>
        };
    }

    let stats = (*stats).clone();

    html! {
        <div>
            if let Some(s) = stats {
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                    <div class="bg-secondary rounded-lg p-4 border border-default">
                        <p class="text-sm text-secondary">{ "Unique IPs" }</p>
                        <p class="text-2xl font-bold mt-1">{ s.total_ips }</p>
                    </div>
                    <div class="bg-secondary rounded-lg p-4 border border-default">
                        <p class="text-sm text-secondary">{ "Total Matches" }</p>
                        <p class="text-2xl font-bold mt-1">{ s.total_matches }</p>
                    </div>
                    <div class="bg-secondary rounded-lg p-4 border border-default">
                        <p class="text-sm text-secondary">{ "Top Words" }</p>
                        <div class="mt-2 space-y-1">
                            { for s.top_words.iter().take(3).map(|w| {
                                html! {
                                    <div class="flex justify-between text-sm">
                                        <span class="text-yellow-400">{ &w.word }</span>
                                        <span class="text-primary">{ w.count }</span>
                                    </div>
                                }
                            })}
                        </div>
                    </div>
                </div>
            }

            <div class="bg-secondary rounded-lg border border-default overflow-hidden">
                <table class="w-full">
                    <thead class="bg-tertiary">
                        <tr>
                            <th class="px-4 py-3 text-left text-sm font-semibold text-secondary">{ "IP Address" }</th>
                            <th class="px-4 py-3 text-left text-sm font-semibold text-secondary">{ "Matched Word" }</th>
                            <th class="px-4 py-3 text-left text-sm font-semibold text-secondary">{ "Endpoint" }</th>
                            <th class="px-4 py-3 text-left text-sm font-semibold text-secondary">{ "Timestamp" }</th>
                        </tr>
                    </thead>
                    <tbody>
                        { for records.iter().map(|record| {
                            html! {
                                <tr class="border-t border-default hover:bg-tertiary transition">
                                    <td class="px-4 py-3 font-mono text-sm">{ &record.ip }</td>
                                    <td class="px-4 py-3">
                                        <span class="px-2 py-0.5 bg-yellow-900/50 text-yellow-300 text-xs rounded font-semibold">
                                            { &record.matched_word }
                                        </span>
                                    </td>
                                    <td class="px-4 py-3 text-sm text-secondary font-mono">{ &record.endpoint }</td>
                                    <td class="px-4 py-3 text-sm text-secondary">{ format_timestamp(record.timestamp) }</td>
                                </tr>
                            }
                        })}
                    </tbody>
                </table>

                if records.is_empty() {
                    <div class="p-8 text-center text-secondary">
                        { "No suspicious word matches detected" }
                    </div>
                }
            </div>
        </div>
    }
}

#[derive(Clone, serde::Deserialize)]
struct UpstreamErrorStats {
    total_ips: usize,
    total_errors: u64,
    top_endpoints: Vec<EndpointCount>,
}

#[derive(Clone, serde::Deserialize)]
struct UpstreamErrorRecord {
    ip: String,
    endpoint: String,
    status_code: u16,
    timestamp: u64,
}

#[function_component]
fn UpstreamErrorsTab() -> Html {
    let records = use_state(|| Vec::<UpstreamErrorRecord>::new());
    let stats = use_state(|| None as Option<UpstreamErrorStats>);
    let loading = use_state(|| true);

    {
        let records = records.clone();
        let stats = stats.clone();
        let loading = loading.clone();
        use_effect_with((), move |_| {
            let records = records.clone();
            let stats = stats.clone();
            let loading = loading.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();

                if let Ok(data) = api.get::<serde_json::Value>("/probes/upstream").await {
                    if let Some(records_arr) = data.get("records").and_then(|v| v.as_array()) {
                        let parsed: Vec<UpstreamErrorRecord> = records_arr
                            .iter()
                            .filter_map(|r| serde_json::from_value(r.clone()).ok())
                            .collect();
                        records.set(parsed);
                    }
                }

                if let Ok(data) = api.get::<serde_json::Value>("/probes/upstream/stats").await {
                    if let Ok(s) = serde_json::from_value(data) {
                        stats.set(Some(s));
                    }
                }

                loading.set(false);
            });
            || ()
        });
    }

    let format_timestamp = |ts: u64| {
        chrono::DateTime::from_timestamp(ts as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "Unknown".to_string())
    };

    let status_class = |code: u16| {
        if code >= 500 {
            "px-2 py-0.5 bg-red-900/50 text-red-300 text-xs rounded"
        } else if code >= 400 {
            "px-2 py-0.5 bg-orange-900/50 text-orange-300 text-xs rounded"
        } else {
            "px-2 py-0.5 bg-gray-700 text-gray-300 text-xs rounded"
        }
    };

    if *loading {
        return html! {
            <div class="flex justify-center py-12">
                <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
            </div>
        };
    }

    let stats = (*stats).clone();

    html! {
        <div>
            <div class="bg-blue-900/20 border border-blue-600 rounded-lg p-4 mb-6">
                <p class="text-blue-400 text-sm">
                    { "Upstream errors from healthy backends may indicate vulnerability probing. Multiple unique endpoints returning errors from the same IP suggests an attacker is mapping your application." }
                </p>
            </div>

            if let Some(s) = stats {
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                    <div class="bg-secondary rounded-lg p-4 border border-default">
                        <p class="text-sm text-secondary">{ "Unique IPs" }</p>
                        <p class="text-2xl font-bold mt-1">{ s.total_ips }</p>
                    </div>
                    <div class="bg-secondary rounded-lg p-4 border border-default">
                        <p class="text-sm text-secondary">{ "Total Errors" }</p>
                        <p class="text-2xl font-bold mt-1">{ s.total_errors }</p>
                    </div>
                    <div class="bg-secondary rounded-lg p-4 border border-default">
                        <p class="text-sm text-secondary">{ "Error Prone Endpoints" }</p>
                        <div class="mt-2 space-y-1">
                            { for s.top_endpoints.iter().take(3).map(|e| {
                                html! {
                                    <div class="flex justify-between text-sm">
                                        <span class="truncate max-w-[120px] text-secondary" title={e.endpoint.clone()}>
                                            { &e.endpoint }
                                        </span>
                                        <span class="text-primary">{ e.count }</span>
                                    </div>
                                }
                            })}
                        </div>
                    </div>
                </div>
            }

            <div class="bg-secondary rounded-lg border border-default overflow-hidden">
                <table class="w-full">
                    <thead class="bg-tertiary">
                        <tr>
                            <th class="px-4 py-3 text-left text-sm font-semibold text-secondary">{ "IP Address" }</th>
                            <th class="px-4 py-3 text-left text-sm font-semibold text-secondary">{ "Status" }</th>
                            <th class="px-4 py-3 text-left text-sm font-semibold text-secondary">{ "Endpoint" }</th>
                            <th class="px-4 py-3 text-left text-sm font-semibold text-secondary">{ "Timestamp" }</th>
                        </tr>
                    </thead>
                    <tbody>
                        { for records.iter().map(|record| {
                            html! {
                                <tr class="border-t border-default hover:bg-tertiary transition">
                                    <td class="px-4 py-3 font-mono text-sm">{ &record.ip }</td>
                                    <td class="px-4 py-3">
                                        <span class={status_class(record.status_code)}>
                                            { record.status_code }
                                        </span>
                                    </td>
                                    <td class="px-4 py-3 text-sm text-secondary font-mono">{ &record.endpoint }</td>
                                    <td class="px-4 py-3 text-sm text-secondary">{ format_timestamp(record.timestamp) }</td>
                                </tr>
                            }
                        })}
                    </tbody>
                </table>

                if records.is_empty() {
                    <div class="p-8 text-center text-secondary">
                        { "No upstream error patterns detected" }
                    </div>
                }
            </div>
        </div>
    }
}
