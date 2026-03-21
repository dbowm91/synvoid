use crate::services::ApiService;
use crate::types::{RequestLogEntry, SiteInfo};
use serde::{Deserialize, Serialize};
use yew::prelude::*;

#[derive(Serialize, Deserialize, Clone)]
pub struct RequestLogsResponse {
    pub entries: Vec<RequestLogEntry>,
    pub total: usize,
    pub has_more: bool,
}

fn format_bytes(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1} MB", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1} KB", n as f64 / 1_000.0)
    } else {
        format!("{} B", n)
    }
}

fn get_status_class(status: u16) -> &'static str {
    match status {
        200..=299 => "text-green-500",
        300..=399 => "text-yellow-500",
        400..=499 => "text-orange-500",
        500..=599 => "text-red-500",
        _ => "text-secondary",
    }
}

fn get_method_class(method: &str) -> &'static str {
    match method {
        "GET" => "bg-blue-500/20 text-blue-400",
        "POST" => "bg-green-500/20 text-green-400",
        "PUT" => "bg-yellow-500/20 text-yellow-400",
        "DELETE" => "bg-red-500/20 text-red-400",
        "PATCH" => "bg-purple-500/20 text-purple-400",
        _ => "bg-tertiary text-secondary",
    }
}

#[function_component]
pub fn RequestLogs() -> Html {
    let logs = use_state(|| Vec::<RequestLogEntry>::new());
    let sites = use_state(|| Vec::<SiteInfo>::new());
    let loading = use_state(|| true);
    let total = use_state(|| 0);
    let has_more = use_state(|| false);

    let selected_site = use_state(|| "".to_string());
    let selected_method = use_state(|| "".to_string());
    let selected_status = use_state(|| "".to_string());
    let search_query = use_state(|| "".to_string());
    let offset = use_state(|| 0);

    let limit = 50;

    {
        let sites = sites.clone();
        use_effect_with((), move |_| {
            let sites = sites.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.list_sites().await {
                    Ok(s) => sites.set(s),
                    Err(_) => {}
                }
            });
            || {}
        });
    }

    {
        let logs = logs.clone();
        let loading = loading.clone();
        let total = total.clone();
        let has_more = has_more.clone();
        let selected_site = selected_site.clone();
        let selected_method = selected_method.clone();
        let selected_status = selected_status.clone();
        let search_query = search_query.clone();
        let offset = offset.clone();

        use_effect_with(
            (
                selected_site.clone(),
                selected_method.clone(),
                selected_status.clone(),
                search_query.clone(),
                (*offset),
            ),
            move |_| {
                let logs = logs.clone();
                let loading = loading.clone();
                let total = total.clone();
                let has_more = has_more.clone();
                let selected_site = selected_site.clone();
                let selected_method = selected_method.clone();
                let selected_status = selected_status.clone();
                let search_query = search_query.clone();
                let offset = offset.clone();

                wasm_bindgen_futures::spawn_local(async move {
                    loading.set(true);
                    let api = ApiService::new();

                    let site_id = if (*selected_site).is_empty() {
                        None
                    } else {
                        Some((*selected_site).as_str())
                    };
                    let method = if (*selected_method).is_empty() {
                        None
                    } else {
                        Some((*selected_method).as_str())
                    };
                    let status = if (*selected_status).is_empty() {
                        None
                    } else {
                        Some((*selected_status).as_str())
                    };
                    let search = if (*search_query).is_empty() {
                        None
                    } else {
                        Some((*search_query).as_str())
                    };
                    let current_offset = *offset;

                    match api
                        .get_request_logs(
                            site_id,
                            method,
                            status,
                            search,
                            Some(limit),
                            Some(current_offset),
                        )
                        .await
                    {
                        Ok(resp) => {
                            logs.set(resp.entries);
                            total.set(resp.total);
                            has_more.set(resp.has_more);
                        }
                        Err(_) => {}
                    }
                    loading.set(false);
                });
                || {}
            },
        );
    }

    let on_site_change = {
        let selected_site = selected_site.clone();
        let offset = offset.clone();
        Callback::from(move |e: Event| {
            let value = e
                .target_unchecked_into::<web_sys::HtmlSelectElement>()
                .value();
            selected_site.set(value);
            offset.set(0);
        })
    };

    let on_method_change = {
        let selected_method = selected_method.clone();
        let offset = offset.clone();
        Callback::from(move |e: Event| {
            let value = e
                .target_unchecked_into::<web_sys::HtmlSelectElement>()
                .value();
            selected_method.set(value);
            offset.set(0);
        })
    };

    let on_status_change = {
        let selected_status = selected_status.clone();
        let offset = offset.clone();
        Callback::from(move |e: Event| {
            let value = e
                .target_unchecked_into::<web_sys::HtmlSelectElement>()
                .value();
            selected_status.set(value);
            offset.set(0);
        })
    };

    let on_search = {
        let search_query = search_query.clone();
        let offset = offset.clone();
        Callback::from(move |e: InputEvent| {
            let value = e
                .target_unchecked_into::<web_sys::HtmlInputElement>()
                .value();
            search_query.set(value);
            offset.set(0);
        })
    };

    let on_prev = {
        let offset = offset.clone();
        Callback::from(move |_| {
            if *offset >= limit {
                offset.set(*offset - limit);
            }
        })
    };

    let on_next = {
        let offset = offset.clone();
        let has_more = has_more.clone();
        Callback::from(move |_| {
            if *has_more {
                offset.set(*offset + limit);
            }
        })
    };

    let current_offset = *offset;
    let showing_end = (current_offset + logs.len()).min(*total);

    html! {
        <div>
            <div class="flex items-center justify-between mb-6">
                <h1 class="text-2xl font-bold">{ "Request Logs" }</h1>
                <div class="flex items-center gap-3">
                    <label class="flex items-center gap-2 text-sm cursor-pointer">
                        <input type="checkbox" class="w-4 h-4 rounded" />
                        <span class="text-secondary">{ "Auto-refresh" }</span>
                    </label>
                </div>
            </div>

            <div class="bg-secondary rounded-lg p-4 border border-default mb-6">
                <div class="flex flex-wrap gap-4">
                    <select
                        class="px-3 py-2 bg-tertiary border border-default rounded-lg text-primary text-sm min-w-[150px]"
                        onchange={on_site_change}
                    >
                        <option value="">{ "All Sites" }</option>
                        { for sites.iter().map(|site| {
                            let domains = site.domains.first().unwrap_or(&site.id).clone();
                            html! {
                                <option value={site.id.clone()}>{domains}</option>
                            }
                        })}
                    </select>

                    <select
                        class="px-3 py-2 bg-tertiary border border-default rounded-lg text-primary text-sm min-w-[150px]"
                        onchange={on_method_change}
                    >
                        <option value="">{ "All Methods" }</option>
                        <option value="GET">{ "GET" }</option>
                        <option value="POST">{ "POST" }</option>
                        <option value="PUT">{ "PUT" }</option>
                        <option value="DELETE">{ "DELETE" }</option>
                        <option value="PATCH">{ "PATCH" }</option>
                    </select>

                    <select
                        class="px-3 py-2 bg-tertiary border border-default rounded-lg text-primary text-sm min-w-[180px]"
                        onchange={on_status_change}
                    >
                        <option value="">{ "All Status" }</option>
                        <option value="2">{ "2xx Success" }</option>
                        <option value="3">{ "3xx Redirect" }</option>
                        <option value="4">{ "4xx Client Error" }</option>
                        <option value="5">{ "5xx Server Error" }</option>
                    </select>

                    <input
                        type="text"
                        placeholder="Search by IP or path..."
                        class="flex-1 px-3 py-2 bg-tertiary border border-default rounded-lg text-primary text-sm min-w-[200px]"
                        oninput={on_search}
                    />
                </div>
            </div>

            <div class="bg-secondary rounded-lg border border-default overflow-hidden">
                <div class="overflow-x-auto">
                    <table class="w-full text-sm">
                        <thead class="bg-tertiary border-b border-default">
                            <tr>
                                <th class="px-4 py-3 text-left text-secondary font-medium">{ "Time" }</th>
                                <th class="px-4 py-3 text-left text-secondary font-medium">{ "Method" }</th>
                                <th class="px-4 py-3 text-left text-secondary font-medium">{ "Path" }</th>
                                <th class="px-4 py-3 text-left text-secondary font-medium">{ "Status" }</th>
                                <th class="px-4 py-3 text-left text-secondary font-medium">{ "Latency" }</th>
                                <th class="px-4 py-3 text-left text-secondary font-medium">{ "Client IP" }</th>
                                <th class="px-4 py-3 text-left text-secondary font-medium">{ "Site" }</th>
                                <th class="px-4 py-3 text-left text-secondary font-medium">{ "Size" }</th>
                            </tr>
                        </thead>
                        <tbody>
                            if *loading {
                                <tr>
                                    <td colspan="8" class="px-4 py-8 text-center text-secondary">
                                        { "Loading..." }
                                    </td>
                                </tr>
                            } else if logs.is_empty() {
                                <tr>
                                    <td colspan="8" class="px-4 py-8 text-center text-secondary">
                                        { "No request logs found" }
                                    </td>
                                </tr>
                            } else {
                                { for logs.iter().map(|log| {
                                    let time = log.timestamp.split('T').nth(1).unwrap_or(&log.timestamp).split('.').next().unwrap_or(&log.timestamp).to_string();
                                    html! {
                                        <tr class="border-b border-default hover:bg-tertiary/50 transition">
                                            <td class="px-4 py-3 text-secondary font-mono text-xs">{time}</td>
                                            <td class="px-4 py-3">
                                                <span class={format!("px-2 py-1 rounded text-xs font-medium {}", get_method_class(&log.method))}>
                                                    {&log.method}
                                                </span>
                                            </td>
                                            <td class="px-4 py-3 text-primary font-mono text-xs max-w-[200px] truncate" title={log.path.clone()}>{&log.path}</td>
                                            <td class={format!("px-4 py-3 font-medium {}", get_status_class(log.status))}>{log.status}</td>
                                            <td class="px-4 py-3 text-secondary">{format!("{}ms", log.response_time_ms)}</td>
                                            <td class="px-4 py-3 text-primary font-mono text-xs">{&log.client_ip}</td>
                                            <td class="px-4 py-3 text-secondary text-xs">{&log.site_id}</td>
                                            <td class="px-4 py-3 text-secondary text-xs">{format_bytes(log.bytes_sent)}</td>
                                        </tr>
                                    }
                                })}
                            }
                        </tbody>
                    </table>
                </div>

                <div class="px-4 py-3 border-t border-default flex items-center justify-between">
                    <span class="text-sm text-secondary">
                        { format!("Showing {}-{} of {} entries", current_offset + 1, showing_end, *total) }
                    </span>
                    <div class="flex gap-2">
                        <button
                            onclick={on_prev}
                            disabled={current_offset == 0}
                            class="px-3 py-1 bg-tertiary rounded text-sm text-secondary hover:text-primary disabled:opacity-50"
                        >
                            { "Previous" }
                        </button>
                        <button
                            onclick={on_next}
                            disabled={!*has_more}
                            class="px-3 py-1 bg-tertiary rounded text-sm text-secondary hover:text-primary disabled:opacity-50"
                        >
                            { "Next" }
                        </button>
                    </div>
                </div>
            </div>
        </div>
    }
}
