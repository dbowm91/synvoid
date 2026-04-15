use crate::components::skeleton::LoadingSpinner;
use crate::services::ApiService;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsCast;
use web_sys::{MessageEvent, WebSocket};
use yew::prelude::*;

const MAX_LOG_ENTRIES: usize = 500;

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub site_id: Option<String>,
    pub message: String,
    pub client_ip: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LogsResponse {
    pub entries: Vec<LogEntry>,
    pub total: usize,
    pub has_more: bool,
}

fn get_level_class(level: &str) -> &'static str {
    match level.to_lowercase().as_str() {
        "trace" => "text-gray-500 bg-gray-500/20",
        "debug" => "text-blue-400 bg-blue-500/20",
        "info" => "text-blue-500 bg-blue-500/20",
        "warn" | "warning" => "text-yellow-500 bg-yellow-500/20",
        "error" => "text-red-500 bg-red-500/20",
        _ => "text-secondary bg-tertiary",
    }
}

fn format_timestamp(ts: &str) -> String {
    ts.split('T')
        .nth(1)
        .unwrap_or(ts)
        .split('.')
        .next()
        .unwrap_or(ts)
        .to_string()
}

#[function_component]
pub fn Logs() -> Html {
    let entries = use_state(Vec::<LogEntry>::new);
    let loading = use_state(|| true);
    let error = use_state(|| None as Option<String>);
    let level_filter = use_state(|| "all".to_string());
    let auto_scroll = use_state(|| true);
    let ws_connected = use_state(|| false);
    let ws_ref = use_mut_ref(|| None::<WebSocket>);

    // Fetch initial logs from REST
    {
        let entries = entries.clone();
        let loading = loading.clone();
        let error = error.clone();
        let level_filter = level_filter.clone();

        use_effect_with(level_filter.clone(), move |filter| {
            let entries = entries.clone();
            let loading = loading.clone();
            let error = error.clone();
            let filter = (**filter).clone();

            wasm_bindgen_futures::spawn_local(async move {
                loading.set(true);
                let api = ApiService::new();

                let path = if filter == "all" {
                    "/logs?limit=200".to_string()
                } else {
                    format!("/logs?level={}&limit=200", filter)
                };

                match api.get::<LogsResponse>(&path).await {
                    Ok(resp) => {
                        entries.set(resp.entries);
                        error.set(None);
                    }
                    Err(e) => error.set(Some(e)),
                }
                loading.set(false);
            });

            || {}
        });
    }

    // WebSocket for real-time streaming
    {
        let entries = entries.clone();
        let ws_connected = ws_connected.clone();
        let ws_ref = ws_ref.clone();

        use_effect_with((), move |_| {
            let window = web_sys::window().unwrap();
            let location = window.location();
            let protocol = if location.protocol().unwrap_or_default() == "https:" {
                "wss:"
            } else {
                "ws:"
            };
            let host = location.host().unwrap_or_default();
            let ws_url = format!("{}//{}/api/ws/logs", protocol, host);

            let ws = match WebSocket::new(&ws_url) {
                Ok(ws) => ws,
                Err(_) => {
                    return Box::new(|| {}) as Box<dyn FnOnce()>;
                }
            };

            {
                let ws_connected = ws_connected.clone();
                let closure =
                    wasm_bindgen::closure::Closure::<dyn FnMut(_)>::new(move |_: MessageEvent| {
                        ws_connected.set(true);
                    });
                ws.set_onopen(Some(closure.as_ref().unchecked_ref()));
                closure.forget();
            }

            {
                let entries = entries.clone();
                let closure =
                    wasm_bindgen::closure::Closure::<dyn FnMut(_)>::new(move |e: MessageEvent| {
                        if let Ok(txt) = e.data().dyn_into::<js_sys::JsString>() {
                            let msg = String::from(txt);
                            if let Ok(entry) = serde_json::from_str::<LogEntry>(&msg) {
                                let mut new_entries = (*entries).clone();
                                new_entries.push(entry);
                                if new_entries.len() > MAX_LOG_ENTRIES {
                                    let drain_count = new_entries.len() - MAX_LOG_ENTRIES;
                                    new_entries.drain(0..drain_count);
                                }
                                entries.set(new_entries);
                            }
                        }
                    });
                ws.set_onmessage(Some(closure.as_ref().unchecked_ref()));
                closure.forget();
            }

            {
                let ws_connected = ws_connected.clone();
                let closure = wasm_bindgen::closure::Closure::<dyn FnMut(_)>::new(
                    move |_: web_sys::Event| {
                        ws_connected.set(false);
                    },
                );
                ws.set_onclose(Some(closure.as_ref().unchecked_ref()));
                closure.forget();
            }

            {
                let ws_connected = ws_connected.clone();
                let closure = wasm_bindgen::closure::Closure::<dyn FnMut(_)>::new(
                    move |_: web_sys::ErrorEvent| {
                        ws_connected.set(false);
                    },
                );
                ws.set_onerror(Some(closure.as_ref().unchecked_ref()));
                closure.forget();
            }

            *ws_ref.borrow_mut() = Some(ws.clone());

            let ws_close = ws.clone();
            Box::new(move || {
                let _ = ws_close.close();
            }) as Box<dyn FnOnce()>
        });
    }

    // Auto-scroll to bottom when new entries arrive
    {
        let entries = entries.clone();
        let auto_scroll = auto_scroll.clone();

        use_effect_with((entries.len(), auto_scroll.clone()), move |(_, scroll)| {
            if **scroll {
                let window = web_sys::window().unwrap();
                let document = window.document().unwrap();
                if let Some(el) = document.get_element_by_id("logs-scroll-container") {
                    el.set_scroll_top(el.scroll_height());
                }
            }
            || {}
        });
    }

    let on_level_change = {
        let level_filter = level_filter.clone();
        Callback::from(move |e: Event| {
            let value = e
                .target_unchecked_into::<web_sys::HtmlSelectElement>()
                .value();
            level_filter.set(value);
        })
    };

    let toggle_auto_scroll = {
        let auto_scroll = auto_scroll.clone();
        Callback::from(move |_| {
            auto_scroll.set(!*auto_scroll);
        })
    };

    let on_clear = {
        let entries = entries.clone();
        Callback::from(move |_| {
            entries.set(Vec::new());
        })
    };

    let filtered_entries: Vec<LogEntry> = if *level_filter == "all" {
        (*entries).clone()
    } else {
        entries
            .iter()
            .filter(|e| e.level.to_lowercase() == *level_filter)
            .cloned()
            .collect()
    };

    let connection_status = if *ws_connected {
        html! {
            <div class="flex items-center gap-2 px-3 py-1 rounded-full text-sm bg-green-500/20 text-green-400">
                <span class="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                { "Live" }
            </div>
        }
    } else {
        html! {
            <div class="flex items-center gap-2 px-3 py-1 rounded-full text-sm bg-gray-500/20 text-gray-400">
                <span class="w-2 h-2 rounded-full bg-gray-500" />
                { "Offline" }
            </div>
        }
    };

    html! {
        <div>
            <div class="flex items-center justify-between mb-6">
                <h1 class="text-2xl font-bold">{ "WAF Logs" }</h1>
                <div class="flex items-center gap-3">
                    { connection_status }
                </div>
            </div>

            if let Some(err) = &*error {
                <div class="bg-red-500/10 border border-red-500 rounded-lg p-4 mb-6 text-red-500">
                    { err }
                </div>
            }

            <div class="bg-secondary rounded-lg p-4 border border-default mb-6">
                <div class="flex flex-wrap items-center gap-4">
                    <select
                        class="px-3 py-2 bg-tertiary border border-default rounded-lg text-primary text-sm min-w-[150px]"
                        onchange={on_level_change}
                    >
                        <option value="all" selected={*level_filter == "all"}>{ "All Levels" }</option>
                        <option value="trace" selected={*level_filter == "trace"}>{ "Trace" }</option>
                        <option value="debug" selected={*level_filter == "debug"}>{ "Debug" }</option>
                        <option value="info" selected={*level_filter == "info"}>{ "Info" }</option>
                        <option value="warn" selected={*level_filter == "warn"}>{ "Warning" }</option>
                        <option value="error" selected={*level_filter == "error"}>{ "Error" }</option>
                    </select>

                    <button
                        onclick={toggle_auto_scroll}
                        class={format!("px-3 py-2 rounded-lg text-sm font-medium {}",
                            if *auto_scroll { "bg-blue-600 text-white" } else { "bg-tertiary text-secondary hover:text-primary" }
                        )}
                    >
                        { if *auto_scroll { "Auto-scroll On" } else { "Auto-scroll Off" } }
                    </button>

                    <button
                        onclick={on_clear}
                        class="px-3 py-2 bg-tertiary text-secondary rounded-lg text-sm hover:text-primary"
                    >
                        { "Clear" }
                    </button>

                    <div class="ml-auto text-sm text-secondary">
                        { format!("{} entries", filtered_entries.len()) }
                    </div>
                </div>
            </div>

            <div class="bg-secondary rounded-lg border border-default overflow-hidden">
                if *loading && entries.is_empty() {
                    <div class="p-4">
                        <LoadingSpinner />
                    </div>
                } else if filtered_entries.is_empty() {
                    <div class="p-8 text-center text-secondary">
                        { "No log entries" }
                    </div>
                } else {
                    <div
                        id="logs-scroll-container"
                        class="p-4 font-mono text-sm max-h-[600px] overflow-y-auto"
                    >
                        { for filtered_entries.iter().map(|entry| {
                            let level_class = get_level_class(&entry.level);
                            let time = format_timestamp(&entry.timestamp);
                            html! {
                                <div class="py-2 border-b border-default last:border-b-0">
                                    <div class="flex items-start gap-4">
                                        <span class="text-secondary text-xs whitespace-nowrap select-none">{ time }</span>
                                        <span class={format!("px-2 py-0.5 rounded text-xs uppercase font-medium {}", level_class)}>
                                            { &entry.level }
                                        </span>
                                        if let Some(site) = &entry.site_id {
                                            <span class="text-purple-400 text-xs">{ site }</span>
                                        }
                                        if let Some(ip) = &entry.client_ip {
                                            <span class="text-green-400 text-xs font-mono">{ ip }</span>
                                        }
                                        if let Some(path) = &entry.path {
                                            <span class="text-cyan-400 text-xs font-mono max-w-[200px] truncate" title={path.clone()}>{ path }</span>
                                        }
                                        if let Some(status) = &entry.status {
                                            <span class={format!("text-xs font-medium {}",
                                                if *status >= 400 { "text-red-400" }
                                                else if *status >= 300 { "text-yellow-400" }
                                                else { "text-green-400" }
                                            )}>{ status.to_string() }</span>
                                        }
                                    </div>
                                    <div class="mt-1 text-primary">{ &entry.message }</div>
                                </div>
                            }
                        })}
                    </div>
                }
            </div>
        </div>
    }
}
