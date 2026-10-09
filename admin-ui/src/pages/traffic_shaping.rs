use crate::components::forms::Input;
use crate::components::skeleton::LoadingSpinner;
use crate::components::{toast_error, toast_success};
use crate::services::ApiService;
use yew::prelude::*;

fn bytes_to_human(bytes: usize) -> String {
    if bytes >= 1_073_741_824 {
        format!("{}GB", bytes / 1_073_741_824)
    } else if bytes >= 1_048_576 {
        format!("{}MB", bytes / 1_048_576)
    } else if bytes >= 1024 {
        format!("{}KB", bytes / 1024)
    } else {
        format!("{}B", bytes)
    }
}

/// Rejects a non-numeric timeout/limit instead of substituting a default that
/// the operator never typed.
fn parse_num(raw: &str, label: &str) -> Result<u64, String> {
    raw.trim()
        .parse::<u64>()
        .map_err(|_| format!("{} must be a whole number of seconds", label))
}

/// Parse a human size (`10`, `512KB`, `10MB`, `1GB`) into bytes.
///
/// Returns `None` rather than collapsing unparseable input to `0`, which is
/// what the previous `unwrap_or(0)` did — a typo in a buffer size silently
/// persisted a zero-sized buffer.
fn human_to_bytes(s: &str) -> Option<usize> {
    let s = s.trim().to_uppercase();
    if s.is_empty() {
        return None;
    }
    let (digits, multiplier) = if let Some(v) = s.strip_suffix("GB") {
        (v, 1_073_741_824usize)
    } else if let Some(v) = s.strip_suffix("MB") {
        (v, 1_048_576)
    } else if let Some(v) = s.strip_suffix("KB") {
        (v, 1024)
    } else if let Some(v) = s.strip_suffix("B") {
        (v, 1)
    } else {
        (s.as_str(), 1)
    };
    digits
        .trim()
        .parse::<usize>()
        .ok()
        // `checked_mul` so a value like 99999999GB overflows to `None`
        // instead of wrapping to a small, plausible-looking size.
        .and_then(|n| n.checked_mul(multiplier))
}

#[function_component]
pub fn TrafficShaping() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let global_enabled = use_state(|| false);
    let global_max_connections = use_state(|| "10000".to_string());
    let _global_max_connection_age = use_state(|| "3600".to_string());
    let global_connection_timeout = use_state(|| "30".to_string());
    let global_idle_timeout = use_state(|| "120".to_string());
    let global_read_timeout = use_state(|| "30".to_string());
    let global_write_timeout = use_state(|| "30".to_string());
    let global_write_buf_size = use_state(|| "256KB".to_string());
    let global_read_buf_size = use_state(|| "256KB".to_string());
    let global_max_request_size = use_state(|| "10MB".to_string());

    let original_global_enabled = use_state(|| false);
    let original_global_max_connections = use_state(|| "10000".to_string());
    let original_global_connection_timeout = use_state(|| "30".to_string());
    let original_global_idle_timeout = use_state(|| "120".to_string());
    let original_global_read_timeout = use_state(|| "30".to_string());
    let original_global_write_timeout = use_state(|| "30".to_string());
    let original_global_write_buf_size = use_state(|| "256KB".to_string());
    let original_global_read_buf_size = use_state(|| "256KB".to_string());
    let original_global_max_request_size = use_state(|| "10MB".to_string());

    let is_dirty = *global_enabled != *original_global_enabled
        || *global_max_connections != *original_global_max_connections
        || *global_connection_timeout != *original_global_connection_timeout
        || *global_idle_timeout != *original_global_idle_timeout
        || *global_read_timeout != *original_global_read_timeout
        || *global_write_timeout != *original_global_write_timeout
        || *global_write_buf_size != *original_global_write_buf_size
        || *global_read_buf_size != *original_global_read_buf_size
        || *global_max_request_size != *original_global_max_request_size;

    use_effect_with((), {
        let loading = loading.clone();
        let global_enabled = global_enabled.clone();
        let global_max_connections = global_max_connections.clone();
        let global_connection_timeout = global_connection_timeout.clone();
        let global_idle_timeout = global_idle_timeout.clone();
        let global_read_timeout = global_read_timeout.clone();
        let global_write_timeout = global_write_timeout.clone();
        let global_write_buf_size = global_write_buf_size.clone();
        let global_read_buf_size = global_read_buf_size.clone();
        let global_max_request_size = global_max_request_size.clone();
        let original_global_enabled = original_global_enabled.clone();
        let original_global_max_connections = original_global_max_connections.clone();
        let original_global_connection_timeout = original_global_connection_timeout.clone();
        let original_global_idle_timeout = original_global_idle_timeout.clone();
        let original_global_read_timeout = original_global_read_timeout.clone();
        let original_global_write_timeout = original_global_write_timeout.clone();
        let original_global_write_buf_size = original_global_write_buf_size.clone();
        let original_global_read_buf_size = original_global_read_buf_size.clone();
        let original_global_max_request_size = original_global_max_request_size.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_traffic_shaping_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(v) = config.get("enabled").and_then(|v| v.as_bool()) {
                            global_enabled.set(v);
                            original_global_enabled.set(v);
                        }
                        if let Some(v) = config.get("max_connections").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            global_max_connections.set(s.clone());
                            original_global_max_connections.set(s);
                        }
                        if let Some(v) = config
                            .get("connection_timeout_secs")
                            .and_then(|v| v.as_u64())
                        {
                            let s = v.to_string();
                            global_connection_timeout.set(s.clone());
                            original_global_connection_timeout.set(s);
                        }
                        if let Some(v) = config.get("idle_timeout_secs").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            global_idle_timeout.set(s.clone());
                            original_global_idle_timeout.set(s);
                        }
                        if let Some(v) = config.get("read_timeout_secs").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            global_read_timeout.set(s.clone());
                            original_global_read_timeout.set(s);
                        }
                        if let Some(v) = config.get("write_timeout_secs").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            global_write_timeout.set(s.clone());
                            original_global_write_timeout.set(s);
                        }
                        if let Some(v) = config.get("write_buf_size").and_then(|v| v.as_u64()) {
                            let s = bytes_to_human(v as usize);
                            global_write_buf_size.set(s.clone());
                            original_global_write_buf_size.set(s);
                        }
                        if let Some(v) = config.get("read_buf_size").and_then(|v| v.as_u64()) {
                            let s = bytes_to_human(v as usize);
                            global_read_buf_size.set(s.clone());
                            original_global_read_buf_size.set(s);
                        }
                        if let Some(v) = config.get("max_request_size").and_then(|v| v.as_u64()) {
                            let s = bytes_to_human(v as usize);
                            global_max_request_size.set(s.clone());
                            original_global_max_request_size.set(s);
                        }
                    }
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    let on_save = {
        let saving = saving.clone();
        let enabled = *global_enabled;
        let max_conn = (*global_max_connections).clone();
        let conn_timeout = (*global_connection_timeout).clone();
        let idle_timeout = (*global_idle_timeout).clone();
        let read_timeout = (*global_read_timeout).clone();
        let write_timeout = (*global_write_timeout).clone();
        let write_buf = (*global_write_buf_size).clone();
        let read_buf = (*global_read_buf_size).clone();
        let max_req = (*global_max_request_size).clone();
        let original_global_enabled = original_global_enabled.clone();
        let original_global_max_connections = original_global_max_connections.clone();
        let original_global_connection_timeout = original_global_connection_timeout.clone();
        let original_global_idle_timeout = original_global_idle_timeout.clone();
        let original_global_read_timeout = original_global_read_timeout.clone();
        let original_global_write_timeout = original_global_write_timeout.clone();
        let original_global_write_buf_size = original_global_write_buf_size.clone();
        let original_global_read_buf_size = original_global_read_buf_size.clone();
        let original_global_max_request_size = original_global_max_request_size.clone();
        Callback::from(move |_: MouseEvent| {
            // Validate before anything is sent: the previous
            // `parse().unwrap_or(default)` chain persisted 10000/30/120/… for
            // any unparseable input, so a typo looked like a successful save.
            let max_conn_value = match parse_num(&max_conn, "Max connections") {
                Ok(v) => v,
                Err(msg) => {
                    toast_error(&msg);
                    return;
                }
            };
            let conn_timeout_value = match parse_num(&conn_timeout, "Connection timeout") {
                Ok(v) => v,
                Err(msg) => {
                    toast_error(&msg);
                    return;
                }
            };
            let idle_timeout_value = match parse_num(&idle_timeout, "Idle timeout") {
                Ok(v) => v,
                Err(msg) => {
                    toast_error(&msg);
                    return;
                }
            };
            let read_timeout_value = match parse_num(&read_timeout, "Read timeout") {
                Ok(v) => v,
                Err(msg) => {
                    toast_error(&msg);
                    return;
                }
            };
            let write_timeout_value = match parse_num(&write_timeout, "Write timeout") {
                Ok(v) => v,
                Err(msg) => {
                    toast_error(&msg);
                    return;
                }
            };
            let write_buf_value = match human_to_bytes(&write_buf) {
                Some(v) => v,
                None => {
                    toast_error("Write buffer size must be a size like 64KB or 1MB");
                    return;
                }
            };
            let read_buf_value = match human_to_bytes(&read_buf) {
                Some(v) => v,
                None => {
                    toast_error("Read buffer size must be a size like 64KB or 1MB");
                    return;
                }
            };
            let max_req_value = match human_to_bytes(&max_req) {
                Some(v) => v,
                None => {
                    toast_error("Max request size must be a size like 10MB or 1GB");
                    return;
                }
            };
            let config = serde_json::json!({
                "config": {
                    "enabled": enabled,
                    "max_connections": max_conn_value,
                    "connection_timeout_secs": conn_timeout_value,
                    "idle_timeout_secs": idle_timeout_value,
                    "read_timeout_secs": read_timeout_value,
                    "write_timeout_secs": write_timeout_value,
                    "write_buf_size": write_buf_value,
                    "read_buf_size": read_buf_value,
                    "max_request_size": max_req_value,
                }
            });
            let saving = saving.clone();
            saving.set(true);
            let og_enabled = enabled;
            let og_max_conn = max_conn.clone();
            let og_conn_timeout = conn_timeout.clone();
            let og_idle_timeout = idle_timeout.clone();
            let og_read_timeout = read_timeout.clone();
            let og_write_timeout = write_timeout.clone();
            let og_write_buf = write_buf.clone();
            let og_read_buf = read_buf.clone();
            let og_max_req = max_req.clone();
            let original_global_enabled = original_global_enabled.clone();
            let original_global_max_connections = original_global_max_connections.clone();
            let original_global_connection_timeout = original_global_connection_timeout.clone();
            let original_global_idle_timeout = original_global_idle_timeout.clone();
            let original_global_read_timeout = original_global_read_timeout.clone();
            let original_global_write_timeout = original_global_write_timeout.clone();
            let original_global_write_buf_size = original_global_write_buf_size.clone();
            let original_global_read_buf_size = original_global_read_buf_size.clone();
            let original_global_max_request_size = original_global_max_request_size.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.update_traffic_shaping_config(&config).await {
                    Ok(_) => {
                        original_global_enabled.set(og_enabled);
                        original_global_max_connections.set(og_max_conn);
                        original_global_connection_timeout.set(og_conn_timeout);
                        original_global_idle_timeout.set(og_idle_timeout);
                        original_global_read_timeout.set(og_read_timeout);
                        original_global_write_timeout.set(og_write_timeout);
                        original_global_write_buf_size.set(og_write_buf);
                        original_global_read_buf_size.set(og_read_buf);
                        original_global_max_request_size.set(og_max_req);
                        toast_success("Traffic shaping configuration saved");
                    }
                    Err(e) => {
                        toast_error(&format!("Failed to save: {}", e));
                    }
                }
                saving.set(false);
            });
        })
    };

    html! {
        <div>
            <div class="flex justify-between items-center mb-6">
                <h1 class="text-2xl font-bold">{ "Traffic Shaping" }</h1>
            </div>

            <div class="bg-secondary rounded-lg border border-default p-6">
                <div class="mb-6">
                    <h2 class="text-lg font-semibold mb-4">{ "Global Connection Limits" }</h2>

                    <div class="flex items-center justify-between py-2 mb-4">
                        <div>
                            <p class="text-primary font-medium">{ "Enable Global Limits" }</p>
                            <p class="text-sm text-secondary">{ "Apply connection limits across all sites" }</p>
                        </div>
                        <button
                            onclick={{
                                let global_enabled = global_enabled.clone();
                                Callback::from(move |_: MouseEvent| {
                                    global_enabled.set(!*global_enabled);
                                })
                            }}
                            role="switch"
                            aria-checked={if *global_enabled { "true" } else { "false" }}
                            aria-label="Enable Global Limits"
                            class={format!("relative w-10 h-6 rounded-full expand-hit {}", if *global_enabled { "bg-blue-600" } else { "bg-gray-600" })}
                        >
                            <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *global_enabled { "translate-x-5" } else { "translate-x-0" })} />
                        </button>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <Input
                            label="Max Connections"
                            name="max_connections"
                            input_type="number"
                            value={(*global_max_connections).clone()}
                            on_change={{
                                let global_max_connections = global_max_connections.clone();
                                Callback::from(move |value: String| {
                                    global_max_connections.set(value);
                                })
                            }}
                            help="Maximum concurrent connections allowed"
                        />
                        <Input
                            label="Connection Timeout (secs)"
                            name="connection_timeout"
                            input_type="number"
                            value={(*global_connection_timeout).clone()}
                            on_change={{
                                let global_connection_timeout = global_connection_timeout.clone();
                                Callback::from(move |value: String| {
                                    global_connection_timeout.set(value);
                                })
                            }}
                        />
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                        <Input
                            label="Idle Timeout (secs)"
                            name="idle_timeout"
                            input_type="number"
                            value={(*global_idle_timeout).clone()}
                            on_change={{
                                let global_idle_timeout = global_idle_timeout.clone();
                                Callback::from(move |value: String| {
                                    global_idle_timeout.set(value);
                                })
                            }}
                            help="Close connections idle for this duration"
                        />
                        <Input
                            label="Read Timeout (secs)"
                            name="read_timeout"
                            input_type="number"
                            value={(*global_read_timeout).clone()}
                            on_change={{
                                let global_read_timeout = global_read_timeout.clone();
                                Callback::from(move |value: String| {
                                    global_read_timeout.set(value);
                                })
                            }}
                        />
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                        <Input
                            label="Write Timeout (secs)"
                            name="write_timeout"
                            input_type="number"
                            value={(*global_write_timeout).clone()}
                            on_change={{
                                let global_write_timeout = global_write_timeout.clone();
                                Callback::from(move |value: String| {
                                    global_write_timeout.set(value);
                                })
                            }}
                        />
                        <Input
                            label="Max Request Size"
                            name="max_request_size"
                            value={(*global_max_request_size).clone()}
                            on_change={{
                                let global_max_request_size = global_max_request_size.clone();
                                Callback::from(move |value: String| {
                                    global_max_request_size.set(value);
                                })
                            }}
                            help="Maximum request body size"
                        />
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                        <Input
                            label="Write Buffer Size"
                            name="write_buf_size"
                            value={(*global_write_buf_size).clone()}
                            on_change={{
                                let global_write_buf_size = global_write_buf_size.clone();
                                Callback::from(move |value: String| {
                                    global_write_buf_size.set(value);
                                })
                            }}
                            help="Buffer size for write operations"
                        />
                        <Input
                            label="Read Buffer Size"
                            name="read_buf_size"
                            value={(*global_read_buf_size).clone()}
                            on_change={{
                                let global_read_buf_size = global_read_buf_size.clone();
                                Callback::from(move |value: String| {
                                    global_read_buf_size.set(value);
                                })
                            }}
                            help="Buffer size for read operations"
                        />
                    </div>
                </div>

                <div class="flex justify-end">
                    <button
                        onclick={on_save}
                        disabled={*saving}
                        class={if is_dirty {
                            "px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50"
                        } else {
                            "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                        }}
                    >
                        { if *saving { "Saving..." } else if is_dirty { "Save*" } else { "Save" } }
                    </button>
                </div>
            </div>
        </div>
    }
}
