use crate::components::forms::{Input, Select};
use crate::components::skeleton::LoadingSpinner;
use crate::components::{toast_error, toast_success};
use crate::services::ApiService;
use crate::types::{ThemeResponse, UpdateThemeRequest};
use wasm_bindgen::JsCast;
use yew::prelude::*;

fn restart_badge() -> Html {
    html! {
        <span class="ml-2 inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">
            { "Requires restart" }
        </span>
    }
}

fn bytes_to_human(bytes: usize) -> String {
    if bytes >= 1_073_741_824 {
        format!("{}GB", bytes / 1_073_741_824)
    } else if bytes >= 1_048_576 {
        format!("{}MB", bytes / 1_048_576)
    } else if bytes >= 1024 {
        format!("{}KB", bytes / 1024)
    } else {
        format!("{}", bytes)
    }
}

fn human_to_bytes(s: &str) -> usize {
    let s = s.trim().to_uppercase();
    if let Some(val) = s.strip_suffix("GB") {
        val.trim().parse::<usize>().unwrap_or(0) * 1_073_741_824
    } else if let Some(val) = s.strip_suffix("MB") {
        val.trim().parse::<usize>().unwrap_or(0) * 1_048_576
    } else if let Some(val) = s.strip_suffix("KB") {
        val.trim().parse::<usize>().unwrap_or(0) * 1024
    } else {
        s.parse::<usize>().unwrap_or(0)
    }
}

fn export_config_to_file(json: &str) {
    let blob = web_sys::Blob::new_with_str_sequence(&js_sys::Array::of1(&json.into())).unwrap();
    let url = web_sys::Url::create_object_url_with_blob(&blob).unwrap();
    let window = web_sys::window().unwrap();
    let document = window.document().unwrap();
    let a = document.create_element("a").unwrap();
    a.set_attribute("href", &url).unwrap();
    a.set_attribute("download", "maluwaf-config.json").unwrap();
    let _ = a.dispatch_event(&web_sys::MouseEvent::new("click").unwrap());
}

#[function_component]
pub fn Settings() -> Html {
    let active_section = use_state(|| "server".to_string());
    let exporting = use_state(|| false);
    let importing = use_state(|| false);

    let on_section_click = {
        let active_section = active_section.clone();
        Callback::from(move |section: String| {
            active_section.set(section);
        })
    };

    let on_export = {
        let exporting = exporting.clone();
        Callback::from(move |_: MouseEvent| {
            let exporting = exporting.clone();
            exporting.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.export_config().await {
                    Ok(data) => {
                        let json = serde_json::to_string_pretty(&data)
                            .unwrap_or_else(|_| "{}".to_string());
                        export_config_to_file(&json);
                        toast_success("Configuration exported");
                    }
                    Err(e) => {
                        toast_error(&format!("Export failed: {}", e));
                    }
                }
                exporting.set(false);
            });
        })
    };

    let on_import = {
        let importing = importing.clone();
        Callback::from(move |_: MouseEvent| {
            let importing = importing.clone();
            let window = web_sys::window().unwrap();
            let document = window.document().unwrap();
            let input: web_sys::HtmlInputElement = document
                .create_element("input")
                .unwrap()
                .dyn_into()
                .unwrap();
            input.set_type("file");
            input.set_accept(".json");

            let importing_clone = importing.clone();
            let input_clone = input.clone();
            let closure = wasm_bindgen::closure::Closure::wrap(Box::new(move |_: web_sys::Event| {
                let input: web_sys::HtmlInputElement = input_clone.clone().dyn_into().unwrap();
                if let Some(files) = input.files() {
                    if let Some(file) = files.get(0) {
                        let importing = importing_clone.clone();
                        importing.set(true);
                        let reader = web_sys::FileReader::new().unwrap();
                        let reader_clone = reader.clone();
                        let read_closure = wasm_bindgen::closure::Closure::wrap(Box::new(
                            move |_: web_sys::Event| {
                                let result = reader_clone.result().unwrap();
                                let text = result.as_string().unwrap();
                                let importing = importing.clone();
                                wasm_bindgen_futures::spawn_local(async move {
                                    let api = ApiService::new();
                                    match serde_json::from_str::<serde_json::Value>(&text) {
                                        Ok(config) => match api.import_config(&config).await {
                                            Ok(_) => {
                                                toast_success("Configuration imported successfully")
                                            }
                                            Err(e) => toast_error(&format!("Import failed: {}", e)),
                                        },
                                        Err(e) => toast_error(&format!("Invalid JSON: {}", e)),
                                    }
                                    importing.set(false);
                                });
                            },
                        )
                            as Box<dyn FnMut(web_sys::Event)>);
                        let _ = reader.add_event_listener_with_callback(
                            "load",
                            read_closure.as_ref().unchecked_ref(),
                        );
                        read_closure.forget();
                        let _ = reader.read_as_text(&file);
                    }
                }
            })
                as Box<dyn FnMut(web_sys::Event)>);
            let _ =
                input.add_event_listener_with_callback("change", closure.as_ref().unchecked_ref());
            closure.forget();
            input.click();
        })
    };

    html! {
        <div>
            <div class="flex justify-between items-center mb-6">
                <h1 class="text-2xl font-bold">{ "Global Settings" }</h1>
                <div class="flex gap-2">
                    <button
                        onclick={on_export}
                        disabled={*exporting}
                        class="px-3 py-2 bg-tertiary text-secondary rounded-lg hover:text-primary text-sm disabled:opacity-50"
                    >
                        { if *exporting { "Exporting..." } else { "Export Config" } }
                    </button>
                    <button
                        onclick={on_import}
                        disabled={*importing}
                        class="px-3 py-2 bg-tertiary text-secondary rounded-lg hover:text-primary text-sm disabled:opacity-50"
                    >
                        { if *importing { "Importing..." } else { "Import Config" } }
                    </button>
                </div>
            </div>

            <div class="flex gap-6">
                <nav class="w-48 flex-shrink-0">
                    <div class="bg-secondary rounded-lg border border-default">
                        <SectionButton label="Server" section="server" active={*active_section == "server"} on_click={on_section_click.clone()} />
                        <SectionButton label="HTTP" section="http" active={*active_section == "http"} on_click={on_section_click.clone()} />
                        <SectionButton label="Logging" section="logging" active={*active_section == "logging"} on_click={on_section_click.clone()} />
                        <SectionButton label="Metrics" section="metrics" active={*active_section == "metrics"} on_click={on_section_click.clone()} />
                        <SectionButton label="Rate Limits" section="ratelimits" active={*active_section == "ratelimits"} on_click={on_section_click.clone()} />
                        <SectionButton label="Bandwidth" section="bandwidth" active={*active_section == "bandwidth"} on_click={on_section_click.clone()} />
                        <SectionButton label="Bot Defaults" section="bot" active={*active_section == "bot"} on_click={on_section_click.clone()} />
                        <SectionButton label="Upload" section="upload" active={*active_section == "upload"} on_click={on_section_click.clone()} />
                        <SectionButton label="Theme" section="theme" active={*active_section == "theme"} on_click={on_section_click.clone()} />
                    </div>
                </nav>

                <div class="flex-1 bg-secondary rounded-lg border border-default">
                    <div class="p-6 border-b border-default">
                        <h2 class="text-lg font-semibold">
                        { match active_section.as_str() {
                            "server" => "Server Configuration",
                            "http" => "HTTP Settings",
                            "logging" => "Logging Configuration",
                            "metrics" => "Metrics Configuration",
                            "ratelimits" => "Rate Limit Defaults",
                            "bandwidth" => "Bandwidth Limits",
                            "bot" => "Bot Protection Defaults",
                            "upload" => "Upload Defaults",
                            "theme" => "Theme Configuration",
                            _ => "Server Configuration",
                        }}
                        </h2>
                    </div>

                    <div class="p-6">
                        { match active_section.as_str() {
                            "server" => html! { <ServerSection /> },
                            "http" => html! { <HttpSection /> },
                            "logging" => html! { <LoggingSection /> },
                            "metrics" => html! { <MetricsSection /> },
                            "ratelimits" => html! { <RateLimitsSection /> },
                            "bandwidth" => html! { <BandwidthSection /> },
                            "bot" => html! { <BotSection /> },
                            "upload" => html! { <UploadSection /> },
                            "theme" => html! { <ThemeSection /> },
                            _ => html! { <ServerSection /> },
                        }}
                    </div>
                </div>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct SectionButtonProps {
    label: String,
    section: String,
    active: bool,
    on_click: Callback<String>,
}

#[function_component]
fn SectionButton(props: &SectionButtonProps) -> Html {
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
fn ServerSection() -> Html {
    let server_config = use_state(|| None::<serde_json::Value>);
    let loading = use_state(|| true);
    let saving = use_state(|| false);
    let host = use_state(|| "0.0.0.0".to_string());
    let port = use_state(|| "8080".to_string());
    let trusted_proxies = use_state(|| "127.0.0.1, ::1".to_string());
    let original_host = use_state(|| "0.0.0.0".to_string());
    let original_port = use_state(|| "8080".to_string());
    let original_proxies = use_state(|| "127.0.0.1, ::1".to_string());

    let is_dirty =
        *host != *original_host || *port != *original_port || *trusted_proxies != *original_proxies;

    use_effect_with((), {
        let server_config = server_config.clone();
        let loading = loading.clone();
        let host = host.clone();
        let port = port.clone();
        let trusted_proxies = trusted_proxies.clone();
        let original_host = original_host.clone();
        let original_port = original_port.clone();
        let original_proxies = original_proxies.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_main_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(server) = config.get("server") {
                            server_config.set(Some(server.clone()));
                            if let Some(h) = server.get("host").and_then(|v| v.as_str()) {
                                host.set(h.to_string());
                                original_host.set(h.to_string());
                            }
                            if let Some(p) = server.get("port").and_then(|v| v.as_u64()) {
                                port.set(p.to_string());
                                original_port.set(p.to_string());
                            }
                            if let Some(tp) =
                                server.get("trusted_proxies").and_then(|v| v.as_array())
                            {
                                let proxies: Vec<String> = tp
                                    .iter()
                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                    .collect();
                                let joined = proxies.join(", ");
                                trusted_proxies.set(joined.clone());
                                original_proxies.set(joined);
                            }
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

    let on_host_change = {
        let host = host.clone();
        Callback::from(move |value: String| {
            host.set(value);
        })
    };

    let on_port_change = {
        let port = port.clone();
        Callback::from(move |value: String| {
            port.set(value);
        })
    };

    let on_proxies_change = {
        let trusted_proxies = trusted_proxies.clone();
        Callback::from(move |value: String| {
            trusted_proxies.set(value);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let host = host.clone();
        let port = port.clone();
        let trusted_proxies = trusted_proxies.clone();
        let server_config = server_config.clone();
        let original_host = original_host.clone();
        let original_port = original_port.clone();
        let original_proxies = original_proxies.clone();
        Callback::from(move |_| {
            let proxies: Vec<String> = trusted_proxies
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let new_config = serde_json::json!({
                "config": {
                    "server": {
                        "host": (*host).clone(),
                        "port": port.parse::<u16>().unwrap_or(8080),
                        "trusted_proxies": proxies
                    }
                }
            });
            let saving = saving.clone();
            let host = host.clone();
            let port = port.clone();
            let trusted_proxies = trusted_proxies.clone();
            let original_host = original_host.clone();
            let original_port = original_port.clone();
            let original_proxies = original_proxies.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.validate_config().await {
                    Ok(_) => {}
                    Err(e) => {
                        saving.set(false);
                        toast_error(&format!("Validation failed: {}", e));
                        return;
                    }
                }
                let _ = api.update_main_config(&new_config).await;
                saving.set(false);
                original_host.set((*host).clone());
                original_port.set((*port).clone());
                original_proxies.set((*trusted_proxies).clone());
                toast_success("Server configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Listen Host"
                    name="host"
                    value={(*host).clone()}
                    on_change={on_host_change}
                    help="IP address to bind the main server to"
                    badge={restart_badge()}
                />
                <Input
                    label="Listen Port"
                    name="port"
                    value={(*port).clone()}
                    on_change={on_port_change}
                    input_type="number"
                    help="TCP port for the main HTTP server"
                    badge={restart_badge()}
                />
            </div>

            <div>
                <Input
                    label="Trusted Proxies"
                    name="trusted_proxies"
                    value={(*trusted_proxies).clone()}
                    on_change={on_proxies_change}
                    help="Comma-separated list of trusted proxy IPs for X-Forwarded-For handling"
                />
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
    }
}

#[function_component]
fn HttpSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let header_read_timeout = use_state(|| "10".to_string());
    let keep_alive_timeout = use_state(|| "60".to_string());
    let max_headers = use_state(|| "128".to_string());
    let max_request_size = use_state(|| "1MB".to_string());
    let max_header_size_ingress = use_state(|| "4KB".to_string());
    let max_header_size_egress = use_state(|| "16KB".to_string());

    let original_header_read_timeout = use_state(|| "10".to_string());
    let original_keep_alive_timeout = use_state(|| "60".to_string());
    let original_max_headers = use_state(|| "128".to_string());
    let original_max_request_size = use_state(|| "1MB".to_string());
    let original_max_header_size_ingress = use_state(|| "4KB".to_string());
    let original_max_header_size_egress = use_state(|| "16KB".to_string());

    let is_dirty = *header_read_timeout != *original_header_read_timeout
        || *keep_alive_timeout != *original_keep_alive_timeout
        || *max_headers != *original_max_headers
        || *max_request_size != *original_max_request_size
        || *max_header_size_ingress != *original_max_header_size_ingress
        || *max_header_size_egress != *original_max_header_size_egress;

    use_effect_with((), {
        let loading = loading.clone();
        let header_read_timeout = header_read_timeout.clone();
        let keep_alive_timeout = keep_alive_timeout.clone();
        let max_headers = max_headers.clone();
        let max_request_size = max_request_size.clone();
        let max_header_size_ingress = max_header_size_ingress.clone();
        let max_header_size_egress = max_header_size_egress.clone();
        let original_header_read_timeout = original_header_read_timeout.clone();
        let original_keep_alive_timeout = original_keep_alive_timeout.clone();
        let original_max_headers = original_max_headers.clone();
        let original_max_request_size = original_max_request_size.clone();
        let original_max_header_size_ingress = original_max_header_size_ingress.clone();
        let original_max_header_size_egress = original_max_header_size_egress.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_http_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(v) = config
                            .get("header_read_timeout_secs")
                            .and_then(|v| v.as_u64())
                        {
                            let s = v.to_string();
                            header_read_timeout.set(s.clone());
                            original_header_read_timeout.set(s);
                        }
                        if let Some(v) = config
                            .get("keep_alive_timeout_secs")
                            .and_then(|v| v.as_u64())
                        {
                            let s = v.to_string();
                            keep_alive_timeout.set(s.clone());
                            original_keep_alive_timeout.set(s);
                        }
                        if let Some(v) = config.get("max_headers").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            max_headers.set(s.clone());
                            original_max_headers.set(s);
                        }
                        if let Some(v) = config.get("max_request_size").and_then(|v| v.as_u64()) {
                            let s = bytes_to_human(v as usize);
                            max_request_size.set(s.clone());
                            original_max_request_size.set(s);
                        }
                        if let Some(v) = config
                            .get("max_header_size_ingress")
                            .and_then(|v| v.as_u64())
                        {
                            let s = bytes_to_human(v as usize);
                            max_header_size_ingress.set(s.clone());
                            original_max_header_size_ingress.set(s);
                        }
                        if let Some(v) = config
                            .get("max_header_size_egress")
                            .and_then(|v| v.as_u64())
                        {
                            let s = bytes_to_human(v as usize);
                            max_header_size_egress.set(s.clone());
                            original_max_header_size_egress.set(s);
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

    let on_change = |state: UseStateHandle<String>| -> Callback<String> {
        Callback::from(move |value: String| {
            state.set(value);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let header_read_timeout = header_read_timeout.clone();
        let keep_alive_timeout = keep_alive_timeout.clone();
        let max_headers = max_headers.clone();
        let max_request_size = max_request_size.clone();
        let max_header_size_ingress = max_header_size_ingress.clone();
        let max_header_size_egress = max_header_size_egress.clone();
        let original_header_read_timeout = original_header_read_timeout.clone();
        let original_keep_alive_timeout = original_keep_alive_timeout.clone();
        let original_max_headers = original_max_headers.clone();
        let original_max_request_size = original_max_request_size.clone();
        let original_max_header_size_ingress = original_max_header_size_ingress.clone();
        let original_max_header_size_egress = original_max_header_size_egress.clone();
        Callback::from(move |_| {
            let config = serde_json::json!({
                "config": {
                    "header_read_timeout_secs": header_read_timeout.parse::<u64>().unwrap_or(10),
                    "keep_alive_timeout_secs": keep_alive_timeout.parse::<u64>().unwrap_or(60),
                    "max_headers": max_headers.parse::<usize>().unwrap_or(128),
                    "max_request_size": human_to_bytes(&max_request_size),
                    "max_header_size_ingress": human_to_bytes(&max_header_size_ingress),
                    "max_header_size_egress": human_to_bytes(&max_header_size_egress),
                }
            });
            let saving = saving.clone();
            let header_read_timeout = header_read_timeout.clone();
            let keep_alive_timeout = keep_alive_timeout.clone();
            let max_headers = max_headers.clone();
            let max_request_size = max_request_size.clone();
            let max_header_size_ingress = max_header_size_ingress.clone();
            let max_header_size_egress = max_header_size_egress.clone();
            let original_header_read_timeout = original_header_read_timeout.clone();
            let original_keep_alive_timeout = original_keep_alive_timeout.clone();
            let original_max_headers = original_max_headers.clone();
            let original_max_request_size = original_max_request_size.clone();
            let original_max_header_size_ingress = original_max_header_size_ingress.clone();
            let original_max_header_size_egress = original_max_header_size_egress.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_http_config(&config).await;
                saving.set(false);
                original_header_read_timeout.set((*header_read_timeout).clone());
                original_keep_alive_timeout.set((*keep_alive_timeout).clone());
                original_max_headers.set((*max_headers).clone());
                original_max_request_size.set((*max_request_size).clone());
                original_max_header_size_ingress.set((*max_header_size_ingress).clone());
                original_max_header_size_egress.set((*max_header_size_egress).clone());
                toast_success("HTTP configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Header Read Timeout (secs)"
                    name="header_read_timeout"
                    input_type="number"
                    value={(*header_read_timeout).clone()}
                    on_change={on_change(header_read_timeout.clone())}
                />
                <Input
                    label="Keep-Alive Timeout (secs)"
                    name="keep_alive_timeout"
                    input_type="number"
                    value={(*keep_alive_timeout).clone()}
                    on_change={on_change(keep_alive_timeout.clone())}
                />
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Max Headers"
                    name="max_headers"
                    input_type="number"
                    value={(*max_headers).clone()}
                    on_change={on_change(max_headers.clone())}
                />
                <Input
                    label="Max Request Size"
                    name="max_request_size"
                    value={(*max_request_size).clone()}
                    on_change={on_change(max_request_size.clone())}
                    help="Maximum request body size"
                />
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Max Header Size (Ingress)"
                    name="max_header_size_ingress"
                    value={(*max_header_size_ingress).clone()}
                    on_change={on_change(max_header_size_ingress.clone())}
                />
                <Input
                    label="Max Header Size (Egress)"
                    name="max_header_size_egress"
                    value={(*max_header_size_egress).clone()}
                    on_change={on_change(max_header_size_egress.clone())}
                />
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
    }
}

#[function_component]
fn LoggingSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let log_level = use_state(|| "info".to_string());
    let access_log_format = use_state(|| "json".to_string());
    let access_log_dir = use_state(|| "/var/log/rustwaf".to_string());
    let retention_days = use_state(|| "5".to_string());
    let max_entries_per_file = use_state(|| "50000".to_string());

    let original_log_level = use_state(|| "info".to_string());
    let original_access_log_format = use_state(|| "json".to_string());
    let original_access_log_dir = use_state(|| "/var/log/rustwaf".to_string());
    let original_retention_days = use_state(|| "5".to_string());
    let original_max_entries_per_file = use_state(|| "50000".to_string());

    let is_dirty = *log_level != *original_log_level
        || *access_log_format != *original_access_log_format
        || *access_log_dir != *original_access_log_dir
        || *retention_days != *original_retention_days
        || *max_entries_per_file != *original_max_entries_per_file;

    use_effect_with((), {
        let loading = loading.clone();
        let log_level = log_level.clone();
        let access_log_format = access_log_format.clone();
        let access_log_dir = access_log_dir.clone();
        let retention_days = retention_days.clone();
        let max_entries_per_file = max_entries_per_file.clone();
        let original_log_level = original_log_level.clone();
        let original_access_log_format = original_access_log_format.clone();
        let original_access_log_dir = original_access_log_dir.clone();
        let original_retention_days = original_retention_days.clone();
        let original_max_entries_per_file = original_max_entries_per_file.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_logging_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(v) = config.get("level").and_then(|v| v.as_str()) {
                            let s = v.to_string();
                            log_level.set(s.clone());
                            original_log_level.set(s);
                        }
                        if let Some(v) = config.get("access_log_format").and_then(|v| v.as_str()) {
                            let s = v.to_string();
                            access_log_format.set(s.clone());
                            original_access_log_format.set(s);
                        }
                        if let Some(v) = config.get("access_log_dir").and_then(|v| v.as_str()) {
                            let s = v.to_string();
                            access_log_dir.set(s.clone());
                            original_access_log_dir.set(s);
                        }
                        if let Some(v) = config.get("retention_days").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            retention_days.set(s.clone());
                            original_retention_days.set(s);
                        }
                        if let Some(v) = config.get("max_entries_per_file").and_then(|v| v.as_u64())
                        {
                            let s = v.to_string();
                            max_entries_per_file.set(s.clone());
                            original_max_entries_per_file.set(s);
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

    let on_change = |state: UseStateHandle<String>| -> Callback<String> {
        Callback::from(move |value: String| {
            state.set(value);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let log_level = log_level.clone();
        let access_log_format = access_log_format.clone();
        let access_log_dir = access_log_dir.clone();
        let retention_days = retention_days.clone();
        let max_entries_per_file = max_entries_per_file.clone();
        let original_log_level = original_log_level.clone();
        let original_access_log_format = original_access_log_format.clone();
        let original_access_log_dir = original_access_log_dir.clone();
        let original_retention_days = original_retention_days.clone();
        let original_max_entries_per_file = original_max_entries_per_file.clone();
        Callback::from(move |_| {
            let config = serde_json::json!({
                "config": {
                    "level": (*log_level).clone(),
                    "access_log_format": (*access_log_format).clone(),
                    "access_log_dir": (*access_log_dir).clone(),
                    "retention_days": retention_days.parse::<u32>().unwrap_or(5),
                    "max_entries_per_file": max_entries_per_file.parse::<u32>().unwrap_or(50000),
                }
            });
            let saving = saving.clone();
            let log_level = log_level.clone();
            let access_log_format = access_log_format.clone();
            let access_log_dir = access_log_dir.clone();
            let retention_days = retention_days.clone();
            let max_entries_per_file = max_entries_per_file.clone();
            let original_log_level = original_log_level.clone();
            let original_access_log_format = original_access_log_format.clone();
            let original_access_log_dir = original_access_log_dir.clone();
            let original_retention_days = original_retention_days.clone();
            let original_max_entries_per_file = original_max_entries_per_file.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_logging_config(&config).await;
                saving.set(false);
                original_log_level.set((*log_level).clone());
                original_access_log_format.set((*access_log_format).clone());
                original_access_log_dir.set((*access_log_dir).clone());
                original_retention_days.set((*retention_days).clone());
                original_max_entries_per_file.set((*max_entries_per_file).clone());
                toast_success("Logging configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <Select
                label="Log Level"
                name="log_level"
                value={(*log_level).clone()}
                options={vec![
                    ("trace".to_string(), "Trace".to_string()),
                    ("debug".to_string(), "Debug".to_string()),
                    ("info".to_string(), "Info".to_string()),
                    ("warn".to_string(), "Warning".to_string()),
                    ("error".to_string(), "Error".to_string()),
                ]}
                help="Minimum log level to record"
                on_change={on_change(log_level.clone())}
            />

            <div class="grid grid-cols-2 gap-4">
                <Select
                    label="Access Log Format"
                    name="access_log_format"
                    value={(*access_log_format).clone()}
                    options={vec![
                        ("json".to_string(), "JSON".to_string()),
                        ("text".to_string(), "Plain Text".to_string()),
                    ]}
                    on_change={on_change(access_log_format.clone())}
                />
                <Input
                    label="Access Log Directory"
                    name="access_log_dir"
                    value={(*access_log_dir).clone()}
                    on_change={on_change(access_log_dir.clone())}
                />
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Retention Days"
                    name="retention_days"
                    input_type="number"
                    value={(*retention_days).clone()}
                    on_change={on_change(retention_days.clone())}
                />
                <Input
                    label="Max Entries Per File"
                    name="max_entries_per_file"
                    input_type="number"
                    value={(*max_entries_per_file).clone()}
                    on_change={on_change(max_entries_per_file.clone())}
                />
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
    }
}

#[function_component]
fn MetricsSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let metrics_enabled = use_state(|| true);
    let metrics_port = use_state(|| "9090".to_string());

    let original_metrics_enabled = use_state(|| true);
    let original_metrics_port = use_state(|| "9090".to_string());

    let is_dirty =
        *metrics_enabled != *original_metrics_enabled || *metrics_port != *original_metrics_port;

    use_effect_with((), {
        let loading = loading.clone();
        let metrics_enabled = metrics_enabled.clone();
        let metrics_port = metrics_port.clone();
        let original_metrics_enabled = original_metrics_enabled.clone();
        let original_metrics_port = original_metrics_port.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_main_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(metrics) = config.get("metrics") {
                            if let Some(v) = metrics.get("enabled").and_then(|v| v.as_bool()) {
                                metrics_enabled.set(v);
                                original_metrics_enabled.set(v);
                            }
                            if let Some(v) = metrics.get("port").and_then(|v| v.as_u64()) {
                                let s = v.to_string();
                                metrics_port.set(s.clone());
                                original_metrics_port.set(s);
                            }
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

    let on_port_change = {
        let metrics_port = metrics_port.clone();
        Callback::from(move |value: String| {
            metrics_port.set(value);
        })
    };

    let on_toggle_enabled = {
        let metrics_enabled = metrics_enabled.clone();
        Callback::from(move |_: MouseEvent| {
            metrics_enabled.set(!*metrics_enabled);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let metrics_enabled = metrics_enabled.clone();
        let metrics_port = metrics_port.clone();
        let original_metrics_enabled = original_metrics_enabled.clone();
        let original_metrics_port = original_metrics_port.clone();
        Callback::from(move |_| {
            let config = serde_json::json!({
                "config": {
                    "metrics": {
                        "enabled": *metrics_enabled,
                        "port": metrics_port.parse::<u16>().unwrap_or(9090),
                    }
                }
            });
            let saving = saving.clone();
            let metrics_enabled = metrics_enabled.clone();
            let metrics_port = metrics_port.clone();
            let original_metrics_enabled = original_metrics_enabled.clone();
            let original_metrics_port = original_metrics_port.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_main_config(&config).await;
                saving.set(false);
                original_metrics_enabled.set(*metrics_enabled);
                original_metrics_port.set((*metrics_port).clone());
                toast_success("Metrics configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Enable Metrics" }</p>
                    <p class="text-sm text-secondary">{ "Expose Prometheus metrics endpoint" }</p>
                </div>
                <button
                    onclick={on_toggle_enabled}
                    class={format!("relative w-10 h-6 rounded-full {}", if *metrics_enabled { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *metrics_enabled { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <Input
                label="Metrics Port"
                name="metrics_port"
                input_type="number"
                value={(*metrics_port).clone()}
                on_change={on_port_change}
                help="Port for Prometheus metrics endpoint"
                badge={restart_badge()}
            />

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
    }
}

#[function_component]
fn RateLimitsSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let ip_per_second = use_state(|| "10".to_string());
    let ip_per_minute = use_state(|| "60".to_string());
    let ip_per_5min = use_state(|| "200".to_string());
    let ip_per_hour = use_state(|| "500".to_string());
    let ip_per_day = use_state(|| "1000".to_string());
    let ip_burst = use_state(|| "20".to_string());
    let global_per_second = use_state(|| "500".to_string());
    let global_per_minute = use_state(|| "5000".to_string());
    let max_connections = use_state(|| "1000".to_string());

    let original_ip_per_second = use_state(|| "10".to_string());
    let original_ip_per_minute = use_state(|| "60".to_string());
    let original_ip_per_5min = use_state(|| "200".to_string());
    let original_ip_per_hour = use_state(|| "500".to_string());
    let original_ip_per_day = use_state(|| "1000".to_string());
    let original_ip_burst = use_state(|| "20".to_string());
    let original_global_per_second = use_state(|| "500".to_string());
    let original_global_per_minute = use_state(|| "5000".to_string());
    let original_max_connections = use_state(|| "1000".to_string());

    let is_dirty = *ip_per_second != *original_ip_per_second
        || *ip_per_minute != *original_ip_per_minute
        || *ip_per_5min != *original_ip_per_5min
        || *ip_per_hour != *original_ip_per_hour
        || *ip_per_day != *original_ip_per_day
        || *ip_burst != *original_ip_burst
        || *global_per_second != *original_global_per_second
        || *global_per_minute != *original_global_per_minute
        || *max_connections != *original_max_connections;

    use_effect_with((), {
        let loading = loading.clone();
        let ip_per_second = ip_per_second.clone();
        let ip_per_minute = ip_per_minute.clone();
        let ip_per_5min = ip_per_5min.clone();
        let ip_per_hour = ip_per_hour.clone();
        let ip_per_day = ip_per_day.clone();
        let ip_burst = ip_burst.clone();
        let global_per_second = global_per_second.clone();
        let global_per_minute = global_per_minute.clone();
        let max_connections = max_connections.clone();
        let original_ip_per_second = original_ip_per_second.clone();
        let original_ip_per_minute = original_ip_per_minute.clone();
        let original_ip_per_5min = original_ip_per_5min.clone();
        let original_ip_per_hour = original_ip_per_hour.clone();
        let original_ip_per_day = original_ip_per_day.clone();
        let original_ip_burst = original_ip_burst.clone();
        let original_global_per_second = original_global_per_second.clone();
        let original_global_per_minute = original_global_per_minute.clone();
        let original_max_connections = original_max_connections.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_rate_limits_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(defaults) = data.get("defaults") {
                        if let Some(ip) = defaults.get("ip") {
                            let set_field =
                                |key: &str,
                                 state: &UseStateHandle<String>,
                                 orig: &UseStateHandle<String>| {
                                    if let Some(v) = ip.get(key).and_then(|v| v.as_u64()) {
                                        let s = v.to_string();
                                        state.set(s.clone());
                                        orig.set(s);
                                    }
                                };
                            set_field("per_second", &ip_per_second, &original_ip_per_second);
                            set_field("per_minute", &ip_per_minute, &original_ip_per_minute);
                            set_field("per_5min", &ip_per_5min, &original_ip_per_5min);
                            set_field("per_hour", &ip_per_hour, &original_ip_per_hour);
                            set_field("per_day", &ip_per_day, &original_ip_per_day);
                            set_field("burst", &ip_burst, &original_ip_burst);
                        }
                        if let Some(global) = defaults.get("global") {
                            let set_field =
                                |key: &str,
                                 state: &UseStateHandle<String>,
                                 orig: &UseStateHandle<String>| {
                                    if let Some(v) = global.get(key).and_then(|v| v.as_u64()) {
                                        let s = v.to_string();
                                        state.set(s.clone());
                                        orig.set(s);
                                    }
                                };
                            set_field(
                                "per_second",
                                &global_per_second,
                                &original_global_per_second,
                            );
                            set_field(
                                "per_minute",
                                &global_per_minute,
                                &original_global_per_minute,
                            );
                            set_field(
                                "max_connections",
                                &max_connections,
                                &original_max_connections,
                            );
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

    let on_change = |state: UseStateHandle<String>| -> Callback<String> {
        Callback::from(move |value: String| {
            state.set(value);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let ip_per_second = ip_per_second.clone();
        let ip_per_minute = ip_per_minute.clone();
        let ip_per_5min = ip_per_5min.clone();
        let ip_per_hour = ip_per_hour.clone();
        let ip_per_day = ip_per_day.clone();
        let ip_burst = ip_burst.clone();
        let global_per_second = global_per_second.clone();
        let global_per_minute = global_per_minute.clone();
        let max_connections = max_connections.clone();
        let original_ip_per_second = original_ip_per_second.clone();
        let original_ip_per_minute = original_ip_per_minute.clone();
        let original_ip_per_5min = original_ip_per_5min.clone();
        let original_ip_per_hour = original_ip_per_hour.clone();
        let original_ip_per_day = original_ip_per_day.clone();
        let original_ip_burst = original_ip_burst.clone();
        let original_global_per_second = original_global_per_second.clone();
        let original_global_per_minute = original_global_per_minute.clone();
        let original_max_connections = original_max_connections.clone();
        Callback::from(move |_| {
            let config = serde_json::json!({
                "defaults": {
                    "ip": {
                        "per_second": ip_per_second.parse::<u32>().unwrap_or(10),
                        "per_minute": ip_per_minute.parse::<u32>().unwrap_or(60),
                        "per_5min": ip_per_5min.parse::<u32>().unwrap_or(200),
                        "per_hour": ip_per_hour.parse::<u32>().unwrap_or(500),
                        "per_day": ip_per_day.parse::<u32>().unwrap_or(1000),
                        "burst": ip_burst.parse::<u32>().unwrap_or(20),
                    },
                    "global": {
                        "per_second": global_per_second.parse::<u32>().unwrap_or(500),
                        "per_minute": global_per_minute.parse::<u32>().unwrap_or(5000),
                        "max_connections": max_connections.parse::<u32>().unwrap_or(1000),
                    }
                }
            });
            let saving = saving.clone();
            let ip_per_second = ip_per_second.clone();
            let ip_per_minute = ip_per_minute.clone();
            let ip_per_5min = ip_per_5min.clone();
            let ip_per_hour = ip_per_hour.clone();
            let ip_per_day = ip_per_day.clone();
            let ip_burst = ip_burst.clone();
            let global_per_second = global_per_second.clone();
            let global_per_minute = global_per_minute.clone();
            let max_connections = max_connections.clone();
            let original_ip_per_second = original_ip_per_second.clone();
            let original_ip_per_minute = original_ip_per_minute.clone();
            let original_ip_per_5min = original_ip_per_5min.clone();
            let original_ip_per_hour = original_ip_per_hour.clone();
            let original_ip_per_day = original_ip_per_day.clone();
            let original_ip_burst = original_ip_burst.clone();
            let original_global_per_second = original_global_per_second.clone();
            let original_global_per_minute = original_global_per_minute.clone();
            let original_max_connections = original_max_connections.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_rate_limits_config(&config).await;
                saving.set(false);
                original_ip_per_second.set((*ip_per_second).clone());
                original_ip_per_minute.set((*ip_per_minute).clone());
                original_ip_per_5min.set((*ip_per_5min).clone());
                original_ip_per_hour.set((*ip_per_hour).clone());
                original_ip_per_day.set((*ip_per_day).clone());
                original_ip_burst.set((*ip_burst).clone());
                original_global_per_second.set((*global_per_second).clone());
                original_global_per_minute.set((*global_per_minute).clone());
                original_max_connections.set((*max_connections).clone());
                toast_success("Rate limits configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <h3 class="font-semibold text-primary">{ "Per-IP Defaults" }</h3>
            <div class="grid grid-cols-3 gap-4">
                <Input label="Per Second" name="ip_per_second" input_type="number" value={(*ip_per_second).clone()} on_change={on_change(ip_per_second.clone())} />
                <Input label="Per Minute" name="ip_per_minute" input_type="number" value={(*ip_per_minute).clone()} on_change={on_change(ip_per_minute.clone())} />
                <Input label="Per 5 Min" name="ip_per_5min" input_type="number" value={(*ip_per_5min).clone()} on_change={on_change(ip_per_5min.clone())} />
                <Input label="Per Hour" name="ip_per_hour" input_type="number" value={(*ip_per_hour).clone()} on_change={on_change(ip_per_hour.clone())} />
                <Input label="Per Day" name="ip_per_day" input_type="number" value={(*ip_per_day).clone()} on_change={on_change(ip_per_day.clone())} />
                <Input label="Burst" name="ip_burst" input_type="number" value={(*ip_burst).clone()} on_change={on_change(ip_burst.clone())} />
            </div>

            <h3 class="font-semibold text-primary mt-6">{ "Global Defaults" }</h3>
            <div class="grid grid-cols-3 gap-4">
                <Input label="Per Second" name="global_per_second" input_type="number" value={(*global_per_second).clone()} on_change={on_change(global_per_second.clone())} />
                <Input label="Per Minute" name="global_per_minute" input_type="number" value={(*global_per_minute).clone()} on_change={on_change(global_per_minute.clone())} />
                <Input label="Max Connections" name="max_connections" input_type="number" value={(*max_connections).clone()} on_change={on_change(max_connections.clone())} />
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
    }
}

#[function_component]
fn BandwidthSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let monthly_cap_ingress = use_state(|| "0".to_string());
    let monthly_cap_egress = use_state(|| "0".to_string());
    let action_on_limit = use_state(|| "block".to_string());
    let reset_mode = use_state(|| "rolling_30_days".to_string());
    let fixed_day = use_state(|| String::new());
    let data_dir = use_state(|| "/var/lib/maluwaf".to_string());

    let original_monthly_cap_ingress = use_state(|| "0".to_string());
    let original_monthly_cap_egress = use_state(|| "0".to_string());
    let original_action_on_limit = use_state(|| "block".to_string());
    let original_reset_mode = use_state(|| "rolling_30_days".to_string());
    let original_fixed_day = use_state(|| String::new());
    let original_data_dir = use_state(|| "/var/lib/maluwaf".to_string());

    let is_dirty = *monthly_cap_ingress != *original_monthly_cap_ingress
        || *monthly_cap_egress != *original_monthly_cap_egress
        || *action_on_limit != *original_action_on_limit
        || *reset_mode != *original_reset_mode
        || *fixed_day != *original_fixed_day
        || *data_dir != *original_data_dir;

    use_effect_with((), {
        let loading = loading.clone();
        let monthly_cap_ingress = monthly_cap_ingress.clone();
        let monthly_cap_egress = monthly_cap_egress.clone();
        let action_on_limit = action_on_limit.clone();
        let reset_mode = reset_mode.clone();
        let fixed_day = fixed_day.clone();
        let data_dir = data_dir.clone();
        let original_monthly_cap_ingress = original_monthly_cap_ingress.clone();
        let original_monthly_cap_egress = original_monthly_cap_egress.clone();
        let original_action_on_limit = original_action_on_limit.clone();
        let original_reset_mode = original_reset_mode.clone();
        let original_fixed_day = original_fixed_day.clone();
        let original_data_dir = original_data_dir.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_traffic_shaping_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(bw) = config.get("bandwidth") {
                            if let Some(v) =
                                bw.get("monthly_cap_ingress_gb").and_then(|v| v.as_u64())
                            {
                                let s = v.to_string();
                                monthly_cap_ingress.set(s.clone());
                                original_monthly_cap_ingress.set(s);
                            }
                            if let Some(v) =
                                bw.get("monthly_cap_egress_gb").and_then(|v| v.as_u64())
                            {
                                let s = v.to_string();
                                monthly_cap_egress.set(s.clone());
                                original_monthly_cap_egress.set(s);
                            }
                            if let Some(v) = bw.get("action_on_limit").and_then(|v| v.as_str()) {
                                let s = v.to_string();
                                action_on_limit.set(s.clone());
                                original_action_on_limit.set(s);
                            }
                            if let Some(v) = bw.get("data_dir").and_then(|v| v.as_str()) {
                                let s = v.to_string();
                                data_dir.set(s.clone());
                                original_data_dir.set(s);
                            }
                            if let Some(reset) = bw.get("monthly_reset") {
                                if let Some(v) = reset.get("mode").and_then(|v| v.as_str()) {
                                    let s = v.to_string();
                                    reset_mode.set(s.clone());
                                    original_reset_mode.set(s);
                                }
                                if let Some(v) = reset.get("fixed_day").and_then(|v| v.as_u64()) {
                                    let s = v.to_string();
                                    fixed_day.set(s.clone());
                                    original_fixed_day.set(s);
                                }
                            }
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

    let on_change = |state: UseStateHandle<String>| -> Callback<String> {
        Callback::from(move |value: String| {
            state.set(value);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let monthly_cap_ingress = monthly_cap_ingress.clone();
        let monthly_cap_egress = monthly_cap_egress.clone();
        let action_on_limit = action_on_limit.clone();
        let reset_mode = reset_mode.clone();
        let fixed_day = fixed_day.clone();
        let data_dir = data_dir.clone();
        let original_monthly_cap_ingress = original_monthly_cap_ingress.clone();
        let original_monthly_cap_egress = original_monthly_cap_egress.clone();
        let original_action_on_limit = original_action_on_limit.clone();
        let original_reset_mode = original_reset_mode.clone();
        let original_fixed_day = original_fixed_day.clone();
        let original_data_dir = original_data_dir.clone();
        Callback::from(move |_| {
            let fixed_day_val = fixed_day.parse::<u32>().ok();
            let mut reset_obj = serde_json::json!({
                "mode": (*reset_mode).clone(),
            });
            if let Some(fd) = fixed_day_val {
                reset_obj["fixed_day"] = serde_json::json!(fd);
            }
            let config = serde_json::json!({
                "config": {
                    "bandwidth": {
                        "monthly_cap_ingress_gb": monthly_cap_ingress.parse::<u64>().unwrap_or(0),
                        "monthly_cap_egress_gb": monthly_cap_egress.parse::<u64>().unwrap_or(0),
                        "action_on_limit": (*action_on_limit).clone(),
                        "monthly_reset": reset_obj,
                        "data_dir": (*data_dir).clone(),
                    }
                }
            });
            let saving = saving.clone();
            let monthly_cap_ingress = monthly_cap_ingress.clone();
            let monthly_cap_egress = monthly_cap_egress.clone();
            let action_on_limit = action_on_limit.clone();
            let reset_mode = reset_mode.clone();
            let fixed_day = fixed_day.clone();
            let data_dir = data_dir.clone();
            let original_monthly_cap_ingress = original_monthly_cap_ingress.clone();
            let original_monthly_cap_egress = original_monthly_cap_egress.clone();
            let original_action_on_limit = original_action_on_limit.clone();
            let original_reset_mode = original_reset_mode.clone();
            let original_fixed_day = original_fixed_day.clone();
            let original_data_dir = original_data_dir.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_traffic_shaping_config(&config).await;
                saving.set(false);
                original_monthly_cap_ingress.set((*monthly_cap_ingress).clone());
                original_monthly_cap_egress.set((*monthly_cap_egress).clone());
                original_action_on_limit.set((*action_on_limit).clone());
                original_reset_mode.set((*reset_mode).clone());
                original_fixed_day.set((*fixed_day).clone());
                original_data_dir.set((*data_dir).clone());
                toast_success("Bandwidth configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <h3 class="font-semibold text-primary">{ "Monthly Limits" }</h3>
            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Monthly Ingress Cap (GB)"
                    name="monthly_cap_ingress_gb"
                    input_type="number"
                    value={(*monthly_cap_ingress).clone()}
                    on_change={on_change(monthly_cap_ingress.clone())}
                    help="Set to 0 for unlimited. For example: 5000 for 5TB"
                />
                <Input
                    label="Monthly Egress Cap (GB)"
                    name="monthly_cap_egress_gb"
                    input_type="number"
                    value={(*monthly_cap_egress).clone()}
                    on_change={on_change(monthly_cap_egress.clone())}
                    help="Set to 0 for unlimited. For example: 5000 for 5TB"
                />
            </div>

            <div class="flex items-center justify-between py-3 border-b border-default">
                <div>
                    <p class="text-primary font-medium">{ "Action on Limit Exceeded" }</p>
                    <p class="text-sm text-secondary">{ "What to do when monthly bandwidth cap is reached" }</p>
                </div>
                <select
                    class="bg-tertiary text-primary px-3 py-2 rounded-lg border border-default"
                    value={(*action_on_limit).clone()}
                    onchange={
                        let action_on_limit = action_on_limit.clone();
                        Callback::from(move |e: Event| {
                            let target: web_sys::HtmlSelectElement = e.target_unchecked_into();
                            action_on_limit.set(target.value());
                        })
                    }
                >
                    <option value="block" selected={*action_on_limit == "block"}>{ "Hard Block (503)" }</option>
                    <option value="throttle" selected={*action_on_limit == "throttle"}>{ "Throttle to Monthly Rate" }</option>
                </select>
            </div>

            <h3 class="font-semibold text-primary mt-6">{ "Reset Configuration" }</h3>
            <div class="flex items-center justify-between py-3 border-b border-default">
                <div>
                    <p class="text-primary font-medium">{ "Reset Mode" }</p>
                    <p class="text-sm text-secondary">{ "How to determine the billing period" }</p>
                </div>
                <select
                    class="bg-tertiary text-primary px-3 py-2 rounded-lg border border-default"
                    value={(*reset_mode).clone()}
                    onchange={
                        let reset_mode = reset_mode.clone();
                        Callback::from(move |e: Event| {
                            let target: web_sys::HtmlSelectElement = e.target_unchecked_into();
                            reset_mode.set(target.value());
                        })
                    }
                >
                    <option value="rolling_30_days" selected={*reset_mode == "rolling_30_days"}>{ "Rolling 30 Days" }</option>
                    <option value="calendar_month" selected={*reset_mode == "calendar_month"}>{ "Calendar Month (1st of each month)" }</option>
                    <option value="fixed_date" selected={*reset_mode == "fixed_date"}>{ "Fixed Day of Month" }</option>
                </select>
            </div>

            <Input
                label="Fixed Day of Month (1-28)"
                name="fixed_day"
                input_type="number"
                value={(*fixed_day).clone()}
                on_change={on_change(fixed_day.clone())}
                help="Day of month to reset bandwidth counters (only for Fixed Date mode)"
            />

            <h3 class="font-semibold text-primary mt-6">{ "Data Persistence" }</h3>
            <Input
                label="Data Directory"
                name="bandwidth_data_dir"
                value={(*data_dir).clone()}
                on_change={on_change(data_dir.clone())}
                help="Directory to store bandwidth counter persistence file"
            />

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
    }
}

#[function_component]
fn BotSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let block_ai_crawlers = use_state(|| true);
    let enable_css_honeypot = use_state(|| true);
    let enable_js_challenge = use_state(|| false);
    let js_difficulty = use_state(|| "6".to_string());

    let original_block_ai_crawlers = use_state(|| true);
    let original_enable_css_honeypot = use_state(|| true);
    let original_enable_js_challenge = use_state(|| false);
    let original_js_difficulty = use_state(|| "6".to_string());

    let is_dirty = *block_ai_crawlers != *original_block_ai_crawlers
        || *enable_css_honeypot != *original_enable_css_honeypot
        || *enable_js_challenge != *original_enable_js_challenge
        || *js_difficulty != *original_js_difficulty;

    use_effect_with((), {
        let loading = loading.clone();
        let block_ai_crawlers = block_ai_crawlers.clone();
        let enable_css_honeypot = enable_css_honeypot.clone();
        let enable_js_challenge = enable_js_challenge.clone();
        let js_difficulty = js_difficulty.clone();
        let original_block_ai_crawlers = original_block_ai_crawlers.clone();
        let original_enable_css_honeypot = original_enable_css_honeypot.clone();
        let original_enable_js_challenge = original_enable_js_challenge.clone();
        let original_js_difficulty = original_js_difficulty.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_bot_detection_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(v) = config.get("block_ai_crawlers").and_then(|v| v.as_bool()) {
                            block_ai_crawlers.set(v);
                            original_block_ai_crawlers.set(v);
                        }
                        if let Some(v) = config.get("enable_css_honeypot").and_then(|v| v.as_bool())
                        {
                            enable_css_honeypot.set(v);
                            original_enable_css_honeypot.set(v);
                        }
                        if let Some(v) = config.get("enable_js_challenge").and_then(|v| v.as_bool())
                        {
                            enable_js_challenge.set(v);
                            original_enable_js_challenge.set(v);
                        }
                        if let Some(v) = config.get("js_difficulty").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            js_difficulty.set(s.clone());
                            original_js_difficulty.set(s);
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

    let on_difficulty_change = {
        let js_difficulty = js_difficulty.clone();
        Callback::from(move |value: String| {
            js_difficulty.set(value);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let block_ai_crawlers = block_ai_crawlers.clone();
        let enable_css_honeypot = enable_css_honeypot.clone();
        let enable_js_challenge = enable_js_challenge.clone();
        let js_difficulty = js_difficulty.clone();
        let original_block_ai_crawlers = original_block_ai_crawlers.clone();
        let original_enable_css_honeypot = original_enable_css_honeypot.clone();
        let original_enable_js_challenge = original_enable_js_challenge.clone();
        let original_js_difficulty = original_js_difficulty.clone();
        Callback::from(move |_| {
            let config = serde_json::json!({
                "config": {
                    "block_ai_crawlers": *block_ai_crawlers,
                    "enable_css_honeypot": *enable_css_honeypot,
                    "enable_js_challenge": *enable_js_challenge,
                    "js_difficulty": js_difficulty.parse::<u8>().unwrap_or(6),
                }
            });
            let saving = saving.clone();
            let block_ai_crawlers = block_ai_crawlers.clone();
            let enable_css_honeypot = enable_css_honeypot.clone();
            let enable_js_challenge = enable_js_challenge.clone();
            let js_difficulty = js_difficulty.clone();
            let original_block_ai_crawlers = original_block_ai_crawlers.clone();
            let original_enable_css_honeypot = original_enable_css_honeypot.clone();
            let original_enable_js_challenge = original_enable_js_challenge.clone();
            let original_js_difficulty = original_js_difficulty.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_bot_detection_config(&config).await;
                saving.set(false);
                original_block_ai_crawlers.set(*block_ai_crawlers);
                original_enable_css_honeypot.set(*enable_css_honeypot);
                original_enable_js_challenge.set(*enable_js_challenge);
                original_js_difficulty.set((*js_difficulty).clone());
                toast_success("Bot detection configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Block AI Crawlers" }</p>
                    <p class="text-sm text-secondary">{ "Block known AI/ML web crawlers" }</p>
                </div>
                <button
                    onclick={
                        let block_ai_crawlers = block_ai_crawlers.clone();
                        Callback::from(move |_: MouseEvent| {
                            block_ai_crawlers.set(!*block_ai_crawlers);
                        })
                    }
                    class={format!("relative w-10 h-6 rounded-full {}", if *block_ai_crawlers { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *block_ai_crawlers { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Enable CSS Honeypot" }</p>
                    <p class="text-sm text-secondary">{ "Use CSS-based bot detection" }</p>
                </div>
                <button
                    onclick={
                        let enable_css_honeypot = enable_css_honeypot.clone();
                        Callback::from(move |_: MouseEvent| {
                            enable_css_honeypot.set(!*enable_css_honeypot);
                        })
                    }
                    class={format!("relative w-10 h-6 rounded-full {}", if *enable_css_honeypot { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *enable_css_honeypot { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Enable JS Challenge" }</p>
                    <p class="text-sm text-secondary">{ "Use Proof-of-Work challenges" }</p>
                </div>
                <button
                    onclick={
                        let enable_js_challenge = enable_js_challenge.clone();
                        Callback::from(move |_: MouseEvent| {
                            enable_js_challenge.set(!*enable_js_challenge);
                        })
                    }
                    class={format!("relative w-10 h-6 rounded-full {}", if *enable_js_challenge { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *enable_js_challenge { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <Input
                label="JS Challenge Difficulty"
                name="js_difficulty"
                input_type="number"
                value={(*js_difficulty).clone()}
                on_change={on_difficulty_change}
                help="Higher values = harder challenges (1-10)"
            />

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
    }
}

#[function_component]
fn UploadSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let max_size = use_state(|| "100MB".to_string());
    let memory_threshold = use_state(|| "10MB".to_string());
    let scan_with_yara = use_state(|| true);
    let sandbox_enabled = use_state(|| true);

    let original_max_size = use_state(|| "100MB".to_string());
    let original_memory_threshold = use_state(|| "10MB".to_string());
    let original_scan_with_yara = use_state(|| true);
    let original_sandbox_enabled = use_state(|| true);

    let is_dirty = *max_size != *original_max_size
        || *memory_threshold != *original_memory_threshold
        || *scan_with_yara != *original_scan_with_yara
        || *sandbox_enabled != *original_sandbox_enabled;

    use_effect_with((), {
        let loading = loading.clone();
        let max_size = max_size.clone();
        let memory_threshold = memory_threshold.clone();
        let scan_with_yara = scan_with_yara.clone();
        let sandbox_enabled = sandbox_enabled.clone();
        let original_max_size = original_max_size.clone();
        let original_memory_threshold = original_memory_threshold.clone();
        let original_scan_with_yara = original_scan_with_yara.clone();
        let original_sandbox_enabled = original_sandbox_enabled.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_main_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(defaults) = config.get("defaults") {
                            if let Some(upload) = defaults.get("upload") {
                                if let Some(v) = upload.get("max_size").and_then(|v| v.as_str()) {
                                    let s = v.to_string();
                                    max_size.set(s.clone());
                                    original_max_size.set(s);
                                }
                                if let Some(v) =
                                    upload.get("memory_threshold").and_then(|v| v.as_str())
                                {
                                    let s = v.to_string();
                                    memory_threshold.set(s.clone());
                                    original_memory_threshold.set(s);
                                }
                                if let Some(v) =
                                    upload.get("scan_with_yara").and_then(|v| v.as_bool())
                                {
                                    scan_with_yara.set(v);
                                    original_scan_with_yara.set(v);
                                }
                                if let Some(v) =
                                    upload.get("sandbox_enabled").and_then(|v| v.as_bool())
                                {
                                    sandbox_enabled.set(v);
                                    original_sandbox_enabled.set(v);
                                }
                            }
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

    let on_change = |state: UseStateHandle<String>| -> Callback<String> {
        Callback::from(move |value: String| {
            state.set(value);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let max_size = max_size.clone();
        let memory_threshold = memory_threshold.clone();
        let scan_with_yara = scan_with_yara.clone();
        let sandbox_enabled = sandbox_enabled.clone();
        let original_max_size = original_max_size.clone();
        let original_memory_threshold = original_memory_threshold.clone();
        let original_scan_with_yara = original_scan_with_yara.clone();
        let original_sandbox_enabled = original_sandbox_enabled.clone();
        Callback::from(move |_| {
            let config = serde_json::json!({
                "config": {
                    "defaults": {
                        "upload": {
                            "max_size": (*max_size).clone(),
                            "memory_threshold": (*memory_threshold).clone(),
                            "scan_with_yara": *scan_with_yara,
                            "sandbox_enabled": *sandbox_enabled,
                        }
                    }
                }
            });
            let saving = saving.clone();
            let max_size = max_size.clone();
            let memory_threshold = memory_threshold.clone();
            let scan_with_yara = scan_with_yara.clone();
            let sandbox_enabled = sandbox_enabled.clone();
            let original_max_size = original_max_size.clone();
            let original_memory_threshold = original_memory_threshold.clone();
            let original_scan_with_yara = original_scan_with_yara.clone();
            let original_sandbox_enabled = original_sandbox_enabled.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_main_config(&config).await;
                saving.set(false);
                original_max_size.set((*max_size).clone());
                original_memory_threshold.set((*memory_threshold).clone());
                original_scan_with_yara.set(*scan_with_yara);
                original_sandbox_enabled.set(*sandbox_enabled);
                toast_success("Upload configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Max Upload Size"
                    name="upload_max_size"
                    value={(*max_size).clone()}
                    on_change={on_change(max_size.clone())}
                />
                <Input
                    label="Memory Threshold"
                    name="upload_memory_threshold"
                    value={(*memory_threshold).clone()}
                    on_change={on_change(memory_threshold.clone())}
                    help="Files under this threshold are scanned in-memory"
                />
            </div>

            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Scan with YARA" }</p>
                    <p class="text-sm text-secondary">{ "Scan uploads for malware signatures" }</p>
                </div>
                <button
                    onclick={
                        let scan_with_yara = scan_with_yara.clone();
                        Callback::from(move |_: MouseEvent| {
                            scan_with_yara.set(!*scan_with_yara);
                        })
                    }
                    class={format!("relative w-10 h-6 rounded-full {}", if *scan_with_yara { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *scan_with_yara { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Sandbox Files" }</p>
                    <p class="text-sm text-secondary">{ "Isolate uploads before forwarding" }</p>
                </div>
                <button
                    onclick={
                        let sandbox_enabled = sandbox_enabled.clone();
                        Callback::from(move |_: MouseEvent| {
                            sandbox_enabled.set(!*sandbox_enabled);
                        })
                    }
                    class={format!("relative w-10 h-6 rounded-full {}", if *sandbox_enabled { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *sandbox_enabled { "translate-x-5" } else { "translate-x-0" })} />
                </button>
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
    }
}

#[function_component]
fn ThemeSection() -> Html {
    let theme_data = use_state(|| None::<ThemeResponse>);
    let selected_preset = use_state(|| "default".to_string());
    let selected_mode = use_state(|| "auto".to_string());
    let preview_html = use_state(|| String::new());
    let preview_light = use_state(|| false);
    let saving = use_state(|| false);
    let loading = use_state(|| true);
    let original_preset = use_state(|| "default".to_string());
    let original_mode = use_state(|| "auto".to_string());

    let is_dirty = *selected_preset != *original_preset || *selected_mode != *original_mode;

    use_effect_with((), {
        let theme_data = theme_data.clone();
        let selected_preset = selected_preset.clone();
        let selected_mode = selected_mode.clone();
        let preview_html = preview_html.clone();
        let preview_light = preview_light.clone();
        let loading = loading.clone();
        let original_preset = original_preset.clone();
        let original_mode = original_mode.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let theme_result = api.get_theme().await;
                let css_result = api.get_theme_css().await;
                let use_light = *preview_light;

                if let Ok(data) = theme_result {
                    theme_data.set(Some(data.clone()));
                    selected_preset.set(data.preset.clone());
                    selected_mode.set(data.mode.clone());
                    original_preset.set(data.preset.clone());
                    original_mode.set(data.mode.clone());

                    if let Ok(css) = css_result {
                        let html = generate_preview_html(&css, &data.colors, use_light);
                        preview_html.set(html);
                    }
                }
                loading.set(false);
            });
            || {}
        }
    });

    let on_preset_change = {
        let selected_preset = selected_preset.clone();
        let preview_html = preview_html.clone();
        let theme_data = theme_data.clone();
        let preview_light = preview_light.clone();
        Callback::from(move |e: Event| {
            let target = e.target().unwrap();
            let value = target
                .dyn_ref::<web_sys::HtmlSelectElement>()
                .map(|el| el.value())
                .unwrap_or_default();
            selected_preset.set(value.clone());

            if let Some(ref data) = *theme_data {
                let colors = get_preset_colors(&value);
                let use_light = *preview_light;
                let html = generate_preview_html("", &colors, use_light);
                preview_html.set(html);
            }
        })
    };

    let on_mode_change = {
        let selected_mode = selected_mode.clone();
        Callback::from(move |e: Event| {
            let target = e.target().unwrap();
            let value = target
                .dyn_ref::<web_sys::HtmlSelectElement>()
                .map(|el| el.value())
                .unwrap_or_default();
            selected_mode.set(value);
        })
    };

    let on_toggle_preview = {
        let preview_light = preview_light.clone();
        let selected_preset = selected_preset.clone();
        let theme_data = theme_data.clone();
        let preview_html = preview_html.clone();
        Callback::from(move |_| {
            let new_value = !*preview_light;
            preview_light.set(new_value);

            if let Some(ref data) = *theme_data {
                let colors = get_preset_colors(&selected_preset);
                let html = generate_preview_html("", &colors, new_value);
                preview_html.set(html);
            }
        })
    };

    let on_save = {
        let saving = saving.clone();
        let selected_preset = selected_preset.clone();
        let selected_mode = selected_mode.clone();
        let theme_data = theme_data.clone();
        let preview_html = preview_html.clone();
        let preview_light = preview_light.clone();
        let original_preset = original_preset.clone();
        let original_mode = original_mode.clone();
        Callback::from(move |_| {
            let preset = (*selected_preset).clone();
            let mode = (*selected_mode).clone();
            let theme_data = theme_data.clone();
            let preview_html = preview_html.clone();
            let preview_light = *preview_light;
            let saving = saving.clone();
            let original_preset = original_preset.clone();
            let original_mode = original_mode.clone();
            let preset_for_orig = preset.clone();
            let mode_for_orig = mode.clone();

            saving.set(true);

            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let request = UpdateThemeRequest {
                    preset: Some(preset),
                    mode: Some(mode),
                    allow_only: None,
                };

                match api.update_theme(&request).await {
                    Ok(data) => {
                        theme_data.set(Some(data.clone()));
                        original_preset.set(preset_for_orig);
                        original_mode.set(mode_for_orig);
                        toast_success("Theme updated successfully");

                        match api.get_theme_css().await {
                            Ok(css) => {
                                let html = generate_preview_html(&css, &data.colors, preview_light);
                                preview_html.set(html);
                            }
                            Err(e) => {
                                tracing::error!("Failed to fetch theme CSS: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        toast_error(&format!("Failed to update theme: {}", e));
                        tracing::error!("Failed to update theme: {}", e);
                    }
                }
                saving.set(false);
            });
        })
    };

    let on_reset = {
        let selected_preset = selected_preset.clone();
        let selected_mode = selected_mode.clone();
        let theme_data = theme_data.clone();
        let preview_html = preview_html.clone();
        let preview_light = preview_light.clone();
        Callback::from(move |_| {
            selected_preset.set("default".to_string());
            selected_mode.set("auto".to_string());

            if let Some(ref data) = *theme_data {
                let colors = get_preset_colors("default");
                let use_light = *preview_light;
                let html = generate_preview_html("", &colors, use_light);
                preview_html.set(html);
            }

            let request = UpdateThemeRequest {
                preset: Some("default".to_string()),
                mode: Some("auto".to_string()),
                allow_only: None,
            };

            let theme_data = theme_data.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.update_theme(&request).await {
                    Ok(data) => {
                        theme_data.set(Some(data.clone()));
                        toast_success("Theme reset to default");
                    }
                    Err(e) => {
                        toast_error(&format!("Failed to reset theme: {}", e));
                    }
                }
            });
        })
    };

    let presets = vec![
        ("default", "Default"),
        ("dark", "Dark"),
        ("light", "Light"),
        ("ocean", "Ocean"),
        ("forest", "Forest"),
        ("sunset", "Sunset"),
    ];

    let modes = vec![
        ("auto", "Auto (System)"),
        ("dark", "Dark"),
        ("light", "Light"),
    ];

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    html! {
        <div class="space-y-6">
            <div>
                <label class="block text-sm font-medium text-primary mb-2">{ "Theme Preset" }</label>
                <select
                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                    value={(*selected_preset).clone()}
                    onchange={on_preset_change}
                >
                    { for presets.iter().map(|(value, label)| {
                        html! {
                            <option value={value.clone()}>{label.clone()}</option>
                        }
                    }) }
                </select>
                <p class="mt-1 text-sm text-secondary">{ "Choose a color scheme for the admin interface" }</p>
            </div>

            <div>
                <label class="block text-sm font-medium text-primary mb-2">{ "Theme Mode" }</label>
                <select
                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                    value={(*selected_mode).clone()}
                    onchange={on_mode_change}
                >
                    { for modes.iter().map(|(value, label)| {
                        html! {
                            <option value={value.clone()}>{label.clone()}</option>
                        }
                    }) }
                </select>
                <p class="mt-1 text-sm text-secondary">{ "How users can switch between light and dark themes" }</p>
            </div>

            <div>
                <div class="flex items-center justify-between mb-2">
                    <label class="block text-sm font-medium text-primary">{ "Preview" }</label>
                    <button
                        onclick={on_toggle_preview}
                        class="px-3 py-1 text-sm bg-tertiary border border-default rounded-lg text-primary hover:opacity-80"
                    >
                        { if *preview_light { "🌙 Dark" } else { "☀️ Light" } }
                    </button>
                </div>
                <div class="border border-default rounded-lg overflow-hidden">
                    <iframe
                        srcdoc={(*preview_html).clone()}
                        class="w-full h-64"
                        sandbox="allow-same-origin"
                    />
                </div>
                <p class="mt-1 text-sm text-secondary">{ "Sample error page preview with current theme" }</p>
            </div>

            <div class="flex justify-between gap-4">
                <button
                    onclick={on_reset}
                    disabled={*saving}
                    class="px-4 py-2 bg-tertiary text-primary rounded-lg hover:opacity-80 disabled:opacity-50"
                >
                    { "Reset to Default" }
                </button>
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class={if is_dirty {
                        "px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50"
                    } else {
                        "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    }}
                >
                    { if *saving { "Saving..." } else if is_dirty { "Save Changes*" } else { "Save Changes" } }
                </button>
            </div>
        </div>
    }
}

fn get_preset_colors(preset: &str) -> crate::types::ThemeColorsResponse {
    match preset {
        "light" => crate::types::ThemeColorsResponse {
            dark: crate::types::ThemeColors {
                background: "#0a0a0f".to_string(),
                surface: "#12121a".to_string(),
                primary: "#e94560".to_string(),
                text: "#f0f0f5".to_string(),
                border: "#2a2a3a".to_string(),
                accent: "#1a1a24".to_string(),
                accent_primary: "#00d4aa".to_string(),
                accent_secondary: "#00b894".to_string(),
            },
            light: crate::types::ThemeColors {
                background: "#f8fafc".to_string(),
                surface: "#ffffff".to_string(),
                primary: "#c41e3a".to_string(),
                text: "#0f172a".to_string(),
                border: "#e2e8f0".to_string(),
                accent: "#f1f5f9".to_string(),
                accent_primary: "#059669".to_string(),
                accent_secondary: "#10b981".to_string(),
            },
        },
        "ocean" => crate::types::ThemeColorsResponse {
            dark: crate::types::ThemeColors {
                background: "#0c1929".to_string(),
                surface: "#132f4c".to_string(),
                primary: "#0ea5e9".to_string(),
                text: "#e3f2fd".to_string(),
                border: "#2d4a6f".to_string(),
                accent: "#173a5e".to_string(),
                accent_primary: "#0ea5e9".to_string(),
                accent_secondary: "#38bdf8".to_string(),
            },
            light: crate::types::ThemeColors {
                background: "#e3f2fd".to_string(),
                surface: "#ffffff".to_string(),
                primary: "#0284c7".to_string(),
                text: "#0c1929".to_string(),
                border: "#90caf9".to_string(),
                accent: "#f1f5f9".to_string(),
                accent_primary: "#0ea5e9".to_string(),
                accent_secondary: "#38bdf8".to_string(),
            },
        },
        "forest" => crate::types::ThemeColorsResponse {
            dark: crate::types::ThemeColors {
                background: "#0a1a0f".to_string(),
                surface: "#132318".to_string(),
                primary: "#22c55e".to_string(),
                text: "#e8f5e9".to_string(),
                border: "#2d4a3a".to_string(),
                accent: "#1a2e21".to_string(),
                accent_primary: "#22c55e".to_string(),
                accent_secondary: "#4ade80".to_string(),
            },
            light: crate::types::ThemeColors {
                background: "#e8f5e9".to_string(),
                surface: "#ffffff".to_string(),
                primary: "#16a34a".to_string(),
                text: "#0a1a0f".to_string(),
                border: "#a5d6a7".to_string(),
                accent: "#f1f5f9".to_string(),
                accent_primary: "#22c55e".to_string(),
                accent_secondary: "#4ade80".to_string(),
            },
        },
        "sunset" => crate::types::ThemeColorsResponse {
            dark: crate::types::ThemeColors {
                background: "#1a0f0a".to_string(),
                surface: "#2a1a14".to_string(),
                primary: "#f97316".to_string(),
                text: "#fff1ec".to_string(),
                border: "#4a3028".to_string(),
                accent: "#3d261e".to_string(),
                accent_primary: "#f97316".to_string(),
                accent_secondary: "#fb923c".to_string(),
            },
            light: crate::types::ThemeColors {
                background: "#fff1ec".to_string(),
                surface: "#ffffff".to_string(),
                primary: "#ea580c".to_string(),
                text: "#1a0f0a".to_string(),
                border: "#ffccbc".to_string(),
                accent: "#f1f5f9".to_string(),
                accent_primary: "#f97316".to_string(),
                accent_secondary: "#fb923c".to_string(),
            },
        },
        _ => crate::types::ThemeColorsResponse {
            dark: crate::types::ThemeColors {
                background: "#0a0a0f".to_string(),
                surface: "#12121a".to_string(),
                primary: "#e94560".to_string(),
                text: "#f0f0f5".to_string(),
                border: "#2a2a3a".to_string(),
                accent: "#1a1a24".to_string(),
                accent_primary: "#00d4aa".to_string(),
                accent_secondary: "#00b894".to_string(),
            },
            light: crate::types::ThemeColors {
                background: "#f8fafc".to_string(),
                surface: "#ffffff".to_string(),
                primary: "#c41e3a".to_string(),
                text: "#0f172a".to_string(),
                border: "#e2e8f0".to_string(),
                accent: "#f1f5f9".to_string(),
                accent_primary: "#059669".to_string(),
                accent_secondary: "#10b981".to_string(),
            },
        },
    }
}

fn generate_preview_html(
    _css: &str,
    colors: &crate::types::ThemeColorsResponse,
    use_light: bool,
) -> String {
    let c = if use_light {
        &colors.light
    } else {
        &colors.dark
    };
    format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: {bg};
            color: {text};
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .card {{
            background: {surface};
            border: 1px solid {border};
            border-radius: 12px;
            padding: 2rem;
            max-width: 400px;
            text-align: center;
        }}
        .status {{
            font-size: 4rem;
            font-weight: bold;
            color: {primary};
            margin-bottom: 1rem;
        }}
        h1 {{
            font-size: 1.5rem;
            margin-bottom: 0.5rem;
        }}
        p {{
            color: {text};
            opacity: 0.8;
        }}
        .footer {{
            margin-top: 1.5rem;
            font-size: 0.75rem;
            opacity: 0.5;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="status">403</div>
        <h1>Forbidden</h1>
        <p>Access to this resource has been blocked by the WAF.</p>
        <div class="footer">MaluWAF</div>
    </div>
</body>
</html>
"#,
        bg = c.background,
        surface = c.surface,
        text = c.text,
        border = c.border,
        primary = c.primary,
    )
}
