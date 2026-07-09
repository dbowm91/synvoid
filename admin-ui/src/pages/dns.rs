use crate::components::skeleton::LoadingSpinner;
use crate::services::ApiService;
use crate::types::DnsConfig;
use serde_json::Value;
use yew::prelude::*;

#[function_component]
pub fn Dns() -> Html {
    let dns_config = use_state(|| None as Option<Value>);
    let loading = use_state(|| true);
    let error = use_state(|| None as Option<String>);
    let saving = use_state(|| false);
    let save_success = use_state(|| None as Option<String>);
    let save_error = use_state(|| None as Option<String>);

    let edited_config = use_state(DnsConfig::default);

    let edited_config_for_render = edited_config.clone();
    let edited_config_for_save = edited_config.clone();

    {
        let dns_config = dns_config.clone();
        let loading = loading.clone();
        let error = error.clone();
        let edited_config = edited_config.clone();
        use_effect_with((), move |_| {
            let dns_config = dns_config.clone();
            let loading = loading.clone();
            let error = error.clone();
            let edited_config = edited_config.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();

                match api.get_dns_config().await {
                    Ok(config_json) => {
                        dns_config.set(Some(config_json.clone()));
                        if let Some(obj) = config_json.as_object() {
                            let mut config = DnsConfig::default();
                            if let Some(v) = obj.get("enabled").and_then(|v| v.as_bool()) {
                                config.enabled = Some(v);
                            }
                            if let Some(v) = obj.get("port").and_then(|v| v.as_u64()) {
                                config.port = Some(v as u16);
                            }
                            if let Some(v) = obj.get("bind_addresses").and_then(|v| v.as_array()) {
                                let addrs: Vec<String> = v
                                    .iter()
                                    .filter_map(|a| a.as_str().map(String::from))
                                    .collect();
                                config.bind_addresses = Some(addrs);
                            }
                            if let Some(v) = obj.get("allow_recursive").and_then(|v| v.as_bool()) {
                                config.allow_recursive = Some(v);
                            }
                            if let Some(v) = obj.get("forwarders").and_then(|v| v.as_array()) {
                                let forwarders: Vec<String> = v
                                    .iter()
                                    .filter_map(|f| f.as_str().map(String::from))
                                    .collect();
                                config.forwarders = Some(forwarders);
                            }
                            if let Some(v) = obj.get("block_tld").and_then(|v| v.as_array()) {
                                let tlds: Vec<String> = v
                                    .iter()
                                    .filter_map(|t| t.as_str().map(String::from))
                                    .collect();
                                config.block_tld = Some(tlds);
                            }
                            if let Some(v) = obj.get("dnssec_enabled").and_then(|v| v.as_bool()) {
                                config.dnssec_enabled = Some(v);
                            }
                            if let Some(v) = obj.get("nxdomain_redirect").and_then(|v| v.as_str()) {
                                config.nxdomain_redirect = Some(v.to_string());
                            }
                            if let Some(v) = obj.get("rpz_enabled").and_then(|v| v.as_bool()) {
                                config.rpz_enabled = Some(v);
                            }
                            edited_config.set(config);
                        }
                    }
                    Err(e) => error.set(Some(format!("Failed to fetch DNS config: {}", e))),
                }

                loading.set(false);
            });
            || {}
        });
    }

    let on_save = {
        let saving = saving.clone();
        let save_success = save_success.clone();
        let save_error = save_error.clone();
        let dns_config = dns_config.clone();
        let edited_config_value = edited_config_for_save.clone();
        Callback::from(move |_| {
            saving.set(true);
            save_success.set(None);
            save_error.set(None);

            let cfg = (*edited_config_value).clone();
            let mut updated_json = serde_json::Map::new();

            if let Some(v) = &cfg.enabled {
                updated_json.insert("enabled".to_string(), serde_json::json!(v));
            }
            if let Some(v) = &cfg.port {
                updated_json.insert("port".to_string(), serde_json::json!(v));
            }
            if let Some(v) = &cfg.bind_addresses {
                updated_json.insert("bind_addresses".to_string(), serde_json::json!(v));
            }
            if let Some(v) = &cfg.allow_recursive {
                updated_json.insert("allow_recursive".to_string(), serde_json::json!(v));
            }
            if let Some(v) = &cfg.forwarders {
                updated_json.insert("forwarders".to_string(), serde_json::json!(v));
            }
            if let Some(v) = &cfg.block_tld {
                updated_json.insert("block_tld".to_string(), serde_json::json!(v));
            }
            if let Some(v) = &cfg.dnssec_enabled {
                updated_json.insert("dnssec_enabled".to_string(), serde_json::json!(v));
            }
            if let Some(v) = &cfg.nxdomain_redirect {
                updated_json.insert("nxdomain_redirect".to_string(), serde_json::json!(v));
            }
            if let Some(v) = &cfg.rpz_enabled {
                updated_json.insert("rpz_enabled".to_string(), serde_json::json!(v));
            }

            let saving = saving.clone();
            let save_success = save_success.clone();
            let save_error = save_error.clone();
            let _dns_config = dns_config.clone();

            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api
                    .update_dns_config(&serde_json::Value::Object(updated_json))
                    .await
                {
                    Ok(_) => {
                        save_success.set(Some("DNS configuration saved successfully.".to_string()));
                    }
                    Err(e) => {
                        save_error.set(Some(format!("Failed to save: {}", e)));
                    }
                }
                saving.set(false);
            });
        })
    };

    let forwarders_string = edited_config_for_render
        .forwarders
        .clone()
        .map(|f| f.join("\n"))
        .unwrap_or_default();
    let block_tld_string = edited_config_for_render
        .block_tld
        .clone()
        .map(|t| t.join(", "))
        .unwrap_or_default();
    let port_string = edited_config_for_render.port.unwrap_or(53).to_string();

    html! {
            <div class="space-y-6">
                <div class="flex justify-between items-center">
                    <h1 class="text-2xl font-bold">{ "DNS Configuration" }</h1>
                </div>

                if let Some(err) = &*error {
                    <div class="bg-red-500/10 border border-red-500 rounded-lg p-4 text-red-500">
                        { err }
                    </div>
                }

                if let Some(msg) = &*save_success {
                    <div class="bg-green-500/10 border border-green-500 rounded-lg p-4 text-green-500">
                        { msg }
                    </div>
                }

                if let Some(msg) = &*save_error {
                    <div class="bg-red-500/10 border border-red-500 rounded-lg p-4 text-red-500">
                        { msg }
                    </div>
                }

                if *loading {
                    <LoadingSpinner />
                } else {
                    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <div class="bg-secondary rounded-lg border border-default p-6">
                            <h2 class="text-lg font-semibold mb-4">{ "Basic Settings" }</h2>
                            <div class="space-y-4">
                                <div>
                                    <label class="flex items-center gap-2 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            checked={edited_config_for_render.enabled.unwrap_or(false)}
                                            onchange={{
                                                let edited_config = edited_config.clone();
                                                Callback::from(move |e: Event| {
                                                    let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                                    let mut cfg = (*edited_config).clone();
                                                    cfg.enabled = Some(input.checked());
                                                    edited_config.set(cfg);
                                                })
                                            }}
                                            class="w-4 h-4 rounded border-default bg-tertiary accent-blue-600"
                                        />
                                        <span class="text-primary">{ "Enable DNS Server" }</span>
                                    </label>
                                </div>

    <div>
                                    <label class="block text-sm text-secondary mb-1">{ "Port" }</label>
                                    <input
                                        type="number"
                                        value={port_string}
                                        oninput={{
                                            let edited_config = edited_config.clone();
                                            Callback::from(move |e: InputEvent| {
                                                let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                                let mut cfg = (*edited_config).clone();
                                                cfg.port = input.value().parse().ok();
                                                edited_config.set(cfg);
                                            })
                                        }}
                                        class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    />
                                </div>

                                <div>
                                    <label class="flex items-center gap-2 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            checked={edited_config_for_render.allow_recursive.unwrap_or(false)}
                                            onchange={{
                                                let edited_config = edited_config.clone();
                                                Callback::from(move |e: Event| {
                                                    let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                                    let mut cfg = (*edited_config).clone();
                                                    cfg.allow_recursive = Some(input.checked());
                                                    edited_config.set(cfg);
                                                })
                                            }}
                                            class="w-4 h-4 rounded border-default bg-tertiary accent-blue-600"
                                        />
                                        <span class="text-primary">{ "Allow Recursive Queries" }</span>
                                    </label>
                                </div>

                                <div>
                                    <label class="flex items-center gap-2 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            checked={edited_config_for_render.dnssec_enabled.unwrap_or(false)}
                                            onchange={{
                                                let edited_config = edited_config.clone();
                                                Callback::from(move |e: Event| {
                                                    let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                                    let mut cfg = (*edited_config).clone();
                                                    cfg.dnssec_enabled = Some(input.checked());
                                                    edited_config.set(cfg);
                                                })
                                            }}
                                            class="w-4 h-4 rounded border-default bg-tertiary accent-blue-600"
                                        />
                                        <span class="text-primary">{ "Enable DNSSEC" }</span>
                                    </label>
                                </div>

                                <div>
                                    <label class="flex items-center gap-2 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            checked={edited_config_for_render.rpz_enabled.unwrap_or(false)}
                                            onchange={{
                                                let edited_config = edited_config.clone();
                                                Callback::from(move |e: Event| {
                                                    let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                                    let mut cfg = (*edited_config).clone();
                                                    cfg.rpz_enabled = Some(input.checked());
                                                    edited_config.set(cfg);
                                                })
                                            }}
                                            class="w-4 h-4 rounded border-default bg-tertiary accent-blue-600"
                                        />
                                        <span class="text-primary">{ "Enable RPZ (Response Policy Zones)" }</span>
                                    </label>
                                </div>
                            </div>
                        </div>

                        <div class="bg-secondary rounded-lg border border-default p-6">
                            <h2 class="text-lg font-semibold mb-4">{ "Forwarding & Blocking" }</h2>
                            <div class="space-y-4">
                                <div>
                                    <label class="block text-sm text-secondary mb-1">{ "DNS Forwarders (one per line)" }</label>
                                    <textarea
                                        class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary font-mono text-sm"
                                        rows="4"
                                        placeholder="8.8.8.8&#10;1.1.1.1"
                                        value={forwarders_string}
                                        oninput={{
                                            let edited_config = edited_config.clone();
                                            Callback::from(move |e: InputEvent| {
                                                let input = e.target_unchecked_into::<web_sys::HtmlTextAreaElement>();
                                                let forwarders: Vec<String> = input.value()
                                                    .split('\n')
                                                    .map(|s| s.trim().to_string())
                                                    .filter(|s| !s.is_empty())
                                                    .collect();
                                                let mut cfg = (*edited_config).clone();
                                                cfg.forwarders = Some(forwarders);
                                                edited_config.set(cfg);
                                            })
                                        }}
                                    />
                                    <p class="mt-1 text-xs text-secondary">{ "Upstream DNS servers to forward queries to" }</p>
                                </div>

                                <div>
                                    <label class="block text-sm text-secondary mb-1">{ "Blocked TLDs (comma-separated)" }</label>
                                    <input
                                        type="text"
                                        placeholder=".onion, .test"
                                        value={block_tld_string}
                                        oninput={{
                                            let edited_config = edited_config.clone();
                                            Callback::from(move |e: InputEvent| {
                                                let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                                let tlds: Vec<String> = input.value()
                                                    .split(',')
                                                    .map(|s| s.trim().to_string())
                                                    .filter(|s| !s.is_empty())
                                                    .collect();
                                                let mut cfg = (*edited_config).clone();
                                                cfg.block_tld = Some(tlds);
                                                edited_config.set(cfg);
                                            })
                                        }}
                                        class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    />
                                    <p class="mt-1 text-xs text-secondary">{ "Block queries for these top-level domains" }</p>
                                </div>

                                <div>
                                    <label class="block text-sm text-secondary mb-1">{ "NXDOMAIN Redirect" }</label>
                                    <input
                                        type="text"
                                        placeholder="http://blocked.local"
                                        value={edited_config_for_render.nxdomain_redirect.clone().unwrap_or_default()}
                                        oninput={{
                                            let edited_config = edited_config.clone();
                                            Callback::from(move |e: InputEvent| {
                                                let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                                let mut cfg = (*edited_config).clone();
                                                cfg.nxdomain_redirect = Some(input.value());
                                                edited_config.set(cfg);
                                            })
                                        }}
                                        class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    />
                                    <p class="mt-1 text-xs text-secondary">{ "Redirect blocked domains to this URL" }</p>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="bg-secondary rounded-lg border border-default p-6">
                        <h2 class="text-lg font-semibold mb-4">{ "Current Configuration (JSON)" }</h2>
                        <pre class="bg-tertiary rounded-lg p-4 overflow-auto text-sm font-mono text-primary max-h-96">
                            { if let Some(config) = &*dns_config {
                                serde_json::to_string_pretty(config).unwrap_or_else(|_| "{}".to_string())
                            } else {
                                "{}".to_string()
                            } }
                        </pre>
                    </div>

                    <div class="flex justify-end">
                        <button
                            onclick={on_save}
                            disabled={*saving}
                            class="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-600/50 text-white rounded-lg transition-colors"
                        >
                            { if *saving { "Saving..." } else { "Save Configuration" } }
                        </button>
                    </div>
                }
            </div>
        }
}
