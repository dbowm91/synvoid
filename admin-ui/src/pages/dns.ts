use crate::components::skeleton::LoadingSpinner;
use crate::services::ApiService;
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

    let edited_config = use_state(|| serde_json::Map::new());

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
                            edited_config.set(obj.clone());
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
        let edited_config_value = edited_config_for_save.clone();

        Callback::from(move |_| {
            saving.set(true);
            save_success.set(None);
            save_error.set(None);

            let cfg = (*edited_config_value).clone();
            let updated_json = serde_json::Value::Object(cfg);

            let saving = saving.clone();
            let save_success = save_success.clone();
            let save_error = save_error.clone();

            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.update_dns_config(&updated_json).await {
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

    let get_bool = |cfg: &serde_json::Map<String, Value>, key: &str, default: bool| -> bool {
        cfg.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
    };

    let get_string = |cfg: &serde_json::Map<String, Value>, key: &str| -> String {
        cfg.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
    };

    let get_u16 = |cfg: &serde_json::Map<String, Value>, key: &str, default: u16| -> u16 {
        cfg.get(key).and_then(|v| v.as_u64()).map(|v| v as u16).unwrap_or(default)
    };

    let get_array_string = |cfg: &serde_json::Map<String, Value>, key: &str| -> Vec<String> {
        cfg.get(key).and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default()
    };

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
                let cfg = (*edited_config_for_render).clone();

                <div class="space-y-4">
                    <details class="bg-secondary rounded-lg border border-default">
                        <summary class="p-4 cursor-pointer font-semibold">{ "Basic Settings" }</summary>
                        <div class="p-4 space-y-4">
                            <div class="flex items-center gap-2">
                                <input
                                    type="checkbox"
                                    id="enabled"
                                    checked={get_bool(&cfg, "enabled", false)}
                                    onchange={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: Event| {
                                            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                            let mut cfg = (*edited_config).clone();
                                            cfg.insert("enabled".to_string(), serde_json::json!(input.checked()));
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-4 h-4 rounded border-default bg-tertiary accent-blue-600"
                                />
                                <label for="enabled" class="text-primary">{ "Enable DNS Server" }</label>
                            </div>

                            <div>
                                <label class="block text-sm text-secondary mb-1">{ "Port" }</label>
                                <input
                                    type="number"
                                    id="port"
                                    value={get_u16(&cfg, "port", 53).to_string()}
                                    oninput={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: InputEvent| {
                                            let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                            let mut cfg = (*edited_config).clone();
                                            if let Ok(v) = input.value().parse() {
                                                cfg.insert("port".to_string(), serde_json::json!(v));
                                            }
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                                />
                            </div>

                            <div>
                                <label class="block text-sm text-secondary mb-1">{ "Bind Address" }</label>
                                <input
                                    type="text"
                                    id="bind_address"
                                    value={get_string(&cfg, "bind_address")}
                                    oninput={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: InputEvent| {
                                            let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                            let mut cfg = (*edited_config).clone();
                                            cfg.insert("bind_address".to_string(), serde_json::json!(input.value()));
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                                />
                            </div>

                            <div>
                                <label class="block text-sm text-secondary mb-1">{ "Mode" }</label>
                                <select
                                    id="mode"
                                    value={get_string(&cfg, "mode")}
                                    onchange={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: Event| {
                                            let input: web_sys::HtmlSelectElement = e.target_unchecked_into();
                                            let mut cfg = (*edited_config).clone();
                                            cfg.insert("mode".to_string(), serde_json::json!(input.value()));
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                                >
                                    <option value="standalone">{ "Standalone" }</option>
                                    <option value="mesh">{ "Mesh" }</option>
                                </select>
                            </div>
                        </div>
                    </details>

                    <details class="bg-secondary rounded-lg border border-default">
                        <summary class="p-4 cursor-pointer font-semibold">{ "Recursive DNS" }</summary>
                        <div class="p-4 space-y-4">
                            <div class="flex items-center gap-2">
                                <input
                                    type="checkbox"
                                    id="allow_recursive"
                                    checked={get_bool(&cfg, "allow_recursive", false)}
                                    onchange={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: Event| {
                                            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                            let mut cfg = (*edited_config).clone();
                                            cfg.insert("allow_recursive".to_string(), serde_json::json!(input.checked()));
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-4 h-4 rounded border-default bg-tertiary accent-blue-600"
                                />
                                <label for="allow_recursive" class="text-primary">{ "Allow Recursive Queries" }</label>
                            </div>

                            <div>
                                <label class="block text-sm text-secondary mb-1">{ "Recursive Bind Address" }</label>
                                <input
                                    type="text"
                                    placeholder="0.0.0.0"
                                    oninput={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: InputEvent| {
                                            let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                            let mut cfg = (*edited_config).clone();
                                            let mut recursive = cfg.get("recursive").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                            recursive.insert("bind_address".to_string(), serde_json::json!(input.value()));
                                            cfg.insert("recursive".to_string(), serde_json::json!(recursive));
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                                />
                            </div>
                        </div>
                    </details>

                    <details class="bg-secondary rounded-lg border border-default">
                        <summary class="p-4 cursor-pointer font-semibold">{ "Forwarding & Blocking" }</summary>
                        <div class="p-4 space-y-4">
                            <div>
                                <label class="block text-sm text-secondary mb-1">{ "DNS Forwarders (one per line)" }</label>
                                <textarea
                                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary font-mono text-sm"
                                    rows="4"
                                    placeholder="8.8.8.8&#10;1.1.1.1"
                                    value={get_array_string(&cfg, "forwarders").join("\n")}
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
                                            cfg.insert("forwarders".to_string(), serde_json::json!(forwarders));
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
                                    value={get_array_string(&cfg, "block_tld").join(", ")}
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
                                            cfg.insert("block_tld".to_string(), serde_json::json!(tlds));
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                                />
                            </div>

                            <div>
                                <label class="block text-sm text-secondary mb-1">{ "NXDOMAIN Redirect" }</label>
                                <input
                                    type="text"
                                    placeholder="http://blocked.local"
                                    value={get_string(&cfg, "nxdomain_redirect")}
                                    oninput={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: InputEvent| {
                                            let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                            let mut cfg = (*edited_config).clone();
                                            cfg.insert("nxdomain_redirect".to_string(), serde_json::json!(input.value()));
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                                />
                            </div>
                        </div>
                    </details>

                    <details class="bg-secondary rounded-lg border border-default">
                        <summary class="p-4 cursor-pointer font-semibold">{ "Rate Limiting & RRL" }</summary>
                        <div class="p-4 space-y-4">
                            <div>
                                <label class="block text-sm text-secondary mb-1">{ "Rate Limit Mode" }</label>
                                <select
                                    onchange={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: Event| {
                                            let input: web_sys::HtmlSelectElement = e.target_unchecked_into();
                                            let mut cfg = (*edited_config).clone();
                                            let mut ratelimit = cfg.get("ratelimit").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                            ratelimit.insert("mode".to_string(), serde_json::json!(input.value()));
                                            cfg.insert("ratelimit".to_string(), serde_json::json!(ratelimit));
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                                >
                                    <option value="shared">{ "Shared" }</option>
                                    <option value="dedicated">{ "Dedicated" }</option>
                                </select>
                            </div>

                            <div class="flex items-center gap-2">
                                <input
                                    type="checkbox"
                                    id="rrl_enabled"
                                    onchange={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: Event| {
                                            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                            let mut cfg = (*edited_config).clone();
                                            let mut rrl = cfg.get("rrl").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                            rrl.insert("enabled".to_string(), serde_json::json!(input.checked()));
                                            cfg.insert("rrl".to_string(), serde_json::json!(rrl));
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-4 h-4 rounded border-default bg-tertiary accent-blue-600"
                                />
                                <label for="rrl_enabled" class="text-primary">{ "Enable Response Rate Limiting" }</label>
                            </div>
                        </div>
                    </details>

                    <details class="bg-secondary rounded-lg border border-default">
                        <summary class="p-4 cursor-pointer font-semibold">{ "DNSSEC" }</summary>
                        <div class="p-4 space-y-4">
                            <div class="flex items-center gap-2">
                                <input
                                    type="checkbox"
                                    id="dnssec_enabled"
                                    checked={get_bool(&cfg, "dnssec_enabled", false)}
                                    onchange={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: Event| {
                                            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                            let mut cfg = (*edited_config).clone();
                                            cfg.insert("dnssec_enabled".to_string(), serde_json::json!(input.checked()));
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-4 h-4 rounded border-default bg-tertiary accent-blue-600"
                                />
                                <label for="dnssec_enabled" class="text-primary">{ "Enable DNSSEC" }</label>
                            </div>
                        </div>
                    </details>

                    <details class="bg-secondary rounded-lg border border-default">
                        <summary class="p-4 cursor-pointer font-semibold">{ "RPZ (Response Policy Zones)" }</summary>
                        <div class="p-4 space-y-4">
                            <div class="flex items-center gap-2">
                                <input
                                    type="checkbox"
                                    id="rpz_enabled"
                                    checked={get_bool(&cfg, "rpz_enabled", false)}
                                    onchange={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: Event| {
                                            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                            let mut cfg = (*edited_config).clone();
                                            cfg.insert("rpz_enabled".to_string(), serde_json::json!(input.checked()));
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-4 h-4 rounded border-default bg-tertiary accent-blue-600"
                                />
                                <label for="rpz_enabled" class="text-primary">{ "Enable RPZ" }</label>
                            </div>
                        </div>
                    </details>

                    <details class="bg-secondary rounded-lg border border-default">
                        <summary class="p-4 cursor-pointer font-semibold">{ "DNS Firewall" }</summary>
                        <div class="p-4 space-y-4">
                            <div class="flex items-center gap-2">
                                <input
                                    type="checkbox"
                                    onchange={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: Event| {
                                            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                            let mut cfg = (*edited_config).clone();
                                            let mut firewall = cfg.get("firewall").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                            firewall.insert("enabled".to_string(), serde_json::json!(input.checked()));
                                            cfg.insert("firewall".to_string(), serde_json::json!(firewall));
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-4 h-4 rounded border-default bg-tertiary accent-blue-600"
                                />
                                <label class="text-primary">{ "Enable DNS Firewall" }</label>
                            </div>
                        </div>
                    </details>

                    <details class="bg-secondary rounded-lg border border-default">
                        <summary class="p-4 cursor-pointer font-semibold">{ "Mesh DNS" }</summary>
                        <div class="p-4 space-y-4">
                            <div class="flex items-center gap-2">
                                <input
                                    type="checkbox"
                                    onchange={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: Event| {
                                            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                            let mut cfg = (*edited_config).clone();
                                            let mut mesh = cfg.get("mesh").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                            mesh.insert("enabled".to_string(), serde_json::json!(input.checked()));
                                            cfg.insert("mesh".to_string(), serde_json::json!(mesh));
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-4 h-4 rounded border-default bg-tertiary accent-blue-600"
                                />
                                <label class="text-primary">{ "Enable Mesh DNS" }</label>
                            </div>
                        </div>
                    </details>

                    <details class="bg-secondary rounded-lg border border-default">
                        <summary class="p-4 cursor-pointer font-semibold">{ "Zones" }</summary>
                        <div class="p-4 space-y-4">
                            <div>
                                <label class="block text-sm text-secondary mb-1">{ "Zone Files (JSON)" }</label>
                                <textarea
                                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary font-mono text-sm"
                                    rows="4"
                                    oninput={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: InputEvent| {
                                            let input = e.target_unchecked_into::<web_sys::HtmlTextAreaElement>();
                                            let mut cfg = (*edited_config).clone();
                                            let mut zones = cfg.get("zones").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                            zones.insert("files".to_string(), serde_json::json!(input.value()));
                                            cfg.insert("zones".to_string(), serde_json::json!(zones));
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    placeholder="[]"
                                />
                            </div>
                        </div>
                    </details>

                    <details class="bg-secondary rounded-lg border border-default">
                        <summary class="p-4 cursor-pointer font-semibold">{ "Limits" }</summary>
                        <div class="p-4 space-y-4">
                            <div>
                                <label class="block text-sm text-secondary mb-1">{ "Max Query Size (bytes)" }</label>
                                <input
                                    type="number"
                                    oninput={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: InputEvent| {
                                            let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                            let mut cfg = (*edited_config).clone();
                                            let mut limits = cfg.get("limits").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                            if let Ok(v) = input.value().parse() {
                                                limits.insert("max_query_size".to_string(), serde_json::json!(v));
                                            }
                                            cfg.insert("limits".to_string(), serde_json::json!(limits));
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                                />
                            </div>
                        </div>
                    </details>

                    <details class="bg-secondary rounded-lg border border-default">
                        <summary class="p-4 cursor-pointer font-semibold">{ "DNS64" }</summary>
                        <div class="p-4 space-y-4">
                            <div class="flex items-center gap-2">
                                <input
                                    type="checkbox"
                                    onchange={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: Event| {
                                            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                            let mut cfg = (*edited_config).clone();
                                            let mut dns64 = cfg.get("dns64").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                            dns64.insert("enabled".to_string(), serde_json::json!(input.checked()));
                                            cfg.insert("dns64".to_string(), serde_json::json!(dns64));
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-4 h-4 rounded border-default bg-tertiary accent-blue-600"
                                />
                                <label class="text-primary">{ "Enable DNS64" }</label>
                            </div>
                        </div>
                    </details>

                    <details class="bg-secondary rounded-lg border border-default">
                        <summary class="p-4 cursor-pointer font-semibold">{ "Prefetch" }</summary>
                        <div class="p-4 space-y-4">
                            <div class="flex items-center gap-2">
                                <input
                                    type="checkbox"
                                    onchange={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: Event| {
                                            let input = web_sys::HtmlInputElement::from(e.target_unchecked_into());
                                            let mut cfg = (*edited_config).clone();
                                            let mut prefetch = cfg.get("prefetch").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                            prefetch.insert("enabled".to_string(), serde_json::json!(input.checked()));
                                            cfg.insert("prefetch".to_string(), serde_json::json!(prefetch));
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-4 h-4 rounded border-default bg-tertiary accent-blue-600"
                                />
                                <label class="text-primary">{ "Enable Prefetch" }</label>
                            </div>
                        </div>
                    </details>

                    <details class="bg-secondary rounded-lg border border-default">
                        <summary class="p-4 cursor-pointer font-semibold">{ "Trust Anchors" }</summary>
                        <div class="p-4 space-y-4">
                            <div>
                                <label class="block text-sm text-secondary mb-1">{ "Trust Anchor Keys (JSON)" }</label>
                                <textarea
                                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary font-mono text-sm"
                                    rows="4"
                                    placeholder="[]"
                                    oninput={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: InputEvent| {
                                            let input = e.target_unchecked_into::<web_sys::HtmlTextAreaElement>();
                                            let mut cfg = (*edited_config).clone();
                                            let mut trust_anchors = cfg.get("trust_anchors").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                            trust_anchors.insert("keys".to_string(), serde_json::json!(input.value()));
                                            cfg.insert("trust_anchors".to_string(), serde_json::json!(trust_anchors));
                                            edited_config.set(cfg);
                                        })
                                    }}
                                />
                            </div>
                        </div>
                    </details>

                    <details class="bg-secondary rounded-lg border border-default">
                        <summary class="p-4 cursor-pointer font-semibold">{ "Anycast" }</summary>
                        <div class="p-4 space-y-4">
                            <div class="flex items-center gap-2">
                                <input
                                    type="checkbox"
                                    onchange={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: Event| {
                                            let input = web_sys::HtmlInputElement::from(e.target_unchecked_into());
                                            let mut cfg = (*edited_config).clone();
                                            let mut anycast = cfg.get("anycast").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                            anycast.insert("enabled".to_string(), serde_json::json!(input.checked()));
                                            cfg.insert("anycast".to_string(), serde_json::json!(anycast));
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-4 h-4 rounded border-default bg-tertiary accent-blue-600"
                                />
                                <label class="text-primary">{ "Enable Anycast" }</label>
                            </div>
                            <div>
                                <label class="block text-sm text-secondary mb-1">{ "Bind Addresses" }</label>
                                <input
                                    type="text"
                                    placeholder="192.168.1.1, 192.168.1.2"
                                    oninput={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: InputEvent| {
                                            let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                            let addrs: Vec<String> = input.value()
                                                .split(',')
                                                .map(|s| s.trim().to_string())
                                                .filter(|s| !s.is_empty())
                                                .collect();
                                            let mut cfg = (*edited_config).clone();
                                            let mut anycast = cfg.get("anycast").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                            anycast.insert("bind_addresses".to_string(), serde_json::json!(addrs));
                                            cfg.insert("anycast".to_string(), serde_json::json!(anycast));
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                                />
                            </div>
                        </div>
                    </details>

                    <details class="bg-secondary rounded-lg border border-default">
                        <summary class="p-4 cursor-pointer font-semibold">{ "Encrypted DNS (DoT/DoH/DoQ)" }</summary>
                        <div class="p-4 space-y-4">
                            <details class="bg-tertiary rounded-lg p-4 mb-4">
                                <summary class="cursor-pointer font-medium">{ "DoT (DNS over TLS)" }</summary>
                                <div class="mt-4 space-y-4">
                                    <div class="flex items-center gap-2">
                                        <input
                                            type="checkbox"
                                            onchange={{
                                                let edited_config = edited_config.clone();
                                                Callback::from(move |e: Event| {
                                                    let input = web_sys::HtmlInputElement::from(e.target_unchecked_into());
                                                    let mut cfg = (*edited_config).clone();
                                                    let mut dot = cfg.get("dot").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                                    dot.insert("enabled".to_string(), serde_json::json!(input.checked()));
                                                    cfg.insert("dot".to_string(), serde_json::json!(dot));
                                                    edited_config.set(cfg);
                                                })
                                            }}
                                            class="w-4 h-4 rounded border-default bg-tertiary accent-blue-600"
                                        />
                                        <label class="text-primary">{ "Enable DoT" }</label>
                                    </div>
                                    <div>
                                        <label class="block text-sm text-secondary mb-1">{ "DoT Bind Address" }</label>
                                        <input
                                            type="text"
                                            placeholder="0.0.0.0"
                                            oninput={{
                                                let edited_config = edited_config.clone();
                                                Callback::from(move |e: InputEvent| {
                                                    let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                                    let mut cfg = (*edited_config).clone();
                                                    let mut dot = cfg.get("dot").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                                    dot.insert("bind_address".to_string(), serde_json::json!(input.value()));
                                                    cfg.insert("dot".to_string(), serde_json::json!(dot));
                                                    edited_config.set(cfg);
                                                })
                                            }}
                                            class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                                        />
                                    </div>
                                    <div>
                                        <label class="block text-sm text-secondary mb-1">{ "DoT Port" }</label>
                                        <input
                                            type="number"
                                            placeholder="853"
                                            oninput={{
                                                let edited_config = edited_config.clone();
                                                Callback::from(move |e: InputEvent| {
                                                    let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                                    let mut cfg = (*edited_config).clone();
                                                    let mut dot = cfg.get("dot").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                                    if let Ok(v) = input.value().parse() {
                                                        dot.insert("port".to_string(), serde_json::json!(v));
                                                    }
                                                    cfg.insert("dot".to_string(), serde_json::json!(dot));
                                                    edited_config.set(cfg);
                                                })
                                            }}
                                            class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                                        />
                                    </div>
                                </div>
                            </details>

                            <details class="bg-tertiary rounded-lg p-4 mb-4">
                                <summary class="cursor-pointer font-medium">{ "DoH (DNS over HTTPS)" }</summary>
                                <div class="mt-4 space-y-4">
                                    <div class="flex items-center gap-2">
                                        <input
                                            type="checkbox"
                                            onchange={{
                                                let edited_config = edited_config.clone();
                                                Callback::from(move |e: Event| {
                                                    let input = web_sys::HtmlInputElement::from(e.target_unchecked_into());
                                                    let mut cfg = (*edited_config).clone();
                                                    let mut doh = cfg.get("doh").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                                    doh.insert("enabled".to_string(), serde_json::json!(input.checked()));
                                                    cfg.insert("doh".to_string(), serde_json::json!(doh));
                                                    edited_config.set(cfg);
                                                })
                                            }}
                                            class="w-4 h-4 rounded border-default bg-tertiary accent-blue-600"
                                        />
                                        <label class="text-primary">{ "Enable DoH" }</label>
                                    </div>
                                    <div>
                                        <label class="block text-sm text-secondary mb-1">{ "DoH Bind Address" }</label>
                                        <input
                                            type="text"
                                            placeholder="0.0.0.0"
                                            oninput={{
                                                let edited_config = edited_config.clone();
                                                Callback::from(move |e: InputEvent| {
                                                    let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                                    let mut cfg = (*edited_config).clone();
                                                    let mut doh = cfg.get("doh").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                                    doh.insert("bind_address".to_string(), serde_json::json!(input.value()));
                                                    cfg.insert("doh".to_string(), serde_json::json!(doh));
                                                    edited_config.set(cfg);
                                                })
                                            }}
                                            class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                                        />
                                    </div>
                                    <div>
                                        <label class="block text-sm text-secondary mb-1">{ "DoH Port" }</label>
                                        <input
                                            type="number"
                                            placeholder="443"
                                            oninput={{
                                                let edited_config = edited_config.clone();
                                                Callback::from(move |e: InputEvent| {
                                                    let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                                    let mut cfg = (*edited_config).clone();
                                                    let mut doh = cfg.get("doh").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                                    if let Ok(v) = input.value().parse() {
                                                        doh.insert("port".to_string(), serde_json::json!(v));
                                                    }
                                                    cfg.insert("doh".to_string(), serde_json::json!(doh));
                                                    edited_config.set(cfg);
                                                })
                                            }}
                                            class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                                        />
                                    </div>
                                </div>
                            </details>

                            <details class="bg-tertiary rounded-lg p-4">
                                <summary class="cursor-pointer font-medium">{ "DoQ (DNS over QUIC)" }</summary>
                                <div class="mt-4 space-y-4">
                                    <div class="flex items-center gap-2">
                                        <input
                                            type="checkbox"
                                            onchange={{
                                                let edited_config = edited_config.clone();
                                                Callback::from(move |e: Event| {
                                                    let input = web_sys::HtmlInputElement::from(e.target_unchecked_into());
                                                    let mut cfg = (*edited_config).clone();
                                                    let mut doq = cfg.get("doq").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                                    doq.insert("enabled".to_string(), serde_json::json!(input.checked()));
                                                    cfg.insert("doq".to_string(), serde_json::json!(doq));
                                                    edited_config.set(cfg);
                                                })
                                            }}
                                            class="w-4 h-4 rounded border-default bg-tertiary accent-blue-600"
                                        />
                                        <label class="text-primary">{ "Enable DoQ" }</label>
                                    </div>
                                    <div>
                                        <label class="block text-sm text-secondary mb-1">{ "DoQ Bind Address" }</label>
                                        <input
                                            type="text"
                                            placeholder="0.0.0.0"
                                            oninput={{
                                                let edited_config = edited_config.clone();
                                                Callback::from(move |e: InputEvent| {
                                                    let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                                    let mut cfg = (*edited_config).clone();
                                                    let mut doq = cfg.get("doq").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                                    doq.insert("bind_address".to_string(), serde_json::json!(input.value()));
                                                    cfg.insert("doq".to_string(), serde_json::json!(doq));
                                                    edited_config.set(cfg);
                                                })
                                            }}
                                            class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                                        />
                                    </div>
                                    <div>
                                        <label class="block text-sm text-secondary mb-1">{ "DoQ Port" }</label>
                                        <input
                                            type="number"
                                            placeholder="853"
                                            oninput={{
                                                let edited_config = edited_config.clone();
                                                Callback::from(move |e: InputEvent| {
                                                    let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                                    let mut cfg = (*edited_config).clone();
                                                    let mut doq = cfg.get("doq").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                                    if let Ok(v) = input.value().parse() {
                                                        doq.insert("port".to_string(), serde_json::json!(v));
                                                    }
                                                    cfg.insert("doq".to_string(), serde_json::json!(doq));
                                                    edited_config.set(cfg);
                                                })
                                            }}
                                            class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                                        />
                                    </div>
                                </div>
                            </details>
                        </div>
                    </details>

                    <details class="bg-secondary rounded-lg border border-default">
                        <summary class="p-4 cursor-pointer font-semibold">{ "Settings" }</summary>
                        <div class="p-4 space-y-4">
                            <div>
                                <label class="block text-sm text-secondary mb-1">{ "Cache Size" }</label>
                                <input
                                    type="number"
                                    oninput={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: InputEvent| {
                                            let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                            let mut cfg = (*edited_config).clone();
                                            let mut settings = cfg.get("settings").and_then(|v| v.as_obj().cloned()).unwrap_or_default();
                                            if let Ok(v) = input.value().parse() {
                                                settings.insert("cache_size".to_string(), serde_json::json!(v));
                                            }
                                            cfg.insert("settings".to_string(), serde_json::json!(settings));
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                                />
                            </div>
                        </div>
                    </details>

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
                </div>

                <div class="flex justify-end mt-6">
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