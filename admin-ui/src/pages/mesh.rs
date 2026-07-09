use crate::components::skeleton::LoadingSpinner;
use crate::services::ApiService;
use crate::types::{MeshAdminStatus, MeshConfig};
use serde_json::Value;
use yew::prelude::*;

#[function_component]
pub fn Mesh() -> Html {
    let mesh_status = use_state(|| None as Option<MeshAdminStatus>);
    let mesh_config = use_state(|| None as Option<Value>);
    let loading = use_state(|| true);
    let error = use_state(|| None as Option<String>);
    let saving = use_state(|| false);
    let save_success = use_state(|| None as Option<String>);
    let save_error = use_state(|| None as Option<String>);

    let edited_config = use_state(MeshConfig::default);

    let edited_config_for_save = edited_config.clone();
    let edited_config_for_render = edited_config.clone();

    let on_save = {
        let saving = saving.clone();
        let save_success = save_success.clone();
        let save_error = save_error.clone();
        let mesh_config = mesh_config.clone();
        let edited_config_value = edited_config_for_save.clone();
        let edited_config_inside = edited_config_for_save.clone();
        Callback::from(move |_| {
            saving.set(true);
            save_success.set(None);
            save_error.set(None);

            let mut updated_json = serde_json::Map::new();
            let cfg = (*edited_config_value).clone();

            if let Some(v) = &cfg.enabled {
                updated_json.insert("enabled".to_string(), serde_json::json!(v));
            }
            if let Some(v) = &cfg.node_id {
                updated_json.insert("node_id".to_string(), serde_json::json!(v));
            }
            if let Some(v) = &cfg.listen_port {
                updated_json.insert("port".to_string(), serde_json::json!(v));
            }
            if let Some(v) = &cfg.dht_enabled {
                updated_json.insert("dht".to_string(), serde_json::json!(v));
            }

            let saving = saving.clone();
            let save_success = save_success.clone();
            let save_error = save_error.clone();
            let mesh_config = mesh_config.clone();
            let edited_config = edited_config_inside.clone();

            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api
                    .update_mesh_config(&serde_json::Value::Object(updated_json))
                    .await
                {
                    Ok(_) => {
                        save_success
                            .set(Some("Mesh configuration saved successfully.".to_string()));
                        if let Some(config_json) = &*mesh_config {
                            if let Some(obj) = config_json.as_object() {
                                let mut config = MeshConfig::default();
                                if let Some(v) = obj.get("enabled").and_then(|v| v.as_bool()) {
                                    config.enabled = Some(v);
                                }
                                if let Some(v) = obj.get("node_id").and_then(|v| v.as_str()) {
                                    config.node_id = Some(v.to_string());
                                }
                                if let Some(v) = obj.get("port").and_then(|v| v.as_u64()) {
                                    config.listen_port = Some(v as u16);
                                }
                                if let Some(v) = obj.get("dht").and_then(|v| v.as_bool()) {
                                    config.dht_enabled = Some(v);
                                }

                                edited_config.set(config);
                            }
                        }
                    }
                    Err(e) => {
                        save_error.set(Some(format!("Failed to save: {}", e)));
                    }
                }
                saving.set(false);
            });
        })
    };

    let port_string = edited_config_for_render
        .listen_port
        .unwrap_or(0)
        .to_string();

    html! {
        <div class="space-y-6">
            <div class="flex justify-between items-center">
                <h1 class="text-2xl font-bold">{ "Mesh Configuration" }</h1>
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
                        <h2 class="text-lg font-semibold mb-4">{ "Mesh Status" }</h2>
                        if let Some(status) = &*mesh_status {
                            <div class="space-y-3">
                                <div class="flex justify-between">
                                    <span class="text-secondary">{ "Node Type" }</span>
                                    <span class={if status.is_global_node { "text-green-500 font-medium" } else { "text-yellow-500 font-medium" }}>
                                        { if status.is_global_node { "Global Node" } else { "Edge Node" } }
                                    </span>
                                </div>
                                <div class="flex justify-between">
                                    <span class="text-secondary">{ "Node ID" }</span>
                                    <span class="text-primary font-mono text-sm">
                                        { status.node_id.as_deref().unwrap_or("N/A") }
                                    </span>
                                </div>
                                <div class="flex justify-between">
                                    <span class="text-secondary">{ "Connected Peers" }</span>
                                    <span class="text-primary font-medium">{ status.connected_peers }</span>
                                </div>
                                <div class="flex justify-between">
                                    <span class="text-secondary">{ "Global Nodes" }</span>
                                    <span class="text-primary font-medium">{ status.global_nodes }</span>
                                </div>
                                <div class="flex justify-between">
                                    <span class="text-secondary">{ "Edge Nodes" }</span>
                                    <span class="text-primary font-medium">{ status.edge_nodes }</span>
                                </div>
                                <div class="border-t border-default pt-3 mt-3">
                                    <div class="flex justify-between">
                                        <span class="text-secondary">{ "Genesis Key" }</span>
                                        <span class={if status.genesis_key_configured { "text-green-500" } else { "text-red-500" }}>
                                            { if status.genesis_key_configured { "Configured" } else { "Not Configured" } }
                                        </span>
                                    </div>
                                    <div class="flex justify-between mt-2">
                                        <span class="text-secondary">{ "Signing Key" }</span>
                                        <span class={if status.signing_key_derived { "text-green-500" } else { "text-red-500" }}>
                                            { if status.signing_key_derived { "Derived" } else { "Not Derived" } }
                                        </span>
                                    </div>
                                    <div class="flex justify-between mt-2">
                                        <span class="text-secondary">{ "0-RTT QUIC" }</span>
                                        <span class={if status.quic_0rtt_enabled { "text-green-500" } else { "text-yellow-500" }}>
                                            { if status.quic_0rtt_enabled { "Enabled" } else { "Disabled" } }
                                        </span>
                                    </div>
                                    if let Some(warning) = &status.quic_0rtt_warning {
                                        <div class="mt-2 text-yellow-500 text-sm">
                                            { warning }
                                        </div>
                                    }
                                </div>
                            </div>
                        } else {
                            <p class="text-secondary">{ "Mesh status unavailable" }</p>
                        }
                    </div>

                    <div class="bg-secondary rounded-lg border border-default p-6">
                        <h2 class="text-lg font-semibold mb-4">{ "Basic Settings" }</h2>
                        <div class="space-y-4">
                            <div>
                                <label class="flex items-center gap-2 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked={edited_config.enabled.unwrap_or(false)}
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
                                    <span class="text-primary">{ "Enable Mesh" }</span>
                                </label>
                            </div>

                            <div>
                                <label class="block text-sm text-secondary mb-1">{ "Node ID" }</label>
                                <input
                                    type="text"
                                    value={edited_config.node_id.clone().unwrap_or_default()}
                                    oninput={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: InputEvent| {
                                            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                            let mut cfg = (*edited_config).clone();
                                            cfg.node_id = Some(input.value());
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    placeholder="Auto-generated if empty"
                                />
                            </div>

                            <div>
                                <label class="block text-sm text-secondary mb-1">{ "Listen Port" }</label>
                                <input
                                    type="number"
                                    value={port_string}
                                    oninput={{
                                        let edited_config = edited_config.clone();
                                        Callback::from(move |e: InputEvent| {
                                            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                            let mut cfg = (*edited_config).clone();
                                            cfg.listen_port = input.value().parse().ok();
                                            edited_config.set(cfg);
                                        })
                                    }}
                                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    placeholder="0 (auto)"
                                />
                            </div>

                            <div>
                                <label class="flex items-center gap-2 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked={edited_config.dht_enabled.unwrap_or(false)}
                                        onchange={{
                                            let edited_config = edited_config.clone();
                                            Callback::from(move |e: Event| {
                                                let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                                let mut cfg = (*edited_config).clone();
                                                cfg.dht_enabled = Some(input.checked());
                                                edited_config.set(cfg);
                                            })
                                        }}
                                        class="w-4 h-4 rounded border-default bg-tertiary accent-blue-600"
                                    />
                                    <span class="text-primary">{ "Enable DHT" }</span>
                                </label>
                            </div>



                            <div class="pt-4 border-t border-default">
                                <button
                                    onclick={on_save}
                                    disabled={*saving}
                                    class="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-600/50 text-white rounded-lg transition-colors"
                                >
                                    { if *saving { "Saving..." } else { "Save Configuration" } }
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="bg-secondary rounded-lg border border-default p-6">
                    <h2 class="text-lg font-semibold mb-4">{ "Current Configuration (JSON)" }</h2>
                    <pre class="bg-tertiary rounded-lg p-4 overflow-auto text-sm font-mono text-primary max-h-96">
                        { if let Some(config) = &*mesh_config {
                            serde_json::to_string_pretty(config).unwrap_or_else(|_| "{}".to_string())
                        } else {
                            "{}".to_string()
                        } }
                    </pre>
                </div>
            }
        </div>
    }
}
