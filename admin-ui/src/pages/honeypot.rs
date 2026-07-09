use crate::services::api::ApiService;
use serde::{Deserialize, Serialize};
use yew::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotStatus {
    pub enabled: bool,
    pub running: bool,
    pub ports: Option<Vec<u16>>,
    pub last_connection: Option<u64>,
    pub connections_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotConnection {
    pub source_ip: String,
    pub port: u16,
    pub timestamp: u64,
    pub request_path: Option<String>,
}

#[function_component]
pub fn Honeypot() -> Html {
    let status = use_state(|| None as Option<HoneypotStatus>);
    let connections = use_state(Vec::<HoneypotConnection>::new);
    let error = use_state(|| None as Option<String>);
    let loading = use_state(|| false);

    {
        let status = status.clone();
        let connections = connections.clone();
        let error = error.clone();

        use_effect_with((), move |_| {
            let status = status.clone();
            let _connections = connections.clone();
            let error = error.clone();

            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();

                match api.get_honeypot_status().await {
                    Ok(value) => {
                        if let Ok(enabled) =
                            value.get("enabled").and_then(|v| v.as_bool()).ok_or(())
                        {
                            let running = value
                                .get("running")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            let ports = value.get("ports").and_then(|v| v.as_array()).map(|arr| {
                                arr.iter()
                                    .filter_map(|p| p.as_u64().map(|n| n as u16))
                                    .collect()
                            });
                            let connections_count = value
                                .get("connections_count")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);
                            let last_connection =
                                value.get("last_connection").and_then(|v| v.as_u64());

                            status.set(Some(HoneypotStatus {
                                enabled,
                                running,
                                ports,
                                last_connection,
                                connections_count,
                            }));
                        }
                    }
                    Err(e) => error.set(Some(e)),
                }
            });
        });
    }

    let on_enable = {
        let loading = loading.clone();
        let status = status.clone();

        Callback::from(move |_| {
            let status = status.clone();
            let loading = loading.clone();
            loading.set(true);

            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                if api.control_honeypot("enable").await.is_ok() {
                    if let Some(mut s) = (*status).clone() {
                        s.enabled = true;
                        s.running = true;
                        status.set(Some(s));
                    }
                }
                loading.set(false);
            });
        })
    };

    let on_disable = {
        let status = status.clone();

        Callback::from(move |_| {
            let status = status.clone();

            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                if api.control_honeypot("disable").await.is_ok() {
                    if let Some(mut s) = (*status).clone() {
                        s.enabled = false;
                        s.running = false;
                        status.set(Some(s));
                    }
                }
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div class="flex justify-between items-center">
                <h1 class="text-2xl font-bold">{ "Port Honeypot" }</h1>
            </div>

            if let Some(err) = &*error {
                <div class="bg-red-500/10 border border-red-500 rounded-lg p-4 text-red-500">
                    { err }
                </div>
            }

            if let Some(st) = &*status {
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                        <div class="text-sm text-gray-400">{ "Status" }</div>
                        <div class="text-lg font-semibold mt-2">
                            if st.enabled {
                                <span class="text-green-400">{ "Enabled" }</span>
                            } else {
                                <span class="text-gray-400">{ "Disabled" }</span>
                            }
                        </div>
                    </div>

                    <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                        <div class="text-sm text-gray-400">{ "Running" }</div>
                        <div class="text-lg font-semibold mt-2">
                            if st.running {
                                <span class="text-green-400">{ "Active" }</span>
                            } else {
                                <span class="text-yellow-400">{ "Inactive" }</span>
                            }
                        </div>
                    </div>

                    <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                        <div class="text-sm text-gray-400">{ "Total Connections" }</div>
                        <div class="text-lg font-semibold mt-2">
                            { st.connections_count }
                        </div>
                    </div>
                </div>

                if let Some(ports) = &st.ports {
                    <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                        <div class="text-lg font-semibold mb-2">{ "Active Ports" }</div>
                        <div class="flex flex-wrap gap-2">
                            {for ports.iter().map(|port| {
                                html! {
                                    <span class="px-3 py-1 bg-blue-900/50 text-blue-300 rounded-full">
                                        { *port }
                                    </span>
                                }
                            })}
                        </div>
                    </div>
                }

                <div class="flex gap-3">
                    if st.enabled {
                        <button
                            class="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg text-white transition-colors"
                            onclick={on_disable}
                        >
                            { "Disable Honeypot" }
                        </button>
                    } else {
                        <button
                            class="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg text-white transition-colors"
                            onclick={on_enable}
                        >
                            { "Enable Honeypot" }
                        </button>
                    }
                </div>
            } else {
                <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                    <div class="text-gray-400">{ "Loading honeypot status..." }</div>
                </div>
            }
        </div>
    }
}
