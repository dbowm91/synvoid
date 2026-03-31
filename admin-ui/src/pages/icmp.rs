use crate::services::api::ApiService;
use serde::{Deserialize, Serialize};
use yew::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpStatus {
    pub enabled: bool,
    pub active: bool,
    pub backends_count: usize,
    pub last_ping: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpBackend {
    pub node_id: String,
    pub address: String,
    pub latency_ms: Option<u32>,
    pub last_seen: u64,
    pub healthy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpConfig {
    pub enabled: bool,
    pub interval_secs: u32,
    pub timeout_secs: u32,
    pub packet_size: u32,
}

#[function_component]
pub fn Icmp() -> Html {
    let status = use_state(|| None as Option<IcmpStatus>);
    let config = use_state(|| None as Option<IcmpConfig>);
    let backends = use_state(|| Vec::<IcmpBackend>::new());
    let error = use_state(|| None as Option<String>);

    {
        let status = status.clone();
        let backends = backends.clone();
        let error = error.clone();

        use_effect_with((), move |_| {
            let status = status.clone();
            let backends = backends.clone();
            let error = error.clone();

            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();

                match api.get_icmp_status().await {
                    Ok(value) => {
                        let enabled = value.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
                        let active = value.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
                        let backends_count = value.get("backends_count")
                            .and_then(|v| v.as_u64()).map(|n| n as usize).unwrap_or(0);
                        let last_ping = value.get("last_ping").and_then(|v| v.as_u64());

                        status.set(Some(IcmpStatus {
                            enabled,
                            active,
                            backends_count,
                            last_ping,
                        }));
                    }
                    Err(e) => error.set(Some(e)),
                }

                match api.get_icmp_backends().await {
                    Ok(value) => {
                        if let Some(arr) = value.as_array() {
                            let mut backend_list = Vec::new();
                            for item in arr {
                                if let Some(node_id) = item.get("node_id").and_then(|v| v.as_str()) {
                                    let address = item.get("address").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                    let latency_ms = item.get("latency_ms").and_then(|v| v.as_u64()).map(|n| n as u32);
                                    let last_seen = item.get("last_seen").and_then(|v| v.as_u64()).unwrap_or(0);
                                    let healthy = item.get("healthy").and_then(|v| v.as_bool()).unwrap_or(false);

                                    backend_list.push(IcmpBackend {
                                        node_id: node_id.to_string(),
                                        address,
                                        latency_ms,
                                        last_seen,
                                        healthy,
                                    });
                                }
                            }
                            backends.set(backend_list);
                        }
                    }
                    Err(e) => error.set(Some(e)),
                }
            });
        });
    }

    let on_enable = {
        let status = status.clone();
        Callback::from(move |_| {
            let status = status.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                if api.enable_icmp().await.is_ok() {
                    let mut s = (*status).clone().unwrap_or_else(|| IcmpStatus {
                        enabled: true,
                        active: true,
                        backends_count: 0,
                        last_ping: None,
                    });
                    s.enabled = true;
                    s.active = true;
                    status.set(Some(s));
                }
            });
        })
    };

    let on_disable = {
        let status = status.clone();
        Callback::from(move |_| {
            let status = status.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                if api.disable_icmp().await.is_ok() {
                    let mut s = (*status).clone().unwrap_or_else(|| IcmpStatus {
                        enabled: false,
                        active: false,
                        backends_count: 0,
                        last_ping: None,
                    });
                    s.enabled = false;
                    s.active = false;
                    status.set(Some(s));
                }
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div class="flex justify-between items-center">
                <h1 class="text-2xl font-bold">{ "ICMP Filtering" }</h1>
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
                        <div class="text-sm text-gray-400">{ "Active" }</div>
                        <div class="text-lg font-semibold mt-2">
                            if st.active {
                                <span class="text-green-400">{ "Active" }</span>
                            } else {
                                <span class="text-yellow-400">{ "Inactive" }</span>
                            }
                        </div>
                    </div>

                    <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                        <div class="text-sm text-gray-400">{ "Backends" }</div>
                        <div class="text-lg font-semibold mt-2">
                            { st.backends_count }
                        </div>
                    </div>
                </div>

                if !backends.is_empty() {
                    <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                        <div class="text-lg font-semibold mb-4">{ "ICMP Backends" }</div>
                        <div class="overflow-x-auto">
                            <table class="min-w-full divide-y divide-gray-700">
                                <thead class="bg-gray-750">
                                    <tr>
                                        <th class="px-4 py-2 text-left text-sm text-gray-400">{ "Node ID" }</th>
                                        <th class="px-4 py-2 text-left text-sm text-gray-400">{ "Address" }</th>
                                        <th class="px-4 py-2 text-left text-sm text-gray-400">{ "Latency" }</th>
                                        <th class="px-4 py-2 text-left text-sm text-gray-400">{ "Status" }</th>
                                    </tr>
                                        </thead>
                                <tbody class="divide-y divide-gray-700">
                                    {for backends.iter().map(|b| {
                                        html! {
                                            <tr>
                                                <td class="px-4 py-2">{ b.node_id.clone() }</td>
                                                <td class="px-4 py-2">{ b.address.clone() }</td>
                                                <td class="px-4 py-2">
                                                    { if let Some(lat) = b.latency_ms {
                                                        format!("{}ms", lat)
                                                    } else {
                                                        "N/A".to_string()
                                                    }}
                                                </td>
                                                <td class="px-4 py-2">
                                                    if b.healthy {
                                                        <span class="text-green-400">{ "Healthy" }</span>
                                                    } else {
                                                        <span class="text-red-400">{ "Unhealthy" }</span>
                                                    }
                                                </td>
                                            </tr>
                                        }
                                    })}
                                </tbody>
                            </table>
                        </div>
                    </div>
                }

                <div class="flex gap-3">
                    if st.enabled {
                        <button
                            class="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg text-white transition-colors"
                            onclick={on_disable}
                        >
                            { "Disable ICMP" }
                        </button>
                    } else {
                        <button
                            class="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg text-white transition-colors"
                            onclick={on_enable}
                        >
                            { "Enable ICMP" }
                        </button>
                    }
                </div>
            } else {
                <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                    <div class="text-gray-400">{ "Loading ICMP status..." }</div>
                </div>
            }
        </div>
    }
}