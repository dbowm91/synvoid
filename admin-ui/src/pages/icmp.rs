//! ICMP filtering page (Phase 90: enforcement truth, not ping health).
//!
//! The server implements firewall enforcement (`GET /icmp/status` returns
//! desired state, live enforcement `applied`/`absent`/`drifted`/`unknown`,
//! the actual selected backend, generation/fingerprint, last receipt, and
//! verification detail; `GET /icmp/backends` returns an object with
//! `backends` plus `current_backend`). This page models that filtering
//! domain: no node/latency/ping concepts. Mutations re-fetch authoritative
//! status instead of optimistically setting UI state.

use crate::services::api::ApiService;
use serde::{Deserialize, Serialize};
use yew::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpApplyReceipt {
    pub backend: String,
    pub fingerprint_hex: String,
    pub generation: u64,
    pub applied_at_secs: u64,
    pub ownership_tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpStatus {
    pub configured: bool,
    pub desired_enabled: bool,
    pub enforcement: String,
    pub selected_backend: Option<String>,
    pub desired_generation: u64,
    pub desired_fingerprint_hex: Option<String>,
    pub last_receipt: Option<IcmpApplyReceipt>,
    pub last_verify_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpBackendEntry {
    pub name: String,
    #[serde(default)]
    pub available: bool,
    #[serde(default)]
    pub compiled: bool,
    #[serde(default)]
    pub usable: bool,
    pub reason: Option<String>,
}

fn parse_status(value: &serde_json::Value) -> IcmpStatus {
    IcmpStatus {
        configured: value
            .get("configured")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        desired_enabled: value
            .get("desired_enabled")
            .and_then(|v| v.as_bool())
            // Compat fallback: legacy `enabled` means desired state.
            .unwrap_or_else(|| {
                value
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            }),
        enforcement: value
            .get("enforcement")
            .and_then(|v| v.as_str())
            // Compat fallback: legacy `status` maps to verified state.
            .unwrap_or_else(|| {
                value
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
            })
            .to_string(),
        selected_backend: value
            .get("selected_backend")
            .and_then(|v| v.as_str())
            // Compat fallback: legacy `backend` is the selected backend.
            .or_else(|| value.get("backend").and_then(|v| v.as_str()))
            .map(|s| s.to_string()),
        desired_generation: value
            .get("desired_generation")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        desired_fingerprint_hex: value
            .get("desired_fingerprint_hex")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        last_receipt: value.get("last_receipt").and_then(|v| {
            if v.is_null() {
                None
            } else {
                serde_json::from_value(v.clone()).ok()
            }
        }),
        last_verify_error: value
            .get("last_verify_error")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    }
}

fn parse_backends(value: &serde_json::Value) -> (Vec<IcmpBackendEntry>, Option<String>) {
    // Server returns an object `{ backends, current_backend }`, never a raw
    // array. A raw array (if ever seen) is treated as a contract mismatch
    // and yields no entries rather than fabricated node data.
    let entries = value
        .get("backends")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| serde_json::from_value(item.clone()).ok())
                .collect()
        })
        .unwrap_or_default();
    let current = value
        .get("current_backend")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    (entries, current)
}

async fn fetch_status_and_backends(
    status: &UseStateHandle<Option<IcmpStatus>>,
    backends: &UseStateHandle<Vec<IcmpBackendEntry>>,
    current_backend: &UseStateHandle<Option<String>>,
    error: &UseStateHandle<Option<String>>,
) {
    let api = ApiService::new();
    match api.get_icmp_status().await {
        Ok(value) => status.set(Some(parse_status(&value))),
        Err(e) => error.set(Some(e.to_string())),
    }
    match api.get_icmp_backends().await {
        Ok(value) => {
            let (entries, current) = parse_backends(&value);
            backends.set(entries);
            current_backend.set(current);
        }
        Err(e) => error.set(Some(e.to_string())),
    }
}

fn enforcement_badge(enforcement: &str) -> Html {
    match enforcement {
        "applied" => html! { <span class="text-green-400">{ "Applied" }</span> },
        "absent" => html! { <span class="text-gray-400">{ "Absent" }</span> },
        "drifted" => html! { <span class="text-red-400">{ "Drifted" }</span> },
        "not_configured" => html! { <span class="text-gray-400">{ "Not configured" }</span> },
        _ => html! { <span class="text-yellow-400">{ "Unknown" }</span> },
    }
}

#[function_component]
pub fn Icmp() -> Html {
    let status = use_state(|| None as Option<IcmpStatus>);
    let backends = use_state(Vec::<IcmpBackendEntry>::new);
    let current_backend = use_state(|| None as Option<String>);
    let error = use_state(|| None as Option<String>);

    {
        let status = status.clone();
        let backends = backends.clone();
        let current_backend = current_backend.clone();
        let error = error.clone();

        use_effect_with((), move |_| {
            let status = status.clone();
            let backends = backends.clone();
            let current_backend = current_backend.clone();
            let error = error.clone();

            wasm_bindgen_futures::spawn_local(async move {
                fetch_status_and_backends(&status, &backends, &current_backend, &error).await;
            });
        });
    }

    // After every mutation, re-fetch authoritative status: HTTP success from
    // enable/disable/config is never treated as proof of enforcement.
    let on_enable = {
        let status = status.clone();
        let backends = backends.clone();
        let current_backend = current_backend.clone();
        let error = error.clone();
        Callback::from(move |_| {
            let status = status.clone();
            let backends = backends.clone();
            let current_backend = current_backend.clone();
            let error = error.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                if let Err(e) = api.enable_icmp().await {
                    error.set(Some(e.to_string()));
                }
                fetch_status_and_backends(&status, &backends, &current_backend, &error).await;
            });
        })
    };

    let on_disable = {
        let status = status.clone();
        let backends = backends.clone();
        let current_backend = current_backend.clone();
        let error = error.clone();
        Callback::from(move |_| {
            let status = status.clone();
            let backends = backends.clone();
            let current_backend = current_backend.clone();
            let error = error.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                if let Err(e) = api.disable_icmp().await {
                    error.set(Some(e.to_string()));
                }
                fetch_status_and_backends(&status, &backends, &current_backend, &error).await;
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
                        <div class="text-sm text-gray-400">{ "Desired state" }</div>
                        <div class="text-lg font-semibold mt-2">
                            if st.desired_enabled {
                                <span class="text-green-400">{ "Enabled" }</span>
                            } else {
                                <span class="text-gray-400">{ "Disabled" }</span>
                            }
                        </div>
                    </div>

                    <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                        <div class="text-sm text-gray-400">{ "Live enforcement" }</div>
                        <div class="text-lg font-semibold mt-2">
                            { enforcement_badge(&st.enforcement) }
                        </div>
                    </div>

                    <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                        <div class="text-sm text-gray-400">{ "Selected backend" }</div>
                        <div class="text-lg font-semibold mt-2">
                            { st.selected_backend.clone().unwrap_or_else(|| "None".to_string()) }
                        </div>
                    </div>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                        <div class="text-sm text-gray-400">{ "Desired generation" }</div>
                        <div class="text-lg font-semibold mt-2">{ st.desired_generation }</div>
                        if let Some(fp) = &st.desired_fingerprint_hex {
                            <div class="text-xs text-gray-500 mt-1">{ format!("fingerprint {}", fp) }</div>
                        }
                    </div>

                    <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                        <div class="text-sm text-gray-400">{ "Last applied receipt" }</div>
                        if let Some(rc) = &st.last_receipt {
                            <div class="text-sm mt-2">
                                { format!("{} generation {} fp {}", rc.backend, rc.generation, rc.fingerprint_hex) }
                            </div>
                            <div class="text-xs text-gray-500 mt-1">{ rc.ownership_tag.clone() }</div>
                        } else {
                            <div class="text-sm text-gray-500 mt-2">{ "None" }</div>
                        }
                    </div>
                </div>

                if let Some(detail) = &st.last_verify_error {
                    <div class="bg-yellow-500/10 border border-yellow-500 rounded-lg p-4 text-yellow-400">
                        { format!("Verification detail: {}", detail) }
                    </div>
                }

                if !backends.is_empty() {
                    <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                        <div class="text-lg font-semibold mb-4">{ "ICMP Backends" }</div>
                        if let Some(current) = &*current_backend {
                            <div class="text-sm text-gray-400 mb-2">{ format!("Selected: {}", current) }</div>
                        }
                        <div class="overflow-x-auto">
                            <table class="min-w-full divide-y divide-gray-700">
                                <thead class="bg-gray-750">
                                    <tr>
                                        <th class="px-4 py-2 text-left text-sm text-gray-400">{ "Backend" }</th>
                                        <th class="px-4 py-2 text-left text-sm text-gray-400">{ "Usable" }</th>
                                        <th class="px-4 py-2 text-left text-sm text-gray-400">{ "Detail" }</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-gray-700">
                                    {for backends.iter().map(|b| {
                                        html! {
                                            <tr>
                                                <td class="px-4 py-2">{ b.name.clone() }</td>
                                                <td class="px-4 py-2">
                                                    if b.usable {
                                                        <span class="text-green-400">{ "Usable" }</span>
                                                    } else {
                                                        <span class="text-red-400">{ "Unusable" }</span>
                                                    }
                                                </td>
                                                <td class="px-4 py-2 text-sm text-gray-400">
                                                    { b.reason.clone().unwrap_or_else(|| if b.compiled { "usable".to_string() } else { "not compiled".to_string() }) }
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
                    if st.desired_enabled {
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
                    <div class="text-gray-400">{ "Loading ICMP enforcement status..." }</div>
                </div>
            }
        </div>
    }
}
