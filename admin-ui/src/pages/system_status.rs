use crate::components::layout::Capabilities;
use crate::services::api::ApiService;
use crate::types::{MasterStatus, MeshAdminStatus, SystemInfo};
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct SystemStatusProps {
    /// The `/mesh/*` endpoints this page reads are registered behind the
    /// backend `mesh` feature. Without this gate the page rendered an empty
    /// "Mesh Status" card and still offered the genesis-key action, because
    /// the visibility guard below fell back to `.unwrap_or(true)` when the
    /// fetch failed.
    pub capabilities: Capabilities,
}

#[function_component]
pub fn SystemStatus(props: &SystemStatusProps) -> Html {
    let mesh_enabled = props.capabilities.mesh_admin;
    let system_info = use_state(|| None as Option<SystemInfo>);
    let master_status = use_state(|| None as Option<MasterStatus>);
    let mesh_status = use_state(|| None as Option<MeshAdminStatus>);
    // Distinguishes "mesh request still in flight" from "mesh request failed",
    // so the card stops shimmering forever on the latter.
    let mesh_failed = use_state(|| false);
    let error = use_state(|| None as Option<String>);
    let show_genesis_modal = use_state(|| false);
    let genesis_key_input = use_state(String::new);
    let deriving_key = use_state(|| false);
    let derive_error = use_state(|| None as Option<String>);
    let derive_success = use_state(|| None as Option<String>);

    {
        let system_info = system_info.clone();
        let master_status = master_status.clone();
        let mesh_status = mesh_status.clone();
        let mesh_failed = mesh_failed.clone();
        let error = error.clone();
        use_effect_with(mesh_enabled, move |mesh_enabled| {
            let system_info = system_info.clone();
            let master_status = master_status.clone();
            let mesh_status = mesh_status.clone();
            let mesh_failed = mesh_failed.clone();
            let error = error.clone();
            // Skip the mesh fetch entirely on a build without the feature
            // rather than firing a request that can only 404.
            let mesh_enabled = *mesh_enabled;
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.get_system_info().await {
                    Ok(info) => system_info.set(Some(info)),
                    Err(e) => error.set(Some(e.to_string())),
                }
                // Canonical supervisor endpoint (`/system/supervisor`).
                match api.get_supervisor().await {
                    Ok(status) => master_status.set(Some(status)),
                    Err(e) => error.set(Some(e.to_string())),
                }
                if mesh_enabled {
                    match api.get_mesh_status().await {
                        Ok(status) => mesh_status.set(Some(status)),
                        Err(_) => mesh_failed.set(true),
                    }
                }
            });
        });
    }

    let on_provide_genesis_key = {
        let genesis_key_input_for_send = genesis_key_input.clone();
        let deriving_key = deriving_key.clone();
        let derive_error = derive_error.clone();
        let derive_success = derive_success.clone();
        let show_genesis_modal_for_close = show_genesis_modal.clone();
        let mesh_status = mesh_status.clone();
        Callback::from(move |_e: MouseEvent| {
            let genesis_key_input = genesis_key_input_for_send.clone();
            let deriving_key = deriving_key.clone();
            let derive_error = derive_error.clone();
            let derive_success = derive_success.clone();
            let show_genesis_modal = show_genesis_modal_for_close.clone();
            let mesh_status = mesh_status.clone();
            deriving_key.set(true);
            derive_error.set(None);
            derive_success.set(None);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.derive_signing_key(&genesis_key_input).await {
                    Ok(response) => {
                        if response.success {
                            derive_success.set(Some(response.message));
                            genesis_key_input.set(String::new());
                            show_genesis_modal.set(false);
                            if let Ok(status) = api.get_mesh_status().await {
                                mesh_status.set(Some(status));
                            }
                        } else {
                            derive_error.set(Some(response.message));
                        }
                    }
                    Err(e) => {
                        derive_error.set(Some(e.to_string()));
                    }
                }
                deriving_key.set(false);
            });
        })
    };

    let genesis_key_input_for_render = genesis_key_input.clone();
    let show_genesis_modal_for_render = show_genesis_modal.clone();

    let format_uptime = |secs: Option<u64>| -> String {
        match secs {
            Some(s) => {
                let days = s / 86400;
                let hours = (s % 86400) / 3600;
                let minutes = (s % 3600) / 60;
                if days > 0 {
                    format!("{}d {}h {}m", days, hours, minutes)
                } else if hours > 0 {
                    format!("{}h {}m", hours, minutes)
                } else {
                    format!("{}m", minutes)
                }
            }
            None => "N/A".to_string(),
        }
    };

    // Fail closed: without the `mesh` feature the status can never load, and the
    // previous `.unwrap_or(true)` therefore offered a button that could only
    // return 404. Show it only when mesh is compiled in AND the status says
    // this node still needs a signing key.
    let show_genesis_modal_button = if mesh_enabled
        && !(*mesh_status)
            .as_ref()
            .map(|s| s.is_global_node && s.signing_key_derived)
            .unwrap_or(true)
    {
        let show_modal = show_genesis_modal.clone();
        Some(Callback::from(move |_| show_modal.set(true)))
    } else {
        None
    };

    let genesis_key_input_for_disable = if *show_genesis_modal_for_render {
        Some(genesis_key_input_for_render.clone())
    } else {
        None
    };

    let modal_input_callback = if *show_genesis_modal_for_render {
        let genesis_key_input = genesis_key_input_for_render.clone();
        Some(Callback::from(move |e: InputEvent| {
            let input = e.target_unchecked_into::<web_sys::HtmlTextAreaElement>();
            genesis_key_input.set(input.value());
        }))
    } else {
        None
    };

    let modal_cancel_callback = if *show_genesis_modal_for_render {
        let genesis_key_input = genesis_key_input_for_render.clone();
        let show_modal = show_genesis_modal_for_render.clone();
        let derive_error_for_cancel = derive_error.clone();
        Some(Callback::from(move |_| {
            show_modal.set(false);
            genesis_key_input.set(String::new());
            derive_error_for_cancel.set(None);
        }))
    } else {
        None
    };

    html! {
        <div class="space-y-6">
            <div class="flex justify-between items-center">
                <h1 class="text-2xl font-bold">{ "System Status" }</h1>
            </div>

            if let Some(err) = &*error {
                <div class="bg-red-500/10 border border-red-500 rounded-lg p-4 text-red-500">
                    { err }
                </div>
            }

            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div class="bg-secondary rounded-lg border border-default p-6">
                    <h2 class="text-lg font-semibold mb-4">{ "System Information" }</h2>
                    if let Some(info) = &*system_info {
                        <div class="space-y-3">
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Version" }</span>
                                <span class="text-primary font-medium">{ &info.version }</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Build" }</span>
                                <span class="text-primary font-medium">{ &info.build_timestamp }</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Architecture" }</span>
                                <span class="text-primary font-medium">{ &info.architecture }</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Running Mode" }</span>
                                <span class="text-primary font-medium">{ &info.running_mode }</span>
                            </div>
                            <div class="mt-4">
                                <span class="text-secondary">{ "Features" }</span>
                                <div class="flex flex-wrap gap-2 mt-2">
                                    { for info.features.iter().map(|f| {
                                        html! {
                                            <span class="px-2 py-1 bg-tertiary rounded text-sm">
                                                { f }
                                            </span>
                                        }
                                    }) }
                                </div>
                            </div>
                        </div>
                    } else {
                        <div class="animate-pulse">
                            <div class="h-4 bg-tertiary rounded w-3/4 mb-2"></div>
                            <div class="h-4 bg-tertiary rounded w-1/2"></div>
                        </div>
                    }
                </div>

                <div class="bg-secondary rounded-lg border border-default p-6">
                    <h2 class="text-lg font-semibold mb-4">{ "Supervisor Process" }</h2>
                    if let Some(status) = &*master_status {
                        <div class="space-y-3">
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Status" }</span>
                                <span class={if status.running { "text-green-500 font-medium" } else { "text-red-500 font-medium" }}>
                                    { if status.running { "Running" } else { "Stopped" } }
                                </span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "PID" }</span>
                                <span class="text-primary font-medium">
                                    { status.pid.map(|p| p.to_string()).unwrap_or_else(|| "N/A".to_string()) }
                                </span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Uptime" }</span>
                                <span class="text-primary font-medium">{ format_uptime(status.uptime_secs) }</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Mode" }</span>
                                <span class="text-primary font-medium">{ &status.mode }</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Worker Mode" }</span>
                                <span class="text-primary font-medium">{ &status.worker_mode }</span>
                            </div>
                        </div>
                    } else {
                        <div class="animate-pulse">
                            <div class="h-4 bg-tertiary rounded w-3/4 mb-2"></div>
                            <div class="h-4 bg-tertiary rounded w-1/2"></div>
                        </div>
                    }
                </div>
            </div>

            if let Some(status) = &*master_status {
                <div class="bg-secondary rounded-lg border border-default p-6">
                    <h2 class="text-lg font-semibold mb-4">{ "Request Statistics" }</h2>
                    <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div class="text-center">
                            <div class="text-2xl font-bold text-primary">{ status.metrics.total_requests }</div>
                            <div class="text-sm text-secondary">{ "Total Requests" }</div>
                        </div>
                        <div class="text-center">
                            <div class="text-2xl font-bold text-green-500">{ status.metrics.proxied }</div>
                            <div class="text-sm text-secondary">{ "Proxied" }</div>
                        </div>
                        <div class="text-center">
                            <div class="text-2xl font-bold text-red-500">{ status.metrics.blocked }</div>
                            <div class="text-sm text-secondary">{ "Blocked" }</div>
                        </div>
                        <div class="text-center">
                            <div class="text-2xl font-bold text-yellow-500">{ status.metrics.challenged }</div>
                            <div class="text-sm text-secondary">{ "Challenged" }</div>
                        </div>
                    </div>
                    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
                        <div class="text-center">
                            <div class="text-2xl font-bold text-primary">{ status.metrics.requests_per_second.round() }</div>
                            <div class="text-sm text-secondary">{ "Req/sec" }</div>
                        </div>
                        <div class="text-center">
                            <div class="text-2xl font-bold text-primary">{ status.metrics.current_concurrent }</div>
                            <div class="text-sm text-secondary">{ "Active Connections" }</div>
                        </div>
                        <div class="text-center">
                            <div class="text-2xl font-bold text-primary">{ status.metrics.peak_concurrent }</div>
                            <div class="text-sm text-secondary">{ "Peak Connections" }</div>
                        </div>
                        <div class="text-center">
                            <div class="text-2xl font-bold text-red-500">{ status.metrics.errors }</div>
                            <div class="text-sm text-secondary">{ "Errors" }</div>
                        </div>
                    </div>
                </div>
            }

            <div class="bg-secondary rounded-lg border border-default p-6">
                <h2 class="text-lg font-semibold mb-4">{ "Architecture" }</h2>
                <div class="flex items-center justify-center p-4">
                    <div class="flex items-center gap-8">
                        <div class="text-center">
                            <div class="w-24 h-24 rounded-full bg-blue-600 flex items-center justify-center text-white font-bold text-lg">
                                { "Supervisor" }
                            </div>
                            <p class="text-sm text-secondary mt-2">{ "Lifecycle" }</p>
                        </div>
                        <div class="w-16 h-1 bg-tertiary"></div>
                        <div class="text-center">
                            <div class="w-24 h-24 rounded-full bg-green-600 flex items-center justify-center text-white font-bold text-lg">
                                { "Workers" }
                            </div>
                            <p class="text-sm text-secondary mt-2">{ "Request Handler" }</p>
                        </div>
                    </div>
                </div>
                <p class="text-sm text-secondary text-center mt-4">
                    { "Supervisor manages worker lifecycle; workers handle requests" }
                </p>
            </div>

            if mesh_enabled {
            <div class="bg-secondary rounded-lg border border-default p-6">
                <div class="flex justify-between items-center mb-4">
                    <h2 class="text-lg font-semibold">{ "Mesh Status" }</h2>
                </div>
                if let Some(status) = &*mesh_status {
                    <div class="space-y-3">
                        <div class="flex justify-between">
                            <span class="text-secondary">{ "Node Type" }</span>
                            <span class={if status.is_global_node { "text-green-500 font-medium" } else { "text-yellow-500 font-medium" }}>
                                { if status.is_global_node { "Global Node" } else { "Edge Node" } }
                            </span>
                        </div>
                        <div class="flex justify-between gap-3">
                            <span class="text-secondary shrink-0">{ "Node ID" }</span>
                            <span class="text-primary font-medium break-all text-right min-w-0">
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
                            <h3 class="text-base font-semibold mb-2">{ "Genesis Key Status" }</h3>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Genesis Key Configured" }</span>
                                <span class={if status.genesis_key_configured { "text-green-500 font-medium" } else { "text-red-500 font-medium" }}>
                                    { if status.genesis_key_configured { "Yes" } else { "No" } }
                                </span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-secondary">{ "Signing Key Derived" }</span>
                                <span class={if status.signing_key_derived { "text-green-500 font-medium" } else { "text-red-500 font-medium" }}>
                                    { if status.signing_key_derived { "Yes" } else { "No" } }
                                </span>
                            </div>
                            if let Some(ref fp) = status.genesis_public_key_fingerprint {
                                <div class="flex justify-between gap-3">
                                    <span class="text-secondary shrink-0">{ "Genesis Public Key" }</span>
                                    <span class="text-primary font-mono text-sm break-all text-right min-w-0">{ fp }</span>
                                </div>
                            }
                            if let Some(ref pk) = status.signing_public_key {
                                <div class="flex justify-between gap-3">
                                    <span class="text-secondary shrink-0">{ "Signing Public Key" }</span>
                                    // `min-w-0` is required alongside `truncate`: a flex
                                    // child defaults to `min-width:auto`, so without it
                                    // the item refuses to shrink and the ellipsis never
                                    // engages — the row just overflows instead.
                                    <span class="text-primary font-mono text-sm truncate max-w-xs min-w-0">{ pk }</span>
                                </div>
                            }
                        </div>
                        if !status.is_global_node && !status.signing_key_derived {
                            <div class="mt-4 pt-3 border-t border-default">
                                <button
                                    onclick={show_genesis_modal_button.clone().unwrap_or_default()}
                                    class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                                >
                                    { "Provide Genesis Key" }
                                </button>
                                <p class="text-sm text-secondary mt-2">
                                    { "Provide a genesis key to become a global node and enable tier key encryption." }
                                </p>
                            </div>
                        }
                    </div>
                } else if *mesh_failed {
                    // Previously this fell through to the loading skeleton
                    // forever, so a failed mesh fetch looked identical to one
                    // still in flight and the card shimmered indefinitely.
                    <div class="text-secondary text-sm">
                        { "Unable to load mesh status." }
                    </div>
                } else {
                    <div class="animate-pulse">
                        <div class="h-4 bg-tertiary rounded w-3/4 mb-2"></div>
                        <div class="h-4 bg-tertiary rounded w-1/2"></div>
                    </div>
                }
            </div>
            }

            if *show_genesis_modal_for_render {
                <div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                    <div class="bg-secondary rounded-lg border border-default p-6 max-w-md w-full mx-4">
                        <h3 class="text-lg font-semibold mb-4">{ "Provide Genesis Key" }</h3>
                        <p class="text-sm text-secondary mb-4">
                            { "Enter the genesis key (base64 encoded) to derive your node's signing key and become a global node." }
                        </p>
                        <textarea
                            class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary font-mono text-sm resize-none"
                            rows="3"
                            placeholder="Enter genesis key (base64)"
                            value={(*genesis_key_input_for_render).clone()}
                            oninput={modal_input_callback.clone().unwrap_or_default()}
                        />
                        if let Some(err) = &*derive_error {
                            <div class="mt-2 text-red-500 text-sm">{ err }</div>
                        }
                        if let Some(ref msg) = *derive_success {
                            <div class="mt-2 text-green-500 text-sm">{ msg }</div>
                        }
                        <div class="flex justify-end gap-3 mt-4">
                            <button
                                onclick={modal_cancel_callback.clone().unwrap_or_default()}
                                class="px-4 py-2 bg-tertiary hover:opacity-80 text-primary rounded-lg transition-colors"
                            >
                                { "Cancel" }
                            </button>
                            <button
                                onclick={on_provide_genesis_key}
                                disabled={*deriving_key || genesis_key_input_for_disable.as_ref().map(|h| h.is_empty()).unwrap_or(false)}
                                class="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-600/50 text-white rounded-lg transition-colors"
                            >
                                { if *deriving_key { "Deriving..." } else { "Derive Signing Key" } }
                            </button>
                        </div>
                    </div>
                </div>
            }
        </div>
    }
}
