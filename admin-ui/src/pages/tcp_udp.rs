//! TCP/UDP listener management.
//!
//! Backed by the always-available `/api/tcp-udp/*` family
//! (`src/admin/handlers/tcp_udp.rs`): list, create, delete, and the supported
//! protocol catalog.
//!
//! Two contract details this page must respect:
//!
//! 1. Mutating endpoints answer with `AdminMutationResult`, and
//!    `NoOpAlreadyAbsent` / `InvalidRejected` arrive as **HTTP 200**. Success
//!    is therefore decided by `AdminMutationResult::applied()`, never by the
//!    HTTP status — see `mutation_banner`.
//! 2. `protocol` is the site's TCP port *name* (the key in
//!    `SiteTcpConfig::ports`), not a transport discriminator. The handler
//!    surfaces TCP ports only, so the column is labelled accordingly.

use yew::prelude::*;

use crate::components::confirm_dialog::{ConfirmDialog, ConfirmType};
use crate::components::forms::{Input, Select};
use crate::components::skeleton::LoadingSpinner;
use crate::components::toast::{toast_error, toast_success};
use crate::components::ToastContainer;
use crate::services::ApiService;
use crate::types::{AdminMutationResult, TcpUdpListener, TcpUdpProtocolInfo};

#[function_component]
pub fn TcpUdp() -> Html {
    let listeners = use_state(Vec::<TcpUdpListener>::new);
    let protocols = use_state(Vec::<TcpUdpProtocolInfo>::new);
    let sites = use_state(Vec::<crate::types::SiteInfo>::new);
    let loading = use_state(|| true);
    let error = use_state(|| None as Option<String>);
    let last_mutation = use_state(|| None as Option<AdminMutationResult>);

    let show_form = use_state(|| false);
    let form_site = use_state(String::new);
    let form_port = use_state(String::new);
    let form_protocol = use_state(String::new);
    let form_upstream = use_state(String::new);
    let saving = use_state(|| false);
    let pending_delete = use_state(|| None as Option<String>);

    // ── Load ────────────────────────────────────────────────────────────
    {
        let listeners = listeners.clone();
        let protocols = protocols.clone();
        let sites = sites.clone();
        let loading = loading.clone();
        let error = error.clone();
        let form_site = form_site.clone();
        let form_protocol = form_protocol.clone();

        use_effect_with((), move |_| {
            let listeners = listeners.clone();
            let protocols = protocols.clone();
            let sites = sites.clone();
            let loading = loading.clone();
            let error = error.clone();
            let form_site = form_site.clone();
            let form_protocol = form_protocol.clone();

            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();

                match api.list_tcp_udp_listeners().await {
                    Ok(list) => listeners.set(list.listeners),
                    Err(e) => error.set(Some(e.to_string())),
                }

                match api.list_tcp_udp_protocols().await {
                    Ok(p) => {
                        if let Some(first) = p.first() {
                            if form_protocol.is_empty() {
                                form_protocol.set(first.name.clone());
                            }
                        }
                        protocols.set(p);
                    }
                    Err(e) => tracing::error!("Failed to fetch protocols: {}", e),
                }

                // The backend 404s a create for an unknown site, so the form
                // offers only real sites rather than free text.
                match api.list_sites().await {
                    Ok(s) => {
                        if let Some(first) = s.first() {
                            if form_site.is_empty() {
                                form_site.set(first.id.clone());
                            }
                        }
                        sites.set(s);
                    }
                    Err(e) => tracing::error!("Failed to fetch sites: {}", e),
                }

                loading.set(false);
            });
            || ()
        });
    }

    let refresh = {
        let listeners = listeners.clone();
        let error = error.clone();
        Callback::from(move |_| {
            let listeners = listeners.clone();
            let error = error.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiService::new().list_tcp_udp_listeners().await {
                    Ok(list) => {
                        listeners.set(list.listeners);
                        error.set(None);
                    }
                    Err(e) => error.set(Some(e.to_string())),
                }
            });
        })
    };

    // ── Field setters ───────────────────────────────────────────────────
    let toggle_form = {
        let show_form = show_form.clone();
        Callback::from(move |_: MouseEvent| {
            let next = !*show_form;
            show_form.set(next);
        })
    };
    let close_form = {
        let show_form = show_form.clone();
        Callback::from(move |_: MouseEvent| show_form.set(false))
    };
    let cancel_delete: Callback<()> = {
        let pending_delete = pending_delete.clone();
        Callback::from(move |_: ()| pending_delete.set(None))
    };
    let set_site = {
        let form_site = form_site.clone();
        Callback::from(move |v: String| form_site.set(v))
    };
    let set_port = {
        let form_port = form_port.clone();
        Callback::from(move |v: String| form_port.set(v))
    };
    let set_protocol = {
        let form_protocol = form_protocol.clone();
        Callback::from(move |v: String| form_protocol.set(v))
    };
    let set_upstream = {
        let form_upstream = form_upstream.clone();
        Callback::from(move |v: String| form_upstream.set(v))
    };

    // ── Create ──────────────────────────────────────────────────────────
    let on_create = {
        let listeners = listeners.clone();
        let error = error.clone();
        let saving = saving.clone();
        let last_mutation = last_mutation.clone();
        let show_form = show_form.clone();
        let form_port = form_port.clone();
        let form_protocol = form_protocol.clone();
        let form_upstream = form_upstream.clone();
        let form_site = form_site.clone();

        Callback::from(move |_: MouseEvent| {
            let site_id = (*form_site).clone();
            let protocol = (*form_protocol).clone();

            // Validate before the round trip so an operator typo does not
            // become a 400 from the server.
            let parsed_port: u16 = match form_port.trim().parse::<u16>() {
                Ok(p) if p > 0 => p,
                _ => {
                    toast_error("Port must be a number between 1 and 65535");
                    return;
                }
            };

            let upstream = form_upstream.trim().to_string();
            if upstream.is_empty() {
                toast_error("Upstream is required");
                return;
            }
            if site_id.is_empty() {
                toast_error("Select a site");
                return;
            }

            let listeners = listeners.clone();
            let error = error.clone();
            let saving = saving.clone();
            let last_mutation = last_mutation.clone();
            let show_form = show_form.clone();
            let form_port = form_port.clone();
            let form_upstream = form_upstream.clone();

            saving.set(true);

            wasm_bindgen_futures::spawn_local(async move {
                let result = ApiService::new()
                    .create_tcp_udp_listener(&site_id, parsed_port, &protocol, &upstream)
                    .await;

                saving.set(false);

                match result {
                    Ok(m) => {
                        last_mutation.set(Some(m.clone()));
                        if m.applied() {
                            toast_success(&m.message);
                            show_form.set(false);
                            form_port.set(String::new());
                            form_upstream.set(String::new());
                            // Re-read rather than assume: the mutation reports
                            // AppliedLocalOnly, so the authoritative list is the
                            // only safe thing to render.
                            match ApiService::new().list_tcp_udp_listeners().await {
                                Ok(list) => listeners.set(list.listeners),
                                Err(e) => error.set(Some(e.to_string())),
                            }
                        } else {
                            // HTTP 200 but nothing changed — say so honestly
                            // rather than reporting success.
                            toast_error(&format!("Not applied: {}", m.message));
                        }
                    }
                    Err(e) => error.set(Some(e.to_string())),
                }
            });
        })
    };

    // ── Delete ──────────────────────────────────────────────────────────
    let on_confirm_delete = {
        let listeners = listeners.clone();
        let error = error.clone();
        let last_mutation = last_mutation.clone();
        let pending_delete = pending_delete.clone();

        Callback::from(move |_| {
            if let Some(listener_id) = (*pending_delete).clone() {
                let listeners = listeners.clone();
                let error = error.clone();
                let last_mutation = last_mutation.clone();
                let pending_delete = pending_delete.clone();

                wasm_bindgen_futures::spawn_local(async move {
                    match ApiService::new()
                        .delete_tcp_udp_listener(&listener_id)
                        .await
                    {
                        Ok(m) => {
                            last_mutation.set(Some(m.clone()));
                            if m.applied() {
                                toast_success(&m.message);
                                match ApiService::new().list_tcp_udp_listeners().await {
                                    Ok(list) => listeners.set(list.listeners),
                                    Err(e) => error.set(Some(e.to_string())),
                                }
                            } else {
                                toast_error(&format!("Not applied: {}", m.message));
                            }
                            pending_delete.set(None);
                        }
                        Err(e) => {
                            pending_delete.set(None);
                            error.set(Some(e.to_string()));
                        }
                    }
                });
            }
        })
    };

    let site_options: Vec<(String, String)> = (*sites)
        .iter()
        .map(|s| (s.id.clone(), s.id.clone()))
        .collect();
    let protocol_options: Vec<(String, String)> = (*protocols)
        .iter()
        .map(|p| (p.name.clone(), p.description.clone()))
        .collect();

    let delete_message = pending_delete
        .as_ref()
        .map(|id| {
            format!(
                "Delete listener \"{}\"? This removes its port from the site config.",
                id
            )
        })
        .unwrap_or_default();

    html! {
        <div>
            <ToastContainer />
            <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-6">
                <div>
                    <h1 class="text-2xl font-bold mb-1">{ "TCP/UDP Listeners" }</h1>
                    <p class="text-secondary text-sm">
                        { "Per-site TCP port mappings. Changes apply to local config only and may require a worker restart to take effect." }
                    </p>
                </div>
                <div class="flex gap-2">
                    <button
                        onclick={refresh.reform(|_: MouseEvent| ())}
                        class="px-4 py-2 rounded-lg bg-tertiary hover:opacity-80 transition"
                    >
                        { "Refresh" }
                    </button>
                    <button
                        onclick={toggle_form.clone()}
                        class="px-4 py-2 rounded-lg bg-action-600 text-white hover:bg-action-700 transition"
                    >
                        { "Add Listener" }
                    </button>
                </div>
            </div>

            if let Some(err) = &*error {
                <div class="bg-red-900/20 border border-red-500/30 rounded-lg p-4 mb-4 text-red-400">
                    { err }
                </div>
            }

            if let Some(m) = &*last_mutation {
                { mutation_banner(m.clone()) }
            }

            if *show_form {
                <div class="bg-secondary rounded-lg border border-default p-6 mb-6">
                    <h2 class="text-lg font-semibold mb-4">{ "New TCP listener" }</h2>

                    if site_options.is_empty() {
                        <p class="text-secondary text-sm">
                            { "No sites configured yet. Create a site before adding a listener." }
                        </p>
                    } else {
                        <Select
                            label="Site"
                            name="tcpudp-site"
                            value={(*form_site).clone()}
                            options={site_options}
                            on_change={set_site}
                        />
                        <Input
                            label="Port"
                            name="tcpudp-port"
                            input_type="number"
                            placeholder="25"
                            help="Local TCP port to accept traffic on"
                            value={(*form_port).clone()}
                            on_change={set_port}
                        />
                        <Select
                            label="Protocol profile"
                            name="tcpudp-protocol"
                            value={(*form_protocol).clone()}
                            options={protocol_options}
                            on_change={set_protocol}
                        />
                        <Input
                            label="Upstream"
                            name="tcpudp-upstream"
                            placeholder="mail.internal:25"
                            help="Backend address traffic is forwarded to"
                            value={(*form_upstream).clone()}
                            on_change={set_upstream}
                        />

                        <div class="flex gap-2 mt-2">
                            <button
                                onclick={on_create}
                                disabled={*saving}
                                class="px-4 py-2 rounded-lg bg-action-600 text-white hover:bg-action-700 disabled:opacity-50 disabled:cursor-not-allowed transition"
                            >
                                { if *saving { "Creating..." } else { "Create" } }
                            </button>
                            <button
                                onclick={close_form.clone()}
                                class="px-4 py-2 rounded-lg bg-tertiary hover:opacity-80 transition"
                            >
                                { "Cancel" }
                            </button>
                        </div>
                    }
                </div>
            }

            if *loading {
                <div class="flex justify-center py-20">
                    <LoadingSpinner />
                </div>
            } else if (*listeners).is_empty() {
                <div class="bg-secondary rounded-lg border border-default p-12 text-center">
                    <p class="text-secondary mb-4">{ "No TCP listeners configured." }</p>
                    <button
                        onclick={toggle_form.clone()}
                        class="px-4 py-2 rounded-lg bg-action-600 text-white hover:bg-action-700 transition"
                    >
                        { "Add the first listener" }
                    </button>
                </div>
            } else {
                <div class="bg-secondary rounded-lg border border-default overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-tertiary">
                            <tr>
                                <th class="text-left px-4 py-3 text-sm font-medium text-secondary">{ "Listener" }</th>
                                <th class="text-left px-4 py-3 text-sm font-medium text-secondary">{ "Port profile" }</th>
                                <th class="text-left px-4 py-3 text-sm font-medium text-secondary">{ "Port" }</th>
                                <th class="text-left px-4 py-3 text-sm font-medium text-secondary">{ "Upstream" }</th>
                                <th class="text-left px-4 py-3 text-sm font-medium text-secondary">{ "Status" }</th>
                                <th class="text-right px-4 py-3 text-sm font-medium text-secondary">{ "Actions" }</th>
                            </tr>
                        </thead>
                        <tbody>
                            { for listeners.iter().map(|listener| {
                                let id = listener.id.clone();
                                let on_delete = pending_delete.clone();
                                html! {
                                    <tr class="border-t border-default">
                                        <td class="px-4 py-3 text-sm font-mono text-primary">{ &listener.id }</td>
                                        <td class="px-4 py-3 text-sm text-secondary">{ &listener.protocol }</td>
                                        <td class="px-4 py-3 text-sm text-primary font-mono">{ listener.port }</td>
                                        <td class="px-4 py-3 text-sm text-primary font-mono truncate max-w-[200px]" title={listener.upstream.clone()}>
                                            { &listener.upstream }
                                        </td>
                                        <td class="px-4 py-3 text-sm">
                                            <span class={if listener.enabled {
                                                "px-2 py-1 rounded bg-green-500/10 text-green-400"
                                            } else {
                                                "px-2 py-1 rounded bg-tertiary text-secondary"
                                            }}>
                                                { if listener.enabled { "Enabled" } else { "Disabled" } }
                                            </span>
                                        </td>
                                        <td class="px-4 py-3 text-right">
                                            <button
                                                onclick={Callback::from(move |_: MouseEvent| on_delete.set(Some(id.clone())))}
                                                class="text-red-500 hover:text-red-400"
                                            >
                                                { "Delete" }
                                            </button>
                                        </td>
                                    </tr>
                                }
                            })}
                        </tbody>
                    </table>
                </div>
            }

            if !(*protocols).is_empty() {
                <div class="mt-8">
                    <h2 class="text-sm font-semibold text-secondary uppercase tracking-wider mb-2">
                        { "Supported protocol profiles" }
                    </h2>
                    <div class="flex flex-wrap gap-2">
                        { for protocols.iter().map(|p| html! {
                            <span class="px-3 py-1 rounded-lg bg-tertiary text-sm text-secondary">
                                { format!("{} — {}", p.name, p.description) }
                            </span>
                        })}
                    </div>
                </div>
            }

            <ConfirmDialog
                show={pending_delete.is_some()}
                title="Delete listener"
                message={delete_message}
                confirm_label={Some("Delete".to_string())}
                confirm_type={ConfirmType::Danger}
                cancel_label={None}
                on_confirm={on_confirm_delete}
                on_cancel={cancel_delete}
            />
        </div>
    }
}

/// Renders the last `AdminMutationResult` so the operator can see what the
/// server actually did — including the propagation mode, which is not
/// "applied everywhere".
fn mutation_banner(m: AdminMutationResult) -> Html {
    let applied = m.applied();
    html! {
        <div class={if applied {
            "bg-green-500/10 border border-green-500/30 rounded-lg p-3 mb-4 text-sm"
        } else {
            "bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3 mb-4 text-sm"
        }}>
            <span class={if applied { "text-green-400" } else { "text-yellow-400" }}>
                { format!("{}: {}", m.status, m.message) }
            </span>
            <span class="text-secondary ml-2">
                { format!("propagation: {}", m.propagation) }
            </span>
        </div>
    }
}
