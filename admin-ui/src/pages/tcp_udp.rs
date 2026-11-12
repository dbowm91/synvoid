//! TCP/UDP listener inventory.
//!
//! Read-only on purpose: the listener definitions come from the global
//! `[tcp.protocols.*]` / `[udp.protocols.*]` maps, the pools bind once at
//! startup, and `create_listener`/`delete_listener` were removed because they
//! mutated a site-local schema no runtime code consumed. Active counts come
//! from the live pools in this process.

use yew::prelude::*;

use crate::components::skeleton::LoadingSpinner;
use crate::services::ApiService;
use crate::types::{HttpListener, TcpUdpListener, TcpUdpProtocolInfo};

#[function_component]
pub fn TcpUdp() -> Html {
    let listeners = use_state(Vec::<TcpUdpListener>::new);
    let http_listeners = use_state(Vec::<HttpListener>::new);
    let protocols = use_state(Vec::<TcpUdpProtocolInfo>::new);
    let loading = use_state(|| true);
    let error = use_state(|| None as Option<String>);

    {
        let listeners = listeners.clone();
        let http_listeners = http_listeners.clone();
        let protocols = protocols.clone();
        let loading = loading.clone();
        let error = error.clone();

        use_effect_with((), move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.list_tcp_udp_listeners().await {
                    Ok(list) => listeners.set(list.listeners),
                    Err(e) => error.set(Some(e.to_string())),
                }
                if let Ok(list) = api.list_http_listeners().await {
                    http_listeners.set(list.listeners);
                }
                if let Ok(p) = api.list_tcp_udp_protocols().await {
                    protocols.set(p);
                }
                loading.set(false);
            });
            || ()
        });
    }

    let refresh = {
        let listeners = listeners.clone();
        let http_listeners = http_listeners.clone();
        let error = error.clone();
        Callback::from(move |_| {
            let listeners = listeners.clone();
            let http_listeners = http_listeners.clone();
            let error = error.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiService::new().list_tcp_udp_listeners().await {
                    Ok(list) => {
                        listeners.set(list.listeners);
                        error.set(None);
                    }
                    Err(e) => error.set(Some(e.to_string())),
                }
                if let Ok(list) = ApiService::new().list_http_listeners().await {
                    http_listeners.set(list.listeners);
                }
            });
        })
    };

    html! {
        <div>
            <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-6">
                <div>
                    <h1 class="text-2xl font-bold mb-1">{ "TCP/UDP Listeners" }</h1>
                    <p class="text-secondary text-sm">
                        { "Listeners bound by this process. Definitions live in the global [tcp.protocols] and [udp.protocols] maps; editing them requires a restart." }
                    </p>
                </div>
                <button
                    onclick={refresh}
                    class="px-4 py-2 rounded-lg bg-tertiary hover:opacity-80 transition"
                >
                    { "Refresh" }
                </button>
            </div>

            if let Some(err) = &*error {
                <div class="bg-red-900/20 border border-red-500/30 rounded-lg p-4 mb-4 text-red-400">
                    { err }
                </div>
            }

            if !(*http_listeners).is_empty() {
                <div class="mb-8">
                    <h2 class="text-sm font-semibold text-secondary uppercase tracking-wider mb-2">
                        { "HTTP / HTTPS / HTTP3 listeners" }
                    </h2>
                    <div class="bg-secondary rounded-lg border border-default overflow-x-auto">
                        <table class="w-full">
                            <thead class="bg-tertiary">
                                <tr>
                                    <th class="text-left px-4 py-3 text-sm font-medium text-secondary">{ "Name" }</th>
                                    <th class="text-left px-4 py-3 text-sm font-medium text-secondary">{ "Transport" }</th>
                                    <th class="text-left px-4 py-3 text-sm font-medium text-secondary">{ "Bound" }</th>
                                    <th class="text-left px-4 py-3 text-sm font-medium text-secondary">{ "Protocols" }</th>
                                    <th class="text-left px-4 py-3 text-sm font-medium text-secondary">{ "Default site" }</th>
                                    <th class="text-left px-4 py-3 text-sm font-medium text-secondary">{ "Sites" }</th>
                                    <th class="text-left px-4 py-3 text-sm font-medium text-secondary">{ "State" }</th>
                                </tr>
                            </thead>
                            <tbody>
                                { for http_listeners.iter().map(|listener| html! {
                                    <tr class="border-t border-default">
                                        <td class="px-4 py-3 text-sm text-primary font-mono">{ &listener.id }</td>
                                        <td class="px-4 py-3 text-sm uppercase text-secondary">{ &listener.transport }</td>
                                        <td class="px-4 py-3 text-sm text-primary font-mono">{ listener.bound_addr.clone().unwrap_or_else(|| listener.configured_addr.clone()) }</td>
                                        <td class="px-4 py-3 text-sm text-secondary">
                                            { if listener.tls { "tls" } else { "plain" } }
                                            { if listener.http2 { " + h2" } else { "" } }
                                            { if listener.http3 { " + h3" } else { "" } }
                                        </td>
                                        <td class="px-4 py-3 text-sm text-primary">{ listener.default_site.clone().unwrap_or_else(|| "—".to_string()) }</td>
                                        <td class="px-4 py-3 text-sm text-primary">{ listener.site_count }</td>
                                        <td class="px-4 py-3 text-sm text-secondary">{ &listener.state }</td>
                                    </tr>
                                })}
                            </tbody>
                        </table>
                    </div>
                </div>
            }

            if *loading {
                <div class="flex justify-center py-20">
                    <LoadingSpinner />
                </div>
            } else if (*listeners).is_empty() {
                <div class="bg-secondary rounded-lg border border-default p-12 text-center">
                    <p class="text-secondary">
                        { "No TCP/UDP listeners are bound. Enable [tcp] or [udp] and declare protocols in main.toml." }
                    </p>
                </div>
            } else {
                <div class="bg-secondary rounded-lg border border-default overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-tertiary">
                            <tr>
                                <th class="text-left px-4 py-3 text-sm font-medium text-secondary">{ "Transport" }</th>
                                <th class="text-left px-4 py-3 text-sm font-medium text-secondary">{ "Protocol" }</th>
                                <th class="text-left px-4 py-3 text-sm font-medium text-secondary">{ "Port" }</th>
                                <th class="text-left px-4 py-3 text-sm font-medium text-secondary">{ "Upstream" }</th>
                                <th class="text-left px-4 py-3 text-sm font-medium text-secondary">{ "Active" }</th>
                                <th class="text-left px-4 py-3 text-sm font-medium text-secondary">{ "State" }</th>
                            </tr>
                        </thead>
                        <tbody>
                            { for listeners.iter().map(|listener| html! {
                                <tr class="border-t border-default">
                                    <td class="px-4 py-3 text-sm uppercase text-secondary">{ &listener.transport }</td>
                                    <td class="px-4 py-3 text-sm text-primary">{ &listener.protocol }</td>
                                    <td class="px-4 py-3 text-sm text-primary font-mono">{ listener.port }</td>
                                    <td class="px-4 py-3 text-sm text-primary font-mono truncate max-w-[240px]" title={listener.upstream.clone()}>
                                        { &listener.upstream }
                                    </td>
                                    <td class="px-4 py-3 text-sm text-primary">{ listener.active_connections }</td>
                                    <td class="px-4 py-3 text-sm">
                                        <span class={if listener.enabled && listener.bound {
                                            "px-2 py-1 rounded bg-green-500/10 text-green-400"
                                        } else {
                                            "px-2 py-1 rounded bg-tertiary text-secondary"
                                        }}>
                                            { if listener.enabled && listener.bound { "Bound" } else { "Inactive" } }
                                        </span>
                                    </td>
                                </tr>
                            })}
                        </tbody>
                    </table>
                </div>
            }

            if !(*protocols).is_empty() {
                <div class="mt-8">
                    <h2 class="text-sm font-semibold text-secondary uppercase tracking-wider mb-2">
                        { "Configured protocol profiles" }
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
        </div>
    }
}
