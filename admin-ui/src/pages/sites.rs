use yew::prelude::*;
use yew_router::prelude::*;

use crate::app::Route;
use crate::services::ApiService;
use crate::types::SiteInfo;

#[function_component]
pub fn Sites() -> Html {
    let sites = use_state(|| Vec::<SiteInfo>::new());
    let loading = use_state(|| true);
    let error = use_state(|| None as Option<String>);

    {
        let sites = sites.clone();
        let loading = loading.clone();
        let error = error.clone();
        use_effect_with((), move |_| {
            let sites = sites.clone();
            let loading = loading.clone();
            let error = error.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.list_sites().await {
                    Ok(s) => sites.set(s),
                    Err(e) => error.set(Some(e)),
                }
                loading.set(false);
            });
            || {}
        });
    }

    let on_delete = {
        let sites = sites.clone();
        Callback::from(move |site_id: String| {
            let sites = sites.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.delete_site(&site_id).await {
                    Ok(_) => {
                        let mut current = (*sites).clone();
                        current.retain(|s| s.id != site_id);
                        sites.set(current);
                    }
                    Err(e) => {
                        tracing::error!("Failed to delete site: {}", e);
                    }
                }
            });
        })
    };

    html! {
        <div>
            <div class="flex justify-between items-center mb-6">
                <h1 class="text-2xl font-bold">{ "Sites" }</h1>
                <Link<Route>
                    to={Route::Sites}
                    classes="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                    { "+ Add Site" }
                </Link<Route>>
            </div>

            if let Some(err) = &*error {
                <div class="bg-red-500/10 border border-red-500 rounded-lg p-4 text-red-500 mb-4">
                    { err }
                </div>
            }

            if *loading {
                <div class="text-center py-8">{ "Loading..." }</div>
            } else if sites.is_empty() {
                <div class="text-center py-8 text-secondary">
                    { "No sites configured. Click '+ Add Site' to create one." }
                </div>
            } else {
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    { for sites.iter().map(|site| {
                        let site_id = site.id.clone();
                        let domains = site.domains.clone();
                        let routes_count = site.routes.keys().count();
                        html! {
                            <SiteCard
                                site_id={site_id.clone()}
                                domains={domains}
                                upstream={site.default_upstream.clone()}
                                routes={routes_count}
                                healthy={true}
                                on_delete={on_delete.clone()}
                            />
                        }
                    })}
                </div>
            }
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct SiteCardProps {
    site_id: String,
    domains: Vec<String>,
    upstream: String,
    routes: usize,
    healthy: bool,
    on_delete: Callback<String>,
}

#[function_component]
fn SiteCard(props: &SiteCardProps) -> Html {
    let status_class = if props.healthy {
        "bg-green-500"
    } else {
        "bg-red-500"
    };
    let primary_domain = props.domains.first().cloned().unwrap_or_else(|| props.site_id.clone());

    let on_delete = {
        let site_id = props.site_id.clone();
        let on_delete = props.on_delete.clone();
        Callback::from(move |_| {
            on_delete.emit(site_id.clone());
        })
    };

    html! {
        <div class="bg-secondary rounded-lg border border-default overflow-hidden">
            <div class="p-4 border-b border-default flex items-center justify-between">
                <div class="flex items-center gap-3">
                    <span class={format!("w-3 h-3 rounded-full {}", status_class)} />
                    <h3 class="text-lg font-semibold">{ &primary_domain }</h3>
                </div>
                <div class="flex gap-2">
                    <Link<Route>
                        to={Route::SiteEditor { id: props.site_id.clone() }}
                        classes="px-3 py-1 text-sm bg-tertiary text-primary rounded hover:opacity-80"
                    >
                        { "Edit" }
                    </Link<Route>>
                    <button onclick={on_delete} class="px-3 py-1 text-sm bg-red-600 text-white rounded hover:bg-red-700">
                        { "Delete" }
                    </button>
                </div>
            </div>

            <div class="p-4">
                <div class="mb-3">
                    <p class="text-sm text-secondary">{ "Domains" }</p>
                    <p class="text-primary">{ props.domains.join(", ") }</p>
                </div>

                <div class="mb-3">
                    <p class="text-sm text-secondary">{ "Default Upstream" }</p>
                    <p class="font-mono text-primary">{ &props.upstream }</p>
                </div>

                <div>
                    <p class="text-sm text-secondary">{ "Route Rules" }</p>
                    <p class="text-primary">{ format!("{} routes configured", props.routes) }</p>
                </div>
            </div>
        </div>
    }
}
