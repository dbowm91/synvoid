use crate::components::skeleton::LoadingSpinner;
use crate::components::toast::{toast_error, toast_success};
use crate::services::ApiService;
use crate::types::SiteUpstreams;
use yew::prelude::*;

#[function_component]
pub fn Upstreams() -> Html {
    let upstreams = use_state(Vec::<SiteUpstreams>::new);
    let loading = use_state(|| true);
    let error = use_state(|| None::<String>);
    let filter = use_state(String::new);
    // site_id of the health check currently in flight, so the row that is
    // working can say so and no second trigger can be queued behind it
    let checking = use_state(|| None::<String>);

    {
        let upstreams = upstreams.clone();
        let loading = loading.clone();
        let error = error.clone();
        use_effect(move || {
            let upstreams = upstreams.clone();
            let loading = loading.clone();
            let error = error.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.get::<Vec<SiteUpstreams>>("/upstreams").await {
                    Ok(data) => {
                        upstreams.set(data);
                        error.set(None);
                    }
                    Err(e) => {
                        error.set(Some(e.to_string()));
                    }
                }
                loading.set(false);
            });
            || ()
        });
    }

    let refresh = {
        let upstreams = upstreams.clone();
        let loading = loading.clone();
        let error = error.clone();
        Callback::from(move |_: MouseEvent| {
            let upstreams = upstreams.clone();
            let loading = loading.clone();
            let error = error.clone();
            loading.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.get::<Vec<SiteUpstreams>>("/upstreams").await {
                    Ok(data) => {
                        upstreams.set(data);
                        error.set(None);
                    }
                    Err(e) => {
                        error.set(Some(e.to_string()));
                    }
                }
                loading.set(false);
            });
        })
    };

    let health_check = {
        let checking = checking.clone();
        move |site_id: String| {
            let checking = checking.clone();
            Callback::from(move |_: MouseEvent| {
                // a check already in flight means one more click would queue a
                // duplicate probe of the same upstreams
                if (*checking).is_some() {
                    return;
                }
                let site_id = site_id.clone();
                checking.set(Some(site_id.clone()));
                let checking = checking.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let api = ApiService::new();
                    // the Result used to be discarded, leaving the operator with no
                    // way to tell an accepted trigger from a rejected one
                    match api.trigger_health_check(&site_id).await {
                        Ok(_) => toast_success("Health check triggered"),
                        Err(e) => toast_error(&format!("Failed to trigger health check: {}", e)),
                    }
                    checking.set(None);
                });
            })
        }
    };

    let filter_lower = filter.to_lowercase();
    let filtered: Vec<&SiteUpstreams> = (*upstreams)
        .iter()
        .filter(|site| {
            if filter_lower.is_empty() {
                return true;
            }
            site.site_id.to_lowercase().contains(&filter_lower)
                || site.default_upstream.to_lowercase().contains(&filter_lower)
                || site
                    .backends
                    .iter()
                    .any(|b| b.url.to_lowercase().contains(&filter_lower))
        })
        .collect();

    let total_backends: usize = filtered.iter().map(|s| s.backends.len()).sum();
    let healthy_count: usize = filtered
        .iter()
        .flat_map(|s| s.backends.iter())
        .filter(|b| b.healthy)
        .count();
    let unhealthy_count = total_backends.saturating_sub(healthy_count);

    html! {
        <div>
            <div class="flex justify-between items-center mb-6">
                <h1 class="text-2xl font-bold">{ "Upstream Servers" }</h1>
                <div class="flex gap-3">
                    <button
                        class="px-4 py-2 bg-tertiary text-primary rounded-lg hover:opacity-80"
                        onclick={refresh}
                    >
                        { "Refresh Status" }
                    </button>
                </div>
            </div>

            if *loading {
                <LoadingSpinner />
            } else if let Some(err) = &*error {
                <div class="bg-red-500/10 border border-red-500/30 rounded-lg p-4 mb-6">
                    <p class="text-red-500">{ format!("Failed to load upstreams: {}", err) }</p>
                </div>
            } else if (*upstreams).is_empty() {
                <div class="bg-secondary rounded-lg border border-default p-8 text-center">
                    <p class="text-secondary">{ "No sites configured. Add a site to see upstream servers." }</p>
                </div>
            } else {
                <div class="mb-4">
                    <input
                        type="text"
                        placeholder="Filter upstreams by site ID or backend URL..."
                        value={(*filter).clone()}
                        oninput={{
                            let filter = filter.clone();
                            Callback::from(move |e: InputEvent| {
                                let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                filter.set(input.value());
                            })
                        }}
                        class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                </div>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
                    <div class="bg-secondary rounded-lg border border-default p-4">
                        <div class="flex items-center gap-3">
                            <div class="p-3 rounded-lg bg-blue-500/10 text-blue-500">
                                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
                                </svg>
                            </div>
                            <div>
                                <p class="text-sm text-secondary">{ "Total Backends" }</p>
                                <p class="text-2xl font-bold">{ total_backends }</p>
                            </div>
                        </div>
                    </div>
                    <div class="bg-secondary rounded-lg border border-default p-4">
                        <div class="flex items-center gap-3">
                            <div class="p-3 rounded-lg bg-green-500/10 text-green-500">
                                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                                </svg>
                            </div>
                            <div>
                                <p class="text-sm text-secondary">{ "Healthy" }</p>
                                <p class="text-2xl font-bold">{ healthy_count }</p>
                            </div>
                        </div>
                    </div>
                    <div class="bg-secondary rounded-lg border border-default p-4">
                        <div class="flex items-center gap-3">
                            <div class="p-3 rounded-lg bg-red-500/10 text-red-500">
                                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                                </svg>
                            </div>
                            <div>
                                <p class="text-sm text-secondary">{ "Unhealthy" }</p>
                                <p class="text-2xl font-bold">{ unhealthy_count }</p>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="space-y-6">
                    if filtered.is_empty() && !filter.is_empty() {
                        <div class="bg-secondary rounded-lg border border-default p-8 text-center">
                            <p class="text-secondary">{ "No upstreams match your filter." }</p>
                        </div>
                    } else {
                        {for filtered.iter().map(|site| {
                            html! {
                                <div class="bg-secondary rounded-lg border border-default p-4">
                                    <div class="flex items-center justify-between mb-4">
                                        <div>
                                            <h3 class="text-lg font-semibold">{ &site.site_id }</h3>
                                            <p class="text-sm text-secondary">
                                                { format!("Default: {}", site.default_upstream) }
                                            </p>
                                        </div>
                                        <button
                                            class="px-3 py-1 text-xs bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
                                            disabled={(*checking).is_some()}
                                            onclick={health_check(site.site_id.clone())}
                                        >
                                            { if checking.as_deref() == Some(site.site_id.as_str()) {
                                                "Checking..."
                                            } else {
                                                "Check Health"
                                            } }
                                        </button>
                                    </div>

                                    <div class="space-y-3">
                                        {for site.backends.iter().map(|backend| {
                                            let status_color = if backend.healthy { "bg-green-500" } else { "bg-red-500" };
                                            let status_text = if backend.healthy { "Healthy" } else { "Unhealthy" };

                                            html! {
                                                <div class="flex flex-wrap items-center justify-between gap-3 p-3 bg-tertiary rounded border border-default">
                                                    <div class="flex items-center gap-3 min-w-0">
                                                        <span class={format!("w-2.5 h-2.5 rounded-full shrink-0 {}", status_color)} />
                                                        <span class="font-mono text-sm break-all min-w-0">{ &backend.url }</span>
                                                        <span class="text-xs text-secondary shrink-0">{ status_text }</span>
                                                    </div>
                                                    <div class="flex items-center gap-6 text-sm text-secondary shrink-0">
                                                        <span>{ format!("{}/{} conn", backend.current_connections, backend.max_connections) }</span>
                                                        <span>{ format!("weight: {}", backend.weight) }</span>
                                                        if backend.consecutive_failures > 0 {
                                                            <span class="text-red-500">{ format!("{} failures", backend.consecutive_failures) }</span>
                                                        } else {
                                                            <span class="text-green-500">{ "OK" }</span>
                                                        }
                                                    </div>
                                                </div>
                                            }
                                        })}
                                    </div>
                                </div>
                            }
                        })}
                    }
                </div>
            }
        </div>
    }
}
