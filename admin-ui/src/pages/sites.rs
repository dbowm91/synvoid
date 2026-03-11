use yew::prelude::*;
use yew_router::prelude::*;

use crate::app::Route;

#[function_component]
pub fn Sites() -> Html {
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

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <SiteCard
                    domains={vec!["example.com".to_string(), "www.example.com".to_string()]}
                    upstream="http://127.0.0.1:8000"
                    routes={3}
                    healthy=true
                />

                <SiteCard
                    domains={vec!["api.example.com".to_string()]}
                    upstream="http://api.internal:8001"
                    routes={5}
                    healthy=true
                />

                <SiteCard
                    domains={vec!["admin.example.com".to_string()]}
                    upstream="http://admin.internal:8002"
                    routes={1}
                    healthy=false
                />
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct SiteCardProps {
    domains: Vec<String>,
    upstream: String,
    routes: usize,
    healthy: bool,
}

#[function_component]
fn SiteCard(props: &SiteCardProps) -> Html {
    let status_class = if props.healthy {
        "bg-green-500"
    } else {
        "bg-red-500"
    };
    let primary_domain = props.domains.first().cloned().unwrap_or_default();

    html! {
        <div class="bg-secondary rounded-lg border border-default overflow-hidden">
            <div class="p-4 border-b border-default flex items-center justify-between">
                <div class="flex items-center gap-3">
                    <span class={format!("w-3 h-3 rounded-full {}", status_class)} />
                    <h3 class="text-lg font-semibold">{ &primary_domain }</h3>
                </div>
                <div class="flex gap-2">
                    <Link<Route>
                        to={Route::SiteEditor { id: primary_domain.clone() }}
                        classes="px-3 py-1 text-sm bg-tertiary text-primary rounded hover:opacity-80"
                    >
                        { "Edit" }
                    </Link<Route>>
                    <button class="px-3 py-1 text-sm bg-red-600 text-white rounded hover:bg-red-700">
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
