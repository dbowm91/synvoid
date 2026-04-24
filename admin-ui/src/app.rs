use yew::prelude::*;
use yew_router::prelude::*;

use crate::components::layout::Sidebar;
use crate::components::ToastContainer;
use crate::hooks::use_theme::*;
use crate::pages::{
    Alerts, Dashboard, Dns, Honeypot, Icmp, Login, Logs, Mesh, Probes, ProcessManagement,
    RequestLogs, Settings, SiteDetail, SiteEditor, Sites, SystemStatus, ThreatLevel, TierKeys,
    TrafficShaping, Upstreams, Workers,
};
use crate::types::UpdateThemeRequest;

#[derive(Clone, Routable, PartialEq)]
pub enum Route {
    #[at("/")]
    Home,
    #[at("/login")]
    Login,
    #[at("/dashboard")]
    Dashboard,
    #[at("/logs")]
    Logs,
    #[at("/logs/requests")]
    RequestLogs,
    #[at("/upstreams")]
    Upstreams,
    #[at("/sites")]
    Sites,
    #[at("/sites/:id")]
    SiteEditor { id: String },
    #[at("/sites/:id/stats")]
    SiteDetail { id: String },
    #[at("/probes")]
    Probes,
    #[at("/dns")]
    Dns,
    #[at("/settings")]
    Settings,
    #[at("/mesh")]
    Mesh,
    #[at("/process")]
    ProcessManagement,
    #[at("/tier-keys")]
    TierKeys,
    #[at("/workers")]
    Workers,
    #[at("/alerts")]
    Alerts,
    #[at("/system-status")]
    SystemStatus,
    #[at("/threat-level")]
    ThreatLevel,
    #[at("/honeypot")]
    Honeypot,
    #[at("/icmp")]
    Icmp,
    #[at("/traffic-shaping")]
    TrafficShaping,
    #[not_found]
    #[at("/404")]
    NotFound,
}

#[function_component]
pub fn App() -> Html {
    let (theme_data, update_theme) = use_api_theme();
    let theme = use_state(|| Theme::Dark);

    let current_theme = (*theme).clone();

    let toggle_theme = {
        let theme = theme.clone();
        let update_theme = update_theme.clone();
        Callback::from(move |_| {
            let new_theme = theme.toggle();
            theme.set(new_theme);

            let request = UpdateThemeRequest {
                preset: Some(new_theme.to_preset().to_string()),
                mode: None,
                allow_only: None,
            };
            update_theme.emit(request);
        })
    };

    let theme_class = current_theme.class().to_string();

    html! {
        <BrowserRouter>
            <ToastContainer />
            <div class={classes!("min-h-screen", "flex", &theme_class)}>
                <Sidebar
                    theme={current_theme}
                    on_toggle_theme={toggle_theme.clone()}
                />
                <main class="flex-1 p-6 overflow-auto">
                    <Switch<Route> render={switch} />
                </main>
            </div>
        </BrowserRouter>
    }
}

fn switch(route: Route) -> Html {
    match route {
        Route::Home | Route::Dashboard => html! { <Dashboard /> },
        Route::Login => html! { <Login /> },
        Route::Logs => html! { <Logs /> },
        Route::RequestLogs => html! { <RequestLogs /> },
        Route::Upstreams => html! { <Upstreams /> },
        Route::Sites => html! { <Sites /> },
        Route::SiteEditor { id } => html! { <SiteEditor id={id} /> },
        Route::SiteDetail { id } => html! { <SiteDetail id={id} /> },
        Route::Probes => html! { <Probes /> },
        Route::Dns => html! { <Dns /> },
        Route::Settings => html! { <Settings /> },
        Route::Mesh => html! { <Mesh /> },
        Route::ProcessManagement => html! { <ProcessManagement /> },
        Route::TierKeys => html! { <TierKeys /> },
        Route::Workers => html! { <Workers /> },
        Route::Alerts => html! { <Alerts /> },
        Route::SystemStatus => html! { <SystemStatus /> },
        Route::ThreatLevel => html! { <ThreatLevel /> },
        Route::Honeypot => html! { <Honeypot /> },
        Route::Icmp => html! { <Icmp /> },
        Route::TrafficShaping => html! { <TrafficShaping /> },
        Route::NotFound => html! { <div class="text-center py-20">
            <h1 class="text-4xl font-bold mb-4">{ "404" }</h1>
            <p class="text-secondary">{ "Page not found" }</p>
        </div> },
    }
}
