use yew::prelude::*;
use yew_router::prelude::*;

use crate::components::layout::Sidebar;
use crate::components::ToastContainer;
use crate::hooks::use_theme::*;
use crate::pages::{
    Dashboard, Logs, Probes, RequestLogs, Settings, SiteEditor, Sites, TcpUdp, TierKeys, Upstreams,
    Workers,
};
use crate::types::UpdateThemeRequest;

#[derive(Clone, Routable, PartialEq)]
pub enum Route {
    #[at("/")]
    Home,
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
    #[at("/tcp-udp")]
    TcpUdp,
    #[at("/probes")]
    Probes,
    #[at("/settings")]
    Settings,
    #[at("/tier-keys")]
    TierKeys,
    #[at("/workers")]
    Workers,
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
        Route::Logs => html! { <Logs /> },
        Route::RequestLogs => html! { <RequestLogs /> },
        Route::Upstreams => html! { <Upstreams /> },
        Route::Sites => html! { <Sites /> },
        Route::SiteEditor { id } => html! { <SiteEditor id={id} /> },
        Route::TcpUdp => html! { <TcpUdp /> },
        Route::Probes => html! { <Probes /> },
        Route::Settings => html! { <Settings /> },
        Route::TierKeys => html! { <TierKeys /> },
        Route::Workers => html! { <Workers /> },
        Route::NotFound => html! { <div class="text-center py-20">
            <h1 class="text-4xl font-bold mb-4">{ "404" }</h1>
            <p class="text-secondary">{ "Page not found" }</p>
        </div> },
    }
}
