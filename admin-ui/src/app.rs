use yew::prelude::*;
use yew_router::prelude::*;

use crate::components::layout::Sidebar;
use crate::hooks::use_theme::*;
use crate::pages::{
    Dashboard, Logs, Probes, RequestLogs, Settings, SiteEditor, Sites, TcpUdp, Upstreams,
};

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
    #[not_found]
    #[at("/404")]
    NotFound,
}

pub struct App {
    theme: Theme,
}

pub enum Msg {
    ToggleTheme,
}

impl Component for App {
    type Message = Msg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        Self { theme: Theme::Dark }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::ToggleTheme => {
                self.theme = match self.theme {
                    Theme::Dark => Theme::Light,
                    Theme::Light => Theme::Dark,
                };
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let toggle_theme = ctx.link().callback(|_| Msg::ToggleTheme);
        let theme_class = self.theme.class().to_string();

        html! {
            <BrowserRouter>
                <div class={classes!("min-h-screen", "flex", &theme_class)}>
                    <Sidebar
                        theme={self.theme}
                        on_toggle_theme={toggle_theme.clone()}
                    />
                    <main class="flex-1 p-6 overflow-auto">
                        <Switch<Route> render={switch} />
                    </main>
                </div>
            </BrowserRouter>
        }
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
        Route::NotFound => html! { <div class="text-center py-20">
            <h1 class="text-4xl font-bold mb-4">{ "404" }</h1>
            <p class="text-secondary">{ "Page not found" }</p>
        </div> },
    }
}
