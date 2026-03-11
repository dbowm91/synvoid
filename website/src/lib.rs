use wasm_bindgen::prelude::*;
use yew::prelude::*;
use yew_router::prelude::*;

mod components;
mod pages;

use components::{ChallengeSplash, Nav, Splash};
use pages::{Challenge, DocPage, Docs, Home, NotFound, SinglePage, SplashPage};

#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook_set();

    let _ = wasm_logger::init(wasm_logger::Config::default());

    web_sys::console::log_1(&"Starting Yew application...".into());

    yew::Renderer::<App>::new().render();
}

fn console_error_panic_hook_set() {
    console_error_panic_hook::set_once();
}

#[derive(Clone, Routable, PartialEq, Debug)]
pub enum Route {
    #[at("/")]
    Home,
    #[at("/splash")]
    Splash,
    #[at("/singlepage")]
    SinglePage,
    #[at("/challenge")]
    Challenge,
    #[at("/docs")]
    Docs,
    #[at("/docs/:name")]
    DocPage { name: String },
    #[not_found]
    #[at("/404")]
    NotFound,
}

fn switch(route: Route) -> Html {
    web_sys::console::log_1(&format!("Switching to route: {:?}", route).into());
    match route {
        Route::Home => html! { <Home /> },
        Route::Splash => html! { <SplashPage /> },
        Route::SinglePage => html! { <SinglePage /> },
        Route::Challenge => html! { <Challenge /> },
        Route::Docs => html! { <Docs /> },
        Route::DocPage { name } => html! { <DocPage {name} /> },
        Route::NotFound => html! { <NotFound /> },
    }
}

#[function_component]
pub fn App() -> Html {
    let show_splash = use_state(|| true);
    let on_splash_complete = {
        let show_splash = show_splash.clone();
        Callback::from(move |_| {
            show_splash.set(false);
        })
    };

    let is_challenge = use_state(|| {
        if let Some(window) = web_sys::window() {
            if let Ok(loc) = window.location().pathname() {
                return loc.starts_with("/challenge");
            }
        }
        false
    });

    let is_singlepage = use_state(|| {
        if let Some(window) = web_sys::window() {
            if let Ok(loc) = window.location().pathname() {
                return loc.starts_with("/singlepage");
            }
        }
        false
    });

    web_sys::console::log_1(&"App component rendering".into());

    html! {
        <>
            if *is_challenge {
                if *show_splash {
                    <ChallengeSplash on_complete={on_splash_complete} />
                }
            } else {
                if *show_splash {
                    <Splash on_complete={on_splash_complete} />
                }
            }
            if !*show_splash {
                <BrowserRouter>
                    <div style="background-color: #0a0a0f; min-height: 100vh; color: #f0f0f5;">
                        if !*is_singlepage {
                            <Nav />
                        }
                        <Switch<Route> render={switch} />
                    </div>
                </BrowserRouter>
            }
        </>
    }
}
