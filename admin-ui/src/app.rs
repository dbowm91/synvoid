use gloo::timers::future::TimeoutFuture;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_router::prelude::*;

use crate::components::layout::{Capabilities, Sidebar};
use crate::components::ToastContainer;
use crate::hooks::use_theme::*;
use crate::pages::{
    Alerts, Dashboard, Dns, Honeypot, Icmp, Login, Logs, Mesh, Probes, ProcessManagement,
    RequestLogs, Settings, SiteDetail, SiteEditor, Sites, SystemStatus, TcpUdp, ThreatLevel,
    TierKeys, TrafficShaping, Upstreams, Workers,
};
use crate::services::api::{set_session_expired_handler, ApiService};
use crate::types::UpdateThemeRequest;

// `Debug` is asserted on in sidebar tests that verify nav active-state
// resolution; it is not otherwise used by the router.
#[derive(Clone, Routable, PartialEq, Debug)]
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
    #[at("/tcp-udp")]
    TcpUdp,
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
    let (_theme_data, update_theme) = use_api_theme();
    let theme = use_state(|| Theme::Dark);
    let auth_state = use_state(|| AuthState::Restoring);
    // `None` until `/system/capabilities` resolves. The route guard holds
    // capability-gated routes in a loading state while this is `None` so a
    // deep link cannot mount a page whose endpoints were never registered.
    let capabilities = use_state(|| Option::<Capabilities>::None);
    let sidebar_open = use_state(|| false);

    {
        let capabilities = capabilities.clone();
        use_effect_with((), move |_| {
            let capabilities = capabilities.clone();
            spawn_local(async move {
                // `None` means "still resolving", and the route guard holds
                // every gated route on it. Leaving the state unset on error
                // would therefore lock DNS/Mesh/ICMP/Honeypot/Process
                // Management at "Checking available features…" indefinitely, so
                // a transient failure is retried and then resolved to a
                // fail-closed terminal state.
                const ATTEMPTS: u32 = 3;
                let mut backoff_ms = 300u32;
                for attempt in 1..=ATTEMPTS {
                    match ApiService::new().get_capabilities().await {
                        Ok(cap) => {
                            capabilities.set(Some(cap));
                            return;
                        }
                        Err(error) if attempt < ATTEMPTS => {
                            tracing::warn!(
                                "capabilities fetch attempt {}/{} failed: {}",
                                attempt,
                                ATTEMPTS,
                                error
                            );
                            TimeoutFuture::new(backoff_ms).await;
                            backoff_ms = backoff_ms.saturating_mul(2);
                        }
                        Err(error) => {
                            tracing::error!(
                                "capabilities unavailable after {} attempts: {}",
                                ATTEMPTS,
                                error
                            );
                            capabilities.set(Some(Capabilities::none_enabled()));
                        }
                    }
                }
            });
            || ()
        });
    }

    // Navigating always closes the drawer; otherwise the page you picked stays
    // hidden behind an overlay on mobile. `Sidebar` invokes `on_close` from
    // each `NavItem` click rather than subscribing to the router, so the
    // teardown does not depend on a router subscription API.

    {
        let auth_state = auth_state.clone();
        use_effect_with((), move |_| {
            let auth_state = auth_state.clone();
            spawn_local(async move {
                match ApiService::restore_session().await {
                    Ok(_) => {
                        auth_state.set(AuthState::Authenticated);
                    }
                    Err(_) => {
                        auth_state.set(AuthState::Unauthenticated);
                    }
                }
            });
            || ()
        });
    }

    {
        let auth_state = auth_state.clone();
        use_effect_with((), move |_| {
            let auth_state = auth_state.clone();
            set_session_expired_handler(Some(Callback::from(move |_| {
                auth_state.set(AuthState::Unauthenticated);
            })));
            || set_session_expired_handler(None)
        });
    }

    let current_theme = *theme;

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

    let on_logout = {
        let auth_state = auth_state.clone();
        Callback::from(move |_| {
            let auth_state = auth_state.clone();
            spawn_local(async move {
                match ApiService::logout().await {
                    Ok(())
                    | Err(crate::services::api::ApiError {
                        status: 401..=403, ..
                    }) => {
                        auth_state.set(AuthState::Unauthenticated);
                        if let Some(window) = web_sys::window() {
                            let _ = window.location().set_href("/login");
                        }
                    }
                    Err(error) => {
                        web_sys::console::error_1(&error.to_string().into());
                    }
                }
            });
        })
    };

    let on_authenticated = {
        let auth_state = auth_state.clone();
        Callback::from(move |_| auth_state.set(AuthState::Authenticated))
    };

    let on_close_sidebar: Callback<()> = {
        let sidebar_open = sidebar_open.clone();
        Callback::from(move |_: ()| sidebar_open.set(false))
    };
    let on_close_scrim = on_close_sidebar.reform(|_: MouseEvent| ());
    let on_open_sidebar: Callback<()> = {
        let sidebar_open = sidebar_open.clone();
        Callback::from(move |_: ()| sidebar_open.set(true))
    };
    let on_open_scrim = on_open_sidebar.reform(|_: MouseEvent| ());

    let theme_class = current_theme.class().to_string();

    match *auth_state {
        AuthState::Restoring => html! {
            <div class="min-h-screen flex items-center justify-center bg-primary">
                <div class="text-secondary">{"Restoring session..."}</div>
            </div>
        },
        AuthState::Unauthenticated => html! {
            <BrowserRouter>
                <ToastContainer />
                <Switch<Route> render={Callback::from({
                    let on_authenticated = on_authenticated.clone();
                    move |route| switch_unauthenticated(route, on_authenticated.clone())
                })} />
            </BrowserRouter>
        },
        AuthState::Authenticated => html! {
            <BrowserRouter>
                <ToastContainer />
                <div class={classes!("min-h-screen", "flex", &theme_class)}>
                    // Scrim only exists while the drawer is open; below `md` the
                    // nav is pinned and this never renders meaningfully.
                    if *sidebar_open {
                        <div
                            class="fixed inset-0 z-30 bg-black/50 md:hidden"
                            onclick={on_close_scrim.clone()}
                            aria-hidden="true"
                        />
                    }
                    <Sidebar
                        theme={current_theme}
                        on_toggle_theme={toggle_theme.clone()}
                        on_logout={on_logout}
                        capabilities={(*capabilities).clone()
                            .unwrap_or_default()}
                        open={*sidebar_open}
                        on_close={on_close_sidebar}
                    />
                    <main class="flex-1 min-w-0 p-4 md:p-6 overflow-auto">
                        <header class="md:hidden flex items-center gap-3 mb-4">
                            <button
                                onclick={on_open_scrim}
                                class="p-2 -ml-2 rounded-lg hover:bg-tertiary transition expand-hit"
                                aria-label="Open navigation"
                            >
                                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
                                </svg>
                            </button>
                            <span class="font-bold accent">{ "SynVoid" }</span>
                        </header>
                        <Switch<Route> render={Callback::from({
                            let capabilities = capabilities.clone();
                            move |route: Route| switch(route, (*capabilities).clone())
                        })} />
                    </main>
                </div>
            </BrowserRouter>
        },
    }
}

#[derive(PartialEq)]
enum AuthState {
    Restoring,
    Authenticated,
    Unauthenticated,
}

/// The capability a route depends on, if any.
///
/// The backend registers those route families behind cargo features
/// (`dns`, `mesh`, `icmp-filter`) or runtime state, so a deep link to one of
/// them on a build without the feature would otherwise mount a page whose
/// endpoints all 404.
fn required_capability(route: &Route) -> Option<Capability> {
    match route {
        Route::Mesh | Route::TierKeys => Some(Capability::MeshAdmin),
        Route::Dns => Some(Capability::DnsAdmin),
        Route::Icmp => Some(Capability::IcmpAdmin),
        Route::ProcessManagement => Some(Capability::ProcessManager),
        Route::Honeypot => Some(Capability::Honeypot),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    MeshAdmin,
    DnsAdmin,
    IcmpAdmin,
    ProcessManager,
    Honeypot,
}

fn capability_allowed(capability: Capability, cap: &Capabilities) -> bool {
    match capability {
        Capability::MeshAdmin => cap.mesh_admin,
        Capability::DnsAdmin => cap.dns_admin,
        Capability::IcmpAdmin => cap.icmp_admin,
        Capability::ProcessManager => cap.process_manager,
        Capability::Honeypot => cap.honeypot,
    }
}

fn capability_label(capability: Capability) -> &'static str {
    match capability {
        Capability::MeshAdmin => "mesh networking",
        Capability::DnsAdmin => "the DNS resolver",
        Capability::IcmpAdmin => "ICMP filtering",
        Capability::ProcessManager => "process management",
        Capability::Honeypot => "the port honeypot",
    }
}

#[function_component(CapabilityNotice)]
fn capability_notice(props: &CapabilityNoticeProps) -> Html {
    html! {
        <div class="max-w-lg mx-auto mt-16 text-center">
            <div class="inline-flex items-center justify-center w-12 h-12 rounded-full bg-tertiary mb-4">
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M12 9v2m0 4h.01M5.07 19h13.86c1.54 0 2.5-1.67 1.73-3L13.73 4c-.77-1.33-2.69-1.33-3.46 0L3.34 16c-.77 1.33.19 3 1.73 3z" />
                </svg>
            </div>
            <h2 class="text-lg font-semibold mb-2">{ "This section is not available" }</h2>
            <p class="text-secondary text-sm">
                { "This SynVoid build was compiled without " }
                <span class="text-primary">{ props.label }</span>
                { ". Rebuild with the corresponding feature enabled to manage it from the dashboard." }
            </p>
        </div>
    }
}

#[derive(Properties, PartialEq)]
pub struct CapabilityNoticeProps {
    pub label: &'static str,
}

fn switch(route: Route, capabilities: Option<Capabilities>) -> Html {
    if let Some(required) = required_capability(&route) {
        match &capabilities {
            // Hold the route rather than mounting it optimistically: the page
            // would otherwise fire its fetches and surface raw 404s.
            None => {
                return html! {
                    <div class="flex items-center justify-center py-20">
                        <div class="text-secondary">{ "Checking available features..." }</div>
                    </div>
                }
            }
            Some(cap) if !capability_allowed(required, cap) => {
                return html! { <CapabilityNotice label={capability_label(required)} /> }
            }
            Some(_) => {}
        }
    }

    match route {
        Route::Login => html! { <Dashboard /> },
        Route::Home | Route::Dashboard => html! { <Dashboard /> },
        Route::Logs => html! { <Logs /> },
        Route::RequestLogs => html! { <RequestLogs /> },
        Route::Upstreams => html! { <Upstreams /> },
        Route::Sites => html! { <Sites /> },
        Route::TcpUdp => html! { <TcpUdp /> },
        Route::SiteEditor { id } => html! { <SiteEditor id={id} /> },
        Route::SiteDetail { id } => html! { <SiteDetail id={id} /> },
        Route::Probes => html! { <Probes /> },
        Route::Dns => html! { <Dns /> },
        Route::Settings => html! {
            // Ungated as a route (server/http/logging work on every build), but
            // it still embeds feature-gated panels, so it needs the flags.
            <Settings capabilities={capabilities.clone().unwrap_or_default()} />
        },
        Route::Mesh => html! { <Mesh /> },
        Route::ProcessManagement => html! { <ProcessManagement /> },
        Route::TierKeys => html! { <TierKeys /> },
        Route::Workers => html! { <Workers /> },
        Route::Alerts => html! { <Alerts /> },
        Route::SystemStatus => html! {
            <SystemStatus capabilities={capabilities.clone().unwrap_or_default()} />
        },
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

fn switch_unauthenticated(route: Route, on_authenticated: Callback<()>) -> Html {
    match route {
        Route::Login
        | Route::Home
        | Route::Dashboard
        | Route::Logs
        | Route::RequestLogs
        | Route::Upstreams
        | Route::Sites
        | Route::TcpUdp
        | Route::SiteEditor { .. }
        | Route::SiteDetail { .. }
        | Route::Probes
        | Route::Dns
        | Route::Settings
        | Route::Mesh
        | Route::ProcessManagement
        | Route::TierKeys
        | Route::Workers
        | Route::Alerts
        | Route::SystemStatus
        | Route::ThreatLevel
        | Route::Honeypot
        | Route::Icmp
        | Route::TrafficShaping
        | Route::NotFound => html! { <Login on_authenticated={on_authenticated} /> },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_enabled() -> Capabilities {
        Capabilities {
            mesh_admin: true,
            dns_admin: true,
            icmp_admin: true,
            honeypot: true,
            process_manager: true,
        }
    }

    #[test]
    fn capability_gated_routes_declare_their_capability() {
        for (route, expected) in [
            (Route::Mesh, Capability::MeshAdmin),
            (Route::TierKeys, Capability::MeshAdmin),
            (Route::Dns, Capability::DnsAdmin),
            (Route::Icmp, Capability::IcmpAdmin),
            (Route::ProcessManagement, Capability::ProcessManager),
            (Route::Honeypot, Capability::Honeypot),
        ] {
            assert!(required_capability(&route) == Some(expected));
        }
    }

    #[test]
    fn always_available_routes_require_no_capability() {
        for route in [
            Route::Dashboard,
            Route::Logs,
            Route::RequestLogs,
            Route::Upstreams,
            Route::Sites,
            Route::Probes,
            Route::Settings,
            Route::Workers,
            Route::Alerts,
            Route::SystemStatus,
            Route::ThreatLevel,
            Route::TrafficShaping,
            Route::NotFound,
        ] {
            assert!(
                required_capability(&route).is_none(),
                "this route must stay ungated"
            );
        }
    }

    /// The regression this guard exists for: on a default build `icmp-filter`
    /// is off, `/api/icmp/*` is never registered, and a bookmark to `/icmp`
    /// used to mount the page and render a raw `HTTP 404` string.
    #[test]
    fn icmp_route_is_denied_when_the_build_lacks_icmp_filter() {
        let mut cap = all_enabled();
        cap.icmp_admin = false;
        assert!(!capability_allowed(Capability::IcmpAdmin, &cap));
        cap.icmp_admin = true;
        assert!(capability_allowed(Capability::IcmpAdmin, &cap));
    }

    #[test]
    fn disabling_mesh_denies_both_mesh_routes_only() {
        let mut cap = all_enabled();
        cap.mesh_admin = false;
        assert!(!capability_allowed(Capability::MeshAdmin, &cap));
        assert!(capability_allowed(Capability::DnsAdmin, &cap));
        assert!(capability_allowed(Capability::IcmpAdmin, &cap));
    }

    #[test]
    fn every_capability_maps_to_an_operator_readable_label() {
        for capability in [
            Capability::MeshAdmin,
            Capability::DnsAdmin,
            Capability::IcmpAdmin,
            Capability::ProcessManager,
            Capability::Honeypot,
        ] {
            assert!(!capability_label(capability).is_empty());
        }
    }
}
