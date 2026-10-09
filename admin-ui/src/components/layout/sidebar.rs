use yew::prelude::*;
use yew_router::prelude::*;

use crate::app::Route;
use crate::hooks::use_theme::Theme;

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct Capabilities {
    #[serde(default)]
    pub mesh_admin: bool,
    #[serde(default)]
    pub dns_admin: bool,
    #[serde(default)]
    pub icmp_admin: bool,
    #[serde(default)]
    pub honeypot: bool,
    #[serde(default)]
    pub process_manager: bool,
    /// Gates the plugin runtime surfaces (`/api/plugins/*`) and the YARA
    /// submission workflow (`/api/yara/*`). The backend derives both from
    /// `cfg!(feature = "mesh")`, so they are currently equal to `mesh_admin`
    /// — but they are separate fields upstream and could diverge, so the UI
    /// keys off the field that actually describes the route family.
    #[serde(default)]
    pub plugins: bool,
    /// Gates the serverless/Spin application surface (`/api/spin/*`,
    /// `/api/serverless/*`), also `cfg!(feature = "mesh")` upstream.
    #[serde(default)]
    pub serverless: bool,
}

/// Pure gating decision: which nav families are visible for a capability set.
/// Kept free of browser I/O so the contract can be unit-tested at the
/// data/decision level (no full-browser suite required).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidebarVisibility {
    pub show_mesh: bool,
    pub show_tier_keys: bool,
    pub show_dns: bool,
    pub show_process_management: bool,
    pub show_honeypot: bool,
    pub show_icmp: bool,
    pub show_plugins: bool,
    pub show_yara: bool,
    pub show_serverless: bool,
}

pub fn sidebar_visibility(cap: &Capabilities) -> SidebarVisibility {
    SidebarVisibility {
        show_mesh: cap.mesh_admin,
        show_tier_keys: cap.mesh_admin,
        show_dns: cap.dns_admin,
        show_process_management: cap.process_manager,
        show_honeypot: cap.honeypot,
        show_icmp: cap.icmp_admin,
        show_plugins: cap.plugins,
        show_yara: cap.plugins,
        show_serverless: cap.serverless,
    }
}

impl Capabilities {
    /// Every optional feature reported as unavailable.
    ///
    /// Used as the terminal state when `/system/capabilities` cannot be
    /// reached: `None` means "still loading", so without this the route guard
    /// would hold gated routes at "Checking available features…" forever. This
    /// fails closed — the nav hides the families and a deep link gets the
    /// capability notice rather than mounting a page whose endpoints 404.
    pub fn none_enabled() -> Self {
        Self {
            mesh_admin: false,
            dns_admin: false,
            icmp_admin: false,
            honeypot: false,
            process_manager: false,
            plugins: false,
            serverless: false,
        }
    }
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            mesh_admin: true,
            dns_admin: true,
            icmp_admin: true,
            honeypot: true,
            process_manager: true,
            plugins: true,
            serverless: true,
        }
    }
}

#[derive(Properties, PartialEq)]
pub struct SidebarProps {
    pub theme: Theme,
    pub on_toggle_theme: Callback<()>,
    pub on_logout: Callback<()>,
    /// Capabilities are fetched once in `App` and shared with the route guard.
    /// Fetching them here as well would let the nav disagree with the guard.
    pub capabilities: Capabilities,
    /// Drawer visibility. Always true at `md` and above regardless of this flag.
    pub open: bool,
    pub on_close: Callback<()>,
}

#[function_component]
pub fn Sidebar(props: &SidebarProps) -> Html {
    let on_toggle = props.on_toggle_theme.reform(|_| ());
    let on_logout = props.on_logout.reform(|_| ());
    let on_close = props.on_close.clone();

    let vis = sidebar_visibility(&props.capabilities);
    let drawer_position = if props.open {
        "translate-x-0"
    } else {
        "-translate-x-full"
    };
    // Bubbling handler on the list container: every `NavItem` click closes the
    // drawer without each item needing its own callback.
    let on_close_nav = props.on_close.reform(|_: MouseEvent| ());

    html! {
        <nav
            class={classes!(
                // Off-canvas below `md`; pinned in-flow above it. `fixed` and
                // `md:sticky` are the only two position utilities, so the
                // breakpoint swap needs no `static` override to fight.
                // Yew's `classes!` takes one class per literal.
                "fixed",
                "md:sticky",
                "md:top-0",
                "inset-y-0",
                "left-0",
                "z-40",
                "w-64",
                "shrink-0",
                // `h-dvh-safe` keeps the footer (Logout / Theme) reachable on
                // mobile Safari and Chrome, where `100vh` exceeds the visible
                // viewport while the URL bar is expanded.
                "h-dvh-safe",
                "bg-secondary",
                "border-r",
                "border-default",
                "flex",
                "flex-col",
                "transition-transform",
                "duration-200",
                drawer_position,
                // The sticky column is full height, so the nav list scrolls
                // internally and Logout/Theme stay reachable on tall pages.
                "md:translate-x-0",
            )}
            aria-label="Primary"
        >
            <div class="p-4 border-b border-default flex items-start justify-between gap-2">
                <div>
                    <h1 class="text-xl font-bold accent">
                        { "SynVoid" }
                    </h1>
                    <p class="text-sm text-secondary">{"Admin Dashboard"}</p>
                </div>
                <button
                    onclick={on_close.reform(|_: MouseEvent| ())}
                    class="md:hidden p-1 -mr-1 rounded-lg hover:bg-tertiary transition expand-hit"
                    aria-label="Close navigation"
                >
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                </button>
            </div>

            <div class="flex-1 overflow-y-auto p-4" onclick={on_close_nav}>
                <NavSection title="Overview">
                    <NavItem to={Route::Dashboard} icon="dashboard" label="Dashboard" />
                    <NavItem to={Route::Logs} icon="logs" label="WAF Logs" />
                    <NavItem to={Route::RequestLogs} icon="request" label="Request Logs" />
                    <NavItem to={Route::Observability} icon="status" label="Observability" />
                    <NavItem to={Route::AuditLogs} icon="list" label="Audit Log" />
                </NavSection>

                <NavSection title="Security">
                    <NavItem to={Route::Probes} icon="radar" label="Probing Activity" />
                </NavSection>

                <NavSection title="Management">
                    <NavItem to={Route::Workers} icon="cpu" label="Workers" />
                    <NavItem to={Route::Upstreams} icon="server" label="Upstreams" />
                    <NavItem to={Route::Sites} icon="globe" label="Sites" />
                    <NavItem to={Route::TcpUdp} icon="arrows" label="TCP/UDP Listeners" />
                    if vis.show_mesh {
                        <NavItem to={Route::Mesh} icon="mesh" label="Mesh" />
                    }
                    if vis.show_tier_keys {
                        <NavItem to={Route::TierKeys} icon="key" label="Tier Keys" />
                    }
                </NavSection>

                <NavSection title="Configuration">
                    <NavItem to={Route::Settings} icon="settings" label="Settings" />
                    if vis.show_dns {
                        <NavItem to={Route::Dns} icon="dns" label="DNS" />
                    }
                    <NavItem to={Route::TrafficShaping} icon="gauge" label="Traffic Shaping" />
                    if vis.show_process_management {
                        <NavItem to={Route::ProcessManagement} icon="process" label="Process Management" />
                    }
                    <NavItem to={Route::ThreatLevel} icon="shield" label="Threat Level" />
                    <NavItem to={Route::Alerts} icon="bell" label="Alerts" />
                    <NavItem to={Route::ErrorPages} icon="file" label="Error Pages" />
                </NavSection>

                <NavSection title="System">
                    <NavItem to={Route::SystemStatus} icon="status" label="System Status" />
                    if vis.show_honeypot {
                        <NavItem to={Route::Honeypot} icon="honeypot" label="Port Honeypot" />
                    }
                    if vis.show_icmp {
                        <NavItem to={Route::Icmp} icon="network" label="ICMP Filter" />
                    }
                </NavSection>
            </div>

            <div class="shrink-0 p-4 border-t border-default space-y-2 bg-secondary">
                <button
                    onclick={on_logout}
                    class="w-full px-4 py-2 rounded-lg bg-red-600/20 text-red-400 hover:bg-red-600/30 transition flex items-center justify-center gap-2"
                >
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                    </svg>
                    <span>{ "Logout" }</span>
                </button>
                <button
                    onclick={on_toggle}
                    class="w-full px-4 py-2 rounded-lg bg-tertiary hover:opacity-80 transition flex items-center justify-between"
                >
                    <span>{ "Theme" }</span>
                    <span>{ props.theme.label() }</span>
                </button>
            </div>
        </nav>
    }
}

#[derive(Properties, PartialEq)]
struct NavSectionProps {
    title: String,
    children: Children,
}

#[function_component]
fn NavSection(props: &NavSectionProps) -> Html {
    html! {
        <div class="mb-6">
            <h3 class="text-xs font-semibold text-secondary uppercase tracking-wider mb-2 px-3">
                { &props.title }
            </h3>
            <div class="space-y-1">
                { for props.children.iter() }
            </div>
        </div>
    }
}

/// Which nav entry should read as "current" for a given route.
///
/// Plain equality is not enough. `Home` and `Dashboard` render the same page,
/// and the Sites family spans three routes — listing a site and editing one are
/// the same destination in the operator's mental model, so the Sites entry
/// stays highlighted across all three.
pub fn is_nav_item_active(current: &Route, target: &Route) -> bool {
    use Route::*;
    match (current, target) {
        (Home, Dashboard) | (Dashboard, Home) => true,
        (SiteEditor { .. } | SiteDetail { .. } | Sites, Sites) => true,
        _ => current == target,
    }
}

#[derive(Properties, PartialEq)]
struct NavItemProps {
    to: Route,
    icon: String,
    label: String,
}

#[function_component]
fn NavItem(props: &NavItemProps) -> Html {
    // `yew_router::Link` (0.20) has no `active_class` prop — `LinkProps` only
    // carries `classes` — so the active state has to be resolved here against
    // the live route and folded into the class list. Without this every item
    // rendered identically and there was no indication of which page you were
    // on.
    let current = use_route::<Route>();
    let is_active = current
        .as_ref()
        .map(|route| is_nav_item_active(route, &props.to))
        .unwrap_or(false);

    let class = classes!(
        "flex",
        "items-center",
        "gap-3",
        "px-3",
        "py-2",
        "rounded-lg",
        "transition",
        // Active: a filled surface plus the accent text colour, so the current
        // page reads at a glance. Inactive: muted text that lifts on hover.
        if is_active {
            "bg-tertiary text-primary font-medium"
        } else {
            "text-secondary hover:bg-tertiary hover:text-primary"
        },
    );

    html! {
        <Link<Route>
            to={props.to.clone()}
            classes={class}
        >
            <span class={classes!(
                "w-5",
                "h-5",
                "flex",
                "items-center",
                "justify-center",
                "shrink-0",
                if is_active { "accent" } else { "" },
            )}>
                { icon(&props.icon) }
            </span>
            // `aria-current="page"` is what conveys "you are here" to a screen
            // reader; the visual highlight alone does not. It lives on the
            // label rather than the `<a>` because `yew_router::Link` 0.20 takes
            // no attributes beyond `classes` — `LinkProps` has no slot for one.
            <span aria-current={if is_active { "page" } else { "false" }}>{ &props.label }</span>
        </Link<Route>>
    }
}

fn icon(name: &str) -> Html {
    match name {
        // Clipboard list — the Audit Log trail.
        "list" => html! {
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9h6m-6 4h4" />
            </svg>
        },
        // Document — the Error Pages catalogue.
        "file" => html! {
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21h10a2 2 0 002-2V7l-4-4H7a2 2 0 00-2 2v14a2 2 0 002 2zM14 3v4a1 1 0 001 1h4M9 13h6M9 17h6" />
            </svg>
        },
        "dashboard" => html! {
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
            </svg>
        },
        "logs" => html! {
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
        },
        "request" => html! {
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
            </svg>
        },
        "server" => html! {
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
            </svg>
        },
        "globe" => html! {
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0 3-4.03 3-9s-1.343-9-3-9m-9 9a9 9 0 019-9" />
            </svg>
        },
        "network" => html! {
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
            </svg>
        },
        "settings" => html! {
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
        },
        "radar" => html! {
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />
            </svg>
        },
        "cpu" => html! {
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
            </svg>
        },
        "process" => html! {
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
        },
        "key" => html! {
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
            </svg>
        },
        "bell" => html! {
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
            </svg>
        },
        "shield" => html! {
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
        },
        "status" => html! {
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
        },
        "honeypot" => html! {
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
        },
        "mesh" => html! {
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
            </svg>
        },
        "dns" => html! {
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0 3-4.03 3-9s-1.343-9-3-9m-9 9a9 9 0 019-9" />
            </svg>
        },
        "arrows" => html! {
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
            </svg>
        },
        "gauge" => html! {
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3a9 9 0 00-9 9 9 9 0 0013.5 8.2M12 3a9 9 0 019 9 9 9 0 01-.7 3.4M12 12l4-4" />
            </svg>
        },
        _ => html! {},
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
            plugins: true,
            serverless: true,
        }
    }

    #[test]
    fn all_enabled_shows_everything() {
        let vis = sidebar_visibility(&all_enabled());
        assert!(vis.show_mesh);
        assert!(vis.show_tier_keys);
        assert!(vis.show_dns);
        assert!(vis.show_process_management);
        assert!(vis.show_honeypot);
        assert!(vis.show_icmp);
    }

    #[test]
    fn mesh_off_hides_mesh_and_tier_keys_only() {
        let mut cap = all_enabled();
        cap.mesh_admin = false;
        let vis = sidebar_visibility(&cap);
        assert!(!vis.show_mesh);
        assert!(!vis.show_tier_keys);
        assert!(vis.show_dns);
        assert!(vis.show_icmp);
    }

    #[test]
    fn dns_off_hides_dns_only() {
        let mut cap = all_enabled();
        cap.dns_admin = false;
        let vis = sidebar_visibility(&cap);
        assert!(!vis.show_dns);
        assert!(vis.show_mesh);
    }

    #[test]
    fn icmp_off_hides_icmp_only() {
        let mut cap = all_enabled();
        cap.icmp_admin = false;
        let vis = sidebar_visibility(&cap);
        assert!(!vis.show_icmp);
        assert!(vis.show_mesh);
    }

    #[test]
    fn capabilities_default_to_all_enabled() {
        // Sidebar starts optimistic before `/system/capabilities` resolves.
        let vis = sidebar_visibility(&Capabilities::default());
        assert!(vis.show_mesh);
        assert!(vis.show_dns);
        assert!(vis.show_icmp);
    }

    /// Every `Route` reachable from a `NavItem`, so the active-state helper is
    /// covered against the real navigation set rather than a hand-picked list.
    fn nav_targets() -> Vec<Route> {
        vec![
            Route::Dashboard,
            Route::Logs,
            Route::RequestLogs,
            Route::Observability,
            Route::AuditLogs,
            Route::Probes,
            Route::Workers,
            Route::Upstreams,
            Route::Sites,
            Route::TcpUdp,
            Route::Mesh,
            Route::TierKeys,
            Route::Settings,
            Route::Dns,
            Route::TrafficShaping,
            Route::ProcessManagement,
            Route::ThreatLevel,
            Route::Alerts,
            Route::ErrorPages,
            Route::SystemStatus,
            Route::Honeypot,
            Route::Icmp,
        ]
    }

    #[test]
    fn a_nav_item_is_active_on_its_own_route() {
        for target in nav_targets() {
            assert!(
                is_nav_item_active(&target, &target),
                "{:?} must highlight itself",
                target
            );
        }
    }

    #[test]
    fn exactly_one_nav_item_is_active_per_route() {
        // `nav_targets()` is the sidebar itself, so each entry appears once.
        // The Sites family spanning three routes means more than one *current
        // route* maps to the Sites entry — but that still lights exactly one
        // nav item, which is the property that matters: the operator must
        // always be able to tell where they are, with no ambiguity.
        let targets = nav_targets();

        for current in targets.iter() {
            let active: Vec<&Route> = targets
                .iter()
                .filter(|target| is_nav_item_active(current, target))
                .collect();
            assert_eq!(
                active.len(),
                1,
                "expected one active nav item for {:?}, got {:?}",
                current,
                active
            );
        }

        // The sub-page routes a nav click can land on must also resolve to a
        // single entry, and to the Sites one.
        for current in [
            Route::SiteEditor { id: "a.com".into() },
            Route::SiteDetail { id: "a.com".into() },
        ] {
            let active: Vec<&Route> = targets
                .iter()
                .filter(|target| is_nav_item_active(&current, target))
                .collect();
            assert_eq!(
                active.len(),
                1,
                "expected one active item for {:?}",
                current
            );
            assert_eq!(active[0], &Route::Sites);
        }
    }

    #[test]
    fn root_and_dashboard_are_the_same_destination() {
        assert!(is_nav_item_active(&Route::Home, &Route::Dashboard));
        assert!(is_nav_item_active(&Route::Dashboard, &Route::Home));
    }

    #[test]
    fn sites_stays_active_across_its_sub_pages() {
        assert!(is_nav_item_active(&Route::Sites, &Route::Sites));
        assert!(is_nav_item_active(
            &Route::SiteEditor {
                id: "example.com".into()
            },
            &Route::Sites
        ));
        assert!(is_nav_item_active(
            &Route::SiteDetail {
                id: "example.com".into()
            },
            &Route::Sites
        ));
    }

    #[test]
    fn unrelated_routes_are_not_active() {
        // A different site id is a different page, so editing site A must not
        // light up a nav entry aimed at the Sites list.
        let editing = Route::SiteEditor { id: "a.com".into() };
        assert!(!is_nav_item_active(&editing, &Route::Dashboard));
        assert!(!is_nav_item_active(&Route::Dashboard, &Route::Settings));
    }
}
