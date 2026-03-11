use yew::prelude::*;
use yew_router::prelude::*;

use crate::app::Route;
use crate::hooks::use_theme::Theme;

#[derive(Properties, PartialEq)]
pub struct SidebarProps {
    pub theme: Theme,
    pub on_toggle_theme: Callback<()>,
}

pub struct Sidebar {
    current_route: String,
}

impl Component for Sidebar {
    type Message = ();
    type Properties = SidebarProps;

    fn create(_ctx: &Context<Self>) -> Self {
        Self {
            current_route: "/".to_string(),
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let on_toggle = ctx.props().on_toggle_theme.reform(|_| ());

        html! {
            <nav class="w-64 bg-secondary border-r border-default min-h-screen flex flex-col">
                <div class="p-4 border-b border-default">
                    <h1 class="text-xl font-bold accent">
                        { "RustWAF" }
                    </h1>
                    <p class="text-sm text-secondary">{"Admin Dashboard"}</p>
                </div>

                <div class="flex-1 p-4">
                    <NavSection title="Overview">
                        <NavItem to={Route::Dashboard} icon="dashboard" label="Dashboard" />
                        <NavItem to={Route::Logs} icon="logs" label="WAF Logs" />
                        <NavItem to={Route::RequestLogs} icon="request" label="Request Logs" />
                    </NavSection>

                    <NavSection title="Security">
                        <NavItem to={Route::Probes} icon="radar" label="Probing Activity" />
                    </NavSection>

                    <NavSection title="Management">
                        <NavItem to={Route::Upstreams} icon="server" label="Upstreams" />
                        <NavItem to={Route::Sites} icon="globe" label="Sites" />
                        <NavItem to={Route::TcpUdp} icon="network" label="TCP/UDP" />
                    </NavSection>

                    <NavSection title="Configuration">
                        <NavItem to={Route::Settings} icon="settings" label="Settings" />
                    </NavSection>
                </div>

                <div class="p-4 border-t border-default">
                    <button
                        onclick={on_toggle}
                        class="w-full px-4 py-2 rounded-lg bg-tertiary hover:opacity-80 transition flex items-center justify-between"
                    >
                        <span>{ "Theme" }</span>
                        <span>{ ctx.props().theme.label() }</span>
                    </button>
                </div>
            </nav>
        }
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
            <h3 class="text-xs font-semibold text-secondary uppercase tracking-wider mb-2">
                { &props.title }
            </h3>
            <div class="space-y-1">
                { props.children.clone() }
            </div>
        </div>
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
    html! {
        <Link<Route>
            to={props.to.clone()}
            classes="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-tertiary transition text-secondary hover:text-primary"
        >
            <span class="w-5 h-5 flex items-center justify-center">
                { icon(&props.icon) }
            </span>
            <span>{ &props.label }</span>
        </Link<Route>>
    }
}

fn icon(name: &str) -> Html {
    match name {
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
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
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
        _ => html! {},
    }
}
