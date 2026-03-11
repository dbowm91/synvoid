use std::collections::HashMap;
use yew::prelude::*;

use crate::components::charts::{Gauge, MultiSeriesLineChart, StackedAreaChart};
use crate::components::realtime_header::RealtimeHeader;

#[function_component]
pub fn Dashboard() -> Html {
    let selected_window = use_state(|| "5m".to_string());

    let request_data = {
        let mut map = HashMap::new();
        map.insert(
            "Requests".to_string(),
            vec![
                120.0, 135.0, 142.0, 128.0, 155.0, 168.0, 172.0, 165.0, 158.0, 175.0, 182.0, 178.0,
            ],
        );
        map.insert(
            "Blocked".to_string(),
            vec![
                5.0, 8.0, 6.0, 12.0, 9.0, 7.0, 11.0, 8.0, 10.0, 14.0, 12.0, 9.0,
            ],
        );
        map
    };

    let blocking_data = {
        let mut map = HashMap::new();
        map.insert(
            "SQLi".to_string(),
            vec![2.0, 3.0, 1.0, 4.0, 2.0, 3.0, 5.0, 2.0, 3.0, 4.0, 2.0, 3.0],
        );
        map.insert(
            "XSS".to_string(),
            vec![1.0, 2.0, 3.0, 1.0, 2.0, 1.0, 2.0, 3.0, 1.0, 2.0, 3.0, 1.0],
        );
        map.insert(
            "Rate Limit".to_string(),
            vec![
                5.0, 8.0, 6.0, 12.0, 9.0, 7.0, 11.0, 8.0, 10.0, 14.0, 12.0, 9.0,
            ],
        );
        map.insert(
            "Bots".to_string(),
            vec![3.0, 2.0, 4.0, 3.0, 2.0, 4.0, 3.0, 2.0, 4.0, 3.0, 2.0, 4.0],
        );
        map.insert(
            "Path Traversal".to_string(),
            vec![1.0, 1.0, 2.0, 1.0, 1.0, 2.0, 1.0, 1.0, 2.0, 1.0, 1.0, 2.0],
        );
        map
    };

    let threat_data = {
        let mut map = HashMap::new();
        map.insert(
            "Threat Score".to_string(),
            vec![
                15.0, 18.0, 22.0, 19.0, 25.0, 28.0, 24.0, 21.0, 19.0, 23.0, 20.0, 18.0,
            ],
        );
        map
    };

    let labels = vec![
        "1m".to_string(),
        "2m".to_string(),
        "3m".to_string(),
        "4m".to_string(),
        "5m".to_string(),
        "6m".to_string(),
        "7m".to_string(),
        "8m".to_string(),
        "9m".to_string(),
        "10m".to_string(),
        "11m".to_string(),
        "12m".to_string(),
    ];

    let on_window_change = {
        let selected_window = selected_window.clone();
        Callback::from(move |window: String| {
            selected_window.set(window);
        })
    };

    html! {
        <div>
            <h1 class="text-2xl font-bold mb-6">{ "Dashboard" }</h1>

            <RealtimeHeader />

            <div class="mb-6">
                <div class="flex gap-2">
                    <WindowButton label="1m" active={*selected_window == "1m"} on_click={on_window_change.clone()} />
                    <WindowButton label="5m" active={*selected_window == "5m"} on_click={on_window_change.clone()} />
                    <WindowButton label="15m" active={*selected_window == "15m"} on_click={on_window_change.clone()} />
                    <WindowButton label="1h" active={*selected_window == "1h"} on_click={on_window_change.clone()} />
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                <div class="bg-secondary rounded-lg p-6 border border-default">
                    <h3 class="text-lg font-semibold mb-4">{ "Request Traffic" }</h3>
                    <MultiSeriesLineChart
                        data_series={request_data}
                        labels={labels.clone()}
                        height="280px"
                        show_legend={true}
                        time_window={Some((*selected_window).clone())}
                    />
                </div>

                <div class="bg-secondary rounded-lg p-6 border border-default">
                    <h3 class="text-lg font-semibold mb-4">{ "Blocking by Type" }</h3>
                    <StackedAreaChart
                        data_series={blocking_data}
                        labels={labels.clone()}
                        height="280px"
                        time_window={Some((*selected_window).clone())}
                    />
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
                <div class="bg-secondary rounded-lg p-6 border border-default">
                    <h3 class="text-lg font-semibold mb-4">{ "Threat Level History" }</h3>
                    <MultiSeriesLineChart
                        data_series={threat_data}
                        labels={labels.clone()}
                        height="200px"
                        show_legend={false}
                    />
                </div>

                <div class="bg-secondary rounded-lg p-6 border border-default">
                    <h3 class="text-lg font-semibold mb-4">{ "System Resources" }</h3>
                    <div class="flex justify-around">
                        <Gauge value={45.0} max={100.0} label="CPU" unit="%" />
                        <Gauge value={62.0} max={100.0} label="Memory" unit="%" />
                    </div>
                </div>

                <div class="bg-secondary rounded-lg p-6 border border-default">
                    <h3 class="text-lg font-semibold mb-4">{ "Quick Stats" }</h3>
                    <div class="space-y-3">
                        <StatRow label="Total Requests" value="1.2M" />
                        <StatRow label="Blocked" value="12.4K" />
                        <StatRow label="Unique IPs" value="8.2K" />
                        <StatRow label="Uptime" value="14d 6h" />
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div class="bg-secondary rounded-lg p-6 border border-default">
                    <h3 class="text-lg font-semibold mb-4">{ "Sites Status" }</h3>
                    <div class="space-y-3">
                        <SiteStatusItem domain="example.com" healthy=true requests="45K" blocked="234" />
                        <SiteStatusItem domain="api.example.com" healthy=true requests="28K" blocked="156" />
                        <SiteStatusItem domain="admin.example.com" healthy=false requests="1.2K" blocked="89" />
                        <SiteStatusItem domain="blog.example.com" healthy=true requests="15K" blocked="45" />
                    </div>
                </div>

                <div class="bg-secondary rounded-lg p-6 border border-default">
                    <h3 class="text-lg font-semibold mb-4">{ "Recent Events" }</h3>
                    <div class="space-y-2">
                        <EventItem
                            time="2 min ago"
                            event="Rate limit triggered"
                            site="api.example.com"
                            level="warning"
                        />
                        <EventItem
                            time="5 min ago"
                            event="SQL injection attempt blocked"
                            site="example.com"
                            level="danger"
                        />
                        <EventItem
                            time="12 min ago"
                            event="Config reloaded"
                            site="system"
                            level="info"
                        />
                        <EventItem
                            time="15 min ago"
                            event="XSS attempt blocked"
                            site="blog.example.com"
                            level="danger"
                        />
                    </div>
                </div>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct WindowButtonProps {
    label: String,
    active: bool,
    on_click: Callback<String>,
}

#[function_component]
fn WindowButton(props: &WindowButtonProps) -> Html {
    let onclick = {
        let label = props.label.clone();
        let on_click = props.on_click.clone();
        Callback::from(move |_| {
            on_click.emit(label.clone());
        })
    };

    let class = if props.active {
        "px-4 py-2 bg-blue-600 text-white rounded-lg text-sm"
    } else {
        "px-4 py-2 bg-tertiary text-secondary rounded-lg hover:text-primary text-sm"
    };

    html! {
        <button onclick={onclick} class={class}>
            { &props.label }
        </button>
    }
}

#[derive(Properties, PartialEq)]
struct StatRowProps {
    label: String,
    value: String,
}

#[function_component]
fn StatRow(props: &StatRowProps) -> Html {
    html! {
        <div class="flex justify-between items-center py-2 border-b border-default last:border-b-0">
            <span class="text-secondary text-sm">{ &props.label }</span>
            <span class="text-primary font-medium">{ &props.value }</span>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct SiteStatusItemProps {
    domain: String,
    healthy: bool,
    requests: String,
    blocked: String,
}

#[function_component]
fn SiteStatusItem(props: &SiteStatusItemProps) -> Html {
    let status_class = if props.healthy {
        "bg-green-500"
    } else {
        "bg-red-500"
    };
    let status_text = if props.healthy {
        "Healthy"
    } else {
        "Unhealthy"
    };

    html! {
        <div class="flex items-center justify-between py-3 border-b border-default last:border-b-0">
            <div class="flex items-center gap-3">
                <span class={format!("w-2 h-2 rounded-full {}", status_class)} />
                <span class="text-primary">{ &props.domain }</span>
            </div>
            <div class="flex items-center gap-4 text-sm">
                <span class="text-secondary">{ format!("{} req", props.requests) }</span>
                <span class="text-red-500">{ format!("{} blocked", props.blocked) }</span>
                <span class="text-secondary text-xs">{ status_text }</span>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct EventItemProps {
    time: String,
    event: String,
    site: String,
    level: String,
}

#[function_component]
fn EventItem(props: &EventItemProps) -> Html {
    let level_class = match props.level.as_str() {
        "danger" => "text-red-500",
        "warning" => "text-yellow-500",
        _ => "text-blue-500",
    };

    html! {
        <div class="flex items-start gap-3 py-2 border-b border-default last:border-b-0">
            <span class={format!("w-2 h-2 rounded-full mt-1.5 {}", level_class)} />
            <div class="flex-1">
                <p class="text-primary">{ &props.event }</p>
                <p class="text-xs text-secondary">
                    { &props.site } { " - " } { &props.time }
                </p>
            </div>
        </div>
    }
}
