use crate::components::charts::Sparkline;
use crate::hooks::use_websocket::{use_websocket_or_poll_with_token, UseWebSocketState};
use crate::types::RealtimeMetrics;
use yew::prelude::*;

fn get_auth_token() -> Option<String> {
    web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
        .and_then(|storage| storage.get_item("admin_token").ok())
        .flatten()
}

fn get_threat_level_color_and_label(level: u8) -> (&'static str, &'static str) {
    match level {
        0..=2 => ("bg-green-500", "Low"),
        3..=5 => ("bg-yellow-500", "Medium"),
        6..=8 => ("bg-orange-500", "High"),
        _ => ("bg-red-500", "Critical"),
    }
}

#[function_component]
pub fn RealtimeHeader() -> Html {
    let metrics_state = use_websocket_or_poll_with_token::<RealtimeMetrics>(
        "/api/ws/metrics",
        "/api/stats/history?seconds=60",
        5000,
        get_auth_token().as_deref(),
    );

    let (ws_state, _refresh) = metrics_state;

    let req_history = use_state(|| vec![0.0; 10]);
    let blocked_history = use_state(|| vec![0.0; 10]);
    let current_metrics = use_state(|| None::<RealtimeMetrics>);
    let last_updated = use_state(|| String::from("--:--:--"));

    {
        let ws_state = ws_state.clone();
        let set_current_metrics = current_metrics.clone();
        let set_last_updated = last_updated.clone();
        let req_history = req_history.clone();
        let blocked_history = blocked_history.clone();

        use_effect_with(ws_state.clone(), move |state| {
            if let UseWebSocketState::Connected(metrics) = (*state).clone() {
                set_current_metrics.set(Some(metrics.clone()));
                let now = chrono_lite();
                set_last_updated.set(now);

                let mut req_hist = (*req_history).clone();
                let mut block_hist = (*blocked_history).clone();
                req_hist.remove(0);
                req_hist.push(metrics.requests_per_second);
                block_hist.remove(0);
                block_hist.push(metrics.blocked_per_second);
                req_history.set(req_hist);
                blocked_history.set(block_hist);
            }
        });
    }

    let metrics = (*current_metrics).clone();

    let (req_per_sec, blocked_per_sec, connections, success_rate, avg_latency) =
        if let Some(ref m) = metrics {
            (
                format!("{:.1}", m.requests_per_second),
                format!("{:.1}", m.blocked_per_second),
                m.current_concurrent.to_string(),
                format!(
                    "{:.1}%",
                    if m.total_requests > 0 {
                        (m.total_requests - m.blocked - m.errors) as f64 / m.total_requests as f64
                            * 100.0
                    } else {
                        100.0
                    }
                ),
                format!("{:.0}ms", m.avg_latency_ms),
            )
        } else {
            (
                "0".to_string(),
                "0".to_string(),
                "0".to_string(),
                "100%".to_string(),
                "0ms".to_string(),
            )
        };

    let threat_level = metrics
        .as_ref()
        .map(|m| m.requests_per_second as u8 / 50)
        .unwrap_or(0)
        .min(10);
    let (threat_bg, threat_label) = get_threat_level_color_and_label(threat_level);

    html! {
        <div class="bg-secondary rounded-lg border border-default p-4 mb-6">
            <div class="flex items-center justify-between mb-4">
                <div class="flex items-center gap-2">
                    <div class={
                        match ws_state {
                            UseWebSocketState::Connected(_) => "w-2 h-2 rounded-full bg-green-500 animate-pulse",
                            UseWebSocketState::Connecting => "w-2 h-2 rounded-full bg-yellow-500 animate-pulse",
                            _ => "w-2 h-2 rounded-full bg-red-500",
                        }
                    } />
                    <span class="text-sm text-secondary">{ "Live Metrics" }</span>
                    <span class="text-xs text-secondary ml-2">{ format!("Updated: {}", *last_updated) }</span>
                </div>
                <div class="flex items-center gap-4">
                    <button class="px-3 py-1 text-xs bg-tertiary rounded hover:opacity-80">
                        { "1m" }
                    </button>
                    <button class="px-3 py-1 text-xs bg-tertiary rounded hover:opacity-80">
                        { "5m" }
                    </button>
                    <button class="px-3 py-1 text-xs bg-tertiary rounded hover:opacity-80">
                        { "15m" }
                    </button>
                    <button class="px-3 py-1 text-xs bg-tertiary rounded hover:opacity-80">
                        { "1h" }
                    </button>
                </div>
            </div>

            <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
                <div class="flex flex-col">
                    <span class="text-xs text-secondary">{ "Req/sec" }</span>
                    <div class="flex items-end justify-between">
                        <span class="text-xl font-bold text-blue-500">{ req_per_sec }</span>
                        <Sparkline data={(*req_history).clone()} color={Some("#3b82f6".to_string())} width={Some("60px".to_string())} height={Some("20px".to_string())} />
                    </div>
                </div>
                <div class="flex flex-col">
                    <span class="text-xs text-secondary">{ "Blocked/sec" }</span>
                    <div class="flex items-end justify-between">
                        <span class="text-xl font-bold text-red-500">{ blocked_per_sec }</span>
                        <Sparkline data={(*blocked_history).clone()} color={Some("#ef4444".to_string())} width={Some("60px".to_string())} height={Some("20px".to_string())} />
                    </div>
                </div>
                <div class="flex flex-col justify-center">
                    <span class="text-xs text-secondary">{ "Connections" }</span>
                    <span class="text-xl font-bold text-green-500">{ connections }</span>
                </div>
                <div class="flex flex-col justify-center">
                    <span class="text-xs text-secondary">{ "Threat Level" }</span>
                    <div class={format!("px-2 py-1 rounded text-xs font-medium text-white {} w-fit", threat_bg)}>
                        { threat_label }
                    </div>
                </div>
                <div class="flex flex-col justify-center">
                    <span class="text-xs text-secondary">{ "Success Rate" }</span>
                    <span class="text-xl font-bold text-green-500">{ success_rate }</span>
                </div>
                <div class="flex flex-col justify-center">
                    <span class="text-xs text-secondary">{ "Avg Latency" }</span>
                    <span class="text-xl font-bold">{ avg_latency }</span>
                </div>
            </div>
        </div>
    }
}

fn chrono_lite() -> String {
    let now = js_sys::Date::new_0();
    let hours = now.get_hours();
    let minutes = now.get_minutes();
    let seconds = now.get_seconds();
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}
