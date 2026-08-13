use crate::components::charts::Sparkline;
use crate::hooks::use_websocket::{use_websocket_or_poll, UseWebSocketState};
use crate::types::RealtimeMetrics;
use yew::prelude::*;

fn get_threat_level_color_and_label(level: u8) -> (&'static str, &'static str) {
    match level {
        1 => ("bg-green-500", "Normal"),
        2 => ("bg-yellow-500", "Elevated"),
        3 => ("bg-orange-500", "High"),
        4 => ("bg-red-500", "Severe"),
        5 => ("bg-red-700", "Critical"),
        _ => ("bg-gray-500", "Unknown"),
    }
}

#[function_component]
pub fn RealtimeHeader() -> Html {
    let metrics_state = use_websocket_or_poll::<RealtimeMetrics>(
        "/api/ws/metrics",
        "/api/stats/history?seconds=60",
        5000,
    );

    let (ws_state, _refresh) = metrics_state;

    let req_history = use_state(|| vec![0.0; 10]);
    let blocked_history = use_state(|| vec![0.0; 10]);
    let current_metrics = use_state(|| None::<RealtimeMetrics>);
    let last_updated = use_state(|| String::from("--:--:--"));
    let selected_range = use_state(|| 60u64);

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
            let total = m.total_requests;
            let blocked = m.blocked;
            let errors = m.errors;
            let valid = total.saturating_add(errors).min(total);
            let success_numerator = total.saturating_sub(blocked).saturating_sub(errors);
            let success_pct = if total > 0 {
                (success_numerator as f64 / total as f64 * 100.0).clamp(0.0, 100.0)
            } else {
                100.0
            };
            let _ = valid;
            (
                format!("{:.1}", m.requests_per_second),
                format!("{:.1}", m.blocked_per_second),
                m.current_concurrent.to_string(),
                format!("{:.1}%", success_pct),
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

    let threat_level = metrics.as_ref().and_then(|m| m.threat_level).unwrap_or(1);
    let is_manual = metrics
        .as_ref()
        .map(|m| m.threat_level_is_manual)
        .unwrap_or(false);
    let (threat_bg, threat_label) = get_threat_level_color_and_label(threat_level);
    let threat_display = if is_manual {
        format!("{} (Manual)", threat_label)
    } else {
        threat_label.to_string()
    };

    let connection_status = match &ws_state {
        UseWebSocketState::Connected(_) => {
            ("w-2 h-2 rounded-full bg-green-500 animate-pulse", "Live")
        }
        UseWebSocketState::Connecting => (
            "w-2 h-2 rounded-full bg-yellow-500 animate-pulse",
            "Connecting",
        ),
        UseWebSocketState::Polling => ("w-2 h-2 rounded-full bg-blue-500 animate-pulse", "Polling"),
        UseWebSocketState::Disconnected => ("w-2 h-2 rounded-full bg-red-500", "Disconnected"),
        UseWebSocketState::Error(_) => ("w-2 h-2 rounded-full bg-red-500", "Error"),
    };

    let on_range_change = {
        let selected_range = selected_range.clone();
        Callback::from(move |secs: u64| {
            selected_range.set(secs);
        })
    };

    html! {
        <div class="bg-secondary rounded-lg border border-default p-4 mb-6">
            <div class="flex items-center justify-between mb-4">
                <div class="flex items-center gap-2">
                    <div class={connection_status.0} />
                    <span class="text-sm text-secondary">{ connection_status.1 }</span>
                    <span class="text-xs text-secondary ml-2">{ format!("Updated: {}", *last_updated) }</span>
                </div>
                <div class="flex items-center gap-2">
                    <button
                        onclick={let cb = on_range_change.clone(); move |_| cb.emit(60)}
                        class={if *selected_range == 60 { "px-3 py-1 text-xs bg-blue-600 text-white rounded" } else { "px-3 py-1 text-xs bg-tertiary rounded hover:opacity-80" }}>
                        { "1m" }
                    </button>
                    <button
                        onclick={let cb = on_range_change.clone(); move |_| cb.emit(300)}
                        class={if *selected_range == 300 { "px-3 py-1 text-xs bg-blue-600 text-white rounded" } else { "px-3 py-1 text-xs bg-tertiary rounded hover:opacity-80" }}>
                        { "5m" }
                    </button>
                    <button
                        onclick={let cb = on_range_change.clone(); move |_| cb.emit(900)}
                        class={if *selected_range == 900 { "px-3 py-1 text-xs bg-blue-600 text-white rounded" } else { "px-3 py-1 text-xs bg-tertiary rounded hover:opacity-80" }}>
                        { "15m" }
                    </button>
                    <button
                        onclick={let cb = on_range_change.clone(); move |_| cb.emit(3600)}
                        class={if *selected_range == 3600 { "px-3 py-1 text-xs bg-blue-600 text-white rounded" } else { "px-3 py-1 text-xs bg-tertiary rounded hover:opacity-80" }}>
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
                        { threat_display }
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
