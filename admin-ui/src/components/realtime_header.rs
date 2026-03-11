use crate::components::charts::Sparkline;
use yew::prelude::*;

#[function_component]
pub fn RealtimeHeader() -> Html {
    let req_history = vec![
        120.0, 135.0, 142.0, 128.0, 155.0, 168.0, 172.0, 165.0, 158.0, 175.0,
    ];
    let blocked_history = vec![5.0, 8.0, 6.0, 12.0, 9.0, 7.0, 11.0, 8.0, 10.0, 14.0];

    html! {
        <div class="bg-secondary rounded-lg border border-default p-4 mb-6">
            <div class="flex items-center justify-between mb-4">
                <div class="flex items-center gap-2">
                    <div class="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                    <span class="text-sm text-secondary">{ "Live Metrics" }</span>
                    <span class="text-xs text-secondary ml-2">{ "Updated: --:--:--" }</span>
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
                        <span class="text-xl font-bold text-blue-500">{ "156" }</span>
                        <Sparkline data={req_history.clone()} color={Some("#3b82f6".to_string())} width={Some("60px".to_string())} height={Some("20px".to_string())} />
                    </div>
                </div>
                <div class="flex flex-col">
                    <span class="text-xs text-secondary">{ "Blocked/sec" }</span>
                    <div class="flex items-end justify-between">
                        <span class="text-xl font-bold text-red-500">{ "9.5" }</span>
                        <Sparkline data={blocked_history.clone()} color={Some("#ef4444".to_string())} width={Some("60px".to_string())} height={Some("20px".to_string())} />
                    </div>
                </div>
                <div class="flex flex-col justify-center">
                    <span class="text-xs text-secondary">{ "Connections" }</span>
                    <span class="text-xl font-bold text-green-500">{ "847" }</span>
                </div>
                <div class="flex flex-col justify-center">
                    <span class="text-xs text-secondary">{ "Threat Level" }</span>
                    <div class="px-2 py-1 rounded text-xs font-medium text-white bg-green-500 w-fit">
                        { "Low" }
                    </div>
                </div>
                <div class="flex flex-col justify-center">
                    <span class="text-xs text-secondary">{ "Success Rate" }</span>
                    <span class="text-xl font-bold text-green-500">{ "99.2%" }</span>
                </div>
                <div class="flex flex-col justify-center">
                    <span class="text-xs text-secondary">{ "Avg Latency" }</span>
                    <span class="text-xl font-bold">{ "23ms" }</span>
                </div>
            </div>
        </div>
    }
}
