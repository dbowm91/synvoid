use serde::{Deserialize, Serialize};
use yew::prelude::*;

#[derive(Serialize, Deserialize, Clone)]
pub struct WafLogEntry {
    pub timestamp: String,
    pub level: String,
    pub site_id: Option<String>,
    pub message: String,
    pub client_ip: Option<String>,
    pub path: Option<String>,
    pub attack_type: Option<String>,
    pub threat_score: Option<u8>,
    pub action: Option<String>,
}

#[function_component]
pub fn Logs() -> Html {
    let streaming = use_state(|| false);

    html! {
        <div>
            <div class="flex items-center justify-between mb-6">
                <h1 class="text-2xl font-bold">{ "WAF Logs" }</h1>
                <div class="flex items-center gap-3">
                    <div class="flex items-center gap-2 px-3 py-1 rounded-full text-sm bg-gray-500/20 text-gray-400">
                        <span class="w-2 h-2 rounded-full bg-gray-500" />
                        { "Offline" }
                    </div>
                </div>
            </div>

            <div class="bg-secondary rounded-lg p-4 border border-default mb-6">
                <div class="flex flex-wrap gap-4">
                    <select class="px-3 py-2 bg-tertiary border border-default rounded-lg text-primary text-sm min-w-[150px]">
                        <option value="all">{ "All Levels" }</option>
                        <option value="trace">{ "Trace" }</option>
                        <option value="debug">{ "Debug" }</option>
                        <option value="info">{ "Info" }</option>
                        <option value="warn">{ "Warning" }</option>
                        <option value="error">{ "Error" }</option>
                    </select>

                    <select class="px-3 py-2 bg-tertiary border border-default rounded-lg text-primary text-sm min-w-[150px]">
                        <option value="all">{ "All Sites" }</option>
                        <option value="example.com">{ "example.com" }</option>
                        <option value="api.example.com">{ "api.example.com" }</option>
                        <option value="system">{ "System" }</option>
                    </select>

                    <input
                        type="text"
                        placeholder="Search logs, IPs, attack types..."
                        class="flex-1 px-3 py-2 bg-tertiary border border-default rounded-lg text-primary text-sm min-w-[200px]"
                    />
                </div>
            </div>

            <div class="bg-secondary rounded-lg border border-default overflow-hidden">
                <div class="p-4 font-mono text-sm max-h-[600px] overflow-y-auto">
                    <div class="py-2 border-b border-default">
                        <div class="flex items-start gap-4">
                            <span class="text-secondary text-xs whitespace-nowrap">{"10:23:45"}</span>
                            <span class="px-2 py-0.5 rounded text-xs uppercase font-medium text-blue-500">{"info"}</span>
                            <span class="text-purple-400 text-xs">{"example.com"}</span>
                            <span class="text-green-400 text-xs font-mono">{"192.168.1.100"}</span>
                        </div>
                        <div class="mt-1 text-primary">{"Request processed successfully"}</div>
                    </div>
                    <div class="py-2 border-b border-default">
                        <div class="flex items-start gap-4">
                            <span class="text-secondary text-xs whitespace-nowrap">{"10:23:44"}</span>
                            <span class="px-2 py-0.5 rounded text-xs uppercase font-medium text-yellow-500">{"warn"}</span>
                            <span class="text-purple-400 text-xs">{"api.example.com"}</span>
                            <span class="text-green-400 text-xs font-mono">{"10.0.0.50"}</span>
                        </div>
                        <div class="mt-1 text-primary">{"Rate limit threshold approaching"}</div>
                    </div>
                    <div class="py-2 border-b border-default">
                        <div class="flex items-start gap-4">
                            <span class="text-secondary text-xs whitespace-nowrap">{"10:23:43"}</span>
                            <span class="px-2 py-0.5 rounded text-xs uppercase font-medium text-red-500">{"error"}</span>
                            <span class="text-purple-400 text-xs">{"admin.example.com"}</span>
                            <span class="text-red-400 text-xs">{"SQLi"}</span>
                        </div>
                        <div class="mt-1 text-primary">{"SQL injection attempt detected"}</div>
                    </div>
                    <div class="py-2 border-b border-default">
                        <div class="flex items-start gap-4">
                            <span class="text-secondary text-xs whitespace-nowrap">{"10:23:42"}</span>
                            <span class="px-2 py-0.5 rounded text-xs uppercase font-medium text-blue-500">{"info"}</span>
                            <span class="text-purple-400 text-xs">{"system"}</span>
                        </div>
                        <div class="mt-1 text-primary">{"Configuration reloaded"}</div>
                    </div>
                </div>

                <div class="px-4 py-3 border-t border-default">
                    <span class="text-sm text-secondary">{ "Showing 4 entries" }</span>
                </div>
            </div>
        </div>
    }
}
