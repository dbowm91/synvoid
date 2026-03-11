use serde::{Deserialize, Serialize};
use yew::prelude::*;

#[derive(Serialize, Deserialize, Clone)]
pub struct RequestLogEntry {
    pub id: String,
    pub timestamp: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub response_time_ms: u32,
    pub site_id: String,
    pub user_agent: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[function_component]
pub fn RequestLogs() -> Html {
    html! {
        <div>
            <div class="flex items-center justify-between mb-6">
                <h1 class="text-2xl font-bold">{ "Request Logs" }</h1>
                <div class="flex items-center gap-3">
                    <label class="flex items-center gap-2 text-sm cursor-pointer">
                        <input type="checkbox" class="w-4 h-4 rounded" />
                        <span class="text-secondary">{ "Auto-refresh" }</span>
                    </label>
                    <button class="px-4 py-2 bg-tertiary text-primary rounded-lg hover:opacity-80 text-sm">
                        { "Export" }
                    </button>
                </div>
            </div>

            <div class="bg-secondary rounded-lg p-4 border border-default mb-6">
                <div class="flex flex-wrap gap-4">
                    <select class="px-3 py-2 bg-tertiary border border-default rounded-lg text-primary text-sm min-w-[150px]">
                        <option value="all">{ "All Sites" }</option>
                        <option value="example.com">{ "example.com" }</option>
                        <option value="api.example.com">{ "api.example.com" }</option>
                    </select>

                    <select class="px-3 py-2 bg-tertiary border border-default rounded-lg text-primary text-sm min-w-[150px]">
                        <option value="all">{ "All Methods" }</option>
                        <option value="GET">{ "GET" }</option>
                        <option value="POST">{ "POST" }</option>
                        <option value="PUT">{ "PUT" }</option>
                        <option value="DELETE">{ "DELETE" }</option>
                    </select>

                    <select class="px-3 py-2 bg-tertiary border border-default rounded-lg text-primary text-sm min-w-[180px]">
                        <option value="all">{ "All Status" }</option>
                        <option value="2xx">{ "2xx Success" }</option>
                        <option value="3xx">{ "3xx Redirect" }</option>
                        <option value="4xx">{ "4xx Client Error" }</option>
                        <option value="5xx">{ "5xx Server Error" }</option>
                    </select>

                    <input
                        type="text"
                        placeholder="Search by IP, path, or user-agent..."
                        class="flex-1 px-3 py-2 bg-tertiary border border-default rounded-lg text-primary text-sm min-w-[200px]"
                    />
                </div>
            </div>

            <div class="bg-secondary rounded-lg border border-default overflow-hidden">
                <div class="overflow-x-auto">
                    <table class="w-full text-sm">
                        <thead class="bg-tertiary border-b border-default">
                            <tr>
                                <th class="px-4 py-3 text-left text-secondary font-medium">{ "Time" }</th>
                                <th class="px-4 py-3 text-left text-secondary font-medium">{ "Method" }</th>
                                <th class="px-4 py-3 text-left text-secondary font-medium">{ "Path" }</th>
                                <th class="px-4 py-3 text-left text-secondary font-medium">{ "Status" }</th>
                                <th class="px-4 py-3 text-left text-secondary font-medium">{ "Latency" }</th>
                                <th class="px-4 py-3 text-left text-secondary font-medium">{ "Client IP" }</th>
                                <th class="px-4 py-3 text-left text-secondary font-medium">{ "Site" }</th>
                                <th class="px-4 py-3 text-left text-secondary font-medium">{ "Size" }</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr class="border-b border-default hover:bg-tertiary/50 transition">
                                <td class="px-4 py-3 text-secondary font-mono text-xs">{"10:23:45"}</td>
                                <td class="px-4 py-3"><span class="px-2 py-1 rounded text-xs font-medium bg-blue-500/20 text-blue-400">{"GET"}</span></td>
                                <td class="px-4 py-3 text-primary font-mono text-xs max-w-[200px] truncate">{"/api/users"}</td>
                                <td class="px-4 py-3 text-green-500">{"200"}</td>
                                <td class="px-4 py-3 text-secondary">{"45ms"}</td>
                                <td class="px-4 py-3 text-primary font-mono text-xs">{"192.168.1.100"}</td>
                                <td class="px-4 py-3 text-secondary text-xs">{"api.example.com"}</td>
                                <td class="px-4 py-3 text-secondary text-xs">{"1.2 KB"}</td>
                            </tr>
                            <tr class="border-b border-default hover:bg-tertiary/50 transition">
                                <td class="px-4 py-3 text-secondary font-mono text-xs">{"10:23:44"}</td>
                                <td class="px-4 py-3"><span class="px-2 py-1 rounded text-xs font-medium bg-green-500/20 text-green-400">{"POST"}</span></td>
                                <td class="px-4 py-3 text-primary font-mono text-xs max-w-[200px] truncate">{"/api/login"}</td>
                                <td class="px-4 py-3 text-yellow-500">{"401"}</td>
                                <td class="px-4 py-3 text-secondary">{"23ms"}</td>
                                <td class="px-4 py-3 text-primary font-mono text-xs">{"10.0.0.50"}</td>
                                <td class="px-4 py-3 text-secondary text-xs">{"example.com"}</td>
                                <td class="px-4 py-3 text-secondary text-xs">{"234 B"}</td>
                            </tr>
                            <tr class="border-b border-default hover:bg-tertiary/50 transition">
                                <td class="px-4 py-3 text-secondary font-mono text-xs">{"10:23:43"}</td>
                                <td class="px-4 py-3"><span class="px-2 py-1 rounded text-xs font-medium bg-blue-500/20 text-blue-400">{"GET"}</span></td>
                                <td class="px-4 py-3 text-primary font-mono text-xs max-w-[200px] truncate">{"/admin/config"}</td>
                                <td class="px-4 py-3 text-red-500">{"403"}</td>
                                <td class="px-4 py-3 text-secondary">{"12ms"}</td>
                                <td class="px-4 py-3 text-primary font-mono text-xs">{"172.16.0.25"}</td>
                                <td class="px-4 py-3 text-secondary text-xs">{"admin.example.com"}</td>
                                <td class="px-4 py-3 text-secondary text-xs">{"45 B"}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                <div class="px-4 py-3 border-t border-default flex items-center justify-between">
                    <span class="text-sm text-secondary">{ "Showing 1-3 of 1,234 entries" }</span>
                    <div class="flex gap-2">
                        <button class="px-3 py-1 bg-tertiary rounded text-sm text-secondary hover:text-primary disabled:opacity-50" disabled={true}>
                            { "Previous" }
                        </button>
                        <button class="px-3 py-1 bg-tertiary rounded text-sm text-secondary hover:text-primary">
                            { "Next" }
                        </button>
                    </div>
                </div>
            </div>
        </div>
    }
}
