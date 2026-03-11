use crate::types::presets::{get_presets, ServerPreset};
use serde::{Deserialize, Serialize};
use yew::prelude::*;

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct UpstreamServer {
    pub id: String,
    pub url: String,
    pub name: String,
    pub status: ServerStatus,
    pub connections: usize,
    pub max_connections: usize,
    pub weight: u32,
    pub consecutive_failures: u32,
    pub preset: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub enum ServerStatus {
    Running,
    Stopped,
    Starting,
    Error,
}

#[function_component]
pub fn Upstreams() -> Html {
    let mock_upstreams = vec![
        UpstreamServer {
            id: "1".to_string(),
            url: "http://127.0.0.1:8000".to_string(),
            name: "Web App Primary".to_string(),
            status: ServerStatus::Running,
            connections: 12,
            max_connections: 100,
            weight: 100,
            consecutive_failures: 0,
            preset: Some("nodejs".to_string()),
        },
        UpstreamServer {
            id: "2".to_string(),
            url: "http://127.0.0.1:8001".to_string(),
            name: "Web App Secondary".to_string(),
            status: ServerStatus::Running,
            connections: 8,
            max_connections: 100,
            weight: 50,
            consecutive_failures: 0,
            preset: Some("nodejs".to_string()),
        },
        UpstreamServer {
            id: "3".to_string(),
            url: "http://api.internal:8001".to_string(),
            name: "API Server".to_string(),
            status: ServerStatus::Running,
            connections: 45,
            max_connections: 200,
            weight: 100,
            consecutive_failures: 0,
            preset: Some("python".to_string()),
        },
    ];

    html! {
        <div>
            <div class="flex justify-between items-center mb-6">
                <h1 class="text-2xl font-bold">{ "Upstream Servers" }</h1>
                <div class="flex gap-3">
                    <button class="px-4 py-2 bg-tertiary text-primary rounded-lg hover:opacity-80">
                        { "Refresh Status" }
                    </button>
                    <button class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
                        { "+ Launch Server" }
                    </button>
                </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
                <div class="bg-secondary rounded-lg border border-default p-4">
                    <div class="flex items-center gap-3">
                        <div class="p-3 rounded-lg bg-blue-500/10 text-blue-500">
                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
                            </svg>
                        </div>
                        <div>
                            <p class="text-sm text-secondary">{ "Total Servers" }</p>
                            <p class="text-2xl font-bold">{ mock_upstreams.len() }</p>
                        </div>
                    </div>
                </div>
                <div class="bg-secondary rounded-lg border border-default p-4">
                    <div class="flex items-center gap-3">
                        <div class="p-3 rounded-lg bg-green-500/10 text-green-500">
                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                            </svg>
                        </div>
                        <div>
                            <p class="text-sm text-secondary">{ "Running" }</p>
                            <p class="text-2xl font-bold">{ mock_upstreams.iter().filter(|s| s.status == ServerStatus::Running).count() }</p>
                        </div>
                    </div>
                </div>
                <div class="bg-secondary rounded-lg border border-default p-4">
                    <div class="flex items-center gap-3">
                        <div class="p-3 rounded-lg bg-gray-500/10 text-gray-500">
                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 10a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z" />
                            </svg>
                        </div>
                        <div>
                            <p class="text-sm text-secondary">{ "Stopped" }</p>
                            <p class="text-2xl font-bold">{ mock_upstreams.iter().filter(|s| s.status == ServerStatus::Stopped).count() }</p>
                        </div>
                    </div>
                </div>
            </div>

            <div class="space-y-4">
                {for mock_upstreams.iter().map(|server| {
                    let status_color = match server.status {
                        ServerStatus::Running => "bg-green-500",
                        ServerStatus::Stopped => "bg-gray-500",
                        ServerStatus::Starting => "bg-yellow-500 animate-pulse",
                        ServerStatus::Error => "bg-red-500",
                    };
                    let status_text = match server.status {
                        ServerStatus::Running => "Running",
                        ServerStatus::Stopped => "Stopped",
                        ServerStatus::Starting => "Starting...",
                        ServerStatus::Error => "Error",
                    };

                    html! {
                        <div class="bg-secondary rounded-lg border border-default p-4">
                            <div class="flex items-center justify-between mb-4">
                                <div class="flex items-center gap-3">
                                    <span class={format!("w-3 h-3 rounded-full {}", status_color)} />
                                    <h3 class="text-lg font-semibold">{ &server.name }</h3>
                                    if let Some(preset) = &server.preset {
                                        <span class="px-2 py-0.5 bg-tertiary rounded text-xs text-secondary">{ preset }</span>
                                    }
                                </div>
                                <span class="text-sm text-secondary">{ status_text }</span>
                            </div>

                            <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                                <div>
                                    <p class="text-xs text-secondary">{ "URL" }</p>
                                    <p class="text-sm font-mono text-primary">{ &server.url }</p>
                                </div>
                                <div>
                                    <p class="text-xs text-secondary">{ "Connections" }</p>
                                    <p class="text-sm text-primary">{ format!("{}/{}", server.connections, server.max_connections) }</p>
                                </div>
                                <div>
                                    <p class="text-xs text-secondary">{ "Weight" }</p>
                                    <p class="text-sm text-primary">{ server.weight }</p>
                                </div>
                                <div>
                                    <p class="text-xs text-secondary">{ "Failures" }</p>
                                    <p class={if server.consecutive_failures > 0 { "text-sm text-red-500" } else { "text-sm text-green-500" }}>
                                        { server.consecutive_failures }
                                    </p>
                                </div>
                            </div>

                            <div class="flex gap-2">
                                if server.status == ServerStatus::Running {
                                    <button class="px-3 py-1 text-xs bg-yellow-600 text-white rounded hover:bg-yellow-700">
                                        { "Stop" }
                                    </button>
                                } else if server.status == ServerStatus::Stopped {
                                    <button class="px-3 py-1 text-xs bg-green-600 text-white rounded hover:bg-green-700">
                                        { "Start" }
                                    </button>
                                }
                                <button class="px-3 py-1 text-xs bg-blue-600 text-white rounded hover:bg-blue-700">
                                    { "Edit" }
                                </button>
                                <button class="px-3 py-1 text-xs bg-red-600 text-white rounded hover:bg-red-700">
                                    { "Delete" }
                                </button>
                            </div>
                        </div>
                    }
                })}
            </div>
        </div>
    }
}
