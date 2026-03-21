#![allow(unused_variables, dead_code)]

use std::sync::Arc;

use axum::{
    extract::State,
    response::{Html, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::sync::{broadcast, RwLock};

use maluwaf::vpn_client::config::Protocol as VpnProtocol;
use maluwaf::vpn_client::{ClientPortMapping, VpnClient, VpnClientConfig};

pub struct VpnState {
    pub client: RwLock<Option<VpnClient>>,
    pub config: RwLock<VpnClientConfig>,
    pub shutdown_tx: broadcast::Sender<()>,
    pub api_key: RwLock<Option<String>>,
}

impl VpnState {
    pub fn new(api_key: Option<String>) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            client: RwLock::new(None),
            config: RwLock::new(VpnClientConfig::default()),
            shutdown_tx,
            api_key: RwLock::new(api_key),
        }
    }
}

impl Clone for VpnState {
    fn clone(&self) -> Self {
        Self {
            client: RwLock::new(None),
            config: RwLock::new(VpnClientConfig::default()),
            shutdown_tx: self.shutdown_tx.clone(),
            api_key: RwLock::new(None),
        }
    }
}

#[derive(Clone)]
pub struct ApiState(pub Arc<VpnState>);

#[derive(Serialize)]
pub struct StatusResponse {
    pub connected: bool,
    pub server: String,
    pub port: u16,
    pub transport: String,
    pub client_id: String,
    pub port_mappings: Vec<PortMappingResponse>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub connected_duration_secs: Option<u64>,
}

#[derive(Serialize)]
pub struct PortMappingResponse {
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: String,
    pub upstream_host: Option<String>,
}

#[derive(Deserialize)]
pub struct ConnectRequest {
    pub server: String,
    pub port: Option<u16>,
    pub client_id: String,
    pub token: String,
    pub transport: Option<String>,
    pub tcp_mappings: Option<Vec<MappingRequest>>,
    pub udp_mappings: Option<Vec<MappingRequest>>,
    pub verify_server: Option<bool>,
    pub api_key: Option<String>,
}

#[derive(Deserialize)]
pub struct MappingRequest {
    pub local_port: u16,
    pub remote_port: u16,
    pub upstream_host: Option<String>,
}

#[derive(Deserialize)]
pub struct AddMappingRequest {
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: String,
    pub upstream_host: Option<String>,
    #[serde(default)]
    pub api_key: Option<String>,
}

fn check_auth(state: &Arc<VpnState>, api_key: Option<&str>) -> bool {
    let stored = state.api_key.blocking_read();
    match (&*stored, api_key) {
        (None, _) => true,
        (Some(stored_key), Some(key)) => stored_key.as_bytes().ct_eq(key.as_bytes()).into(),
        _ => false,
    }
}

fn sanitize_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

async fn get_status(State(state): State<Arc<VpnState>>) -> Json<StatusResponse> {
    let client = state.client.read().await;
    let config = state.config.read().await;

    let (connected, stats) = if let Some(ref c) = *client {
        let s = c.get_stats();
        (c.is_connected(), s)
    } else {
        (false, maluwaf::vpn_client::VpnStats::default())
    };

    let port_mappings: Vec<PortMappingResponse> = config
        .port_mappings
        .iter()
        .map(|m| PortMappingResponse {
            local_port: m.local_port,
            remote_port: m.remote_port,
            protocol: m.protocol.to_string(),
            upstream_host: m.upstream_host.clone(),
        })
        .collect();

    let duration = if connected {
        stats.connected_at.map(|t| t.elapsed().as_secs())
    } else {
        None
    };

    Json(StatusResponse {
        connected,
        server: config.server_host.clone(),
        port: config.server_port,
        transport: format!("{:?}", config.transport),
        client_id: config.client_id.clone(),
        port_mappings,
        bytes_sent: stats.bytes_sent,
        bytes_received: stats.bytes_received,
        packets_sent: stats.packets_sent,
        packets_received: stats.packets_received,
        connected_duration_secs: duration,
    })
}

async fn connect(
    State(state): State<Arc<VpnState>>,
    Json(req): Json<ConnectRequest>,
) -> Json<serde_json::Value> {
    if !check_auth(&state, req.api_key.as_deref()) {
        return Json(serde_json::json!({"status": "error", "message": "Unauthorized"}));
    }

    let server = req.server.trim();
    if server.is_empty() {
        return Json(serde_json::json!({"status": "error", "message": "Server is required"}));
    }

    let client_id = req.client_id.trim();
    if client_id.is_empty() {
        return Json(serde_json::json!({"status": "error", "message": "Client ID is required"}));
    }

    let token = req.token.trim();
    if token.is_empty() {
        return Json(serde_json::json!({"status": "error", "message": "Token is required"}));
    }

    let port = req.port.unwrap_or(51821);
    if port == 0 {
        return Json(serde_json::json!({"status": "error", "message": "Invalid port"}));
    }

    let mut config = VpnClientConfig::new(server, port, client_id, token)
        .with_verify_server(req.verify_server.unwrap_or(true));

    if let Some(t) = req.transport {
        if t.eq_ignore_ascii_case("wireguard") {
            config = config.with_transport(maluwaf::vpn_client::TransportType::WireGuard);
        }
    }

    if let Some(tcp) = req.tcp_mappings {
        for m in tcp {
            if m.local_port == 0 || m.remote_port == 0 {
                return Json(
                    serde_json::json!({"status": "error", "message": "Invalid port mapping ports"}),
                );
            }
            config = config.with_tcp_mapping(m.local_port, m.remote_port);
        }
    }

    if let Some(udp) = req.udp_mappings {
        for m in udp {
            if m.local_port == 0 || m.remote_port == 0 {
                return Json(
                    serde_json::json!({"status": "error", "message": "Invalid port mapping ports"}),
                );
            }
            config = config.with_udp_mapping(m.local_port, m.remote_port);
        }
    }

    *state.config.write().await = config.clone();

    match VpnClient::new(config) {
        Ok(client) => {
            let mut c = state.client.write().await;
            *c = Some(client);
            Json(serde_json::json!({"status": "ok", "message": "Connected"}))
        }
        Err(e) => Json(serde_json::json!({"status": "error", "message": e.to_string()})),
    }
}

async fn disconnect(
    State(state): State<Arc<VpnState>>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let api_key = req.get("api_key").and_then(|v| v.as_str());
    if !check_auth(&state, api_key) {
        return Json(serde_json::json!({"status": "error", "message": "Unauthorized"}));
    }

    let mut client = state.client.write().await;
    if let Some(ref mut c) = *client {
        c.disconnect().await;
        *client = None;
        Json(serde_json::json!({"status": "ok", "message": "Disconnected"}))
    } else {
        Json(serde_json::json!({"status": "error", "message": "Not connected"}))
    }
}

async fn add_mapping(
    State(state): State<Arc<VpnState>>,
    Json(req): Json<AddMappingRequest>,
) -> Json<serde_json::Value> {
    let api_key = req.api_key.as_deref();
    if !check_auth(&state, api_key) {
        return Json(serde_json::json!({"status": "error", "message": "Unauthorized"}));
    }

    if req.local_port == 0 || req.remote_port == 0 {
        return Json(serde_json::json!({"status": "error", "message": "Invalid ports"}));
    }

    let mut config = state.config.write().await;

    let protocol = if req.protocol.eq_ignore_ascii_case("udp") {
        VpnProtocol::Udp
    } else {
        VpnProtocol::Tcp
    };

    let mapping = ClientPortMapping {
        local_port: req.local_port,
        remote_port: req.remote_port,
        protocol,
        upstream_host: req.upstream_host,
    };

    config.port_mappings.push(mapping);

    Json(serde_json::json!({"status": "ok", "message": "Mapping added"}))
}

async fn remove_mapping(
    State(state): State<Arc<VpnState>>,
    Json(req): Json<AddMappingRequest>,
) -> Json<serde_json::Value> {
    let api_key = req.api_key.as_deref();
    if !check_auth(&state, api_key) {
        return Json(serde_json::json!({"status": "error", "message": "Unauthorized"}));
    }

    let mut config = state.config.write().await;

    config.port_mappings.retain(|m| {
        !(m.local_port == req.local_port
            && m.protocol.to_string().eq_ignore_ascii_case(&req.protocol))
    });

    Json(serde_json::json!({"status": "ok", "message": "Mapping removed"}))
}

fn get_dashboard_html() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MaluWAF VPN Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root { --bg-primary: #0a0a0f; --bg-secondary: #12121a; --bg-tertiary: #1a1a24; --bg-card: #16161f; --text-primary: #f0f0f5; --text-secondary: #9090a0; --accent-primary: #00d4aa; --accent-secondary: #00b894; --accent-glow: rgba(0,212,170,0.3); --border-color: #2a2a3a; }
        body { background-color: var(--bg-primary); color: var(--text-primary); font-family: 'Inter', sans-serif; }
        .bg-card { background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 12px; }
        .text-accent { color: var(--accent-primary); }
        .border-accent { border-color: var(--accent-primary); }
        input, select { background-color: var(--bg-tertiary); border: 1px solid var(--border-color); color: var(--text-primary); border-radius: 8px; padding: 10px 14px; width: 100%; box-sizing: border-box; }
        input:focus, select:focus { outline: none; border-color: var(--accent-primary); box-shadow: 0 0 0 2px var(--accent-glow); }
        button { background-color: var(--accent-primary); color: var(--bg-primary); border-radius: 8px; padding: 10px 20px; font-weight: 600; border: none; cursor: pointer; transition: all 0.2s; }
        button:hover { box-shadow: 0 0 15px var(--accent-glow); transform: translateY(-1px); }
        button:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }
        button.secondary { background-color: var(--bg-tertiary); color: var(--text-primary); border: 1px solid var(--border-color); }
        button.secondary:hover { box-shadow: none; background-color: var(--bg-secondary); }
        button.danger { background-color: #dc2626; }
        button.danger:hover { box-shadow: 0 0 15px rgba(220,38,38,0.4); }
        .status-dot { width: 10px; height: 10px; border-radius: 50%; }
        .status-connected { background-color: #22c55e; box-shadow: 0 0 8px #22c55e; }
        .status-disconnected { background-color: #6b7280; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .animate-pulse { animation: pulse 2s infinite; }
    </style>
</head>
<body class="min-h-screen">
    <div class="max-w-5xl mx-auto p-6">
        <header class="flex justify-between items-center mb-8">
            <div class="flex items-center gap-4">
                <div class="w-12 h-12 rounded-xl bg-[var(--accent-primary)] flex items-center justify-center text-2xl font-bold text-[var(--bg-primary)]">M</div>
                <div>
                    <h1 class="text-2xl font-bold">VPN Dashboard</h1>
                    <p class="text-sm text-[var(--text-secondary)]" id="transportType">Transport: --</p>
                </div>
            </div>
            <div class="flex items-center gap-4">
                <div class="flex items-center gap-2 px-3 py-1.5 bg-[var(--bg-card)] rounded-lg border border-[var(--border-color)]">
                    <span class="status-dot" id="statusDot"></span>
                    <span id="statusText" class="font-medium">Disconnected</span>
                </div>
            </div>
        </header>
        
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
            <div class="bg-card p-6">
                <h2 class="text-lg font-semibold mb-4 flex items-center gap-2">
                    <svg class="w-5 h-5 text-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                    Connection
                </h2>
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm text-[var(--text-secondary)] mb-1.5">Server</label>
                        <input type="text" id="server" placeholder="waf.example.com">
                    </div>
                    <div class="grid grid-cols-2 gap-3">
                        <div>
                            <label class="block text-sm text-[var(--text-secondary)] mb-1.5">Port</label>
                            <input type="number" id="port" value="51821">
                        </div>
                        <div>
                            <label class="block text-sm text-[var(--text-secondary)] mb-1.5">Transport</label>
                            <select id="transport">
                                <option value="quic">QUIC</option>
                                <option value="wireguard">WireGuard</option>
                            </select>
                        </div>
                    </div>
                    <div>
                        <label class="block text-sm text-[var(--text-secondary)] mb-1.5">Client ID</label>
                        <input type="text" id="clientId" placeholder="my-client">
                    </div>
                    <div>
                        <label class="block text-sm text-[var(--text-secondary)] mb-1.5">Auth Token</label>
                        <input type="password" id="token" placeholder="your-secret-token">
                    </div>
                    <div class="flex gap-2">
                        <button onclick="connect()" id="connectBtn" class="flex-1">Connect</button>
                        <button onclick="disconnect()" class="danger" id="disconnectBtn" disabled>Disconnect</button>
                    </div>
                </div>
            </div>
            
            <div class="bg-card p-6">
                <h2 class="text-lg font-semibold mb-4 flex items-center gap-2">
                    <svg class="w-5 h-5 text-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
                    Statistics
                </h2>
                <div class="grid grid-cols-2 gap-3 mb-4">
                    <div class="bg-[var(--bg-secondary)] p-4 rounded-lg">
                        <div class="text-xs text-[var(--text-secondary)] uppercase tracking-wide">Upload</div>
                        <div class="text-xl font-mono font-semibold text-accent" id="bytesSent">0 B</div>
                    </div>
                    <div class="bg-[var(--bg-secondary)] p-4 rounded-lg">
                        <div class="text-xs text-[var(--text-secondary)] uppercase tracking-wide">Download</div>
                        <div class="text-xl font-mono font-semibold text-blue-400" id="bytesReceived">0 B</div>
                    </div>
                    <div class="bg-[var(--bg-secondary)] p-4 rounded-lg">
                        <div class="text-xs text-[var(--text-secondary)] uppercase tracking-wide">Packets Sent</div>
                        <div class="text-lg font-mono" id="packetsSent">0</div>
                    </div>
                    <div class="bg-[var(--bg-secondary)] p-4 rounded-lg">
                        <div class="text-xs text-[var(--text-secondary)] uppercase tracking-wide">Packets Received</div>
                        <div class="text-lg font-mono" id="packetsReceived">0</div>
                    </div>
                </div>
                <div class="flex justify-between items-center text-sm text-[var(--text-secondary)] bg-[var(--bg-secondary)] p-3 rounded-lg">
                    <span>Duration:</span>
                    <span class="font-mono" id="duration">--</span>
                </div>
            </div>
        </div>
        
        <div class="bg-card p-6 mb-6">
            <h2 class="text-lg font-semibold mb-4 flex items-center gap-2">
                <svg class="w-5 h-5 text-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z"/></svg>
                Traffic
            </h2>
            <canvas id="trafficChart" height="100"></canvas>
        </div>
        
        <div class="bg-card p-6">
            <h2 class="text-lg font-semibold mb-4 flex items-center gap-2">
                <svg class="w-5 h-5 text-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"/></svg>
                Port Mappings
            </h2>
            <div class="flex gap-2 mb-4 flex-wrap">
                <input type="number" id="mapLocalPort" class="w-24" placeholder="Local">
                <input type="number" id="mapRemotePort" class="w-24" placeholder="Remote">
                <select id="mapProtocol" class="w-24">
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                </select>
                <input type="text" id="mapUpstream" class="flex-1 min-w-[200px]" placeholder="Upstream (optional)">
                <button onclick="addMapping()" class="secondary">Add</button>
            </div>
            <div id="mappingsList" class="space-y-2"></div>
        </div>
    </div>
    
    <script>
        let chart = null;
        let cumulativeData = { upload: [], download: [], labels: [] };
        
        function formatBytes(b) { 
            if (!b || b === 0) return '0 B'; 
            const k = 1024; 
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB']; 
            const i = Math.floor(Math.log(b) / Math.log(k)); 
            return parseFloat((b / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]; 
        }
        
        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }
        
        function initChart() {
            const ctx = document.getElementById('trafficChart').getContext('2d');
            chart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        { label: 'Upload', data: [], borderColor: '#00d4aa', backgroundColor: 'rgba(0,212,170,0.1)', fill: true, tension: 0.3, pointRadius: 0 },
                        { label: 'Download', data: [], borderColor: '#3b82f6', backgroundColor: 'rgba(59,130,246,0.1)', fill: true, tension: 0.3, pointRadius: 0 }
                    ]
                },
                options: {
                    responsive: true,
                    interaction: { intersect: false, mode: 'index' },
                    scales: {
                        x: { display: false },
                        y: { 
                            ticks: { color: '#9090a0', callback: v => formatBytes(v) },
                            grid: { color: '#2a2a3a' },
                            beginAtZero: true
                        }
                    },
                    plugins: {
                        legend: { labels: { color: '#f0f0f5' } },
                        tooltip: { callbacks: { label: ctx => ctx.dataset.label + ': ' + formatBytes(ctx.raw) } }
                    }
                }
            });
        }
        
        async function loadStatus() {
            try {
                const res = await fetch('/api/status');
                const d = await res.json();
                
                document.getElementById('server').value = d.server || '';
                document.getElementById('port').value = d.port || 51821;
                document.getElementById('transportType').textContent = 'Transport: ' + (d.transport || '--');
                document.getElementById('clientId').value = d.client_id || '';
                
                document.getElementById('bytesSent').textContent = formatBytes(d.bytes_sent);
                document.getElementById('bytesReceived').textContent = formatBytes(d.bytes_received);
                document.getElementById('packetsSent').textContent = d.packets_sent.toLocaleString();
                document.getElementById('packetsReceived').textContent = d.packets_received.toLocaleString();
                document.getElementById('duration').textContent = d.connected_duration_secs ? d.connected_duration_secs + 's' : '--';
                
                cumulativeData.labels.push(new Date().toLocaleTimeString());
                cumulativeData.upload.push(d.bytes_sent);
                cumulativeData.download.push(d.bytes_received);
                if (cumulativeData.labels.length > 30) {
                    cumulativeData.labels.shift();
                    cumulativeData.upload.shift();
                    cumulativeData.download.shift();
                }
                chart.data.labels = cumulativeData.labels;
                chart.data.datasets[0].data = cumulativeData.upload;
                chart.data.datasets[1].data = cumulativeData.download;
                chart.update('none');
                
                const statusDot = document.getElementById('statusDot');
                const statusText = document.getElementById('statusText');
                const connectBtn = document.getElementById('connectBtn');
                const disconnectBtn = document.getElementById('disconnectBtn');
                
                if (d.connected) {
                    statusDot.className = 'status-dot status-connected';
                    statusText.textContent = 'Connected';
                    connectBtn.disabled = true;
                    disconnectBtn.disabled = false;
                } else {
                    statusDot.className = 'status-dot status-disconnected';
                    statusText.textContent = 'Disconnected';
                    connectBtn.disabled = false;
                    disconnectBtn.disabled = true;
                }
                
                const list = document.getElementById('mappingsList');
                if (d.port_mappings && d.port_mappings.length > 0) {
                    list.innerHTML = d.port_mappings.map(m => 
                        '<div class="flex justify-between items-center bg-[var(--bg-secondary)] p-3 rounded-lg">' +
                            '<span class="font-mono text-sm">' + escapeHtml(String(m.local_port)) + ' → ' + escapeHtml(String(m.remote_port)) + ' <span class="text-[var(--text-secondary)]">(' + escapeHtml(m.protocol).toUpperCase() + ')</span>' +
                            (m.upstream_host ? ' <span class="text-accent">→ ' + escapeHtml(m.upstream_host) + '</span>' : '') + '</span>' +
                            '<button onclick="removeMapping(' + m.local_port + ',\'' + m.protocol + '\')" class="text-red-400 text-sm hover:text-red-300 bg-transparent border-none cursor-pointer">Remove</button>' +
                        '</div>'
                    ).join('');
                } else {
                    list.innerHTML = '<div class="text-[var(--text-secondary)] text-center py-4">No port mappings configured</div>';
                }
            } catch(e) { console.error(e); }
        }
        
        async function connect() {
            const s = document.getElementById('server').value;
            const p = parseInt(document.getElementById('port').value);
            const t = document.getElementById('transport').value;
            const c = document.getElementById('clientId').value;
            const tok = document.getElementById('token').value;
            if (!s || !c || !tok) { alert('Fill all required fields'); return; }
            if (!Number.isInteger(p) || p <= 0 || p > 65535) { alert('Invalid port'); return; }
            const res = await fetch('/api/connect', { 
                method: 'POST', 
                headers: {'Content-Type': 'application/json'}, 
                body: JSON.stringify({ server: s, port: p, transport: t, client_id: c, token: tok, verify_server: true }) 
            });
            const d = await res.json();
            if (d.status === 'error') { alert(d.message); }
            loadStatus();
        }
        
        async function disconnect() {
            await fetch('/api/disconnect', { 
                method: 'POST', 
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({}) 
            });
            loadStatus();
        }
        
        async function addMapping() {
            const lp = parseInt(document.getElementById('mapLocalPort').value);
            const rp = parseInt(document.getElementById('mapRemotePort').value);
            const proto = document.getElementById('mapProtocol').value;
            const up = document.getElementById('mapUpstream').value || null;
            if (!lp || !rp || lp <= 0 || rp <= 0 || lp > 65535 || rp > 65535) { alert('Invalid ports'); return; }
            await fetch('/api/mapping/add', { 
                method: 'POST', 
                headers: {'Content-Type': 'application/json'}, 
                body: JSON.stringify({ local_port: lp, remote_port: rp, protocol: proto, upstream_host: up }) 
            });
            document.getElementById('mapLocalPort').value = '';
            document.getElementById('mapRemotePort').value = '';
            document.getElementById('mapUpstream').value = '';
            loadStatus();
        }
        
        async function removeMapping(localPort, protocol) {
            await fetch('/api/mapping/remove', { 
                method: 'POST', 
                headers: {'Content-Type': 'application/json'}, 
                body: JSON.stringify({ local_port: localPort, protocol: protocol }) 
            });
            loadStatus();
        }
        
        initChart();
        loadStatus();
        setInterval(loadStatus, 2000);
    </script>
</body>
</html>"#
}

async fn dashboard() -> Html<String> {
    Html(get_dashboard_html().to_string())
}

pub async fn start_server(addr: &str, api_key: Option<String>) {
    let state = Arc::new(VpnState::new(api_key));

    let app = Router::new()
        .route("/", get(dashboard))
        .route("/api/status", get(get_status))
        .route("/api/connect", post(connect))
        .route("/api/disconnect", post(disconnect))
        .route("/api/mapping/add", post(add_mapping))
        .route("/api/mapping/remove", post(remove_mapping))
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind to {}: {}", addr, e);
            return;
        }
    };

    tracing::info!("VPN Dashboard: http://{}/", addr);

    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("Server error: {}", e);
    }
}

#[tokio::main]
async fn main() {
    tracing::info!(
        "Use 'maluwaf --help' to see available commands. This binary is not yet fully implemented."
    );
}
