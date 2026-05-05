use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct TcpDefaults {
    #[serde(default = "default_tcp_enabled")]
    pub enabled: bool,
    #[serde(default = "default_tcp_worker_pool_size")]
    pub worker_pool_size: usize,
    #[serde(default)]
    pub protocols: HashMap<String, TcpProtocolConfig>,
    #[serde(default)]
    pub socket: TcpSocketConfig,
    #[serde(default = "default_syn_rate_per_ip")]
    pub syn_rate_per_ip: u32,
    #[serde(default = "default_syn_rate_global")]
    pub syn_rate_global: u32,
    #[serde(default = "default_connection_rate_per_ip")]
    pub connection_rate_per_ip: u32,
    #[serde(default = "default_connection_rate_global")]
    pub connection_rate_global: u32,
    #[serde(default = "default_half_open_max")]
    pub half_open_max: u32,
    #[serde(default = "default_half_open_per_ip_max")]
    pub half_open_per_ip_max: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct TcpSocketConfig {
    #[serde(default = "default_tcp_nodelay")]
    pub nodelay: bool,
    #[serde(default = "default_tcp_send_buffer_size")]
    pub send_buffer_size: usize,
    #[serde(default = "default_tcp_recv_buffer_size")]
    pub recv_buffer_size: usize,
}

impl Default for TcpSocketConfig {
    fn default() -> Self {
        Self {
            nodelay: default_tcp_nodelay(),
            send_buffer_size: default_tcp_send_buffer_size(),
            recv_buffer_size: default_tcp_recv_buffer_size(),
        }
    }
}

fn default_tcp_nodelay() -> bool {
    true
}
fn default_tcp_send_buffer_size() -> usize {
    262144
}
fn default_tcp_recv_buffer_size() -> usize {
    262144
}

fn default_syn_rate_per_ip() -> u32 {
    50
}
fn default_syn_rate_global() -> u32 {
    10000
}
fn default_connection_rate_per_ip() -> u32 {
    100
}
fn default_connection_rate_global() -> u32 {
    20000
}
fn default_half_open_max() -> u32 {
    1000
}
fn default_half_open_per_ip_max() -> u32 {
    10
}

impl Default for TcpDefaults {
    fn default() -> Self {
        Self {
            enabled: false,
            worker_pool_size: 4,
            protocols: Self::default_protocols(),
            socket: TcpSocketConfig::default(),
            syn_rate_per_ip: default_syn_rate_per_ip(),
            syn_rate_global: default_syn_rate_global(),
            connection_rate_per_ip: default_connection_rate_per_ip(),
            connection_rate_global: default_connection_rate_global(),
            half_open_max: default_half_open_max(),
            half_open_per_ip_max: default_half_open_per_ip_max(),
        }
    }
}

impl TcpDefaults {
    fn default_protocols() -> HashMap<String, TcpProtocolConfig> {
        let mut protocols = HashMap::new();
        protocols.insert(
            "smtp".to_string(),
            TcpProtocolConfig {
                ports: vec![25, 587],
                upstream_format: Some("127.0.0.1:{port}".to_string()),
                upstream_format_v6: Some("[::1]:{port}".to_string()),
            },
        );
        protocols.insert(
            "imap".to_string(),
            TcpProtocolConfig {
                ports: vec![143, 993],
                upstream_format: Some("127.0.0.1:{port}".to_string()),
                upstream_format_v6: Some("[::1]:{port}".to_string()),
            },
        );
        protocols.insert(
            "pop3".to_string(),
            TcpProtocolConfig {
                ports: vec![110, 995],
                upstream_format: Some("127.0.0.1:{port}".to_string()),
                upstream_format_v6: Some("[::1]:{port}".to_string()),
            },
        );
        protocols.insert(
            "mysql".to_string(),
            TcpProtocolConfig {
                ports: vec![3306],
                upstream_format: Some("127.0.0.1:{port}".to_string()),
                upstream_format_v6: Some("[::1]:{port}".to_string()),
            },
        );
        protocols.insert(
            "postgres".to_string(),
            TcpProtocolConfig {
                ports: vec![5432],
                upstream_format: Some("127.0.0.1:{port}".to_string()),
                upstream_format_v6: Some("[::1]:{port}".to_string()),
            },
        );
        protocols
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct TcpProtocolConfig {
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub upstream_format: Option<String>,
    #[serde(default)]
    pub upstream_format_v6: Option<String>,
}

fn default_tcp_enabled() -> bool {
    false
}
fn default_tcp_worker_pool_size() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct UdpDefaults {
    #[serde(default = "default_udp_enabled")]
    pub enabled: bool,
    #[serde(default = "default_udp_worker_pool_size")]
    pub worker_pool_size: usize,
    #[serde(default)]
    pub protocols: HashMap<String, UdpProtocolConfig>,
    #[serde(default)]
    pub socket: UdpSocketConfig,
    #[serde(default = "default_udp_rate_per_ip")]
    pub rate_per_ip: u32,
    #[serde(default = "default_udp_rate_global")]
    pub rate_global: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct UdpSocketConfig {
    #[serde(default = "default_udp_recv_buffer_size")]
    pub recv_buffer_size: usize,
    #[serde(default = "default_udp_send_buffer_size")]
    pub send_buffer_size: usize,
}

impl Default for UdpSocketConfig {
    fn default() -> Self {
        Self {
            recv_buffer_size: default_udp_recv_buffer_size(),
            send_buffer_size: default_udp_send_buffer_size(),
        }
    }
}

fn default_udp_recv_buffer_size() -> usize {
    131072
}
fn default_udp_send_buffer_size() -> usize {
    131072
}

impl Default for UdpDefaults {
    fn default() -> Self {
        Self {
            enabled: false,
            worker_pool_size: 4,
            protocols: Self::default_protocols(),
            socket: UdpSocketConfig::default(),
            rate_per_ip: default_udp_rate_per_ip(),
            rate_global: default_udp_rate_global(),
        }
    }
}

impl UdpDefaults {
    fn default_protocols() -> HashMap<String, UdpProtocolConfig> {
        let mut protocols = HashMap::new();
        protocols.insert(
            "dns".to_string(),
            UdpProtocolConfig {
                ports: vec![53],
                upstream_format: Some("127.0.0.1:5353".to_string()),
                upstream_format_v6: Some("[::1]:5353".to_string()),
            },
        );
        protocols
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct UdpProtocolConfig {
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub upstream_format: Option<String>,
    #[serde(default)]
    pub upstream_format_v6: Option<String>,
}

fn default_udp_enabled() -> bool {
    false
}
fn default_udp_worker_pool_size() -> usize {
    4
}
fn default_udp_rate_per_ip() -> u32 {
    1000
}
fn default_udp_rate_global() -> u32 {
    100000
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct TarpitDefaults {
    #[serde(default = "default_tarpit_enabled")]
    pub enabled: bool,
    #[serde(default = "default_tarpit_depth")]
    pub max_depth: u32,
    #[serde(default = "default_tarpit_links")]
    pub links_per_page: u32,
    #[serde(default = "default_tarpit_delay")]
    pub response_delay_ms: u64,
    #[serde(default)]
    pub scraper_user_agents: Vec<String>,
    #[serde(default)]
    pub content_templates: Vec<String>,
}

impl Default for TarpitDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            max_depth: 10,
            links_per_page: 50,
            response_delay_ms: 100,
            scraper_user_agents: vec![
                "scrapy".to_string(),
                "curl".to_string(),
                "wget".to_string(),
                "python-requests".to_string(),
                "python-urllib".to_string(),
                "aiohttp".to_string(),
                "httpx".to_string(),
                "go-http".to_string(),
                "node-fetch".to_string(),
                "axios".to_string(),
                "rubygems".to_string(),
                "java".to_string(),
                "okhttp".to_string(),
                "feedparser".to_string(),
                " UniversalFeedParser".to_string(),
                "libwww-perl".to_string(),
                "PySpider".to_string(),
                "scrapeloader".to_string(),
                "SiteAnalyzer".to_string(),
                "Screaming Frog".to_string(),
            ],
            content_templates: vec![],
        }
    }
}

fn default_tarpit_enabled() -> bool {
    true
}
fn default_tarpit_depth() -> u32 {
    10
}
fn default_tarpit_links() -> u32 {
    50
}
fn default_tarpit_delay() -> u64 {
    100
}
