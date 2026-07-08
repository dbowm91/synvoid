use serde::{Deserialize, Serialize};
use std::net::IpAddr;

fn default_true() -> bool {
    true
}
fn default_mesh_enabled() -> bool {
    false
}
fn default_max_prompt_bytes() -> usize {
    4096
}
fn default_max_response_bytes() -> usize {
    2048
}
fn default_max_generation_secs() -> u64 {
    10
}
fn default_max_turns() -> usize {
    5
}
fn default_max_concurrent_ai() -> usize {
    4
}
fn default_max_provider_failures() -> usize {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_mesh_enabled")]
    pub mesh_enabled: bool,
    #[serde(default)]
    pub scoring: crate::threat_intel::ScoringConfig,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mesh_enabled: false,
            scoring: crate::threat_intel::ScoringConfig::default(),
        }
    }
}

/// AI responder operational mode. Default is `Disabled`.
///
/// - `Disabled`: No AI responses; template/vulnerable-app only.
/// - `TemplateOnly`: Deterministic protocol banners, no external calls.
/// - `LocalModelOnly`: Local model (e.g. Ollama) with strict budgets.
/// - `ExternalProvider`: External API (OpenAI/Anthropic) — experimental, opt-in.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AiResponderMode {
    #[default]
    Disabled,
    TemplateOnly,
    LocalModelOnly,
    ExternalProvider,
}

/// Hard budgets for AI responder behavior. Prevents unbounded cost, prompt
/// injection amplification, and provider abuse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiBudgetConfig {
    /// Maximum prompt bytes sent to provider (token approximation via bytes).
    #[serde(default = "default_max_prompt_bytes")]
    pub max_prompt_bytes: usize,
    /// Maximum response bytes retained from provider.
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
    /// Maximum generation duration in seconds before timeout.
    #[serde(default = "default_max_generation_secs")]
    pub max_generation_duration_secs: u64,
    /// Maximum AI turns per connection.
    #[serde(default = "default_max_turns")]
    pub max_turns_per_connection: usize,
    /// Maximum concurrent AI responder requests globally.
    #[serde(default = "default_max_concurrent_ai")]
    pub max_concurrent_requests: usize,
    /// Provider failures before circuit breaker opens.
    #[serde(default = "default_max_provider_failures")]
    pub max_provider_failures: usize,
}

impl Default for AiBudgetConfig {
    fn default() -> Self {
        Self {
            max_prompt_bytes: default_max_prompt_bytes(),
            max_response_bytes: default_max_response_bytes(),
            max_generation_duration_secs: default_max_generation_secs(),
            max_turns_per_connection: default_max_turns(),
            max_concurrent_requests: default_max_concurrent_ai(),
            max_provider_failures: default_max_provider_failures(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortHoneypotConfig {
    pub enabled: bool,
    pub bind_address: IpAddr,
    pub min_port: u16,
    pub max_port: u16,
    pub min_rotation_interval_secs: u64,
    pub max_rotation_interval_secs: u64,
    pub rotation_interval_secs: u64,
    pub num_honeypot_ports: usize,
    pub connection_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub max_payload_size: usize,
    pub max_concurrent_connections: usize,
    pub max_connections_per_ip: usize,
    pub services: Vec<ServiceConfig>,
    pub storage: StorageConfig,
    pub response_mode: ResponseModeConfig,
    pub stable_ports: Vec<StablePortConfig>,
    pub ai_config: Option<AiConfig>,
    pub site_scope: String,
    pub threat_intel: ThreatIntelConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StablePortConfig {
    pub port: u16,
    pub service: String,
    pub responder: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseModeConfig {
    pub mode: String,
    pub responder_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    /// AI responder mode. Default: `Disabled`.
    #[serde(default)]
    pub mode: AiResponderMode,
    /// Provider identifier: "ollama", "openai", or "anthropic".
    pub provider: String,
    pub endpoint: Option<String>,
    pub api_key: Option<String>,
    pub model: String,
    pub timeout_secs: u64,
    pub system_prompt: Option<String>,
    /// Hard budgets for prompt/response sizes, concurrency, and circuit breaker.
    #[serde(default)]
    pub budget: AiBudgetConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub name: String,
    pub protocol: String,
    pub banner: Vec<u8>,
    pub ports: Vec<u16>,
    pub response_patterns: Vec<ResponsePattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePattern {
    pub pattern: String,
    pub response: Vec<u8>,
    pub next_protocol: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PayloadRetentionMode {
    None,
    HashOnly,
    #[default]
    Truncated,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageWriterConfig {
    pub queue_capacity: usize,
    pub batch_size: usize,
    pub flush_interval_ms: u64,
    pub write_timeout_ms: u64,
    pub payload_retention_mode: PayloadRetentionMode,
    pub max_stored_payload_bytes: usize,
    pub max_stored_payload_hex_bytes: usize,
}

impl Default for StorageWriterConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 4096,
            batch_size: 64,
            flush_interval_ms: 1000,
            write_timeout_ms: 500,
            payload_retention_mode: PayloadRetentionMode::Truncated,
            max_stored_payload_bytes: 256,
            max_stored_payload_hex_bytes: 512,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub database_path: String,
    pub max_records: u64,
    pub retention_days: u32,
    pub flush_interval_secs: u32,
    #[serde(default)]
    pub writer: StorageWriterConfig,
}

impl Default for PortHoneypotConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: IpAddr::from([0, 0, 0, 0]),
            min_port: 10000,
            max_port: 60000,
            min_rotation_interval_secs: 600,
            max_rotation_interval_secs: 3600,
            rotation_interval_secs: 1800,
            num_honeypot_ports: 3,
            connection_timeout_ms: 5000,
            read_timeout_ms: 10000,
            max_payload_size: 8192,
            max_concurrent_connections: 256,
            max_connections_per_ip: 10,
            services: default_services(),
            storage: StorageConfig::default(),
            response_mode: ResponseModeConfig {
                mode: "cycling".to_string(),
                responder_type: Some("vulnerable".to_string()),
            },
            stable_ports: Vec::new(),
            ai_config: None,
            site_scope: "global".to_string(),
            threat_intel: ThreatIntelConfig::default(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database_path: "/var/lib/synvoid/honeypot.db".to_string(),
            max_records: 1_000_000,
            retention_days: 90,
            flush_interval_secs: 60,
            writer: StorageWriterConfig::default(),
        }
    }
}

fn default_services() -> Vec<ServiceConfig> {
    vec![
        ServiceConfig {
            name: "http".to_string(),
            protocol: "http".to_string(),
            banner: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Length: 0\r\n\r\n".to_vec(),
            ports: vec![80, 8080, 8888],
            response_patterns: vec![
                ResponsePattern {
                    pattern: r"^GET ".to_string(),
                    response: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\nContent-Length: 426\r\n\r\n".to_vec(),
                    next_protocol: None,
                },
                ResponsePattern {
                    pattern: r"^POST ".to_string(),
                    response: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Length: 0\r\n\r\n".to_vec(),
                    next_protocol: None,
                },
            ],
        },
        ServiceConfig {
            name: "https".to_string(),
            protocol: "tls".to_string(),
            banner: vec![0x16, 0x03, 0x01, 0x00, 0xc8, 0x01, 0x00, 0x00, 0xc4, 0x03, 0x03],
            ports: vec![443, 8443],
            response_patterns: vec![],
        },
        ServiceConfig {
            name: "ssh".to_string(),
            protocol: "ssh".to_string(),
            banner: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n".to_vec(),
            ports: vec![22, 2222],
            response_patterns: vec![],
        },
        ServiceConfig {
            name: "mysql".to_string(),
            protocol: "mysql".to_string(),
            banner: vec![0x0a, 0x00, 0x00, 0x01, 0xff, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            ports: vec![3306],
            response_patterns: vec![],
        },
        ServiceConfig {
            name: "redis".to_string(),
            protocol: "redis".to_string(),
            banner: b"+OK\r\n".to_vec(),
            ports: vec![6379],
            response_patterns: vec![],
        },
        ServiceConfig {
            name: "ftp".to_string(),
            protocol: "ftp".to_string(),
            banner: b"220 (vsFTPd 3.0.3)\r\n".to_vec(),
            ports: vec![21],
            response_patterns: vec![
                ResponsePattern {
                    pattern: r"^USER ".to_string(),
                    response: b"331 Please specify the password.\r\n".to_vec(),
                    next_protocol: None,
                },
                ResponsePattern {
                    pattern: r"^PASS ".to_string(),
                    response: b"530 Login authentication failed\r\n".to_vec(),
                    next_protocol: None,
                },
            ],
        },
        ServiceConfig {
            name: "postgresql".to_string(),
            protocol: "postgresql".to_string(),
            banner: [0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f].to_vec(),
            ports: vec![5432, 5433],
            response_patterns: vec![],
        },
        ServiceConfig {
            name: "smb".to_string(),
            protocol: "smb".to_string(),
            banner: [0x00, 0x00, 0x00, 0x85].to_vec(),
            ports: vec![139, 445],
            response_patterns: vec![],
        },
        ServiceConfig {
            name: "rdp".to_string(),
            protocol: "rdp".to_string(),
            banner: [0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00].to_vec(),
            ports: vec![3389],
            response_patterns: vec![],
        },
        ServiceConfig {
            name: "vnc".to_string(),
            protocol: "vnc".to_string(),
            banner: b"RFB 003.008\n".to_vec(),
            ports: vec![5900, 5901, 5902],
            response_patterns: vec![],
        },
        ServiceConfig {
            name: "smtp".to_string(),
            protocol: "smtp".to_string(),
            banner: b"220 mail.example.com ESMTP Postfix\r\n".to_vec(),
            ports: vec![25, 465, 587],
            response_patterns: vec![
                ResponsePattern {
                    pattern: r"^EHLO".to_string(),
                    response: b"250-mail.example.com\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-ETRN\r\n250-STARTTLS\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250 SMTPUTF8\r\n".to_vec(),
                    next_protocol: None,
                },
                ResponsePattern {
                    pattern: r"^QUIT".to_string(),
                    response: b"221 2.0.0 Bye\r\n".to_vec(),
                    next_protocol: None,
                },
            ],
        },
    ]
}
