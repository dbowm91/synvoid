use serde::{Deserialize, Serialize};
use std::net::IpAddr;

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
    pub services: Vec<ServiceConfig>,
    pub storage: StorageConfig,
    pub response_mode: ResponseModeConfig,
    pub stable_ports: Vec<StablePortConfig>,
    pub ai_config: Option<AiConfig>,
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
    pub provider: String,
    pub endpoint: Option<String>,
    pub api_key: Option<String>,
    pub model: String,
    pub timeout_secs: u64,
    pub system_prompt: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub database_path: String,
    pub max_records: u64,
    pub retention_days: u32,
    pub flush_interval_secs: u32,
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
            services: default_services(),
            storage: StorageConfig::default(),
            response_mode: ResponseModeConfig {
                mode: "cycling".to_string(),
                responder_type: Some("vulnerable".to_string()),
            },
            stable_ports: Vec::new(),
            ai_config: None,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database_path: "/var/lib/maluwaf/honeypot.db".to_string(),
            max_records: 1_000_000,
            retention_days: 90,
            flush_interval_secs: 60,
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
            banner: vec![0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f].to_vec(),
            ports: vec![5432, 5433],
            response_patterns: vec![],
        },
        ServiceConfig {
            name: "smb".to_string(),
            protocol: "smb".to_string(),
            banner: vec![0x00, 0x00, 0x00, 0x85].to_vec(),
            ports: vec![139, 445],
            response_patterns: vec![],
        },
        ServiceConfig {
            name: "rdp".to_string(),
            protocol: "rdp".to_string(),
            banner: vec![0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00].to_vec(),
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
