use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerPreset {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: PresetCategory,
    pub config: PresetConfig,
    pub icon: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PresetCategory {
    WebApp,
    StaticFile,
    Email,
    Database,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PresetConfig {
    pub default_port: u16,
    pub protocol: String,
    pub recommended_upstream_format: Option<String>,
    pub suggested_settings: Vec<SettingSuggestion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SettingSuggestion {
    pub key: String,
    pub value: String,
    pub description: String,
}

pub fn get_presets() -> Vec<ServerPreset> {
    vec![
        ServerPreset {
            id: "static_files".to_string(),
            name: "Static File Server".to_string(),
            description: "Serve static files (HTML, CSS, JS, images)".to_string(),
            category: PresetCategory::StaticFile,
            icon: "document".to_string(),
            config: PresetConfig {
                default_port: 80,
                protocol: "http".to_string(),
                recommended_upstream_format: None,
                suggested_settings: vec![
                    SettingSuggestion {
                        key: "enable_static".to_string(),
                        value: "true".to_string(),
                        description: "Enable static file serving".to_string(),
                    },
                    SettingSuggestion {
                        key: "index_files".to_string(),
                        value: "index.html,index.htm".to_string(),
                        description: "Default index files to serve".to_string(),
                    },
                    SettingSuggestion {
                        key: "cache_headers".to_string(),
                        value: "true".to_string(),
                        description: "Enable browser caching headers".to_string(),
                    },
                    SettingSuggestion {
                        key: "gzip".to_string(),
                        value: "true".to_string(),
                        description: "Enable Gzip compression".to_string(),
                    },
                ],
            },
        },
        ServerPreset {
            id: "nodejs".to_string(),
            name: "Node.js Web App".to_string(),
            description: "Reverse proxy to Node.js application server".to_string(),
            category: PresetCategory::WebApp,
            icon: "code".to_string(),
            config: PresetConfig {
                default_port: 3000,
                protocol: "http".to_string(),
                recommended_upstream_format: Some("http://127.0.0.1:3000".to_string()),
                suggested_settings: vec![
                    SettingSuggestion {
                        key: "health_check_path".to_string(),
                        value: "/health".to_string(),
                        description: "Path for health check endpoint".to_string(),
                    },
                    SettingSuggestion {
                        key: "request_timeout".to_string(),
                        value: "30".to_string(),
                        description: "Request timeout in seconds".to_string(),
                    },
                    SettingSuggestion {
                        key: "keep_alive".to_string(),
                        value: "true".to_string(),
                        description: "Enable keep-alive connections".to_string(),
                    },
                ],
            },
        },
        ServerPreset {
            id: "python".to_string(),
            name: "Python Web App (Django/Flask)".to_string(),
            description: "Reverse proxy to Python WSGI application".to_string(),
            category: PresetCategory::WebApp,
            icon: "code".to_string(),
            config: PresetConfig {
                default_port: 8000,
                protocol: "http".to_string(),
                recommended_upstream_format: Some("http://127.0.0.1:8000".to_string()),
                suggested_settings: vec![
                    SettingSuggestion {
                        key: "health_check_path".to_string(),
                        value: "/health".to_string(),
                        description: "Path for health check endpoint".to_string(),
                    },
                    SettingSuggestion {
                        key: "request_timeout".to_string(),
                        value: "60".to_string(),
                        description: "Request timeout in seconds (Python apps may need longer)"
                            .to_string(),
                    },
                    SettingSuggestion {
                        key: "max_body_size".to_string(),
                        value: "50MB".to_string(),
                        description: "Maximum request body size".to_string(),
                    },
                ],
            },
        },
        ServerPreset {
            id: "golang".to_string(),
            name: "Go Web App".to_string(),
            description: "Reverse proxy to Go HTTP server".to_string(),
            category: PresetCategory::WebApp,
            icon: "code".to_string(),
            config: PresetConfig {
                default_port: 8080,
                protocol: "http".to_string(),
                recommended_upstream_format: Some("http://127.0.0.1:8080".to_string()),
                suggested_settings: vec![
                    SettingSuggestion {
                        key: "health_check_path".to_string(),
                        value: "/health".to_string(),
                        description: "Path for health check endpoint".to_string(),
                    },
                    SettingSuggestion {
                        key: "request_timeout".to_string(),
                        value: "30".to_string(),
                        description: "Request timeout in seconds".to_string(),
                    },
                ],
            },
        },
        ServerPreset {
            id: "php".to_string(),
            name: "PHP (PHP-FPM)".to_string(),
            description: "Execute PHP files via PHP-FPM FastCGI".to_string(),
            category: PresetCategory::WebApp,
            icon: "code".to_string(),
            config: PresetConfig {
                default_port: 9000,
                protocol: "php".to_string(),
                recommended_upstream_format: Some("unix:/var/run/php-fpm/www.sock".to_string()),
                suggested_settings: vec![
                    SettingSuggestion {
                        key: "php.socket".to_string(),
                        value: "unix:/var/run/php-fpm/www.sock".to_string(),
                        description: "PHP-FPM socket path (unix socket or host:port)".to_string(),
                    },
                    SettingSuggestion {
                        key: "php.root".to_string(),
                        value: "/var/www/html".to_string(),
                        description: "Document root for PHP files".to_string(),
                    },
                    SettingSuggestion {
                        key: "php.index".to_string(),
                        value: "index.php".to_string(),
                        description: "Default index file for PHP".to_string(),
                    },
                    SettingSuggestion {
                        key: "php.read_timeout".to_string(),
                        value: "60".to_string(),
                        description: "PHP request timeout in seconds".to_string(),
                    },
                    SettingSuggestion {
                        key: "php.upload_tmp".to_string(),
                        value: "/tmp".to_string(),
                        description: "Temporary directory for uploads".to_string(),
                    },
                    SettingSuggestion {
                        key: "php.max_execution_time".to_string(),
                        value: "30".to_string(),
                        description: "Maximum execution time in seconds".to_string(),
                    },
                    SettingSuggestion {
                        key: "php.memory_limit".to_string(),
                        value: "128M".to_string(),
                        description: "PHP memory limit".to_string(),
                    },
                    SettingSuggestion {
                        key: "php.upload_max_filesize".to_string(),
                        value: "50M".to_string(),
                        description: "Maximum upload file size".to_string(),
                    },
                ],
            },
        },
        ServerPreset {
            id: "cgi".to_string(),
            name: "CGI-bin".to_string(),
            description: "Execute CGI scripts (Perl, Python, etc.)".to_string(),
            category: PresetCategory::WebApp,
            icon: "terminal".to_string(),
            config: PresetConfig {
                default_port: 80,
                protocol: "cgi".to_string(),
                recommended_upstream_format: None,
                suggested_settings: vec![
                    SettingSuggestion {
                        key: "cgi.root".to_string(),
                        value: "/var/www/cgi-bin".to_string(),
                        description: "CGI script root directory".to_string(),
                    },
                    SettingSuggestion {
                        key: "cgi.index".to_string(),
                        value: "index.cgi".to_string(),
                        description: "Default CGI index script".to_string(),
                    },
                    SettingSuggestion {
                        key: "cgi.timeout".to_string(),
                        value: "30".to_string(),
                        description: "CGI script timeout in seconds".to_string(),
                    },
                ],
            },
        },
        ServerPreset {
            id: "smtp".to_string(),
            name: "SMTP Server".to_string(),
            description: "Email sending server (port 25, 587, 465)".to_string(),
            category: PresetCategory::Email,
            icon: "mail".to_string(),
            config: PresetConfig {
                default_port: 587,
                protocol: "smtp".to_string(),
                recommended_upstream_format: Some("127.0.0.1:{port}".to_string()),
                suggested_settings: vec![
                    SettingSuggestion {
                        key: "ports".to_string(),
                        value: "25,587,465".to_string(),
                        description: "SMTP ports to proxy".to_string(),
                    },
                    SettingSuggestion {
                        key: "tls_required".to_string(),
                        value: "true".to_string(),
                        description: "Require TLS encryption".to_string(),
                    },
                ],
            },
        },
        ServerPreset {
            id: "imap".to_string(),
            name: "IMAP Server".to_string(),
            description: "Email retrieval server (port 143, 993)".to_string(),
            category: PresetCategory::Email,
            icon: "mail".to_string(),
            config: PresetConfig {
                default_port: 993,
                protocol: "imap".to_string(),
                recommended_upstream_format: Some("127.0.0.1:{port}".to_string()),
                suggested_settings: vec![
                    SettingSuggestion {
                        key: "ports".to_string(),
                        value: "143,993".to_string(),
                        description: "IMAP ports (plain and SSL)".to_string(),
                    },
                    SettingSuggestion {
                        key: "tls_required".to_string(),
                        value: "true".to_string(),
                        description: "Require SSL/TLS encryption".to_string(),
                    },
                ],
            },
        },
        ServerPreset {
            id: "pop3".to_string(),
            name: "POP3 Server".to_string(),
            description: "Email retrieval server (port 110, 995)".to_string(),
            category: PresetCategory::Email,
            icon: "mail".to_string(),
            config: PresetConfig {
                default_port: 995,
                protocol: "pop3".to_string(),
                recommended_upstream_format: Some("127.0.0.1:{port}".to_string()),
                suggested_settings: vec![SettingSuggestion {
                    key: "ports".to_string(),
                    value: "110,995".to_string(),
                    description: "POP3 ports (plain and SSL)".to_string(),
                }],
            },
        },
        ServerPreset {
            id: "mysql".to_string(),
            name: "MySQL Database".to_string(),
            description: "MySQL database server (port 3306)".to_string(),
            category: PresetCategory::Database,
            icon: "database".to_string(),
            config: PresetConfig {
                default_port: 3306,
                protocol: "mysql".to_string(),
                recommended_upstream_format: Some("127.0.0.1:3306".to_string()),
                suggested_settings: vec![
                    SettingSuggestion {
                        key: "connection_pool".to_string(),
                        value: "10".to_string(),
                        description: "Maximum connections in pool".to_string(),
                    },
                    SettingSuggestion {
                        key: "query_timeout".to_string(),
                        value: "30".to_string(),
                        description: "Query timeout in seconds".to_string(),
                    },
                ],
            },
        },
        ServerPreset {
            id: "postgres".to_string(),
            name: "PostgreSQL Database".to_string(),
            description: "PostgreSQL database server (port 5432)".to_string(),
            category: PresetCategory::Database,
            icon: "database".to_string(),
            config: PresetConfig {
                default_port: 5432,
                protocol: "postgresql".to_string(),
                recommended_upstream_format: Some("127.0.0.1:5432".to_string()),
                suggested_settings: vec![
                    SettingSuggestion {
                        key: "connection_pool".to_string(),
                        value: "20".to_string(),
                        description: "Maximum connections in pool".to_string(),
                    },
                    SettingSuggestion {
                        key: "query_timeout".to_string(),
                        value: "30".to_string(),
                        description: "Query timeout in seconds".to_string(),
                    },
                ],
            },
        },
        ServerPreset {
            id: "redis".to_string(),
            name: "Redis Cache".to_string(),
            description: "Redis key-value store (port 6379)".to_string(),
            category: PresetCategory::Database,
            icon: "database".to_string(),
            config: PresetConfig {
                default_port: 6379,
                protocol: "redis".to_string(),
                recommended_upstream_format: Some("127.0.0.1:6379".to_string()),
                suggested_settings: vec![
                    SettingSuggestion {
                        key: "connection_pool".to_string(),
                        value: "50".to_string(),
                        description: "Maximum connections in pool".to_string(),
                    },
                    SettingSuggestion {
                        key: "command_timeout".to_string(),
                        value: "5".to_string(),
                        description: "Command timeout in seconds".to_string(),
                    },
                ],
            },
        },
    ]
}

pub fn get_presets_by_category(category: &PresetCategory) -> Vec<ServerPreset> {
    get_presets()
        .into_iter()
        .filter(|p| &p.category == category)
        .collect()
}
