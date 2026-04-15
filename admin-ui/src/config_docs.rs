pub struct ConfigFieldDoc {
    pub label: &'static str,
    pub description: &'static str,
    pub impact: Option<&'static str>,
    pub default: &'static str,
}

pub struct ConfigSectionDoc {
    pub title: &'static str,
    pub description: &'static str,
}

pub const SECTIONS: &[(&str, ConfigSectionDoc)] = &[
    (
        "server",
        ConfigSectionDoc {
            title: "Server Configuration",
            description: "Basic server binding and network settings",
        },
    ),
    (
        "http",
        ConfigSectionDoc {
            title: "HTTP Settings",
            description: "HTTP protocol timeouts, limits, and buffer sizes",
        },
    ),
    (
        "tls",
        ConfigSectionDoc {
            title: "TLS/HTTPS",
            description: "HTTPS certificate and encryption settings",
        },
    ),
    (
        "acme",
        ConfigSectionDoc {
            title: "ACME (Let's Encrypt)",
            description: "Automatic certificate management",
        },
    ),
    (
        "http3",
        ConfigSectionDoc {
            title: "HTTP/3 (QUIC)",
            description: "Next-generation HTTP protocol over QUIC",
        },
    ),
    (
        "logging",
        ConfigSectionDoc {
            title: "Logging",
            description: "Log level, format, and retention settings",
        },
    ),
    (
        "threat_level",
        ConfigSectionDoc {
            title: "Threat Level",
            description: "Adaptive security threat level configuration",
        },
    ),
    (
        "rate_limits",
        ConfigSectionDoc {
            title: "Rate Limiting",
            description: "Request limiting per IP and globally",
        },
    ),
    (
        "traffic_shaping",
        ConfigSectionDoc {
            title: "Traffic Shaping",
            description: "Bandwidth and connection limiting",
        },
    ),
    (
        "bot",
        ConfigSectionDoc {
            title: "Bot Protection",
            description: "Bot detection and challenge settings",
        },
    ),
    (
        "security",
        ConfigSectionDoc {
            title: "Security Headers",
            description: "HTTP header security configuration",
        },
    ),
    (
        "ip_feeds",
        ConfigSectionDoc {
            title: "IP Feeds",
            description: "External IP blocklist feeds",
        },
    ),
    (
        "tarpit",
        ConfigSectionDoc {
            title: "Tarpit",
            description: "Scraping trap configuration",
        },
    ),
    (
        "upload",
        ConfigSectionDoc {
            title: "Upload Settings",
            description: "File upload limits and scanning",
        },
    ),
];

pub const FIELDS: &[(&str, &str, ConfigFieldDoc)] = &[
    ("server", "host", ConfigFieldDoc {
        label: "Listen Host",
        description: "IP address to bind the main server to. Use 0.0.0.0 for all interfaces, 127.0.0.1 for localhost only.",
        impact: Some("Changing this may make the server inaccessible from certain networks."),
        default: "0.0.0.0",
    }),
    ("server", "port", ConfigFieldDoc {
        label: "Listen Port",
        description: "TCP port for the main HTTP server. Standard HTTP port is 80, but non-root users typically use 8080.",
        impact: Some("Ensure the port is not already in use and firewall rules allow traffic."),
        default: "8080",
    }),
    ("server", "host_v6", ConfigFieldDoc {
        label: "IPv6 Listen Host",
        description: "IPv6 address to bind to. Use :: for all interfaces, ::1 for localhost only.",
        impact: Some("Leave empty to disable IPv6 binding."),
        default: "(none)",
    }),
    ("server", "trusted_proxies", ConfigFieldDoc {
        label: "Trusted Proxies",
        description: "IP addresses of trusted reverse proxies. These IPs will be trusted for X-Forwarded-For headers.",
        impact: Some("Incorrect configuration can allow IP spoofing attacks."),
        default: "127.0.0.1, ::1",
    }),

    ("http", "header_read_timeout_secs", ConfigFieldDoc {
        label: "Header Read Timeout",
        description: "Seconds to wait for complete HTTP headers before closing the connection.",
        impact: Some("Lower values protect against slowloris attacks but may disconnect slow clients."),
        default: "10",
    }),
    ("http", "keep_alive_timeout_secs", ConfigFieldDoc {
        label: "Keep-Alive Timeout",
        description: "Seconds to keep idle connections open before closing.",
        impact: Some("Higher values reduce connection overhead but consume more resources."),
        default: "60",
    }),
    ("http", "max_headers", ConfigFieldDoc {
        label: "Max Headers",
        description: "Maximum number of headers allowed in a single request.",
        impact: Some("Lower values use less memory but may reject legitimate large requests."),
        default: "128",
    }),
    ("http", "max_request_line_size", ConfigFieldDoc {
        label: "Max Request Line Size",
        description: "Maximum size in bytes for the HTTP request line (method, URI, version).",
        impact: Some("Too low may block requests with long URLs."),
        default: "8192",
    }),
    ("http", "max_header_size_ingress", ConfigFieldDoc {
        label: "Max Ingress Header Size",
        description: "Maximum total size of all request headers from clients.",
        impact: Some("Lower values protect against header-based attacks."),
        default: "4096",
    }),
    ("http", "max_header_size_egress", ConfigFieldDoc {
        label: "Max Egress Header Size",
        description: "Maximum total size of response headers sent to clients.",
        impact: Some("May truncate large Set-Cookie headers from backends."),
        default: "16384",
    }),
    ("http", "max_request_size", ConfigFieldDoc {
        label: "Max Request Body Size",
        description: "Maximum size of the request body in bytes.",
        impact: Some("Lower values protect against large payload attacks but limit uploads."),
        default: "1048576 (1MB)",
    }),
    ("http", "pipeline_limit", ConfigFieldDoc {
        label: "Pipeline Limit",
        description: "Maximum number of pipelined requests per connection.",
        impact: Some("Lower values reduce memory but may slow down pipelined clients."),
        default: "32",
    }),

    ("tls", "enabled", ConfigFieldDoc {
        label: "Enable TLS",
        description: "Enable HTTPS/TLS encryption for secure connections.",
        impact: Some("Disabling TLS exposes all traffic in plaintext. Only disable behind a TLS-terminating proxy."),
        default: "false",
    }),
    ("tls", "port", ConfigFieldDoc {
        label: "TLS Port",
        description: "TCP port for HTTPS connections. Standard HTTPS port is 443.",
        impact: Some("Port 443 requires root privileges or capability binding."),
        default: "443",
    }),
    ("tls", "cert_path", ConfigFieldDoc {
        label: "Certificate Path",
        description: "Path to the TLS certificate file (PEM format).",
        impact: Some("Required when TLS is enabled and ACME is not used."),
        default: "(none)",
    }),
    ("tls", "key_path", ConfigFieldDoc {
        label: "Private Key Path",
        description: "Path to the TLS private key file (PEM format).",
        impact: Some("Must correspond to the certificate. Keep this file secure!"),
        default: "(none)",
    }),
    ("tls", "prefer_post_quantum", ConfigFieldDoc {
        label: "Prefer Post-Quantum Ciphers",
        description: "Prefer post-quantum secure cipher suites when available.",
        impact: Some("Provides forward security against quantum computers with minor performance impact."),
        default: "true",
    }),
    ("tls", "watch_dir", ConfigFieldDoc {
        label: "Certificate Watch Directory",
        description: "Directory to watch for certificate changes. Auto-reloads when files change.",
        impact: Some("Useful with certbot or other ACME clients that update certificates."),
        default: "(none)",
    }),

    ("acme", "enabled", ConfigFieldDoc {
        label: "Enable ACME",
        description: "Enable automatic certificate provisioning via Let's Encrypt or other ACME providers.",
        impact: Some("Requires email and domains to be configured. Automates certificate management."),
        default: "false",
    }),
    ("acme", "email", ConfigFieldDoc {
        label: "ACME Email",
        description: "Email address for Let's Encrypt account and expiry notifications.",
        impact: Some("Required for ACME certificate issuance."),
        default: "(none)",
    }),
    ("acme", "domains", ConfigFieldDoc {
        label: "ACME Domains",
        description: "List of domains to obtain certificates for.",
        impact: Some("Each domain must resolve to this server and be accessible via HTTP-01 challenge."),
        default: "[]",
    }),
    ("acme", "staging", ConfigFieldDoc {
        label: "Use Staging CA",
        description: "Use Let's Encrypt staging environment for testing. Staging certificates are not trusted.",
        impact: Some("Use for testing to avoid rate limits. Set to false for production."),
        default: "false",
    }),
    ("acme", "cache_dir", ConfigFieldDoc {
        label: "ACME Cache Directory",
        description: "Directory to store ACME account data and certificates.",
        impact: Some("Must be writable. Certificates persist across restarts."),
        default: "(none)",
    }),

    ("http3", "enabled", ConfigFieldDoc {
        label: "Enable HTTP/3",
        description: "Enable HTTP/3 (QUIC) protocol support. Requires TLS to be enabled.",
        impact: Some("Provides faster connection setup and better performance on unstable networks."),
        default: "false",
    }),
    ("http3", "port", ConfigFieldDoc {
        label: "HTTP/3 Port",
        description: "UDP port for HTTP/3 connections. Standard is 443.",
        impact: Some("Firewall must allow UDP traffic on this port."),
        default: "443",
    }),
    ("http3", "alt_svc_max_age", ConfigFieldDoc {
        label: "Alt-Svc Max Age",
        description: "Seconds to advertise HTTP/3 availability via Alt-Svc header.",
        impact: Some("Higher values reduce HTTP/3 discovery time for returning clients."),
        default: "86400 (24h)",
    }),

    ("logging", "level", ConfigFieldDoc {
        label: "Log Level",
        description: "Minimum log level to record. Lower levels include all higher levels.",
        impact: Some("Debug/trace levels produce large amounts of logs. Use info for production."),
        default: "info",
    }),
    ("logging", "access_log", ConfigFieldDoc {
        label: "Enable Access Log",
        description: "Record all HTTP requests to access log files.",
        impact: Some("Essential for debugging and security analysis. Disable only for performance."),
        default: "true",
    }),
    ("logging", "access_log_dir", ConfigFieldDoc {
        label: "Access Log Directory",
        description: "Directory to store access log files.",
        impact: Some("Must be writable. Leave empty for default location."),
        default: "(default)",
    }),
    ("logging", "retention_days", ConfigFieldDoc {
        label: "Log Retention (Days)",
        description: "Number of days to keep access log files before deletion.",
        impact: Some("Higher values use more disk space. Consider log rotation for long retention."),
        default: "5",
    }),
    ("logging", "max_entries_per_file", ConfigFieldDoc {
        label: "Max Entries Per File",
        description: "Maximum log entries per file before rotation.",
        impact: Some("Lower values create more files but easier to process."),
        default: "50000",
    }),
    ("logging", "access_log_format", ConfigFieldDoc {
        label: "Access Log Format",
        description: "Format for access logs: JSON (structured) or text (human-readable).",
        impact: Some("JSON is better for log aggregation and analysis tools."),
        default: "json",
    }),

    ("threat_level", "initial", ConfigFieldDoc {
        label: "Initial Threat Level",
        description: "Starting threat level (1-5). Level 1 is normal, level 5 is maximum security.",
        impact: Some("Higher initial levels immediately apply stricter rate limits."),
        default: "1",
    }),
    ("threat_level", "auto_scale", ConfigFieldDoc {
        label: "Auto-Scale Threat Level",
        description: "Automatically adjust threat level based on detected attacks.",
        impact: Some("Provides adaptive security. Disable for manual control only."),
        default: "true",
    }),
    ("threat_level", "scale_up_attacks_per_min", ConfigFieldDoc {
        label: "Scale-Up Attack Threshold",
        description: "Attacks per minute to trigger threat level increase.",
        impact: Some("Lower values trigger faster escalation but may overreact."),
        default: "50",
    }),
    ("threat_level", "scale_down_attacks_per_min", ConfigFieldDoc {
        label: "Scale-Down Attack Threshold",
        description: "Attacks per minute to trigger threat level decrease.",
        impact: Some("Lower values return to normal faster after attacks stop."),
        default: "10",
    }),
    ("threat_level", "cooldown_secs", ConfigFieldDoc {
        label: "Cooldown Period",
        description: "Seconds to wait before scaling threat level again.",
        impact: Some("Prevents rapid fluctuations in threat level."),
        default: "60",
    }),

    ("rate_limits", "mode", ConfigFieldDoc {
        label: "Rate Limit Mode",
        description: "Shared: all sites share global limits. Isolated: each site has independent limits.",
        impact: Some("Isolated provides better isolation but uses more memory."),
        default: "shared",
    }),
    ("rate_limits", "ip_per_second", ConfigFieldDoc {
        label: "Per-IP Requests/Second",
        description: "Maximum requests per second from a single IP address.",
        impact: Some("Lower values protect against DDoS but may block legitimate bursts."),
        default: "10",
    }),
    ("rate_limits", "ip_per_minute", ConfigFieldDoc {
        label: "Per-IP Requests/Minute",
        description: "Maximum requests per minute from a single IP address.",
        impact: Some("Sustained limit for single IP addresses."),
        default: "60",
    }),
    ("rate_limits", "ip_per_hour", ConfigFieldDoc {
        label: "Per-IP Requests/Hour",
        description: "Maximum requests per hour from a single IP address.",
        impact: Some("Long-term limit for single IP addresses."),
        default: "500",
    }),
    ("rate_limits", "ip_burst", ConfigFieldDoc {
        label: "Per-IP Burst Size",
        description: "Number of requests that can exceed the per-second limit temporarily.",
        impact: Some("Allows short bursts of legitimate activity."),
        default: "20",
    }),
    ("rate_limits", "global_per_second", ConfigFieldDoc {
        label: "Global Requests/Second",
        description: "Maximum total requests per second across all IPs.",
        impact: Some("Protects backend from overload."),
        default: "500",
    }),
    ("rate_limits", "global_max_connections", ConfigFieldDoc {
        label: "Max Connections",
        description: "Maximum concurrent connections across all clients.",
        impact: Some("Prevents connection exhaustion attacks."),
        default: "1000",
    }),

    ("traffic_shaping", "enabled", ConfigFieldDoc {
        label: "Enable Traffic Shaping",
        description: "Enable bandwidth and connection limiting.",
        impact: Some("Provides protection against bandwidth-based attacks."),
        default: "true",
    }),
    ("traffic_shaping", "ingress_max_mb_s", ConfigFieldDoc {
        label: "Ingress Bandwidth (MB/s)",
        description: "Maximum incoming bandwidth in megabytes per second.",
        impact: Some("Lower values protect against bandwidth exhaustion."),
        default: "128",
    }),
    ("traffic_shaping", "egress_max_mb_s", ConfigFieldDoc {
        label: "Egress Bandwidth (MB/s)",
        description: "Maximum outgoing bandwidth in megabytes per second.",
        impact: Some("Lower values protect your server from being used as a file server."),
        default: "128",
    }),
    ("traffic_shaping", "max_connections_per_ip", ConfigFieldDoc {
        label: "Max Connections Per IP",
        description: "Maximum concurrent connections from a single IP.",
        impact: Some("Prevents connection exhaustion from single attacker."),
        default: "10",
    }),

    ("bot", "block_ai_crawlers", ConfigFieldDoc {
        label: "Block AI Crawlers",
        description: "Block known AI/ML web crawlers (GPTBot, ClaudeBot, etc.).",
        impact: Some("Prevents AI training data collection from your site."),
        default: "true",
    }),
    ("bot", "enable_css_honeypot", ConfigFieldDoc {
        label: "Enable CSS Honeypot",
        description: "Use invisible CSS links to detect and trap scrapers.",
        impact: Some("Catches scrapers without affecting human users."),
        default: "true",
    }),
    ("bot", "enable_js_challenge", ConfigFieldDoc {
        label: "Enable JS Challenge",
        description: "Require JavaScript execution before allowing access.",
        impact: Some("Blocks simple bots but may affect accessibility."),
        default: "false",
    }),
    ("bot", "js_difficulty", ConfigFieldDoc {
        label: "JS Challenge Difficulty",
        description: "Difficulty level for JavaScript challenges (1-10).",
        impact: Some("Higher values require more client CPU time."),
        default: "1",
    }),
    ("bot", "challenge_window_secs", ConfigFieldDoc {
        label: "Challenge Validity Window",
        description: "Seconds a passed challenge remains valid.",
        impact: Some("Higher values reduce challenge frequency for users."),
        default: "300 (5 min)",
    }),

    ("security", "sanitize_forwarded_headers", ConfigFieldDoc {
        label: "Sanitize Forwarded Headers",
        description: "Clean and validate X-Forwarded-* headers from proxies.",
        impact: Some("Prevents header injection attacks through proxy headers."),
        default: "true",
    }),
    ("security", "global_security_headers", ConfigFieldDoc {
        label: "Add Security Headers",
        description: "Automatically add security headers (X-Frame-Options, etc.).",
        impact: Some("Provides defense-in-depth against common attacks."),
        default: "false",
    }),

    ("ip_feeds", "enabled", ConfigFieldDoc {
        label: "Enable IP Feeds",
        description: "Download and use external IP blocklists.",
        impact: Some("Provides up-to-date protection against known malicious IPs."),
        default: "true",
    }),
    ("ip_feeds", "update_interval_hours", ConfigFieldDoc {
        label: "Update Interval (Hours)",
        description: "Hours between blocklist downloads.",
        impact: Some("Lower values provide faster updates but more network traffic."),
        default: "2",
    }),
    ("ip_feeds", "url", ConfigFieldDoc {
        label: "Feed URL",
        description: "URL of the IP blocklist feed (plain text, one IP/CIDR per line).",
        impact: Some("Change to use alternative blocklist sources."),
        default: "bitwire-it/ipblocklist",
    }),

    ("tarpit", "enabled", ConfigFieldDoc {
        label: "Enable Tarpit",
        description: "Trap scrapers in an infinite maze of fake pages.",
        impact: Some("Wastes attacker resources and slows down scanning."),
        default: "true",
    }),
    ("tarpit", "max_depth", ConfigFieldDoc {
        label: "Maximum Depth",
        description: "Maximum depth of tarpit pages to generate.",
        impact: Some("Higher values trap scrapers longer."),
        default: "10",
    }),
    ("tarpit", "links_per_page", ConfigFieldDoc {
        label: "Links Per Page",
        description: "Number of fake links to generate per tarpit page.",
        impact: Some("Higher values create more crawlable paths."),
        default: "50",
    }),
    ("tarpit", "response_delay_ms", ConfigFieldDoc {
        label: "Response Delay (ms)",
        description: "Milliseconds to delay tarpit responses.",
        impact: Some("Higher values slow down scrapers more."),
        default: "100",
    }),

    ("upload", "enabled", ConfigFieldDoc {
        label: "Enable Upload Handling",
        description: "Process and validate file uploads.",
        impact: Some("Disable only if your application doesn't handle uploads."),
        default: "true",
    }),
    ("upload", "max_size", ConfigFieldDoc {
        label: "Max Upload Size",
        description: "Maximum allowed upload size (e.g., 100MB, 1GB).",
        impact: Some("Lower values protect against storage exhaustion."),
        default: "100MB",
    }),
    ("upload", "scan_with_yara", ConfigFieldDoc {
        label: "Scan with YARA",
        description: "Scan uploaded files with YARA rules for malware detection.",
        impact: Some("Provides malware protection with small performance overhead."),
        default: "true",
    }),
    ("upload", "sandbox_enabled", ConfigFieldDoc {
        label: "Sandbox Dangerous Files",
        description: "Execute potentially dangerous files in sandbox before allowing.",
        impact: Some("Additional protection against zero-day malware."),
        default: "true",
    }),
];

pub fn get_field_doc(section: &str, field: &str) -> Option<&'static ConfigFieldDoc> {
    FIELDS
        .iter()
        .find(|(s, f, _)| *s == section && *f == field)
        .map(|(_, _, doc)| doc)
}

pub fn get_section_doc(section: &str) -> Option<&'static ConfigSectionDoc> {
    SECTIONS
        .iter()
        .find(|(s, _)| *s == section)
        .map(|(_, doc)| doc)
}
