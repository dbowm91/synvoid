#![allow(clippy::derivable_impls)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::limits::{BlocklistLimitsConfig, ProxyLimitsConfig, RateLimitMemoryConfig};
use super::network::{TarpitDefaults, TcpDefaults, UdpDefaults};
use super::traffic::TrafficShapingDefaults;
use super::upload::UploadDefaults;
use super::validation::ConfigValidationError;
use crate::theme::ThemeDefaults;

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
#[serde(default)]
pub struct DefaultsConfig {
    pub ratelimit: RateLimitDefaults,
    pub blocked: BlockedDefaults,
    pub honeypot: HoneypotDefaults,
    pub honeypot_probe: HoneypotProbingDefaults,
    pub suspicious_words: SuspiciousWordsConfig,
    pub upstream_errors: UpstreamErrorsConfig,
    pub error_pages: ErrorPagesDefaults,
    pub bot: BotDefaults,
    pub css_challenge: CssChallengeDefaults,
    pub pow_challenge: PowChallengeDefaults,
    pub challenge: ChallengeDefaults,
    pub auth: AuthDefaults,
    pub worker_pool: WorkerPoolDefaults,
    pub persistence: PersistenceConfig,
    #[serde(default)]
    pub rate_limit_memory: RateLimitMemoryConfig,
    #[serde(default)]
    pub proxy_limits: ProxyLimitsConfig,
    #[serde(default)]
    pub blocklist_limits: BlocklistLimitsConfig,
    #[serde(default)]
    pub tcp: TcpDefaults,
    #[serde(default)]
    pub udp: UdpDefaults,
    #[serde(default)]
    pub tarpit: TarpitDefaults,
    #[serde(default)]
    pub upload: UploadDefaults,
    #[serde(default)]
    pub theme: ThemeDefaults,
    #[serde(default)]
    pub traffic_shaping: TrafficShapingDefaults,
    #[serde(default)]
    pub asn_scraping: AsnScrapingConfig,
}

impl Default for DefaultsConfig {
    fn default() -> Self {
        Self {
            ratelimit: RateLimitDefaults::default(),
            blocked: BlockedDefaults::default(),
            honeypot: HoneypotDefaults::default(),
            honeypot_probe: HoneypotProbingDefaults::default(),
            suspicious_words: SuspiciousWordsConfig::default(),
            upstream_errors: UpstreamErrorsConfig::default(),
            error_pages: ErrorPagesDefaults::default(),
            bot: BotDefaults::default(),
            css_challenge: CssChallengeDefaults::default(),
            pow_challenge: PowChallengeDefaults::default(),
            challenge: ChallengeDefaults::default(),
            auth: AuthDefaults::default(),
            worker_pool: WorkerPoolDefaults::default(),
            persistence: PersistenceConfig::default(),
            rate_limit_memory: RateLimitMemoryConfig::default(),
            proxy_limits: ProxyLimitsConfig::default(),
            blocklist_limits: BlocklistLimitsConfig::default(),
            tcp: TcpDefaults::default(),
            udp: UdpDefaults::default(),
            tarpit: TarpitDefaults::default(),
            upload: UploadDefaults::default(),
            theme: ThemeDefaults::default(),
            traffic_shaping: TrafficShapingDefaults::default(),
            asn_scraping: AsnScrapingConfig::default(),
        }
    }
}

impl DefaultsConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        self.ratelimit.validate()?;
        self.upload.validate()?;
        self.worker_pool.validate()?;
        self.bot.validate()?;
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct RateLimitDefaults {
    #[serde(default = "default_ratelimit_mode")]
    pub mode: String,
    pub ip: IpRateLimitConfig,
    pub global: GlobalRateLimitConfig,
    #[serde(default)]
    pub endpoints: Vec<EndpointRateLimitConfig>,
}

impl Default for RateLimitDefaults {
    fn default() -> Self {
        Self {
            mode: default_ratelimit_mode(),
            ip: IpRateLimitConfig::default(),
            global: GlobalRateLimitConfig::default(),
            endpoints: vec![],
        }
    }
}

impl RateLimitDefaults {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        match self.mode.as_str() {
            "shared" | "isolated" => {}
            _ => {
                return Err(ConfigValidationError {
                    field: "defaults.ratelimit.mode".to_string(),
                    message: "Mode must be 'shared' or 'isolated'".to_string(),
                });
            }
        }
        Ok(())
    }
}

fn default_ratelimit_mode() -> String {
    "shared".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct IpRateLimitConfig {
    #[serde(default = "default_ip_per_second")]
    pub per_second: u32,
    #[serde(default = "default_ip_per_minute")]
    pub per_minute: u32,
    #[serde(default = "default_ip_per_5min")]
    pub per_5min: u32,
    #[serde(default = "default_ip_per_10min")]
    pub per_10min: u32,
    #[serde(default = "default_ip_per_hour")]
    pub per_hour: u32,
    #[serde(default = "default_ip_per_day")]
    pub per_day: u32,
    #[serde(default = "default_ip_burst")]
    pub burst: u32,
}

fn default_ip_per_second() -> u32 {
    10
}
fn default_ip_per_minute() -> u32 {
    60
}
fn default_ip_per_5min() -> u32 {
    200
}
fn default_ip_per_10min() -> u32 {
    350
}
fn default_ip_per_hour() -> u32 {
    500
}
fn default_ip_per_day() -> u32 {
    1000
}
fn default_ip_burst() -> u32 {
    20
}

/// Rust `Default` **must** mirror the per-field serde defaults.
///
/// `DefaultsConfig` carries a struct-level `#[serde(default)]`, so an omitted or
/// empty `[defaults]` table is resolved through `DefaultsConfig::default()` and
/// never consults the `#[serde(default = "...")]` attributes below. Deriving
/// `Default` on this struct therefore yielded all zeros, so `per_second` resolved
/// to `0` rather than `10` and the site limiter's `len() >= per_second` check
/// rejected 100% of traffic with HTTP 429.
///
/// Each field delegates to its `default_*` function so there is exactly one
/// source of truth. Pinned by `tests/serde_defaults_match_rust_defaults.rs`.
impl Default for IpRateLimitConfig {
    fn default() -> Self {
        Self {
            per_second: default_ip_per_second(),
            per_minute: default_ip_per_minute(),
            per_5min: default_ip_per_5min(),
            per_10min: default_ip_per_10min(),
            per_hour: default_ip_per_hour(),
            per_day: default_ip_per_day(),
            burst: default_ip_burst(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct GlobalRateLimitConfig {
    #[serde(default = "default_global_per_second")]
    pub per_second: u32,
    #[serde(default = "default_global_per_minute")]
    pub per_minute: u32,
    #[serde(default = "default_global_per_5min")]
    pub per_5min: u32,
    #[serde(default = "default_global_max_connections")]
    pub max_connections: u32,
}

fn default_global_per_second() -> u32 {
    500
}
fn default_global_per_minute() -> u32 {
    5000
}
fn default_global_per_5min() -> u32 {
    20000
}
fn default_global_max_connections() -> u32 {
    1000
}

/// Rust `Default` **must** mirror the per-field serde defaults — see the note on
/// [`IpRateLimitConfig::default`]. Derived `Default` resolved `max_connections`
/// to `0` instead of `1000` on the `[defaults]`-omitted path.
impl Default for GlobalRateLimitConfig {
    fn default() -> Self {
        Self {
            per_second: default_global_per_second(),
            per_minute: default_global_per_minute(),
            per_5min: default_global_per_5min(),
            max_connections: default_global_max_connections(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct EndpointRateLimitConfig {
    pub path_pattern: String,
    #[serde(default = "default_endpoint_per_minute")]
    pub per_minute: u32,
    #[serde(default = "default_endpoint_per_hour")]
    pub per_hour: u32,
    #[serde(default = "default_endpoint_burst")]
    pub burst: u32,
}

fn default_endpoint_per_minute() -> u32 {
    60
}
fn default_endpoint_per_hour() -> u32 {
    500
}
fn default_endpoint_burst() -> u32 {
    10
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct BlockedDefaults {
    #[serde(default = "default_blocked_paths")]
    pub paths: Vec<String>,
    #[serde(default = "default_regex")]
    pub use_regex: bool,
    #[serde(default = "default_block_methods")]
    pub block_methods: Vec<String>,
    #[serde(default = "default_block_response")]
    pub block_response_code: u16,
}

/// Rust `Default` **must** mirror the per-field serde defaults — see the note on
/// [`IpRateLimitConfig::default`].
///
/// This one previously failed *open*: `paths` and `block_methods` used a bare
/// `#[serde(default)]`, so writing an explicit `[defaults.blocked]` table — or
/// omitting `[defaults]` entirely, which routes through this impl — disagreed
/// about whether `/.env`, `/.git` and `/wp-login.php` are blocked. The empty-table
/// form silently disabled blocked-path protection. Both paths now share one
/// source of truth.
impl Default for BlockedDefaults {
    fn default() -> Self {
        Self {
            paths: default_blocked_paths(),
            use_regex: default_regex(),
            block_methods: default_block_methods(),
            block_response_code: default_block_response(),
        }
    }
}

fn default_blocked_paths() -> Vec<String> {
    vec![
        "/.env".to_string(),
        "/.git".to_string(),
        "/wp-login.php".to_string(),
    ]
}

fn default_block_methods() -> Vec<String> {
    vec!["GET".to_string(), "POST".to_string()]
}

fn default_regex() -> bool {
    true
}
fn default_block_response() -> u16 {
    403
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct BotDefaults {
    #[serde(default = "default_block_ai")]
    pub block_ai_crawlers: bool,
    #[serde(default = "default_true")]
    pub enable_css_honeypot: bool,
    #[serde(default)]
    pub enable_js_challenge: bool,
    #[serde(default = "default_known_bots_allow")]
    pub known_bots_allow: Vec<String>,
    #[serde(default = "default_ai_crawlers_block")]
    pub ai_crawlers_block: Vec<String>,
    #[serde(default = "default_scraper_patterns")]
    pub scraper_patterns: Vec<String>,
    #[serde(default = "default_challenge_cookie_name")]
    pub challenge_cookie_name: String,
    #[serde(default = "default_challenge_window")]
    pub challenge_window_secs: u64,
    #[serde(default = "default_js_difficulty")]
    pub js_difficulty: u8,
    #[serde(default = "default_challenge_rate_limit_max_attempts")]
    pub challenge_max_attempts: u32,
    #[serde(default = "default_challenge_rate_limit_window")]
    pub challenge_rate_limit_window_secs: u64,
}

impl Default for BotDefaults {
    fn default() -> Self {
        Self {
            block_ai_crawlers: default_block_ai(),
            enable_css_honeypot: default_true(),
            enable_js_challenge: false,
            known_bots_allow: default_known_bots_allow(),
            ai_crawlers_block: default_ai_crawlers_block(),
            scraper_patterns: default_scraper_patterns(),
            challenge_cookie_name: "waf_challenge".to_string(),
            challenge_window_secs: 300,
            js_difficulty: 1,
            challenge_max_attempts: 5,
            challenge_rate_limit_window_secs: 3600,
        }
    }
}

fn default_known_bots_allow() -> Vec<String> {
    vec![
        "googlebot".to_string(),
        "bingbot".to_string(),
        "yandex".to_string(),
        "duckduckbot".to_string(),
    ]
}

fn default_ai_crawlers_block() -> Vec<String> {
    vec![
        // OpenAI
        "GPTBot".to_string(),
        "ChatGPT-User".to_string(),
        "ChatGPT-Plugin".to_string(),
        "OAI-SearchBot".to_string(),
        // Anthropic
        "ClaudeBot".to_string(),
        "Claude-Web".to_string(),
        "anthropic-ai".to_string(),
        // Google
        "Google-Extended".to_string(),
        "GoogleOther".to_string(),
        // Common Crawl
        "CCBot".to_string(),
        // Perplexity
        "PerplexityBot".to_string(),
        // Apple
        "Applebot".to_string(),
        "Applebot-Extended".to_string(),
        // Amazon
        "Amazonbot".to_string(),
        // Meta / Facebook
        "Meta-ExternalBot".to_string(),
        "FacebookBot".to_string(),
        "meta-externalagent".to_string(),
        // ByteDance / TikTok
        "Bytespider".to_string(),
        // xAI
        "Grok".to_string(),
        // Mistral
        "MistralAI".to_string(),
        "MistralAI-User".to_string(),
        // Cohere
        "CohereBot".to_string(),
        "cohere-training-data-crawler".to_string(),
        // AI21
        "AI21".to_string(),
    ]
}

fn default_scraper_patterns() -> Vec<String> {
    vec![
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
        "pyspider".to_string(),
        "scrapeloader".to_string(),
        "siteanalyzer".to_string(),
        "screaming frog".to_string(),
    ]
}

impl BotDefaults {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.js_difficulty == 0 {
            return Err(ConfigValidationError {
                field: "defaults.bot.js_difficulty".to_string(),
                message: "JS difficulty must be greater than 0".to_string(),
            });
        }
        if self.challenge_max_attempts == 0 {
            return Err(ConfigValidationError {
                field: "defaults.bot.challenge_max_attempts".to_string(),
                message: "Challenge max attempts must be greater than 0".to_string(),
            });
        }
        Ok(())
    }
}

fn default_block_ai() -> bool {
    true
}
pub fn default_true() -> bool {
    true
}
fn default_challenge_rate_limit_max_attempts() -> u32 {
    5
}
fn default_challenge_rate_limit_window() -> u64 {
    3600
}
fn default_challenge_cookie_name() -> String {
    "waf_challenge".to_string()
}
fn default_challenge_window() -> u64 {
    300
}
fn default_js_difficulty() -> u8 {
    1
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct AsnScrapingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_asn_requests_per_minute")]
    pub requests_per_minute: u32,
    #[serde(default = "default_asn_requests_per_5min")]
    pub requests_per_5min: u32,
    #[serde(default = "default_asn_requests_per_hour")]
    pub requests_per_hour: u32,
    #[serde(default = "default_asn_unique_ips_threshold")]
    pub unique_ips_threshold: u32,
    #[serde(default = "default_asn_unique_ips_window_secs")]
    pub unique_ips_window_secs: u64,
    #[serde(default = "default_asn_violations_before_block")]
    pub violations_before_block: u32,
    #[serde(default = "default_asn_ban_duration_secs")]
    pub ban_duration_secs: u64,
    #[serde(default = "default_asn_cache_size")]
    pub cache_size: usize,
    #[serde(default = "default_whitelisted_asns")]
    pub whitelisted_asns: Vec<u32>,
}

impl Default for AsnScrapingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            requests_per_minute: 300,
            requests_per_5min: 1000,
            requests_per_hour: 5000,
            unique_ips_threshold: 50,
            unique_ips_window_secs: 300,
            violations_before_block: 2,
            ban_duration_secs: 3600,
            cache_size: 10000,
            whitelisted_asns: default_whitelisted_asns(),
        }
    }
}

fn default_whitelisted_asns() -> Vec<u32> {
    vec![
        15169, // Google
        13335, // Cloudflare
        8075,  // Microsoft
        32934, // Meta
        14906, // Apple
        20940, // Akamai
        16625, // Akamai
        13414, // Twitter/X
        14618, // Amazon
        16509, // Amazon
        3836,  // Verizon
        7922,  // Comcast
    ]
}

fn default_asn_requests_per_minute() -> u32 {
    300
}
fn default_asn_requests_per_5min() -> u32 {
    1000
}
fn default_asn_requests_per_hour() -> u32 {
    5000
}
fn default_asn_unique_ips_threshold() -> u32 {
    50
}
fn default_asn_unique_ips_window_secs() -> u64 {
    300
}
fn default_asn_violations_before_block() -> u32 {
    2
}
fn default_asn_ban_duration_secs() -> u64 {
    3600
}
fn default_asn_cache_size() -> usize {
    10000
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct HoneypotDefaults {
    #[serde(default = "default_honeypot_endpoints_file")]
    pub endpoints_file: String,
    #[serde(default = "default_honeypot_paths_per_ip")]
    pub paths_per_ip: usize,
    #[serde(default = "default_honeypot_ttl")]
    pub ttl_secs: u64,
    #[serde(default)]
    pub block: HoneypotBlockDefaults,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct HoneypotBlockDefaults {
    #[serde(default = "default_honeypot_block_enabled")]
    pub enabled: bool,
    #[serde(default = "default_honeypot_ban_duration")]
    pub ban_duration: String,
}

impl Default for HoneypotDefaults {
    fn default() -> Self {
        Self {
            endpoints_file: "config/honeypot_endpoints.txt".to_string(),
            paths_per_ip: 5,
            ttl_secs: 86400,
            block: HoneypotBlockDefaults::default(),
        }
    }
}

impl Default for HoneypotBlockDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            ban_duration: "24h".to_string(),
        }
    }
}

fn default_honeypot_endpoints_file() -> String {
    "config/honeypot_endpoints.txt".to_string()
}
fn default_honeypot_paths_per_ip() -> usize {
    5
}
fn default_honeypot_ttl() -> u64 {
    86400
}
fn default_honeypot_block_enabled() -> bool {
    true
}
fn default_honeypot_ban_duration() -> String {
    "24h".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct HoneypotProbingDefaults {
    #[serde(default = "default_probing_enabled")]
    pub enabled: bool,
    #[serde(default = "default_probing_max_endpoints")]
    pub max_endpoints_per_window: usize,
    #[serde(default = "default_probing_window")]
    pub window_secs: u64,
    #[serde(default = "default_probing_retention")]
    pub retention_days: u64,
    #[serde(default = "default_probing_max_records")]
    pub max_records: usize,
    #[serde(default = "default_probing_enabled")]
    pub auto_ban_elevated_threat: bool,
    #[serde(default = "default_probing_threshold")]
    pub elevated_threat_threshold: u8,
    #[serde(default = "default_probing_ban_duration")]
    pub elevated_ban_duration: u64,
}

impl Default for HoneypotProbingDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            max_endpoints_per_window: 3,
            window_secs: 300,
            retention_days: 7,
            max_records: 1000,
            auto_ban_elevated_threat: true,
            elevated_threat_threshold: 3,
            elevated_ban_duration: 900,
        }
    }
}

fn default_probing_enabled() -> bool {
    true
}

fn default_honeypot_ports() -> Vec<u16> {
    vec![22, 80, 443, 3306, 6379, 8080, 8443]
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HoneypotPortConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_honeypot_ports")]
    pub ports: Vec<u16>,
}

impl Default for HoneypotPortConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ports: default_honeypot_ports(),
        }
    }
}

fn default_probing_max_endpoints() -> usize {
    3
}
fn default_probing_window() -> u64 {
    300
}
fn default_probing_retention() -> u64 {
    7
}
fn default_probing_max_records() -> usize {
    1000
}
fn default_probing_threshold() -> u8 {
    3
}
fn default_probing_ban_duration() -> u64 {
    900
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct SuspiciousWordsConfig {
    #[serde(default = "default_suspicious_words_enabled")]
    pub enabled: bool,
    #[serde(default = "default_suspicious_words")]
    pub words: Vec<String>,
}

/// Rust `Default` **must** mirror the per-field serde defaults — see the note on
/// [`IpRateLimitConfig::default`]. This one previously failed *open*: an explicit
/// `[defaults.suspicious_words]` table parsed `words` as empty, so
/// suspicious-word scanning silently switched off.
impl Default for SuspiciousWordsConfig {
    fn default() -> Self {
        Self {
            enabled: default_suspicious_words_enabled(),
            words: default_suspicious_words(),
        }
    }
}

fn default_suspicious_words() -> Vec<String> {
    vec![
        "admin".to_string(),
        "administrator".to_string(),
        "backup".to_string(),
        "bak".to_string(),
        "config".to_string(),
        "debug".to_string(),
        ".git".to_string(),
        ".svn".to_string(),
        ".env".to_string(),
        "wp-admin".to_string(),
        "phpmyadmin".to_string(),
        "shell".to_string(),
        "webshell".to_string(),
        "passwd".to_string(),
        "shadow".to_string(),
        "id_rsa".to_string(),
        "database".to_string(),
        "db".to_string(),
        "sql".to_string(),
        "dump".to_string(),
        "restore".to_string(),
    ]
}

fn default_suspicious_words_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct UpstreamErrorsConfig {
    #[serde(default = "default_upstream_errors_enabled")]
    pub enabled: bool,
    #[serde(default = "default_min_error_endpoints")]
    pub min_error_endpoints: usize,
    #[serde(default = "default_probing_window")]
    pub window_secs: u64,
    #[serde(default = "default_error_codes")]
    pub error_codes: Vec<u16>,
    #[serde(default = "default_probing_enabled")]
    pub auto_ban_elevated_threat: bool,
    #[serde(default = "default_probing_threshold")]
    pub elevated_threat_threshold: u8,
    #[serde(default = "default_probing_ban_duration")]
    pub elevated_ban_duration: u64,
}

impl Default for UpstreamErrorsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_error_endpoints: 3,
            window_secs: 300,
            error_codes: vec![400, 401, 403, 404, 500, 502, 503],
            auto_ban_elevated_threat: true,
            elevated_threat_threshold: 3,
            elevated_ban_duration: 900,
        }
    }
}

fn default_upstream_errors_enabled() -> bool {
    true
}
fn default_min_error_endpoints() -> usize {
    3
}
fn default_error_codes() -> Vec<u16> {
    vec![400, 401, 403, 404, 500, 502, 503]
}

/// Error page configuration for custom error responses.
///
/// Modes:
/// - `generic`: Plain HTML, no styling - default for stealth/undetectable WAF
/// - `styled`: Modern styled pages with SynVoid branding
/// - `custom`: User-defined directory (requires custom_directory to be set)
#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct ErrorPagesDefaults {
    /// Enable custom error pages
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Error page mode: "generic", "styled", or "custom"
    #[serde(default = "default_error_pages_mode")]
    pub mode: String,
    /// Base directory for error pages (subdirectories: generic/, styled/)
    #[serde(default = "default_error_pages_directory")]
    pub directory: String,
}

impl Default for ErrorPagesDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: "generic".to_string(),
            directory: "config/error_pages".to_string(),
        }
    }
}

fn default_error_pages_directory() -> String {
    "config/error_pages".to_string()
}
fn default_error_pages_mode() -> String {
    "generic".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct CssChallengeDefaults {
    #[serde(default = "default_css_enabled")]
    pub enabled: bool,
    #[serde(default = "default_css_invalid_min")]
    pub invalid_count_min: u32,
    #[serde(default = "default_css_invalid_max")]
    pub invalid_count_max: u32,
    #[serde(default = "default_css_valid_count")]
    pub valid_count: u32,
    #[serde(default = "default_css_asset_path")]
    pub asset_path: String,
    #[serde(default = "default_css_window")]
    pub challenge_window_secs: u64,
    #[serde(default = "default_css_verification_window")]
    pub verification_window_secs: u32,
    pub block: CssBlockDefaults,
    #[serde(default = "default_css_exempt_paths")]
    pub exempt_paths: Vec<String>,
}

fn default_css_exempt_paths() -> Vec<String> {
    vec![
        "/_waf_css_challenge".to_string(),
        "/_waf_assets".to_string(),
    ]
}

impl Default for CssChallengeDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            invalid_count_min: 80,
            invalid_count_max: 120,
            valid_count: 3,
            asset_path: "/_waf_assets".to_string(),
            challenge_window_secs: 300,
            verification_window_secs: 30,
            block: CssBlockDefaults::default(),
            exempt_paths: default_css_exempt_paths(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct CssBlockDefaults {
    #[serde(default = "default_css_block_enabled")]
    pub enabled: bool,
    #[serde(default = "default_css_ban_duration")]
    pub ban_duration: String,
}

impl Default for CssBlockDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            ban_duration: "24h".to_string(),
        }
    }
}

fn default_css_enabled() -> bool {
    true
}
fn default_css_invalid_min() -> u32 {
    80
}
fn default_css_invalid_max() -> u32 {
    120
}
fn default_css_valid_count() -> u32 {
    3
}
fn default_css_asset_path() -> String {
    "/_waf_assets".to_string()
}
fn default_css_window() -> u64 {
    300
}
fn default_css_verification_window() -> u32 {
    30
}
fn default_css_block_enabled() -> bool {
    true
}
fn default_css_ban_duration() -> String {
    "24h".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct PowChallengeDefaults {
    #[serde(default = "default_pow_enabled")]
    pub enabled: bool,
    #[serde(default = "default_pow_difficulty")]
    pub difficulty: u8,
    #[serde(default = "default_true")]
    pub adaptive_difficulty: bool,
    #[serde(default = "default_pow_max_difficulty")]
    pub max_difficulty: u8,
    #[serde(default = "default_pow_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_pow_window")]
    pub window_secs: u64,
    #[serde(default = "default_true")]
    pub prefer_wasm: bool,
    pub block: PowBlockDefaults,
}

impl Default for PowChallengeDefaults {
    fn default() -> Self {
        Self {
            enabled: default_pow_enabled(),
            difficulty: default_pow_difficulty(),
            adaptive_difficulty: default_true(),
            max_difficulty: default_pow_max_difficulty(),
            timeout_secs: default_pow_timeout(),
            window_secs: default_pow_window(),
            prefer_wasm: default_true(),
            block: PowBlockDefaults::default(),
        }
    }
}

fn default_pow_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct PowBlockDefaults {
    #[serde(default = "default_pow_block_enabled")]
    pub enabled: bool,
    #[serde(default = "default_pow_ban_duration")]
    pub ban_duration: String,
}

impl Default for PowBlockDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            ban_duration: "1h".to_string(),
        }
    }
}

fn default_pow_difficulty() -> u8 {
    6
}
fn default_pow_max_difficulty() -> u8 {
    12
}
fn default_pow_timeout() -> u64 {
    60
}
fn default_pow_window() -> u64 {
    300
}
fn default_pow_block_enabled() -> bool {
    true
}
fn default_pow_ban_duration() -> String {
    "1h".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct ChallengeDefaults {
    #[serde(default = "default_challenge_priority")]
    pub priority: String,
}

impl Default for ChallengeDefaults {
    fn default() -> Self {
        Self {
            priority: default_challenge_priority(),
        }
    }
}

fn default_challenge_priority() -> String {
    "pow_then_css".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct AuthDefaults {
    #[serde(default = "default_auth_enabled")]
    pub enabled: bool,
    #[serde(default = "default_auth_session_duration")]
    pub session_duration_secs: u64,
    #[serde(default = "default_auth_max_attempts")]
    pub max_login_attempts: u32,
    #[serde(default = "default_auth_lockout_duration")]
    pub lockout_duration_secs: u64,
    #[serde(default = "default_auth_login_path")]
    pub login_path: String,
}

impl Default for AuthDefaults {
    fn default() -> Self {
        Self {
            enabled: false,
            session_duration_secs: 86400,
            max_login_attempts: 3,
            lockout_duration_secs: 3600,
            login_path: "/_waf_login".to_string(),
        }
    }
}

fn default_auth_enabled() -> bool {
    false
}
fn default_auth_session_duration() -> u64 {
    86400
}
fn default_auth_max_attempts() -> u32 {
    3
}
fn default_auth_lockout_duration() -> u64 {
    3600
}
fn default_auth_login_path() -> String {
    "/_waf_login".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct WorkerPoolDefaults {
    #[serde(default = "default_worker_pool_mode")]
    pub mode: String,
    #[serde(default = "default_workers")]
    pub workers: usize,
    #[serde(default = "default_worker_port_base")]
    pub worker_port_base: u16,
    #[serde(default = "default_auto_scale")]
    pub auto_scale: bool,
}

impl Default for WorkerPoolDefaults {
    fn default() -> Self {
        Self {
            mode: "shared".to_string(),
            workers: 4,
            worker_port_base: 9000,
            auto_scale: true,
        }
    }
}

impl WorkerPoolDefaults {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        match self.mode.as_str() {
            "shared" | "isolated" => {}
            _ => {
                return Err(ConfigValidationError {
                    field: "defaults.worker_pool.mode".to_string(),
                    message: "Mode must be 'shared' or 'isolated'".to_string(),
                });
            }
        }
        if self.workers == 0 {
            return Err(ConfigValidationError {
                field: "defaults.worker_pool.workers".to_string(),
                message: "Worker count must be greater than 0".to_string(),
            });
        }
        Ok(())
    }
}

fn default_worker_pool_mode() -> String {
    "shared".to_string()
}
fn default_workers() -> usize {
    4
}
fn default_worker_port_base() -> u16 {
    9000
}
fn default_auto_scale() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct PersistenceConfig {
    #[serde(default = "default_persistence_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub data_dir: Option<String>,
    #[serde(default = "default_persist_interval_secs")]
    pub persist_interval_secs: u64,
    #[serde(default = "default_use_persistent_kv")]
    pub use_persistent_kv: bool,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            data_dir: None,
            persist_interval_secs: 60,
            use_persistent_kv: false,
        }
    }
}

fn default_persistence_enabled() -> bool {
    true
}
fn default_persist_interval_secs() -> u64 {
    60
}
fn default_use_persistent_kv() -> bool {
    false
}
