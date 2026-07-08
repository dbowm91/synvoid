use serde::{Deserialize, Serialize};

/// Redirect policy for tarpit responses.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedirectPolicy {
    /// Only allow relative redirects (no absolute URLs).
    #[default]
    RelativeOnly,
    /// Allow redirects to specific whitelisted hosts.
    AllowList(Vec<String>),
    /// Allow any redirect target (not recommended for production).
    AllowAll,
}

/// Admission control limits for tarpit sessions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdmissionConfig {
    /// Maximum concurrent tarpit sessions globally.
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,
    /// Maximum concurrent tarpit sessions per IP.
    #[serde(default = "default_max_per_ip")]
    pub max_per_ip: usize,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            max_concurrent: default_max_concurrent(),
            max_per_ip: default_max_per_ip(),
        }
    }
}

fn default_max_concurrent() -> usize {
    256
}
fn default_max_per_ip() -> usize {
    4
}

/// Duration and output budgets for tarpit streams.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BudgetConfig {
    /// Maximum connection duration in seconds.
    #[serde(default = "default_max_duration_secs")]
    pub max_duration_secs: u64,
    /// Maximum chunks (HTML segments) sent per response.
    #[serde(default = "default_max_chunks")]
    pub max_chunks: u64,
    /// Maximum total bytes sent per response.
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
    /// Maximum idle time (no client activity) in seconds before closing.
    #[serde(default = "default_max_idle_secs")]
    pub max_idle_secs: u64,
    /// Write timeout per chunk in milliseconds.
    #[serde(default = "default_write_timeout_ms")]
    pub write_timeout_ms: u64,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            max_duration_secs: default_max_duration_secs(),
            max_chunks: default_max_chunks(),
            max_bytes: default_max_bytes(),
            max_idle_secs: default_max_idle_secs(),
            write_timeout_ms: default_write_timeout_ms(),
        }
    }
}

fn default_max_duration_secs() -> u64 {
    600
}
fn default_max_chunks() -> u64 {
    500
}
fn default_max_bytes() -> u64 {
    50 * 1024 * 1024 // 50 MB
}
fn default_max_idle_secs() -> u64 {
    30
}
fn default_write_timeout_ms() -> u64 {
    5000
}

/// Fingerprint resistance configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FingerprintConfig {
    /// Minimum delay between chunks in milliseconds.
    #[serde(default = "default_min_chunk_delay_ms")]
    pub min_chunk_delay_ms: u64,
    /// Maximum delay between chunks in milliseconds.
    #[serde(default = "default_max_chunk_delay_ms")]
    pub max_chunk_delay_ms: u64,
    /// Whether to vary content types across responses.
    #[serde(default = "default_vary_content_type")]
    pub vary_content_type: bool,
    /// Whether to vary HTTP status codes across responses.
    #[serde(default = "default_vary_status_code")]
    pub vary_status_code: bool,
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        Self {
            min_chunk_delay_ms: default_min_chunk_delay_ms(),
            max_chunk_delay_ms: default_max_chunk_delay_ms(),
            vary_content_type: default_vary_content_type(),
            vary_status_code: default_vary_status_code(),
        }
    }
}

fn default_min_chunk_delay_ms() -> u64 {
    5
}
fn default_max_chunk_delay_ms() -> u64 {
    30
}
fn default_vary_content_type() -> bool {
    true
}
fn default_vary_status_code() -> bool {
    true
}

/// Configuration for the tarpit module.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TarpitConfig {
    pub enabled: bool,
    #[serde(default = "default_max_depth")]
    pub max_depth: u32,
    #[serde(default = "default_links_per_page")]
    pub links_per_page: u32,
    #[serde(default = "default_response_delay_ms")]
    pub response_delay_ms: u64,
    #[serde(default)]
    pub scraper_patterns: Vec<String>,
    #[serde(default)]
    pub redirect_policy: RedirectPolicy,
    #[serde(default)]
    pub admission: AdmissionConfig,
    #[serde(default)]
    pub budget: BudgetConfig,
    #[serde(default)]
    pub fingerprint: FingerprintConfig,
}

fn default_max_depth() -> u32 {
    10
}
fn default_links_per_page() -> u32 {
    50
}
fn default_response_delay_ms() -> u64 {
    100
}

impl Default for TarpitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_depth: default_max_depth(),
            links_per_page: default_links_per_page(),
            response_delay_ms: default_response_delay_ms(),
            scraper_patterns: vec![
                "scrapy".to_string(),
                "curl".to_string(),
                "wget".to_string(),
                "python-requests".to_string(),
                "python-urllib".to_string(),
                "aiohttp".to_string(),
                "httpx".to_string(),
            ],
            redirect_policy: RedirectPolicy::default(),
            admission: AdmissionConfig::default(),
            budget: BudgetConfig::default(),
            fingerprint: FingerprintConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_roundtrip() {
        let config = TarpitConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: TarpitConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.max_depth, deserialized.max_depth);
        assert_eq!(config.links_per_page, deserialized.links_per_page);
        assert_eq!(config.budget.max_bytes, deserialized.budget.max_bytes);
    }

    #[test]
    fn redirect_policy_default() {
        assert!(matches!(
            RedirectPolicy::default(),
            RedirectPolicy::RelativeOnly
        ));
    }

    #[test]
    fn admission_defaults() {
        let adm = AdmissionConfig::default();
        assert_eq!(adm.max_concurrent, 256);
        assert_eq!(adm.max_per_ip, 4);
    }

    #[test]
    fn budget_defaults() {
        let bud = BudgetConfig::default();
        assert_eq!(bud.max_duration_secs, 600);
        assert_eq!(bud.max_chunks, 500);
        assert_eq!(bud.max_bytes, 50 * 1024 * 1024);
        assert_eq!(bud.max_idle_secs, 30);
        assert_eq!(bud.write_timeout_ms, 5000);
    }

    #[test]
    fn fingerprint_defaults() {
        let fp = FingerprintConfig::default();
        assert_eq!(fp.min_chunk_delay_ms, 5);
        assert_eq!(fp.max_chunk_delay_ms, 30);
        assert!(fp.vary_content_type);
        assert!(fp.vary_status_code);
    }

    #[test]
    fn config_partial_json_uses_defaults() {
        let json = r#"{"enabled": false}"#;
        let config: TarpitConfig = serde_json::from_str(json).unwrap();
        assert!(!config.enabled);
        assert_eq!(config.max_depth, 10);
        assert_eq!(config.response_delay_ms, 100);
    }

    #[test]
    fn redirect_policy_allow_list_roundtrip() {
        let policy = RedirectPolicy::AllowList(vec!["example.com".to_string()]);
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: RedirectPolicy = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            deserialized,
            RedirectPolicy::AllowList(ref hosts) if hosts.len() == 1
        ));
    }
}
