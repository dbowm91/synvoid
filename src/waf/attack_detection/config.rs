use serde::Deserialize;

use crate::config::defaults::default_true;

#[derive(Debug, Clone, Deserialize)]
pub struct DetectorConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            custom_patterns: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SimpleDetectorConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for SimpleDetectorConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AnomalyScoringConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_anomaly_threshold")]
    pub threshold: u32,
}

fn default_anomaly_threshold() -> u32 {
    100
}

impl Default for AnomalyScoringConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_anomaly_threshold(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AttackDetectionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_paranoia_level")]
    pub paranoia_level: u8,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default = "default_max_header_size")]
    pub max_header_size: usize,
    #[serde(default = "default_max_headers")]
    pub max_headers: usize,
    #[serde(default = "default_max_body_size")]
    pub max_request_body_size: Option<usize>,
    #[serde(default)]
    pub anomaly_scoring: AnomalyScoringConfig,
    #[serde(default)]
    pub sqli: SimpleDetectorConfig,
    #[serde(default)]
    pub xss: SimpleDetectorConfig,
    #[serde(default)]
    pub path_traversal: DetectorConfig,
    #[serde(default)]
    pub rfi: DetectorConfig,
    #[serde(default)]
    pub ssrf: SsrfConfig,
    #[serde(default)]
    pub ssti: DetectorConfig,
    #[serde(default)]
    pub cmd_injection: DetectorConfig,
    #[serde(default)]
    pub xxe: DetectorConfig,
    #[serde(default)]
    pub jwt: DetectorConfig,
    #[serde(default)]
    pub request_smuggling: SimpleDetectorConfig,
    #[serde(default)]
    pub ldap_injection: DetectorConfig,
    #[serde(default)]
    pub xpath_injection: DetectorConfig,
    #[serde(default)]
    pub open_redirect: DetectorConfig,
}

fn default_paranoia_level() -> u8 {
    2
}

fn default_action() -> String {
    "stall".to_string()
}

fn default_max_header_size() -> usize {
    8192
}

fn default_max_headers() -> usize {
    128
}

fn default_max_body_size() -> Option<usize> {
    Some(10485760) // 10MB default
}

impl Default for AttackDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            paranoia_level: default_paranoia_level(),
            action: default_action(),
            max_header_size: default_max_header_size(),
            max_headers: default_max_headers(),
            max_request_body_size: default_max_body_size(),
            anomaly_scoring: AnomalyScoringConfig::default(),
            sqli: SimpleDetectorConfig::default(),
            xss: SimpleDetectorConfig::default(),
            path_traversal: DetectorConfig::default(),
            rfi: DetectorConfig::default(),
            ssrf: SsrfConfig::default(),
            ssti: DetectorConfig::default(),
            cmd_injection: DetectorConfig::default(),
            xxe: DetectorConfig::default(),
            jwt: DetectorConfig::default(),
            request_smuggling: SimpleDetectorConfig::default(),
            ldap_injection: DetectorConfig::default(),
            xpath_injection: DetectorConfig::default(),
            open_redirect: DetectorConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SsrfConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
    #[serde(default = "default_block_private_ips")]
    pub block_private_ips: bool,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

fn default_block_private_ips() -> bool {
    true
}

pub type SqliConfig = SimpleDetectorConfig;
pub type XssConfig = SimpleDetectorConfig;
pub type PathTraversalConfig = DetectorConfig;
pub type RfiConfig = DetectorConfig;
pub type SstiConfig = DetectorConfig;
pub type CmdInjectionConfig = DetectorConfig;
pub type XxeConfig = DetectorConfig;
pub type JwtConfig = DetectorConfig;
pub type RequestSmugglingConfig = SimpleDetectorConfig;
pub type LdapInjectionConfig = DetectorConfig;
pub type XPathInjectionConfig = DetectorConfig;
pub type OpenRedirectConfig = DetectorConfig;

#[derive(Debug, Clone)]
pub struct AttackDetectionResult {
    pub attack_type: AttackType,
    pub fingerprint: Option<String>,
    pub matched_pattern: Option<String>,
    pub input_location: InputLocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttackType {
    Sqli,
    Xss,
    PathTraversal,
    Rfi,
    Ssrf,
    Ssti,
    CmdInjection,
    Xxe,
    Jwt,
    RequestSmuggling,
    LdapInjection,
    XPathInjection,
    OpenRedirect,
    Other,
}

impl std::fmt::Display for AttackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackType::Sqli => write!(f, "SQLi"),
            AttackType::Xss => write!(f, "XSS"),
            AttackType::PathTraversal => write!(f, "PathTraversal"),
            AttackType::Rfi => write!(f, "RFI"),
            AttackType::Ssrf => write!(f, "SSRF"),
            AttackType::Ssti => write!(f, "SSTI"),
            AttackType::CmdInjection => write!(f, "CmdInjection"),
            AttackType::Xxe => write!(f, "XXE"),
            AttackType::Jwt => write!(f, "JWT"),
            AttackType::RequestSmuggling => write!(f, "RequestSmuggling"),
            AttackType::LdapInjection => write!(f, "LdapInjection"),
            AttackType::XPathInjection => write!(f, "XPathInjection"),
            AttackType::OpenRedirect => write!(f, "OpenRedirect"),
            AttackType::Other => write!(f, "Other"),
        }
    }
}

use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum InputLocation {
    QueryString,
    PostBody,
    Header(Arc<str>),
    Path,
    Cookie(Arc<str>),
}

impl std::fmt::Display for InputLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InputLocation::QueryString => write!(f, "query_string"),
            InputLocation::PostBody => write!(f, "post_body"),
            InputLocation::Header(name) => write!(f, "header:{}", name),
            InputLocation::Path => write!(f, "path"),
            InputLocation::Cookie(name) => write!(f, "cookie:{}", name),
        }
    }
}
