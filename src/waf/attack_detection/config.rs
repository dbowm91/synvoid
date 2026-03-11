use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct AttackDetectionConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_paranoia_level")]
    pub paranoia_level: u8,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default = "default_max_header_size")]
    pub max_header_size: usize,
    #[serde(default = "default_max_headers")]
    pub max_headers: usize,
    #[serde(default)]
    pub sqli: SqliConfig,
    #[serde(default)]
    pub xss: XssConfig,
    #[serde(default)]
    pub path_traversal: PathTraversalConfig,
    #[serde(default)]
    pub rfi: RfiConfig,
    #[serde(default)]
    pub ssrf: SsrfConfig,
    #[serde(default)]
    pub ssti: SstiConfig,
    #[serde(default)]
    pub cmd_injection: CmdInjectionConfig,
    #[serde(default)]
    pub xxe: XxeConfig,
    #[serde(default)]
    pub jwt: JwtConfig,
    #[serde(default)]
    pub request_smuggling: RequestSmugglingConfig,
    #[serde(default)]
    pub ldap_injection: LdapInjectionConfig,
    #[serde(default)]
    pub xpath_injection: XPathInjectionConfig,
    #[serde(default)]
    pub open_redirect: OpenRedirectConfig,
}

impl Default for AttackDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            paranoia_level: default_paranoia_level(),
            action: default_action(),
            max_header_size: default_max_header_size(),
            max_headers: default_max_headers(),
            sqli: SqliConfig::default(),
            xss: XssConfig::default(),
            path_traversal: PathTraversalConfig::default(),
            rfi: RfiConfig::default(),
            ssrf: SsrfConfig::default(),
            ssti: SstiConfig::default(),
            cmd_injection: CmdInjectionConfig::default(),
            xxe: XxeConfig::default(),
            jwt: JwtConfig::default(),
            request_smuggling: RequestSmugglingConfig::default(),
            ldap_injection: LdapInjectionConfig::default(),
            xpath_injection: XPathInjectionConfig::default(),
            open_redirect: OpenRedirectConfig::default(),
        }
    }
}

fn default_enabled() -> bool {
    true
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

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SqliConfig {
    #[serde(default = "default_sqli_enabled")]
    pub enabled: bool,
}

fn default_sqli_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct XssConfig {
    #[serde(default = "default_xss_enabled")]
    pub enabled: bool,
}

fn default_xss_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PathTraversalConfig {
    #[serde(default = "default_path_traversal_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
}

fn default_path_traversal_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RfiConfig {
    #[serde(default = "default_rfi_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
}

fn default_rfi_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SsrfConfig {
    #[serde(default = "default_ssrf_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
    #[serde(default = "default_block_private_ips")]
    pub block_private_ips: bool,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

fn default_ssrf_enabled() -> bool {
    true
}

fn default_block_private_ips() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SstiConfig {
    #[serde(default = "default_ssti_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
}

fn default_ssti_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CmdInjectionConfig {
    #[serde(default = "default_cmd_injection_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
}

fn default_cmd_injection_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct XxeConfig {
    #[serde(default = "default_xxe_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
}

fn default_xxe_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct JwtConfig {
    #[serde(default = "default_jwt_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
}

fn default_jwt_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RequestSmugglingConfig {
    #[serde(default = "default_request_smuggling_enabled")]
    pub enabled: bool,
}

fn default_request_smuggling_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct LdapInjectionConfig {
    #[serde(default = "default_ldap_injection_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
}

fn default_ldap_injection_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct XPathInjectionConfig {
    #[serde(default = "default_xpath_injection_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
}

fn default_xpath_injection_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct OpenRedirectConfig {
    #[serde(default = "default_open_redirect_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
}

fn default_open_redirect_enabled() -> bool {
    true
}

#[derive(Debug, Clone)]
pub struct AttackDetectionResult {
    pub attack_type: AttackType,
    pub fingerprint: Option<String>,
    pub matched_pattern: Option<String>,
    pub input_location: InputLocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        }
    }
}

#[derive(Debug, Clone)]
pub enum InputLocation {
    QueryString,
    PostBody,
    Header(String),
    Path,
    Cookie(String),
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
