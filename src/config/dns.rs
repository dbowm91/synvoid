use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsMode {
    #[default]
    Standalone,
    Mesh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsRateLimitMode {
    #[default]
    Shared,
    Dedicated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_dns_bind_address")]
    pub bind_address: String,

    #[serde(default = "default_dns_port")]
    pub port: u16,

    #[serde(default)]
    pub mode: DnsMode,

    #[serde(default)]
    pub ratelimit: DnsRateLimitConfig,

    #[serde(default)]
    pub rrl: DnsRrlConfig,

    #[serde(default)]
    pub firewall: DnsFirewallConfig,

    #[serde(default)]
    pub settings: DnsSettingsConfig,

    #[serde(default)]
    pub mesh: DnsMeshConfig,

    #[serde(default)]
    pub zones: DnsZonesConfig,

    #[serde(default)]
    pub limits: DnsLimitsConfig,

    #[serde(default)]
    pub dnssec: DnsSecConfig,

    #[serde(default)]
    pub dot: DnsDotConfig,

    #[serde(default)]
    pub doh: DnsDohConfig,

    #[serde(default)]
    pub doq: DnsDoqConfig,

    #[serde(default)]
    pub rpz: DnsRpzConfig,

    #[serde(default)]
    pub dns64: Dns64Config,

    #[serde(default)]
    pub prefetch: DnsPrefetchConfig,

    #[serde(default)]
    pub trust_anchors: TrustAnchorConfig,

    #[serde(default)]
    pub anycast: DnsAnycastConfig,

    #[serde(default)]
    pub recursive: RecursiveDnsConfig,
}

fn default_dns_bind_address() -> String {
    "0.0.0.0".to_string()
}

fn default_dns_port() -> u16 {
    53
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsRateLimitConfig {
    #[serde(default)]
    pub mode: DnsRateLimitMode,

    #[serde(default = "default_dns_per_second")]
    pub per_second: u64,

    #[serde(default = "default_dns_per_minute")]
    pub per_minute: u64,
}

fn default_dns_per_second() -> u64 {
    500
}

fn default_dns_per_minute() -> u64 {
    5000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsSettingsConfig {
    #[serde(default = "default_dns_ttl")]
    pub default_ttl: u32,

    #[serde(default = "default_min_geo_ttl")]
    pub min_geo_ttl: u32,

    #[serde(default)]
    pub allow_transfer: Vec<String>,

    #[serde(default = "default_cache_enabled")]
    pub cache_enabled: bool,

    #[serde(default = "default_cache_size")]
    pub cache_size: usize,

    #[serde(default = "default_cache_max_ttl")]
    pub cache_max_ttl: u64,

    #[serde(default = "default_cache_min_ttl")]
    pub cache_min_ttl: u64,

    #[serde(default = "default_negative_cache_ttl")]
    pub negative_cache_ttl: u32,

    #[serde(default)]
    pub allow_wildcard_transfer: bool,

    #[serde(default)]
    pub wildcard_transfer_requires_tsig: bool,

    #[serde(default = "default_require_tsig")]
    pub require_tsig: bool,

    #[serde(default)]
    pub serve_stale: ServeStaleConfig,

    #[serde(default = "default_ixfr_history_size")]
    pub ixfr_history_size: usize,

    #[serde(default = "default_ixfr_enabled")]
    pub ixfr_enabled: bool,

    #[serde(default = "default_ixfr_fallback_to_axfr")]
    pub ixfr_fallback_to_axfr: bool,

    #[serde(default)]
    pub ecs_filtering: EcsFilteringConfig,

    #[serde(default)]
    pub padding: DnsPaddingConfig,

    #[serde(default)]
    pub query_coalescing: QueryCoalescingConfig,

    #[serde(default)]
    pub dynamic_update: DynamicUpdateConfig,

    #[serde(default)]
    pub notify: NotifyConfig,

    #[serde(default)]
    pub qname_privacy: QnamePrivacyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DnsPaddingConfig {
    #[serde(default = "default_padding_enabled")]
    pub enabled: bool,

    #[serde(default = "default_padding_block_size")]
    pub block_size: usize,

    #[serde(default = "default_padding_mode")]
    pub mode: DnsPaddingMode,
}

fn default_padding_enabled() -> bool {
    false
}

fn default_padding_block_size() -> usize {
    128
}

fn default_padding_mode() -> DnsPaddingMode {
    DnsPaddingMode::Normal
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsPaddingMode {
    #[default]
    Normal,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct QnamePrivacyConfig {
    #[serde(default = "default_qname_privacy_enabled")]
    pub enabled: bool,

    #[serde(default = "default_qname_privacy_mode")]
    pub mode: QnamePrivacyMode,

    #[serde(default = "default_qname_log_level")]
    pub log_level: QnameLogLevel,
}

fn default_qname_privacy_enabled() -> bool {
    false
}

fn default_qname_privacy_mode() -> QnamePrivacyMode {
    QnamePrivacyMode::ZoneOnly
}

fn default_qname_log_level() -> QnameLogLevel {
    QnameLogLevel::Zone
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum QnamePrivacyMode {
    #[default]
    ZoneOnly,
    Truncate,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum QnameLogLevel {
    #[default]
    Zone,
    Debug,
    Hidden,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct QueryCoalescingConfig {
    #[serde(default = "default_coalescing_enabled")]
    pub enabled: bool,

    #[serde(default = "default_coalescing_max_wait")]
    pub max_wait_ms: u64,

    #[serde(default = "default_coalescing_max_entries")]
    pub max_entries: usize,

    #[serde(default = "default_coalescing_entry_ttl")]
    pub entry_ttl_secs: u64,

    #[serde(default = "default_coalescing_cleanup_interval")]
    pub cleanup_interval_secs: u64,
}

fn default_coalescing_enabled() -> bool {
    false
}

fn default_coalescing_max_wait() -> u64 {
    500
}

fn default_coalescing_max_entries() -> usize {
    10000
}

fn default_coalescing_entry_ttl() -> u64 {
    30
}

fn default_coalescing_cleanup_interval() -> u64 {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DynamicUpdateConfig {
    #[serde(default = "default_dynamic_update_enabled")]
    pub enabled: bool,

    #[serde(default)]
    pub allow_any: bool,

    #[serde(default)]
    pub require_tsig: bool,
}

fn default_dynamic_update_enabled() -> bool {
    false
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NotifyConfig {
    #[serde(default = "default_notify_enabled")]
    pub enabled: bool,

    #[serde(default)]
    pub also_notify: Vec<String>,
}

fn default_notify_enabled() -> bool {
    false
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EcsFilteringConfig {
    #[serde(default = "default_ecs_enabled")]
    pub enabled: bool,

    #[serde(default = "default_ecs_prefix_v4")]
    pub prefix_v4: u8,

    #[serde(default = "default_ecs_prefix_v6")]
    pub prefix_v6: u8,

    #[serde(default)]
    pub allow_private_prefix: bool,
}

fn default_ecs_enabled() -> bool {
    false
}

fn default_ecs_prefix_v4() -> u8 {
    24
}

fn default_ecs_prefix_v6() -> u8 {
    48
}

fn default_ixfr_history_size() -> usize {
    200
}

fn default_ixfr_enabled() -> bool {
    true
}

fn default_ixfr_fallback_to_axfr() -> bool {
    true
}

fn default_dns_ttl() -> u32 {
    300
}

fn default_negative_cache_ttl() -> u32 {
    300
}

fn default_min_geo_ttl() -> u32 {
    60
}

fn default_cache_enabled() -> bool {
    true
}

fn default_cache_size() -> usize {
    100000
}

fn default_cache_max_ttl() -> u64 {
    3600
}

fn default_cache_min_ttl() -> u64 {
    60
}

fn default_allow_wildcard_transfer() -> bool {
    false
}

fn default_wildcard_transfer_requires_tsig() -> bool {
    true
}

fn default_require_tsig() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ServeStaleConfig {
    #[serde(default = "default_serve_stale_enabled")]
    pub enabled: bool,

    #[serde(default = "default_serve_stale_max_stale")]
    pub max_stale_secs: u64,

    #[serde(default = "default_serve_stale_max_count")]
    pub max_stale_count: usize,
}

fn default_serve_stale_enabled() -> bool {
    false
}

fn default_serve_stale_max_stale() -> u64 {
    86400
}

fn default_serve_stale_max_count() -> usize {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DnsRrlConfig {
    #[serde(default = "default_rrl_enabled")]
    pub enabled: bool,

    #[serde(default = "default_rrl_responses_per_second")]
    pub responses_per_second: u64,

    #[serde(default = "default_rrl_window_secs")]
    pub window_secs: u64,

    #[serde(default = "default_rrl_max_responses")]
    pub max_responses: u64,

    #[serde(default = "default_rrl_ttl")]
    pub ttl: u32,
}

fn default_rrl_enabled() -> bool {
    true
}

fn default_rrl_responses_per_second() -> u64 {
    100
}

fn default_rrl_window_secs() -> u64 {
    5
}

fn default_rrl_max_responses() -> u64 {
    1000
}

fn default_rrl_ttl() -> u32 {
    300
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FirewallAction {
    #[default]
    Allow,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DnsFirewallConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub default_action: FirewallAction,

    #[serde(default = "default_true")]
    pub block_internal_ips: bool,

    #[serde(default = "default_true")]
    pub block_zone_transfers: bool,

    #[serde(default = "default_firewall_max_rules")]
    pub max_rules: usize,

    #[serde(default)]
    pub rebinding_protection: RebindingProtectionConfig,
}

fn default_firewall_max_rules() -> usize {
    1000
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RebindingProtectionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_min_rebinding_ttl")]
    pub min_ttl_for_internal: u32,

    #[serde(default)]
    pub allowed_internal_domains: Vec<String>,

    #[serde(default)]
    pub block_short_ttl_internal: bool,
}

fn default_min_rebinding_ttl() -> u32 {
    1800
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DnsLimitsConfig {
    #[serde(default = "default_max_tcp_connections")]
    pub max_tcp_connections: usize,

    #[serde(default = "default_max_concurrent_queries")]
    pub max_concurrent_queries: usize,

    #[serde(default = "default_max_query_size")]
    pub max_query_size: usize,

    #[serde(default = "default_max_response_size")]
    pub max_response_size: usize,

    #[serde(default = "default_max_records_per_response")]
    pub max_records_per_response: usize,

    #[serde(default = "default_max_tcp_idle_time")]
    pub max_tcp_idle_time_secs: u64,

    #[serde(default = "default_max_tcp_query_time")]
    pub max_tcp_query_time_secs: u64,

    #[serde(default = "default_udp_buffer_size")]
    pub udp_buffer_size: usize,

    #[serde(default)]
    pub enable_graceful_degradation: bool,
}

fn default_max_tcp_connections() -> usize {
    500
}

fn default_max_concurrent_queries() -> usize {
    2500
}

fn default_max_query_size() -> usize {
    65535
}

fn default_max_response_size() -> usize {
    65535
}

fn default_max_records_per_response() -> usize {
    1000
}

fn default_max_tcp_idle_time() -> u64 {
    300
}

fn default_max_tcp_query_time() -> u64 {
    30
}

fn default_udp_buffer_size() -> usize {
    65535
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DnsDotConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_dot_port")]
    pub port: u16,

    #[serde(default)]
    pub bind_address: String,

    #[serde(default)]
    pub tls_cert_path: Option<String>,

    #[serde(default)]
    pub tls_key_path: Option<String>,

    #[serde(default = "default_true")]
    pub use_system_cert_store: bool,
}

fn default_dot_port() -> u16 {
    853
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DnsDohConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_doh_port")]
    pub port: u16,

    #[serde(default)]
    pub bind_address: String,

    #[serde(default = "default_doh_path")]
    pub path: String,

    #[serde(default)]
    pub json_path: String,

    #[serde(default)]
    pub tls_cert_path: Option<String>,

    #[serde(default)]
    pub tls_key_path: Option<String>,

    #[serde(default = "default_true")]
    pub use_system_cert_store: bool,
}

fn default_doh_port() -> u16 {
    443
}

fn default_doh_path() -> String {
    "/dns-query".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DnsDoqConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_doq_port")]
    pub port: u16,

    #[serde(default)]
    pub bind_address: String,

    #[serde(default)]
    pub tls_cert_path: Option<String>,

    #[serde(default)]
    pub tls_key_path: Option<String>,

    #[serde(default = "default_true")]
    pub use_system_cert_store: bool,

    #[serde(default = "default_doq_max_concurrent_streams")]
    pub max_concurrent_streams: u32,

    #[serde(default = "default_doq_idle_timeout")]
    pub idle_timeout_secs: u64,
}

fn default_doq_port() -> u16 {
    853
}

fn default_doq_max_concurrent_streams() -> u32 {
    100
}

fn default_doq_idle_timeout() -> u64 {
    30
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DnsRpzConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub primary_zone: String,

    #[serde(default)]
    pub allow_transfer: Vec<String>,

    #[serde(default)]
    pub refresh_interval_secs: u64,

    #[serde(default)]
    pub retry_interval_secs: u64,

    #[serde(default)]
    pub expire_interval_secs: u64,

    #[serde(default)]
    pub min_ttl: u32,

    #[serde(default)]
    pub max_ttl: u32,

    #[serde(default)]
    pub default_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Dns64Config {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_dns64_prefix")]
    pub prefix: String,

    #[serde(default)]
    pub exclude_aaaa_synthesis: bool,
}

fn default_dns64_prefix() -> String {
    "64:ff9b::".to_string()
}

impl Default for Dns64Config {
    fn default() -> Self {
        Self {
            enabled: false,
            prefix: default_dns64_prefix(),
            exclude_aaaa_synthesis: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsPrefetchConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_prefetch_min_queries")]
    pub min_query_count: u32,

    #[serde(default = "default_prefetch_ttl_threshold")]
    pub prefetch_ttl_threshold: u32,

    #[serde(default = "default_max_prefetch_names")]
    pub max_prefetched_names: usize,
}

fn default_prefetch_min_queries() -> u32 {
    10
}

fn default_prefetch_ttl_threshold() -> u32 {
    300
}

fn default_max_prefetch_names() -> usize {
    1000
}

impl Default for DnsPrefetchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_query_count: default_prefetch_min_queries(),
            prefetch_ttl_threshold: default_prefetch_ttl_threshold(),
            max_prefetched_names: default_max_prefetch_names(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TrustAnchorConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_db_path")]
    pub db_path: String,

    #[serde(default = "default_trust_anchor_path")]
    pub anchor_file_path: String,

    #[serde(default = "default_trust_anchor_refresh")]
    pub refresh_interval_secs: u64,

    #[serde(default = "default_pending_observation")]
    pub pending_observation_days: u64,

    #[serde(default = "default_revocation_grace")]
    pub revocation_grace_days: u64,

    #[serde(default = "default_extended_removal")]
    pub extended_removal_days: u64,

    #[serde(default = "default_trust_anchor_retention")]
    pub trust_anchor_retention_days: u64,

    #[serde(default)]
    pub allow_key_rotation: bool,
}

fn default_db_path() -> String {
    "/var/lib/maluwaf/dns/trust_anchors.db".to_string()
}

fn default_trust_anchor_path() -> String {
    "/var/lib/maluwaf/dns/trusted-key.key".to_string()
}

fn default_trust_anchor_refresh() -> u64 {
    3600
}

fn default_pending_observation() -> u64 {
    30
}

fn default_revocation_grace() -> u64 {
    30
}

fn default_extended_removal() -> u64 {
    60
}

fn default_trust_anchor_retention() -> u64 {
    7
}

impl Default for TrustAnchorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            db_path: default_db_path(),
            anchor_file_path: default_trust_anchor_path(),
            refresh_interval_secs: default_trust_anchor_refresh(),
            pending_observation_days: default_pending_observation(),
            revocation_grace_days: default_revocation_grace(),
            extended_removal_days: default_extended_removal(),
            trust_anchor_retention_days: default_trust_anchor_retention(),
            allow_key_rotation: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsMeshConfig {
    #[serde(default = "default_true")]
    pub register_to_global: bool,

    #[serde(default = "default_registration_interval")]
    pub registration_interval_secs: u64,

    #[serde(default = "default_true")]
    pub accept_registrations: bool,

    #[serde(default = "default_sync_interval")]
    pub sync_interval_secs: u64,

    #[serde(default = "default_upstream_dns_servers")]
    pub upstream_dns_servers: Vec<String>,

    #[serde(default = "default_verification_retry_interval")]
    pub verification_retry_interval_secs: u64,

    #[serde(default = "default_verification_timeout")]
    pub verification_timeout_secs: u64,

    #[serde(default)]
    pub qname_minimization: bool,

    #[serde(default)]
    pub require_cert_chain_verification: bool,
}

use super::defaults::default_true;

fn default_registration_interval() -> u64 {
    60
}

fn default_sync_interval() -> u64 {
    30
}

fn default_verification_retry_interval() -> u64 {
    30
}

fn default_verification_timeout() -> u64 {
    600 // 10 minutes
}

fn default_upstream_dns_servers() -> Vec<String> {
    vec![]
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsZonesConfig {
    #[serde(default)]
    pub items: Vec<DnsZoneEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsZoneEntry {
    pub zone: String,

    #[serde(default)]
    pub records: Vec<DnsRecordEntry>,

    #[serde(default)]
    pub dnssec: Option<DnsZoneDnssecConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsZoneDnssecConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub algorithm: Option<DnsSecAlgorithm>,

    #[serde(default)]
    pub nsec_enabled: bool,

    #[serde(default)]
    pub nsec3_enabled: bool,

    #[serde(default)]
    pub nsec3_iterations: Option<u16>,

    #[serde(default)]
    pub nsec3_algorithm: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsRecordType {
    A,
    Aaaa,
    CName,
    Mx,
    Txt,
    Ns,
    Soa,
    Srv,
    Ptr,
    Caa,
    Tlsa,
    Svcb,
    Https,
    Naptr,
    Sshfp,
    Uri,
    Rp,
    Afsdb,
    Ds,
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecordEntry {
    pub name: String,

    #[serde(default = "default_record_type_a")]
    pub record_type: DnsRecordType,

    pub value: String,

    #[serde(default = "default_record_ttl")]
    pub ttl: Option<u32>,

    #[serde(default)]
    pub priority: Option<u32>,
}

fn default_record_type_a() -> DnsRecordType {
    DnsRecordType::A
}

fn default_record_ttl() -> Option<u32> {
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsSecAlgorithm {
    #[default]
    Ed25519,
    RsaSha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsSecKeyType {
    #[default]
    Zsk,
    Ksk,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TsigAlgorithm {
    #[default]
    HmacSha256,
    HmacSha1,
    HmacSha384,
    HmacSha512,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct TsigKeyConfig {
    pub name: String,
    pub secret_base64: String,
    #[serde(default)]
    pub algorithm: TsigAlgorithm,
}

impl TsigAlgorithm {
    pub fn to_u16(&self) -> u16 {
        match self {
            TsigAlgorithm::HmacSha256 => 161,
            TsigAlgorithm::HmacSha1 => 249,
            TsigAlgorithm::HmacSha384 => 170,
            TsigAlgorithm::HmacSha512 => 172,
        }
    }

    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            161 => Some(TsigAlgorithm::HmacSha256),
            249 => Some(TsigAlgorithm::HmacSha1),
            170 => Some(TsigAlgorithm::HmacSha384),
            172 => Some(TsigAlgorithm::HmacSha512),
            _ => None,
        }
    }

    pub fn key_size(&self) -> usize {
        match self {
            TsigAlgorithm::HmacSha256 => 32,
            TsigAlgorithm::HmacSha1 => 20,
            TsigAlgorithm::HmacSha384 => 48,
            TsigAlgorithm::HmacSha512 => 64,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsSecConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub domain: String,

    #[serde(default = "default_dnssec_key_path")]
    pub key_path: String,

    #[serde(default = "default_rollover_interval")]
    pub rollover_interval_days: u32,

    #[serde(default)]
    pub algorithm: DnsSecAlgorithm,

    #[serde(default = "default_rsa_key_size")]
    pub rsa_key_size: u32,

    #[serde(default = "default_ksk_key_size")]
    pub ksk_key_size: u32,

    #[serde(default = "default_true")]
    pub nsec3_enabled: bool,

    #[serde(default)]
    pub nsec_enabled: bool,

    #[serde(default = "default_nsec3_iterations")]
    pub nsec3_iterations: u16,

    #[serde(default = "default_nsec3_algorithm")]
    pub nsec3_algorithm: u8,

    #[serde(default)]
    pub tsig_keys: Vec<TsigKeyConfig>,

    #[serde(default)]
    pub hsm: HsmConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HsmConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub provider: HsmProvider,

    #[serde(default)]
    pub module_path: String,

    #[serde(default)]
    pub slot_id: Option<usize>,

    #[serde(default)]
    pub pin: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HsmProvider {
    #[default]
    Pkcs11,
    Soft,
}

fn default_ksk_key_size() -> u32 {
    4096
}

fn default_nsec3_iterations() -> u16 {
    50
}

fn default_nsec3_algorithm() -> u8 {
    1 // SHA-1 (RFC 5155)
}

fn default_dnssec_key_path() -> String {
    "/var/lib/maluwaf/dns/keys".to_string()
}

fn default_rollover_interval() -> u32 {
    30
}

fn default_rsa_key_size() -> u32 {
    2048
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: default_dns_bind_address(),
            port: default_dns_port(),
            mode: DnsMode::Standalone,
            ratelimit: DnsRateLimitConfig::default(),
            rrl: DnsRrlConfig::default(),
            firewall: DnsFirewallConfig::default(),
            settings: DnsSettingsConfig::default(),
            mesh: DnsMeshConfig::default(),
            zones: DnsZonesConfig::default(),
            limits: DnsLimitsConfig::default(),
            dnssec: DnsSecConfig::default(),
            dot: DnsDotConfig::default(),
            doh: DnsDohConfig::default(),
            doq: DnsDoqConfig::default(),
            rpz: DnsRpzConfig::default(),
            dns64: Dns64Config::default(),
            prefetch: DnsPrefetchConfig::default(),
            trust_anchors: TrustAnchorConfig::default(),
            anycast: DnsAnycastConfig::default(),
            recursive: RecursiveDnsConfig::default(),
        }
    }
}

impl Default for DnsRateLimitConfig {
    fn default() -> Self {
        Self {
            mode: DnsRateLimitMode::Shared,
            per_second: default_dns_per_second(),
            per_minute: default_dns_per_minute(),
        }
    }
}

impl Default for DnsSettingsConfig {
    fn default() -> Self {
        Self {
            default_ttl: default_dns_ttl(),
            min_geo_ttl: default_min_geo_ttl(),
            negative_cache_ttl: default_negative_cache_ttl(),
            allow_transfer: Vec::new(),
            cache_enabled: default_cache_enabled(),
            cache_size: default_cache_size(),
            cache_max_ttl: default_cache_max_ttl(),
            cache_min_ttl: default_cache_min_ttl(),
            allow_wildcard_transfer: default_allow_wildcard_transfer(),
            wildcard_transfer_requires_tsig: default_wildcard_transfer_requires_tsig(),
            require_tsig: default_require_tsig(),
            serve_stale: ServeStaleConfig::default(),
            ixfr_history_size: default_ixfr_history_size(),
            ixfr_enabled: default_ixfr_enabled(),
            ixfr_fallback_to_axfr: default_ixfr_fallback_to_axfr(),
            ecs_filtering: EcsFilteringConfig::default(),
            padding: DnsPaddingConfig::default(),
            query_coalescing: QueryCoalescingConfig::default(),
            dynamic_update: DynamicUpdateConfig::default(),
            notify: NotifyConfig::default(),
            qname_privacy: QnamePrivacyConfig::default(),
        }
    }
}

impl Default for EcsFilteringConfig {
    fn default() -> Self {
        Self {
            enabled: default_ecs_enabled(),
            prefix_v4: default_ecs_prefix_v4(),
            prefix_v6: default_ecs_prefix_v6(),
            allow_private_prefix: false,
        }
    }
}

impl Default for DnsMeshConfig {
    fn default() -> Self {
        Self {
            register_to_global: true,
            registration_interval_secs: default_registration_interval(),
            accept_registrations: true,
            sync_interval_secs: default_sync_interval(),
            upstream_dns_servers: default_upstream_dns_servers(),
            verification_retry_interval_secs: default_verification_retry_interval(),
            verification_timeout_secs: default_verification_timeout(),
            qname_minimization: true,
            require_cert_chain_verification: false,
        }
    }
}

impl Default for DnsSecConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            domain: String::new(),
            key_path: default_dnssec_key_path(),
            rollover_interval_days: default_rollover_interval(),
            algorithm: DnsSecAlgorithm::Ed25519,
            rsa_key_size: default_rsa_key_size(),
            ksk_key_size: default_ksk_key_size(),
            nsec3_enabled: default_true(),
            nsec_enabled: false,
            nsec3_iterations: default_nsec3_iterations(),
            nsec3_algorithm: default_nsec3_algorithm(),
            tsig_keys: Vec::new(),
            hsm: HsmConfig::default(),
        }
    }
}

impl DnsConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if self.port == 0 {
            return Err(DnsConfigError::InvalidPort(
                "Port cannot be zero".to_string(),
            ));
        }

        if self.bind_address.parse::<std::net::IpAddr>().is_err()
            && self.bind_address != "0.0.0.0"
            && self.bind_address != "::"
        {
            return Err(DnsConfigError::InvalidBindAddress(format!(
                "Invalid bind address: {}",
                self.bind_address
            )));
        }

        self.ratelimit.validate()?;
        self.rrl.validate()?;
        self.settings.validate()?;
        self.dnssec.validate()?;

        if let DnsMode::Mesh = self.mode {
            self.mesh.validate()?;
        }

        self.anycast.validate()?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum DnsConfigError {
    InvalidPort(String),
    InvalidBindAddress(String),
    InvalidRateLimit(String),
    InvalidRrl(String),
    InvalidSettings(String),
    InvalidDnsSec(String),
    InvalidMesh(String),
    InvalidAnycast(String),
    InvalidRecursive(String),
}

impl std::fmt::Display for DnsConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsConfigError::InvalidPort(msg) => write!(f, "Invalid port: {}", msg),
            DnsConfigError::InvalidBindAddress(msg) => write!(f, "Invalid bind address: {}", msg),
            DnsConfigError::InvalidRateLimit(msg) => write!(f, "Invalid rate limit: {}", msg),
            DnsConfigError::InvalidRrl(msg) => write!(f, "Invalid RRL: {}", msg),
            DnsConfigError::InvalidSettings(msg) => write!(f, "Invalid settings: {}", msg),
            DnsConfigError::InvalidDnsSec(msg) => write!(f, "Invalid DNSSEC: {}", msg),
            DnsConfigError::InvalidMesh(msg) => write!(f, "Invalid mesh: {}", msg),
            DnsConfigError::InvalidAnycast(msg) => write!(f, "Invalid anycast: {}", msg),
            DnsConfigError::InvalidRecursive(msg) => write!(f, "Invalid recursive DNS: {}", msg),
        }
    }
}

impl std::error::Error for DnsConfigError {}

impl DnsRateLimitConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if self.per_second == 0 && self.per_minute == 0 {
            return Err(DnsConfigError::InvalidRateLimit(
                "At least one of per_second or per_minute must be greater than zero".to_string(),
            ));
        }

        if self.per_second > 1000000 {
            return Err(DnsConfigError::InvalidRateLimit(
                "per_second cannot exceed 1000000".to_string(),
            ));
        }

        if self.per_minute > 60000000 {
            return Err(DnsConfigError::InvalidRateLimit(
                "per_minute cannot exceed 60000000".to_string(),
            ));
        }

        Ok(())
    }
}

impl DnsRrlConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if self.enabled {
            if self.responses_per_second == 0 {
                return Err(DnsConfigError::InvalidRrl(
                    "responses_per_second must be greater than zero when enabled".to_string(),
                ));
            }

            if self.window_secs == 0 {
                return Err(DnsConfigError::InvalidRrl(
                    "window_secs must be greater than zero".to_string(),
                ));
            }

            if self.ttl > 86400 {
                return Err(DnsConfigError::InvalidRrl(
                    "ttl cannot exceed 86400 seconds (24 hours)".to_string(),
                ));
            }
        }

        Ok(())
    }
}

impl DnsSettingsConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if self.default_ttl > 86400 {
            return Err(DnsConfigError::InvalidSettings(
                "default_ttl cannot exceed 86400 seconds (24 hours)".to_string(),
            ));
        }

        if self.cache_max_ttl > 604800 {
            return Err(DnsConfigError::InvalidSettings(
                "cache_max_ttl cannot exceed 604800 seconds (7 days)".to_string(),
            ));
        }

        if self.cache_min_ttl > self.cache_max_ttl {
            return Err(DnsConfigError::InvalidSettings(
                "cache_min_ttl cannot be greater than cache_max_ttl".to_string(),
            ));
        }

        if self.cache_size == 0 {
            return Err(DnsConfigError::InvalidSettings(
                "cache_size must be greater than zero".to_string(),
            ));
        }

        Ok(())
    }
}

impl DnsSecConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if self.domain.is_empty() {
            return Err(DnsConfigError::InvalidDnsSec(
                "domain must be specified when DNSSEC is enabled".to_string(),
            ));
        }

        if self.key_path.is_empty() {
            return Err(DnsConfigError::InvalidDnsSec(
                "key_path must be specified when DNSSEC is enabled".to_string(),
            ));
        }

        match self.algorithm {
            DnsSecAlgorithm::RsaSha256 => {
                if self.rsa_key_size < 1024 || self.rsa_key_size > 4096 {
                    return Err(DnsConfigError::InvalidDnsSec(
                        "rsa_key_size must be between 1024 and 4096".to_string(),
                    ));
                }
            }
            DnsSecAlgorithm::Ed25519 => {
                // Ed25519 has no key size requirements
            }
        }

        if self.rollover_interval_days == 0 {
            return Err(DnsConfigError::InvalidDnsSec(
                "rollover_interval_days must be greater than zero".to_string(),
            ));
        }

        if self.nsec3_algorithm != 1 && self.nsec3_algorithm != 2 {
            return Err(DnsConfigError::InvalidDnsSec(
                "nsec3_algorithm must be 1 (SHA-1) or 2 (SHA-256)".to_string(),
            ));
        }

        Ok(())
    }
}

impl DnsMeshConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if self.registration_interval_secs == 0 {
            return Err(DnsConfigError::InvalidMesh(
                "registration_interval_secs must be greater than zero".to_string(),
            ));
        }

        if self.sync_interval_secs == 0 {
            return Err(DnsConfigError::InvalidMesh(
                "sync_interval_secs must be greater than zero".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsAnycastConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub bind_addresses: Vec<String>,

    #[serde(default)]
    pub port: u16,

    #[serde(default)]
    pub use_pktinfo: bool,

    #[serde(default = "default_health_check_domain")]
    pub health_check_domain: String,

    #[serde(default)]
    pub health_check_interval_secs: u64,

    #[serde(default = "default_capacity")]
    pub capacity: u32,

    #[serde(default)]
    pub mesh_based_sync: bool,

    #[serde(default = "default_anycast_sync_interval")]
    pub sync_interval_secs: u64,

    #[serde(default)]
    pub geo: Option<String>,

    #[serde(default = "default_sync_trigger_on_update")]
    pub sync_trigger_on_update: bool,
}

fn default_capacity() -> u32 {
    10000
}

fn default_health_check_domain() -> String {
    "_healthcheck.local".to_string()
}

fn default_anycast_sync_interval() -> u64 {
    300
}

fn default_sync_trigger_on_update() -> bool {
    true
}

impl Default for DnsAnycastConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_addresses: Vec::new(),
            port: 53,
            use_pktinfo: true,
            health_check_domain: default_health_check_domain(),
            health_check_interval_secs: 5,
            capacity: 10000,
            mesh_based_sync: true,
            sync_interval_secs: default_anycast_sync_interval(),
            geo: None,
            sync_trigger_on_update: default_sync_trigger_on_update(),
        }
    }
}

impl DnsAnycastConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if self.bind_addresses.is_empty() {
            return Err(DnsConfigError::InvalidAnycast(
                "bind_addresses cannot be empty when anycast is enabled".to_string(),
            ));
        }

        if self.health_check_interval_secs == 0 {
            return Err(DnsConfigError::InvalidAnycast(
                "health_check_interval_secs must be greater than zero".to_string(),
            ));
        }

        if self.capacity == 0 {
            return Err(DnsConfigError::InvalidAnycast(
                "capacity must be greater than zero".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RecursiveUpstreamProvider {
    #[default]
    System,
    Google,
    Cloudflare,
    Custom,
    Recursive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RecursiveUpstreamServer {
    #[serde(default)]
    pub address: String,

    #[serde(default)]
    pub port: u16,

    #[serde(default)]
    pub ip: Option<std::net::IpAddr>,
}

impl Default for RecursiveUpstreamServer {
    fn default() -> Self {
        Self {
            address: String::new(),
            port: 53,
            ip: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RecursiveCacheConfig {
    #[serde(default = "default_recursive_cache_size")]
    pub capacity: usize,

    #[serde(default = "default_recursive_negative_cache_ttl")]
    pub negative_ttl_secs: u64,

    #[serde(default = "default_recursive_stale_ttl")]
    pub stale_ttl_secs: u64,

    #[serde(default = "default_recursive_max_ttl")]
    pub max_ttl_secs: u64,

    #[serde(default = "default_recursive_min_ttl")]
    pub min_ttl_secs: u64,
}

fn default_recursive_cache_size() -> usize {
    1000000
}

fn default_recursive_negative_cache_ttl() -> u64 {
    300
}

fn default_recursive_stale_ttl() -> u64 {
    86400
}

fn default_recursive_max_ttl() -> u64 {
    86400
}

fn default_recursive_min_ttl() -> u64 {
    0
}

impl Default for RecursiveCacheConfig {
    fn default() -> Self {
        Self {
            capacity: default_recursive_cache_size(),
            negative_ttl_secs: default_recursive_negative_cache_ttl(),
            stale_ttl_secs: default_recursive_stale_ttl(),
            max_ttl_secs: default_recursive_max_ttl(),
            min_ttl_secs: default_recursive_min_ttl(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RecursiveDnsConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_recursive_bind_address")]
    pub bind_address: String,

    #[serde(default = "default_recursive_port")]
    pub port: u16,

    #[serde(default)]
    pub upstream_provider: RecursiveUpstreamProvider,

    #[serde(default)]
    pub upstream_servers: Vec<RecursiveUpstreamServer>,

    #[serde(default)]
    pub cache: RecursiveCacheConfig,

    #[serde(default = "default_recursive_true")]
    pub dnssec_validation: bool,

    #[serde(default = "default_recursive_true")]
    pub qname_minimization: bool,

    #[serde(default = "default_recursive_query_timeout")]
    pub query_timeout_secs: u64,

    #[serde(default = "default_recursive_max_concurrent_queries")]
    pub max_concurrent_queries: usize,

    #[serde(default)]
    pub ratelimit: DnsRateLimitConfig,

    #[serde(default)]
    pub firewall: DnsFirewallConfig,

    #[serde(default = "default_root_hints_path")]
    pub root_hints_path: String,

    #[serde(default = "default_recursive_trust_anchor_path")]
    pub trust_anchor_path: String,
}

fn default_recursive_bind_address() -> String {
    "127.0.0.1".to_string()
}

fn default_recursive_port() -> u16 {
    1053
}

fn default_recursive_true() -> bool {
    true
}

fn default_recursive_query_timeout() -> u64 {
    5
}

fn default_recursive_max_concurrent_queries() -> usize {
    10000
}

fn default_root_hints_path() -> String {
    "root.hints".to_string()
}

fn default_recursive_trust_anchor_path() -> String {
    "trusted-key.key".to_string()
}

impl Default for RecursiveDnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: default_recursive_bind_address(),
            port: default_recursive_port(),
            upstream_provider: RecursiveUpstreamProvider::System,
            upstream_servers: Vec::new(),
            cache: RecursiveCacheConfig::default(),
            dnssec_validation: true,
            qname_minimization: true,
            query_timeout_secs: default_recursive_query_timeout(),
            max_concurrent_queries: default_recursive_max_concurrent_queries(),
            ratelimit: DnsRateLimitConfig::default(),
            firewall: DnsFirewallConfig::default(),
            root_hints_path: default_root_hints_path(),
            trust_anchor_path: default_recursive_trust_anchor_path(),
        }
    }
}

impl RecursiveDnsConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if self.upstream_provider == RecursiveUpstreamProvider::Custom
            && self.upstream_servers.is_empty()
        {
            return Err(DnsConfigError::InvalidRecursive(
                "Custom upstream provider requires at least one upstream server".to_string(),
            ));
        }

        for server in &self.upstream_servers {
            if server.ip.is_none() && server.address.is_empty() {
                return Err(DnsConfigError::InvalidRecursive(
                    "Upstream server must have either an IP address or hostname".to_string(),
                ));
            }
        }

        if self.query_timeout_secs == 0 {
            return Err(DnsConfigError::InvalidRecursive(
                "query_timeout_secs must be greater than zero".to_string(),
            ));
        }

        if self.max_concurrent_queries == 0 {
            return Err(DnsConfigError::InvalidRecursive(
                "max_concurrent_queries must be greater than zero".to_string(),
            ));
        }

        self.ratelimit.validate()?;

        if self.cache.negative_ttl_secs > self.cache.max_ttl_secs {
            return Err(DnsConfigError::InvalidRecursive(
                "negative_ttl_secs cannot exceed max_ttl_secs".to_string(),
            ));
        }

        if self.cache.stale_ttl_secs < self.cache.negative_ttl_secs {
            return Err(DnsConfigError::InvalidRecursive(
                "stale_ttl_secs should be >= negative_ttl_secs for effective negative caching"
                    .to_string(),
            ));
        }

        Ok(())
    }

    pub fn upstream_ips(&self) -> Vec<std::net::IpAddr> {
        let mut ips: Vec<std::net::IpAddr> =
            self.upstream_servers.iter().filter_map(|s| s.ip).collect();

        if ips.is_empty() {
            match self.upstream_provider {
                RecursiveUpstreamProvider::Google => {
                    ips.push(std::net::IpAddr::from([8, 8, 8, 8]));
                    ips.push(std::net::IpAddr::from([8, 8, 4, 4]));
                }
                RecursiveUpstreamProvider::Cloudflare => {
                    ips.push(std::net::IpAddr::from([1, 1, 1, 1]));
                    ips.push(std::net::IpAddr::from([1, 0, 0, 1]));
                }
                _ => {}
            }
        }

        ips
    }
}
