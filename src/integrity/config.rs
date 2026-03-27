//! Configuration for the integrity module

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum IntegrityMode {
    #[default]
    Disabled,
    Audit,
    Enforced,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub mode: IntegrityMode,

    #[serde(default)]
    pub key_exchange_url: Option<String>,

    #[serde(default)]
    pub global_node_domains: Vec<String>,

    #[serde(default = "default_session_ttl_secs")]
    pub session_ttl_secs: u64,

    #[serde(default = "default_session_max")]
    pub max_concurrent_sessions: usize,

    #[serde(default)]
    pub sign_request_headers: Vec<String>,

    #[serde(default)]
    pub sign_response_headers: Vec<String>,

    #[serde(default = "default_true")]
    pub include_body_hash: bool,

    #[serde(default = "default_true")]
    pub include_method: bool,

    #[serde(default = "default_true")]
    pub include_path: bool,

    #[serde(default = "default_true")]
    pub include_query: bool,

    #[serde(default)]
    pub cache_freshness_signed: bool,

    #[serde(default)]
    pub audit_report_url: Option<String>,

    #[serde(default = "default_true")]
    pub verify_on_edge: bool,

    #[serde(default = "default_true")]
    pub allow_unsigned_on_edge_failure: bool,

    #[serde(default)]
    pub audit_pow_enabled: bool,

    #[serde(default = "default_audit_pow_difficulty")]
    pub audit_pow_difficulty: u8,

    #[serde(default = "default_audit_pow_timeout")]
    pub audit_pow_timeout: u64,

    #[serde(default)]
    pub audit_nodes: Vec<String>,

    #[serde(default)]
    pub allowed_upstream_ips: Vec<String>,
}

fn default_true() -> bool {
    true
}

fn default_session_ttl_secs() -> u64 {
    300
}

fn default_session_max() -> usize {
    10000
}

fn default_audit_pow_difficulty() -> u8 {
    2
}

fn default_audit_pow_timeout() -> u64 {
    30000
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: IntegrityMode::Disabled,
            key_exchange_url: None,
            global_node_domains: Vec::new(),
            session_ttl_secs: default_session_ttl_secs(),
            max_concurrent_sessions: default_session_max(),
            sign_request_headers: vec![
                "content-type".to_string(),
                "content-length".to_string(),
                "accept".to_string(),
                "accept-language".to_string(),
            ],
            sign_response_headers: vec![
                "content-type".to_string(),
                "content-length".to_string(),
                "cache-control".to_string(),
                "etag".to_string(),
                "last-modified".to_string(),
            ],
            include_body_hash: true,
            include_method: true,
            include_path: true,
            include_query: true,
            cache_freshness_signed: true,
            audit_report_url: None,
            verify_on_edge: true,
            allow_unsigned_on_edge_failure: true,
            audit_pow_enabled: false,
            audit_pow_difficulty: default_audit_pow_difficulty(),
            audit_pow_timeout: default_audit_pow_timeout(),
            audit_nodes: Vec::new(),
            allowed_upstream_ips: Vec::new(),
        }
    }
}

impl IntegrityConfig {
    pub fn is_enabled(&self) -> bool {
        self.enabled && self.mode != IntegrityMode::Disabled
    }

    pub fn is_audit_only(&self) -> bool {
        self.enabled && self.mode == IntegrityMode::Audit
    }

    pub fn is_enforced(&self) -> bool {
        self.enabled && self.mode == IntegrityMode::Enforced
    }

    pub fn to_header_value(
        &self,
        edge_node_id: &str,
        mesh_id: &str,
        pow_challenge: Option<String>,
    ) -> Option<String> {
        if !self.enabled {
            return None;
        }

        let mut config = serde_json::Map::new();

        if let Some(ref url) = self.key_exchange_url {
            config.insert(
                "key_exchange_url".to_string(),
                serde_json::Value::String(url.clone()),
            );
        }

        config.insert(
            "mesh_id".to_string(),
            serde_json::Value::String(mesh_id.to_string()),
        );

        if let Some(ref audit_url) = self.audit_report_url {
            if !audit_url.is_empty() {
                config.insert(
                    "audit_report_url".to_string(),
                    serde_json::Value::String(audit_url.clone()),
                );
            }
        }

        if self.audit_pow_enabled {
            config.insert(
                "audit_pow_required".to_string(),
                serde_json::Value::Bool(true),
            );
            config.insert(
                "audit_pow_difficulty".to_string(),
                serde_json::Value::Number(serde_json::Number::from(self.audit_pow_difficulty)),
            );
            config.insert(
                "audit_pow_timeout".to_string(),
                serde_json::Value::Number(serde_json::Number::from(self.audit_pow_timeout)),
            );
        }

        if let Some(challenge) = pow_challenge {
            config.insert(
                "audit_pow_challenge".to_string(),
                serde_json::Value::String(challenge),
            );
        }

        if !self.audit_nodes.is_empty() {
            config.insert(
                "audit_nodes".to_string(),
                serde_json::to_value(&self.audit_nodes).ok()?,
            );
        }

        if !self.allowed_upstream_ips.is_empty() {
            config.insert(
                "allowed_upstream_ips".to_string(),
                serde_json::to_value(&self.allowed_upstream_ips).ok()?,
            );
        }

        config.insert(
            "edge_node_id".to_string(),
            serde_json::Value::String(edge_node_id.to_string()),
        );

        serde_json::to_string(&config).ok()
    }
}
