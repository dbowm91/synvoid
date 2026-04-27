use crate::config::RuleFeedConfig;
use crate::http_client::{create_simple_http_client, get_with_timeout, HttpClient};
use crate::utils::is_newer_version;
use base64::Engine;
use chrono::DateTime;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use std::sync::LazyLock;

/// Default embedded Ed25519 public key for rule feed signature verification.
///
/// Deployments MUST replace this placeholder with a real base64-encoded
/// 32-byte Ed25519 public key matching the private key used to sign rule feeds.
///
/// To generate a key pair:
///   ed25519-dalek: SigningKey::generate(&mut rand::rng())
///
/// Configure via `waf.rule_feed.public_key` in the TOML config, or set the
/// MALUWAF_RULE_FEED_PUBLIC_KEY environment variable.
///
/// If this placeholder remains, a random key is generated at startup and all
/// rule feed signature verifications will fail (rules will not be applied).
const EMBEDDED_PUBLIC_KEY: &str = "DEFAULT_EMBEDDED_PUBLIC_KEY_PLACEHOLDER";

const PLACEHOLDER_KEY: &str = "DEFAULT_EMBEDDED_PUBLIC_KEY_PLACEHOLDER";

static RULE_PATTERN_STORE: LazyLock<RwLock<GlobalRulePatterns>> =
    LazyLock::new(|| RwLock::new(GlobalRulePatterns::default()));

#[derive(Default, Clone)]
pub struct GlobalRulePatterns {
    pub sqli: Option<Vec<String>>,
    pub xss: Option<Vec<String>>,
    pub cmd_injection: Option<Vec<String>>,
    pub path_traversal: Option<Vec<String>>,
    pub ssrf: Option<Vec<String>>,
    pub ssti: Option<Vec<String>>,
    pub open_redirect: Option<Vec<String>>,
    pub xxe: Option<Vec<String>>,
    pub rfi: Option<Vec<String>>,
    pub ldap_injection: Option<Vec<String>>,
    pub xpath_injection: Option<Vec<String>>,
    pub jwt: Option<Vec<String>>,
}

impl GlobalRulePatterns {
    pub fn update_from_rule_set(&mut self, rules: &RuleSet) {
        if let Some(ref sqli) = rules.sqli {
            if let Some(ref patterns) = sqli.patterns {
                self.sqli = Some(patterns.clone());
            }
        }
        if let Some(ref xss) = rules.xss {
            if let Some(ref patterns) = xss.patterns {
                self.xss = Some(patterns.clone());
            }
        }
        if let Some(ref cmd) = rules.cmd_injection {
            if let Some(ref patterns) = cmd.patterns {
                self.cmd_injection = Some(patterns.clone());
            }
        }
        if let Some(ref pt) = rules.path_traversal {
            if let Some(ref patterns) = pt.patterns {
                self.path_traversal = Some(patterns.clone());
            }
        }
        if let Some(ref ssrf) = rules.ssrf {
            if let Some(ref patterns) = ssrf.patterns {
                self.ssrf = Some(patterns.clone());
            }
        }
        if let Some(ref ssti) = rules.ssti {
            if let Some(ref patterns) = ssti.patterns {
                self.ssti = Some(patterns.clone());
            }
        }
        if let Some(ref or) = rules.open_redirect {
            if let Some(ref patterns) = or.patterns {
                self.open_redirect = Some(patterns.clone());
            }
        }
        if let Some(ref xxe) = rules.xxe {
            if let Some(ref patterns) = xxe.patterns {
                self.xxe = Some(patterns.clone());
            }
        }
        if let Some(ref rfi) = rules.rfi {
            if let Some(ref patterns) = rfi.patterns {
                self.rfi = Some(patterns.clone());
            }
        }
        if let Some(ref ldap) = rules.ldap_injection {
            if let Some(ref patterns) = ldap.patterns {
                self.ldap_injection = Some(patterns.clone());
            }
        }
        if let Some(ref xpath) = rules.xpath_injection {
            if let Some(ref patterns) = xpath.patterns {
                self.xpath_injection = Some(patterns.clone());
            }
        }
        if let Some(ref jwt) = rules.jwt {
            if let Some(ref patterns) = jwt.patterns {
                self.jwt = Some(patterns.clone());
            }
        }
    }
}

pub fn get_global_patterns() -> GlobalRulePatterns {
    RULE_PATTERN_STORE.read().clone()
}

pub fn clear_global_patterns() {
    *RULE_PATTERN_STORE.write() = GlobalRulePatterns::default();
}

pub fn update_patterns_for_category(category: &str, patterns: Vec<String>) {
    let mut store = RULE_PATTERN_STORE.write();
    macro_rules! set_cat {
        ($name:expr, $field:ident) => {
            if category == $name {
                store.$field = Some(patterns);
                return;
            }
        };
    }
    set_cat!("sqli", sqli);
    set_cat!("xss", xss);
    set_cat!("cmd_injection", cmd_injection);
    set_cat!("path_traversal", path_traversal);
    set_cat!("ssrf", ssrf);
    set_cat!("ssti", ssti);
    set_cat!("open_redirect", open_redirect);
    set_cat!("xxe", xxe);
    set_cat!("rfi", rfi);
    set_cat!("ldap_injection", ldap_injection);
    set_cat!("xpath_injection", xpath_injection);
    set_cat!("jwt", jwt);
}

pub fn get_custom_patterns_for_category(category: &str) -> Vec<String> {
    let patterns = RULE_PATTERN_STORE.read();
    macro_rules! get_cat {
        ($name:expr, $field:ident) => {
            if category == $name {
                return patterns.$field.clone().unwrap_or_default();
            }
        };
    }
    get_cat!("sqli", sqli);
    get_cat!("xss", xss);
    get_cat!("cmd_injection", cmd_injection);
    get_cat!("path_traversal", path_traversal);
    get_cat!("ssrf", ssrf);
    get_cat!("ssti", ssti);
    get_cat!("open_redirect", open_redirect);
    get_cat!("xxe", xxe);
    get_cat!("rfi", rfi);
    get_cat!("ldap_injection", ldap_injection);
    get_cat!("xpath_injection", xpath_injection);
    get_cat!("jwt", jwt);
    Vec::new()
}

pub fn get_merged_patterns(
    category: &str,
    default_patterns: &[&'static str],
    config_custom: &[String],
) -> Vec<String> {
    let mut result: Vec<String> = default_patterns.iter().map(|s| s.to_string()).collect();

    result.extend(config_custom.iter().cloned());

    let feed_patterns = get_custom_patterns_for_category(category);
    result.extend(feed_patterns.iter().cloned());

    result
}

pub fn has_custom_patterns(category: &str) -> bool {
    let patterns = RULE_PATTERN_STORE.read();
    macro_rules! has_cat {
        ($name:expr, $field:ident) => {
            if category == $name {
                return patterns.$field.is_some();
            }
        };
    }
    has_cat!("sqli", sqli);
    has_cat!("xss", xss);
    has_cat!("cmd_injection", cmd_injection);
    has_cat!("path_traversal", path_traversal);
    has_cat!("ssrf", ssrf);
    has_cat!("ssti", ssti);
    has_cat!("open_redirect", open_redirect);
    has_cat!("xxe", xxe);
    has_cat!("rfi", rfi);
    has_cat!("ldap_injection", ldap_injection);
    has_cat!("xpath_injection", xpath_injection);
    has_cat!("jwt", jwt);
    false
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFeedResponse {
    pub version: String,
    #[serde(default)]
    pub previous_version: Option<String>,
    pub timestamp: String,
    pub signature: String,
    pub rules: RuleSet,
    #[serde(default)]
    pub changelog: Vec<ChangelogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleSet {
    #[serde(default)]
    pub sqli: Option<RuleCategory>,
    #[serde(default)]
    pub xss: Option<RuleCategory>,
    #[serde(default)]
    pub cmd_injection: Option<RuleCategory>,
    #[serde(default)]
    pub path_traversal: Option<RuleCategory>,
    #[serde(default)]
    pub ssrf: Option<RuleCategory>,
    #[serde(default)]
    pub ssti: Option<RuleCategory>,
    #[serde(default)]
    pub open_redirect: Option<RuleCategory>,
    #[serde(default)]
    pub xxe: Option<RuleCategory>,
    #[serde(default)]
    pub rfi: Option<RuleCategory>,
    #[serde(default)]
    pub ldap_injection: Option<RuleCategory>,
    #[serde(default)]
    pub xpath_injection: Option<RuleCategory>,
    #[serde(default)]
    pub jwt: Option<RuleCategory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCategory {
    pub enabled: bool,
    #[serde(default)]
    pub threshold: Option<u32>,
    #[serde(default)]
    pub patterns: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangelogEntry {
    #[serde(rename = "type")]
    pub entry_type: String,
    #[serde(default)]
    pub rule: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedRules {
    pub version: String,
    pub timestamp: u64,
    pub rules: RuleSet,
    pub changelog: Vec<ChangelogEntry>,
}

pub struct RuleFeedManager {
    pub(crate) config: RuleFeedConfig,
    client: HttpClient,
    current_version: Arc<RwLock<Option<String>>>,
    pub(crate) downloaded_rules: Arc<RwLock<Option<ParsedRules>>>,
    last_update: Arc<RwLock<u64>>,
    last_check: Arc<RwLock<u64>>,
    embedded_public_key: VerifyingKey,
    #[allow(clippy::type_complexity)]
    pub(crate) on_apply_callback: Arc<
        RwLock<
            Option<Box<dyn Fn(String, Vec<crate::process::ipc::RulePatternData>) + Send + Sync>>,
        >,
    >,
}

impl RuleFeedManager {
    pub fn new(config: RuleFeedConfig) -> Result<Arc<Self>, String> {
        let embedded_public_key = config
            .public_key
            .as_deref()
            .filter(|k| !k.is_empty())
            .map(Self::parse_embedded_key)
            .transpose()?
            .unwrap_or_else(|| {
                Self::parse_embedded_key(EMBEDDED_PUBLIC_KEY).expect("Invalid embedded key")
            });

        let manager = Arc::new(Self {
            config,
            client: create_simple_http_client(Duration::from_secs(30)),
            current_version: Arc::new(RwLock::new(None)),
            downloaded_rules: Arc::new(RwLock::new(None)),
            last_update: Arc::new(RwLock::new(0)),
            last_check: Arc::new(RwLock::new(0)),
            embedded_public_key,
            on_apply_callback: Arc::new(RwLock::new(None)),
        });

        // Try to load rules from disk on startup
        if let Err(e) = manager.load_from_disk() {
            tracing::debug!("No existing rules loaded from disk: {}", e);
        }

        Ok(manager)
    }

    pub fn save_to_disk(&self, rules: &ParsedRules) -> Result<(), String> {
        let Some(ref storage_dir) = self.config.storage_dir else {
            return Ok(());
        };

        let dir = Path::new(storage_dir);
        if !dir.exists() {
            fs::create_dir_all(dir).map_err(|e| format!("Failed to create storage dir: {}", e))?;
        }

        let file_path = dir.join("rules.json");

        let json = serde_json::to_string_pretty(rules)
            .map_err(|e| format!("Failed to serialize rules: {}", e))?;

        fs::write(file_path, json).map_err(|e| format!("Failed to write rules to disk: {}", e))?;

        Ok(())
    }

    pub fn load_from_disk(&self) -> Result<(), String> {
        let Some(ref storage_dir) = self.config.storage_dir else {
            return Err("No storage directory configured".to_string());
        };

        let file_path = Path::new(storage_dir).join("rules.json");
        if !file_path.exists() {
            return Err("Rules file not found".to_string());
        }

        let json =
            fs::read_to_string(file_path).map_err(|e| format!("Failed to read rules: {}", e))?;
        let rules: ParsedRules =
            serde_json::from_str(&json).map_err(|e| format!("Failed to parse rules: {}", e))?;

        // Apply loaded rules
        apply_rule_set_to_detection(&rules.rules);

        *self.current_version.write() = Some(rules.version.clone());
        *self.last_update.write() = rules.timestamp;

        tracing::info!(
            "Loaded rule version {} from disk persistence",
            rules.version
        );

        Ok(())
    }

    pub fn set_on_apply_callback<F>(&self, callback: F)
    where
        F: Fn(String, Vec<crate::process::ipc::RulePatternData>) + Send + Sync + 'static,
    {
        *self.on_apply_callback.write() = Some(Box::new(callback));
    }

    fn parse_embedded_key(key_str: &str) -> Result<VerifyingKey, String> {
        if key_str == PLACEHOLDER_KEY {
            return Err(
                "RULE FEED SECURITY VIOLATION: Public key still set to placeholder value. \
                 Set [waf.rule_feed.public_key] in the TOML config to a valid \
                 base64-encoded 32-byte Ed25519 verifying key. Refusing to start with \
                 insecure default."
                    .to_string(),
            );
        }

        // If a real base64-encoded 32-byte Ed25519 public key is provided, use it
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(key_str) {
            if bytes.len() == 32 {
                if let Ok(key) =
                    VerifyingKey::from_bytes(bytes[..32].try_into().expect("Invalid key length"))
                {
                    return Ok(key);
                }
            }
        }

        Err(
            "RULE FEED SECURITY VIOLATION: No valid embedded Ed25519 public key configured. \
             Set [waf.rule_feed.public_key] in the TOML config to a base64-encoded \
             32-byte Ed25519 verifying key. Refusing to start."
                .to_string(),
        )
    }

    pub fn start_background_fetching(self: &Arc<Self>) {
        if !self.config.enabled {
            tracing::info!("Rule feed is disabled");
            return;
        }

        let self_clone = Arc::clone(self);

        tokio::spawn(async move {
            loop {
                self_clone.check_and_fetch().await;

                let interval =
                    Duration::from_secs(self_clone.config.update_interval_hours as u64 * 3600);
                tokio::time::sleep(interval).await;
            }
        });
    }

    pub async fn check_and_fetch(&self) {
        *self.last_check.write() = now_timestamp();

        tracing::info!("Checking for rule updates from {}", self.config.url);

        match self.fetch_rules(&self.config.url).await {
            Ok(rules) => {
                let current = self.current_version.read().clone();
                let current_str = current.as_deref().unwrap_or("none");

                if !self.config.allow_downgrade && !is_newer_version(&rules.version, current_str) {
                    tracing::info!(
                        "Rule version {} is not newer than current {}",
                        rules.version,
                        current_str
                    );
                    return;
                }

                tracing::info!("Fetched new rules version {}", rules.version);
                *self.downloaded_rules.write() = Some(rules.clone());

                if self.config.auto_apply && self.apply_rules().is_ok() {
                    *self.current_version.write() = Some(rules.version.clone());
                    *self.last_update.write() = now_timestamp();

                    // Persist to disk
                    if let Err(e) = self.save_to_disk(&rules) {
                        tracing::warn!("Failed to persist rules to disk: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to fetch rule feed: {}", e);
            }
        }
    }

    async fn fetch_rules(&self, url: &str) -> Result<ParsedRules, String> {
        let response = get_with_timeout(&self.client, url, Duration::from_secs(30))
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        if !response.status.is_success() {
            return Err(format!("HTTP error: {}", response.status));
        }

        let body_str = String::from_utf8_lossy(&response.body);
        let feed_response: RuleFeedResponse =
            serde_json::from_str(&body_str).map_err(|e| format!("Failed to parse JSON: {}", e))?;

        let timestamp = Self::parse_timestamp(&feed_response.timestamp)
            .map_err(|e| format!("Invalid timestamp: {}", e))?;

        let payload_for_sig = Self::create_payload_for_signature(&feed_response);

        self.verify_signature(&payload_for_sig, &feed_response.signature)?;

        let parsed = ParsedRules {
            version: feed_response.version,
            timestamp,
            rules: feed_response.rules,
            changelog: feed_response.changelog,
        };

        Ok(parsed)
    }

    fn parse_timestamp(ts: &str) -> Result<u64, String> {
        if let Ok(dt) = DateTime::parse_from_rfc3339(ts) {
            return Ok(dt.timestamp() as u64);
        }

        if let Ok(t) = ts.parse::<u64>() {
            return Ok(t);
        }

        Err("Invalid timestamp format".to_string())
    }

    fn create_payload_for_signature(response: &RuleFeedResponse) -> String {
        let mut sig_payload = response.clone();
        sig_payload.signature = String::new();
        serde_json::to_string(&sig_payload).unwrap_or_default()
    }

    fn verify_signature(&self, payload: &str, signature_b64: &str) -> Result<(), String> {
        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(signature_b64)
            .map_err(|e| format!("Invalid signature encoding: {}", e))?;

        if signature_bytes.len() != 64 {
            return Err(format!(
                "Invalid signature length: {}",
                signature_bytes.len()
            ));
        }

        let signature = Ed25519Signature::from_slice(&signature_bytes)
            .map_err(|e| format!("Invalid signature: {}", e))?;

        let payload_bytes = payload.as_bytes();

        if self
            .embedded_public_key
            .verify(payload_bytes, &signature)
            .is_err()
        {
            return Err("Signature verification failed".to_string());
        }

        Ok(())
    }

    pub fn apply_rules(&self) -> Result<(), String> {
        let rules = self.downloaded_rules.read();
        let rules = rules.as_ref().ok_or("No rules downloaded")?;

        apply_rule_set_to_detection(&rules.rules);

        tracing::info!("Applied rule version {}", rules.version);

        // Call the broadcast callback if set
        if let Some(ref callback) = *self.on_apply_callback.read() {
            let patterns = convert_rules_to_ipc_patterns(&rules.rules);
            callback(rules.version.clone(), patterns);
        }

        Ok(())
    }

    pub fn get_current_version(&self) -> Option<String> {
        self.current_version.read().clone()
    }

    pub fn get_last_update(&self) -> u64 {
        *self.last_update.read()
    }

    pub fn get_last_check(&self) -> u64 {
        *self.last_check.read()
    }

    pub fn has_pending_update(&self) -> bool {
        self.downloaded_rules.read().is_some()
    }

    pub fn discard_pending(&self) {
        *self.downloaded_rules.write() = None;
    }
}

fn now_timestamp() -> u64 {
    crate::utils::safe_unix_timestamp()
}

fn apply_rule_set_to_detection(rules: &RuleSet) {
    let mut global_patterns = RULE_PATTERN_STORE.write();
    global_patterns.update_from_rule_set(rules);

    tracing::debug!("Updated global pattern store");

    if let Some(ref sqli) = rules.sqli {
        tracing::debug!("Applying SQLi rules: enabled={}", sqli.enabled);
    }
    if let Some(ref xss) = rules.xss {
        tracing::debug!("Applying XSS rules: enabled={}", xss.enabled);
    }
    if let Some(ref cmd) = rules.cmd_injection {
        tracing::debug!("Applying cmd_injection rules: enabled={}", cmd.enabled);
    }
    if let Some(ref pt) = rules.path_traversal {
        tracing::debug!("Applying path_traversal rules: enabled={}", pt.enabled);
    }
    if let Some(ref ssrf) = rules.ssrf {
        tracing::debug!("Applying ssrf rules: enabled={}", ssrf.enabled);
    }
    if let Some(ref ssti) = rules.ssti {
        tracing::debug!("Applying ssti rules: enabled={}", ssti.enabled);
    }
    if let Some(ref or) = rules.open_redirect {
        tracing::debug!("Applying open_redirect rules: enabled={}", or.enabled);
    }
}

pub struct RuleFeedManagerForWaf {
    pub(crate) inner: Arc<RuleFeedManager>,
}

impl RuleFeedManagerForWaf {
    pub fn set_on_apply_callback<F>(&self, callback: F)
    where
        F: Fn(String, Vec<crate::process::ipc::RulePatternData>) + Send + Sync + 'static,
    {
        self.inner.set_on_apply_callback(callback);
    }
}

fn convert_rules_to_ipc_patterns(rules: &RuleSet) -> Vec<crate::process::ipc::RulePatternData> {
    let mut patterns = Vec::new();

    macro_rules! push_if_present {
        ($field:ident, $category:expr) => {
            if let Some(ref rule) = rules.$field {
                if let Some(ref p) = rule.patterns {
                    patterns.push(crate::process::ipc::RulePatternData {
                        category: $category.to_string(),
                        patterns: p.clone(),
                    });
                }
            }
        };
    }

    push_if_present!(sqli, "sqli");
    push_if_present!(xss, "xss");
    push_if_present!(path_traversal, "path_traversal");
    push_if_present!(rfi, "rfi");
    push_if_present!(ssrf, "ssrf");
    push_if_present!(ssti, "ssti");
    push_if_present!(cmd_injection, "cmd_injection");
    push_if_present!(xxe, "xxe");
    push_if_present!(jwt, "jwt");
    push_if_present!(ldap_injection, "ldap_injection");
    push_if_present!(xpath_injection, "xpath_injection");
    push_if_present!(open_redirect, "open_redirect");

    patterns
}

impl RuleFeedManagerForWaf {
    pub fn new(config: RuleFeedConfig) -> Result<Arc<Self>, String> {
        Ok(Arc::new(Self {
            inner: RuleFeedManager::new(config)?,
        }))
    }

    pub fn start_background_fetching(self: &Arc<Self>) {
        self.inner.start_background_fetching();
    }

    pub fn get_current_version(&self) -> Option<String> {
        self.inner.get_current_version()
    }

    pub fn get_last_update(&self) -> u64 {
        self.inner.get_last_update()
    }

    pub fn get_last_check(&self) -> u64 {
        self.inner.get_last_check()
    }

    pub fn has_pending_update(&self) -> bool {
        self.inner.has_pending_update()
    }

    pub async fn check_for_updates(&self) -> Result<Option<String>, String> {
        self.inner.check_and_fetch().await;
        Ok(self.inner.get_current_version())
    }

    pub fn apply_pending(&self) -> Result<(), String> {
        self.inner.apply_rules()
    }

    pub fn discard_pending(&self) {
        self.inner.discard_pending();
    }

    pub fn get_changelog(&self) -> Vec<ChangelogEntry> {
        let rules = self.inner.downloaded_rules.read();
        rules
            .as_ref()
            .map(|r| r.changelog.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_newer_version_basic() {
        assert!(crate::utils::is_newer_version("2.0.0", "1.0.0"));
        assert!(crate::utils::is_newer_version("1.1.0", "1.0.0"));
        assert!(crate::utils::is_newer_version("1.0.1", "1.0.0"));
        assert!(!crate::utils::is_newer_version("1.0.0", "2.0.0"));
        assert!(!crate::utils::is_newer_version("1.0.0", "1.1.0"));
        assert!(!crate::utils::is_newer_version("1.0.0", "1.0.1"));
    }

    #[test]
    fn test_is_newer_version_equal() {
        assert!(!crate::utils::is_newer_version("1.0.0", "1.0.0"));
    }

    #[test]
    fn test_is_newer_version_from_none() {
        assert!(crate::utils::is_newer_version("0.0.1", "none"));
        assert!(crate::utils::is_newer_version("10.0.0", "none"));
    }

    #[test]
    fn test_is_newer_version_different_lengths() {
        assert!(crate::utils::is_newer_version("1.0.0.1", "1.0.0"));
        assert!(crate::utils::is_newer_version("2.0", "1.9.9"));
        assert!(!crate::utils::is_newer_version("1.0", "1.0.1"));
    }

    #[test]
    fn test_base64_decode_valid() {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode("SGVsbG8=")
            .unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_base64_decode_no_padding() {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode("SGVsbG8gV29ybGQ=")
            .unwrap();
        assert_eq!(decoded, b"Hello World");
    }

    #[test]
    fn test_base64_decode_invalid_char() {
        assert!(base64::engine::general_purpose::STANDARD
            .decode("!invalid!")
            .is_err());
    }

    #[test]
    fn test_base64_decode_with_newlines() {
        let input = "SGVs\nbG8="
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(input)
            .unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_parse_timestamp_rfc3339() {
        let ts = RuleFeedManager::parse_timestamp("2025-01-15T12:00:00Z").unwrap();
        assert!(ts > 0);
    }

    #[test]
    fn test_parse_timestamp_unix() {
        let ts = RuleFeedManager::parse_timestamp("1700000000").unwrap();
        assert_eq!(ts, 1700000000);
    }

    #[test]
    fn test_parse_timestamp_invalid() {
        assert!(RuleFeedManager::parse_timestamp("not-a-timestamp").is_err());
    }

    #[test]
    fn test_convert_rules_to_ipc_patterns_roundtrip() {
        let rules = RuleSet {
            sqli: Some(RuleCategory {
                enabled: true,
                threshold: Some(5),
                patterns: Some(vec!["' OR 1=1".to_string(), "UNION SELECT".to_string()]),
            }),
            xss: Some(RuleCategory {
                enabled: true,
                threshold: Some(3),
                patterns: Some(vec!["<script>".to_string()]),
            }),
            cmd_injection: None,
            path_traversal: None,
            ssrf: None,
            ssti: None,
            open_redirect: None,
            xxe: None,
            rfi: None,
            ldap_injection: None,
            xpath_injection: None,
            jwt: None,
        };

        let ipc_patterns = convert_rules_to_ipc_patterns(&rules);
        assert_eq!(ipc_patterns.len(), 2);

        let sqli = ipc_patterns.iter().find(|p| p.category == "sqli").unwrap();
        assert_eq!(sqli.patterns, vec!["' OR 1=1", "UNION SELECT"]);

        let xss = ipc_patterns.iter().find(|p| p.category == "xss").unwrap();
        assert_eq!(xss.patterns, vec!["<script>"]);
    }

    #[test]
    fn test_convert_rules_to_ipc_patterns_empty() {
        let rules = RuleSet::default();
        let ipc_patterns = convert_rules_to_ipc_patterns(&rules);
        assert!(ipc_patterns.is_empty());
    }

    #[test]
    fn test_global_rule_patterns_update_from_rule_set() {
        let mut patterns = GlobalRulePatterns::default();
        let rules = RuleSet {
            sqli: Some(RuleCategory {
                enabled: true,
                threshold: None,
                patterns: Some(vec!["pat1".to_string(), "pat2".to_string()]),
            }),
            ..RuleSet::default()
        };
        patterns.update_from_rule_set(&rules);
        assert_eq!(
            patterns.sqli,
            Some(vec!["pat1".to_string(), "pat2".to_string()])
        );
        assert!(patterns.xss.is_none());
    }

    #[test]
    fn test_global_rule_patterns_update_preserves_none() {
        let mut patterns = GlobalRulePatterns::default();
        let rules = RuleSet {
            sqli: Some(RuleCategory {
                enabled: true,
                threshold: None,
                patterns: None, // no patterns, should set to None
            }),
            ..RuleSet::default()
        };
        patterns.update_from_rule_set(&rules);
        assert!(patterns.sqli.is_none());
    }

    #[test]
    fn test_update_and_get_custom_patterns() {
        clear_global_patterns();

        update_patterns_for_category("sqli", vec!["custom1".to_string()]);
        assert!(has_custom_patterns("sqli"));
        assert!(!has_custom_patterns("xss"));

        let retrieved = get_custom_patterns_for_category("sqli");
        assert_eq!(retrieved, vec!["custom1"]);

        let empty = get_custom_patterns_for_category("xss");
        assert!(empty.is_empty());

        clear_global_patterns();
        assert!(!has_custom_patterns("sqli"));
    }

    #[test]
    fn test_get_merged_patterns() {
        clear_global_patterns();
        update_patterns_for_category("sqli", vec!["feed_pattern".to_string()]);

        let defaults = vec!["default1", "default2"];
        let config_custom = vec!["config1".to_string()];
        let merged = get_merged_patterns("sqli", &defaults, &config_custom);

        assert!(merged.contains(&"default1".to_string()));
        assert!(merged.contains(&"default2".to_string()));
        assert!(merged.contains(&"config1".to_string()));
        assert!(merged.contains(&"feed_pattern".to_string()));

        clear_global_patterns();
    }

    #[test]
    fn test_parse_embedded_key_invalid() {
        let result = RuleFeedManager::parse_embedded_key("DEFAULT_EMBEDDED_PUBLIC_KEY_PLACEHOLDER");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("RULE FEED SECURITY VIOLATION"));
    }

    #[test]
    fn test_parse_embedded_key_valid_base64() {
        // Generate a real Ed25519 key, encode as base64, and verify parse works
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let key_bytes = verifying_key.as_bytes();

        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(key_bytes);

        let parsed = RuleFeedManager::parse_embedded_key(&encoded).unwrap();
        assert_eq!(parsed.as_bytes(), verifying_key.as_bytes());
    }

    #[test]
    fn test_create_payload_for_signature() {
        let response = RuleFeedResponse {
            version: "1.0.0".to_string(),
            previous_version: None,
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            signature: "somesig".to_string(),
            rules: RuleSet::default(),
            changelog: vec![],
        };
        let payload = RuleFeedManager::create_payload_for_signature(&response);
        // Signature field should be empty in payload
        assert!(payload.contains(r#""signature":""#));
        assert!(payload.contains(r#""version":"1.0.0""#));
        // Original signature should NOT be in payload
        assert!(!payload.contains("somesig"));
    }

    #[test]
    fn test_multi_category_pattern_merge() {
        // This tests the same merge logic used by reload_attack_detector
        clear_global_patterns();

        // Simulate patterns from rule feed for multiple categories
        update_patterns_for_category("path_traversal", vec!["../custom_traversal".to_string()]);
        update_patterns_for_category("rfi", vec!["evil_include".to_string()]);
        update_patterns_for_category("cmd_injection", vec!["; custom_cmd".to_string()]);
        // ssti and xxe have no feed patterns
        assert!(has_custom_patterns("path_traversal"));
        assert!(has_custom_patterns("rfi"));
        assert!(has_custom_patterns("cmd_injection"));
        assert!(!has_custom_patterns("ssti"));
        assert!(!has_custom_patterns("xxe"));

        // Simulate the merge that reload_attack_detector does
        let categories = [
            ("path_traversal", vec!["config_traversal".to_string()]),
            ("rfi", vec!["config_rfi".to_string()]),
            ("cmd_injection", vec![]),
            ("ssti", vec!["config_ssti".to_string()]),
            ("xxe", vec![]),
        ];

        for (category, config_patterns) in &categories {
            let feed_patterns = get_custom_patterns_for_category(category);
            let mut merged = config_patterns.clone();
            merged.extend(feed_patterns);

            match *category {
                "path_traversal" => {
                    assert!(merged.contains(&"config_traversal".to_string()));
                    assert!(merged.contains(&"../custom_traversal".to_string()));
                }
                "rfi" => {
                    assert!(merged.contains(&"config_rfi".to_string()));
                    assert!(merged.contains(&"evil_include".to_string()));
                }
                "cmd_injection" => {
                    assert!(merged.contains(&"; custom_cmd".to_string()));
                    assert_eq!(merged.len(), 1); // config was empty, only feed
                }
                "ssti" => {
                    assert!(merged.contains(&"config_ssti".to_string()));
                    assert_eq!(merged.len(), 1); // no feed patterns
                }
                "xxe" => {
                    assert!(merged.is_empty()); // neither config nor feed
                }
                _ => {}
            }
        }

        clear_global_patterns();
    }
}
