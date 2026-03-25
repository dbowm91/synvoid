use crate::config::RuleFeedConfig;
use crate::http_client::{HttpClient, get_with_timeout, create_simple_http_client};
use chrono::DateTime;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const EMBEDDED_PUBLIC_KEY: &str = "DEFAULT_EMBEDDED_PUBLIC_KEY_PLACEHOLDER";

static RULE_PATTERN_STORE: once_cell::sync::Lazy<RwLock<GlobalRulePatterns>> = 
    once_cell::sync::Lazy::new(|| RwLock::new(GlobalRulePatterns::default()));

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
    match category {
        "sqli" => store.sqli = Some(patterns),
        "xss" => store.xss = Some(patterns),
        "cmd_injection" => store.cmd_injection = Some(patterns),
        "path_traversal" => store.path_traversal = Some(patterns),
        "ssrf" => store.ssrf = Some(patterns),
        "ssti" => store.ssti = Some(patterns),
        "open_redirect" => store.open_redirect = Some(patterns),
        "xxe" => store.xxe = Some(patterns),
        "rfi" => store.rfi = Some(patterns),
        "ldap_injection" => store.ldap_injection = Some(patterns),
        "xpath_injection" => store.xpath_injection = Some(patterns),
        "jwt" => store.jwt = Some(patterns),
        _ => {}
    }
}

pub fn get_custom_patterns_for_category(category: &str) -> Vec<String> {
    let patterns = RULE_PATTERN_STORE.read();
    match category {
        "sqli" => patterns.sqli.clone().unwrap_or_default(),
        "xss" => patterns.xss.clone().unwrap_or_default(),
        "cmd_injection" => patterns.cmd_injection.clone().unwrap_or_default(),
        "path_traversal" => patterns.path_traversal.clone().unwrap_or_default(),
        "ssrf" => patterns.ssrf.clone().unwrap_or_default(),
        "ssti" => patterns.ssti.clone().unwrap_or_default(),
        "open_redirect" => patterns.open_redirect.clone().unwrap_or_default(),
        "xxe" => patterns.xxe.clone().unwrap_or_default(),
        "rfi" => patterns.rfi.clone().unwrap_or_default(),
        "ldap_injection" => patterns.ldap_injection.clone().unwrap_or_default(),
        "xpath_injection" => patterns.xpath_injection.clone().unwrap_or_default(),
        "jwt" => patterns.jwt.clone().unwrap_or_default(),
        _ => Vec::new(),
    }
}

pub fn get_merged_patterns(category: &str, default_patterns: &[&'static str], config_custom: &[String]) -> Vec<String> {
    let mut result: Vec<String> = default_patterns.iter().map(|s| s.to_string()).collect();
    
    result.extend(config_custom.iter().cloned());
    
    let feed_patterns = get_custom_patterns_for_category(category);
    result.extend(feed_patterns.iter().cloned());
    
    result
}

pub fn has_custom_patterns(category: &str) -> bool {
    let patterns = RULE_PATTERN_STORE.read();
    match category {
        "sqli" => patterns.sqli.is_some(),
        "xss" => patterns.xss.is_some(),
        "cmd_injection" => patterns.cmd_injection.is_some(),
        "path_traversal" => patterns.path_traversal.is_some(),
        "ssrf" => patterns.ssrf.is_some(),
        "ssti" => patterns.ssti.is_some(),
        "open_redirect" => patterns.open_redirect.is_some(),
        "xxe" => patterns.xxe.is_some(),
        "rfi" => patterns.rfi.is_some(),
        "ldap_injection" => patterns.ldap_injection.is_some(),
        "xpath_injection" => patterns.xpath_injection.is_some(),
        "jwt" => patterns.jwt.is_some(),
        _ => false,
    }
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

#[derive(Debug, Clone)]
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
    pub(crate) on_apply_callback: Arc<RwLock<Option<Box<dyn Fn(String, Vec<crate::process::ipc::RulePatternData>) + Send + Sync>>>>,
}

impl RuleFeedManager {
    pub fn new(config: RuleFeedConfig) -> Arc<Self> {
        let embedded_public_key = Self::parse_embedded_key(EMBEDDED_PUBLIC_KEY);
        
        Arc::new(Self {
            config,
            client: create_simple_http_client(Duration::from_secs(30)),
            current_version: Arc::new(RwLock::new(None)),
            downloaded_rules: Arc::new(RwLock::new(None)),
            last_update: Arc::new(RwLock::new(0)),
            last_check: Arc::new(RwLock::new(0)),
            embedded_public_key,
            on_apply_callback: Arc::new(RwLock::new(None)),
        })
    }

    pub fn set_on_apply_callback<F>(&self, callback: F)
    where
        F: Fn(String, Vec<crate::process::ipc::RulePatternData>) + Send + Sync + 'static,
    {
        *self.on_apply_callback.write() = Some(Box::new(callback));
    }

    fn parse_embedded_key(key_str: &str) -> VerifyingKey {
        // If a real base64-encoded 32-byte Ed25519 public key is provided, use it
        if let Ok(bytes) = base64_decode(key_str) {
            if bytes.len() == 32 {
                if let Ok(key) = VerifyingKey::from_bytes(
                    bytes[..32].try_into().expect("Invalid key length")
                ) {
                    return key;
                }
            }
        }

        // No valid key provided — generate a random one at startup.
        // This means rule signature verification will only work if the feed
        // server signs with the same key. Log a warning so operators know.
        tracing::warn!(
            "No valid embedded Ed25519 public key configured (placeholder or invalid). \
             Generating a random key — rule feed signature verification will fail unless \
             the feed server uses the corresponding private key."
        );
        let mut key_bytes = [0u8; 32];
        rand::Rng::fill(&mut rand::rng(), &mut key_bytes);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
        signing_key.verifying_key()
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
                
                let interval = Duration::from_secs(
                    self_clone.config.update_interval_hours as u64 * 3600
                );
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
                
                if !self.config.allow_downgrade && !Self::is_newer_version(&rules.version, current_str) {
                    tracing::info!("Rule version {} is not newer than current {}", rules.version, current_str);
                    return;
                }

                tracing::info!("Fetched new rules version {}", rules.version);
                *self.downloaded_rules.write() = Some(rules.clone());
                
                if self.config.auto_apply
                    && self.apply_rules().is_ok()
                {
                    *self.current_version.write() = Some(rules.version);
                    *self.last_update.write() = now_timestamp();
                }
            }
            Err(e) => {
                tracing::error!("Failed to fetch rule feed: {}", e);
            }
        }
    }

    fn is_newer_version(new: &str, current: &str) -> bool {
        if current == "none" {
            return true;
        }
        
        let new_parts: Vec<u32> = new.split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        let current_parts: Vec<u32> = current.split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        
        for i in 0..new_parts.len().max(current_parts.len()) {
            let new_part = new_parts.get(i).unwrap_or(&0);
            let current_part = current_parts.get(i).unwrap_or(&0);
            
            if new_part > current_part {
                return true;
            } else if new_part < current_part {
                return false;
            }
        }
        false
    }

    async fn fetch_rules(&self, url: &str) -> Result<ParsedRules, String> {
        let response = get_with_timeout(&self.client, url, Duration::from_secs(30))
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        if !response.status.is_success() {
            return Err(format!("HTTP error: {}", response.status));
        }

        let feed_response: RuleFeedResponse = serde_json::from_str(&response.body)
            .map_err(|e| format!("Failed to parse JSON: {}", e))?;

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
        let signature_bytes = base64_decode(signature_b64)
            .map_err(|e| format!("Invalid signature encoding: {}", e))?;

        if signature_bytes.len() != 64 {
            return Err(format!("Invalid signature length: {}", signature_bytes.len()));
        }

        let signature = Ed25519Signature::from_slice(&signature_bytes)
            .map_err(|e| format!("Invalid signature: {}", e))?;

        let payload_bytes = payload.as_bytes();
        
        if self.embedded_public_key.verify(payload_bytes, &signature).is_err() {
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    let input = input.as_bytes();
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    
    let mut buf = [0u8; 4];
    let mut buf_len = 0;
    
    for &byte in input {
        if byte == b'=' {
            break;
        }
        if byte == b'\n' || byte == b'\r' {
            continue;
        }
        
        let val = CHARS.iter().position(|&x| x == byte)
            .ok_or_else(|| format!("Invalid base64 character: {}", byte as char))? as u8;
        
        buf[buf_len] = val;
        buf_len += 1;
        
        if buf_len == 4 {
            output.push((buf[0] << 2) | (buf[1] >> 4));
            output.push((buf[1] << 4) | (buf[2] >> 2));
            output.push((buf[2] << 6) | buf[3]);
            buf_len = 0;
        }
    }
    
    if buf_len > 0 {
        output.push((buf[0] << 2) | (buf[1] >> 4));
        if buf_len > 2 {
            output.push((buf[1] << 4) | (buf[2] >> 2));
        }
    }
    
    Ok(output)
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
    
    if let Some(ref sqli) = rules.sqli {
        if let Some(ref p) = sqli.patterns {
            patterns.push(crate::process::ipc::RulePatternData {
                category: "sqli".to_string(),
                patterns: p.clone(),
            });
        }
    }
    if let Some(ref xss) = rules.xss {
        if let Some(ref p) = xss.patterns {
            patterns.push(crate::process::ipc::RulePatternData {
                category: "xss".to_string(),
                patterns: p.clone(),
            });
        }
    }
    if let Some(ref pt) = rules.path_traversal {
        if let Some(ref p) = pt.patterns {
            patterns.push(crate::process::ipc::RulePatternData {
                category: "path_traversal".to_string(),
                patterns: p.clone(),
            });
        }
    }
    if let Some(ref rfi) = rules.rfi {
        if let Some(ref p) = rfi.patterns {
            patterns.push(crate::process::ipc::RulePatternData {
                category: "rfi".to_string(),
                patterns: p.clone(),
            });
        }
    }
    if let Some(ref ssrf) = rules.ssrf {
        if let Some(ref p) = ssrf.patterns {
            patterns.push(crate::process::ipc::RulePatternData {
                category: "ssrf".to_string(),
                patterns: p.clone(),
            });
        }
    }
    if let Some(ref ssti) = rules.ssti {
        if let Some(ref p) = ssti.patterns {
            patterns.push(crate::process::ipc::RulePatternData {
                category: "ssti".to_string(),
                patterns: p.clone(),
            });
        }
    }
    if let Some(ref cmd) = rules.cmd_injection {
        if let Some(ref p) = cmd.patterns {
            patterns.push(crate::process::ipc::RulePatternData {
                category: "cmd_injection".to_string(),
                patterns: p.clone(),
            });
        }
    }
    if let Some(ref xxe) = rules.xxe {
        if let Some(ref p) = xxe.patterns {
            patterns.push(crate::process::ipc::RulePatternData {
                category: "xxe".to_string(),
                patterns: p.clone(),
            });
        }
    }
    if let Some(ref jwt) = rules.jwt {
        if let Some(ref p) = jwt.patterns {
            patterns.push(crate::process::ipc::RulePatternData {
                category: "jwt".to_string(),
                patterns: p.clone(),
            });
        }
    }
    if let Some(ref ldap) = rules.ldap_injection {
        if let Some(ref p) = ldap.patterns {
            patterns.push(crate::process::ipc::RulePatternData {
                category: "ldap_injection".to_string(),
                patterns: p.clone(),
            });
        }
    }
    if let Some(ref xpath) = rules.xpath_injection {
        if let Some(ref p) = xpath.patterns {
            patterns.push(crate::process::ipc::RulePatternData {
                category: "xpath_injection".to_string(),
                patterns: p.clone(),
            });
        }
    }
    if let Some(ref or) = rules.open_redirect {
        if let Some(ref p) = or.patterns {
            patterns.push(crate::process::ipc::RulePatternData {
                category: "open_redirect".to_string(),
                patterns: p.clone(),
            });
        }
    }
    
    patterns
}

impl RuleFeedManagerForWaf {
    pub fn new(config: RuleFeedConfig) -> Arc<Self> {
        Arc::new(Self {
            inner: RuleFeedManager::new(config),
        })
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
        rules.as_ref().map(|r| r.changelog.clone()).unwrap_or_default()
    }
}
