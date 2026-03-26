use crate::config::YaraRuleFeedConfig;
use crate::http_client::{HttpClient, get_with_timeout, create_simple_http_client};
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleFeedResponse {
    pub version: String,
    #[serde(default)]
    pub previous_version: Option<String>,
    pub timestamp: String,
    pub signature: String,
    pub rules: String,
    #[serde(default)]
    pub changelog: Vec<YaraChangelogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraChangelogEntry {
    #[serde(rename = "type")]
    pub entry_type: String,
    #[serde(default)]
    pub rule: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct ParsedYaraRules {
    pub version: String,
    pub previous_version: Option<String>,
    pub timestamp: u64,
    pub rules: String,
    pub changelog: Vec<YaraChangelogEntry>,
}

#[derive(Debug, Clone)]
pub struct YaraRuleVersion {
    pub version: String,
    pub timestamp: u64,
    pub rules: String,
    pub source: YaraRuleSource,
}

#[derive(Debug, Clone, PartialEq)]
pub enum YaraRuleSource {
    Local,
    Feed,
    Mesh,
    MeshApproved,
}

pub struct YaraRuleFeedManager {
    config: YaraRuleFeedConfig,
    client: HttpClient,
    current_version: Arc<RwLock<Option<String>>>,
    current_rules: Arc<RwLock<Option<String>>>,
    downloaded_rules: Arc<RwLock<Option<ParsedYaraRules>>>,
    last_update: Arc<RwLock<u64>>,
    last_check: Arc<RwLock<u64>>,
    embedded_public_key: Option<VerifyingKey>,
    history: Arc<RwLock<Vec<YaraRuleVersion>>>,
    max_history: usize,
}

impl YaraRuleFeedManager {
    pub fn new(config: YaraRuleFeedConfig) -> Arc<Self> {
        let embedded_public_key = if !config.signer_public_key.is_empty() {
            Self::parse_embedded_key(&config.signer_public_key)
        } else {
            None
        };

        Arc::new(Self {
            config,
            client: create_simple_http_client(Duration::from_secs(30)),
            current_version: Arc::new(RwLock::new(None)),
            current_rules: Arc::new(RwLock::new(None)),
            downloaded_rules: Arc::new(RwLock::new(None)),
            last_update: Arc::new(RwLock::new(0)),
            last_check: Arc::new(RwLock::new(0)),
            embedded_public_key,
            history: Arc::new(RwLock::new(Vec::new())),
            max_history: 10,
        })
    }

    fn parse_embedded_key(key_str: &str) -> Option<VerifyingKey> {
        if let Ok(bytes) = base64_decode(key_str) {
            if bytes.len() == 32 {
                let array: [u8; 32] = match bytes[..32].try_into() {
                    Ok(arr) => arr,
                    Err(_) => return None,
                };
                return VerifyingKey::from_bytes(&array).ok();
            }
        }
        None
    }

    pub fn start_background_fetching(self: &Arc<Self>, is_elevated: Arc<RwLock<bool>>) {
        if !self.config.enabled {
            tracing::info!("YARA rule feed is disabled");
            return;
        }

        let self_clone = Arc::clone(self);
        
        tokio::spawn(async move {
            loop {
                let interval_hours = {
                    let elevated = *is_elevated.read();
                    if elevated {
                        self_clone.config.elevated_interval_hours
                    } else {
                        self_clone.config.update_interval_hours
                    }
                };

                self_clone.check_and_fetch().await;
                
                let interval = Duration::from_secs(
                    interval_hours as u64 * 3600
                );
                tokio::time::sleep(interval).await;
            }
        });
    }

    pub async fn check_and_fetch(&self) {
        *self.last_check.write() = now_timestamp();
        
        tracing::info!("Checking for YARA rule updates from {}", self.config.url);
        
        match self.fetch_rules(&self.config.url).await {
            Ok(rules) => {
                let current = self.current_version.read().clone();
                let current_str = current.as_deref().unwrap_or("none");
                
                if !self.config.allow_downgrade && !Self::is_newer_version(&rules.version, current_str) {
                    tracing::info!("YARA rule version {} is not newer than current {}", rules.version, current_str);
                    return;
                }

                tracing::info!("Fetched new YARA rules version {}", rules.version);
                *self.downloaded_rules.write() = Some(rules.clone());
                
                if self.config.auto_apply
                    && self.apply_rules().is_ok() {
                        *self.current_version.write() = Some(rules.version.clone());
                        *self.last_update.write() = now_timestamp();
                    }
            }
            Err(e) => {
                tracing::error!("Failed to fetch YARA rule feed: {}", e);
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

    async fn fetch_rules(&self, url: &str) -> Result<ParsedYaraRules, String> {
        let response = get_with_timeout(&self.client, url, Duration::from_secs(30))
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        if !response.status.is_success() {
            return Err(format!("HTTP error: {}", response.status));
        }

        let rules_size = response.body.len();
        let max_size = (self.config.max_rules_size_kb as usize) * 1024;
        if rules_size > max_size {
            return Err(format!("Rules size {}KB exceeds limit {}KB", rules_size / 1024, self.config.max_rules_size_kb));
        }

        let body_str = String::from_utf8_lossy(&response.body);
        let feed_response: YaraRuleFeedResponse = serde_json::from_str(&body_str)
            .map_err(|e| format!("Failed to parse JSON: {}", e))?;

        let timestamp = Self::parse_timestamp(&feed_response.timestamp)
            .map_err(|e| format!("Invalid timestamp: {}", e))?;

        if let Some(ref public_key) = self.embedded_public_key {
            let payload_for_sig = Self::create_payload_for_signature(&feed_response);
            self.verify_signature(&payload_for_sig, &feed_response.signature, public_key)?;
        } else if !feed_response.signature.is_empty() {
            tracing::warn!("YARA rule signature present but no public key configured, skipping verification");
        }

        let parsed = ParsedYaraRules {
            version: feed_response.version,
            previous_version: feed_response.previous_version,
            timestamp,
            rules: feed_response.rules,
            changelog: feed_response.changelog,
        };

        Ok(parsed)
    }

    fn parse_timestamp(ts: &str) -> Result<u64, String> {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
            return Ok(dt.timestamp() as u64);
        }
        
        if let Ok(t) = ts.parse::<u64>() {
            return Ok(t);
        }
        
        Err("Invalid timestamp format".to_string())
    }

    fn create_payload_for_signature(response: &YaraRuleFeedResponse) -> String {
        let mut sig_payload = response.clone();
        sig_payload.signature = String::new();
        serde_json::to_string(&sig_payload).unwrap_or_default()
    }

    fn verify_signature(&self, payload: &str, signature_b64: &str, public_key: &VerifyingKey) -> Result<(), String> {
        let signature_bytes = base64_decode(signature_b64)
            .map_err(|e| format!("Invalid signature encoding: {}", e))?;

        if signature_bytes.len() != 64 {
            return Err(format!("Invalid signature length: {}", signature_bytes.len()));
        }

        let signature = Ed25519Signature::from_slice(&signature_bytes)
            .map_err(|e| format!("Invalid signature: {}", e))?;

        let payload_bytes = payload.as_bytes();
        
        if public_key.verify(payload_bytes, &signature).is_err() {
            return Err("Signature verification failed".to_string());
        }

        Ok(())
    }

    pub fn apply_rules(&self) -> Result<String, String> {
        let rules = self.downloaded_rules.read();
        let rules = rules.as_ref().ok_or("No rules downloaded")?;

        let version = rules.version.clone();
        let rules_content = rules.rules.clone();
        
        *self.current_rules.write() = Some(rules_content);
        
        self.add_to_history(rules.version.clone(), rules.rules.clone(), YaraRuleSource::Feed);
        
        tracing::info!("Applied YARA rule version {}", rules.version);
        Ok(version)
    }

    pub fn add_to_history_inline(&self, version: String, rules: String, source: String) {
        let source_enum = match source.as_str() {
            "Local" => YaraRuleSource::Local,
            "Feed" => YaraRuleSource::Feed,
            "Mesh" => YaraRuleSource::Mesh,
            "MeshApproved" => YaraRuleSource::MeshApproved,
            _ => YaraRuleSource::Local,
        };
        self.add_to_history(version, rules, source_enum);
    }

    pub fn apply_rules_from_mesh(&self, version: String, rules: String) -> Result<String, String> {
        *self.current_rules.write() = Some(rules.clone());
        self.add_to_history(version.clone(), rules, YaraRuleSource::MeshApproved);
        *self.current_version.write() = Some(version.clone());
        *self.last_update.write() = now_timestamp();
        tracing::info!("Applied YARA rule version {} from mesh", version);
        Ok(version)
    }

    fn add_to_history(&self, version: String, rules: String, source: YaraRuleSource) {
        let mut history = self.history.write();
        let entry = YaraRuleVersion {
            version,
            timestamp: now_timestamp(),
            rules,
            source,
        };
        history.push(entry);
        if history.len() > self.max_history {
            history.remove(0);
        }
    }

    pub fn rollback(&self, target_version: Option<String>) -> Result<String, String> {
        let history = self.history.read();
        
        if history.is_empty() {
            return Err("No rule history available for rollback".to_string());
        }

        let target_idx = if let Some(ref ver) = target_version {
            match history.iter().position(|r| r.version == *ver) {
                Some(idx) => idx,
                None => return Err(format!("Version {} not found in history", ver)),
            }
        } else if history.len() < 2 {
            return Err("Need at least 2 rule versions for rollback".to_string());
        } else {
            history.len() - 2
        };

        let target = history.get(target_idx).ok_or("Invalid history index")?;
        
        let target_version_str = target.version.clone();
        let target_rules_str = target.rules.clone();
        
        drop(history);
        
        self.add_to_history(target_version_str.clone(), target_rules_str, YaraRuleSource::Local);
        *self.current_version.write() = Some(target_version_str.clone());
        
        tracing::info!("Rolled back to YARA rule version {}", target_version_str);
        Ok(target_version_str)
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

    pub fn get_pending_rules(&self) -> Option<ParsedYaraRules> {
        self.downloaded_rules.read().clone()
    }

    pub fn get_history(&self) -> Vec<YaraRuleVersion> {
        self.history.read().clone()
    }

    pub fn get_rules_for_scanner(&self) -> Option<String> {
        self.current_rules.read().clone()
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
