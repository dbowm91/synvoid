use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use synvoid_config::YaraRuleFeedConfig;
use synvoid_http_client::{create_simple_http_client, get_with_timeout, HttpClient};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum YaraFeedError {
    #[error("Request failed: {0}")]
    RequestFailed(String),
    #[error("HTTP error: {0}")]
    HttpError(u16),
    #[error("Rules size {size}KB exceeds limit {limit}KB")]
    RulesSizeExceedsLimit { size: usize, limit: usize },
    #[error("Failed to parse JSON: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(String),
    #[error("Invalid signature encoding: {0}")]
    InvalidSignatureEncoding(String),
    #[error("Invalid signature length: {0}")]
    InvalidSignatureLength(usize),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    #[error("No rules downloaded")]
    NoRulesDownloaded,
    #[error("No rule history available for rollback")]
    NoRuleHistory,
    #[error("Version {0} not found in history")]
    VersionNotFound(String),
    #[error("Need at least 2 rule versions for rollback")]
    InsufficientHistory,
    #[error("Invalid history index")]
    InvalidHistoryIndex,
}

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
        if let Ok(bytes) = STANDARD.decode(key_str) {
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

                let interval = Duration::from_secs(interval_hours as u64 * 3600);
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

                if !self.config.allow_downgrade
                    && current_str != "none"
                    && !synvoid_utils::is_newer_version(&rules.version, current_str)
                {
                    tracing::info!(
                        "YARA rule version {} is not newer than current {}",
                        rules.version,
                        current_str
                    );
                    return;
                }

                tracing::info!("Fetched new YARA rules version {}", rules.version);
                *self.downloaded_rules.write() = Some(rules.clone());

                if self.config.auto_apply && self.apply_rules().is_ok() {
                    *self.current_version.write() = Some(rules.version.clone());
                    *self.last_update.write() = now_timestamp();
                }
            }
            Err(e) => {
                tracing::error!("Failed to fetch YARA rule feed: {}", e);
            }
        }
    }

    async fn fetch_rules(&self, url: &str) -> Result<ParsedYaraRules, YaraFeedError> {
        let response = get_with_timeout(&self.client, url, Duration::from_secs(30))
            .await
            .map_err(|e| YaraFeedError::RequestFailed(e.to_string()))?;

        if !response.status.is_success() {
            return Err(YaraFeedError::HttpError(response.status.as_u16()));
        }

        let rules_size = response.body.len();
        let max_size = (self.config.max_rules_size_kb as usize) * 1024;
        if rules_size > max_size {
            return Err(YaraFeedError::RulesSizeExceedsLimit {
                size: rules_size / 1024,
                limit: self.config.max_rules_size_kb as usize,
            });
        }

        let body_str = String::from_utf8_lossy(&response.body);
        let feed_response: YaraRuleFeedResponse =
            serde_json::from_str(&body_str).map_err(YaraFeedError::JsonError)?;

        let timestamp = Self::parse_timestamp(&feed_response.timestamp)?;

        if let Some(ref public_key) = self.embedded_public_key {
            let payload_for_sig = Self::create_payload_for_signature(&feed_response);
            self.verify_signature(&payload_for_sig, &feed_response.signature, public_key)?;
        } else if !feed_response.signature.is_empty() {
            tracing::warn!(
                "YARA rule signature present but no public key configured, skipping verification"
            );
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

    fn parse_timestamp(ts: &str) -> Result<u64, YaraFeedError> {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
            return Ok(dt.timestamp() as u64);
        }

        if let Ok(t) = ts.parse::<u64>() {
            return Ok(t);
        }

        Err(YaraFeedError::InvalidTimestamp(ts.to_string()))
    }

    fn create_payload_for_signature(response: &YaraRuleFeedResponse) -> String {
        let mut sig_payload = response.clone();
        sig_payload.signature = String::new();
        serde_json::to_string(&sig_payload).unwrap_or_default()
    }

    fn verify_signature(
        &self,
        payload: &str,
        signature_b64: &str,
        public_key: &VerifyingKey,
    ) -> Result<(), YaraFeedError> {
        let signature_bytes = STANDARD
            .decode(signature_b64)
            .map_err(|e| YaraFeedError::InvalidSignatureEncoding(e.to_string()))?;

        if signature_bytes.len() != 64 {
            return Err(YaraFeedError::InvalidSignatureLength(signature_bytes.len()));
        }

        let signature = Ed25519Signature::from_slice(&signature_bytes)
            .map_err(|e| YaraFeedError::InvalidSignature(e.to_string()))?;

        let payload_bytes = payload.as_bytes();

        if public_key.verify(payload_bytes, &signature).is_err() {
            return Err(YaraFeedError::SignatureVerificationFailed);
        }

        Ok(())
    }

    pub fn apply_rules(&self) -> Result<String, YaraFeedError> {
        let rules = self.downloaded_rules.read();
        let rules = rules.as_ref().ok_or(YaraFeedError::NoRulesDownloaded)?;

        let version = rules.version.clone();
        let rules_content = rules.rules.clone();

        *self.current_rules.write() = Some(rules_content);

        self.add_to_history(
            rules.version.clone(),
            rules.rules.clone(),
            YaraRuleSource::Feed,
        );

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

    pub fn apply_rules_from_mesh(
        &self,
        version: String,
        rules: String,
    ) -> Result<String, YaraFeedError> {
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

    pub fn rollback(&self, target_version: Option<String>) -> Result<String, YaraFeedError> {
        let history = self.history.read();

        if history.is_empty() {
            return Err(YaraFeedError::NoRuleHistory);
        }

        let target_idx = if let Some(ref ver) = target_version {
            match history.iter().position(|r| r.version == *ver) {
                Some(idx) => idx,
                None => return Err(YaraFeedError::VersionNotFound(ver.clone())),
            }
        } else if history.len() < 2 {
            return Err(YaraFeedError::InsufficientHistory);
        } else {
            history.len() - 2
        };

        let target = history
            .get(target_idx)
            .ok_or(YaraFeedError::InvalidHistoryIndex)?;

        let target_version_str = target.version.clone();
        let target_rules_str = target.rules.clone();

        drop(history);

        self.add_to_history(
            target_version_str.clone(),
            target_rules_str,
            YaraRuleSource::Local,
        );
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
    synvoid_utils::safe_unix_timestamp()
}
