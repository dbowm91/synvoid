use crate::mesh::MeshConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use chrono::Utc;
use parking_lot::RwLock;

const CONFIG_ENCRYPTION_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureConfigValue {
    pub encrypted: bool,
    pub value: String,
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedConfig {
    pub version: u32,
    pub entries: HashMap<String, SecureConfigValue>,
    pub checksum: String,
}

pub struct SecureConfigManager {
    #[allow(dead_code)]
    config: Arc<MeshConfig>,
    encryption_key: Arc<RwLock<Option<[u8; CONFIG_ENCRYPTION_KEY_SIZE]>>>,
    secured_values: Arc<RwLock<HashMap<String, String>>>,
}

impl SecureConfigManager {
    pub fn new(config: Arc<MeshConfig>) -> Self {
        Self {
            config,
            encryption_key: Arc::new(RwLock::new(None)),
            secured_values: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn set_encryption_key(&self, key: &[u8; CONFIG_ENCRYPTION_KEY_SIZE]) {
        let mut encryption_key = self.encryption_key.write();
        *encryption_key = Some(*key);
        tracing::info!("Encryption key configured for secure config manager");
    }

    pub fn generate_encryption_key(&self) -> [u8; CONFIG_ENCRYPTION_KEY_SIZE] {
        let mut key = [0u8; CONFIG_ENCRYPTION_KEY_SIZE];
        rand::fill(&mut key);

        let mut encryption_key = self.encryption_key.write();
        *encryption_key = Some(key);

        tracing::info!("Generated new encryption key for secure config manager");
        key
    }

    pub fn has_encryption_key(&self) -> bool {
        self.encryption_key.read().is_some()
    }

    pub fn encrypt_value(&self, plaintext: &str) -> Result<SecureConfigValue, SecureConfigError> {
        let key = self.encryption_key.read();
        let key = key.as_ref().ok_or(SecureConfigError::NoEncryptionKey)?;

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| SecureConfigError::EncryptionError(e.to_string()))?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| SecureConfigError::EncryptionError(e.to_string()))?;

        Ok(SecureConfigValue {
            encrypted: true,
            value: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ciphertext),
            nonce: Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                nonce_bytes,
            )),
        })
    }

    pub fn decrypt_value(
        &self,
        encrypted: &SecureConfigValue,
    ) -> Result<String, SecureConfigError> {
        if !encrypted.encrypted {
            return Ok(encrypted.value.clone());
        }

        let key = self.encryption_key.read();
        let key = key.as_ref().ok_or(SecureConfigError::NoEncryptionKey)?;

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| SecureConfigError::EncryptionError(e.to_string()))?;

        let nonce_bytes =
            encrypted
                .nonce
                .as_ref()
                .ok_or(SecureConfigError::InvalidEncryptedValue(
                    "Missing nonce".to_string(),
                ))?;

        let nonce_decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, nonce_bytes)
                .map_err(|e| SecureConfigError::DecryptionError(e.to_string()))?;

        let nonce = Nonce::from_slice(&nonce_decoded);

        let ciphertext =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &encrypted.value)
                .map_err(|e| SecureConfigError::DecryptionError(e.to_string()))?;

        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| SecureConfigError::DecryptionError(e.to_string()))?;

        String::from_utf8(plaintext).map_err(|e| SecureConfigError::DecryptionError(e.to_string()))
    }

    pub fn secure_value(&self, key: &str, value: &str) -> Result<(), SecureConfigError> {
        let encrypted = self.encrypt_value(value)?;
        let mut secured = self.secured_values.write();
        secured.insert(
            key.to_string(),
            serde_json::to_string(&encrypted)
                .map_err(|e| SecureConfigError::SerializationError(e.to_string()))?,
        );

        tracing::debug!("Secured configuration value: {}", key);
        Ok(())
    }

    pub fn get_secured_value(&self, key: &str) -> Option<String> {
        let secured = self.secured_values.read();
        let encrypted_str = secured.get(key)?;

        let encrypted: SecureConfigValue = serde_json::from_str(encrypted_str).ok()?;
        self.decrypt_value(&encrypted).ok()
    }

    pub fn export_encrypted_config(&self, path: &PathBuf) -> Result<(), SecureConfigError> {
        let secured = self.secured_values.read();

        let entries: HashMap<String, SecureConfigValue> = secured
            .iter()
            .filter_map(|(k, v)| {
                let encrypted: SecureConfigValue = serde_json::from_str(v).ok()?;
                Some((k.clone(), encrypted))
            })
            .collect();

        let json = serde_json::to_string(&entries)
            .map_err(|e| SecureConfigError::SerializationError(e.to_string()))?;

        let checksum = format!("{:x}", Sha256::digest(&json));

        let export = EncryptedConfig {
            version: 1,
            entries,
            checksum,
        };

        let export_json = serde_json::to_string_pretty(&export)
            .map_err(|e| SecureConfigError::SerializationError(e.to_string()))?;

        std::fs::write(path, export_json).map_err(|e| SecureConfigError::IoError(e.to_string()))?;

        tracing::info!("Exported encrypted configuration to {:?}", path);
        Ok(())
    }

    pub fn import_encrypted_config(&self, path: &PathBuf) -> Result<(), SecureConfigError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| SecureConfigError::IoError(e.to_string()))?;

        let import: EncryptedConfig = serde_json::from_str(&content)
            .map_err(|e| SecureConfigError::DeserializationError(e.to_string()))?;

        let json = serde_json::to_string(&import.entries)
            .map_err(|e| SecureConfigError::SerializationError(e.to_string()))?;

        let checksum = format!("{:x}", Sha256::digest(&json));
        if checksum != import.checksum {
            return Err(SecureConfigError::ChecksumMismatch);
        }

        let mut secured = self.secured_values.write();
        for (key, value) in import.entries {
            secured.insert(
                key,
                serde_json::to_string(&value)
                    .map_err(|e| SecureConfigError::SerializationError(e.to_string()))?,
            );
        }

        tracing::info!("Imported encrypted configuration from {:?}", path);
        Ok(())
    }

    pub fn secure_mesh_config(&self, config: &MeshConfig) -> Result<MeshConfig, SecureConfigError> {
        let mut secured_config = config.clone();

        if let Some(auth_tokens) = config
            .tls
            .certificate_pin_public_keys
            .clone()
            .into_iter()
            .next()
        {
            self.secure_value("tls.certificate_pin_public_keys", &auth_tokens)?;
            secured_config.tls.certificate_pin_public_keys = Vec::new();
        }

        for (key, value) in config.local_upstreams.iter() {
            if !value.upstream_url.is_empty() {
                let secure_key = format!("upstream.{}", key);
                self.secure_value(&secure_key, &value.upstream_url)?;
            }
        }

        tracing::info!("Secured mesh configuration");
        Ok(secured_config)
    }

    pub fn validate_config_security(&self, config: &MeshConfig) -> Vec<ConfigSecurityIssue> {
        let mut issues = Vec::new();

        if config.tls.auto_generate_certs && config.tls.cert_path.is_none() {
            issues.push(ConfigSecurityIssue {
                severity: SecuritySeverity::Warning,
                issue: "Auto-generated certificates in production are not recommended".to_string(),
                recommendation: "Use proper CA-signed certificates for production".to_string(),
            });
        }

        if config.tls.min_tls_version != "1.3" {
            issues.push(ConfigSecurityIssue {
                severity: SecuritySeverity::Warning,
                issue: format!(
                    "TLS {} is below recommended version 1.3",
                    config.tls.min_tls_version
                ),
                recommendation: "Use TLS 1.3 for enhanced security".to_string(),
            });
        }

        if !config.tls.enforce_mutual_tls && !config.seeds.is_empty() {
            issues.push(ConfigSecurityIssue {
                severity: SecuritySeverity::Info,
                issue: "Mutual TLS not enforced for peer connections".to_string(),
                recommendation: "Enable mutual TLS for enhanced security".to_string(),
            });
        }

        if config.tls.cert_rotation_interval_secs.is_none() {
            issues.push(ConfigSecurityIssue {
                severity: SecuritySeverity::Info,
                issue: "Certificate rotation not configured".to_string(),
                recommendation: "Configure automatic certificate rotation".to_string(),
            });
        }

        issues
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSecurityIssue {
    pub severity: SecuritySeverity,
    pub issue: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, thiserror::Error)]
pub enum SecureConfigError {
    #[error("No encryption key configured")]
    NoEncryptionKey,
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    #[error("Invalid encrypted value: {0}")]
    InvalidEncryptedValue(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    #[error("IO error: {0}")]
    IoError(String),
    #[error("Checksum mismatch - configuration may be tampered")]
    ChecksumMismatch,
}

pub struct SecurityEventLogger {
    #[allow(dead_code)]
    config: Arc<MeshConfig>,
    event_buffer: Arc<RwLock<Vec<SecurityEvent>>>,
    max_buffer_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp: i64,
    pub event_type: SecurityEventType,
    pub source_node: String,
    pub target_node: Option<String>,
    pub details: String,
    pub severity: SecuritySeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityEventType {
    AuthenticationSuccess,
    AuthenticationFailure,
    AuthorizationFailure,
    CertificateExpiry,
    CertificateRevoked,
    PeerConnected,
    PeerDisconnected,
    RateLimitExceeded,
    AttackDetected,
    ConfigurationChanged,
    UnauthorizedAccessAttempt,
}

impl SecurityEventLogger {
    pub fn new(config: Arc<MeshConfig>, max_buffer_size: usize) -> Self {
        Self {
            config,
            event_buffer: Arc::new(RwLock::new(Vec::new())),
            max_buffer_size,
        }
    }

    pub fn log_event(&self, event: SecurityEvent) {
        let mut buffer = self.event_buffer.write();

        if buffer.len() >= self.max_buffer_size {
            buffer.remove(0);
        }

        buffer.push(event.clone());

        match event.severity {
            SecuritySeverity::Critical => {
                tracing::error!(
                    "SECURITY: {} - {} (node: {})",
                    event.event_type.as_str(),
                    event.details,
                    event.source_node
                );
            }
            SecuritySeverity::Warning => {
                tracing::warn!(
                    "SECURITY: {} - {} (node: {})",
                    event.event_type.as_str(),
                    event.details,
                    event.source_node
                );
            }
            SecuritySeverity::Info => {
                tracing::info!(
                    "SECURITY: {} - {} (node: {})",
                    event.event_type.as_str(),
                    event.details,
                    event.source_node
                );
            }
        }
    }

    pub fn log_auth_success(&self, source_node: &str, target_node: Option<&str>) {
        self.log_event(SecurityEvent {
            timestamp: Utc::now().timestamp(),
            event_type: SecurityEventType::AuthenticationSuccess,
            source_node: source_node.to_string(),
            target_node: target_node.map(String::from),
            details: "Authentication successful".to_string(),
            severity: SecuritySeverity::Info,
        });
    }

    pub fn log_auth_failure(&self, source_node: &str, target_node: Option<&str>, reason: &str) {
        self.log_event(SecurityEvent {
            timestamp: Utc::now().timestamp(),
            event_type: SecurityEventType::AuthenticationFailure,
            source_node: source_node.to_string(),
            target_node: target_node.map(String::from),
            details: format!("Authentication failed: {}", reason),
            severity: SecuritySeverity::Warning,
        });
    }

    pub fn log_rate_limit_exceeded(&self, source_node: &str, limit_type: &str) {
        self.log_event(SecurityEvent {
            timestamp: Utc::now().timestamp(),
            event_type: SecurityEventType::RateLimitExceeded,
            source_node: source_node.to_string(),
            target_node: None,
            details: format!("Rate limit exceeded: {}", limit_type),
            severity: SecuritySeverity::Warning,
        });
    }

    pub fn log_attack_detected(&self, source_node: &str, attack_type: &str) {
        self.log_event(SecurityEvent {
            timestamp: Utc::now().timestamp(),
            event_type: SecurityEventType::AttackDetected,
            source_node: source_node.to_string(),
            target_node: None,
            details: format!("Attack detected: {}", attack_type),
            severity: SecuritySeverity::Critical,
        });
    }

    pub fn get_recent_events(&self, count: usize) -> Vec<SecurityEvent> {
        let buffer = self.event_buffer.read();
        buffer.iter().rev().take(count).cloned().collect()
    }

    pub fn get_events_by_severity(&self, severity: SecuritySeverity) -> Vec<SecurityEvent> {
        let buffer = self.event_buffer.read();
        buffer
            .iter()
            .filter(|e| e.severity == severity)
            .cloned()
            .collect()
    }

    pub fn clear_events(&self) {
        let mut buffer = self.event_buffer.write();
        buffer.clear();
    }
}

impl SecurityEventType {
    pub fn as_str(&self) -> &str {
        match self {
            SecurityEventType::AuthenticationSuccess => "AUTH_SUCCESS",
            SecurityEventType::AuthenticationFailure => "AUTH_FAILURE",
            SecurityEventType::AuthorizationFailure => "AUTHZ_FAILURE",
            SecurityEventType::CertificateExpiry => "CERT_EXPIRY",
            SecurityEventType::CertificateRevoked => "CERT_REVOKED",
            SecurityEventType::PeerConnected => "PEER_CONNECTED",
            SecurityEventType::PeerDisconnected => "PEER_DISCONNECTED",
            SecurityEventType::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            SecurityEventType::AttackDetected => "ATTACK_DETECTED",
            SecurityEventType::ConfigurationChanged => "CONFIG_CHANGED",
            SecurityEventType::UnauthorizedAccessAttempt => "UNAUTHORIZED_ACCESS",
        }
    }
}
