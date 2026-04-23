use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::mesh::config::MeshConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAccessRule {
    pub id: String,
    pub action: AccessAction,
    pub direction: TrafficDirection,
    pub source_pattern: Option<String>,
    pub destination_pattern: Option<String>,
    pub port_range: Option<(u16, u16)>,
    pub protocol: Option<Protocol>,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessAction {
    Allow,
    Deny,
    Log,
    Challenge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrafficDirection {
    Inbound,
    Outbound,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    QUIC,
    Any,
}

pub struct NetworkAccessControl {
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    config: Arc<MeshConfig>,
    rules: Arc<RwLock<Vec<NetworkAccessRule>>>,
    connection_tracker: Arc<RwLock<HashMap<String, ConnectionState>>>,
    whitelist: Arc<RwLock<std::collections::HashSet<String>>>,
    blacklist: Arc<RwLock<std::collections::HashSet<String>>>,
}

#[derive(Debug, Clone)]
pub struct ConnectionState {
    pub node_id: String,
    pub remote_addr: IpAddr,
    pub connected_at: std::time::Instant,
    pub last_activity: std::time::Instant,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_allowed: u64,
    pub packets_denied: u64,
}

impl NetworkAccessControl {
    pub fn new(config: Arc<MeshConfig>) -> Self {
        Self {
            config,
            rules: Arc::new(RwLock::new(Vec::new())),
            connection_tracker: Arc::new(RwLock::new(HashMap::new())),
            whitelist: Arc::new(RwLock::new(std::collections::HashSet::new())),
            blacklist: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }

    pub fn add_rule(&self, rule: NetworkAccessRule) {
        let mut rules = self.rules.write();
        rules.push(rule);
    }

    pub fn add_default_rules(&self) {
        let default_rules = vec![
            NetworkAccessRule {
                id: "allow-established".to_string(),
                action: AccessAction::Allow,
                direction: TrafficDirection::Both,
                source_pattern: None,
                destination_pattern: None,
                port_range: None,
                protocol: None,
                description: "Allow established connections".to_string(),
            },
            NetworkAccessRule {
                id: "allow-mesh-port".to_string(),
                action: AccessAction::Allow,
                direction: TrafficDirection::Both,
                source_pattern: None,
                destination_pattern: None,
                port_range: Some((5001, 5001)),
                protocol: Some(Protocol::QUIC),
                description: "Allow mesh QUIC traffic on port 5001".to_string(),
            },
            NetworkAccessRule {
                id: "deny-all".to_string(),
                action: AccessAction::Deny,
                direction: TrafficDirection::Both,
                source_pattern: None,
                destination_pattern: None,
                port_range: None,
                protocol: None,
                description: "Deny all other traffic".to_string(),
            },
        ];

        let mut rules = self.rules.write();
        *rules = default_rules;
    }

    pub fn check_access(
        &self,
        source: &str,
        destination: &str,
        port: u16,
        protocol: Protocol,
    ) -> AccessDecision {
        let rules = self.rules.read();

        for rule in rules.iter() {
            if self.rule_matches(rule, source, destination, port, protocol) {
                return AccessDecision {
                    action: rule.action,
                    rule_id: rule.id.clone(),
                    reason: rule.description.clone(),
                };
            }
        }

        AccessDecision {
            action: AccessAction::Deny,
            rule_id: "default-deny".to_string(),
            reason: "No matching rule, default deny".to_string(),
        }
    }

    fn rule_matches(
        &self,
        rule: &NetworkAccessRule,
        source: &str,
        destination: &str,
        port: u16,
        protocol: Protocol,
    ) -> bool {
        if let Some(ref source_pattern) = rule.source_pattern {
            if !source.contains(source_pattern) {
                return false;
            }
        }

        if let Some(ref dest_pattern) = rule.destination_pattern {
            if !destination.contains(dest_pattern) {
                return false;
            }
        }

        if let Some((start, end)) = rule.port_range {
            if port < start || port > end {
                return false;
            }
        }

        if let Some(rule_protocol) = rule.protocol {
            if rule_protocol != Protocol::Any && rule_protocol != protocol {
                return false;
            }
        }

        true
    }

    pub fn whitelist_node(&self, node_id: &str) {
        let mut whitelist = self.whitelist.write();
        whitelist.insert(node_id.to_string());

        let mut blacklist = self.blacklist.write();
        blacklist.remove(node_id);

        tracing::info!("Node {} added to whitelist", node_id);
    }

    pub fn blacklist_node(&self, node_id: &str) {
        let mut blacklist = self.blacklist.write();
        blacklist.insert(node_id.to_string());

        let mut whitelist = self.whitelist.write();
        whitelist.remove(node_id);

        tracing::warn!("Node {} added to blacklist", node_id);
    }

    pub fn is_whitelisted(&self, node_id: &str) -> bool {
        let whitelist = self.whitelist.read();
        whitelist.contains(node_id)
    }

    pub fn is_blacklisted(&self, node_id: &str) -> bool {
        let blacklist = self.blacklist.read();
        blacklist.contains(node_id)
    }

    pub fn check_node_access(&self, node_id: &str) -> AccessDecision {
        if self.is_blacklisted(node_id) {
            return AccessDecision {
                action: AccessAction::Deny,
                rule_id: "blacklist".to_string(),
                reason: format!("Node {} is blacklisted", node_id),
            };
        }

        if self.is_whitelisted(node_id) {
            return AccessDecision {
                action: AccessAction::Allow,
                rule_id: "whitelist".to_string(),
                reason: format!("Node {} is whitelisted", node_id),
            };
        }

        AccessDecision {
            action: AccessAction::Challenge,
            rule_id: "default".to_string(),
            reason: "Node requires verification".to_string(),
        }
    }

    pub fn track_connection(&self, node_id: &str, remote_addr: IpAddr) {
        let mut connections = self.connection_tracker.write();
        connections.insert(
            node_id.to_string(),
            ConnectionState {
                node_id: node_id.to_string(),
                remote_addr,
                connected_at: std::time::Instant::now(),
                last_activity: std::time::Instant::now(),
                bytes_sent: 0,
                bytes_received: 0,
                packets_allowed: 0,
                packets_denied: 0,
            },
        );
    }

    pub fn update_connection_stats(&self, node_id: &str, bytes_sent: u64, bytes_received: u64) {
        let mut connections = self.connection_tracker.write();
        if let Some(conn) = connections.get_mut(node_id) {
            conn.bytes_sent += bytes_sent;
            conn.bytes_received += bytes_received;
            conn.last_activity = std::time::Instant::now();
        }
    }

    pub fn record_packet(&self, node_id: &str, allowed: bool) {
        let mut connections = self.connection_tracker.write();
        if let Some(conn) = connections.get_mut(node_id) {
            if allowed {
                conn.packets_allowed += 1;
            } else {
                conn.packets_denied += 1;
            }
        }
    }

    pub fn get_connection_state(&self, node_id: &str) -> Option<ConnectionState> {
        let connections = self.connection_tracker.read();
        connections.get(node_id).cloned()
    }

    pub fn get_all_connections(&self) -> Vec<ConnectionState> {
        let connections = self.connection_tracker.read();
        connections.values().cloned().collect()
    }

    pub fn cleanup_stale_connections(&self, timeout: std::time::Duration) {
        let now = std::time::Instant::now();

        let mut connections = self.connection_tracker.write();
        connections.retain(|_, conn| now.duration_since(conn.last_activity) < timeout);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessDecision {
    pub action: AccessAction,
    pub rule_id: String,
    pub reason: String,
}

pub struct MeshDataEncryption {
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    config: Arc<MeshConfig>,
    encryption_key: Arc<RwLock<Option<[u8; 32]>>>,
}

impl MeshDataEncryption {
    pub fn new(config: Arc<MeshConfig>) -> Self {
        Self {
            config,
            encryption_key: Arc::new(RwLock::new(None)),
        }
    }

    pub fn set_encryption_key(&self, key: [u8; 32]) {
        let mut encryption_key = self.encryption_key.write();
        *encryption_key = Some(key);
        tracing::info!("Data encryption key configured");
    }

    pub fn generate_key(&self) -> [u8; 32] {
        use rand::{RngCore, SeedableRng};
        let mut key = [0u8; 32];
        let mut rng = rand::rngs::StdRng::from_os_rng();
        rng.fill_bytes(&mut key);

        let mut encryption_key = self.encryption_key.write();
        *encryption_key = Some(key);

        key
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Option<Vec<u8>> {
        use rand::{RngCore, SeedableRng};
        let key = self.encryption_key.read();
        let key = key.as_ref()?;

        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        let cipher = Aes256Gcm::new_from_slice(key).ok()?;

        let mut nonce_bytes = [0u8; 12];
        let mut rng = rand::rngs::StdRng::from_os_rng();
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext).ok()?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Some(result)
    }

    pub fn decrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 12 {
            return None;
        }

        let key = self.encryption_key.read();
        let key = key.as_ref()?;

        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        let cipher = Aes256Gcm::new_from_slice(key).ok()?;

        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];

        let plaintext = cipher.decrypt(nonce, ciphertext).ok()?;

        Some(plaintext)
    }

    pub fn is_enabled(&self) -> bool {
        self.encryption_key.read().is_some()
    }
}
