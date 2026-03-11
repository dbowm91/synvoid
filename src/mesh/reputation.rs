#![allow(unused_variables, dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::mesh::config::MeshNodeRole;

const DEFAULT_BASE_REPUTATION: i64 = 50;
const GLOBAL_NODE_BASE_REPUTATION: i64 = 80;
const EDGE_NODE_BASE_REPUTATION: i64 = 60;
const ORIGIN_NODE_BASE_REPUTATION: i64 = 50;
const MAX_REPUTATION: i64 = 100;
const MIN_REPUTATION: i64 = 0;

const THREAT_ACCEPTED_BONUS: i64 = 1;
const THREAT_REJECTED_PENALTY: i64 = 2;
const FALSE_POSITIVE_PENALTY: i64 = 5;
const GLOBAL_NODE_TRUST_BONUS: i64 = 10;

const REPUTATION_DECAY_INTERVAL_SECS: u64 = 3600;
const REPUTATION_HISTORY_SIZE: usize = 1000;

#[derive(Debug, Clone)]
pub struct PeerReputation {
    pub node_id: String,
    pub role: MeshNodeRole,
    pub score: i64,
    pub threats_accepted: u64,
    pub threats_rejected: u64,
    pub false_positive_reports: u64,
    pub last_updated: Instant,
}

#[derive(Debug, Clone)]
pub struct ReputationEvent {
    pub timestamp: Instant,
    pub event_type: ReputationEventType,
    pub delta: i64,
    pub details: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationEventType {
    ThreatAccepted,
    ThreatRejected,
    FalsePositive,
    RoleUpgrade,
    RoleDowngrade,
    PeriodicDecay,
}

pub struct ReputationManager {
    config: Arc<ReputationConfig>,
    peers: RwLock<HashMap<String, PeerReputationState>>,
    last_decay: RwLock<Instant>,
}

struct PeerReputationState {
    reputation: PeerReputation,
    history: Vec<ReputationEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_min_rep")]
    pub min_reputation_for_acceptance: i64,
    #[serde(default = "default_global_threshold")]
    pub global_node_trust_threshold: i64,
    #[serde(default = "default_decay_enabled")]
    pub decay_enabled: bool,
    #[serde(default = "default_decay_interval")]
    pub decay_interval_secs: u64,
    #[serde(default = "default_threat_bonus")]
    pub threat_accepted_bonus: i64,
    #[serde(default = "default_threat_penalty")]
    pub threat_rejected_penalty: i64,
    #[serde(default = "default_fp_penalty")]
    pub false_positive_penalty: i64,
    #[serde(default = "default_hub_only")]
    pub hub_only_mode: bool,
}

fn default_enabled() -> bool {
    true
}
fn default_min_rep() -> i64 {
    30
}
fn default_global_threshold() -> i64 {
    50
}
fn default_decay_enabled() -> bool {
    true
}
fn default_decay_interval() -> u64 {
    3600
}
fn default_threat_bonus() -> i64 {
    1
}
fn default_threat_penalty() -> i64 {
    2
}
fn default_fp_penalty() -> i64 {
    5
}
fn default_hub_only() -> bool {
    false
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_reputation_for_acceptance: 30,
            global_node_trust_threshold: 50,
            decay_enabled: true,
            decay_interval_secs: REPUTATION_DECAY_INTERVAL_SECS,
            threat_accepted_bonus: THREAT_ACCEPTED_BONUS,
            threat_rejected_penalty: THREAT_REJECTED_PENALTY,
            false_positive_penalty: FALSE_POSITIVE_PENALTY,
            hub_only_mode: false,
        }
    }
}

impl PeerReputation {
    pub fn new(node_id: String, role: MeshNodeRole) -> Self {
        let base_score = if role.is_global() {
            GLOBAL_NODE_BASE_REPUTATION
        } else if role.is_origin() {
            ORIGIN_NODE_BASE_REPUTATION
        } else {
            EDGE_NODE_BASE_REPUTATION
        };

        Self {
            node_id,
            role,
            score: base_score,
            threats_accepted: 0,
            threats_rejected: 0,
            false_positive_reports: 0,
            last_updated: Instant::now(),
        }
    }

    pub fn get_score(&self) -> i64 {
        self.score
    }

    pub fn update_role(&mut self, new_role: MeshNodeRole) {
        let new_base = if new_role.is_global() {
            GLOBAL_NODE_BASE_REPUTATION
        } else if new_role.is_origin() {
            ORIGIN_NODE_BASE_REPUTATION
        } else {
            EDGE_NODE_BASE_REPUTATION
        };

        let delta = new_base - (self.score / 2);
        self.score = (self.score + delta).clamp(MIN_REPUTATION, MAX_REPUTATION);
        self.role = new_role;
        self.last_updated = Instant::now();
    }

    pub fn record_threat_accepted(&mut self) {
        self.score = (self.score + THREAT_ACCEPTED_BONUS).clamp(MIN_REPUTATION, MAX_REPUTATION);
        self.threats_accepted += 1;
        self.last_updated = Instant::now();
    }

    pub fn record_threat_rejected(&mut self) {
        self.score = (self.score - THREAT_REJECTED_PENALTY).clamp(MIN_REPUTATION, MAX_REPUTATION);
        self.threats_rejected += 1;
        self.last_updated = Instant::now();
    }

    pub fn record_false_positive(&mut self) {
        self.score = (self.score - FALSE_POSITIVE_PENALTY).clamp(MIN_REPUTATION, MAX_REPUTATION);
        self.false_positive_reports += 1;
        self.last_updated = Instant::now();
    }

    pub fn apply_decay(&mut self, decay_factor: f64) {
        let current = self.score;
        self.score = ((current as f64) * decay_factor).round() as i64;
        self.score = self.score.clamp(MIN_REPUTATION, MAX_REPUTATION);
        self.last_updated = Instant::now();
    }

    pub fn get_stats(&self) -> PeerReputationStats {
        PeerReputationStats {
            node_id: self.node_id.clone(),
            role: self.role,
            score: self.score,
            threats_accepted: self.threats_accepted,
            threats_rejected: self.threats_rejected,
            false_positive_reports: self.false_positive_reports,
            last_updated: self.last_updated,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerReputationStats {
    pub node_id: String,
    pub role: MeshNodeRole,
    pub score: i64,
    pub threats_accepted: u64,
    pub threats_rejected: u64,
    pub false_positive_reports: u64,
    pub last_updated: Instant,
}

impl ReputationManager {
    pub fn new(config: ReputationConfig) -> Self {
        Self {
            config: Arc::new(config),
            peers: RwLock::new(HashMap::new()),
            last_decay: RwLock::new(Instant::now()),
        }
    }

    pub fn register_peer(&self, node_id: String, role: MeshNodeRole) {
        let mut peers = self.peers.write();

        if let Some(existing) = peers.get_mut(&node_id) {
            existing.reputation.update_role(role);
            return;
        }

        peers.insert(
            node_id.clone(),
            PeerReputationState {
                reputation: PeerReputation::new(node_id, role),
                history: Vec::new(),
            },
        );
    }

    pub fn unregister_peer(&self, node_id: &str) {
        let mut peers = self.peers.write();
        peers.remove(node_id);
    }

    pub fn get_peer_reputation(&self, node_id: &str) -> Option<PeerReputation> {
        let peers = self.peers.read();
        peers.get(node_id).map(|p| p.reputation.clone())
    }

    pub fn get_all_peer_ids(&self) -> Vec<String> {
        let peers = self.peers.read();
        peers.keys().cloned().collect()
    }

    pub fn evaluate_threat(
        &self,
        source_node_id: &str,
        source_role: MeshNodeRole,
    ) -> ThreatAcceptanceDecision {
        if !self.config.enabled {
            return ThreatAcceptanceDecision {
                accepted: true,
                reason: "Reputation system disabled".to_string(),
                reputation_score: DEFAULT_BASE_REPUTATION,
                is_trusted_global: false,
            };
        }

        if self.config.hub_only_mode && !source_role.is_global() {
            return ThreatAcceptanceDecision {
                accepted: false,
                reason: "Hub-only mode: only Global nodes trusted".to_string(),
                reputation_score: 0,
                is_trusted_global: false,
            };
        }

        {
            let peers = self.peers.read();
            if let Some(peer) = peers.get(source_node_id) {
                let score = peer.reputation.score;

                let is_global_node = source_role.is_global();
                let is_trusted_global =
                    is_global_node && score >= self.config.global_node_trust_threshold;

                if is_trusted_global {
                    return ThreatAcceptanceDecision {
                        accepted: true,
                        reason: "Trusted Global node".to_string(),
                        reputation_score: score,
                        is_trusted_global: true,
                    };
                }

                if score >= self.config.min_reputation_for_acceptance {
                    return ThreatAcceptanceDecision {
                        accepted: true,
                        reason: "Sufficient reputation score".to_string(),
                        reputation_score: score,
                        is_trusted_global: false,
                    };
                }

                return ThreatAcceptanceDecision {
                    accepted: false,
                    reason: format!(
                        "Insufficient reputation: {} < {}",
                        score, self.config.min_reputation_for_acceptance
                    ),
                    reputation_score: score,
                    is_trusted_global: false,
                };
            }
        }

        let base_score = if source_role.is_global() {
            GLOBAL_NODE_BASE_REPUTATION
        } else if source_role.is_origin() {
            ORIGIN_NODE_BASE_REPUTATION
        } else {
            EDGE_NODE_BASE_REPUTATION
        };

        if self.config.hub_only_mode && !source_role.is_global() {
            return ThreatAcceptanceDecision {
                accepted: false,
                reason: "Hub-only mode: unknown non-Global node".to_string(),
                reputation_score: base_score,
                is_trusted_global: false,
            };
        }

        if base_score >= self.config.min_reputation_for_acceptance {
            ThreatAcceptanceDecision {
                accepted: true,
                reason: "Base reputation from role".to_string(),
                reputation_score: base_score,
                is_trusted_global: source_role.is_global(),
            }
        } else {
            ThreatAcceptanceDecision {
                accepted: false,
                reason: "Unknown node with insufficient base reputation".to_string(),
                reputation_score: base_score,
                is_trusted_global: false,
            }
        }
    }

    pub fn record_threat_accepted(&self, node_id: &str) {
        let mut peers = self.peers.write();
        if let Some(peer) = peers.get_mut(node_id) {
            peer.reputation.record_threat_accepted();
        }
    }

    pub fn record_threat_rejected(&self, node_id: &str) {
        let mut peers = self.peers.write();
        if let Some(peer) = peers.get_mut(node_id) {
            peer.reputation.record_threat_rejected();
        }
    }

    pub fn record_false_positive(&self, node_id: &str) {
        let mut peers = self.peers.write();
        if let Some(peer) = peers.get_mut(node_id) {
            peer.reputation.record_false_positive();
        }
    }

    pub fn apply_periodic_decay(&self) {
        let last = *self.last_decay.read();
        if last.elapsed() < Duration::from_secs(self.config.decay_interval_secs) {
            return;
        }

        *self.last_decay.write() = Instant::now();

        let decay_factor = 0.95;
        let mut peers = self.peers.write();
        for peer in peers.values_mut() {
            peer.reputation.apply_decay(decay_factor);
        }

        tracing::debug!("Applied reputation decay with factor {}", decay_factor);
    }

    pub fn get_all_stats(&self) -> Vec<PeerReputationStats> {
        let peers = self.peers.read();
        peers.values().map(|p| p.reputation.get_stats()).collect()
    }
}

#[derive(Debug, Clone)]
pub struct ThreatAcceptanceDecision {
    pub accepted: bool,
    pub reason: String,
    pub reputation_score: i64,
    pub is_trusted_global: bool,
}
