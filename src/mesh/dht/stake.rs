use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::mesh::config::MeshNodeRole;
use crate::utils::current_timestamp;

const DEFAULT_MIN_STAKE_FOR_DHT_WRITE: i64 = 30;
const DEFAULT_MIN_STAKE_FOR_DHT_READ: i64 = 10;
const DEFAULT_MIN_STAKE_FOR_ROUTING: i64 = 20;
const DEFAULT_SLASHING_THRESHOLD: i64 = 10;
const DEFAULT_STAKE_GRACE_PERIOD_SECS: u64 = 300;
const DEFAULT_STAKE_RECOVERY_PERIOD_SECS: u64 = 3600;
const GLOBAL_NODE_STAKE_WEIGHT: f64 = 1.5;
const ORIGIN_NODE_STAKE_WEIGHT: f64 = 1.2;
const EDGE_NODE_STAKE_WEIGHT: f64 = 1.0;

#[derive(
    Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize, JsonSchema,
)]
pub struct StakeConfig {
    #[serde(default = "default_min_stake_for_dht_write")]
    pub min_stake_for_dht_write: i64,
    #[serde(default = "default_min_stake_for_dht_read")]
    pub min_stake_for_dht_read: i64,
    #[serde(default = "default_min_stake_for_routing")]
    pub min_stake_for_routing: i64,
    #[serde(default = "default_slashing_threshold")]
    pub slashing_threshold: i64,
    #[serde(default = "default_stake_grace_period")]
    pub stake_grace_period_secs: u64,
    #[serde(default = "default_stake_recovery_period")]
    pub stake_recovery_period_secs: u64,
    #[serde(default)]
    pub slashing_enabled: bool,
    #[serde(default)]
    pub strict_mode: bool,
}

fn default_min_stake_for_dht_write() -> i64 {
    DEFAULT_MIN_STAKE_FOR_DHT_WRITE
}
fn default_min_stake_for_dht_read() -> i64 {
    DEFAULT_MIN_STAKE_FOR_DHT_READ
}
fn default_min_stake_for_routing() -> i64 {
    DEFAULT_MIN_STAKE_FOR_ROUTING
}
fn default_slashing_threshold() -> i64 {
    DEFAULT_SLASHING_THRESHOLD
}
fn default_stake_grace_period() -> u64 {
    DEFAULT_STAKE_GRACE_PERIOD_SECS
}
fn default_stake_recovery_period() -> u64 {
    DEFAULT_STAKE_RECOVERY_PERIOD_SECS
}

impl Default for StakeConfig {
    fn default() -> Self {
        Self {
            min_stake_for_dht_write: DEFAULT_MIN_STAKE_FOR_DHT_WRITE,
            min_stake_for_dht_read: DEFAULT_MIN_STAKE_FOR_DHT_READ,
            min_stake_for_routing: DEFAULT_MIN_STAKE_FOR_ROUTING,
            slashing_threshold: DEFAULT_SLASHING_THRESHOLD,
            stake_grace_period_secs: DEFAULT_STAKE_GRACE_PERIOD_SECS,
            stake_recovery_period_secs: DEFAULT_STAKE_RECOVERY_PERIOD_SECS,
            slashing_enabled: true,
            strict_mode: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct NodeStake {
    pub node_id: String,
    pub reputation: i64,
    pub role: MeshNodeRole,
    pub stake_weight: f64,
    pub effective_stake: f64,
    pub is_active: bool,
    pub is_slashed: bool,
    pub slashed_at: Option<u64>,
    pub last_update: u64,
    pub grace_period_ends_at: Option<u64>,
}

impl NodeStake {
    pub fn new(node_id: String, reputation: i64, role: MeshNodeRole) -> Self {
        let stake_weight = Self::calculate_weight(&role);
        let effective_stake = reputation as f64 * stake_weight;

        Self {
            node_id,
            reputation,
            role,
            stake_weight,
            effective_stake,
            is_active: false,
            is_slashed: false,
            slashed_at: None,
            last_update: current_timestamp(),
            grace_period_ends_at: None,
        }
    }

    fn calculate_weight(role: &MeshNodeRole) -> f64 {
        if role.is_global() {
            GLOBAL_NODE_STAKE_WEIGHT
        } else if role.is_origin() {
            ORIGIN_NODE_STAKE_WEIGHT
        } else {
            EDGE_NODE_STAKE_WEIGHT
        }
    }

    pub fn update(&mut self, reputation: i64, role: MeshNodeRole) {
        self.reputation = reputation;
        self.role = role;
        self.stake_weight = Self::calculate_weight(&role);
        self.effective_stake = reputation as f64 * self.stake_weight;
        self.last_update = current_timestamp();
    }

    pub fn activate(&mut self) {
        if !self.is_active && !self.is_slashed {
            self.is_active = true;
            self.grace_period_ends_at = None;
        }
    }

    pub fn can_write_to_dht(&self, min_stake: i64) -> bool {
        self.is_active && !self.is_slashed && (self.effective_stake as i64) >= min_stake
    }

    pub fn can_read_from_dht(&self, min_stake: i64) -> bool {
        self.is_active && !self.is_slashed && (self.effective_stake as i64) >= min_stake
    }

    pub fn can_be_in_routing_table(&self, min_stake: i64) -> bool {
        !self.is_slashed && (self.effective_stake as i64) >= min_stake
    }

    pub fn is_in_grace_period(&self) -> bool {
        if let Some(ends_at) = self.grace_period_ends_at {
            current_timestamp() < ends_at
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub enum SlashReason {
    InvalidRecordSignature,
    DhtPoisoning,
    SybilAttack,
    EclipseAttack,
    RepeatedMisbehavior,
    GlobalNodeSlash {
        reason: String,
        evidence: Vec<String>,
    },
}

impl SlashReason {
    pub fn severity(&self) -> &str {
        match self {
            SlashReason::InvalidRecordSignature => "medium",
            SlashReason::DhtPoisoning => "high",
            SlashReason::SybilAttack => "critical",
            SlashReason::EclipseAttack => "critical",
            SlashReason::RepeatedMisbehavior => "medium",
            SlashReason::GlobalNodeSlash { .. } => "high",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct SlashEvent {
    pub node_id: String,
    pub reason: SlashReason,
    pub slashed_at: u64,
    pub slashed_by: String,
    pub evidence: Vec<String>,
    pub recovery_available_at: Option<u64>,
}

pub struct StakeManager {
    config: Arc<StakeConfig>,
    local_node_id: String,
    is_global: bool,
    stakes: RwLock<HashMap<String, NodeStake>>,
    slash_events: RwLock<Vec<SlashEvent>>,
    global_slash_votes: RwLock<HashMap<String, Vec<GlobalSlashVote>>>,
}

#[derive(Debug, Clone)]
pub struct GlobalSlashVote {
    pub voter_node_id: String,
    pub target_node_id: String,
    pub reason: SlashReason,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StakeLevel {
    None,
    ReadOnly,
    Routing,
    Full,
}

impl StakeManager {
    pub fn new(config: StakeConfig, local_node_id: String, is_global: bool) -> Self {
        Self {
            config: Arc::new(config),
            local_node_id,
            is_global,
            stakes: RwLock::new(HashMap::new()),
            slash_events: RwLock::new(Vec::new()),
            global_slash_votes: RwLock::new(HashMap::new()),
        }
    }

    pub fn get_config(&self) -> Arc<StakeConfig> {
        self.config.clone()
    }

    pub fn register_node(
        &self,
        node_id: String,
        reputation: i64,
        role: MeshNodeRole,
        caller_verified_id: Option<&str>,
    ) {
        let mut stakes = self.stakes.write();

        if let Some(caller) = caller_verified_id {
            if node_id != caller {
                tracing::warn!(
                    "Node {} rejected: node_id does not match verified caller identity {}",
                    node_id,
                    caller
                );
                return;
            }
        }

        if let Some(existing) = stakes.get_mut(&node_id) {
            existing.update(reputation, role);
            return;
        }

        let node_id_for_key = node_id.clone();
        let mut stake = NodeStake::new(node_id, reputation, role);
        stake.grace_period_ends_at =
            Some(current_timestamp() + self.config.stake_grace_period_secs);

        stakes.insert(node_id_for_key, stake);
    }

    pub fn unregister_node(&self, node_id: &str) {
        let mut stakes = self.stakes.write();
        stakes.remove(node_id);
    }

    pub fn update_reputation(&self, node_id: &str, reputation: i64, role: MeshNodeRole) {
        let mut stakes = self.stakes.write();
        if let Some(stake) = stakes.get_mut(node_id) {
            stake.update(reputation, role);

            if let Some(grace_end) = stake.grace_period_ends_at {
                if current_timestamp() >= grace_end {
                    stake.activate();
                }
            }
        }
    }

    pub fn sync_from_reputation(
        &self,
        reputation_mgr: &crate::mesh::reputation::ReputationManager,
    ) {
        let peer_ids = reputation_mgr.get_all_peer_ids();

        for node_id in peer_ids {
            if let Some(rep) = reputation_mgr.get_peer_reputation(&node_id) {
                self.update_reputation(&node_id, rep.score, rep.role);
            }
        }

        tracing::debug!("Synced reputation to stake manager");
    }

    pub fn can_write_dht(&self, node_id: &str) -> bool {
        let stakes = self.stakes.read();
        match stakes.get(node_id) {
            Some(s) => s.can_write_to_dht(self.config.min_stake_for_dht_write),
            None => false,
        }
    }

    pub fn can_read_dht(&self, node_id: &str) -> bool {
        let stakes = self.stakes.read();
        stakes
            .get(node_id)
            .map(|s| s.can_read_from_dht(self.config.min_stake_for_dht_read))
            .unwrap_or(false)
    }

    pub fn can_be_in_routing(&self, node_id: &str) -> bool {
        let stakes = self.stakes.read();
        stakes
            .get(node_id)
            .map(|s| {
                s.can_be_in_routing_table(self.config.min_stake_for_routing)
                    && !s.is_in_grace_period()
            })
            .unwrap_or(false)
    }

    pub fn get_stake_level(&self, node_id: &str) -> StakeLevel {
        let stakes = self.stakes.read();
        match stakes.get(node_id) {
            Some(s) if s.is_slashed => StakeLevel::None,
            Some(s) if s.effective_stake as i64 >= self.config.min_stake_for_dht_write => {
                StakeLevel::Full
            }
            Some(s) if s.effective_stake as i64 >= self.config.min_stake_for_routing => {
                StakeLevel::Routing
            }
            Some(s) if s.effective_stake as i64 >= self.config.min_stake_for_dht_read => {
                StakeLevel::ReadOnly
            }
            _ => StakeLevel::None,
        }
    }

    pub fn get_stake_weight(&self, node_id: &str) -> f64 {
        let stakes = self.stakes.read();
        stakes
            .get(node_id)
            .map(|s| s.effective_stake)
            .unwrap_or(0.0)
    }

    pub fn slash_node(
        &self,
        node_id: &str,
        reason: SlashReason,
        slashed_by: &str,
    ) -> Option<SlashEvent> {
        if !self.config.slashing_enabled {
            tracing::debug!("Slashing disabled, ignoring slash request for {}", node_id);
            return None;
        }

        let mut stakes = self.stakes.write();
        let stake = stakes.get_mut(node_id)?;

        if stake.is_slashed {
            tracing::debug!("Node {} already slashed", node_id);
            return None;
        }

        stake.is_slashed = true;
        stake.is_active = false;
        stake.slashed_at = Some(current_timestamp());

        let recovery_available_at = if self.config.stake_recovery_period_secs > 0 {
            Some(current_timestamp() + self.config.stake_recovery_period_secs)
        } else {
            None
        };

        let event = SlashEvent {
            node_id: node_id.to_string(),
            reason: reason.clone(),
            slashed_at: current_timestamp(),
            slashed_by: slashed_by.to_string(),
            evidence: Vec::new(),
            recovery_available_at,
        };

        drop(stakes);

        let mut events = self.slash_events.write();
        events.push(event.clone());

        tracing::warn!(
            "Node {} slashed by {} for {:?}",
            node_id,
            slashed_by,
            reason
        );

        Some(event)
    }

    pub fn attempt_recovery(&self, node_id: &str) -> bool {
        let mut stakes = self.stakes.write();
        if let Some(stake) = stakes.get_mut(node_id) {
            if stake.is_slashed {
                if let Some(recovery_at) = stake.slashed_at {
                    if current_timestamp() >= recovery_at + self.config.stake_recovery_period_secs {
                        stake.is_slashed = false;
                        stake.reputation = 0;
                        stake.effective_stake = 0.0;
                        stake.grace_period_ends_at =
                            Some(current_timestamp() + self.config.stake_grace_period_secs);
                        tracing::info!("Node {} recovered from slashing", node_id);
                        return true;
                    }
                }
            }
        }
        false
    }

    fn get_global_node_count(&self) -> usize {
        let stakes = self.stakes.read();
        stakes.values().filter(|s| s.role.is_global()).count()
    }

    pub fn process_global_slash_vote(&self, vote: GlobalSlashVote) {
        let target_id = vote.target_node_id.clone();
        let mut votes = self.global_slash_votes.write();

        let entry = votes.entry(vote.target_node_id.clone()).or_default();

        if !entry.iter().any(|v| v.voter_node_id == vote.voter_node_id) {
            entry.push(vote);
        }

        let global_count = self.get_global_node_count();
        let quorum = (global_count * 2 / 3).max(1);

        if entry.len() >= quorum {
            if let Some(reason) = entry.first().map(|v| v.reason.clone()) {
                drop(votes);
                self.slash_node(&target_id, reason, "global_committee");
            }
        }
    }

    pub fn submit_global_slash_vote(&self, target_node_id: String, reason: SlashReason) {
        if !self.is_global {
            tracing::warn!("Non-global node attempted to submit global slash vote");
            return;
        }

        let vote = GlobalSlashVote {
            voter_node_id: self.local_node_id.clone(),
            target_node_id,
            reason,
            timestamp: current_timestamp(),
        };

        self.process_global_slash_vote(vote);
    }

    pub fn get_slash_event(&self, node_id: &str) -> Option<SlashEvent> {
        let events = self.slash_events.read();
        events.iter().rfind(|e| e.node_id == node_id).cloned()
    }

    pub fn is_slashed(&self, node_id: &str) -> bool {
        let stakes = self.stakes.read();
        stakes.get(node_id).map(|s| s.is_slashed).unwrap_or(false)
    }

    pub fn manual_slash(&self, node_id: &str, reason: SlashReason, operator: &str) {
        tracing::warn!(
            "Manual slash by {}: node {} for {:?}",
            operator,
            node_id,
            reason
        );
        self.slash_node(node_id, reason, operator);
    }

    pub fn manual_unslash(&self, node_id: &str, operator: &str) {
        let mut stakes = self.stakes.write();
        if let Some(stake) = stakes.get_mut(node_id) {
            if stake.is_slashed {
                stake.is_slashed = false;
                stake.slashed_at = None;
                stake.is_active = true;
                tracing::info!("Manual unslash by {}: node {} restored", operator, node_id);

                let mut events = self.slash_events.write();
                events.retain(|e| e.node_id != node_id);
            }
        }
    }

    pub fn manual_add_peer(&self, node_id: String, reputation: i64, role: MeshNodeRole) {
        let mut stakes = self.stakes.write();
        if stakes.contains_key(&node_id) {
            tracing::debug!("Peer {} already exists in stake manager", node_id);
            return;
        }
        let mut stake = NodeStake::new(node_id.clone(), reputation, role);
        stake.is_active = true;
        stake.activate();
        stakes.insert(node_id.clone(), stake);
        tracing::info!(
            "Manual add: node {} added with reputation {}",
            node_id,
            reputation
        );
    }

    pub fn manual_remove_peer(&self, node_id: &str) {
        let mut stakes = self.stakes.write();
        if stakes.remove(node_id).is_some() {
            tracing::info!("Manual remove: node {} removed from stake manager", node_id);
        }
    }

    pub fn get_all_active_stakes(&self) -> Vec<NodeStake> {
        let stakes = self.stakes.read();
        stakes
            .values()
            .filter(|s| s.is_active && !s.is_slashed)
            .cloned()
            .collect()
    }

    pub fn get_peers_by_stake(&self, count: usize, min_stake: i64) -> Vec<String> {
        let mut all: Vec<_> = {
            let stakes = self.stakes.read();
            stakes
                .values()
                .filter(|s| !s.is_slashed && (s.effective_stake as i64) >= min_stake)
                .map(|s| (s.node_id.clone(), s.effective_stake))
                .collect()
        };

        all.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        all.into_iter().take(count).map(|(id, _)| id).collect()
    }

    pub fn cleanup_expired_slash_records(&self, max_age_secs: u64) {
        let now = current_timestamp();
        let mut events = self.slash_events.write();
        events.retain(|e| {
            if let Some(recovery) = e.recovery_available_at {
                now.saturating_sub(recovery) < max_age_secs
            } else {
                true
            }
        });
    }

    pub fn calculate_stake_weight(reputation: i64, role: &MeshNodeRole) -> f64 {
        let role_weight = match role {
            _ if role.is_global() => GLOBAL_NODE_STAKE_WEIGHT,
            _ if role.is_origin() => ORIGIN_NODE_STAKE_WEIGHT,
            _ => EDGE_NODE_STAKE_WEIGHT,
        };
        reputation as f64 * role_weight
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stake_calculation() {
        let mut config = StakeConfig::default();
        config.stake_grace_period_secs = 0;
        let manager = StakeManager::new(config, "local-node".to_string(), true);

        manager.register_node("global-1".to_string(), 80, MeshNodeRole::GLOBAL, None);
        manager.register_node("origin-1".to_string(), 50, MeshNodeRole::ORIGIN, None);
        manager.register_node("edge-1".to_string(), 60, MeshNodeRole::EDGE, None);

        manager.update_reputation("global-1", 80, MeshNodeRole::GLOBAL);
        manager.update_reputation("origin-1", 50, MeshNodeRole::ORIGIN);
        manager.update_reputation("edge-1", 60, MeshNodeRole::EDGE);

        assert!(manager.can_write_dht("global-1"));
        assert!(manager.can_write_dht("origin-1"));
        assert!(manager.can_write_dht("edge-1"));

        assert_eq!(manager.get_stake_level("global-1"), StakeLevel::Full);
    }

    #[test]
    fn test_slashing() {
        let mut config = StakeConfig::default();
        config.stake_grace_period_secs = 0;
        let manager = StakeManager::new(config, "global-1".to_string(), true);

        manager.register_node("malicious".to_string(), 50, MeshNodeRole::EDGE, None);
        manager.update_reputation("malicious", 50, MeshNodeRole::EDGE);

        assert!(manager.can_write_dht("malicious"));

        manager.slash_node("malicious", SlashReason::DhtPoisoning, "global-1");

        assert!(!manager.can_write_dht("malicious"));
        assert!(manager.is_slashed("malicious"));
    }
}
