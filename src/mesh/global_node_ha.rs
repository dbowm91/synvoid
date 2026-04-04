#![allow(dead_code)]

use std::collections::HashMap;

use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GlobalNodeRole {
    Follower,
    Candidate,
    Leader,
}

impl std::fmt::Display for GlobalNodeRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GlobalNodeRole::Follower => write!(f, "Follower"),
            GlobalNodeRole::Candidate => write!(f, "Candidate"),
            GlobalNodeRole::Leader => write!(f, "Leader"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalNodeState {
    pub node_id: String,
    pub role: GlobalNodeRole,
    pub term: u64,
    pub voted_for: Option<String>,
    pub last_heartbeat: u64,
    pub last_election_time: u64,
    pub election_timeout_expires: Option<u64>,
    pub is_leader: bool,
}

impl GlobalNodeState {
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            role: GlobalNodeRole::Follower,
            term: 0,
            voted_for: None,
            last_heartbeat: 0,
            last_election_time: 0,
            election_timeout_expires: None,
            is_leader: false,
        }
    }

    pub fn become_follower(&mut self, term: u64) {
        self.role = GlobalNodeRole::Follower;
        self.term = term;
        self.is_leader = false;
        self.voted_for = None;
    }

    pub fn become_candidate(&mut self) {
        self.role = GlobalNodeRole::Candidate;
        self.term += 1;
        self.voted_for = Some(self.node_id.clone());
    }

    pub fn become_leader(&mut self) {
        self.role = GlobalNodeRole::Leader;
        self.is_leader = true;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRequest {
    pub term: u64,
    pub candidate_id: String,
    pub last_log_index: u64,
    pub last_log_term: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteResponse {
    pub term: u64,
    pub vote_granted: bool,
    pub voter_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMessage {
    pub term: u64,
    pub leader_id: String,
    pub commit_index: u64,
    pub prev_log_index: u64,
    pub prev_log_term: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalNodeHAConfig {
    pub election_timeout_min_ms: u64,
    pub election_timeout_max_ms: u64,
    pub heartbeat_interval_ms: u64,
    pub election_timeout_jitter_ms: u64,
    pub min_election_timeout_ms: u64,
    pub max_global_nodes_for_single_leader: usize,
}

impl Default for GlobalNodeHAConfig {
    fn default() -> Self {
        Self {
            election_timeout_min_ms: 150,
            election_timeout_max_ms: 300,
            heartbeat_interval_ms: 50,
            election_timeout_jitter_ms: 50,
            min_election_timeout_ms: 150,
            max_global_nodes_for_single_leader: 7,
        }
    }
}

pub struct GlobalNodeHAManager {
    node_id: String,
    state: RwLock<GlobalNodeState>,
    votes_received: RwLock<HashMap<String, bool>>,
    known_global_nodes: RwLock<Vec<String>>,
    config: GlobalNodeHAConfig,
    last_election_timeout: RwLock<Option<u64>>,
}

impl GlobalNodeHAManager {
    pub fn new(node_id: String, config: GlobalNodeHAConfig) -> Self {
        let node_id_clone = node_id.clone();
        Self {
            node_id,
            state: RwLock::new(GlobalNodeState::new(node_id_clone)),
            votes_received: RwLock::new(HashMap::new()),
            known_global_nodes: RwLock::new(Vec::new()),
            config,
            last_election_timeout: RwLock::new(None),
        }
    }

    pub async fn get_state(&self) -> GlobalNodeState {
        self.state.read().await.clone()
    }

    pub async fn get_role(&self) -> GlobalNodeRole {
        self.state.read().await.role
    }

    pub async fn is_leader(&self) -> bool {
        self.state.read().await.is_leader
    }

    pub async fn get_term(&self) -> u64 {
        self.state.read().await.term
    }

    pub async fn register_global_node(&self, node_id: &str) {
        let mut nodes = self.known_global_nodes.write().await;
        if !nodes.contains(&node_id.to_string()) {
            nodes.push(node_id.to_string());
        }
    }

    pub async fn unregister_global_node(&self, node_id: &str) {
        let mut nodes = self.known_global_nodes.write().await;
        nodes.retain(|n| n != node_id);
    }

    pub async fn get_global_nodes(&self) -> Vec<String> {
        self.known_global_nodes.read().await.clone()
    }

    pub async fn start_election_if_needed(&self) -> Option<VoteRequest> {
        let mut state = self.state.write().await;
        let now = crate::utils::current_timestamp();

        if state.role == GlobalNodeRole::Leader {
            return None;
        }

        let timeout_expires = state.election_timeout_expires.unwrap_or(0);
        if now < timeout_expires {
            return None;
        }

        state.become_candidate();
        state.last_election_time = now;

        let election_timeout = self.random_election_timeout();
        state.election_timeout_expires = Some(now + election_timeout);
        *self.last_election_timeout.write().await = Some(election_timeout);

        let vote_request = VoteRequest {
            term: state.term,
            candidate_id: state.node_id.clone(),
            last_log_index: 0,
            last_log_term: 0,
        };

        let mut votes = self.votes_received.write().await;
        votes.clear();
        votes.insert(state.node_id.clone(), true);

        Some(vote_request)
    }

    pub async fn handle_vote_request(&self, request: &VoteRequest) -> VoteResponse {
        let mut state = self.state.write().await;
        let voter_id = state.node_id.clone();

        if request.term > state.term {
            state.become_follower(request.term);
        }

        let vote_granted = if request.term < state.term {
            false
        } else if state.voted_for.is_none() || state.voted_for.as_ref() == Some(&request.candidate_id) {
            state.voted_for = Some(request.candidate_id.clone());
            true
        } else {
            false
        };

        VoteResponse {
            term: state.term,
            vote_granted,
            voter_id,
        }
    }

    pub async fn handle_vote_response(&self, response: &VoteResponse) -> bool {
        let mut state = self.state.write().await;

        if response.term > state.term {
            state.become_follower(response.term);
            return false;
        }

        if state.role != GlobalNodeRole::Candidate {
            return false;
        }

        if response.vote_granted {
            let mut votes = self.votes_received.write().await;
            votes.insert(response.voter_id.clone(), true);

            let majority = (self.known_global_nodes.read().await.len() / 2) + 1;
            if votes.values().filter(|v| **v).count() >= majority {
                state.become_leader();
                return true;
            }
        }

        false
    }

    pub async fn handle_heartbeat(&self, heartbeat: &HeartbeatMessage) -> bool {
        let mut state = self.state.write().await;

        if heartbeat.term > state.term {
            state.become_follower(heartbeat.term);
        }

        if heartbeat.term == state.term && state.role != GlobalNodeRole::Leader {
            state.last_heartbeat = crate::utils::current_timestamp();
            state.election_timeout_expires = Some(
                crate::utils::current_timestamp() + self.random_election_timeout()
            );
        }

        heartbeat.term >= state.term
    }

    pub async fn send_heartbeat(&self) -> Option<HeartbeatMessage> {
        let state = self.state.read().await;

        if state.role != GlobalNodeRole::Leader {
            return None;
        }

        Some(HeartbeatMessage {
            term: state.term,
            leader_id: state.node_id.clone(),
            commit_index: 0,
            prev_log_index: 0,
            prev_log_term: 0,
        })
    }

    pub async fn step_down(&self, new_term: u64) {
        let mut state = self.state.write().await;
        if new_term > state.term {
            state.become_follower(new_term);
        }
    }

    fn random_election_timeout(&self) -> u64 {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let base = rng.gen_range(self.config.election_timeout_min_ms..self.config.election_timeout_max_ms);
        let jitter = rng.gen_range(0..self.config.election_timeout_jitter_ms);
        base + jitter
    }

    pub async fn should_start_election(&self) -> bool {
        let state = self.state.read().await;
        let now = crate::utils::current_timestamp();

        if state.role == GlobalNodeRole::Leader {
            return false;
        }

        if let Some(expires) = state.election_timeout_expires {
            return now >= expires;
        }

        true
    }

    pub async fn reset_election_timeout(&self) {
        let mut state = self.state.write().await;
        state.election_timeout_expires = Some(
            crate::utils::current_timestamp() + self.random_election_timeout()
        );
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderInfo {
    pub node_id: String,
    pub term: u64,
    pub last_heartbeat: u64,
    pub global_nodes_count: usize,
}

pub struct GlobalNodeLeaderTracker {
    current_leader: RwLock<Option<LeaderInfo>>,
    leader_history: RwLock<Vec<LeaderInfo>>,
    config: GlobalNodeHAConfig,
}

impl GlobalNodeLeaderTracker {
    pub fn new(config: GlobalNodeHAConfig) -> Self {
        Self {
            current_leader: RwLock::new(None),
            leader_history: RwLock::new(Vec::new()),
            config,
        }
    }

    pub async fn update_leader(&self, node_id: &str, term: u64) {
        let now = crate::utils::current_timestamp();
        let leader_info = LeaderInfo {
            node_id: node_id.to_string(),
            term,
            last_heartbeat: now,
            global_nodes_count: 0,
        };

        *self.current_leader.write().await = Some(leader_info.clone());

        let mut history = self.leader_history.write().await;
        if history.len() >= 100 {
            history.remove(0);
        }
        history.push(leader_info);
    }

    pub async fn get_current_leader(&self) -> Option<LeaderInfo> {
        self.current_leader.read().await.clone()
    }

    pub async fn get_leader_history(&self) -> Vec<LeaderInfo> {
        self.leader_history.read().await.clone()
    }

    pub async fn is_leader_healthy(&self) -> bool {
        if let Some(leader) = self.current_leader.read().await.as_ref() {
            let now = crate::utils::current_timestamp();
            let stale_threshold = self.config.heartbeat_interval_ms * 3;
            return (now - leader.last_heartbeat) < stale_threshold;
        }
        false
    }

    pub async fn clear_leader(&self) {
        *self.current_leader.write().await = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_initial_state() {
        let manager = GlobalNodeHAManager::new("node1".to_string(), GlobalNodeHAConfig::default());
        let state = manager.get_state().await;

        assert_eq!(state.node_id, "node1");
        assert_eq!(state.role, GlobalNodeRole::Follower);
        assert_eq!(state.term, 0);
        assert!(!state.is_leader);
    }

    #[tokio::test]
    async fn test_vote_request() {
        let manager = GlobalNodeHAManager::new("node1".to_string(), GlobalNodeHAConfig::default());

        let response = manager.handle_vote_request(&VoteRequest {
            term: 1,
            candidate_id: "node2".to_string(),
            last_log_index: 0,
            last_log_term: 0,
        }).await;

        assert!(response.vote_granted);
        assert_eq!(response.voter_id, "node1");
    }

    #[tokio::test]
    async fn test_vote_request_stale_term() {
        let manager = GlobalNodeHAManager::new("node1".to_string(), GlobalNodeHAConfig::default());

        let response = manager.handle_vote_request(&VoteRequest {
            term: 0,
            candidate_id: "node2".to_string(),
            last_log_index: 0,
            last_log_term: 0,
        }).await;

        assert!(!response.vote_granted);
    }

    #[tokio::test]
    async fn test_election_win() {
        let manager = GlobalNodeHAManager::new("node1".to_string(), GlobalNodeHAConfig::default());

        manager.register_global_node("node1").await;
        manager.register_global_node("node2").await;
        manager.register_global_node("node3").await;

        let _ = manager.start_election_if_needed().await;

        let won = manager.handle_vote_response(&VoteResponse {
            term: 1,
            vote_granted: true,
            voter_id: "node2".to_string(),
        }).await;

        assert!(!won);

        let won = manager.handle_vote_response(&VoteResponse {
            term: 1,
            vote_granted: true,
            voter_id: "node3".to_string(),
        }).await;

        assert!(won);

        let state = manager.get_state().await;
        assert_eq!(state.role, GlobalNodeRole::Leader);
        assert!(state.is_leader);
    }

    #[tokio::test]
    async fn test_heartbeat() {
        let manager = GlobalNodeHAManager::new("node1".to_string(), GlobalNodeHAConfig::default());

        let accepted = manager.handle_heartbeat(&HeartbeatMessage {
            term: 1,
            leader_id: "node2".to_string(),
            commit_index: 0,
            prev_log_index: 0,
            prev_log_term: 0,
        }).await;

        assert!(accepted);

        let state = manager.get_state().await;
        assert_eq!(state.role, GlobalNodeRole::Follower);
        assert_eq!(state.term, 1);
    }

    #[tokio::test]
    async fn test_leader_tracker() {
        let tracker = GlobalNodeLeaderTracker::new(GlobalNodeHAConfig::default());

        tracker.update_leader("node1", 1).await;

        let leader = tracker.get_current_leader().await;
        assert!(leader.is_some());
        assert_eq!(leader.unwrap().node_id, "node1");
    }
}
