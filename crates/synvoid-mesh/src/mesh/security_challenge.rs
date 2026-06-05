use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use digest::Digest;
use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use rand::Rng;
use sha2::Sha256;

use crate::config::MeshConfig;

const DEFAULT_CHALLENGE_TIMEOUT_SECS: u64 = 60;
const DEFAULT_CHALLENGE_DIFFICULTY: u32 = 24;
const MAX_CHALLENGE_ATTEMPTS: usize = 3;
const CHALLENGE_CACHE_SIZE: usize = 1000;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct MeshSecurityChallenge {
    pub challenge_id: String,
    pub challenge_type: ChallengeType,
    pub difficulty: u32,
    pub created_at: Instant,
    pub expires_at: Instant,
    pub target_node: String,
    pub challenge_data: Vec<u8>,
    pub solution: Option<String>,
    pub verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeType {
    ProofOfWork,
    TimeBased,
    Crypto,
}

pub struct MeshSecurityChallengeManager {
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    config: Arc<MeshConfig>,
    active_challenges: Arc<RwLock<HashMap<String, MeshSecurityChallenge>>>,
    challenge_history: Arc<RwLock<Vec<MeshSecurityChallenge>>>,
    node_challenge_counts: Arc<RwLock<HashMap<String, usize>>>,
}

impl MeshSecurityChallengeManager {
    pub fn new(config: Arc<MeshConfig>) -> Self {
        Self {
            config,
            active_challenges: Arc::new(RwLock::new(HashMap::new())),
            challenge_history: Arc::new(RwLock::new(Vec::new())),
            node_challenge_counts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn generate_proof_of_work_challenge(&self, target_node: &str) -> MeshSecurityChallenge {
        let mut rng = rand::rng();

        let difficulty = DEFAULT_CHALLENGE_DIFFICULTY;
        let prefix: Vec<u8> = (0..8).map(|_| rng.random()).collect();

        let challenge_data = [
            prefix.as_slice(),
            difficulty.to_le_bytes().as_slice(),
            target_node.as_bytes(),
        ]
        .concat();

        let challenge_id = uuid::Uuid::new_v4().to_string();
        let now = Instant::now();

        MeshSecurityChallenge {
            challenge_id: challenge_id.clone(),
            challenge_type: ChallengeType::ProofOfWork,
            difficulty,
            created_at: now,
            expires_at: now + Duration::from_secs(DEFAULT_CHALLENGE_TIMEOUT_SECS),
            target_node: target_node.to_string(),
            challenge_data,
            solution: None,
            verified: false,
        }
    }

    pub fn verify_proof_of_work(&self, challenge_id: &str, solution: &str) -> bool {
        let mut challenges = self.active_challenges.write();

        let challenge = match challenges.get(challenge_id) {
            Some(c) => c.clone(),
            None => {
                tracing::warn!("Challenge {} not found", challenge_id);
                return false;
            }
        };

        if Instant::now() > challenge.expires_at {
            tracing::warn!("Challenge {} has expired", challenge_id);
            challenges.remove(challenge_id);
            return false;
        }

        let solution_bytes = solution.as_bytes();
        let hash =
            sha2::Sha256::digest([challenge.challenge_data.as_slice(), solution_bytes].concat());

        let hash_bytes: [u8; 32] = hash.into();
        let leading_zeros = hash_bytes.iter().take_while(|&&b| b == 0).count();

        if leading_zeros >= challenge.difficulty as usize {
            if let Some(c) = challenges.get_mut(challenge_id) {
                c.solution = Some(solution.to_string());
                c.verified = true;
            }

            let mut history = self.challenge_history.write();
            if let Some(c) = challenges.get(challenge_id) {
                history.push(c.clone());
            }

            if history.len() > CHALLENGE_CACHE_SIZE {
                history.remove(0);
            }

            tracing::info!(
                "Proof of work challenge {} verified successfully",
                challenge_id
            );
            true
        } else {
            tracing::warn!(
                "Proof of work challenge {} failed ({} < {})",
                challenge_id,
                leading_zeros,
                challenge.difficulty
            );
            false
        }
    }

    pub fn generate_time_based_challenge(&self, target_node: &str) -> MeshSecurityChallenge {
        let now = Instant::now();
        let challenge_id = uuid::Uuid::new_v4().to_string();

        let time_window = (now.elapsed().as_secs() / 30) % 100;
        let challenge_data = format!("{}:{}:{}", target_node, time_window, challenge_id);

        let mut mac =
            HmacSha256::new_from_slice(target_node.as_bytes()).expect("HMAC accepts any key size");
        mac.update(challenge_data.as_bytes());
        let expected_solution = hex::encode(mac.finalize().into_bytes());

        MeshSecurityChallenge {
            challenge_id: challenge_id.clone(),
            challenge_type: ChallengeType::TimeBased,
            difficulty: 0,
            created_at: now,
            expires_at: now + Duration::from_secs(5),
            target_node: target_node.to_string(),
            challenge_data: challenge_data.into_bytes(),
            solution: Some(expected_solution),
            verified: false,
        }
    }

    pub fn verify_time_based_challenge(&self, challenge_id: &str, solution: &str) -> bool {
        let mut challenges = self.active_challenges.write();

        let challenge = match challenges.get(challenge_id) {
            Some(c) => c.clone(),
            None => {
                tracing::warn!("Time-based challenge {} not found", challenge_id);
                return false;
            }
        };

        if Instant::now() > challenge.expires_at {
            tracing::warn!("Time-based challenge {} has expired", challenge_id);
            challenges.remove(challenge_id);
            return false;
        }

        let expected_solution = match &challenge.solution {
            Some(s) => s,
            None => {
                tracing::warn!(
                    "Time-based challenge {} has no expected solution",
                    challenge_id
                );
                return false;
            }
        };

        if solution != expected_solution {
            tracing::warn!(
                "Time-based challenge {} verification failed: invalid solution",
                challenge_id
            );
            return false;
        }

        if let Some(c) = challenges.get_mut(challenge_id) {
            c.verified = true;
        }

        let mut history = self.challenge_history.write();
        if let Some(c) = challenges.get(challenge_id) {
            history.push(c.clone());
        }

        tracing::info!(
            "Time-based challenge {} verified successfully",
            challenge_id
        );
        true
    }

    pub fn create_challenge(
        &self,
        target_node: &str,
        challenge_type: ChallengeType,
    ) -> MeshSecurityChallenge {
        let challenge = match challenge_type {
            ChallengeType::ProofOfWork => self.generate_proof_of_work_challenge(target_node),
            ChallengeType::TimeBased => self.generate_time_based_challenge(target_node),
            ChallengeType::Crypto => self.generate_proof_of_work_challenge(target_node),
        };

        let mut challenges = self.active_challenges.write();
        challenges.insert(challenge.challenge_id.clone(), challenge.clone());

        let mut counts = self.node_challenge_counts.write();
        *counts.entry(target_node.to_string()).or_insert(0) += 1;

        challenge
    }

    pub fn verify_challenge(&self, challenge_id: &str, solution: &str) -> bool {
        let challenge_type = {
            let challenges = self.active_challenges.read();
            challenges.get(challenge_id).map(|c| c.challenge_type)
        };

        match challenge_type {
            Some(ChallengeType::ProofOfWork) | Some(ChallengeType::Crypto) => {
                self.verify_proof_of_work(challenge_id, solution)
            }
            Some(ChallengeType::TimeBased) => {
                self.verify_time_based_challenge(challenge_id, solution)
            }
            None => false,
        }
    }

    pub fn is_challenge_valid(&self, challenge_id: &str) -> bool {
        let challenges = self.active_challenges.read();

        if let Some(challenge) = challenges.get(challenge_id) {
            if challenge.verified {
                return false;
            }
            return Instant::now() <= challenge.expires_at;
        }

        false
    }

    pub fn cleanup_expired_challenges(&self) {
        let now = Instant::now();

        let mut challenges = self.active_challenges.write();
        challenges.retain(|_, c| now <= c.expires_at);

        let mut history = self.challenge_history.write();
        history.retain(|c| now.duration_since(c.created_at) < Duration::from_secs(3600));
    }

    pub fn get_node_challenge_count(&self, node_id: &str) -> usize {
        let counts = self.node_challenge_counts.read();
        *counts.get(node_id).unwrap_or(&0)
    }

    pub fn is_node_rate_limited(&self, node_id: &str) -> bool {
        self.get_node_challenge_count(node_id) >= MAX_CHALLENGE_ATTEMPTS * 10
    }
}

pub struct MeshAttackDetector {
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    config: Arc<MeshConfig>,
    suspicious_patterns: Arc<RwLock<Vec<SuspiciousPattern>>>,
    blocked_nodes: Arc<RwLock<std::collections::HashSet<String>>>,
    attack_history: Arc<RwLock<Vec<AttackEvent>>>,
    transport: Arc<RwLock<Option<Arc<crate::transport::MeshTransport>>>>,
}

impl std::fmt::Debug for MeshAttackDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshAttackDetector")
            .field("config", &self.config)
            .field("suspicious_patterns", &self.suspicious_patterns)
            .field("blocked_nodes", &self.blocked_nodes)
            .field("attack_history", &self.attack_history)
            .field("transport", &"<omitted>")
            .finish()
    }
}

impl Clone for MeshAttackDetector {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            suspicious_patterns: self.suspicious_patterns.clone(),
            blocked_nodes: self.blocked_nodes.clone(),
            attack_history: self.attack_history.clone(),
            transport: self.transport.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SuspiciousPattern {
    pub pattern: String,
    pub pattern_type: PatternType,
    pub severity: AttackSeverity,
    pub description: String,
    pub compiled_regex: Option<Arc<regex::Regex>>,
}

impl SuspiciousPattern {
    pub fn new(
        pattern: String,
        pattern_type: PatternType,
        severity: AttackSeverity,
        description: String,
    ) -> Self {
        let compiled_regex = if pattern_type == PatternType::Regex {
            regex::Regex::new(&format!("(?{{max=10000}}){}", pattern))
                .ok()
                .map(Arc::new)
        } else {
            None
        };
        Self {
            pattern,
            pattern_type,
            severity,
            description,
            compiled_regex,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternType {
    Regex,
    Prefix,
    Suffix,
    Contains,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct AttackEvent {
    pub timestamp: Instant,
    pub source_node: String,
    pub attack_type: String,
    pub severity: AttackSeverity,
    pub details: String,
    pub signed_evidence: Option<crate::dht::AuditReceipt>,
}

impl MeshAttackDetector {
    pub fn new(config: Arc<MeshConfig>) -> Self {
        let mut detector = Self {
            config,
            suspicious_patterns: Arc::new(RwLock::new(Vec::new())),
            blocked_nodes: Arc::new(RwLock::new(std::collections::HashSet::new())),
            attack_history: Arc::new(RwLock::new(Vec::new())),
            transport: Arc::new(RwLock::new(None)),
        };

        detector.init_default_patterns();
        detector
    }

    pub fn set_transport(&self, transport: Arc<crate::transport::MeshTransport>) {
        let mut t = self.transport.write();
        *t = Some(transport);
    }

    fn init_default_patterns(&mut self) {
        let patterns = vec![
            SuspiciousPattern::new(
                r"(?i)(union.*select|select.*from|drop\s+table|insert\s+into)".to_string(),
                PatternType::Regex,
                AttackSeverity::High,
                "SQL Injection attempt detected".to_string(),
            ),
            SuspiciousPattern::new(
                r"(?i)<script|javascript:|on\w+\s*=".to_string(),
                PatternType::Regex,
                AttackSeverity::High,
                "XSS attempt detected".to_string(),
            ),
            SuspiciousPattern::new(
                r"\.\./|\.\.\\".to_string(),
                PatternType::Regex,
                AttackSeverity::Medium,
                "Path traversal attempt detected".to_string(),
            ),
            SuspiciousPattern::new(
                r"[;&|`$]".to_string(),
                PatternType::Regex,
                AttackSeverity::High,
                "Command injection attempt detected".to_string(),
            ),
            SuspiciousPattern::new(
                r"http[s]?://".to_string(),
                PatternType::Regex,
                AttackSeverity::Medium,
                "Potential SSRF attempt detected".to_string(),
            ),
        ];

        let mut patterns_guard = self.suspicious_patterns.write();
        *patterns_guard = patterns;
    }

    pub fn add_pattern(&self, pattern: SuspiciousPattern) {
        let mut patterns = self.suspicious_patterns.write();
        patterns.push(pattern);
    }

    pub fn detect_attack(&self, data: &str, source_node: &str) -> Option<AttackEvent> {
        let patterns = self.suspicious_patterns.read();

        for pattern in patterns.iter() {
            let matches = match pattern.pattern_type {
                PatternType::Regex => pattern
                    .compiled_regex
                    .as_ref()
                    .map(|re| re.is_match(data))
                    .unwrap_or(false),
                PatternType::Contains => data.contains(&pattern.pattern),
                PatternType::Prefix => data.starts_with(&pattern.pattern),
                PatternType::Suffix => data.ends_with(&pattern.pattern),
            };

            if matches {
                let event = AttackEvent {
                    timestamp: Instant::now(),
                    source_node: source_node.to_string(),
                    attack_type: pattern.description.clone(),
                    severity: pattern.severity,
                    details: format!("Matched pattern: {}", pattern.pattern),
                    signed_evidence: None,
                };

                self.record_attack(event.clone());

                return Some(event);
            }
        }

        None
    }

    pub fn record_attack(&self, event: AttackEvent) {
        let mut history = self.attack_history.write();
        history.push(event.clone());

        if history.len() > 10000 {
            history.remove(0);
        }

        match event.severity {
            AttackSeverity::Critical | AttackSeverity::High => {
                self.block_node(&event.source_node);
            }
            _ => {}
        }

        tracing::warn!(
            "Mesh attack detected from {}: {} ({:?})",
            event.source_node,
            event.attack_type,
            event.severity
        );
    }

    pub fn block_node(&self, node_id: &str) {
        let mut blocked = self.blocked_nodes.write();
        blocked.insert(node_id.to_string());
        tracing::info!("Node {} blocked due to attack detection", node_id);

        if let Some(transport) = self.transport.read().as_ref() {
            let transport = transport.clone();
            let node_id = node_id.to_string();
            tokio::spawn(async move {
                transport
                    .broadcast_peer_block(&node_id, "attack_detected", 3600, None)
                    .await;
            });
        }
    }

    pub fn unblock_node(&self, node_id: &str) {
        let mut blocked = self.blocked_nodes.write();
        blocked.remove(node_id);
        tracing::info!("Node {} unblocked", node_id);
    }

    pub fn is_blocked(&self, node_id: &str) -> bool {
        let blocked = self.blocked_nodes.read();
        blocked.contains(node_id)
    }

    pub fn get_attack_history(&self, limit: usize) -> Vec<AttackEvent> {
        let history = self.attack_history.read();
        history.iter().rev().take(limit).cloned().collect()
    }

    pub fn get_blocked_nodes(&self) -> Vec<String> {
        let blocked = self.blocked_nodes.read();
        blocked.iter().cloned().collect()
    }

    pub fn cleanup_old_events(&self, max_age: Duration) {
        let now = Instant::now();
        let mut history = self.attack_history.write();
        history.retain(|e| now.duration_since(e.timestamp) < max_age);
    }
}
