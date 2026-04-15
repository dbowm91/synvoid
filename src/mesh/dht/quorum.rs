use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::mesh::safe_unix_timestamp;

#[derive(Debug, Clone)]
pub enum RejectionReason {
    DomainTaken,
    InvalidFormat,
    Unauthorized,
    PolicyViolation,
    Unknown(String),
}

impl RejectionReason {
    pub fn is_verifiable(&self) -> bool {
        matches!(self, RejectionReason::DomainTaken)
    }

    pub fn to_string(&self) -> String {
        match self {
            RejectionReason::DomainTaken => "domain_taken".to_string(),
            RejectionReason::InvalidFormat => "invalid_format".to_string(),
            RejectionReason::Unauthorized => "unauthorized".to_string(),
            RejectionReason::PolicyViolation => "policy_violation".to_string(),
            RejectionReason::Unknown(s) => s.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct QuorumSignature {
    pub node_id: String,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct QuorumRejection {
    pub node_id: String,
    pub reason: RejectionReason,
    pub evidence: Option<Vec<u8>>,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub enum QuorumResult {
    Approved(Vec<QuorumSignature>),
    Rejected {
        rejection: QuorumRejection,
        verified: bool,
    },
    Timeout {
        signatures_collected: Vec<QuorumSignature>,
        threshold: usize,
    },
}

#[derive(Clone)]
pub struct QuorumRequest {
    pub request_id: String,
    pub key: String,
    pub value: Vec<u8>,
    pub ttl_seconds: u64,
    pub origin_node_id: String,
    pub origin_signature: Vec<u8>,
    pub signatures: Vec<QuorumSignature>,
    pub rejections: Vec<QuorumRejection>,
    pub global_nodes_contacted: Vec<String>,
    pub created_at: u64,
    pub deadline: u64,
}

impl QuorumRequest {
    pub fn new(
        request_id: String,
        key: String,
        value: Vec<u8>,
        ttl_seconds: u64,
        origin_node_id: String,
        origin_signature: Vec<u8>,
        global_nodes: &[String],
    ) -> Self {
        let now = safe_unix_timestamp();
        Self {
            request_id,
            key,
            value,
            ttl_seconds,
            origin_node_id,
            origin_signature,
            signatures: Vec::new(),
            rejections: Vec::new(),
            global_nodes_contacted: global_nodes.to_vec(),
            created_at: now,
            deadline: now + 10,
        }
    }

    pub fn add_signature(&mut self, node_id: String, signature: Vec<u8>) {
        if !self.signatures.iter().any(|s| s.node_id == node_id) {
            self.signatures.push(QuorumSignature {
                node_id,
                signature,
                timestamp: safe_unix_timestamp(),
            });
        }
    }

    pub fn add_rejection(&mut self, node_id: String, reason: RejectionReason, evidence: Option<Vec<u8>>) {
        if !self.rejections.iter().any(|r| r.node_id == node_id) {
            self.rejections.push(QuorumRejection {
                node_id,
                reason,
                evidence,
                timestamp: safe_unix_timestamp(),
            });
        }
    }

    pub fn threshold_met(&self, total_nodes: usize) -> bool {
        self.signatures.len() >= Self::required_signatures(total_nodes)
    }

    pub fn required_signatures(total_nodes: usize) -> usize {
        (total_nodes * 2 / 3) + 1
    }

    pub fn is_complete(&self, total_nodes: usize) -> bool {
        self.deadline_passed() || self.threshold_met(total_nodes) || self.has_rejections()
    }

    pub fn deadline_passed(&self) -> bool {
        safe_unix_timestamp() > self.deadline
    }

    pub fn has_rejections(&self) -> bool {
        !self.rejections.is_empty()
    }

    pub fn into_result(self, total_nodes: usize) -> QuorumResult {
        if self.has_rejections() {
            let rejection = self.rejections.first().unwrap().clone();
            let verified = true;
            return QuorumResult::Rejected { rejection, verified };
        }

        if self.threshold_met(total_nodes) {
            return QuorumResult::Approved(self.signatures);
        }

        QuorumResult::Timeout {
            signatures_collected: self.signatures,
            threshold: Self::required_signatures(total_nodes),
        }
    }
}

pub struct QuorumManager {
    pending_requests: Arc<RwLock<HashMap<String, QuorumRequest>>>,
    veto_history: Arc<RwLock<HashMap<String, Vec<RejectedClaim>>>>,
    verification_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct RejectedClaim {
    pub key: String,
    pub reason: RejectionReason,
    pub timestamp: u64,
    pub verified_fruitless: bool,
}

impl QuorumManager {
    pub fn new() -> Self {
        Self {
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            veto_history: Arc::new(RwLock::new(HashMap::new())),
            verification_enabled: true,
        }
    }

    pub async fn start_request(&self, request: QuorumRequest) -> String {
        let request_id = request.request_id.clone();
        let mut pending = self.pending_requests.write().await;
        pending.insert(request_id.clone(), request);
        request_id
    }

    pub async fn get_request(&self, request_id: &str) -> Option<QuorumRequest> {
        let pending = self.pending_requests.read().await;
        pending.get(request_id).cloned()
    }

    pub async fn add_signature(&self, request_id: &str, node_id: String, signature: Vec<u8>) -> bool {
        let mut pending = self.pending_requests.write().await;
        if let Some(request) = pending.get_mut(request_id) {
            request.add_signature(node_id, signature);
            true
        } else {
            false
        }
    }

    pub async fn add_rejection(&self, request_id: &str, node_id: String, reason: RejectionReason, evidence: Option<Vec<u8>>) {
        let mut pending = self.pending_requests.write().await;
        if let Some(request) = pending.get_mut(request_id) {
            request.add_rejection(node_id.clone(), reason.clone(), evidence);
        }

        if reason.is_verifiable() {
            let mut history = self.veto_history.write().await;
            history
                .entry(node_id.clone())
                .or_default()
                .push(RejectedClaim {
                    key: request_id.to_string(),
                    reason,
                    timestamp: safe_unix_timestamp(),
                    verified_fruitless: false,
                });
        }
    }

    pub async fn complete_request(&self, request_id: &str) -> Option<QuorumRequest> {
        let mut pending = self.pending_requests.write().await;
        pending.remove(request_id)
    }

    pub async fn verify_rejection(&self, rejection: &QuorumRejection, dht_get: impl Fn(&str) -> Option<Vec<u8>>) -> bool {
        match &rejection.reason {
            RejectionReason::DomainTaken => {
                let key = &rejection.node_id;
                if dht_get(key).is_some() {
                    true
                } else {
                    let mut history = self.veto_history.write().await;
                    if let Some(claims) = history.get_mut(&rejection.node_id) {
                        if let Some(last) = claims.last_mut() {
                            last.verified_fruitless = true;
                        }
                    }
                    false
                }
            }
            _ => true,
        }
    }

    pub async fn get_veto_abuse_score(&self, node_id: &str) -> f64 {
        let history = self.veto_history.read().await;
        if let Some(claims) = history.get(node_id) {
            let total = claims.len() as f64;
            if total == 0.0 {
                return 0.0;
            }
            let fruitless = claims.iter().filter(|c| c.verified_fruitless).count() as f64;
            fruitless / total
        } else {
            0.0
        }
    }

    pub async fn cleanup_old_entries(&self, max_age_seconds: u64) {
        let now = safe_unix_timestamp();
        let mut pending = self.pending_requests.write().await;
        pending.retain(|_, r| now - r.created_at < max_age_seconds);

        let mut history = self.veto_history.write().await;
        for claims in history.values_mut() {
            claims.retain(|c| now - c.timestamp < 86400);
        }
        history.retain(|_, v| !v.is_empty());
    }
}

impl Default for QuorumManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_required_signatures() {
        assert_eq!(QuorumRequest::required_signatures(3), 3);
        assert_eq!(QuorumRequest::required_signatures(4), 3);
        assert_eq!(QuorumRequest::required_signatures(5), 4);
        assert_eq!(QuorumRequest::required_signatures(6), 5);
    }

    #[tokio::test]
    async fn test_quorum_request_add_signature() {
        let mut request = QuorumRequest::new(
            "req1".to_string(),
            "verified_upstream:example.com".to_string(),
            vec![],
            300,
            "origin1".to_string(),
            vec![],
            &["global1".to_string(), "global2".to_string(), "global3".to_string()],
        );

        request.add_signature("global1".to_string(), vec![1, 2, 3]);
        assert_eq!(request.signatures.len(), 1);

        request.add_signature("global1".to_string(), vec![4, 5, 6]);
        assert_eq!(request.signatures.len(), 1);
    }

    #[tokio::test]
    async fn test_quorum_request_add_rejection() {
        let mut request = QuorumRequest::new(
            "req1".to_string(),
            "verified_upstream:example.com".to_string(),
            vec![],
            300,
            "origin1".to_string(),
            vec![],
            &["global1".to_string(), "global2".to_string(), "global3".to_string()],
        );

        request.add_rejection(
            "global1".to_string(),
            RejectionReason::DomainTaken,
            None,
        );
        assert_eq!(request.rejections.len(), 1);
        assert!(request.has_rejections());
    }

    #[tokio::test]
    async fn test_threshold_met() {
        let mut request = QuorumRequest::new(
            "req1".to_string(),
            "verified_upstream:example.com".to_string(),
            vec![],
            300,
            "origin1".to_string(),
            vec![],
            &["global1".to_string(), "global2".to_string(), "global3".to_string()],
        );

        assert!(!request.threshold_met(3));

        request.add_signature("global1".to_string(), vec![1]);
        assert!(!request.threshold_met(3));

        request.add_signature("global2".to_string(), vec![2]);
        assert!(!request.threshold_met(3));

        request.add_signature("global3".to_string(), vec![3]);
        assert!(request.threshold_met(3));
    }
}
