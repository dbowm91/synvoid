use crate::mesh::safe_unix_timestamp;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuorumMode {
    Full,
    Regional { max_nodes: usize, min_nodes: usize },
}

impl Default for QuorumMode {
    fn default() -> Self {
        QuorumMode::Full
    }
}

impl QuorumMode {
    pub fn regional(max_nodes: usize, min_nodes: usize) -> Self {
        QuorumMode::Regional {
            max_nodes: max_nodes.max(min_nodes),
            min_nodes: min_nodes.min(max_nodes),
        }
    }

    pub fn is_regional(&self) -> bool {
        matches!(self, QuorumMode::Regional { .. })
    }

    pub fn max_nodes(&self) -> usize {
        match self {
            QuorumMode::Full => usize::MAX,
            QuorumMode::Regional { max_nodes, .. } => *max_nodes,
        }
    }

    pub fn min_nodes(&self) -> usize {
        match self {
            QuorumMode::Full => 3,
            QuorumMode::Regional { min_nodes, .. } => *min_nodes,
        }
    }
}

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
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RejectionReason::DomainTaken => write!(f, "domain_taken"),
            RejectionReason::InvalidFormat => write!(f, "invalid_format"),
            RejectionReason::Unauthorized => write!(f, "unauthorized"),
            RejectionReason::PolicyViolation => write!(f, "policy_violation"),
            RejectionReason::Unknown(s) => write!(f, "{}", s),
        }
    }
}

impl FromStr for RejectionReason {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "domain_taken" => Ok(RejectionReason::DomainTaken),
            "invalid_format" => Ok(RejectionReason::InvalidFormat),
            "unauthorized" => Ok(RejectionReason::Unauthorized),
            "policy_violation" => Ok(RejectionReason::PolicyViolation),
            _ => Ok(RejectionReason::Unknown(s.to_string())),
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
    pub quorum_mode: QuorumMode,
    pub regional_nodes_contacted: Vec<String>,
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
        timeout_secs: u64,
    ) -> Self {
        Self::with_mode(
            request_id,
            key,
            value,
            ttl_seconds,
            origin_node_id,
            origin_signature,
            global_nodes,
            timeout_secs,
            QuorumMode::Full,
        )
    }

    pub fn with_mode(
        request_id: String,
        key: String,
        value: Vec<u8>,
        ttl_seconds: u64,
        origin_node_id: String,
        origin_signature: Vec<u8>,
        global_nodes: &[String],
        timeout_secs: u64,
        quorum_mode: QuorumMode,
    ) -> Self {
        let now = safe_unix_timestamp();
        let regional_nodes_contacted = match quorum_mode {
            QuorumMode::Regional { .. } => Vec::new(),
            QuorumMode::Full => Vec::new(),
        };
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
            deadline: now + timeout_secs,
            quorum_mode,
            regional_nodes_contacted,
        }
    }

    pub fn set_regional_nodes(&mut self, nodes: Vec<String>) {
        self.regional_nodes_contacted = nodes;
    }

    pub fn effective_node_count(&self) -> usize {
        match self.quorum_mode {
            QuorumMode::Full => self.global_nodes_contacted.len(),
            QuorumMode::Regional { .. } => {
                if self.regional_nodes_contacted.is_empty() {
                    self.global_nodes_contacted.len()
                } else {
                    self.regional_nodes_contacted.len()
                }
            }
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

    pub fn add_rejection(
        &mut self,
        node_id: String,
        reason: RejectionReason,
        evidence: Option<Vec<u8>>,
    ) {
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
        let effective = self.effective_node_count_for(total_nodes);
        self.signatures.len() >= Self::required_signatures_for(effective)
    }

    pub fn required_signatures(total_nodes: usize) -> usize {
        Self::required_signatures_for(total_nodes)
    }

    pub fn required_signatures_for(node_count: usize) -> usize {
        if node_count == 0 {
            return 1;
        }
        (node_count * 2 / 3) + 1
    }

    pub fn effective_node_count_for(&self, total_nodes: usize) -> usize {
        match self.quorum_mode {
            QuorumMode::Full => total_nodes,
            QuorumMode::Regional { min_nodes, .. } => {
                let regional = if self.regional_nodes_contacted.is_empty() {
                    total_nodes.min(self.quorum_mode.max_nodes())
                } else {
                    self.regional_nodes_contacted.len()
                };
                regional.max(min_nodes)
            }
        }
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
            return QuorumResult::Rejected {
                rejection,
                verified,
            };
        }

        if self.threshold_met(total_nodes) {
            return QuorumResult::Approved(self.signatures);
        }

        let effective = self.effective_node_count_for(total_nodes);
        QuorumResult::Timeout {
            signatures_collected: self.signatures,
            threshold: Self::required_signatures_for(effective),
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

    pub fn is_verification_enabled(&self) -> bool {
        self.verification_enabled
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

    pub async fn add_signature(
        &self,
        request_id: &str,
        node_id: String,
        signature: Vec<u8>,
    ) -> bool {
        let mut pending = self.pending_requests.write().await;
        if let Some(request) = pending.get_mut(request_id) {
            request.add_signature(node_id, signature);
            true
        } else {
            false
        }
    }

    pub async fn add_rejection(
        &self,
        request_id: &str,
        node_id: String,
        reason: RejectionReason,
        evidence: Option<Vec<u8>>,
    ) {
        let abuse_score = self.get_veto_abuse_score(&node_id).await;
        if abuse_score > 0.5 {
            tracing::warn!(
                "Ignoring rejection from node {} due to high abuse score ({})",
                node_id,
                abuse_score
            );
            return;
        }

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

    pub async fn verify_rejection(
        &self,
        rejection: &QuorumRejection,
        dht_get: impl Fn(&str) -> Option<Vec<u8>>,
    ) -> bool {
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

pub struct GlobalNodeInfo {
    pub node_id: String,
    pub latency_ms: Option<u32>,
}

pub fn select_regional_nodes(
    all_global_nodes: &[GlobalNodeInfo],
    max_nodes: usize,
    min_nodes: usize,
) -> Vec<String> {
    if all_global_nodes.len() <= max_nodes {
        return all_global_nodes.iter().map(|n| n.node_id.clone()).collect();
    }

    let mut sorted: Vec<&GlobalNodeInfo> = all_global_nodes.iter().collect();
    sorted.sort_by(|a, b| {
        let latency_a = a.latency_ms.unwrap_or(u32::MAX);
        let latency_b = b.latency_ms.unwrap_or(u32::MAX);
        latency_a.cmp(&latency_b)
    });

    let count = max_nodes.max(min_nodes).min(sorted.len());
    sorted[..count]
        .iter()
        .map(|n| n.node_id.clone())
        .collect()
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
            &[
                "global1".to_string(),
                "global2".to_string(),
                "global3".to_string(),
            ],
            10,
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
            &[
                "global1".to_string(),
                "global2".to_string(),
                "global3".to_string(),
            ],
            10,
        );

        request.add_rejection("global1".to_string(), RejectionReason::DomainTaken, None);
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
            &[
                "global1".to_string(),
                "global2".to_string(),
                "global3".to_string(),
            ],
            10,
        );

        assert!(!request.threshold_met(3));

        request.add_signature("global1".to_string(), vec![1]);
        assert!(!request.threshold_met(3));

        request.add_signature("global2".to_string(), vec![2]);
        assert!(!request.threshold_met(3));

        request.add_signature("global3".to_string(), vec![3]);
        assert!(request.threshold_met(3));
    }

    #[test]
    fn test_regional_quorum_threshold() {
        let mode = QuorumMode::regional(20, 3);
        let mut request = QuorumRequest::with_mode(
            "req-regional".to_string(),
            "verified_upstream:example.com".to_string(),
            vec![],
            300,
            "origin1".to_string(),
            vec![],
            &(0..50).map(|i| format!("global{}", i)).collect::<Vec<_>>(),
            10,
            mode,
        );

        let regional_nodes: Vec<String> = (0..20).map(|i| format!("global{}", i)).collect();
        request.set_regional_nodes(regional_nodes);

        let effective = request.effective_node_count_for(50);
        assert_eq!(effective, 20);

        let required = QuorumRequest::required_signatures_for(effective);
        assert_eq!(required, 14);

        for i in 0..13 {
            request.add_signature(format!("global{}", i), vec![i as u8]);
        }
        assert!(!request.threshold_met(50));

        request.add_signature("global13".to_string(), vec![13]);
        assert!(request.threshold_met(50));
    }

    #[test]
    fn test_regional_quorum_fallback_to_min() {
        let mode = QuorumMode::regional(20, 5);
        let mut request = QuorumRequest::with_mode(
            "req-regional".to_string(),
            "verified_upstream:example.com".to_string(),
            vec![],
            300,
            "origin1".to_string(),
            vec![],
            &[
                "global1".to_string(),
                "global2".to_string(),
                "global3".to_string(),
            ],
            10,
            mode,
        );

        let regional_nodes = vec!["global1".to_string(), "global2".to_string()];
        request.set_regional_nodes(regional_nodes);

        let effective = request.effective_node_count_for(3);
        assert_eq!(effective, 5);
    }

    #[test]
    fn test_select_regional_nodes_sorts_by_latency() {
        let nodes: Vec<GlobalNodeInfo> = (0..50)
            .map(|i| GlobalNodeInfo {
                node_id: format!("node-{}", i),
                latency_ms: Some(50 - i as u32),
            })
            .collect();

        let selected = select_regional_nodes(&nodes, 20, 3);
        assert_eq!(selected.len(), 20);
        assert_eq!(selected[0], "node-49");
        assert_eq!(selected[19], "node-30");
    }

    #[test]
    fn test_select_regional_nodes_returns_all_when_below_max() {
        let nodes: Vec<GlobalNodeInfo> = (0..5)
            .map(|i| GlobalNodeInfo {
                node_id: format!("node-{}", i),
                latency_ms: Some(i as u32 * 10),
            })
            .collect();

        let selected = select_regional_nodes(&nodes, 20, 3);
        assert_eq!(selected.len(), 5);
    }

    #[test]
    fn test_select_regional_nodes_no_latency_data() {
        let nodes: Vec<GlobalNodeInfo> = (0..30)
            .map(|i| GlobalNodeInfo {
                node_id: format!("node-{}", i),
                latency_ms: None,
            })
            .collect();

        let selected = select_regional_nodes(&nodes, 20, 3);
        assert_eq!(selected.len(), 20);
    }

    #[test]
    fn test_50_node_regional_quorum_simulation() {
        let mode = QuorumMode::regional(20, 3);
        let all_nodes: Vec<String> = (0..50).map(|i| format!("global-{}", i)).collect();

        let mut request = QuorumRequest::with_mode(
            "req-50-node".to_string(),
            "verified_upstream:example.com".to_string(),
            vec![1, 2, 3],
            300,
            "origin1".to_string(),
            vec![],
            &all_nodes,
            10,
            mode,
        );

        let regional: Vec<String> = (0..20).map(|i| format!("global-{}", i)).collect();
        request.set_regional_nodes(regional.clone());

        assert_eq!(request.effective_node_count_for(50), 20);
        let required = QuorumRequest::required_signatures_for(20);
        assert_eq!(required, 14);

        for node_id in &regional[..14] {
            request.add_signature(node_id.clone(), vec![1]);
        }

        assert!(request.threshold_met(50));

        if let QuorumResult::Approved(sigs) = request.into_result(50) {
            assert_eq!(sigs.len(), 14);
        } else {
            panic!("Expected Approved result");
        }
    }

    #[test]
    fn test_full_quorum_mode_unchanged() {
        let mode = QuorumMode::Full;
        assert!(!mode.is_regional());
        assert_eq!(mode.max_nodes(), usize::MAX);

        let request = QuorumRequest::with_mode(
            "req1".to_string(),
            "key".to_string(),
            vec![],
            300,
            "origin1".to_string(),
            vec![],
            &[
                "global1".to_string(),
                "global2".to_string(),
                "global3".to_string(),
            ],
            10,
            mode,
        );

        assert_eq!(request.effective_node_count_for(3), 3);
        assert_eq!(QuorumRequest::required_signatures_for(3), 3);
    }
}
