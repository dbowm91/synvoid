use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct NetworkPolicy {
    pub min_reputation_for_read: i64,
    pub min_reputation_for_write: i64,
    pub blocked_nodes: Vec<BlockedNode>,
    pub last_updated: u64,
    pub updated_by: String,
    pub valid_from: u64,
    pub signature: Vec<u8>,
}

impl NetworkPolicy {
    pub fn new(
        min_reputation_for_read: i64,
        min_reputation_for_write: i64,
        updated_by: String,
    ) -> Self {
        let now = synvoid_utils::safe_unix_timestamp();

        Self {
            min_reputation_for_read,
            min_reputation_for_write,
            blocked_nodes: Vec::new(),
            last_updated: now,
            updated_by,
            valid_from: now,
            signature: Vec::new(),
        }
    }

    pub fn sign(&mut self, signer: &crate::protocol::MeshMessageSigner) {
        let content = self.get_signable_content();
        self.signature = signer.sign(content.as_bytes());
    }

    pub fn get_signable_content(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.min_reputation_for_read,
            self.min_reputation_for_write,
            self.last_updated,
            self.updated_by,
            self.blocked_nodes.len()
        )
    }

    pub fn verify_signature(&self, public_key: &[u8]) -> bool {
        if self.signature.is_empty() {
            return false;
        }
        let content = self.get_signable_content();
        crate::cert::verify_ed25519(&content, &self.signature, public_key)
    }

    pub fn is_expired(&self, max_age_secs: u64) -> bool {
        let now = synvoid_utils::safe_unix_timestamp();
        now.saturating_sub(self.last_updated) > max_age_secs
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct AuditReceipt {
    pub reporter_node_id: String,
    pub target_node_id: String,
    pub evidence_hash: String,
    pub evidence_type: String,
    pub reporter_signature: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct BlockedNode {
    pub node_id: String,
    pub blocked_ip: Option<String>,
    pub blocked_hash: Option<String>,
    pub reason: String,
    pub blocked_at: u64,
    pub blocked_by: String,
    pub expires_at: Option<u64>,
    pub evidence_receipt: Option<AuditReceipt>,
}

impl BlockedNode {
    pub fn new(
        node_id: String,
        blocked_ip: Option<String>,
        blocked_hash: Option<String>,
        reason: String,
        blocked_by: String,
    ) -> Self {
        let now = synvoid_utils::safe_unix_timestamp();

        Self {
            node_id,
            blocked_ip,
            blocked_hash,
            reason,
            blocked_at: now,
            blocked_by,
            expires_at: None,
            evidence_receipt: None,
        }
    }

    pub fn with_evidence(mut self, receipt: AuditReceipt) -> Self {
        self.evidence_receipt = Some(receipt);
        self
    }

    pub fn with_expiry(mut self, duration_secs: u64) -> Self {
        self.expires_at = Some(self.blocked_at + duration_secs);
        self
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let now = synvoid_utils::safe_unix_timestamp();
            now > expires_at
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct GlobalNodeBlocklist {
    pub blocked_nodes: Vec<BlockedNode>,
    pub last_updated: u64,
    pub updated_by: String,
    pub signature: Vec<u8>,
}

impl GlobalNodeBlocklist {
    pub fn new(updated_by: String) -> Self {
        let now = synvoid_utils::safe_unix_timestamp();

        Self {
            blocked_nodes: Vec::new(),
            last_updated: now,
            updated_by,
            signature: Vec::new(),
        }
    }

    pub fn add_block(&mut self, node: BlockedNode) {
        self.blocked_nodes.retain(|b| b.node_id != node.node_id);
        self.blocked_nodes.push(node);
        self.last_updated = synvoid_utils::safe_unix_timestamp();
    }

    pub fn remove_block(&mut self, node_id: &str) {
        self.blocked_nodes.retain(|b| b.node_id != node_id);
        self.last_updated = synvoid_utils::safe_unix_timestamp();
    }

    pub fn is_blocked(&self, node_id: &str, ip: Option<&str>) -> bool {
        self.blocked_nodes.iter().any(|b| {
            if b.node_id == node_id {
                if let Some(blocked_ip) = &b.blocked_ip {
                    if let Some(request_ip) = ip {
                        return blocked_ip == request_ip;
                    }
                }
                return true;
            }
            false
        })
    }

    pub fn sign(&mut self, signer: &crate::protocol::MeshMessageSigner) {
        let content = self.get_signable_content();
        self.signature = signer.sign(content.as_bytes());
    }

    pub fn get_signable_content(&self) -> String {
        format!(
            "{}:{}:{}",
            self.blocked_nodes.len(),
            self.last_updated,
            self.updated_by
        )
    }

    pub fn verify_signature(&self, public_key: &[u8]) -> bool {
        if self.signature.is_empty() {
            return false;
        }
        let content = self.get_signable_content();
        crate::cert::verify_ed25519(&content, &self.signature, public_key)
    }
}

pub const MAX_REPUTATION_THRESHOLD: i64 = 80;
pub const MIN_REPUTATION_THRESHOLD: i64 = 0;

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub enum BotAction {
    Add,
    Remove,
    Update,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct AiBotEntry {
    pub pattern: String,
    pub action: BotAction,
    pub source: String,
    pub timestamp: u64,
    pub expires_at: Option<u64>,
}

impl AiBotEntry {
    pub fn new(pattern: String, action: BotAction, source: String) -> Self {
        Self {
            pattern,
            action,
            source,
            timestamp: synvoid_utils::safe_unix_timestamp(),
            expires_at: None,
        }
    }

    pub fn with_expiry(mut self, duration_secs: u64) -> Self {
        self.expires_at = Some(self.timestamp + duration_secs);
        self
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            synvoid_utils::safe_unix_timestamp() > expires_at
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct GlobalAiBotList {
    pub entries: Vec<AiBotEntry>,
    pub last_updated: u64,
    pub updated_by: String,
    pub signature: Vec<u8>,
}

impl GlobalAiBotList {
    pub fn new(updated_by: String) -> Self {
        Self {
            entries: Vec::new(),
            last_updated: synvoid_utils::safe_unix_timestamp(),
            updated_by,
            signature: Vec::new(),
        }
    }

    pub fn add_entry(&mut self, entry: AiBotEntry) {
        self.entries.retain(|e| e.pattern != entry.pattern);
        self.entries.push(entry);
        self.last_updated = synvoid_utils::safe_unix_timestamp();
    }

    pub fn remove_entry(&mut self, pattern: &str) {
        self.entries.retain(|e| e.pattern != pattern);
        self.last_updated = synvoid_utils::safe_unix_timestamp();
    }

    pub fn sign(&mut self, signer: &crate::protocol::MeshMessageSigner) {
        let content = self.get_signable_content();
        self.signature = signer.sign(content.as_bytes());
    }

    pub fn get_signable_content(&self) -> String {
        format!(
            "{}:{}:{}",
            self.entries.len(),
            self.last_updated,
            self.updated_by
        )
    }

    pub fn verify_signature(&self, public_key: &[u8]) -> bool {
        if self.signature.is_empty() {
            return false;
        }
        let content = self.get_signable_content();
        crate::cert::verify_ed25519(&content, &self.signature, public_key)
    }

    pub fn is_stale(&self, max_age_secs: u64) -> bool {
        let now = synvoid_utils::safe_unix_timestamp();
        now.saturating_sub(self.last_updated) > max_age_secs
    }
}
