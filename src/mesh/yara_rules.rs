use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::mesh::config::{MeshNodeRole, YaraRulesMeshConfig};
use crate::mesh::protocol::MeshMessage;
use crate::upload::yara_rule_feed::YaraRuleFeedManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleSubmission {
    pub submission_id: String,
    pub rules: String,
    pub description: String,
    pub submitted_by: String,
    pub submitted_at: u64,
    pub status: YaraRuleSubmissionStatus,
    pub reviewed_by: Option<String>,
    pub reviewed_at: Option<u64>,
    pub review_notes: Option<String>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum YaraRuleSubmissionStatus {
    Pending,
    Approved,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleVersionInfo {
    pub version: String,
    pub rules: String,
    pub created_at: u64,
    pub created_by: String,
    pub source: YaraRuleSource,
    pub is_approved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum YaraRuleSource {
    Local,
    Feed,
    MeshGlobal,
    MeshEdgeApproved,
}

pub struct YaraRulesManager {
    config: Arc<YaraRulesMeshConfig>,
    node_id: String,
    node_role: MeshNodeRole,
    signer: Option<Arc<crate::mesh::protocol::MeshMessageSigner>>,
    current_version: Arc<RwLock<Option<String>>>,
    local_rules: Arc<RwLock<Option<String>>>,
    submissions: Arc<RwLock<HashMap<String, YaraRuleSubmission>>>,
    last_sync: RwLock<Instant>,
    feed_manager: Option<Arc<YaraRuleFeedManager>>,
    mesh_sender: Arc<RwLock<Option<mpsc::Sender<MeshMessage>>>>,
    data_dir: Option<std::path::PathBuf>,
}

impl YaraRulesManager {
    pub fn new(
        config: YaraRulesMeshConfig,
        node_id: String,
        node_role: MeshNodeRole,
        signer: Option<Arc<crate::mesh::protocol::MeshMessageSigner>>,
        feed_manager: Option<Arc<YaraRuleFeedManager>>,
        data_dir: Option<std::path::PathBuf>,
    ) -> Self {
        let manager = Self {
            config: Arc::new(config),
            node_id,
            node_role,
            signer,
            current_version: Arc::new(RwLock::new(None)),
            local_rules: Arc::new(RwLock::new(None)),
            submissions: Arc::new(RwLock::new(HashMap::new())),
            last_sync: RwLock::new(Instant::now()),
            feed_manager,
            mesh_sender: Arc::new(RwLock::new(None)),
            data_dir,
        };

        if manager.node_role.is_global() || manager.node_role.contains(MeshNodeRole::Global) {
            let _ = manager.load_submissions_from_disk();
        }

        manager
    }

    pub fn set_mesh_sender(&self, sender: mpsc::Sender<MeshMessage>) {
        let mut sender_guard = self.mesh_sender.write();
        *sender_guard = Some(sender);
    }

    pub fn get_current_version(&self) -> Option<String> {
        self.current_version.read().clone()
    }

    pub fn get_current_rules(&self) -> Option<String> {
        self.local_rules.read().clone()
    }

    pub fn has_feed_manager(&self) -> bool {
        self.feed_manager.is_some()
    }

    pub fn get_feed_manager(
        &self,
    ) -> Option<Arc<crate::upload::yara_rule_feed::YaraRuleFeedManager>> {
        self.feed_manager.clone()
    }

    pub fn apply_rules_from_feed(&self) -> Result<String, String> {
        if let Some(ref feed_manager) = self.feed_manager {
            let version = feed_manager.apply_rules()?;
            if let Some(rules) = feed_manager.get_rules_for_scanner() {
                *self.local_rules.write() = Some(rules.clone());
                *self.current_version.write() = Some(version.clone());
                tracing::info!("Applied YARA rules from feed, version: {}", version);
                return Ok(version);
            }
        }
        Err("No feed manager or no applied rules".to_string())
    }

    pub fn apply_rules(
        &self,
        rules: String,
        version: String,
        source: YaraRuleSource,
    ) -> Result<String, String> {
        *self.local_rules.write() = Some(rules.clone());
        *self.current_version.write() = Some(version.clone());

        if let Some(ref fm) = self.feed_manager {
            let source_str = match source {
                YaraRuleSource::Local => "Local",
                YaraRuleSource::Feed => "Feed",
                YaraRuleSource::MeshGlobal => "Mesh",
                YaraRuleSource::MeshEdgeApproved => "MeshApproved",
            };
            fm.add_to_history_inline(version.clone(), rules, source_str.to_string());
        }

        tracing::info!("Applied YARA rules version {} from {:?}", version, source);
        Ok(version)
    }

    pub fn submit_rule_for_approval(
        &self,
        rules: String,
        description: String,
    ) -> Result<String, String> {
        if !self.config.allow_edge_submissions {
            return Err("Edge submissions are disabled".to_string());
        }

        if !self.node_role.is_edge() && !self.node_role.contains(MeshNodeRole::EDGE) {
            return Err("Only edge nodes can submit rules".to_string());
        }

        let submission_id = uuid::Uuid::new_v4().to_string();
        let submission_id_clone = submission_id.clone();
        let now = crate::mesh::safe_unix_timestamp();

        let mut signature = Vec::new();
        if let Some(ref signer) = self.signer {
            let content = format!("{}:{}:{}:{}", submission_id, rules.len(), self.node_id, now);
            signature = signer.sign(&content);
        }

        let submission = YaraRuleSubmission {
            submission_id: submission_id.clone(),
            rules,
            submitted_by: self.node_id.clone(),
            submitted_at: now,
            description,
            status: YaraRuleSubmissionStatus::Pending,
            reviewed_by: None,
            reviewed_at: None,
            review_notes: None,
            signature,
        };

        let submission_clone = submission.clone();
        self.submissions
            .write()
            .insert(submission_id.clone(), submission);

        if let Err(e) = self.save_submission_to_disk(&submission_clone) {
            tracing::warn!("Failed to save submission to disk: {}", e);
        }

        self.broadcast_submission(&submission_clone)?;

        tracing::info!("Submitted YARA rules for approval: {}", submission_id_clone);
        Ok(submission_id_clone)
    }

    fn broadcast_submission(&self, submission: &YaraRuleSubmission) -> Result<(), String> {
        let sender = self.mesh_sender.read();
        if let Some(ref sender) = *sender {
            let signer_public_key = self
                .signer
                .as_ref()
                .map(|s| s.get_public_key())
                .unwrap_or_default();

            let message = MeshMessage::YaraRuleSubmission {
                request_id: submission.submission_id.clone().into(),
                submission_id: submission.submission_id.clone().into(),
                node_id: submission.submitted_by.clone().into(),
                timestamp: submission.submitted_at,
                signature: submission.signature.clone(),
                rules: submission.rules.clone(),
                description: submission.description.clone(),
                signer_public_key,
            };

            let sender_clone = sender.clone();
            tokio::spawn(async move {
                let _ = sender_clone.send(message).await;
            });
        }
        Ok(())
    }

    pub fn approve_submission(
        &self,
        submission_id: &str,
        review_notes: Option<String>,
    ) -> Result<String, String> {
        if !self.node_role.is_global() && !self.node_role.contains(MeshNodeRole::Global) {
            return Err("Only global nodes can approve submissions".to_string());
        }

        let mut submissions = self.submissions.write();
        let submission = submissions
            .get_mut(submission_id)
            .ok_or("Submission not found")?;

        if submission.status != YaraRuleSubmissionStatus::Pending {
            return Err("Submission already processed".to_string());
        }

        let now = crate::mesh::safe_unix_timestamp();

        submission.status = YaraRuleSubmissionStatus::Approved;
        submission.reviewed_by = Some(self.node_id.clone());
        submission.reviewed_at = Some(now);
        submission.review_notes = review_notes;

        let rules = submission.rules.clone();
        let submission_id_str = submission.submission_id.clone();
        let version = format!("edge-{}-{}", &submission_id_str[..8], now);

        drop(submissions);

        self.apply_rules(rules, version.clone(), YaraRuleSource::MeshEdgeApproved)?;

        let _ = self.delete_submission_from_disk(submission_id);

        self.broadcast_approved_rules(&version)?;

        tracing::info!("Approved YARA rule submission: {}", version);
        Ok(version)
    }

    pub fn reject_submission(
        &self,
        submission_id: &str,
        review_notes: String,
    ) -> Result<(), String> {
        if !self.node_role.is_global() && !self.node_role.contains(MeshNodeRole::Global) {
            return Err("Only global nodes can reject submissions".to_string());
        }

        let mut submissions = self.submissions.write();
        let submission = submissions
            .get_mut(submission_id)
            .ok_or("Submission not found")?;

        if submission.status != YaraRuleSubmissionStatus::Pending {
            return Err("Submission already processed".to_string());
        }

        let now = crate::mesh::safe_unix_timestamp();

        submission.status = YaraRuleSubmissionStatus::Rejected;
        submission.reviewed_by = Some(self.node_id.clone());
        submission.reviewed_at = Some(now);
        submission.review_notes = Some(review_notes);

        let _ = self.delete_submission_from_disk(submission_id);

        tracing::info!("Rejected YARA rule submission: {}", submission_id);
        Ok(())
    }

    pub fn get_pending_submissions(&self) -> Vec<YaraRuleSubmission> {
        self.submissions
            .read()
            .values()
            .filter(|s| s.status == YaraRuleSubmissionStatus::Pending)
            .cloned()
            .collect()
    }

    pub fn get_submission(&self, submission_id: &str) -> Option<YaraRuleSubmission> {
        self.submissions.read().get(submission_id).cloned()
    }

    fn broadcast_approved_rules(&self, version: &str) -> Result<(), String> {
        let sender = self.mesh_sender.read();
        if let Some(ref sender) = *sender {
            let rules = self.local_rules.read().clone().ok_or("No local rules")?;

            let signer_public_key = self
                .signer
                .as_ref()
                .map(|s| s.get_public_key())
                .unwrap_or_default();

            let message = MeshMessage::YaraRuleAnnounce {
                request_id: uuid::Uuid::new_v4().to_string().into(),
                version: version.into(),
                rules,
                timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
                source_node_id: self.node_id.clone().into(),
                source_role: self.node_role,
                signature: Vec::new(),
                signer_public_key,
            };

            let sender_clone = sender.clone();
            tokio::spawn(async move {
                let _ = sender_clone.send(message).await;
            });
        }
        Ok(())
    }

    pub fn should_sync(&self) -> bool {
        if !self.config.enabled {
            return false;
        }

        let last = *self.last_sync.read();
        last.elapsed() > Duration::from_secs(self.config.sync_interval_secs)
    }

    pub fn record_sync(&self) {
        *self.last_sync.write() = Instant::now();
    }

    fn submissions_dir(&self) -> Option<std::path::PathBuf> {
        self.data_dir.as_ref().map(|d| d.join("yara_submissions"))
    }

    fn save_submission_to_disk(&self, submission: &YaraRuleSubmission) -> Result<(), String> {
        let Some(dir) = self.submissions_dir() else {
            return Ok(());
        };

        let path = dir.join(format!("{}.json", submission.submission_id));

        let json = serde_json::to_string_pretty(submission)
            .map_err(|e| format!("Failed to serialize submission: {}", e))?;

        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create submissions dir: {}", e))?;

        std::fs::write(&path, json).map_err(|e| format!("Failed to write submission: {}", e))?;

        tracing::debug!("Saved submission {} to disk", submission.submission_id);
        Ok(())
    }

    fn load_submissions_from_disk(&self) -> Result<(), String> {
        let Some(dir) = self.submissions_dir() else {
            return Ok(());
        };

        if !dir.exists() {
            return Ok(());
        }

        let entries = std::fs::read_dir(&dir)
            .map_err(|e| format!("Failed to read submissions dir: {}", e))?;

        let mut loaded = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                match std::fs::read_to_string(&path) {
                    Ok(content) => match serde_json::from_str::<YaraRuleSubmission>(&content) {
                        Ok(submission) => {
                            if submission.status == YaraRuleSubmissionStatus::Pending {
                                self.submissions
                                    .write()
                                    .insert(submission.submission_id.clone(), submission);
                                loaded += 1;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to parse submission {:?}: {}", path, e);
                        }
                    },
                    Err(e) => {
                        tracing::warn!("Failed to read submission {:?}: {}", path, e);
                    }
                }
            }
        }

        if loaded > 0 {
            tracing::info!("Loaded {} pending YARA rule submissions from disk", loaded);
        }

        Ok(())
    }

    pub fn delete_submission_from_disk(&self, submission_id: &str) -> Result<(), String> {
        let Some(dir) = self.submissions_dir() else {
            return Ok(());
        };

        let path = dir.join(format!("{}.json", submission_id));

        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| format!("Failed to delete submission: {}", e))?;
            tracing::debug!("Deleted submission {} from disk", submission_id);
        }

        Ok(())
    }

    pub fn request_sync_from_global(&self) -> Option<MeshMessage> {
        if !self.config.enabled {
            return None;
        }

        Some(MeshMessage::YaraRuleSyncRequest {
            request_id: uuid::Uuid::new_v4().to_string().into(),
            node_id: self.node_id.clone().into(),
            version: self.current_version.read().clone(),
        })
    }

    pub fn handle_incoming_rules(
        &self,
        version: String,
        rules: String,
        _from_node: &str,
    ) -> Result<String, String> {
        if rules.len() > (self.config.max_rules_size_kb as usize) * 1024 {
            return Err("Rules size exceeds limit".to_string());
        }

        let current = self.current_version.read();
        if let Some(ref current_ver) = *current {
            if !crate::utils::is_newer_version(&version, current_ver) {
                return Err("Received rules are not newer".to_string());
            }
        }
        drop(current);

        self.apply_rules(rules, version, YaraRuleSource::MeshGlobal)
    }

    pub fn handle_mesh_message(
        &self,
        message: &MeshMessage,
        from_node: &str,
    ) -> Option<MeshMessage> {
        match message {
            MeshMessage::YaraRuleAnnounce {
                request_id,
                version,
                rules,
                timestamp: _,
                source_node_id: _,
                source_role: _,
                signature: _,
                signer_public_key: _,
            } => {
                tracing::info!(
                    "Received YARA rule announce from {}: version {}",
                    from_node,
                    version
                );

                if let Err(e) =
                    self.handle_incoming_rules(version.clone(), rules.clone(), from_node)
                {
                    tracing::warn!("Failed to apply incoming YARA rules: {}", e);
                }

                Some(MeshMessage::YaraRuleAcknowledgement {
                    original_request_id: request_id.clone(),
                    node_id: self.node_id.clone().into(),
                    accepted: true,
                    reason: "Rules applied".into(),
                    timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
                })
            }
            MeshMessage::YaraRuleSyncRequest {
                request_id,
                node_id: _,
                version,
            } => {
                tracing::debug!(
                    "Received YARA rule sync request from {} (current: {:?})",
                    from_node,
                    version
                );

                if let Some(rules) = self.local_rules.read().clone() {
                    let ver = self.current_version.read().clone();
                    let signer_public_key = self
                        .signer
                        .as_ref()
                        .map(|s| s.get_public_key())
                        .unwrap_or_default();
                    Some(MeshMessage::YaraRuleSyncResponse {
                        request_id: request_id.clone(),
                        version: ver.unwrap_or_default(),
                        rules,
                        is_full: true,
                        timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
                        signature: Vec::new(),
                        signer_public_key,
                    })
                } else {
                    None
                }
            }
            MeshMessage::YaraRuleSyncResponse {
                request_id: _,
                version,
                rules,
                is_full: _,
                timestamp: _,
                signature: _,
                ..
            } => {
                tracing::info!(
                    "Received YARA rule sync response from {}: version {}",
                    from_node,
                    version
                );

                if let Err(e) =
                    self.handle_incoming_rules(version.clone(), rules.clone(), from_node)
                {
                    tracing::warn!("Failed to apply synced YARA rules: {}", e);
                }

                None
            }
            MeshMessage::YaraRuleSubmission {
                request_id,
                submission_id,
                node_id,
                timestamp: _,
                signature,
                rules,
                description,
                signer_public_key: _,
            } => {
                tracing::info!(
                    "Received YARA rule submission from {}: {}",
                    from_node,
                    submission_id
                );

                if self.node_role.is_global() || self.node_role.contains(MeshNodeRole::Global) {
                    let submission = YaraRuleSubmission {
                        submission_id: submission_id.to_string(),
                        rules: rules.clone(),
                        description: description.clone(),
                        submitted_by: node_id.to_string(),
                        submitted_at: crate::mesh::protocol::MeshMessage::generate_timestamp(),
                        status: YaraRuleSubmissionStatus::Pending,
                        reviewed_by: None,
                        reviewed_at: None,
                        review_notes: None,
                        signature: signature.clone(),
                    };

                    let submission_id_str = submission.submission_id.clone();
                    self.submissions
                        .write()
                        .insert(submission_id_str.clone(), submission.clone());

                    if let Err(e) = self.save_submission_to_disk(&submission) {
                        tracing::warn!("Failed to save submission to disk: {}", e);
                    }

                    tracing::info!(
                        "Stored YARA rule submission {} for review",
                        submission_id_str
                    );

                    Some(MeshMessage::YaraRuleSubmissionResponse {
                        original_request_id: request_id.clone(),
                        submission_id: submission_id.clone(),
                        node_id: self.node_id.clone().into(),
                        status: "pending".into(),
                        timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
                    })
                } else {
                    None
                }
            }
            MeshMessage::YaraRuleAcknowledgement {
                original_request_id: _,
                node_id: _,
                accepted,
                reason,
                timestamp: _,
            } => {
                tracing::debug!(
                    "YARA rule ack from {}: accepted={}, reason={}",
                    from_node,
                    accepted,
                    reason
                );
                None
            }
            MeshMessage::YaraRuleSubmissionResponse {
                original_request_id: _,
                submission_id: _,
                node_id: _,
                status: _,
                timestamp: _,
            } => None,
            _ => None,
        }
    }

    pub fn get_stats(&self) -> YaraRulesStats {
        YaraRulesStats {
            node_id: self.node_id.clone(),
            node_role: self.node_role,
            current_version: self.current_version.read().clone(),
            pending_submissions: self
                .submissions
                .read()
                .values()
                .filter(|s| s.status == YaraRuleSubmissionStatus::Pending)
                .count(),
            total_submissions: self.submissions.read().len(),
            last_sync: *self.last_sync.read(),
            is_global: self.node_role.is_global() || self.node_role.contains(MeshNodeRole::Global),
        }
    }
}

#[derive(Debug, Clone)]
pub struct YaraRulesStats {
    pub node_id: String,
    pub node_role: MeshNodeRole,
    pub current_version: Option<String>,
    pub pending_submissions: usize,
    pub total_submissions: usize,
    pub last_sync: Instant,
    pub is_global: bool,
}

impl Clone for YaraRulesManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            node_id: self.node_id.clone(),
            node_role: self.node_role,
            signer: self.signer.clone(),
            current_version: Arc::clone(&self.current_version),
            local_rules: Arc::clone(&self.local_rules),
            submissions: Arc::clone(&self.submissions),
            last_sync: RwLock::new(*self.last_sync.read()),
            feed_manager: self.feed_manager.clone(),
            mesh_sender: Arc::clone(&self.mesh_sender),
            data_dir: self.data_dir.clone(),
        }
    }
}
