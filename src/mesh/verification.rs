use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::mesh::dht::keys::DhtKey;
use crate::mesh::dht::{
    OriginPenalty, OriginReachability, ReachabilityStatus, VerificationStatus, VerificationTask,
};
use crate::mesh::safe_unix_timestamp;

const DEFAULT_REACHABILITY_TTL_SECS: u64 = 60;
const DEFAULT_PENALTY_TTL_SECS: u64 = 600;
const DEFAULT_PENALTY_INITIAL: i32 = -20;
const DEFAULT_PENALTY_RECOVERY_RATE: i32 = 5;
const DEFAULT_PENALTY_RECOVERY_INTERVAL_SECS: u64 = 600;
const DEFAULT_MAX_PENALTIES_PER_TTL: usize = 1;

#[derive(Clone)]
pub struct VerificationTaskManager {
    record_store: Arc<RwLock<Option<Arc<crate::mesh::dht::RecordStoreManager>>>>,
    node_id: String,
    config: VerificationConfig,
    pending_tasks: Arc<RwLock<HashMap<String, Instant>>>,
}

#[derive(Clone)]
pub struct VerificationConfig {
    pub reachability_ttl_secs: u64,
    pub penalty_ttl_secs: u64,
    pub penalty_initial: i32,
    pub penalty_recovery_rate: i32,
    pub penalty_recovery_interval_secs: u64,
    pub max_penalties_per_ttl: usize,
    pub verification_nodes_count: usize,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            reachability_ttl_secs: DEFAULT_REACHABILITY_TTL_SECS,
            penalty_ttl_secs: DEFAULT_PENALTY_TTL_SECS,
            penalty_initial: DEFAULT_PENALTY_INITIAL,
            penalty_recovery_rate: DEFAULT_PENALTY_RECOVERY_RATE,
            penalty_recovery_interval_secs: DEFAULT_PENALTY_RECOVERY_INTERVAL_SECS,
            max_penalties_per_ttl: DEFAULT_MAX_PENALTIES_PER_TTL,
            verification_nodes_count: 3,
        }
    }
}

impl VerificationTaskManager {
    pub fn new(node_id: String, config: VerificationConfig) -> Self {
        Self {
            record_store: Arc::new(RwLock::new(None)),
            node_id,
            config,
            pending_tasks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn get_verification_nodes_count(&self) -> usize {
        self.config.verification_nodes_count
    }

    pub fn set_record_store(&self, record_store: Arc<crate::mesh::dht::RecordStoreManager>) {
        let mut rs = self.record_store.write();
        *rs = Some(record_store);
    }

    pub fn report_reachability(
        &self,
        upstream_id: &str,
        provider_node_id: &str,
        status: ReachabilityStatus,
        latency_ms: u32,
        error_rate: f32,
        consecutive_failures: u32,
    ) {
        let record_store_opt = self.record_store.read().clone();
        let Some(record_store) = record_store_opt else {
            tracing::debug!("Record store not available for reachability report");
            return;
        };

        let reachability = OriginReachability {
            upstream_id: upstream_id.to_string(),
            provider_node_id: provider_node_id.to_string(),
            status,
            latency_ms,
            error_rate,
            consecutive_failures,
            timestamp: safe_unix_timestamp(),
        };

        let key = DhtKey::origin_reachability(upstream_id, provider_node_id);
        let key_str = key.as_str();

        if let Ok(value) = serde_json::to_vec(&reachability) {
            if record_store.store_and_announce(
                key_str.to_string(),
                value,
                self.config.reachability_ttl_secs,
            ) {
                tracing::debug!(
                    "Stored reachability for {}:{} - status: {:?}",
                    upstream_id,
                    provider_node_id,
                    status
                );
            }
        }

        if status == ReachabilityStatus::Failed || consecutive_failures >= 3 {
            self.initiate_verification_if_needed(upstream_id, provider_node_id);
        }
    }

    fn initiate_verification_if_needed(&self, upstream_id: &str, provider_node_id: &str) {
        let task_key = format!("{}:{}", upstream_id, provider_node_id);

        {
            let pending = self.pending_tasks.read();
            if pending.contains_key(&task_key) {
                tracing::debug!("Verification already pending for {}", task_key);
                return;
            }
        }

        let record_store_opt = self.record_store.read().clone();
        let Some(record_store) = record_store_opt else {
            return;
        };

        let key = DhtKey::verification_task(upstream_id, provider_node_id);
        let key_str = key.as_str();

        if let Some(existing) = record_store.get(&key_str) {
            if let Ok(task) = serde_json::from_slice::<VerificationTask>(&existing.value) {
                if task.status == VerificationStatus::InProgress
                    || task.status == VerificationStatus::Pending
                {
                    tracing::debug!("Verification task already exists for {}", task_key);
                    return;
                }
            }
        }

        let now = safe_unix_timestamp();
        let task = VerificationTask {
            upstream_id: upstream_id.to_string(),
            provider_node_id: provider_node_id.to_string(),
            status: VerificationStatus::Pending,
            reporting_node_id: self.node_id.clone(),
            created_at: now,
            expires_at: now + self.config.penalty_ttl_secs,
            verification_node_ids: Vec::new(),
            verification_results: Vec::new(),
        };

        if let Ok(value) = serde_json::to_vec(&task) {
            if record_store.store_and_announce(
                key_str.to_string(),
                value,
                self.config.penalty_ttl_secs,
            ) {
                tracing::info!(
                    "Created verification task for {}:{}",
                    upstream_id,
                    provider_node_id
                );
                let mut pending = self.pending_tasks.write();
                pending.insert(task_key, Instant::now());
            }
        }
    }

    pub fn apply_penalty(
        &self,
        upstream_id: &str,
        provider_node_id: &str,
    ) -> Option<OriginPenalty> {
        let record_store_opt = self.record_store.read().clone();
        let Some(record_store) = record_store_opt else {
            return None;
        };

        let key = DhtKey::origin_penalty(upstream_id, provider_node_id);
        let key_str = key.as_str();

        let existing_penalty = record_store.get(&key_str);

        let current_penalty = if let Some(record) = existing_penalty {
            if let Ok(penalty) = serde_json::from_slice::<OriginPenalty>(&record.value) {
                let now = safe_unix_timestamp();
                let recovery_intervals =
                    (now - penalty.last_updated) / self.config.penalty_recovery_interval_secs;

                // Exponential backoff: penalty halves every interval
                let mut new_score = penalty.penalty_score as f32;
                for _ in 0..recovery_intervals {
                    new_score *= 0.5;
                }

                let new_penalty = (new_score.round() as i32).min(0);
                Some((penalty, new_penalty, now))
            } else {
                None
            }
        } else {
            None
        };

        let (penalty_score, last_updated) = match current_penalty {
            Some((_, new_score, time)) => (new_score, time),
            None => (self.config.penalty_initial, safe_unix_timestamp()),
        };

        let now = safe_unix_timestamp();
        let penalty = OriginPenalty {
            upstream_id: upstream_id.to_string(),
            provider_node_id: provider_node_id.to_string(),
            penalty_score,
            created_at: current_penalty.map(|(p, _, _)| p.created_at).unwrap_or(now),
            last_updated,
            expires_at: now + self.config.penalty_ttl_secs,
            applied_by: self.node_id.clone(),
        };

        if let Ok(value) = serde_json::to_vec(&penalty) {
            if record_store.store_and_announce(
                key_str.to_string(),
                value,
                self.config.penalty_ttl_secs,
            ) {
                tracing::info!(
                    "Applied penalty {} to {}:{}",
                    penalty_score,
                    upstream_id,
                    provider_node_id
                );
                return Some(penalty);
            }
        }

        None
    }

    pub fn get_penalty(&self, upstream_id: &str, provider_node_id: &str) -> Option<OriginPenalty> {
        let record_store_opt = self.record_store.read().clone();
        let Some(record_store) = record_store_opt else {
            return None;
        };

        let key = DhtKey::origin_penalty(upstream_id, provider_node_id);
        let key_str = key.as_str();

        if let Some(record) = record_store.get(&key_str) {
            if let Ok(penalty) = serde_json::from_slice::<OriginPenalty>(&record.value) {
                let now = safe_unix_timestamp();
                if penalty.expires_at > now {
                    return Some(penalty);
                }
            }
        }

        None
    }

    pub fn cleanup_expired_tasks(&self) {
        let mut pending = self.pending_tasks.write();
        pending.retain(|_, instant| {
            instant.elapsed() < Duration::from_secs(self.config.penalty_ttl_secs)
        });
    }

    pub fn record_verification_result(
        &self,
        upstream_id: &str,
        provider_node_id: &str,
        verifying_node_id: &str,
        verified: bool,
    ) {
        tracing::info!(
            "Verification result for {} (provider: {}) from node {}: verified={}",
            upstream_id,
            provider_node_id,
            verifying_node_id,
            verified
        );

        let record_store_opt = self.record_store.read().clone();
        let Some(record_store) = record_store_opt else {
            tracing::debug!("Record store not available for verification result");
            return;
        };

        let key = DhtKey::verification_task(upstream_id, provider_node_id);
        let key_str = key.as_str();

        let task_opt = record_store.get(&key_str);

        let Some(task_record) = task_opt else {
            tracing::debug!(
                "No verification task found for {}:{}",
                upstream_id,
                provider_node_id
            );
            return;
        };

        let mut task = match serde_json::from_slice::<crate::mesh::dht::VerificationTask>(
            &task_record.value,
        ) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("Failed to deserialize verification task: {}", e);
                return;
            }
        };

        let task_key = format!("{}:{}", upstream_id, provider_node_id);

        if task.status != crate::mesh::dht::VerificationStatus::InProgress {
            tracing::debug!("Verification task not in progress, ignoring result");
            return;
        }

        if task
            .verification_results
            .iter()
            .any(|r| r.node_id == verifying_node_id)
        {
            tracing::debug!("Already received result from node {}", verifying_node_id);
            return;
        }

        task.verification_results
            .push(crate::mesh::dht::VerificationResult {
                node_id: verifying_node_id.to_string(),
                verified,
                timestamp: safe_unix_timestamp(),
            });

        let total_responses = task.verification_results.len();
        let total_expected = task.verification_node_ids.len();
        let failure_count = task
            .verification_results
            .iter()
            .filter(|r| !r.verified)
            .count();
        let success_count = task
            .verification_results
            .iter()
            .filter(|r| r.verified)
            .count();

        let threshold = std::cmp::min(self.config.verification_nodes_count, total_expected.max(1));

        tracing::info!(
            "Verification progress for {}: {}/{} responses, {} failures, {} successes (threshold: {})",
            task_key,
            total_responses,
            total_expected,
            failure_count,
            success_count,
            threshold
        );

        if total_responses >= total_expected {
            task.status = crate::mesh::dht::VerificationStatus::Completed;

            if failure_count >= threshold {
                tracing::warn!(
                    "Applying penalty to {}: {} out of {} nodes reported failure (threshold: {})",
                    task_key,
                    failure_count,
                    total_responses,
                    threshold
                );
                self.apply_penalty(upstream_id, provider_node_id);
            } else {
                tracing::info!(
                    "Not applying penalty to {}: only {} failures out of {} (threshold: {})",
                    task_key,
                    failure_count,
                    total_responses,
                    threshold
                );
            }
        }

        if let Ok(value) = serde_json::to_vec(&task) {
            let _ = record_store.store_and_announce(
                key_str.to_string(),
                value,
                self.config.penalty_ttl_secs,
            );
        }
    }

    pub fn process_pending_tasks(&self) {
        let record_store_opt = self.record_store.read().clone();
        let Some(record_store) = record_store_opt else {
            return;
        };

        let pending = self.pending_tasks.read();
        let task_keys: Vec<String> = pending.keys().cloned().collect();
        drop(pending);

        let now = safe_unix_timestamp();

        for task_key in task_keys {
            let parts: Vec<&str> = task_key.split(':').collect();
            if parts.len() != 2 {
                continue;
            }
            let upstream_id = parts[0];
            let provider_node_id = parts[1];

            let key = DhtKey::verification_task(upstream_id, provider_node_id);
            let key_str = key.as_str();

            if let Some(record) = record_store.get(&key_str) {
                if let Ok(task) = serde_json::from_slice::<VerificationTask>(&record.value) {
                    if task.status == VerificationStatus::Pending
                        || task.status == VerificationStatus::InProgress
                    {
                        if task.expires_at < now {
                            tracing::debug!(
                                "Verification task expired for {}:{}",
                                upstream_id,
                                provider_node_id
                            );
                            let mut pending = self.pending_tasks.write();
                            pending.remove(&task_key);
                        } else if task.status == VerificationStatus::Pending
                            && task.verification_node_ids.is_empty()
                        {
                            tracing::info!(
                                "Verification task {}:{} needs dispatch",
                                upstream_id,
                                provider_node_id
                            );
                        }
                    }
                }
            } else {
                let mut pending = self.pending_tasks.write();
                pending.remove(&task_key);
            }
        }

        self.cleanup_expired_tasks();
    }

    pub fn get_pending_dispatch_tasks(&self) -> Vec<(String, String, VerificationTask)> {
        let mut result = Vec::new();

        let pending = self.pending_tasks.read();
        let task_keys: Vec<String> = pending.keys().cloned().collect();
        drop(pending);

        let record_store_opt = self.record_store.read().clone();
        let Some(record_store) = record_store_opt else {
            return result;
        };

        for task_key in task_keys {
            let parts: Vec<&str> = task_key.split(':').collect();
            if parts.len() != 2 {
                continue;
            }
            let upstream_id = parts[0];
            let provider_node_id = parts[1];

            let key = DhtKey::verification_task(upstream_id, provider_node_id);
            let key_str = key.as_str();

            if let Some(record) = record_store.get(&key_str) {
                if let Ok(task) = serde_json::from_slice::<VerificationTask>(&record.value) {
                    if task.status == VerificationStatus::Pending
                        && task.verification_node_ids.is_empty()
                        && task.expires_at > safe_unix_timestamp()
                    {
                        result.push((
                            task_key.clone(),
                            format!("{}:{}", upstream_id, provider_node_id),
                            task,
                        ));
                    }
                }
            }
        }

        result
    }

    pub fn mark_task_in_progress(&self, task_key: &str, verification_node_ids: Vec<String>) {
        let parts: Vec<&str> = task_key.split(':').collect();
        if parts.len() != 2 {
            return;
        }
        let upstream_id = parts[0];
        let provider_node_id = parts[1];

        let record_store_opt = self.record_store.read().clone();
        let Some(record_store) = record_store_opt else {
            return;
        };

        let key = DhtKey::verification_task(upstream_id, provider_node_id);
        let key_str = key.as_str();

        if let Some(record) = record_store.get(&key_str) {
            if let Ok(mut task) = serde_json::from_slice::<VerificationTask>(&record.value) {
                task.status = VerificationStatus::InProgress;
                task.verification_node_ids = verification_node_ids;

                if let Ok(value) = serde_json::to_vec(&task) {
                    let _ = record_store.store_and_announce(
                        key_str.to_string(),
                        value,
                        self.config.penalty_ttl_secs,
                    );
                }
            }
        }
    }
}

impl Default for VerificationTaskManager {
    fn default() -> Self {
        Self::new(String::new(), VerificationConfig::default())
    }
}
