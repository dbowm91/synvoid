#![allow(unused_variables, unused_mut)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use parking_lot::RwLock;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock as TokioRwLock;

use crate::mesh::audit_session::{AuditSessionManager, SessionValidationResult};
use crate::mesh::config::MeshConfig;
use crate::mesh::topology::MeshTopology;

const DEFAULT_AUDIT_REPORT_COOLDOWN_SECS: u64 = 60;
const SIGNED_REPORT_COOLDOWN_SECS: u64 = 60;
const DEFAULT_MIN_REPUTATION_THRESHOLD: f64 = 0.5;
const SIGNED_MAX_REPORTS_PER_MINUTE: usize = 10;
const UNSIGNED_MAX_REPORTS_PER_MINUTE: usize = 1;
const DEFAULT_POW_DIFFICULTY: u8 = 2;
const DEFAULT_POW_TIMEOUT_SECS: u64 = 30;
const DEFAULT_POW_WINDOW_SECS: u64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientAuditReport {
    pub mesh_id: String,
    pub edge_node_id: String,
    pub session_id: Option<String>,
    pub audit_results: AuditResults,
    pub timestamp: i64,
    pub pow_challenge: Option<String>,
    pub pow_nonce: Option<String>,
    pub signature: Option<String>,
    pub signed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResults {
    pub success: bool,
    pub passed: bool,
    pub results: Vec<NodeProbeResult>,
    pub summary: AuditSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeProbeResult {
    #[serde(rename = "nodeUrl")]
    pub node_url: String,
    #[serde(rename = "upstreamIp")]
    pub upstream_ip: Option<String>,
    #[serde(rename = "routedToAllowedIp")]
    pub routed_to_allowed_ip: bool,
    pub node_id: Option<String>,
    pub success: bool,
    pub error: Option<String>,
    pub latency_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReportResponse {
    pub accepted: bool,
    pub message: String,
    pub reputation_updated: Option<f64>,
    pub quarantined: bool,
    pub quarantine_reason: Option<String>,
    pub new_pow_challenge: Option<String>,
}

pub struct ClientAuditManager {
    #[allow(dead_code)] // Reserved for configurable client audit
    config: Arc<MeshConfig>,
    topology: Arc<TokioRwLock<MeshTopology>>,
    session_manager: Arc<AuditSessionManager>,
    pending_reports: Arc<RwLock<HashMap<String, Instant>>>,
    quarantine_enabled: bool,
    min_reputation_threshold: f64,
    pow_enabled: bool,
    pow_difficulty: u8,
    pow_timeout_secs: u64,
    #[allow(dead_code)] // Reserved for configurable PoW window
    pow_window_secs: u64,
    pow_secret_key: [u8; 32],
}

impl ClientAuditManager {
    pub fn new(config: Arc<MeshConfig>, topology: Arc<TokioRwLock<MeshTopology>>) -> Self {
        let mut pow_secret_key = [0u8; 32];
        rand::fill(&mut pow_secret_key);

        let session_manager = Arc::new(AuditSessionManager::new(config.clone()));

        Self {
            config,
            topology,
            session_manager,
            pending_reports: Arc::new(RwLock::new(HashMap::new())),
            quarantine_enabled: false,
            min_reputation_threshold: DEFAULT_MIN_REPUTATION_THRESHOLD,
            pow_enabled: true,
            pow_difficulty: DEFAULT_POW_DIFFICULTY,
            pow_timeout_secs: DEFAULT_POW_TIMEOUT_SECS,
            pow_window_secs: DEFAULT_POW_WINDOW_SECS,
            pow_secret_key,
        }
    }

    pub fn with_quarantine(mut self, enabled: bool) -> Self {
        self.quarantine_enabled = enabled;
        self
    }

    pub fn with_reputation_threshold(mut self, threshold: f64) -> Self {
        self.min_reputation_threshold = threshold;
        self
    }

    pub fn with_pow(mut self, enabled: bool, difficulty: u8) -> Self {
        self.pow_enabled = enabled;
        self.pow_difficulty = difficulty.clamp(1, 10);
        self
    }

    pub fn get_session_manager(&self) -> Arc<AuditSessionManager> {
        self.session_manager.clone()
    }

    fn generate_pow_challenge(&self) -> String {
        let now = crate::utils::current_timestamp();
        let mut rng = rand::rng();
        let server_nonce: u64 = rng.random();

        let mut challenge_data = Vec::new();
        challenge_data.extend_from_slice(&self.pow_secret_key);
        challenge_data.extend_from_slice(&now.to_le_bytes());
        challenge_data.extend_from_slice(&server_nonce.to_le_bytes());

        let hash = Sha256::digest(&challenge_data);
        let payload = format!("{}:{}", now, hex::encode(hash));
        let challenge = BASE64.encode(payload.as_bytes());

        challenge
    }

    fn verify_pow_solution(&self, challenge: &str, nonce: &str) -> bool {
        let now = crate::utils::current_timestamp();

        let decoded = match BASE64.decode(challenge.as_bytes()) {
            Ok(d) => d,
            Err(_) => return false,
        };

        let payload = match String::from_utf8(decoded) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let parts: Vec<&str> = payload.split(':').collect();
        if parts.len() != 2 {
            return false;
        }

        let timestamp: u64 = match parts[0].parse() {
            Ok(t) => t,
            Err(_) => return false,
        };

        let age = now.saturating_sub(timestamp);
        if age > self.pow_timeout_secs {
            return false;
        }

        if timestamp > now + 60 {
            return false;
        }

        let input = format!("{}{}", challenge, nonce);
        let hash = Sha256::digest(input.as_bytes());

        self.has_leading_zeros(&hash, self.pow_difficulty as usize)
    }

    fn has_leading_zeros(&self, hash: &[u8], zeros: usize) -> bool {
        let mut bit_index = 0;
        for byte in hash {
            if bit_index >= zeros {
                return true;
            }
            let byte = *byte;
            for j in (0..8).rev() {
                if bit_index >= zeros {
                    return true;
                }
                if (byte >> j) & 1 == 0 {
                    bit_index += 1;
                } else {
                    return false;
                }
            }
        }
        bit_index >= zeros
    }

    fn cleanup_old_reports(&self) {
        let mut pending = self.pending_reports.write();
        let now = Instant::now();
        pending.retain(|_, v| {
            now.duration_since(*v).as_secs() < DEFAULT_AUDIT_REPORT_COOLDOWN_SECS * 2
        });
    }

    pub async fn process_audit_report(&self, report: ClientAuditReport) -> AuditReportResponse {
        let node_id = &report.edge_node_id;

        if node_id.is_empty() {
            return AuditReportResponse {
                accepted: false,
                message: "Empty node_id".to_string(),
                reputation_updated: None,
                quarantined: false,
                quarantine_reason: None,
                new_pow_challenge: None,
            };
        }

        if report.mesh_id.is_empty() {
            return AuditReportResponse {
                accepted: false,
                message: "Empty mesh_id".to_string(),
                reputation_updated: None,
                quarantined: false,
                quarantine_reason: None,
                new_pow_challenge: None,
            };
        }

        let session_validation: Option<SessionValidationResult> =
            if let Some(session_id) = &report.session_id {
                match self.session_manager.validate_session(session_id, node_id) {
                    Ok(val) => Some(val),
                    Err(e) => {
                        tracing::debug!("Session validation failed for {}: {:?}", session_id, e);
                        None
                    }
                }
            } else {
                None
            };

        let has_valid_session = session_validation.is_some();

        if has_valid_session {
            if let Some(session_id) = &report.session_id {
                tracing::debug!("Authenticated audit report from session {}", session_id);
            }
        }

        if self.pow_enabled {
            if let (Some(challenge), Some(nonce)) = (&report.pow_challenge, &report.pow_nonce) {
                if !self.verify_pow_solution(challenge, nonce) {
                    return AuditReportResponse {
                        accepted: false,
                        message: "Invalid POW solution".to_string(),
                        reputation_updated: None,
                        quarantined: false,
                        quarantine_reason: None,
                        new_pow_challenge: None,
                    };
                }
            } else {
                return AuditReportResponse {
                    accepted: false,
                    message: "POW solution required for audit reports".to_string(),
                    reputation_updated: None,
                    quarantined: false,
                    quarantine_reason: None,
                    new_pow_challenge: None,
                };
            }
        }

        if let Some(ref session_val) = session_validation {
            if session_val.mesh_id != report.mesh_id {
                return AuditReportResponse {
                    accepted: false,
                    message: "Mesh ID mismatch".to_string(),
                    reputation_updated: None,
                    quarantined: false,
                    quarantine_reason: None,
                    new_pow_challenge: None,
                };
            }
        }

        self.cleanup_old_reports();

        {
            let pending = self.pending_reports.read();
            if let Some(last_report) = pending.get(node_id) {
                let cooldown = if has_valid_session {
                    SIGNED_REPORT_COOLDOWN_SECS
                } else {
                    DEFAULT_AUDIT_REPORT_COOLDOWN_SECS
                };
                if last_report.elapsed().as_secs() < cooldown {
                    return AuditReportResponse {
                        accepted: false,
                        message: format!("Report rate limited, try again in {} seconds", cooldown),
                        reputation_updated: None,
                        quarantined: false,
                        quarantine_reason: None,
                        new_pow_challenge: None,
                    };
                }
            }
        }

        let total = report.audit_results.summary.total;
        let passed = report.audit_results.summary.passed;
        let failed = report.audit_results.summary.failed;

        if total == 0 || total != passed + failed {
            return AuditReportResponse {
                accepted: false,
                message: "Invalid audit summary: total mismatch".to_string(),
                reputation_updated: None,
                quarantined: false,
                quarantine_reason: None,
                new_pow_challenge: None,
            };
        }

        let max_per_report = if has_valid_session {
            SIGNED_MAX_REPORTS_PER_MINUTE
        } else {
            UNSIGNED_MAX_REPORTS_PER_MINUTE
        };
        if passed > max_per_report || failed > max_per_report {
            return AuditReportResponse {
                accepted: false,
                message: "Audit counts exceed maximum".to_string(),
                reputation_updated: None,
                quarantined: false,
                quarantine_reason: None,
                new_pow_challenge: None,
            };
        }

        {
            let mut pending = self.pending_reports.write();
            pending.insert(node_id.clone(), Instant::now());
        }

        let passed_u64 = passed as u64;
        let failed_u64 = failed as u64;

        let new_reputation = {
            let mut topology = self.topology.write().await;
            topology
                .update_peer_audit_stats(node_id, passed_u64, failed_u64)
                .await;
            topology.get_peer_audit_reputation(node_id).await
        };

        let (reputation, quarantined, quarantine_reason) = if let Some(rep) = new_reputation {
            let quarantined = self.should_quarantine_by_reputation(rep);

            if quarantined {
                self.topology
                    .write()
                    .await
                    .update_peer_status(node_id, crate::mesh::topology::PeerStatus::Unhealthy)
                    .await;
                tracing::warn!(
                    "Node {} quarantined due to audit failures (reputation: {:.2})",
                    node_id,
                    rep
                );
                (
                    Some(rep),
                    true,
                    Some(format!(
                        "Audit reputation {:.2} below threshold {:.2}",
                        rep, self.min_reputation_threshold
                    )),
                )
            } else {
                (Some(rep), false, None)
            }
        } else {
            tracing::debug!("Audit report for unknown node: {}", node_id);
            (None, false, None)
        };

        tracing::info!(
            "Processed audit report from node {}: passed={}/{}, reputation={:.2}, authenticated={}",
            node_id,
            passed,
            total,
            reputation.unwrap_or(-1.0),
            has_valid_session
        );

        let new_pow_challenge = if self.pow_enabled && report.pow_nonce.is_none() {
            Some(self.generate_pow_challenge())
        } else {
            None
        };

        AuditReportResponse {
            accepted: true,
            message: "Audit report processed".to_string(),
            reputation_updated: reputation,
            quarantined,
            quarantine_reason,
            new_pow_challenge,
        }
    }

    fn should_quarantine_by_reputation(&self, reputation: f64) -> bool {
        if !self.quarantine_enabled {
            return false;
        }

        reputation < self.min_reputation_threshold
    }

    pub fn create_session(
        &self,
        session_id: String,
        edge_node_id: String,
        mesh_id: String,
    ) -> bool {
        self.session_manager
            .create_session(session_id, edge_node_id, mesh_id)
    }

    pub fn generate_new_pow_challenge(&self) -> String {
        self.generate_pow_challenge()
    }

    pub async fn get_node_reputation(&self, node_id: &str) -> Option<f64> {
        self.topology
            .read()
            .await
            .get_peer_audit_reputation(node_id)
            .await
    }
}

pub async fn handle_audit_report(
    State(manager): State<Arc<ClientAuditManager>>,
    Json(report): Json<ClientAuditReport>,
) -> Json<AuditReportResponse> {
    let response = manager.process_audit_report(report).await;
    Json(response)
}
