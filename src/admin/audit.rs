use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use uuid::Uuid;

const MAX_AUDIT_LOGS: usize = 10000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub action: String,
    pub target_resource: String,
    pub client_ip: String,
    pub user_agent: Option<String>,
    pub details: Option<String>,
    pub success: bool,
}

impl AuditLog {
    pub fn new(
        user_id: Option<String>,
        username: Option<String>,
        action: String,
        target_resource: String,
        client_ip: String,
        user_agent: Option<String>,
        details: Option<String>,
        success: bool,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            user_id,
            username,
            action,
            target_resource,
            client_ip,
            user_agent,
            details,
            success,
        }
    }
}

#[derive(Clone)]
pub struct AuditState {
    logs: Arc<RwLock<VecDeque<AuditLog>>>,
}

impl AuditState {
    pub fn new() -> Self {
        Self {
            logs: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_AUDIT_LOGS))),
        }
    }

    pub fn log(&self, audit_log: AuditLog) {
        let mut logs = self.logs.write();
        if logs.len() >= MAX_AUDIT_LOGS {
            logs.pop_front();
        }
        logs.push_back(audit_log);
    }

    pub fn get_logs(&self, limit: usize, offset: usize) -> Vec<AuditLog> {
        let logs = self.logs.read();
        logs.iter()
            .rev()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn get_logs_for_user(&self, username: &str, limit: usize) -> Vec<AuditLog> {
        let logs = self.logs.read();
        logs.iter()
            .rev()
            .filter(|log| log.username.as_deref() == Some(username))
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn get_logs_for_resource(&self, resource: &str, limit: usize) -> Vec<AuditLog> {
        let logs = self.logs.read();
        logs.iter()
            .rev()
            .filter(|log| log.target_resource.contains(resource))
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn count(&self) -> usize {
        self.logs.read().len()
    }
}

impl Default for AuditState {
    fn default() -> Self {
        Self::new()
    }
}
