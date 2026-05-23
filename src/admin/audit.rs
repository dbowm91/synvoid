use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::BufRead;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

const MAX_AUDIT_LOGS: usize = 10000;
const MAX_CONFIG_VERSIONS: usize = 100;
const AUDIT_LOG_FILENAME: &str = "audit.log";

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
    audit_file: PathBuf,
}

impl AuditState {
    pub fn new() -> Self {
        Self {
            logs: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_AUDIT_LOGS))),
            audit_file: PathBuf::new(),
        }
    }

    pub fn with_audit_dir(mut self, audit_dir: PathBuf) -> Self {
        let audit_file = audit_dir.join(AUDIT_LOG_FILENAME);
        if let Some(parent) = audit_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(&audit_file) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(&audit_file, perms);
            }
        }
        self.audit_file = audit_file;
        self
    }

    pub fn load_recent_entries(&self) -> Result<(), String> {
        if !self.audit_file.exists() {
            return Ok(());
        }
        let path = self.audit_file.clone();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|e| format!("Failed to open audit log file: {}", e))?;
        let reader = std::io::BufReader::new(file);
        let mut logs = self.logs.write();
        for line in reader.lines().flatten() {
            if let Ok(entry) = serde_json::from_str::<AuditLog>(&line) {
                if logs.len() >= MAX_AUDIT_LOGS {
                    logs.pop_front();
                }
                logs.push_back(entry);
            }
        }
        Ok(())
    }

    pub fn log(&self, audit_log: AuditLog) {
        {
            let mut logs = self.logs.write();
            if logs.len() >= MAX_AUDIT_LOGS {
                logs.pop_front();
            }
            logs.push_back(audit_log.clone());
        }
        if !self.audit_file.as_os_str().is_empty() {
            if let Ok(json) = serde_json::to_string(&audit_log) {
                let line = json + "\n";
                if let Err(e) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.audit_file)
                    .and_then(|mut f| {
                        use std::io::Write;
                        f.write_all(line.as_bytes())
                    })
                {
                    tracing::warn!("Failed to persist audit log: {}", e);
                    super::metrics_events::record_audit_write_failure();
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(metadata) = std::fs::metadata(&self.audit_file) {
                        let mut perms = metadata.permissions();
                        perms.set_mode(0o600);
                        let _ = std::fs::set_permissions(&self.audit_file, perms);
                    }
                }
            }
        }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogFilter {
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub action_prefix: Option<String>,
    pub success: Option<bool>,
    pub limit: usize,
    pub offset: usize,
}

impl Default for AuditLogFilter {
    fn default() -> Self {
        Self {
            start_time: None,
            end_time: None,
            action_prefix: None,
            success: None,
            limit: 100,
            offset: 0,
        }
    }
}

impl AuditState {
    pub fn get_filtered_logs(&self, filter: &AuditLogFilter) -> Vec<AuditLog> {
        let logs = self.logs.read();
        logs.iter()
            .rev()
            .filter(|log| {
                if let Some(ref start) = filter.start_time {
                    if log.timestamp < *start {
                        return false;
                    }
                }
                if let Some(ref end) = filter.end_time {
                    if log.timestamp > *end {
                        return false;
                    }
                }
                if let Some(ref prefix) = filter.action_prefix {
                    if !log.action.starts_with(prefix) {
                        return false;
                    }
                }
                if let Some(success) = filter.success {
                    if log.success != success {
                        return false;
                    }
                }
                true
            })
            .skip(filter.offset)
            .take(filter.limit)
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigVersion {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub description: Option<String>,
    pub file_path: PathBuf,
}

impl ConfigVersion {
    pub fn new(file_path: PathBuf, description: Option<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            description,
            file_path,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConfigVersionManager {
    versions: Arc<RwLock<VecDeque<ConfigVersion>>>,
    versions_dir: PathBuf,
}

impl ConfigVersionManager {
    pub fn new(config_dir: PathBuf) -> Self {
        let versions_dir = config_dir.join("versions");
        Self {
            versions: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_CONFIG_VERSIONS))),
            versions_dir,
        }
    }

    pub fn versions_dir(&self) -> &PathBuf {
        &self.versions_dir
    }

    pub fn save_version(
        &self,
        toml_content: &str,
        description: Option<String>,
    ) -> Result<ConfigVersion, String> {
        let version = ConfigVersion::new(PathBuf::new(), description);
        let timestamp = version.timestamp.format("%Y%m%d_%H%M%S").to_string();
        let version_filename = format!("main-{}.toml", timestamp);
        let version_path = self.versions_dir.join(&version_filename);

        std::fs::create_dir_all(&self.versions_dir)
            .map_err(|e| format!("Failed to create versions directory: {}", e))?;

        std::fs::write(&version_path, toml_content)
            .map_err(|e| format!("Failed to write version file: {}", e))?;

        let mut version_with_path = version;
        version_with_path.file_path = version_path;

        let mut versions = self.versions.write();
        if versions.len() >= MAX_CONFIG_VERSIONS {
            if let Some(oldest) = versions.pop_front() {
                if let Err(e) = std::fs::remove_file(&oldest.file_path) {
                    tracing::warn!("Failed to remove old config version: {}", e);
                }
            }
        }
        versions.push_back(version_with_path.clone());

        Ok(version_with_path)
    }

    pub fn list_versions(&self) -> Vec<ConfigVersion> {
        let versions = self.versions.read();
        versions.iter().rev().cloned().collect()
    }

    pub fn get_version(&self, id: &str) -> Option<ConfigVersion> {
        let versions = self.versions.read();
        versions.iter().find(|v| v.id == id).cloned()
    }

    pub fn get_version_content(&self, id: &str) -> Option<String> {
        let versions = self.versions.read();
        versions
            .iter()
            .find(|v| v.id == id)
            .and_then(|v| std::fs::read_to_string(&v.file_path).ok())
    }

    pub fn rollback(&self, id: &str, target_path: &PathBuf) -> Result<(), String> {
        let content = self
            .get_version_content(id)
            .ok_or_else(|| "Version not found".to_string())?;

        std::fs::write(target_path, &content)
            .map_err(|e| format!("Failed to rollback config: {}", e))?;

        Ok(())
    }

    pub fn load_existing_versions(&self) -> Result<(), String> {
        if !self.versions_dir.exists() {
            return Ok(());
        }

        let mut versions: Vec<ConfigVersion> = std::fs::read_dir(&self.versions_dir)
            .map_err(|e| format!("Failed to read versions directory: {}", e))?
            .filter_map(|entry: std::io::Result<std::fs::DirEntry>| {
                let entry = entry.ok()?;
                let path = entry.path();
                if path.extension()?.to_str()? == "toml" {
                    let filename = path.file_name()?.to_str()?;
                    if filename.starts_with("main-") && filename.ends_with(".toml") {
                        let timestamp_str = filename
                            .trim_start_matches("main-")
                            .trim_end_matches(".toml");
                        if let Ok(timestamp) =
                            DateTime::parse_from_str(timestamp_str, "%Y%m%d_%H%M%S")
                        {
                            return Some(Ok(ConfigVersion {
                                id: filename.to_string(),
                                timestamp: timestamp.with_timezone(&Utc),
                                description: None,
                                file_path: path,
                            }));
                        }
                    }
                }
                None
            })
            .filter_map(|r: std::result::Result<ConfigVersion, std::io::Error>| r.ok())
            .collect();

        versions.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        let mut versions_lock = self.versions.write();
        for v in versions.into_iter().rev().take(MAX_CONFIG_VERSIONS) {
            versions_lock.push_back(v);
        }

        Ok(())
    }
}

impl Default for ConfigVersionManager {
    fn default() -> Self {
        Self {
            versions: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_CONFIG_VERSIONS))),
            versions_dir: PathBuf::new(),
        }
    }
}
