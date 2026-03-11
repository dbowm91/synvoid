use chrono::Utc;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct SiteLogger {
    log_dir: PathBuf,
    format: String,
    max_entries: u32,
    retention_days: u32,
    file_handles: Arc<Mutex<HashMap<String, Arc<Mutex<SiteLogWriter>>>>>,
}

struct SiteLogWriter {
    file_path: PathBuf,
    entry_count: u32,
    date: String,
}

impl SiteLogger {
    pub fn new(log_dir: PathBuf, format: String, max_entries: u32, retention_days: u32) -> Self {
        if !log_dir.exists() {
            let _ = std::fs::create_dir_all(&log_dir);
        }

        Self {
            log_dir,
            format,
            max_entries,
            retention_days,
            file_handles: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn log(&self, site_id: &str, entry: &AccessLogEntry) {
        let date = Utc::now().format("%Y-%m-%d").to_string();
        let filename = format!("{}-{}.log", site_id, date);
        let file_path = self.log_dir.join(&filename);

        let mut handles = self.file_handles.lock();

        let writer = handles.entry(site_id.to_string()).or_insert_with(|| {
            Arc::new(Mutex::new(SiteLogWriter {
                file_path: file_path.clone(),
                entry_count: 0,
                date: date.clone(),
            }))
        });

        let mut writer = writer.lock();

        if writer.date != date {
            writer.file_path = self.log_dir.join(&filename);
            writer.entry_count = 0;
            writer.date = date;
        }

        let log_line = match self.format.as_str() {
            "json" => self.format_json(entry),
            _ => self.format_text(entry),
        };

        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&writer.file_path)
        {
            let _ = writeln!(file, "{}", log_line);
            writer.entry_count += 1;

            if self.max_entries > 0 && writer.entry_count >= self.max_entries {
                writer.entry_count = 0;
            }
        }
    }

    fn format_json(&self, entry: &AccessLogEntry) -> String {
        serde_json::to_string(&entry).unwrap_or_default()
    }

    fn format_text(&self, entry: &AccessLogEntry) -> String {
        format!(
            "{} {} {} {} {} {} {:?} {}",
            entry.timestamp,
            entry.client_ip,
            entry.method,
            entry.path,
            entry.status,
            entry.response_time_ms,
            entry.block_reason,
            entry.user_agent.as_deref().unwrap_or("-")
        )
    }

    pub fn cleanup_old_logs(&self) {
        if let Ok(entries) = std::fs::read_dir(&self.log_dir) {
            let cutoff = Utc::now() - chrono::Duration::days(self.retention_days as i64);

            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    if let Ok(modified) = metadata.modified() {
                        let modified_time: chrono::DateTime<Utc> = modified.into();
                        if modified_time < cutoff {
                            let _ = std::fs::remove_file(entry.path());
                            tracing::info!("Removed old log: {:?}", entry.path());
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AccessLogEntry {
    pub timestamp: String,
    pub site_id: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub response_time_ms: u64,
    pub blocked: bool,
    pub block_reason: Option<String>,
    pub user_agent: Option<String>,
}

impl AccessLogEntry {
    pub fn new(
        site_id: String,
        client_ip: String,
        method: String,
        path: String,
        status: u16,
        response_time_ms: u64,
        blocked: bool,
        block_reason: Option<String>,
        user_agent: Option<String>,
    ) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            site_id,
            client_ip,
            method,
            path,
            status,
            response_time_ms,
            blocked,
            block_reason,
            user_agent,
        }
    }
}

pub fn scrub_sensitive_data(body: &str, sensitive_fields: &[String], replacement: &str) -> String {
    if body.is_empty() {
        return body.to_string();
    }

    let mut result = body.to_string();

    for field in sensitive_fields {
        let patterns = [
            format!(r#""{}"\s*:\s*"[^"]*"#, field),
            format!(r#""{}"\s*:\s*'[^']*'"#, field),
            format!(r#"{}=[^&]*"#, field),
        ];

        for pattern in &patterns {
            if let Ok(regex) = regex::Regex::new(pattern) {
                result = regex
                    .replace_all(&result, format!(r#""{}": "{}""#, field, replacement))
                    .to_string();
            }
        }
    }

    result
}

pub fn truncate_body(body: &str, max_size: usize) -> String {
    if body.len() <= max_size {
        body.to_string()
    } else {
        format!(
            "{}...[truncated {} bytes]",
            &body[..max_size],
            body.len() - max_size
        )
    }
}

pub mod syslog;
pub use syslog::{SyslogError, SyslogLogger};
