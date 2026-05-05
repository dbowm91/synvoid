use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use tokio::fs;

use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub sandbox_dir: PathBuf,
    pub quarantine_dir: PathBuf,
    pub sandbox_level: crate::platform::SandboxLevel,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            sandbox_dir: PathBuf::from("/var/lib/synvoid/sandbox"),
            quarantine_dir: PathBuf::from("/var/lib/synvoid/quarantine"),
            sandbox_level: crate::platform::SandboxLevel::Off,
        }
    }
}

impl SandboxConfig {
    pub fn new(sandbox_dir: impl Into<PathBuf>, quarantine_dir: impl Into<PathBuf>) -> Self {
        Self {
            sandbox_dir: sandbox_dir.into(),
            quarantine_dir: quarantine_dir.into(),
            sandbox_level: crate::platform::SandboxLevel::Off,
        }
    }

    pub fn with_sandbox_level(mut self, level: crate::platform::SandboxLevel) -> Self {
        self.sandbox_level = level;
        self
    }

    pub async fn ensure_dirs_exist(&self) -> std::io::Result<()> {
        fs::create_dir_all(&self.sandbox_dir).await?;
        fs::create_dir_all(&self.quarantine_dir).await?;
        Ok(())
    }

    pub fn apply_platform_sandbox(&self) -> Option<crate::platform::ProcessSandbox> {
        if self.sandbox_level == crate::platform::SandboxLevel::Off {
            return None;
        }

        if !crate::platform::is_sandbox_supported() {
            tracing::warn!(
                "OS-level sandboxing requested but not supported on this platform. \
                 Using basic directory isolation instead."
            );
            return None;
        }

        let paths = crate::platform::SandboxPaths::new()
            .add_read_path(&self.sandbox_dir)
            .add_write_path(&self.quarantine_dir);

        match crate::platform::ProcessSandbox::with_paths(self.sandbox_level, paths) {
            Ok(sandbox) => {
                tracing::info!(
                    "Platform sandbox applied (level: {:?}, feature: {})",
                    sandbox.level(),
                    sandbox.feature_name()
                );
                Some(sandbox)
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to apply platform sandbox: {}. Using basic directory isolation instead.",
                    e
                );
                None
            }
        }
    }
}

#[derive(Debug)]
pub struct SandboxHandle {
    pub id: Uuid,
    pub sandbox_dir: PathBuf,
    pub temp_file: NamedTempFile,
    pub file_path: PathBuf,
    bytes_written: u64,
}

impl SandboxHandle {
    pub async fn new(config: &SandboxConfig) -> std::io::Result<Self> {
        let id = Uuid::new_v4();
        let sandbox_dir = config.sandbox_dir.join(id.to_string());

        fs::create_dir_all(&sandbox_dir).await?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&sandbox_dir, std::fs::Permissions::from_mode(0o700)).await?;
        }

        let temp_file = NamedTempFile::new_in(&sandbox_dir)?;
        let file_path = temp_file.path().to_path_buf();

        Ok(Self {
            id,
            sandbox_dir,
            temp_file,
            file_path,
            bytes_written: 0,
        })
    }

    pub fn file(&self) -> &std::fs::File {
        self.temp_file.as_file()
    }

    pub fn path(&self) -> &Path {
        self.temp_file.path()
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    pub fn read_bytes(&self) -> std::io::Result<Vec<u8>> {
        use std::io::Read;
        let mut buf = Vec::new();
        let mut file = self.temp_file.reopen()?;
        file.read_to_end(&mut buf)?;
        Ok(buf)
    }

    pub fn read_header(&self, max_bytes: usize) -> std::io::Result<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = self.temp_file.reopen()?;
        let mut buf = vec![0u8; max_bytes];
        let bytes_read = file.read(&mut buf)?;
        buf.truncate(bytes_read);
        file.seek(SeekFrom::Start(0))?;
        Ok(buf)
    }

    pub fn write_sync(&mut self, data: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        self.temp_file.write_all(data)?;
        self.bytes_written += data.len() as u64;
        Ok(())
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        use std::io::Write;
        self.temp_file.flush()
    }
}

#[derive(Debug)]
pub struct QuarantineEntry {
    pub id: Uuid,
    pub original_filename: Option<String>,
    pub detected_mime: Option<String>,
    pub file_path: PathBuf,
    pub metadata_path: PathBuf,
    pub yara_matches: Vec<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl QuarantineEntry {
    pub async fn save_metadata(&self) -> std::io::Result<()> {
        let metadata = serde_json::json!({
            "id": self.id.to_string(),
            "original_filename": self.original_filename,
            "detected_mime": self.detected_mime,
            "yara_matches": self.yara_matches,
            "timestamp": self.timestamp.to_rfc3339(),
        });

        fs::write(
            &self.metadata_path,
            serde_json::to_string_pretty(&metadata).unwrap(),
        )
        .await
    }
}

pub struct Sandbox {
    pub config: SandboxConfig,
}

impl Sandbox {
    pub fn new(config: SandboxConfig) -> Self {
        Self { config }
    }

    pub async fn create_handle(&self) -> std::io::Result<SandboxHandle> {
        self.config.ensure_dirs_exist().await?;
        SandboxHandle::new(&self.config).await
    }

    pub async fn quarantine(
        &self,
        source_path: &Path,
        original_filename: Option<&str>,
        detected_mime: Option<&str>,
        yara_matches: &[String],
    ) -> std::io::Result<QuarantineEntry> {
        self.config.ensure_dirs_exist().await?;

        let id = Uuid::new_v4();
        let quarantine_subdir = self.config.quarantine_dir.join(id.to_string());

        fs::create_dir_all(&quarantine_subdir).await?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&quarantine_subdir, std::fs::Permissions::from_mode(0o700)).await?;
        }

        let file_path = quarantine_subdir.join("file");
        let metadata_path = quarantine_subdir.join("metadata.json");

        fs::copy(source_path, &file_path).await?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o400)).await?;
        }

        let entry = QuarantineEntry {
            id,
            original_filename: original_filename.map(|s| s.to_string()),
            detected_mime: detected_mime.map(|s| s.to_string()),
            file_path,
            metadata_path,
            yara_matches: yara_matches.to_vec(),
            timestamp: chrono::Utc::now(),
        };

        entry.save_metadata().await?;

        Ok(entry)
    }

    pub async fn cleanup_old_entries(&self, max_age_hours: u64) -> std::io::Result<u64> {
        let mut removed_count = 0u64;
        let mut entries = fs::read_dir(&self.config.quarantine_dir).await?;

        let cutoff = chrono::Utc::now() - chrono::Duration::hours(max_age_hours as i64);

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_dir() {
                if let Ok(metadata) = entry.metadata().await {
                    if let Ok(modified) = metadata.modified() {
                        let modified: chrono::DateTime<chrono::Utc> = modified.into();
                        if modified < cutoff && fs::remove_dir_all(&path).await.is_ok() {
                            removed_count += 1;
                        }
                    }
                }
            }
        }

        Ok(removed_count)
    }
}

#[derive(Debug, Clone)]
pub enum SandboxError {
    IoError(String),
    SizeExceeded {
        max: u64,
        actual: u64,
    },
    TypeNotAllowed {
        detected: String,
        allowed: Vec<String>,
    },
    MalwareDetected {
        matches: Vec<String>,
    },
    WriteError(String),
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxError::IoError(msg) => write!(f, "IO error: {}", msg),
            SandboxError::SizeExceeded { max, actual } => {
                write!(f, "Upload size {} exceeds maximum {}", actual, max)
            }
            SandboxError::TypeNotAllowed { detected, allowed } => {
                write!(
                    f,
                    "MIME type '{}' not allowed. Allowed types: {:?}",
                    detected, allowed
                )
            }
            SandboxError::MalwareDetected { matches } => {
                write!(f, "Malware detected: {:?}", matches)
            }
            SandboxError::WriteError(msg) => write!(f, "Write error: {}", msg),
        }
    }
}

impl std::error::Error for SandboxError {}
