#![allow(unexpected_cfgs)]

//! Canonical file-manager implementation.
//!
//! `FileManager` is reusable domain logic (filesystem validation, directory
//! listing/mutations, upload restrictions) owned by `synvoid-static-files`.
//! HTTP status mapping and admin authentication stay in the root HTTP/admin
//! adapters; this module only exposes transport-neutral
//! `FileManagerError::status_code() -> u16`.
//!
//! Upload security capabilities (malware scanning, upload rate limiting,
//! content MIME detection) are injected through the narrow
//! [`FileManagerSecurityBackend`] trait. The composition root (which may use
//! `synvoid-upload` types) implements the trait and passes
//! `Arc<dyn FileManagerSecurityBackend>` to [`FileManager::new`]. This keeps
//! `synvoid-static-files` free of the `synvoid-upload` dependency (which
//! would cycle via `synvoid-mesh` → `synvoid-proxy` → `synvoid-static-files`)
//! and free of the root `synvoid` crate.
//!
//! Rule-update lifecycle: the security backend owns its scanner generation.
//! There is deliberately no periodic-refresh background task in this module —
//! a background operation must not report successful work that is not
//! performed. To pick up new YARA rules, the owner constructs a new backend
//! (or restarts the owning service). Mesh-distributed rule feeds are owned by
//! `synvoid-upload`'s `UploadValidator`, not by this manager. The active rule
//! version is observable via [`FileManager::yara_rule_version`].
//!
//! Archive extraction (`extract_archive` zip/tar paths) is currently inactive:
//! the `archive`-gated decoders are not wired to a Cargo feature, so those
//! formats return `FileManagerError::OperationNotPermitted`. This preserves
//! the pre-extraction behavior; enabling archive support is future work,
//! not part of this ownership closure.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::SystemTime;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::fs;
use walkdir::WalkDir;

use synvoid_config::site::SiteStaticConfig;

/// Narrow upload-security backend injected at the composition boundary.
///
/// Implementors live outside `synvoid-static-files` (e.g. a root adapter over
/// `synvoid-upload` types) so this crate stays free of heavyweight scanner
/// dependencies and dependency cycles.
#[async_trait::async_trait]
pub trait FileManagerSecurityBackend: Send + Sync {
    /// Scan upload bytes; returns matched rule names (empty when clean).
    ///
    /// `Err(message)` signals a scan error. `FileManager` treats scan errors
    /// as fail-open with a warning (preserving historical behavior) and
    /// surfaces matches as `FileManagerError::MalwareDetected`.
    async fn scan_upload_bytes(&self, data: &[u8]) -> Result<Vec<String>, String>;

    /// Rate-limit check for an upload of `bytes` under `client_key`.
    /// Returns `true` when the upload is allowed.
    fn check_upload_rate_allowed(&self, client_key: &str, bytes: u64) -> bool;

    /// Content-based MIME detection used for `allowed_mime_types` enforcement.
    /// Returns detected MIME types (empty when unknown).
    fn detect_content_mime_types(&self, data: &[u8]) -> Vec<String>;

    /// Observable scanner rule version, if the backend carries one.
    /// `None` means scanning is disabled or unversioned.
    fn yara_rule_version(&self) -> Option<String> {
        None
    }
}

/// Permissive backend for unit tests that exercise filesystem policy without
/// security enforcement. NOT for production use.
#[derive(Debug, Default)]
pub struct AllowAllSecurityBackend;

#[async_trait::async_trait]
impl FileManagerSecurityBackend for AllowAllSecurityBackend {
    async fn scan_upload_bytes(&self, _data: &[u8]) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }

    fn check_upload_rate_allowed(&self, _client_key: &str, _bytes: u64) -> bool {
        true
    }

    fn detect_content_mime_types(&self, _data: &[u8]) -> Vec<String> {
        Vec::new()
    }
}

fn make_blocked_extensions_set() -> HashSet<String> {
    BLOCKED_EXTENSIONS
        .iter()
        .map(|s| s.to_lowercase())
        .collect()
}

static BLOCKED_EXTENSIONS_SET: LazyLock<HashSet<String>> =
    LazyLock::new(make_blocked_extensions_set);

const BLOCKED_EXTENSIONS: &[&str] = &[
    "exe",
    "dll",
    "so",
    "dylib",
    "bat",
    "cmd",
    "ps1",
    "sh",
    "bash",
    "zsh",
    "scr",
    "pif",
    "application",
    "gadget",
    "msh",
    "msh1",
    "msh2",
    "mshxml",
    "msh1xml",
    "msh2xml",
    "jar",
    "app",
    "bin",
    "elf",
    "mach",
    "kernel",
    "lock",
    "back",
    "bak",
    "old",
    "swp",
    "tmp",
];

const MAX_PATH_DEPTH: usize = 50;
const DEFAULT_ARCHIVE_MAX_DEPTH: u32 = 3;
const DEFAULT_ARCHIVE_MAX_SIZE: u64 = 100 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct FileManagerConfig {
    pub enabled: bool,
    pub root_path: PathBuf,
    pub max_file_size: u64,
    pub blocked_extensions: Vec<String>,
    pub allowed_extensions: Vec<String>,
    pub allowed_mime_types: Vec<String>,
    /// Hint for backend construction (whether the owner should enable YARA).
    /// `FileManager` always invokes the injected backend for scans; owners
    /// construct the backend with or without YARA based on this flag.
    pub scan_on_upload: bool,
    pub allow_hidden_files: bool,
    pub allow_symlinks: bool,
    pub archive_max_depth: u32,
    pub archive_max_size: u64,
}

impl Default for FileManagerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            root_path: PathBuf::from("/"),
            max_file_size: 100 * 1024 * 1024,
            blocked_extensions: BLOCKED_EXTENSIONS.iter().map(|s| s.to_string()).collect(),
            allowed_extensions: Vec::new(),
            allowed_mime_types: Vec::new(),
            scan_on_upload: true,
            allow_hidden_files: false,
            allow_symlinks: false,
            archive_max_depth: DEFAULT_ARCHIVE_MAX_DEPTH,
            archive_max_size: DEFAULT_ARCHIVE_MAX_SIZE,
        }
    }
}

impl FileManagerConfig {
    pub fn from_static_config(config: &SiteStaticConfig, root_path: Option<PathBuf>) -> Self {
        let root = root_path.or_else(|| config.default_root.clone().map(PathBuf::from));

        Self {
            enabled: true,
            root_path: root.unwrap_or_else(|| PathBuf::from("/var/www")),
            max_file_size: config
                .max_file_size
                .as_ref()
                .and_then(|s| parse_size(s))
                .unwrap_or(100 * 1024 * 1024),
            blocked_extensions: BLOCKED_EXTENSIONS.iter().map(|s| s.to_string()).collect(),
            allowed_extensions: Vec::new(),
            allowed_mime_types: Vec::new(),
            scan_on_upload: true,
            allow_hidden_files: config.block_hidden_files.map(|v| !v).unwrap_or(false),
            allow_symlinks: config.allow_symlinks.unwrap_or(false),
            archive_max_depth: DEFAULT_ARCHIVE_MAX_DEPTH,
            archive_max_size: DEFAULT_ARCHIVE_MAX_SIZE,
        }
    }

    pub fn is_extension_blocked(&self, ext: &str) -> bool {
        let ext_lower = ext.to_lowercase();

        if !self.allowed_extensions.is_empty() {
            return !self
                .allowed_extensions
                .iter()
                .any(|e| e.to_lowercase() == ext_lower);
        }

        BLOCKED_EXTENSIONS_SET.contains(&ext_lower)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FileManagerError {
    #[error("Path not found: {0}")]
    NotFound(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Path traversal detected")]
    PathTraversal,

    #[error("Invalid path: {0}")]
    InvalidPath(String),

    #[error("File exists: {0}")]
    FileExists(String),

    #[error("Directory not empty: {0}")]
    DirectoryNotEmpty(String),

    #[error("Extension blocked: {0}")]
    ExtensionBlocked(String),

    #[error("File too large: {0}")]
    FileTooLarge(String),

    #[error("Malware detected: {0}")]
    MalwareDetected(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Operation not permitted")]
    OperationNotPermitted,
}

impl FileManagerError {
    pub fn status_code(&self) -> u16 {
        match self {
            FileManagerError::NotFound(_) => 404,
            FileManagerError::Forbidden(_) => 403,
            FileManagerError::PathTraversal => 403,
            FileManagerError::InvalidPath(_) => 400,
            FileManagerError::FileExists(_) => 409,
            FileManagerError::DirectoryNotEmpty(_) => 409,
            FileManagerError::ExtensionBlocked(_) => 403,
            FileManagerError::FileTooLarge(_) => 413,
            FileManagerError::MalwareDetected(_) => 403,
            FileManagerError::IoError(_) => 500,
            FileManagerError::OperationNotPermitted => 403,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub is_directory: bool,
    pub size: u64,
    pub modified: Option<u64>,
    pub permissions: Option<String>,
    pub is_hidden: bool,
    pub is_symlink: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DirectoryListing {
    pub path: String,
    pub entries: Vec<FileEntry>,
    pub total_count: usize,
    pub directory_count: usize,
    pub file_count: usize,
    pub total_size: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SearchResult {
    pub query: String,
    pub matches: Vec<FileEntry>,
    pub total_matches: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Permissions {
    pub mode: String,
    pub octal: String,
}

pub struct FileManager {
    config: Arc<FileManagerConfig>,
    security: Arc<dyn FileManagerSecurityBackend>,
}

impl FileManager {
    /// Construct a `FileManager` with an injected security backend.
    ///
    /// The caller (composition root) owns scanner/rule lifecycle: construct
    /// the backend with the desired YARA generation and rate-limit state,
    /// then pass it here. `FileManager` never spawns background refresh
    /// tasks; to pick up new rules, build a new backend + manager.
    pub fn new(config: FileManagerConfig, security: Arc<dyn FileManagerSecurityBackend>) -> Self {
        Self {
            config: Arc::new(config),
            security,
        }
    }

    /// Current YARA rule version reported by the injected backend, if any.
    ///
    /// Exposes the observable scanner generation so operators can verify
    /// which rules an instance was built with. `None` means scanning is
    /// disabled or the backend carries no version tag.
    pub fn yara_rule_version(&self) -> Option<String> {
        self.security.yara_rule_version()
    }

    pub fn config(&self) -> &FileManagerConfig {
        &self.config
    }

    async fn validate_and_resolve_path(
        &self,
        user_path: &str,
    ) -> Result<PathBuf, FileManagerError> {
        if user_path.is_empty() {
            return Err(FileManagerError::InvalidPath("empty path".to_string()));
        }

        if user_path.contains('\0') {
            return Err(FileManagerError::InvalidPath(
                "null byte in path".to_string(),
            ));
        }

        // Enforced before any filesystem access so both existing targets and
        // missing-leaf mutation paths (which return early from the ancestor
        // walk below) observe the same depth bound.
        let depth = user_path.trim_start_matches('/').matches('/').count();
        if depth > MAX_PATH_DEPTH {
            return Err(FileManagerError::InvalidPath(format!(
                "path depth exceeds maximum of {}",
                MAX_PATH_DEPTH
            )));
        }

        let canonical = tokio::fs::canonicalize(&self.config.root_path)
            .await
            .map_err(FileManagerError::IoError)?;

        let mut relative = PathBuf::new();
        for component in Path::new(user_path.trim_start_matches('/')).components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::Normal(name) => relative.push(name),
                std::path::Component::ParentDir => {
                    if !relative.pop() {
                        return Err(FileManagerError::PathTraversal);
                    }
                }
                std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                    return Err(FileManagerError::InvalidPath(
                        "absolute path component is not allowed".to_string(),
                    ));
                }
            }
        }

        if relative.as_os_str().is_empty() {
            return Ok(canonical);
        }

        let full_path = canonical.join(&relative);
        let target_canonical = match tokio::fs::canonicalize(&full_path).await {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Mutating operations may legitimately address a new leaf.
                // Canonicalize the nearest existing ancestor so a missing
                // suffix is still checked against the real root (including
                // symlinked ancestors) before it is returned to the caller.
                let mut ancestor = full_path.clone();
                let mut missing_components = Vec::new();
                while tokio::fs::metadata(&ancestor).await.is_err() {
                    let Some(name) = ancestor.file_name().map(|name| name.to_os_string()) else {
                        return Err(FileManagerError::NotFound(user_path.to_string()));
                    };
                    missing_components.push(name);
                    if !ancestor.pop() {
                        return Err(FileManagerError::NotFound(user_path.to_string()));
                    }
                }

                let ancestor_canonical = tokio::fs::canonicalize(&ancestor)
                    .await
                    .map_err(FileManagerError::IoError)?;
                if !ancestor_canonical.starts_with(&canonical) {
                    return Err(FileManagerError::PathTraversal);
                }

                let mut candidate = ancestor_canonical;
                for component in missing_components.iter().rev() {
                    candidate.push(component);
                }
                candidate
            }
            Err(error) => return Err(FileManagerError::IoError(error)),
        };

        if !target_canonical.starts_with(&canonical) {
            tracing::warn!(
                "Path traversal attempt: {} -> {} (root: {})",
                user_path,
                target_canonical.display(),
                canonical.display()
            );
            return Err(FileManagerError::PathTraversal);
        }

        Ok(target_canonical)
    }

    fn check_hidden_file(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with('.'))
            .unwrap_or(false)
    }

    fn check_blocked_extension(&self, path: &Path) -> Option<String> {
        path.extension()
            .and_then(|e| e.to_str())
            .filter(|ext| self.config.is_extension_blocked(ext))
            .map(|ext| ext.to_string())
    }

    pub async fn list_directory(&self, path: &str) -> Result<DirectoryListing, FileManagerError> {
        let resolved = self.validate_and_resolve_path(path).await?;

        let metadata = fs::metadata(&resolved)
            .await
            .map_err(FileManagerError::IoError)?;

        if !metadata.is_dir() {
            return Err(FileManagerError::InvalidPath("not a directory".to_string()));
        }

        let mut entries = Vec::new();
        let mut dir_count = 0;
        let mut file_count = 0;
        let mut total_size = 0u64;

        let dir_stream = fs::read_dir(&resolved)
            .await
            .map_err(FileManagerError::IoError)?;

        tokio::pin!(dir_stream);

        while let Some(entry) = dir_stream
            .next_entry()
            .await
            .map_err(FileManagerError::IoError)?
        {
            let entry_path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            if name.starts_with('.') && !self.config.allow_hidden_files {
                continue;
            }

            let is_hidden = self.check_hidden_file(&entry_path);

            if let Some(ref blocked_ext) = self.check_blocked_extension(&entry_path) {
                tracing::debug!("Skipping blocked extension: {}", blocked_ext);
                continue;
            }

            let entry_meta = entry.metadata().await.map_err(FileManagerError::IoError)?;

            let is_symlink = entry_meta.is_symlink();
            let is_dir = entry_meta.is_dir();

            let modified = entry_meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_secs());

            let permissions = Self::get_permissions_string(&entry_meta);

            let size = if is_dir { 0 } else { entry_meta.len() };
            total_size += size;

            if is_dir {
                dir_count += 1;
            } else {
                file_count += 1;
            }

            let relative_path = if path == "/" {
                format!("/{}", name)
            } else {
                format!("{}/{}", path.trim_end_matches('/'), name)
            };

            entries.push(FileEntry {
                name,
                path: relative_path,
                is_directory: is_dir,
                size,
                modified,
                permissions,
                is_hidden,
                is_symlink,
            });
        }

        entries.sort_by(|a, b| match (a.is_directory, b.is_directory) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        });

        let total_count = entries.len();

        Ok(DirectoryListing {
            path: path.to_string(),
            entries,
            total_count,
            directory_count: dir_count,
            file_count,
            total_size,
        })
    }

    pub async fn read_file(&self, path: &str) -> Result<Vec<u8>, FileManagerError> {
        let resolved = self.validate_and_resolve_path(path).await?;

        let metadata = fs::metadata(&resolved)
            .await
            .map_err(FileManagerError::IoError)?;

        if metadata.is_dir() {
            return Err(FileManagerError::InvalidPath(
                "cannot read directory as file".to_string(),
            ));
        }

        if metadata.len() > self.config.max_file_size {
            return Err(FileManagerError::FileTooLarge(format!(
                "file size {} exceeds maximum {}",
                metadata.len(),
                self.config.max_file_size
            )));
        }

        let data = fs::read(&resolved)
            .await
            .map_err(FileManagerError::IoError)?;

        Ok(data)
    }

    pub async fn write_file(&self, path: &str, data: Vec<u8>) -> Result<(), FileManagerError> {
        if data.len() as u64 > self.config.max_file_size {
            return Err(FileManagerError::FileTooLarge(format!(
                "file size {} exceeds maximum {}",
                data.len(),
                self.config.max_file_size
            )));
        }

        let resolved = self.validate_and_resolve_path(path).await?;

        if let Some(ref blocked_ext) = self.check_blocked_extension(&resolved) {
            return Err(FileManagerError::ExtensionBlocked(blocked_ext.clone()));
        }

        fs::write(&resolved, data)
            .await
            .map_err(FileManagerError::IoError)?;

        Ok(())
    }

    pub async fn create_directory(&self, path: &str) -> Result<(), FileManagerError> {
        let resolved = self.validate_and_resolve_path(path).await?;

        if resolved.exists() {
            return Err(FileManagerError::FileExists(format!(
                "path already exists: {}",
                path
            )));
        }

        fs::create_dir_all(&resolved)
            .await
            .map_err(FileManagerError::IoError)?;

        Ok(())
    }

    pub async fn delete(&self, path: &str) -> Result<(), FileManagerError> {
        let resolved = self.validate_and_resolve_path(path).await?;

        if !resolved.exists() {
            return Err(FileManagerError::NotFound(path.to_string()));
        }

        let metadata = fs::metadata(&resolved)
            .await
            .map_err(FileManagerError::IoError)?;

        if metadata.is_dir() {
            let mut entries = fs::read_dir(&resolved)
                .await
                .map_err(FileManagerError::IoError)?;

            if entries
                .next_entry()
                .await
                .map_err(FileManagerError::IoError)?
                .is_some()
            {
                return Err(FileManagerError::DirectoryNotEmpty(path.to_string()));
            }

            fs::remove_dir(&resolved)
                .await
                .map_err(FileManagerError::IoError)?;
        } else {
            fs::remove_file(&resolved)
                .await
                .map_err(FileManagerError::IoError)?;
        }

        Ok(())
    }

    pub async fn rename(&self, old_path: &str, new_path: &str) -> Result<(), FileManagerError> {
        let old_resolved = self.validate_and_resolve_path(old_path).await?;
        let new_resolved = self.validate_and_resolve_path(new_path).await?;

        if !old_resolved.exists() {
            return Err(FileManagerError::NotFound(old_path.to_string()));
        }

        if new_resolved.exists() {
            return Err(FileManagerError::FileExists(format!(
                "destination already exists: {}",
                new_path
            )));
        }

        if let Some(ref blocked_ext) = self.check_blocked_extension(&new_resolved) {
            return Err(FileManagerError::ExtensionBlocked(blocked_ext.clone()));
        }

        fs::rename(&old_resolved, &new_resolved)
            .await
            .map_err(FileManagerError::IoError)?;

        Ok(())
    }

    pub async fn get_permissions(&self, path: &str) -> Result<Permissions, FileManagerError> {
        let resolved = self.validate_and_resolve_path(path).await?;

        let metadata = fs::metadata(&resolved)
            .await
            .map_err(FileManagerError::IoError)?;

        Ok(Self::get_permissions_from_metadata(&metadata))
    }

    pub async fn set_permissions(&self, path: &str, mode: u32) -> Result<(), FileManagerError> {
        let resolved = self.validate_and_resolve_path(path).await?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(mode as _);
            fs::set_permissions(&resolved, permissions)
                .await
                .map_err(FileManagerError::IoError)?;
        }

        #[cfg(not(unix))]
        {
            let _ = (resolved, mode);
            return Err(FileManagerError::OperationNotPermitted);
        }

        Ok(())
    }

    pub async fn search(&self, query: &str, path: &str) -> Result<SearchResult, FileManagerError> {
        let resolved = self.validate_and_resolve_path(path).await?;

        let metadata = fs::metadata(&resolved)
            .await
            .map_err(FileManagerError::IoError)?;

        if !metadata.is_dir() {
            return Err(FileManagerError::InvalidPath(
                "search must be performed on a directory".to_string(),
            ));
        }

        let query_lower = query.to_lowercase();
        let mut matches = Vec::new();

        for entry in WalkDir::new(&resolved)
            .follow_links(self.config.allow_symlinks)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let entry_path = entry.path();
            let name = entry_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            if name.to_lowercase().contains(&query_lower) {
                let relative_path = entry_path
                    .strip_prefix(&resolved)
                    .map(|p| {
                        let p_str = p.to_string_lossy();
                        if path == "/" {
                            format!("/{}", p_str)
                        } else {
                            format!("{}/{}", path.trim_end_matches('/'), p_str)
                        }
                    })
                    .unwrap_or_else(|_| path.to_string());

                let entry_meta = entry.metadata().ok();

                let modified = entry_meta
                    .as_ref()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs());

                let permissions = entry_meta.as_ref().and_then(Self::get_permissions_string);

                matches.push(FileEntry {
                    name: name.to_string(),
                    path: relative_path,
                    is_directory: entry_path.is_dir(),
                    size: entry_meta.as_ref().map(|m| m.len()).unwrap_or(0),
                    modified,
                    permissions,
                    is_hidden: self.check_hidden_file(entry_path),
                    is_symlink: entry_meta.as_ref().map(|m| m.is_symlink()).unwrap_or(false),
                });

                if matches.len() >= 1000 {
                    break;
                }
            }
        }

        let total_matches = matches.len();

        Ok(SearchResult {
            query: query.to_string(),
            matches,
            total_matches,
        })
    }

    pub async fn upload_file(
        &self,
        dest_path: &str,
        filename: &str,
        data: Vec<u8>,
    ) -> Result<FileEntry, FileManagerError> {
        if data.len() as u64 > self.config.max_file_size {
            return Err(FileManagerError::FileTooLarge(format!(
                "file size {} exceeds maximum {}",
                data.len(),
                self.config.max_file_size
            )));
        }

        if !self
            .security
            .check_upload_rate_allowed("file_manager", data.len() as u64)
        {
            tracing::warn!("Upload rate limit exceeded for file_manager");
            return Err(FileManagerError::InvalidPath(
                "Rate limit exceeded for uploads".to_string(),
            ));
        }

        let clean_filename = filename
            .replace(['/', '\\', '\0'], "_")
            .replace("..", "_")
            .trim()
            .to_string();

        if clean_filename.is_empty() {
            return Err(FileManagerError::InvalidPath("empty filename".to_string()));
        }

        let file_path = if dest_path == "/" {
            format!("/{}", clean_filename)
        } else {
            format!("{}/{}", dest_path.trim_end_matches('/'), clean_filename)
        };

        let resolved = self.validate_and_resolve_path(&file_path).await?;

        if let Some(ref blocked_ext) = self.check_blocked_extension(&resolved) {
            return Err(FileManagerError::ExtensionBlocked(blocked_ext.clone()));
        }

        if !self.config.allowed_mime_types.is_empty() {
            let detected_mime_types = self.security.detect_content_mime_types(&data);
            if let Some(mime) = detected_mime_types.first() {
                if !self.config.allowed_mime_types.iter().any(|m| m == mime) {
                    tracing::warn!(
                        "Upload rejected: MIME type {} not in allowed list: {:?}",
                        mime,
                        self.config.allowed_mime_types
                    );
                    return Err(FileManagerError::InvalidPath(format!(
                        "MIME type {} not allowed",
                        mime
                    )));
                }
            }

            if let Some(claimed_ext) = resolved.extension().and_then(|e| e.to_str()) {
                let claimed_mime = format!("application/{}", claimed_ext);
                if !self
                    .config
                    .allowed_mime_types
                    .iter()
                    .any(|m| m == &claimed_mime)
                    && detected_mime_types.iter().any(|m| *m != claimed_mime)
                {
                    tracing::warn!(
                        "Upload warning: extension MIME mismatch - claimed: {}, detected: {:?}",
                        claimed_mime,
                        detected_mime_types
                    );
                }
            }
        }

        if self.config.scan_on_upload {
            // Scanner generation is owned by the injected backend; rule
            // updates require constructing a new backend + manager.
            // See module docs for the rule-update lifecycle.
            match self.security.scan_upload_bytes(&data).await {
                Ok(matched) if !matched.is_empty() => {
                    tracing::warn!(
                        "Upload blocked: malware detected in file {} - matches: {:?}",
                        filename,
                        matched
                    );
                    return Err(FileManagerError::MalwareDetected(matched.join(", ")));
                }
                Err(e) => {
                    tracing::warn!("Malware scan error for file {}: {}", filename, e);
                }
                _ => {}
            }
        }

        fs::write(&resolved, data)
            .await
            .map_err(FileManagerError::IoError)?;

        let metadata = fs::metadata(&resolved)
            .await
            .map_err(FileManagerError::IoError)?;

        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());

        Ok(FileEntry {
            name: clean_filename,
            path: file_path,
            is_directory: false,
            size: metadata.len(),
            modified,
            permissions: Self::get_permissions_string(&metadata),
            is_hidden: false,
            is_symlink: metadata.is_symlink(),
        })
    }

    pub async fn extract_archive(
        &self,
        archive_path: &str,
        dest_path: &str,
    ) -> Result<Vec<FileEntry>, FileManagerError> {
        let archive_resolved = self.validate_and_resolve_path(archive_path).await?;

        let ext = archive_resolved
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .unwrap_or_default();

        if !["zip", "tar", "gz", "tgz", "bz2"].contains(&ext.as_str()) {
            return Err(FileManagerError::InvalidPath(format!(
                "unsupported archive format: {}",
                ext
            )));
        }

        let dest_resolved = self.validate_and_resolve_path(dest_path).await?;

        if !dest_resolved.exists() {
            fs::create_dir_all(&dest_resolved)
                .await
                .map_err(FileManagerError::IoError)?;
        }

        let archive_data = fs::read(&archive_resolved)
            .await
            .map_err(FileManagerError::IoError)?;

        let mut extracted = Vec::new();

        match ext.as_str() {
            "zip" => {
                extracted = self.extract_zip(&archive_data, &dest_resolved).await?;
            }
            "tar" => {
                extracted = self.extract_tar(&archive_data, &dest_resolved).await?;
            }
            "gz" | "tgz" => {
                if archive_path.ends_with(".tar.gz") || archive_path.ends_with(".tgz") {
                    extracted = self.extract_tar_gz(&archive_data, &dest_resolved).await?;
                } else {
                    let file_name = archive_resolved
                        .file_stem()
                        .and_then(|n| n.to_str())
                        .unwrap_or("extracted");
                    let output_path = dest_resolved.join(file_name);
                    fs::write(&output_path, &archive_data)
                        .await
                        .map_err(FileManagerError::IoError)?;
                    extracted.push(self.entry_from_path(&output_path, &dest_resolved).await?);
                }
            }
            "bz2" => {
                let file_name = archive_resolved
                    .file_stem()
                    .and_then(|n| n.to_str())
                    .unwrap_or("extracted");
                let output_path = dest_resolved.join(file_name);
                fs::write(&output_path, &archive_data)
                    .await
                    .map_err(FileManagerError::IoError)?;
                extracted.push(self.entry_from_path(&output_path, &dest_resolved).await?);
            }
            _ => {
                return Err(FileManagerError::InvalidPath(format!(
                    "unsupported archive format: {}",
                    ext
                )));
            }
        }

        Ok(extracted)
    }

    #[cfg(feature = "archive")]
    async fn extract_zip(
        &self,
        data: &[u8],
        dest: &Path,
    ) -> Result<Vec<FileEntry>, FileManagerError> {
        use std::io::Cursor;
        use std::path::PathBuf;

        let reader = Cursor::new(data);
        let mut archive = zip::ZipArchive::new(reader)
            .map_err(|e| FileManagerError::InvalidPath(format!("invalid zip: {}", e)))?;

        let mut extracted = Vec::new();
        let mut total_extracted_size: u64 = 0;
        let max_size = self.config.archive_max_size;
        let max_compression_ratio = 10;

        let dest_canonical = dest.canonicalize()?;

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|e| FileManagerError::InvalidPath(format!("zip error: {}", e)))?;

            let compressed_size = file.compressed_size();
            let uncompressed_size = file.size();

            if uncompressed_size > 0 && compressed_size > 0 {
                let ratio = uncompressed_size as f64 / compressed_size as f64;
                if ratio > max_compression_ratio as f64 {
                    return Err(FileManagerError::InvalidPath(format!(
                        "potential zip bomb detected: compression ratio {} exceeds limit {}",
                        ratio, max_compression_ratio
                    )));
                }
            }

            let outpath = dest.join(file.name());

            let outpath_canonical = outpath.canonicalize().unwrap_or_else(|_| {
                outpath.components().fold(PathBuf::new(), |mut acc, c| {
                    match c {
                        std::path::Component::ParentDir => {
                            if let Some(parent) = acc.parent() {
                                acc = parent.to_path_buf();
                            }
                        }
                        std::path::Component::Normal(s) => {
                            acc.push(s);
                        }
                        _ => {}
                    }
                    acc
                })
            });

            if !outpath_canonical.starts_with(&dest_canonical) {
                return Err(FileManagerError::InvalidPath(
                    "Path traversal attempt detected in ZIP archive".to_string(),
                ));
            }

            let file_size = file.size();

            if total_extracted_size.saturating_add(file_size) > max_size {
                return Err(FileManagerError::InvalidPath(format!(
                    "archive extraction would exceed maximum size limit of {} bytes",
                    max_size
                )));
            }

            if file.name().ends_with('/') {
                fs::create_dir_all(&outpath)
                    .await
                    .map_err(FileManagerError::IoError)?;
            } else {
                if let Some(parent) = outpath.parent() {
                    fs::create_dir_all(parent)
                        .await
                        .map_err(FileManagerError::IoError)?;
                }

                let mut outfile = fs::File::create(&outpath)
                    .await
                    .map_err(FileManagerError::IoError)?;
                let bytes_copied = tokio::io::copy(&mut file, &mut outfile)
                    .await
                    .map_err(FileManagerError::IoError)?;
                total_extracted_size += bytes_copied;
            }

            extracted.push(self.entry_from_path(&outpath, dest).await?);
        }

        Ok(extracted)
    }

    #[cfg(not(feature = "archive"))]
    async fn extract_zip(
        &self,
        _data: &[u8],
        _dest: &Path,
    ) -> Result<Vec<FileEntry>, FileManagerError> {
        Err(FileManagerError::OperationNotPermitted)
    }

    #[cfg(feature = "archive")]
    async fn extract_tar(
        &self,
        data: &[u8],
        dest: &Path,
    ) -> Result<Vec<FileEntry>, FileManagerError> {
        use std::io::Cursor;
        use std::path::PathBuf;

        let reader = Cursor::new(data);
        let mut archive = tar::Archive::new(reader);

        let mut extracted = Vec::new();
        let mut total_extracted_size: u64 = 0;
        let max_size = self.config.archive_max_size;

        let dest_canonical = dest.canonicalize()?;

        for entry in archive
            .entries()
            .map_err(|e| FileManagerError::InvalidPath(format!("invalid tar: {}", e)))?
        {
            let mut entry = entry.map_err(FileManagerError::IoError)?;

            let entry_type = entry.header().entry_type();
            if entry_type.is_symlink() || entry_type.is_hard_link() {
                return Err(FileManagerError::InvalidPath(
                    "symbolic and hard links are not allowed in extracted archives".to_string(),
                ));
            }

            let entry_path = entry
                .path()
                .map_err(FileManagerError::IoError)?
                .into_owned();
            let outpath = dest.join(&entry_path);

            let outpath_canonical = outpath.canonicalize().unwrap_or_else(|_| {
                outpath.components().fold(PathBuf::new(), |mut acc, c| {
                    match c {
                        std::path::Component::ParentDir => {
                            if let Some(parent) = acc.parent() {
                                acc = parent.to_path_buf();
                            }
                        }
                        std::path::Component::Normal(s) => {
                            acc.push(s);
                        }
                        _ => {}
                    }
                    acc
                })
            });

            if !outpath_canonical.starts_with(&dest_canonical) {
                return Err(FileManagerError::InvalidPath(
                    "Path traversal attempt detected in TAR archive".to_string(),
                ));
            }

            let entry_size = entry.header().size().unwrap_or(0);

            if total_extracted_size.saturating_add(entry_size) > max_size {
                return Err(FileManagerError::InvalidPath(format!(
                    "archive extraction would exceed maximum size limit of {} bytes",
                    max_size
                )));
            }

            entry
                .unpack_in(dest)
                .await
                .map_err(FileManagerError::IoError)?;

            total_extracted_size += entry_size;

            let path = dest.join(&entry_path);
            extracted.push(self.entry_from_path(&path, dest).await?);
        }

        Ok(extracted)
    }

    #[cfg(not(feature = "archive"))]
    async fn extract_tar(
        &self,
        _data: &[u8],
        _dest: &Path,
    ) -> Result<Vec<FileEntry>, FileManagerError> {
        Err(FileManagerError::OperationNotPermitted)
    }

    #[cfg(feature = "archive")]
    async fn extract_tar_gz(
        &self,
        data: &[u8],
        dest: &Path,
    ) -> Result<Vec<FileEntry>, FileManagerError> {
        use std::io::Cursor;
        use std::path::PathBuf;

        let decoder = Cursor::new(data);
        let mut decoder = flate2::read::GzDecoder::new(decoder);

        let mut archive = tar::Archive::new(&mut decoder);

        let mut extracted = Vec::new();
        let mut total_extracted_size: u64 = 0;
        let max_size = self.config.archive_max_size;

        let dest_canonical = dest.canonicalize()?;

        for entry in archive
            .entries()
            .map_err(|e| FileManagerError::InvalidPath(format!("invalid tar.gz: {}", e)))?
        {
            let mut entry = entry.map_err(FileManagerError::IoError)?;

            let entry_type = entry.header().entry_type();
            if entry_type.is_symlink() || entry_type.is_hard_link() {
                return Err(FileManagerError::InvalidPath(
                    "symbolic and hard links are not allowed in extracted archives".to_string(),
                ));
            }

            let entry_path = entry
                .path()
                .map_err(FileManagerError::IoError)?
                .into_owned();
            let outpath = dest.join(&entry_path);

            let outpath_canonical = outpath.canonicalize().unwrap_or_else(|_| {
                outpath.components().fold(PathBuf::new(), |mut acc, c| {
                    match c {
                        std::path::Component::ParentDir => {
                            if let Some(parent) = acc.parent() {
                                acc = parent.to_path_buf();
                            }
                        }
                        std::path::Component::Normal(s) => {
                            acc.push(s);
                        }
                        _ => {}
                    }
                    acc
                })
            });

            if !outpath_canonical.starts_with(&dest_canonical) {
                return Err(FileManagerError::InvalidPath(
                    "Path traversal attempt detected in TAR.GZ archive".to_string(),
                ));
            }

            let entry_size = entry.header().size().unwrap_or(0);

            if total_extracted_size.saturating_add(entry_size) > max_size {
                return Err(FileManagerError::InvalidPath(format!(
                    "archive extraction would exceed maximum size limit of {} bytes",
                    max_size
                )));
            }

            entry
                .unpack_in(dest)
                .await
                .map_err(FileManagerError::IoError)?;

            total_extracted_size += entry_size;

            let path = dest.join(&entry_path);
            extracted.push(self.entry_from_path(&path, dest).await?);
        }

        Ok(extracted)
    }

    #[cfg(not(feature = "archive"))]
    async fn extract_tar_gz(
        &self,
        _data: &[u8],
        _dest: &Path,
    ) -> Result<Vec<FileEntry>, FileManagerError> {
        Err(FileManagerError::OperationNotPermitted)
    }

    async fn entry_from_path(
        &self,
        path: &Path,
        base: &Path,
    ) -> Result<FileEntry, FileManagerError> {
        let metadata = fs::metadata(path)
            .await
            .map_err(FileManagerError::IoError)?;

        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        let relative_path = path
            .strip_prefix(base)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| name.clone());

        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());

        Ok(FileEntry {
            name,
            path: format!("/{}", relative_path),
            is_directory: metadata.is_dir(),
            size: metadata.len(),
            modified,
            permissions: Self::get_permissions_string(&metadata),
            is_hidden: self.check_hidden_file(path),
            is_symlink: metadata.is_symlink(),
        })
    }

    fn get_permissions_string(metadata: &std::fs::Metadata) -> Option<String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            Some(format!("{:o}", mode))
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            None
        }
    }

    fn get_permissions_from_metadata(metadata: &std::fs::Metadata) -> Permissions {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            Permissions {
                mode: Self::format_mode(mode),
                octal: format!("{:o}", mode),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Permissions {
                mode: "unknown".to_string(),
                octal: "0".to_string(),
            }
        }
    }

    #[cfg(unix)]
    fn format_mode(mode: u32) -> String {
        let mut s = String::with_capacity(9);

        s.push(if mode & 0o400 != 0 { 'r' } else { '-' });
        s.push(if mode & 0o200 != 0 { 'w' } else { '-' });
        s.push(if mode & 0o100 != 0 { 'x' } else { '-' });

        s.push(if mode & 0o040 != 0 { 'r' } else { '-' });
        s.push(if mode & 0o020 != 0 { 'w' } else { '-' });
        s.push(if mode & 0o010 != 0 { 'x' } else { '-' });

        s.push(if mode & 0o004 != 0 { 'r' } else { '-' });
        s.push(if mode & 0o002 != 0 { 'w' } else { '-' });
        s.push(if mode & 0o001 != 0 { 'x' } else { '-' });

        s
    }
}

fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let num: u64 = s
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .ok()?;
    let suffix = s
        .chars()
        .skip_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .trim()
        .to_lowercase();
    let multiplier = match suffix.as_str() {
        "kb" | "k" => 1024,
        "mb" | "m" => 1024 * 1024,
        "gb" | "g" => 1024 * 1024 * 1024,
        "" => 1,
        _ => return None,
    };
    Some(num * multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn test_manager(config: FileManagerConfig) -> FileManager {
        FileManager::new(config, Arc::new(AllowAllSecurityBackend))
    }

    /// Configurable backend for policy tests (malware, rate limit, MIME).
    #[derive(Debug)]
    struct TestBackend {
        scan_matches: Vec<String>,
        scan_error: Option<String>,
        rate_allowed: bool,
        mime_types: Vec<String>,
        version: Option<String>,
    }

    impl Default for TestBackend {
        fn default() -> Self {
            Self {
                scan_matches: Vec::new(),
                scan_error: None,
                rate_allowed: true,
                mime_types: Vec::new(),
                version: None,
            }
        }
    }

    #[async_trait::async_trait]
    impl FileManagerSecurityBackend for TestBackend {
        async fn scan_upload_bytes(&self, _data: &[u8]) -> Result<Vec<String>, String> {
            if let Some(err) = &self.scan_error {
                return Err(err.clone());
            }
            Ok(self.scan_matches.clone())
        }

        fn check_upload_rate_allowed(&self, _client_key: &str, _bytes: u64) -> bool {
            self.rate_allowed
        }

        fn detect_content_mime_types(&self, _data: &[u8]) -> Vec<String> {
            self.mime_types.clone()
        }

        fn yara_rule_version(&self) -> Option<String> {
            self.version.clone()
        }
    }

    fn test_manager_with_backend(config: FileManagerConfig, backend: TestBackend) -> FileManager {
        FileManager::new(config, Arc::new(backend))
    }

    #[test]
    fn test_parse_size() {
        assert_eq!(parse_size("1024"), Some(1024));
        assert_eq!(parse_size("1kb"), Some(1024));
        assert_eq!(parse_size("1mb"), Some(1024 * 1024));
        assert_eq!(parse_size("1gb"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_size("100"), Some(100));
    }

    #[test]
    fn test_default_config() {
        let config = FileManagerConfig::default();
        assert!(!config.enabled);
        assert!(config.is_extension_blocked("exe"));
        assert!(config.is_extension_blocked("dll"));
        assert!(!config.is_extension_blocked("txt"));
    }

    #[tokio::test]
    async fn test_extension_blocking_with_allowlist() {
        let config = FileManagerConfig {
            allowed_extensions: vec!["txt".to_string(), "md".to_string()],
            ..FileManagerConfig::default()
        };

        assert!(!config.is_extension_blocked("txt"));
        assert!(!config.is_extension_blocked("md"));
        assert!(config.is_extension_blocked("exe"));
    }

    #[tokio::test]
    async fn test_new_mutation_paths_resolve_under_root() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = FileManagerConfig {
            enabled: true,
            root_path: temp_dir.path().to_path_buf(),
            ..FileManagerConfig::default()
        };
        let manager = test_manager(config);

        manager.create_directory("/new/nested").await.unwrap();
        manager
            .write_file("/new/nested/file.txt", b"safe".to_vec())
            .await
            .unwrap();

        assert_eq!(
            manager.read_file("/new/nested/file.txt").await.unwrap(),
            b"safe"
        );
    }

    #[tokio::test]
    async fn test_new_mutation_path_rejects_parent_escape() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = FileManagerConfig {
            enabled: true,
            root_path: temp_dir.path().to_path_buf(),
            ..FileManagerConfig::default()
        };
        let manager = test_manager(config);

        assert!(matches!(
            manager
                .write_file("/../outside.txt", b"blocked".to_vec())
                .await,
            Err(FileManagerError::PathTraversal)
        ));
    }

    #[cfg(feature = "archive")]
    #[tokio::test]
    async fn test_extract_zip_rejects_traversal_entry() {
        use std::io::Cursor;

        let temp_dir = tempfile::tempdir().unwrap();
        let config = FileManagerConfig {
            enabled: true,
            root_path: temp_dir.path().to_path_buf(),
            ..FileManagerConfig::default()
        };
        let manager = test_manager(config);

        let dest_dir = temp_dir.path().join("extract_dest");

        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buf);
            zip.start_file("../../../etc/passwd", Default::default())
                .unwrap();
            zip.write_all(b"pwned").unwrap();
            zip.finish().unwrap();
        }
        let archive_data = buf.into_inner();

        let result = manager.extract_archive("/test.zip", "/extract_dest").await;
        match result {
            Err(FileManagerError::InvalidPath(msg)) if msg.contains("Path traversal") => {}
            Err(FileManagerError::OperationNotPermitted) => {}
            other => panic!(
                "Expected path traversal or feature-gated error, got: {:?}",
                other
            ),
        }

        assert!(
            !dest_dir.join("../../../etc/passwd").exists(),
            "Path traversal must not write outside destination"
        );
    }

    #[tokio::test]
    async fn test_dotdot_escape_variants_rejected() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = FileManagerConfig {
            enabled: true,
            root_path: temp_dir.path().to_path_buf(),
            ..FileManagerConfig::default()
        };
        let manager = test_manager(config);

        for path in [
            "/..",
            "/../outside.txt",
            "/a/../../escape.txt",
            "/a/b/../../../../escape.txt",
        ] {
            assert!(
                matches!(
                    manager.write_file(path, b"blocked".to_vec()).await,
                    Err(FileManagerError::PathTraversal)
                ),
                "expected PathTraversal for {path}"
            );
        }

        for path in ["", "/\0evil", "evil\0.txt"] {
            assert!(
                matches!(
                    manager.read_file(path).await,
                    Err(FileManagerError::InvalidPath(_))
                ),
                "expected InvalidPath for {path:?}"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_symlinked_ancestor_escape_rejected() {
        use std::os::unix::fs::symlink;

        let outside_dir = tempfile::tempdir().unwrap();
        std::fs::write(outside_dir.path().join("secret.txt"), b"secret").unwrap();

        let root_dir = tempfile::tempdir().unwrap();
        symlink(outside_dir.path(), root_dir.path().join("link")).unwrap();

        let config = FileManagerConfig {
            enabled: true,
            root_path: root_dir.path().to_path_buf(),
            ..FileManagerConfig::default()
        };
        let manager = test_manager(config);

        // Existing file reached through a symlinked ancestor escapes the root.
        assert!(matches!(
            manager.read_file("/link/secret.txt").await,
            Err(FileManagerError::PathTraversal)
        ));

        // Missing-leaf mutation under a symlinked ancestor whose nearest
        // existing ancestor is outside the root must also be rejected.
        assert!(matches!(
            manager
                .write_file("/link/new-evil.txt", b"blocked".to_vec())
                .await,
            Err(FileManagerError::PathTraversal)
        ));
    }

    #[tokio::test]
    async fn test_hidden_file_policy() {
        let temp_dir = tempfile::tempdir().unwrap();
        std::fs::write(temp_dir.path().join(".hidden.txt"), b"h").unwrap();
        std::fs::write(temp_dir.path().join("visible.txt"), b"v").unwrap();

        let hidden_closed = test_manager(FileManagerConfig {
            enabled: true,
            root_path: temp_dir.path().to_path_buf(),
            allow_hidden_files: false,
            ..FileManagerConfig::default()
        });
        let listing = hidden_closed.list_directory("/").await.unwrap();
        assert!(listing.entries.iter().all(|e| !e.is_hidden));
        assert!(listing.entries.iter().any(|e| e.name == "visible.txt"));

        let hidden_open = test_manager(FileManagerConfig {
            enabled: true,
            root_path: temp_dir.path().to_path_buf(),
            allow_hidden_files: true,
            ..FileManagerConfig::default()
        });
        let listing = hidden_open.list_directory("/").await.unwrap();
        assert!(listing.entries.iter().any(|e| e.name == ".hidden.txt"));
    }

    #[tokio::test]
    async fn test_blocked_extension_enforced_on_write_and_upload() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manager = test_manager(FileManagerConfig {
            enabled: true,
            root_path: temp_dir.path().to_path_buf(),
            ..FileManagerConfig::default()
        });

        assert!(matches!(
            manager.write_file("/evil.exe", b"x".to_vec()).await,
            Err(FileManagerError::ExtensionBlocked(_))
        ));
        assert!(matches!(
            manager.upload_file("/", "evil.dll", b"x".to_vec()).await,
            Err(FileManagerError::ExtensionBlocked(_))
        ));
        manager
            .write_file("/ok.txt", b"fine".to_vec())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_max_path_depth_enforced_for_missing_leaf() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manager = test_manager(FileManagerConfig {
            enabled: true,
            root_path: temp_dir.path().to_path_buf(),
            ..FileManagerConfig::default()
        });

        let deep = format!("/{}/leaf.txt", vec!["a"; 60].join("/"));
        assert!(matches!(
            manager.write_file(&deep, b"x".to_vec()).await,
            Err(FileManagerError::InvalidPath(_))
        ));
    }

    #[tokio::test]
    async fn test_file_size_limits() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manager = test_manager(FileManagerConfig {
            enabled: true,
            root_path: temp_dir.path().to_path_buf(),
            max_file_size: 4,
            ..FileManagerConfig::default()
        });

        assert!(matches!(
            manager.write_file("/big.txt", b"12345".to_vec()).await,
            Err(FileManagerError::FileTooLarge(_))
        ));
        assert!(matches!(
            manager.upload_file("/", "big.txt", b"12345".to_vec()).await,
            Err(FileManagerError::FileTooLarge(_))
        ));

        // Existing oversized file is rejected on read.
        std::fs::write(temp_dir.path().join("big.txt"), b"12345").unwrap();
        assert!(matches!(
            manager.read_file("/big.txt").await,
            Err(FileManagerError::FileTooLarge(_))
        ));
    }

    #[tokio::test]
    async fn test_directory_file_type_confusion() {
        let temp_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp_dir.path().join("subdir")).unwrap();
        std::fs::write(temp_dir.path().join("file.txt"), b"data").unwrap();
        let manager = test_manager(FileManagerConfig {
            enabled: true,
            root_path: temp_dir.path().to_path_buf(),
            ..FileManagerConfig::default()
        });

        assert!(matches!(
            manager.read_file("/subdir").await,
            Err(FileManagerError::InvalidPath(_))
        ));
        assert!(matches!(
            manager.list_directory("/file.txt").await,
            Err(FileManagerError::InvalidPath(_))
        ));
        assert!(matches!(
            manager.search("x", "/file.txt").await,
            Err(FileManagerError::InvalidPath(_))
        ));
    }

    #[tokio::test]
    async fn test_delete_rejects_non_empty_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp_dir.path().join("full")).unwrap();
        std::fs::write(temp_dir.path().join("full/a.txt"), b"a").unwrap();
        std::fs::create_dir(temp_dir.path().join("empty")).unwrap();
        let manager = test_manager(FileManagerConfig {
            enabled: true,
            root_path: temp_dir.path().to_path_buf(),
            ..FileManagerConfig::default()
        });

        assert!(matches!(
            manager.delete("/full").await,
            Err(FileManagerError::DirectoryNotEmpty(_))
        ));
        assert!(matches!(
            manager.delete("/missing").await,
            Err(FileManagerError::NotFound(_))
        ));
        manager.delete("/empty").await.unwrap();
    }

    #[tokio::test]
    async fn test_upload_malware_detection_and_scan_error_policy() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = || FileManagerConfig {
            enabled: true,
            root_path: temp_dir.path().to_path_buf(),
            ..FileManagerConfig::default()
        };

        let infected = test_manager_with_backend(
            config(),
            TestBackend {
                scan_matches: vec!["EvilRule".to_string()],
                ..TestBackend::default()
            },
        );
        assert!(matches!(
            infected
                .upload_file("/", "evil.txt", b"payload".to_vec())
                .await,
            Err(FileManagerError::MalwareDetected(_))
        ));

        // Scan errors fail open with a warning (historical behavior): the
        // upload still succeeds.
        let flaky = test_manager_with_backend(
            config(),
            TestBackend {
                scan_error: Some("scanner unavailable".to_string()),
                ..TestBackend::default()
            },
        );
        flaky
            .upload_file("/", "maybe.txt", b"payload".to_vec())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_upload_rate_limit_and_mime_allowlist() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = |mime_types: Vec<String>| FileManagerConfig {
            enabled: true,
            root_path: temp_dir.path().to_path_buf(),
            allowed_mime_types: mime_types,
            ..FileManagerConfig::default()
        };

        let throttled = test_manager_with_backend(
            config(Vec::new()),
            TestBackend {
                rate_allowed: false,
                ..TestBackend::default()
            },
        );
        assert!(matches!(
            throttled.upload_file("/", "a.txt", b"x".to_vec()).await,
            Err(FileManagerError::InvalidPath(msg)) if msg.contains("Rate limit")
        ));

        let mime_enforced = test_manager_with_backend(
            config(vec!["text/plain".to_string()]),
            TestBackend {
                mime_types: vec!["application/x-dosexec".to_string()],
                ..TestBackend::default()
            },
        );
        assert!(matches!(
            mime_enforced.upload_file("/", "a.txt", b"MZ".to_vec()).await,
            Err(FileManagerError::InvalidPath(msg)) if msg.contains("MIME type")
        ));

        let mime_ok = test_manager_with_backend(
            config(vec!["text/plain".to_string()]),
            TestBackend {
                mime_types: vec!["text/plain".to_string()],
                ..TestBackend::default()
            },
        );
        mime_ok
            .upload_file("/", "ok.txt", b"hello".to_vec())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_yara_rule_version_delegates_to_backend() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manager = test_manager_with_backend(
            FileManagerConfig {
                enabled: true,
                root_path: temp_dir.path().to_path_buf(),
                ..FileManagerConfig::default()
            },
            TestBackend {
                version: Some("v42".to_string()),
                ..TestBackend::default()
            },
        );
        assert_eq!(manager.yara_rule_version(), Some("v42".to_string()));

        let unversioned = test_manager(FileManagerConfig {
            enabled: true,
            root_path: temp_dir.path().to_path_buf(),
            ..FileManagerConfig::default()
        });
        assert_eq!(unversioned.yara_rule_version(), None);
    }
}
