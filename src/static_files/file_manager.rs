#![allow(unexpected_cfgs)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::fs;
use walkdir::WalkDir;

use crate::config::site::SiteStaticConfig;

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

#[derive(Debug, Clone)]
pub struct FileManagerConfig {
    pub enabled: bool,
    pub root_path: PathBuf,
    pub max_file_size: u64,
    pub blocked_extensions: Vec<String>,
    pub allowed_extensions: Vec<String>,
    pub allow_hidden_files: bool,
    pub allow_symlinks: bool,
}

impl Default for FileManagerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            root_path: PathBuf::from("/"),
            max_file_size: 100 * 1024 * 1024,
            blocked_extensions: BLOCKED_EXTENSIONS.iter().map(|s| s.to_string()).collect(),
            allowed_extensions: Vec::new(),
            allow_hidden_files: false,
            allow_symlinks: false,
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
            allow_hidden_files: config.block_hidden_files.map(|v| !v).unwrap_or(false),
            allow_symlinks: config.allow_symlinks.unwrap_or(false),
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

        self.blocked_extensions
            .iter()
            .any(|e| e.to_lowercase() == ext_lower)
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
}

impl FileManager {
    pub fn new(config: FileManagerConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
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

        let user_path_clean = user_path.trim_start_matches('/');
        let full_path = self.config.root_path.join(user_path_clean);

        let canonical = tokio::fs::canonicalize(&self.config.root_path)
            .await
            .map_err(FileManagerError::IoError)?;

        if user_path_clean.is_empty() {
            return Ok(canonical);
        }

        let target_canonical = tokio::fs::canonicalize(&full_path)
            .await
            .or_else(|_| {
                if self.config.allow_symlinks {
                    Ok(full_path.clone())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "not found",
                    ))
                }
            })
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    FileManagerError::NotFound(user_path.to_string())
                } else {
                    FileManagerError::IoError(e)
                }
            })?;

        if !target_canonical.starts_with(&canonical) {
            tracing::warn!(
                "Path traversal attempt: {} -> {} (root: {})",
                user_path,
                target_canonical.display(),
                canonical.display()
            );
            return Err(FileManagerError::PathTraversal);
        }

        let depth = user_path_clean.matches('/').count();
        if depth > MAX_PATH_DEPTH {
            return Err(FileManagerError::InvalidPath(format!(
                "path depth exceeds maximum of {}",
                MAX_PATH_DEPTH
            )));
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

        let dest_canonical = dest
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from(dest));

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|e| FileManagerError::InvalidPath(format!("zip error: {}", e)))?;

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
                tokio::io::copy(&mut file, &mut outfile)
                    .await
                    .map_err(FileManagerError::IoError)?;
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
        let reader = Cursor::new(data);
        let mut archive = tar::Archive::new(reader);

        let mut extracted = Vec::new();

        for entry in archive
            .entries()
            .map_err(|e| FileManagerError::InvalidPath(format!("invalid tar: {}", e)))?
        {
            let mut entry = entry.map_err(FileManagerError::IoError)?;
            entry
                .unpack_in(dest)
                .await
                .map_err(FileManagerError::IoError)?;

            let path = dest.join(entry.path().map_err(FileManagerError::IoError)?);
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
        let decoder = Cursor::new(data);
        let mut decoder = flate2::read::GzDecoder::new(decoder);

        let mut archive = tar::Archive::new(&mut decoder);

        let mut extracted = Vec::new();

        for entry in archive
            .entries()
            .map_err(|e| FileManagerError::InvalidPath(format!("invalid tar.gz: {}", e)))?
        {
            let mut entry = entry.map_err(FileManagerError::IoError)?;
            entry
                .unpack_in(dest)
                .await
                .map_err(FileManagerError::IoError)?;

            let path = dest.join(entry.path().map_err(FileManagerError::IoError)?);
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
        let mut config = FileManagerConfig::default();
        config.allowed_extensions = vec!["txt".to_string(), "md".to_string()];

        assert!(!config.is_extension_blocked("txt"));
        assert!(!config.is_extension_blocked("md"));
        assert!(config.is_extension_blocked("exe"));
    }
}
