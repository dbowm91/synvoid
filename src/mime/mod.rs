pub mod nginx_parser;

use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::Path;
use std::sync::LazyLock;

pub static MIME_REGISTRY: LazyLock<RwLock<MimeRegistry>> =
    LazyLock::new(|| RwLock::new(MimeRegistry::with_defaults()));

pub fn init_mimes_from_file<P: AsRef<Path>>(path: P) -> Result<(), MimeError> {
    let mut registry = MIME_REGISTRY.write();
    registry.load_from_file(path)
}

pub fn reload_mimes_from_file<P: AsRef<Path>>(path: P) -> Result<(), MimeError> {
    let mut registry = MIME_REGISTRY.write();
    registry.clear();
    registry.register_defaults();
    match registry.load_from_file(path) {
        Ok(()) => Ok(()),
        Err(e) => {
            tracing::warn!("Failed to load mimes from file, using defaults: {}", e);
            Ok(())
        }
    }
}

pub fn reload_mimes_from_path(path: Option<&Path>) -> Result<(), MimeError> {
    if let Some(p) = path {
        reload_mimes_from_file(p)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileCategory {
    Image,
    Video,
    Audio,
    Document,
    Archive,
    Font,
    Code,
    Executable,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct MimeTypeInfo {
    pub mime_type: String,
    pub extensions: Vec<String>,
    pub category: FileCategory,
}

impl MimeTypeInfo {
    pub fn new(
        mime_type: impl Into<String>,
        extensions: Vec<String>,
        category: FileCategory,
    ) -> Self {
        Self {
            mime_type: mime_type.into(),
            extensions,
            category,
        }
    }

    pub fn primary_extension(&self) -> Option<&str> {
        self.extensions.first().map(|s| s.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct MimeRegistry {
    mime_to_extensions: HashMap<String, Vec<String>>,
    extension_to_mime: HashMap<String, String>,
    mime_categories: HashMap<String, FileCategory>,
}

impl Default for MimeRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl MimeRegistry {
    pub fn new() -> Self {
        Self {
            mime_to_extensions: HashMap::new(),
            extension_to_mime: HashMap::new(),
            mime_categories: HashMap::new(),
        }
    }

    pub fn clear(&mut self) {
        self.mime_to_extensions.clear();
        self.extension_to_mime.clear();
        self.mime_categories.clear();
    }

    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register_defaults();
        registry
    }

    fn register_defaults(&mut self) {
        let defaults = vec![
            (
                "text/html",
                vec!["html", "htm", "shtml"],
                FileCategory::Document,
            ),
            ("text/css", vec!["css"], FileCategory::Code),
            ("text/javascript", vec!["js", "mjs"], FileCategory::Code),
            ("text/plain", vec!["txt", "log"], FileCategory::Document),
            ("text/xml", vec!["xml"], FileCategory::Document),
            ("text/csv", vec!["csv"], FileCategory::Document),
            (
                "text/markdown",
                vec!["md", "markdown"],
                FileCategory::Document,
            ),
            ("image/gif", vec!["gif"], FileCategory::Image),
            (
                "image/jpeg",
                vec!["jpg", "jpeg", "jpe"],
                FileCategory::Image,
            ),
            ("image/png", vec!["png"], FileCategory::Image),
            ("image/webp", vec!["webp"], FileCategory::Image),
            ("image/svg+xml", vec!["svg", "svgz"], FileCategory::Image),
            ("image/avif", vec!["avif"], FileCategory::Image),
            ("image/bmp", vec!["bmp"], FileCategory::Image),
            ("image/tiff", vec!["tif", "tiff"], FileCategory::Image),
            ("image/x-icon", vec!["ico"], FileCategory::Image),
            ("video/mp4", vec!["mp4", "m4v"], FileCategory::Video),
            ("video/webm", vec!["webm"], FileCategory::Video),
            (
                "video/mpeg",
                vec!["mpeg", "mpg", "mpe"],
                FileCategory::Video,
            ),
            ("video/quicktime", vec!["mov"], FileCategory::Video),
            ("video/x-msvideo", vec!["avi"], FileCategory::Video),
            ("video/x-matroska", vec!["mkv"], FileCategory::Video),
            ("video/x-flv", vec!["flv"], FileCategory::Video),
            ("video/3gpp", vec!["3gp", "3gpp"], FileCategory::Video),
            ("audio/mpeg", vec!["mp3"], FileCategory::Audio),
            ("audio/ogg", vec!["ogg", "oga"], FileCategory::Audio),
            ("audio/wav", vec!["wav"], FileCategory::Audio),
            ("audio/webm", vec!["weba"], FileCategory::Audio),
            ("audio/aac", vec!["aac"], FileCategory::Audio),
            ("audio/x-m4a", vec!["m4a"], FileCategory::Audio),
            ("audio/flac", vec!["flac"], FileCategory::Audio),
            ("application/pdf", vec!["pdf"], FileCategory::Document),
            ("application/msword", vec!["doc"], FileCategory::Document),
            (
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                vec!["docx"],
                FileCategory::Document,
            ),
            (
                "application/vnd.ms-excel",
                vec!["xls"],
                FileCategory::Document,
            ),
            (
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                vec!["xlsx"],
                FileCategory::Document,
            ),
            (
                "application/vnd.ms-powerpoint",
                vec!["ppt"],
                FileCategory::Document,
            ),
            (
                "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                vec!["pptx"],
                FileCategory::Document,
            ),
            (
                "application/vnd.oasis.opendocument.text",
                vec!["odt"],
                FileCategory::Document,
            ),
            (
                "application/vnd.oasis.opendocument.spreadsheet",
                vec!["ods"],
                FileCategory::Document,
            ),
            (
                "application/vnd.oasis.opendocument.presentation",
                vec!["odp"],
                FileCategory::Document,
            ),
            ("application/rtf", vec!["rtf"], FileCategory::Document),
            ("application/zip", vec!["zip"], FileCategory::Archive),
            (
                "application/x-rar-compressed",
                vec!["rar"],
                FileCategory::Archive,
            ),
            (
                "application/x-7z-compressed",
                vec!["7z"],
                FileCategory::Archive,
            ),
            ("application/x-tar", vec!["tar"], FileCategory::Archive),
            (
                "application/gzip",
                vec!["gz", "gzip"],
                FileCategory::Archive,
            ),
            (
                "application/x-bzip2",
                vec!["bz2", "bzip2"],
                FileCategory::Archive,
            ),
            ("application/json", vec!["json"], FileCategory::Document),
            ("application/xml", vec!["xml"], FileCategory::Document),
            ("font/woff", vec!["woff"], FileCategory::Font),
            ("font/woff2", vec!["woff2"], FileCategory::Font),
            ("font/ttf", vec!["ttf"], FileCategory::Font),
            ("font/otf", vec!["otf"], FileCategory::Font),
            (
                "application/vnd.ms-fontobject",
                vec!["eot"],
                FileCategory::Font,
            ),
            (
                "application/x-msdownload",
                vec!["exe", "dll", "com"],
                FileCategory::Executable,
            ),
            ("application/x-sh", vec!["sh"], FileCategory::Code),
            ("application/x-python", vec!["py"], FileCategory::Code),
            ("application/wasm", vec!["wasm"], FileCategory::Code),
            (
                "application/octet-stream",
                vec!["bin", "dat"],
                FileCategory::Unknown,
            ),
        ];

        for (mime, exts, category) in defaults {
            self.register(mime, exts, category);
        }
    }

    pub fn register(&mut self, mime_type: &str, extensions: Vec<&str>, category: FileCategory) {
        let mime_lower = mime_type.to_lowercase();
        let exts_owned: Vec<String> = extensions.iter().map(|s| s.to_lowercase()).collect();

        self.mime_to_extensions
            .insert(mime_lower.clone(), exts_owned.clone());
        self.mime_categories.insert(mime_lower.clone(), category);

        for ext in exts_owned {
            self.extension_to_mime.insert(ext, mime_lower.clone());
        }
    }

    pub fn register_from_nginx_format(&mut self, content: &str) -> Result<(), MimeError> {
        let entries = nginx_parser::parse_nginx_mime_types(content)?;
        for (mime, extensions) in entries {
            let category = Self::categorize_by_mime(&mime);
            self.register(
                &mime,
                extensions.iter().map(|s| s.as_str()).collect(),
                category,
            );
        }
        Ok(())
    }

    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), MimeError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| MimeError::IoError(e.to_string()))?;
        self.register_from_nginx_format(&content)
    }

    fn categorize_by_mime(mime: &str) -> FileCategory {
        let mime_lower = mime.to_lowercase();
        if mime_lower.starts_with("image/") {
            FileCategory::Image
        } else if mime_lower.starts_with("video/") {
            FileCategory::Video
        } else if mime_lower.starts_with("audio/") {
            FileCategory::Audio
        } else if mime_lower.starts_with("font/") || mime_lower.contains("font") {
            FileCategory::Font
        } else if mime_lower.starts_with("text/")
            && (mime_lower.contains("javascript") || mime_lower.contains("css"))
        {
            FileCategory::Code
        } else if mime_lower.contains("zip")
            || mime_lower.contains("rar")
            || mime_lower.contains("tar")
            || mime_lower.contains("7z")
            || mime_lower.contains("gzip")
            || mime_lower.contains("bzip")
            || mime_lower.contains("compressed")
        {
            FileCategory::Archive
        } else if mime_lower.contains("executable")
            || mime_lower.contains("octet-stream")
            || mime_lower.contains("x-msdownload")
        {
            FileCategory::Executable
        } else {
            FileCategory::Document
        }
    }

    pub fn get_mime_for_extension(&self, extension: &str) -> Option<String> {
        self.extension_to_mime
            .get(&extension.to_lowercase())
            .cloned()
    }

    pub fn get_extensions_for_mime(&self, mime_type: &str) -> Option<Vec<String>> {
        self.mime_to_extensions
            .get(&mime_type.to_lowercase())
            .cloned()
    }

    pub fn get_category(&self, mime_type: &str) -> FileCategory {
        self.mime_categories
            .get(&mime_type.to_lowercase())
            .copied()
            .unwrap_or(FileCategory::Unknown)
    }

    pub fn get_info(&self, mime_type: &str) -> Option<MimeTypeInfo> {
        let mime_lower = mime_type.to_lowercase();
        let extensions = self.mime_to_extensions.get(&mime_lower)?.clone();
        let category = self
            .mime_categories
            .get(&mime_lower)
            .copied()
            .unwrap_or(FileCategory::Unknown);
        Some(MimeTypeInfo {
            mime_type: mime_lower,
            extensions,
            category,
        })
    }

    pub fn normalize_mime(&self, mime_type: &str) -> String {
        let normalized = mime_type
            .split(';')
            .next()
            .unwrap_or(mime_type)
            .trim()
            .to_lowercase();

        match normalized.as_str() {
            "image/jpg" | "image/jpe" => "image/jpeg".to_string(),
            "image/x-png" => "image/png".to_string(),
            "text/x-json" | "application/x-json" => "application/json".to_string(),
            "text/x-javascript" | "application/x-javascript" => "text/javascript".to_string(),
            _ => normalized,
        }
    }

    pub fn mime_matches_pattern(&self, mime_type: &str, pattern: &str) -> bool {
        let mime_lower = mime_type.to_lowercase();
        let pattern_lower = pattern.to_lowercase();

        if pattern_lower.ends_with("/*") {
            let prefix = &pattern_lower[..pattern_lower.len() - 1];
            mime_lower.starts_with(prefix)
        } else if pattern_lower.contains('*') {
            let parts: Vec<&str> = pattern_lower.split('*').collect();
            if parts.len() == 2 {
                mime_lower.starts_with(parts[0]) && mime_lower.ends_with(parts[1])
            } else {
                mime_lower == pattern_lower
            }
        } else {
            mime_lower == pattern_lower
        }
    }

    pub fn is_mime_allowed(&self, mime_type: &str, allowed_patterns: &[String]) -> bool {
        if allowed_patterns.is_empty() {
            return true;
        }

        let normalized = self.normalize_mime(mime_type);
        allowed_patterns
            .iter()
            .any(|pattern| self.mime_matches_pattern(&normalized, pattern))
    }

    pub fn all_mime_types(&self) -> Vec<String> {
        self.mime_to_extensions.keys().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.mime_to_extensions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mime_to_extensions.is_empty()
    }
}

pub fn detect_from_bytes(data: &[u8]) -> Option<MimeTypeInfo> {
    let kind = infer::get(data)?;
    let mime = kind.mime_type().to_string();
    let ext = kind.extension().to_string();

    let registry = MIME_REGISTRY.read();
    if let Some(info) = registry.get_info(&mime) {
        Some(info)
    } else {
        let category = MimeRegistry::categorize_by_mime(&mime);
        Some(MimeTypeInfo::new(mime, vec![ext], category))
    }
}

pub fn detect_from_bytes_with_fallback(data: &[u8], fallback_extension: &str) -> MimeTypeInfo {
    if let Some(info) = detect_from_bytes(data) {
        info
    } else {
        let registry = MIME_REGISTRY.read();
        if let Some(mime) = registry.get_mime_for_extension(fallback_extension) {
            if let Some(info) = registry.get_info(&mime) {
                return info;
            }
        }
        MimeTypeInfo::new(
            "application/octet-stream",
            vec![fallback_extension.to_string()],
            FileCategory::Unknown,
        )
    }
}

pub fn global_registry() -> &'static RwLock<MimeRegistry> {
    &MIME_REGISTRY
}

#[derive(Debug, Clone)]
pub enum MimeError {
    ParseError(String),
    IoError(String),
}

impl std::fmt::Display for MimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MimeError::ParseError(msg) => write!(f, "MIME parse error: {}", msg),
            MimeError::IoError(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for MimeError {}
