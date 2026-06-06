use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use bytes::Bytes;
use parking_lot::RwLock;
use thiserror::Error;

use synvoid_config::site::SiteStaticConfig;

use tokio::fs as async_fs;

#[derive(Error, Debug)]
pub enum MinifierError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("CSS minification error: {0}")]
    CssMinify(String),
    #[error("JS minification error: {0}")]
    JsMinify(String),
    #[error("HTML minification error: {0}")]
    HtmlMinify(String),
    #[error("Compression error: {0}")]
    Compression(String),
    #[error("File not found: {0}")]
    NotFound(String),
    #[error("Cache error: {0}")]
    Cache(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ContentType {
    Html,
    Css,
    Js,
    Svg,
    Other,
}

impl ContentType {
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "html" | "htm" => ContentType::Html,
            "css" => ContentType::Css,
            "js" | "mjs" => ContentType::Js,
            "svg" => ContentType::Svg,
            _ => ContentType::Other,
        }
    }

    pub fn from_mime(mime: &str) -> Self {
        if mime.contains("html") {
            ContentType::Html
        } else if mime.contains("css") {
            ContentType::Css
        } else if mime.contains("javascript") || mime.contains("js") {
            ContentType::Js
        } else if mime.contains("svg") {
            ContentType::Svg
        } else {
            ContentType::Other
        }
    }

    pub fn to_mime(&self) -> &'static str {
        match self {
            ContentType::Html => "text/html",
            ContentType::Css => "text/css",
            ContentType::Js => "application/javascript",
            ContentType::Svg => "image/svg+xml",
            ContentType::Other => "application/octet-stream",
        }
    }
}

pub fn content_type_from_path(path: &str) -> String {
    path.rsplit('.')
        .next()
        .map(|e| {
            let ct = ContentType::from_extension(e);
            ct.to_mime().to_string()
        })
        .unwrap_or_else(|| "application/octet-stream".to_string())
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Encoding {
    Gzip,
    Br,
    None,
}

impl Encoding {
    pub fn extension(&self) -> &str {
        match self {
            Encoding::Gzip => "gz",
            Encoding::Br => "br",
            Encoding::None => "",
        }
    }

    pub fn content_encoding(&self) -> &str {
        match self {
            Encoding::Gzip => "gzip",
            Encoding::Br => "br",
            Encoding::None => "",
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct CacheKey {
    pub site_id: Arc<str>,
    pub path: Arc<str>,
    pub encoding: Encoding,
}

#[derive(Clone)]
pub struct CacheEntry {
    pub content: Bytes,
    pub mtime: SystemTime,
    pub generated_at: Instant,
    pub content_type: ContentType,
}

pub struct MinifierConfig {
    pub enabled: bool,
    pub enable_html: bool,
    pub enable_css: bool,
    pub enable_js: bool,
    pub enable_svg: bool,
    pub enable_gzip: bool,
    pub enable_brotli: bool,
    pub gzip_level: u32,
    pub brotli_level: u32,
    pub minified_dir: PathBuf,
    pub enable_cache: bool,
    pub cache_max_entries: usize,
    pub cache_ttl_secs: u64,
}

impl MinifierConfig {
    pub fn from_site_config(site_id: &str, config: &SiteStaticConfig) -> Self {
        let enabled = config.enable_minification.unwrap_or(true);
        let global_cache_dir = std::env::var("SYNVOID_CACHE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/var/cache/synvoid"));

        let minified_dir = global_cache_dir.join("minified").join(site_id);

        Self {
            enabled,
            enable_html: config.enable_html_minification.unwrap_or(true),
            enable_css: config.enable_css_minification.unwrap_or(true),
            enable_js: config.enable_js_minification.unwrap_or(true),
            enable_svg: config.enable_svg_compression.unwrap_or(true),
            enable_gzip: config.enable_compression.unwrap_or(true),
            enable_brotli: config.enable_brotli.unwrap_or(true),
            gzip_level: config.gzip_level.unwrap_or(9),
            brotli_level: config.brotli_level.unwrap_or(11),
            minified_dir,
            enable_cache: config.enable_file_cache.unwrap_or(true),
            cache_max_entries: config.cache_max_entries.unwrap_or(10000),
            cache_ttl_secs: config.cache_ttl_seconds.unwrap_or(3600),
        }
    }
}

pub struct MinifierCache {
    entries: RwLock<HashMap<CacheKey, CacheEntry>>,
    config: MinifierConfig,
    generator: MinifierGenerator,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
}

impl MinifierCache {
    pub fn new(config: MinifierConfig) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            config,
            generator: MinifierGenerator::new(),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
        }
    }

    pub fn config_from_site(site_id: &str, site_config: &SiteStaticConfig) -> MinifierConfig {
        MinifierConfig::from_site_config(site_id, site_config)
    }

    pub fn config(&self) -> &MinifierConfig {
        &self.config
    }

    pub fn get(&self, key: &CacheKey) -> Option<CacheEntry> {
        if !self.config.enabled || !self.config.enable_cache {
            self.cache_misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let entries = self.entries.read();
        let entry = entries.get(key)?;

        let age = entry.generated_at.elapsed().as_secs();
        if age > self.config.cache_ttl_secs {
            self.cache_misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        self.cache_hits.fetch_add(1, Ordering::Relaxed);
        Some(entry.clone())
    }

    pub fn insert(&self, key: CacheKey, entry: CacheEntry) {
        if !self.config.enabled || !self.config.enable_cache {
            return;
        }

        let mut entries = self.entries.write();

        if entries.len() >= self.config.cache_max_entries {
            self.evict_lru(&mut entries);
        }

        entries.insert(key, entry);
    }

    pub fn invalidate(&self, site_id: &str, path: &str) {
        let mut entries = self.entries.write();
        let site_id_arc: Arc<str> = site_id.into();
        let path_arc: Arc<str> = path.into();
        let keys: Vec<_> = entries
            .keys()
            .filter(|k| k.site_id == site_id_arc && k.path == path_arc)
            .cloned()
            .collect();

        for key in keys {
            entries.remove(&key);
        }
    }

    pub fn clear_site(&self, site_id: &str) {
        let mut entries = self.entries.write();
        let site_id_arc: Arc<str> = site_id.into();
        let keys: Vec<_> = entries
            .keys()
            .filter(|k| k.site_id == site_id_arc)
            .cloned()
            .collect();

        for key in keys {
            entries.remove(&key);
        }
    }

    fn evict_lru(&self, entries: &mut HashMap<CacheKey, CacheEntry>) {
        if entries.is_empty() {
            return;
        }

        let oldest_key = entries
            .iter()
            .min_by_key(|(_, v)| v.generated_at)
            .map(|(k, _)| k.clone());

        if let Some(key) = oldest_key {
            entries.remove(&key);
        }
    }

    pub fn cache_hits(&self) -> u64 {
        self.cache_hits.load(Ordering::Relaxed)
    }

    pub fn cache_misses(&self) -> u64 {
        self.cache_misses.load(Ordering::Relaxed)
    }

    pub fn cache_hit_rate(&self) -> f64 {
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total > 0 {
            (hits as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    }

    pub fn minify_and_cache(
        &self,
        site_id: &str,
        path: &str,
        original_content: &[u8],
        mtime: SystemTime,
    ) -> Result<CacheEntry, MinifierError> {
        if !self.config.enabled {
            return Err(MinifierError::Cache("Minification disabled".to_string()));
        }

        let extension = Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        let content_type = ContentType::from_extension(extension);

        let should_minify = match content_type {
            ContentType::Html => self.config.enable_html,
            ContentType::Css => self.config.enable_css,
            ContentType::Js => self.config.enable_js,
            ContentType::Svg => self.config.enable_svg,
            ContentType::Other => false,
        };

        let minified = if should_minify {
            match content_type {
                ContentType::Html => {
                    let input = String::from_utf8_lossy(original_content);
                    match self.generator.minify_html(&input) {
                        Ok(m) => m.into_bytes(),
                        Err(e) => {
                            tracing::warn!("HTML minification failed for {}: {}", path, e);
                            original_content.to_vec()
                        }
                    }
                }
                ContentType::Css => {
                    let input = String::from_utf8_lossy(original_content);
                    match self.generator.minify_css(&input) {
                        Ok(m) => m.into_bytes(),
                        Err(e) => {
                            tracing::warn!("CSS minification failed for {}: {}", path, e);
                            original_content.to_vec()
                        }
                    }
                }
                ContentType::Js => {
                    let input = String::from_utf8_lossy(original_content);
                    match self.generator.minify_js(&input) {
                        Ok(m) => m.into_bytes(),
                        Err(e) => {
                            tracing::warn!("JS minification failed for {}: {}", path, e);
                            original_content.to_vec()
                        }
                    }
                }
                ContentType::Svg => original_content.to_vec(),
                ContentType::Other => original_content.to_vec(),
            }
        } else {
            original_content.to_vec()
        };

        let entry = CacheEntry {
            content: Bytes::from(minified),
            mtime,
            generated_at: Instant::now(),
            content_type,
        };

        let key = CacheKey {
            site_id: Arc::from(site_id),
            path: Arc::from(path),
            encoding: Encoding::None,
        };
        self.insert(key, entry.clone());

        Ok(entry)
    }

    pub fn generate_compressed(
        &self,
        site_id: &str,
        path: &str,
        content: &[u8],
        encoding: &Encoding,
    ) -> Result<Bytes, MinifierError> {
        if !self.config.enabled {
            return Err(MinifierError::Cache("Minification disabled".to_string()));
        }

        let compressed = match encoding {
            Encoding::Gzip if self.config.enable_gzip => self
                .generator
                .compress_gzip(content, self.config.gzip_level)?,
            Encoding::Br if self.config.enable_brotli => self
                .generator
                .compress_brotli(content, self.config.brotli_level)?,
            _ => {
                return Err(MinifierError::Compression(
                    "Encoding not enabled".to_string(),
                ))
            }
        };

        let key = CacheKey {
            site_id: Arc::from(site_id),
            path: Arc::from(path),
            encoding: encoding.clone(),
        };

        let entry = CacheEntry {
            content: Bytes::from(compressed),
            mtime: SystemTime::now(),
            generated_at: Instant::now(),
            content_type: ContentType::Other,
        };
        self.insert(key, entry.clone());

        Ok(entry.content)
    }

    pub fn get_or_create_compressed(
        &self,
        site_id: &str,
        path: &str,
        minified_content: &[u8],
        encoding: &str,
    ) -> Result<Bytes, String> {
        let enc = match encoding {
            "gzip" => Encoding::Gzip,
            "br" => Encoding::Br,
            _ => return Ok(Bytes::from(minified_content.to_vec())),
        };

        let key = CacheKey {
            site_id: Arc::from(site_id),
            path: Arc::from(path),
            encoding: enc.clone(),
        };

        if let Some(entry) = self.get(&key) {
            return Ok(entry.content.clone());
        }

        let content = self
            .generate_compressed(site_id, path, minified_content, &enc)
            .map_err(|e| format!("{} compression failed: {}", encoding, e))?;

        Ok(content)
    }

    pub fn write_to_disk(
        &self,
        site_id: &str,
        path: &str,
        content: &[u8],
        _mtime: SystemTime,
    ) -> Result<PathBuf, MinifierError> {
        let _key = CacheKey {
            site_id: Arc::from(site_id),
            path: Arc::from(path),
            encoding: Encoding::None,
        };

        let site_dir = self.config.minified_dir.join(site_id);
        std::fs::create_dir_all(&site_dir)?;

        let relative_path = path.trim_start_matches('/');
        let minified_path = site_dir.join(relative_path);

        if let Some(parent) = minified_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(&minified_path, content)?;

        tracing::debug!("Wrote minified file: {}", minified_path.display());

        Ok(minified_path)
    }

    pub fn write_compressed_to_disk(
        &self,
        site_id: &str,
        path: &str,
        content: &[u8],
        encoding: &Encoding,
    ) -> Result<PathBuf, MinifierError> {
        let site_dir = self.config.minified_dir.join(site_id);
        std::fs::create_dir_all(&site_dir)?;

        let relative_path = path.trim_start_matches('/');
        let extension = Path::new(relative_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        let new_extension = if encoding.extension().is_empty() {
            extension.to_string()
        } else if extension.is_empty() {
            encoding.extension().to_string()
        } else {
            format!("{}.{}", extension, encoding.extension())
        };

        let compressed_path = site_dir.join(Path::new(relative_path).with_extension(new_extension));

        if let Some(parent) = compressed_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(&compressed_path, content)?;

        tracing::debug!("Wrote compressed file: {}", compressed_path.display());

        Ok(compressed_path)
    }

    pub async fn write_to_disk_async(
        &self,
        site_id: &str,
        path: &str,
        content: &[u8],
        _mtime: SystemTime,
    ) -> Result<PathBuf, MinifierError> {
        let site_dir = self.config.minified_dir.join(site_id);
        async_fs::create_dir_all(&site_dir).await?;

        let relative_path = path.trim_start_matches('/');
        let minified_path = site_dir.join(relative_path);

        if let Some(parent) = minified_path.parent() {
            async_fs::create_dir_all(parent).await?;
        }

        async_fs::write(&minified_path, content).await?;

        tracing::debug!("Wrote minified file: {}", minified_path.display());

        Ok(minified_path)
    }

    pub async fn write_compressed_to_disk_async(
        &self,
        site_id: &str,
        path: &str,
        content: &[u8],
        encoding: &Encoding,
    ) -> Result<PathBuf, MinifierError> {
        let site_dir = self.config.minified_dir.join(site_id);
        async_fs::create_dir_all(&site_dir).await?;

        let relative_path = path.trim_start_matches('/');
        let extension = Path::new(relative_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        let new_extension = if encoding.extension().is_empty() {
            extension.to_string()
        } else if extension.is_empty() {
            encoding.extension().to_string()
        } else {
            format!("{}.{}", extension, encoding.extension())
        };

        let compressed_path = site_dir.join(Path::new(relative_path).with_extension(new_extension));

        if let Some(parent) = compressed_path.parent() {
            async_fs::create_dir_all(parent).await?;
        }

        async_fs::write(&compressed_path, content).await?;

        tracing::debug!("Wrote compressed file: {}", compressed_path.display());

        Ok(compressed_path)
    }

    pub fn get_minified_path(&self, site_id: &str, path: &str) -> PathBuf {
        let relative_path = path.trim_start_matches('/');
        self.config.minified_dir.join(site_id).join(relative_path)
    }

    pub fn get_compressed_path(&self, site_id: &str, path: &str, encoding: &Encoding) -> PathBuf {
        let relative_path = path.trim_start_matches('/');
        let extension = Path::new(relative_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        let new_extension = if encoding.extension().is_empty() {
            extension.to_string()
        } else if extension.is_empty() {
            encoding.extension().to_string()
        } else {
            format!("{}.{}", extension, encoding.extension())
        };

        self.config
            .minified_dir
            .join(site_id)
            .join(Path::new(relative_path).with_extension(new_extension))
    }

    pub fn check_and_invalidate(&self, site_id: &str, path: &str) -> bool {
        let minified_path = self.get_minified_path(site_id, path);

        if !minified_path.exists() {
            let original_path = PathBuf::from(path);
            if !original_path.exists() {
                tracing::warn!("Original file not found for {}: {}", site_id, path);
                self.invalidate(site_id, path);
                self.delete_minified_files(site_id, path);
                return true;
            }
        }

        false
    }

    pub fn delete_minified_files(&self, site_id: &str, path: &str) {
        let base_path = self.get_minified_path(site_id, path);

        let paths_to_delete = vec![
            base_path.clone(),
            base_path.with_extension("css.gz"),
            base_path.with_extension("css.br"),
            base_path.with_extension("js.gz"),
            base_path.with_extension("js.br"),
            base_path.with_extension("html.gz"),
            base_path.with_extension("html.br"),
            base_path.with_extension("svg.gz"),
            base_path.with_extension("svg.br"),
        ];

        for path in paths_to_delete {
            if path.exists() {
                if let Err(e) = std::fs::remove_file(&path) {
                    tracing::warn!("Failed to delete minified file {}: {}", path.display(), e);
                } else {
                    tracing::debug!("Deleted minified file: {}", path.display());
                }
            }
        }
    }

    pub fn scan_existing(
        &self,
        site_id: &str,
        _source_root: &Path,
    ) -> Result<usize, MinifierError> {
        if !self.config.minified_dir.exists() {
            return Ok(0);
        }

        let site_dir = self.config.minified_dir.join(site_id);
        if !site_dir.exists() {
            return Ok(0);
        }

        let mut count = 0;
        for entry in walkdir::WalkDir::new(&site_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            if let Ok(metadata) = entry.metadata() {
                let path = entry.path();
                let relative = path
                    .strip_prefix(&site_dir)
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                if !relative.is_empty() {
                    let key = CacheKey {
                        site_id: Arc::from(site_id),
                        path: Arc::from(format!("/{}", relative)),
                        encoding: Encoding::None,
                    };

                    let entry = CacheEntry {
                        content: Bytes::from(std::fs::read(path)?),
                        mtime: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                        generated_at: Instant::now(),
                        content_type: ContentType::from_extension(
                            path.extension().and_then(|e| e.to_str()).unwrap_or(""),
                        ),
                    };

                    self.insert(key, entry);
                    count += 1;
                }
            }
        }

        tracing::info!(
            "Scanned {} existing minified files for site {}",
            count,
            site_id
        );
        Ok(count)
    }
}

pub struct MinifierGenerator;

impl MinifierGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn minify_css(&self, input: &str) -> Result<String, MinifierError> {
        use lightningcss::stylesheet::{MinifyOptions, ParserOptions, PrinterOptions};

        let mut stylesheet =
            lightningcss::stylesheet::StyleSheet::parse(input, ParserOptions::default())
                .map_err(|e| MinifierError::CssMinify(e.to_string()))?;

        stylesheet
            .minify(MinifyOptions::default())
            .map_err(|e| MinifierError::CssMinify(e.to_string()))?;

        let output = stylesheet
            .to_css(PrinterOptions {
                minify: true,
                ..Default::default()
            })
            .map_err(|e| MinifierError::CssMinify(e.to_string()))?;

        Ok(output.code)
    }

    pub fn minify_js(&self, input: &str) -> Result<String, MinifierError> {
        use minify_js::{minify, Session, TopLevelMode};

        let code = input.as_bytes();
        let session = Session::new();
        let mut out = Vec::new();

        minify(&session, TopLevelMode::Global, code, &mut out)
            .map_err(|e| MinifierError::JsMinify(e.to_string()))?;

        String::from_utf8(out).map_err(|e| MinifierError::JsMinify(e.to_string()))
    }

    pub fn minify_html(&self, input: &str) -> Result<String, MinifierError> {
        use minify_html::{minify, Cfg};

        let mut cfg = Cfg::new();
        cfg.minify_js = true;
        cfg.minify_css = true;

        let output = minify(input.as_bytes(), &cfg);

        String::from_utf8(output).map_err(|e| MinifierError::HtmlMinify(e.to_string()))
    }

    pub fn compress_gzip(&self, input: &[u8], level: u32) -> Result<Vec<u8>, MinifierError> {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let level = level.min(9);
        let compression = Compression::new(level);
        let mut encoder = GzEncoder::new(Vec::new(), compression);

        use std::io::Write;
        encoder
            .write_all(input)
            .map_err(|e| MinifierError::Compression(e.to_string()))?;

        encoder
            .finish()
            .map_err(|e| MinifierError::Compression(e.to_string()))
    }

    pub fn compress_brotli(&self, input: &[u8], level: u32) -> Result<Vec<u8>, MinifierError> {
        use brotli::CompressorWriter;

        let level = level.min(11);
        let mut output = Vec::new();
        {
            let mut encoder = CompressorWriter::new(&mut output, 4096, level, 22);

            use std::io::Write;
            encoder
                .write_all(input)
                .map_err(|e| MinifierError::Compression(e.to_string()))?;
            encoder
                .flush()
                .map_err(|e| MinifierError::Compression(e.to_string()))?;
        }

        Ok(output)
    }
}

impl Default for MinifierGenerator {
    fn default() -> Self {
        Self::new()
    }
}
