pub mod client;
pub mod directory;
pub mod minifier;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use http::{Method, Response, StatusCode};
use http_body_util::Full;
use metrics::{counter, histogram};
use tokio::io::AsyncReadExt;

use synvoid_config::site::{SiteStaticConfig, SiteStaticThemeConfig};
#[cfg(feature = "mesh")]
use synvoid_config::{
    MeshCompressionConfig, MeshImageProtectionConfig, MeshMinificationConfig,
};
#[cfg(not(feature = "mesh"))]
pub type MeshCompressionConfig = ();
#[cfg(not(feature = "mesh"))]
pub type MeshImageProtectionConfig = ();
#[cfg(not(feature = "mesh"))]
pub type MeshMinificationConfig = ();
use synvoid_app_handlers::mime::MIME_REGISTRY;
use synvoid_theme::ThemeConfig;
use minifier::MinifierCache;

#[derive(Clone)]
pub struct NormalizedLocation {
    pub url_prefix: String,
    pub fs_root: PathBuf,
    pub index: Option<String>,
    pub try_files: Vec<String>,
    pub cache_ttl: Option<u64>,
    pub theme: Option<SiteStaticThemeConfig>,
}

#[derive(Clone)]
pub struct StaticFileHandler {
    config: Arc<SiteStaticConfig>,
    locations: Vec<NormalizedLocation>,
    gzip_types: Vec<String>,
    max_file_size: u64,
    gzip_level: u32,
    gzip_min_size: usize,
    allow_symlinks: bool,
    block_hidden_files: bool,
    enable_compression: bool,
    gzip_on_the_fly: bool,
    directory_listing: bool,
    default_cache_ttl: Option<u64>,
    site_id: String,
    minified_cache_dir: Option<PathBuf>,
    enable_zero_copy: bool,
    mesh_image_protection: Option<MeshImageProtectionConfig>,
    mesh_compression: Option<MeshCompressionConfig>,
    mesh_minification: Option<MeshMinificationConfig>,
    theme_config: ThemeConfig,
    directory_template_path: Option<String>,
    minifier_client: Option<client::MinifierClient>,
    #[allow(dead_code)]
    image_poison_config: Option<MeshImageProtectionConfig>,
}

#[derive(Debug, thiserror::Error)]
pub enum StaticError {
    #[error("File not found: {0}")]
    NotFound(String),
    #[error("Forbidden: {0}")]
    Forbidden(String),
    #[error("Directory listing disabled")]
    DirectoryListingDisabled,
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("File too large: {0}")]
    FileTooLarge(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

impl StaticError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            StaticError::NotFound(_) => StatusCode::NOT_FOUND,
            StaticError::Forbidden(_) => StatusCode::FORBIDDEN,
            StaticError::DirectoryListingDisabled => StatusCode::FORBIDDEN,
            StaticError::BadRequest(_) => StatusCode::BAD_REQUEST,
            StaticError::FileTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            StaticError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

pub enum StaticResponseBody {
    InMemory(Bytes),
    Buffered(Bytes),
}

pub struct StaticResponse {
    pub status: StatusCode,
    pub headers: Vec<(String, String)>,
    pub body: StaticResponseBody,
}

impl StaticResponse {
    pub fn into_bytes(self) -> Bytes {
        match self.body {
            StaticResponseBody::InMemory(b) => b,
            StaticResponseBody::Buffered(b) => b,
        }
    }
}

impl StaticFileHandler {
    pub fn new(config: SiteStaticConfig, theme_config: ThemeConfig) -> Result<Self, String> {
        Self::new_with_minifier(
            config,
            String::new(),
            None,
            None,
            None,
            None,
            None,
            None,
            theme_config,
        )
    }

    pub fn new_with_minifier(
        config: SiteStaticConfig,
        site_id: String,
        _minifier_cache: Option<Arc<MinifierCache>>,
        minifier_client: Option<client::MinifierClient>,
        _async_minifier_client: Option<client::AsyncMinifierClient>,
        mesh_image_protection: Option<MeshImageProtectionConfig>,
        mesh_compression: Option<MeshCompressionConfig>,
        mesh_minification: Option<MeshMinificationConfig>,
        theme_config: ThemeConfig,
    ) -> Result<Self, String> {
        let enabled = config.enabled.unwrap_or(false);
        let gzip_level = config.gzip_level.unwrap_or(5);
        let gzip_min_size = config.gzip_min_size.unwrap_or(256);
        let default_cache_ttl = config.default_cache_ttl;
        let allow_symlinks = config.allow_symlinks.unwrap_or(false);
        let block_hidden_files = config.block_hidden_files.unwrap_or(true);
        let enable_compression = config.enable_compression.unwrap_or(true);
        let gzip_on_the_fly = config.gzip_on_the_fly.unwrap_or(true);
        let directory_listing = config.directory_listing.unwrap_or(false);
        let directory_template_path = config
            .theme
            .as_ref()
            .and_then(|t| t.directory_template_path.clone());

        let config_clone = config.clone();

        if !enabled {
            let minified_cache_dir = config.minified_dir.as_ref().map(|_d| {
                let global_cache_dir = std::env::var("SYNVOID_CACHE_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from("/var/cache/synvoid"));
                global_cache_dir.join("minified").join(&site_id)
            });

            return Ok(Self {
                config: Arc::new(config),
                locations: vec![],
                gzip_types: vec![],
                max_file_size: 100 * 1024 * 1024,
                gzip_level: 5,
                gzip_min_size: 256,
                allow_symlinks: false,
                block_hidden_files: true,
                enable_compression: true,
                gzip_on_the_fly: true,
                directory_listing: false,
                default_cache_ttl: None,
                site_id,
                minified_cache_dir,
                enable_zero_copy: false,
                mesh_image_protection: mesh_image_protection.clone(),
                mesh_compression,
                mesh_minification,
                theme_config,
                directory_template_path: None,
                minifier_client,
                image_poison_config: mesh_image_protection.clone(),
            });
        }

        let default_root = config.default_root.as_ref().map(PathBuf::from);
        let mut locations = Vec::new();

        for loc in &config.locations {
            let root = if loc.root.is_empty() {
                if let Some(ref default) = default_root {
                    let suffix = loc.path.trim_start_matches('/');
                    default.join(suffix)
                } else {
                    return Err(format!("No root specified for location {}", loc.path));
                }
            } else {
                PathBuf::from(&loc.root)
            };

            if !root.exists() {
                tracing::warn!("Static root does not exist: {:?}", root);
                continue;
            }

            locations.push(NormalizedLocation {
                url_prefix: loc.path.clone(),
                fs_root: root,
                index: loc.index.clone(),
                try_files: loc
                    .try_files
                    .clone()
                    .unwrap_or_else(|| vec!["$uri".to_string()]),
                cache_ttl: loc.cache_ttl,
                theme: loc.theme.clone(),
            });
        }

        let max_file_size = config
            .max_file_size
            .as_ref()
            .and_then(|s| parse_size(s))
            .unwrap_or(100 * 1024 * 1024);

        let gzip_types = config.gzip_types.clone().unwrap_or_else(default_gzip_types);

        let minified_cache_dir = config.minified_dir.as_ref().map(|_d| {
            let global_cache_dir = std::env::var("SYNVOID_CACHE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/var/cache/synvoid"));
            global_cache_dir.join("minified").join(&site_id)
        });

        Ok(Self {
            config: Arc::new(config_clone),
            locations,
            gzip_types,
            max_file_size,
            gzip_level,
            gzip_min_size,
            allow_symlinks,
            block_hidden_files,
            enable_compression,
            gzip_on_the_fly,
            directory_listing,
            default_cache_ttl,
            site_id,
            minified_cache_dir,
            enable_zero_copy: cfg!(unix),
            mesh_image_protection: mesh_image_protection.clone(),
            mesh_compression,
            mesh_minification,
            theme_config,
            directory_template_path,
            minifier_client,
            image_poison_config: mesh_image_protection.clone(),
        })
    }

    pub fn is_enabled(&self) -> bool {
        !self.locations.is_empty()
    }

    pub fn with_mesh_config(
        mut self,
        image_protection: Option<MeshImageProtectionConfig>,
        compression: Option<MeshCompressionConfig>,
        minification: Option<MeshMinificationConfig>,
    ) -> Self {
        self.mesh_image_protection = image_protection;
        self.mesh_compression = compression;
        self.mesh_minification = minification;
        self
    }

    pub fn get_matching_location(&self, path: &str) -> Option<&NormalizedLocation> {
        self.locations
            .iter()
            .filter(|loc| path.starts_with(&loc.url_prefix))
            .max_by_key(|loc| loc.url_prefix.len())
    }

    pub async fn serve(
        &self,
        path: &str,
        _method: &Method,
        accept_encoding: Option<&str>,
        if_none_match: Option<&str>,
        if_modified_since: Option<&str>,
        range_header: Option<&str>,
    ) -> Result<StaticResponse, StaticError> {
        counter!("synvoid.static.requests").increment(1);

        let location = self
            .get_matching_location(path)
            .ok_or_else(|| StaticError::NotFound(path.to_string()))?;

        let relative_path = path
            .strip_prefix(&location.url_prefix)
            .unwrap_or(path)
            .trim_start_matches('/');

        let resolved = self.resolve_path(location, relative_path).await?;
        let metadata = tokio::fs::metadata(&resolved).await.map_err(|e| {
            tracing::debug!("Failed to get metadata for {}: {}", resolved.display(), e);
            StaticError::NotFound(path.to_string())
        })?;

        if metadata.is_dir() {
            return self
                .serve_directory(path, location, &resolved, accept_encoding)
                .await;
        }

        if metadata.len() > self.max_file_size {
            histogram!("synvoid.static.file_too_large").record(metadata.len() as f64);
            return Err(StaticError::FileTooLarge(format!(
                "File exceeds max size of {} bytes",
                self.max_file_size
            )));
        }

        self.serve_file(
            &resolved,
            metadata,
            path,
            location,
            accept_encoding,
            if_none_match,
            if_modified_since,
            range_header,
        )
        .await
    }

    async fn resolve_path(
        &self,
        location: &NormalizedLocation,
        relative_path: &str,
    ) -> Result<PathBuf, StaticError> {
        if relative_path.is_empty() || relative_path == "/" {
            return Err(StaticError::NotFound("empty path".to_string()));
        }

        let mut full_path = location.fs_root.join(relative_path);

        let canonical = match tokio::fs::canonicalize(&full_path).await {
            Ok(c) => c,
            Err(_) => {
                if self.allow_symlinks {
                    let fp = full_path.clone();
                    match tokio::task::spawn_blocking(move || std::fs::metadata(&fp)).await {
                        Ok(Ok(m)) if m.is_symlink() => {
                            let fp = full_path.clone();
                            std::fs::read_link(&fp).unwrap_or_else(|_| fp.clone())
                        }
                        _ => full_path.clone(),
                    }
                } else {
                    full_path.clone()
                }
            }
        };

        let canonical_root = tokio::fs::canonicalize(&location.fs_root)
            .await
            .unwrap_or_else(|_| location.fs_root.clone());

        if !canonical.starts_with(&canonical_root) {
            tracing::warn!(
                "Path traversal attempt: {} -> {} (root: {})",
                relative_path,
                canonical.display(),
                canonical_root.display()
            );
            return Err(StaticError::Forbidden(
                "path traversal not allowed".to_string(),
            ));
        }
        full_path = canonical;

        if self.block_hidden_files {
            for component in full_path.components() {
                let name = component.as_os_str().to_string_lossy();
                if name.starts_with('.') && name != ".htaccess" {
                    return Err(StaticError::Forbidden(format!(
                        "hidden file not allowed: {}",
                        name
                    )));
                }
            }
        }

        Ok(full_path)
    }

    async fn serve_file(
        &self,
        path: &Path,
        metadata: std::fs::Metadata,
        _url_path: &str,
        location: &NormalizedLocation,
        accept_encoding: Option<&str>,
        if_none_match: Option<&str>,
        if_modified_since: Option<&str>,
        range_header: Option<&str>,
    ) -> Result<StaticResponse, StaticError> {
        let mtime = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let etag = format!(
            "\"{:x}-{:x}\"",
            metadata.len(),
            mtime
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        );
        let file_size = metadata.len();

        if let Some(etag_header) = if_none_match {
            if etag_header.contains(&etag) || etag_header == "*" {
                return Ok(StaticResponse {
                    status: StatusCode::NOT_MODIFIED,
                    headers: vec![
                        ("ETag".to_string(), etag.clone()),
                        (
                            "Cache-Control".to_string(),
                            "public, max-age=31536000, immutable".to_string(),
                        ),
                    ],
                    body: StaticResponseBody::InMemory(Bytes::from_static(&[])),
                });
            }
        }

        if let Some(modified_since) = if_modified_since {
            if let Ok(since) = httpdate_parse_http_date(modified_since) {
                if mtime <= since {
                    return Ok(StaticResponse {
                        status: StatusCode::NOT_MODIFIED,
                        headers: vec![
                            ("ETag".to_string(), etag),
                            (
                                "Cache-Control".to_string(),
                                format!(
                                    "max-age={}",
                                    location
                                        .cache_ttl
                                        .or(self.default_cache_ttl)
                                        .unwrap_or(3600)
                                ),
                            ),
                        ],
                        body: StaticResponseBody::InMemory(Bytes::from_static(&[])),
                    });
                }
            }
        }

        if let Some(range_spec) = range_header {
            if let Some((start, end)) = Self::parse_range(range_spec, file_size) {
                let file = tokio::fs::File::open(path)
                    .await
                    .map_err(|e| StaticError::Internal(e.to_string()))?;

                let mut file = tokio::io::BufReader::new(file);
                let mut buffer = Vec::new();
                let mut remaining = end - start + 1;
                let mut to_skip = start;

                while remaining > 0 {
                    let buf_size = std::cmp::min(8192, remaining as usize);
                    let mut buf = vec![0u8; buf_size];
                    let n = file
                        .read(&mut buf)
                        .await
                        .map_err(|e| StaticError::Internal(e.to_string()))?;
                    if n == 0 {
                        break;
                    }
                    if to_skip > 0 {
                        let skip = std::cmp::min(to_skip as usize, n);
                        buf = buf[skip..].to_vec();
                        to_skip -= skip as u64;
                        if buf.is_empty() {
                            continue;
                        }
                    }
                    let take = std::cmp::min(buf.len(), remaining as usize);
                    buffer.extend_from_slice(&buf[..take]);
                    remaining -= take as u64;
                }

                let body_len = buffer.len() as u64;
                let mut headers = Vec::new();
                headers.push((
                    "Content-Type".to_string(),
                    MIME_REGISTRY
                        .read()
                        .get_mime_for_extension(
                            path.extension().and_then(|e| e.to_str()).unwrap_or(""),
                        )
                        .unwrap_or_else(|| "application/octet-stream".to_string()),
                ));
                headers.push(("Content-Length".to_string(), body_len.to_string()));
                headers.push((
                    "Content-Range".to_string(),
                    format!("bytes {}-{}/{}", start, end, file_size),
                ));
                headers.push(("Accept-Ranges".to_string(), "bytes".to_string()));

                return Ok(StaticResponse {
                    status: StatusCode::PARTIAL_CONTENT,
                    headers,
                    body: StaticResponseBody::InMemory(Bytes::from(buffer)),
                });
            }
        }

        let body = tokio::fs::read(path).await.map_err(|e| {
            tracing::error!("Failed to read file {}: {}", path.display(), e);
            StaticError::Internal(e.to_string())
        })?;

        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let mime_type = MIME_REGISTRY
            .read()
            .get_mime_for_extension(extension)
            .unwrap_or_else(|| "application/octet-stream".to_string());

        let mut headers = Vec::new();
        headers.push(("Content-Type".to_string(), mime_type.clone()));
        headers.push(("Content-Length".to_string(), body.len().to_string()));
        headers.push(("ETag".to_string(), etag));

        if let Ok(mtime_str) = httpdate_fmt_http_date(mtime) {
            headers.push(("Last-Modified".to_string(), mtime_str));
        }

        let cache_ttl = location
            .cache_ttl
            .or(self.default_cache_ttl)
            .unwrap_or(3600);
        headers.push((
            "Cache-Control".to_string(),
            format!("public, max-age={}", cache_ttl),
        ));

        let use_precompressed = self.enable_compression;
        let use_gzip_otf = self.gzip_on_the_fly;

        if let Some(encoding) = accept_encoding {
            if use_precompressed {
                let br_path = path.with_extension(format!("{}.br", extension));
                let gz_path = path.with_extension(format!("{}.gz", extension));

                if encoding.contains("br") && br_path.exists() {
                    let compressed = tokio::fs::read(&br_path)
                        .await
                        .map_err(|e| StaticError::Internal(e.to_string()))?;
                    headers.push(("Content-Encoding".to_string(), "br".to_string()));
                    headers.push(("Vary".to_string(), "Accept-Encoding".to_string()));
                    histogram!("synvoid.static.served_compressed").record(1.0);
                    return Ok(StaticResponse {
                        status: StatusCode::OK,
                        headers,
                        body: StaticResponseBody::InMemory(Bytes::from(compressed)),
                    });
                }

                if encoding.contains("gzip") && gz_path.exists() {
                    let compressed = tokio::fs::read(&gz_path)
                        .await
                        .map_err(|e| StaticError::Internal(e.to_string()))?;
                    headers.push(("Content-Encoding".to_string(), "gzip".to_string()));
                    headers.push(("Vary".to_string(), "Accept-Encoding".to_string()));
                    histogram!("synvoid.static.served_compressed").record(1.0);
                    return Ok(StaticResponse {
                        status: StatusCode::OK,
                        headers,
                        body: StaticResponseBody::InMemory(Bytes::from(compressed)),
                    });
                }

                if let Some(ref cache_dir) = self.minified_cache_dir {
                    let relative_path = path.strip_prefix(&location.fs_root).unwrap_or(path);
                    let minified_br =
                        cache_dir.join(relative_path.with_extension(format!("{}.br", extension)));
                    let minified_gz =
                        cache_dir.join(relative_path.with_extension(format!("{}.gz", extension)));

                    if encoding.contains("br") && minified_br.exists() {
                        let compressed = tokio::fs::read(&minified_br)
                            .await
                            .map_err(|e| StaticError::Internal(e.to_string()))?;
                        headers.push(("Content-Encoding".to_string(), "br".to_string()));
                        headers.push(("Vary".to_string(), "Accept-Encoding".to_string()));
                        histogram!("synvoid.static.served_compressed").record(1.0);
                        counter!("synvoid.static.compression_served", "encoding" => "brotli_precompressed", "site" => self.site_id.clone()).increment(1);
                        return Ok(StaticResponse {
                            status: StatusCode::OK,
                            headers,
                            body: StaticResponseBody::InMemory(Bytes::from(compressed)),
                        });
                    }

                    if encoding.contains("gzip") && minified_gz.exists() {
                        let compressed = tokio::fs::read(&minified_gz)
                            .await
                            .map_err(|e| StaticError::Internal(e.to_string()))?;
                        headers.push(("Content-Encoding".to_string(), "gzip".to_string()));
                        headers.push(("Vary".to_string(), "Accept-Encoding".to_string()));
                        histogram!("synvoid.static.served_compressed").record(1.0);
                        counter!("synvoid.static.compression_served", "encoding" => "gzip_precompressed", "site" => self.site_id.clone()).increment(1);
                        return Ok(StaticResponse {
                            status: StatusCode::OK,
                            headers,
                            body: StaticResponseBody::InMemory(Bytes::from(compressed)),
                        });
                    }
                }
            }

            if self.minifier_client.is_some()
                && self.mesh_minification.is_some()
                && is_minifiable_content(&mime_type)
            {
                let relative_path = path.strip_prefix(&location.fs_root).unwrap_or(path);
                let encoding = accept_encoding.as_deref().unwrap_or("identity");

                if let Some(ref minifier_client) = self.minifier_client {
                    match minifier_client.request_minify(
                        &self.site_id,
                        relative_path.to_str().unwrap_or(""),
                        Some(encoding),
                    ) {
                        Ok(result) => {
                            if !result.content.is_empty() {
                                histogram!("synvoid.static.served_minified").record(1.0);
                                counter!("synvoid.static.minification_served", "site" => self.site_id.clone()).increment(1);

                                if encoding == "br" {
                                    headers
                                        .push(("Content-Encoding".to_string(), "br".to_string()));
                                } else if encoding == "gzip" {
                                    headers
                                        .push(("Content-Encoding".to_string(), "gzip".to_string()));
                                }
                                headers.push(("Vary".to_string(), "Accept-Encoding".to_string()));

                                return Ok(StaticResponse {
                                    status: StatusCode::OK,
                                    headers,
                                    body: StaticResponseBody::InMemory(Bytes::from(result.content)),
                                });
                            }
                        }
                        Err(e) => {
                            client::record_cpu_offload_fallback();
                            tracing::debug!(
                                "Minification failed for {}: {}",
                                relative_path.display(),
                                e
                            );
                        }
                    }
                }
            }

            if use_gzip_otf
                && encoding.contains("gzip")
                && body.len() >= self.gzip_min_size
                && self.gzip_types.contains(&mime_type)
            {
                use flate2::write::GzEncoder;
                use flate2::Compression;

                let mut encoder = GzEncoder::new(Vec::new(), Compression::new(self.gzip_level));
                use std::io::Write;
                encoder
                    .write_all(&body)
                    .map_err(|e| StaticError::Internal(e.to_string()))?;
                let compressed = encoder
                    .finish()
                    .map_err(|e| StaticError::Internal(e.to_string()))?;

                if compressed.len() < body.len() {
                    headers.push(("Content-Encoding".to_string(), "gzip".to_string()));
                    headers.push(("Vary".to_string(), "Accept-Encoding".to_string()));
                    histogram!("synvoid.static.served_gzip_otf").record(1.0);
                    counter!("synvoid.static.compression_served", "encoding" => "gzip_otf", "site" => self.site_id.clone()).increment(1);
                    histogram!("synvoid.static.compression_ratio", "encoding" => "gzip")
                        .record(body.len() as f64 / compressed.len() as f64);
                    return Ok(StaticResponse {
                        status: StatusCode::OK,
                        headers,
                        body: StaticResponseBody::InMemory(Bytes::from(compressed)),
                    });
                }
            }
        }

        counter!("synvoid.static.served").increment(1);

        let body = if self.enable_zero_copy && body.len() > 4096 {
            StaticResponseBody::Buffered(Bytes::from(body))
        } else {
            StaticResponseBody::InMemory(Bytes::from(body))
        };

        Ok(StaticResponse {
            status: StatusCode::OK,
            headers,
            body,
        })
    }

    fn parse_range(header: &str, file_size: u64) -> Option<(u64, u64)> {
        let prefix = "bytes=";
        if !header.starts_with(prefix) {
            return None;
        }
        let ranges = header[prefix.len()..].split(',').next()?;
        let range = ranges.trim();
        let parts: Vec<&str> = range.split('-').collect();
        if parts.len() != 2 {
            return None;
        }
        let start = if parts[0].is_empty() {
            if parts[1].is_empty() {
                return None;
            }
            file_size.saturating_sub(parts[1].parse().ok()?) - 1
        } else {
            parts[0].parse().ok()?
        };
        let end = if parts[1].is_empty() {
            file_size - 1
        } else {
            parts[1].parse().ok()?
        };
        if start > end || end >= file_size {
            return None;
        }
        Some((start, end))
    }

    async fn serve_directory(
        &self,
        url_path: &str,
        location: &NormalizedLocation,
        dir_path: &Path,
        accept_encoding: Option<&str>,
    ) -> Result<StaticResponse, StaticError> {
        if let Some(ref index) = location.index {
            let index_path = dir_path.join(index);
            if index_path.exists() {
                let index_metadata = tokio::fs::metadata(&index_path)
                    .await
                    .map_err(|_| StaticError::NotFound("index not found".to_string()))?;
                return self
                    .serve_file(
                        &index_path,
                        index_metadata,
                        url_path,
                        location,
                        accept_encoding,
                        None,
                        None,
                        None,
                    )
                    .await;
            }
        }

        for try_file in &location.try_files {
            if try_file == "$uri" {
                continue;
            }
            let tf = try_file
                .replace("$uri", url_path)
                .trim_start_matches('/')
                .to_string();
            let tf_path = dir_path.join(&tf);
            if tf_path.exists() {
                let tf_metadata = tokio::fs::metadata(&tf_path)
                    .await
                    .map_err(|_| StaticError::NotFound("try file not found".to_string()))?;
                if tf_metadata.is_file() {
                    return self
                        .serve_file(
                            &tf_path,
                            tf_metadata,
                            url_path,
                            location,
                            accept_encoding,
                            None,
                            None,
                            None,
                        )
                        .await;
                }
            }
        }

        if self.directory_listing {
            let format = self
                .config
                .directory_listing_format
                .as_deref()
                .unwrap_or("html");

            let effective_theme_config = location
                .theme
                .as_ref()
                .map(|t| t.to_theme_config(&self.theme_config))
                .unwrap_or_else(|| self.theme_config.clone());

            let effective_template_path: Option<String> = location
                .theme
                .as_ref()
                .and_then(|t| t.directory_template_path.clone())
                .or_else(|| self.directory_template_path.clone());

            let body = if let Some(template_path) = effective_template_path.as_deref() {
                if format == "html" {
                    let template = directory::load_directory_template(template_path)?;
                    let entries = directory::collect_directory_entries(dir_path)?;
                    directory::render_custom_template(&template, url_path, &entries)?
                } else {
                    directory::render_directory_listing(
                        dir_path,
                        url_path,
                        format,
                        &effective_theme_config,
                        &directory::DirectoryListingParams::default(),
                    )?
                }
            } else {
                directory::render_directory_listing(
                    dir_path,
                    url_path,
                    format,
                    &effective_theme_config,
                    &directory::DirectoryListingParams::default(),
                )?
            };
            return Ok(StaticResponse {
                status: StatusCode::OK,
                headers: vec![
                    ("Content-Type".to_string(), "text/html".to_string()),
                    ("Cache-Control".to_string(), "no-cache".to_string()),
                ],
                body: StaticResponseBody::InMemory(Bytes::from(body)),
            });
        }

        Err(StaticError::DirectoryListingDisabled)
    }

    pub fn into_response(
        self,
        result: Result<StaticResponse, StaticError>,
    ) -> Response<Full<Bytes>> {
        match result {
            Ok(resp) => {
                let status = resp.status;
                let headers: Vec<_> = resp.headers.into_iter().collect();
                let body_bytes = match resp.body {
                    StaticResponseBody::InMemory(b) => b,
                    StaticResponseBody::Buffered(b) => b,
                };
                let mut builder = Response::builder().status(status);
                for (key, value) in headers {
                    builder = builder.header(&key, &value);
                }
                builder.body(Full::new(body_bytes)).unwrap_or_else(|_| {
                    Response::builder()
                        .status(500)
                        .body(Full::new(Bytes::from("Internal Server Error")))
                        .unwrap()
                })
            }
            Err(e) => {
                counter!("synvoid.static.errors").increment(1);
                let status = e.status_code();
                let body = match &e {
                    StaticError::NotFound(path) => format!("404 Not Found: {}", path),
                    StaticError::Forbidden(reason) => format!("403 Forbidden: {}", reason),
                    StaticError::DirectoryListingDisabled => {
                        "403 Forbidden: Directory listing disabled".to_string()
                    }
                    StaticError::FileTooLarge(msg) => format!("413 Payload Too Large: {}", msg),
                    StaticError::BadRequest(msg) => format!("400 Bad Request: {}", msg),
                    StaticError::Internal(msg) => format!("500 Internal Error: {}", msg),
                };
                Response::builder()
                    .status(status)
                    .header("Content-Type", "text/plain")
                    .header("Content-Length", body.len())
                    .body(Full::new(Bytes::from(body)))
                    .unwrap()
            }
        }
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

fn default_gzip_types() -> Vec<String> {
    vec![
        "text/html".to_string(),
        "text/css".to_string(),
        "text/javascript".to_string(),
        "application/javascript".to_string(),
        "application/json".to_string(),
        "application/xml".to_string(),
        "text/xml".to_string(),
        "application/atom+xml".to_string(),
        "application/rss+xml".to_string(),
        "application/vnd.ms-fontobject".to_string(),
        "application/x-font-ttf".to_string(),
        "application/x-web-app-manifest+json".to_string(),
        "font/opentype".to_string(),
        "font/ttf".to_string(),
        "font/eot".to_string(),
        "font/otf".to_string(),
        "image/svg+xml".to_string(),
        "image/x-icon".to_string(),
        "text/x-component".to_string(),
        "text/x-cross-domain-policy".to_string(),
    ]
}

fn is_minifiable_content(mime_type: &str) -> bool {
    matches!(
        mime_type,
        "text/html"
            | "text/css"
            | "text/javascript"
            | "application/javascript"
            | "application/json"
            | "application/xml"
            | "text/xml"
            | "application/atom+xml"
            | "application/rss+xml"
            | "application/vnd.ms-fontobject"
            | "application/x-font-ttf"
            | "application/x-web-app-manifest+json"
            | "font/opentype"
            | "font/ttf"
            | "font/eot"
            | "font/otf"
            | "image/svg+xml"
            | "text/x-component"
            | "text/x-cross-domain-policy"
    )
}

fn httpdate_parse_http_date(s: &str) -> Result<SystemTime, std::io::Error> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 5 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid format",
        ));
    }

    let day: u64 = parts[1]
        .parse()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid day"))?;
    let month = MONTH_NAMES
        .iter()
        .position(|&m| m == parts[2])
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid month"))?;
    let year: u64 = parts[3]
        .parse()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid year"))?;
    let time_parts: Vec<u64> = parts[4].split(':').filter_map(|s| s.parse().ok()).collect();
    if time_parts.len() != 3 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid time",
        ));
    }

    let secs = ymdhms_to_unix(
        year,
        month as u64 + 1,
        day,
        time_parts[0],
        time_parts[1],
        time_parts[2],
    );
    SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(secs))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "time overflow"))
}

fn httpdate_fmt_http_date(time: SystemTime) -> std::io::Result<String> {
    let duration = time.duration_since(SystemTime::UNIX_EPOCH).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "time before epoch")
    })?;
    let secs = duration.as_secs();

    let (year, month, day, hour, min, sec, weekday) = unix_to_ymdhms(secs);

    Ok(format!(
        "{}, {} {} {} {:02}:{:02}:{:02} GMT",
        DAY_NAMES[weekday as usize],
        day,
        MONTH_NAMES[(month - 1) as usize],
        year,
        hour,
        min,
        sec
    ))
}

const DAY_NAMES: &[&str] = &["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTH_NAMES: &[&str] = &[
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn unix_to_ymdhms(secs: u64) -> (u64, u64, u64, u64, u64, u64, u64) {
    let mut remaining = secs;
    let mut year = 1970;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining < days_in_year * 86400 {
            break;
        }
        remaining -= days_in_year * 86400;
        year += 1;
    }

    let days = remaining / 86400;
    let weekday = (days + 4) % 7;
    remaining %= 86400;

    let hour = remaining / 3600;
    remaining %= 3600;

    let min = remaining / 60;
    let sec = remaining % 60;

    let mut month = 1;
    let mut day = days + 1;

    loop {
        let days_in_month = days_in_month_of(year, month);
        if day <= days_in_month {
            break;
        }
        day -= days_in_month;
        month += 1;
    }

    (year, month, day, hour, min, sec, weekday)
}

fn ymdhms_to_unix(year: u64, month: u64, day: u64, hour: u64, min: u64, sec: u64) -> u64 {
    let mut days = 0u64;

    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }

    for m in 1..month {
        days += days_in_month_of(year, m);
    }

    days += day - 1;

    days * 86400 + hour * 3600 + min * 60 + sec
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_in_month_of(year: u64, month: u64) -> u64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 30,
    }
}
