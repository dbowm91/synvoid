//! Inline response-transform helpers for already-buffered bodies.
//!
//! These helpers are intentionally bounded and are used only when the response
//! body is already resident in memory. Static-file minify/compress work stays
//! on the CPU offload plane; these helpers cover the small inline cases that
//! remain on the unified worker.

use bytes::Bytes;
use dashmap::DashMap;
use std::sync::LazyLock;

use crate::config::site::{SiteImagePoisonConfig, SiteStaticConfig};
#[cfg(feature = "mesh")]
use crate::mesh::config::{
    MeshCompressionConfig, MeshImageProtectionConfig, MeshMinificationConfig,
};

pub struct ResponseTransformConfig<'a> {
    pub minification: Option<MinificationSettings<'a>>,
    pub image_poisoning: Option<ImagePoisonSettings<'a>>,
    pub compression: Option<CompressionSettings<'a>>,
}

pub struct MinificationSettings<'a> {
    pub enabled: bool,
    pub html: bool,
    pub css: bool,
    pub js: bool,
    pub _marker: std::marker::PhantomData<&'a ()>,
}

pub struct ImagePoisonSettings<'a> {
    pub enabled: bool,
    pub min_size: u64,
    pub whitelist_patterns: Option<&'a Vec<String>>,
    pub _marker: std::marker::PhantomData<&'a ()>,
}

pub struct CompressionSettings<'a> {
    pub enabled: bool,
    pub brotli_level: u32,
    pub gzip_level: u32,
    pub _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a> ResponseTransformConfig<'a> {
    #[cfg(feature = "mesh")]
    pub fn from_mesh_config(
        minification: Option<&'a MeshMinificationConfig>,
        image_protection: Option<&'a MeshImageProtectionConfig>,
        compression: Option<&'a MeshCompressionConfig>,
    ) -> Self {
        let minification = minification.and_then(|m| {
            if m.enabled.unwrap_or(false) {
                Some(MinificationSettings {
                    enabled: true,
                    html: m.enable_html.unwrap_or(true),
                    css: m.enable_css.unwrap_or(true),
                    js: m.enable_js.unwrap_or(true),
                    _marker: std::marker::PhantomData,
                })
            } else {
                None
            }
        });

        let image_poisoning = image_protection.and_then(|i| {
            if i.enabled.unwrap_or(false) {
                Some(ImagePoisonSettings {
                    enabled: true,
                    min_size: i.min_size_bytes.unwrap_or(100 * 1024) as u64,
                    whitelist_patterns: i.whitelist_patterns.as_ref(),
                    _marker: std::marker::PhantomData,
                })
            } else {
                None
            }
        });

        let compression = compression.and_then(|c| {
            if c.enabled.unwrap_or(false) {
                Some(CompressionSettings {
                    enabled: true,
                    brotli_level: c.brotli_level.unwrap_or(6),
                    gzip_level: c.gzip_level.unwrap_or(6),
                    _marker: std::marker::PhantomData,
                })
            } else {
                None
            }
        });

        Self {
            minification,
            image_poisoning,
            compression,
        }
    }

    #[allow(clippy::borrowed_box)]
    pub fn from_static_config(
        static_config: &'a SiteStaticConfig,
        image_poison_config: &'a SiteImagePoisonConfig,
    ) -> Self {
        let minification = if static_config.enable_minification.unwrap_or(false) {
            Some(MinificationSettings {
                enabled: true,
                html: static_config.enable_html_minification.unwrap_or(true),
                css: static_config.enable_css_minification.unwrap_or(true),
                js: static_config.enable_js_minification.unwrap_or(true),
                _marker: std::marker::PhantomData,
            })
        } else {
            None
        };

        let image_poisoning = if image_poison_config.enabled.unwrap_or(false) {
            Some(ImagePoisonSettings {
                enabled: true,
                min_size: image_poison_config.max_dimension.unwrap_or(4096) as u64,
                whitelist_patterns: image_poison_config.whitelist_patterns.as_ref(),
                _marker: std::marker::PhantomData,
            })
        } else {
            None
        };

        let compression = if static_config.enable_compression.unwrap_or(false) {
            Some(CompressionSettings {
                enabled: true,
                brotli_level: static_config.brotli_level.unwrap_or(6),
                gzip_level: static_config.gzip_level.unwrap_or(6),
                _marker: std::marker::PhantomData,
            })
        } else {
            None
        };

        Self {
            minification,
            image_poisoning,
            compression,
        }
    }
}

pub struct ResponseTransformResult {
    pub body: Bytes,
    pub body_len: u64,
    pub additional_headers: Vec<(String, String)>,
}

static WHITELIST_REGEX_CACHE: LazyLock<DashMap<String, Option<regex::Regex>>> =
    LazyLock::new(DashMap::new);

static IMAGE_PROTECTION_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\.(?:jpe?g|png|gif|webp|bmp|svg|ico)(?:\?|$)").unwrap());

pub fn path_looks_like_image(path: &str) -> bool {
    IMAGE_PROTECTION_REGEX.is_match(path)
}

pub fn is_whitelisted_path(whitelist_patterns: Option<&Vec<String>>, path: &str) -> bool {
    whitelist_patterns
        .map(|patterns| {
            patterns.iter().any(|pattern| {
                WHITELIST_REGEX_CACHE
                    .entry(pattern.clone())
                    .or_insert_with(|| regex::Regex::new(pattern).ok())
                    .value()
                    .as_ref()
                    .map(|regex| regex.is_match(path))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

pub fn apply_minification(
    body: Bytes,
    content_type: Option<&str>,
    settings: &MinificationSettings,
) -> Bytes {
    let ct = content_type.unwrap_or("");

    if !ct.contains("text/html") && !ct.contains("text/css") && !ct.contains("javascript") {
        return body;
    }

    let generator = crate::static_files::minifier::MinifierGenerator::new();

    if ct.contains("text/html") && settings.html {
        if let Ok(text) = String::from_utf8(body.to_vec()) {
            if let Ok(minified) = generator.minify_html(&text) {
                return Bytes::from(minified);
            }
        }
    } else if ct.contains("text/css") && settings.css {
        if let Ok(text) = String::from_utf8(body.to_vec()) {
            if let Ok(minified) = generator.minify_css(&text) {
                return Bytes::from(minified);
            }
        }
    } else if ct.contains("javascript") && settings.js {
        if let Ok(text) = String::from_utf8(body.to_vec()) {
            if let Ok(minified) = generator.minify_js(&text) {
                return Bytes::from(minified);
            }
        }
    }

    body
}

pub fn apply_compression(
    body: Bytes,
    accept_encoding: Option<&str>,
    settings: &CompressionSettings,
) -> (Bytes, Option<String>) {
    let accept_encoding = accept_encoding.unwrap_or("");
    let generator = crate::static_files::minifier::MinifierGenerator::new();

    if accept_encoding.contains("br") {
        if let Ok(compressed) = generator.compress_brotli(&body, settings.brotli_level) {
            return (Bytes::from(compressed), Some("br".to_string()));
        }
    }

    if accept_encoding.contains("gzip") {
        if let Ok(compressed) = generator.compress_gzip(&body, settings.gzip_level) {
            return (Bytes::from(compressed), Some("gzip".to_string()));
        }
    }

    (body, None)
}
