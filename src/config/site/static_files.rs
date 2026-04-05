use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::error_pages::SiteThemeConfig;

fn default_block_hidden_files() -> Option<bool> {
    Some(true)
}

fn default_gzip_on_the_fly() -> Option<bool> {
    Some(true)
}

fn default_gzip_level() -> Option<u32> {
    Some(5)
}

fn default_gzip_min_size() -> Option<usize> {
    Some(256)
}

fn default_gzip_types() -> Option<Vec<String>> {
    Some(vec![
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
    ])
}

fn default_enable_minification() -> Option<bool> {
    Some(true)
}

fn default_enable_html_minification() -> Option<bool> {
    Some(true)
}

fn default_enable_css_minification() -> Option<bool> {
    Some(true)
}

fn default_enable_js_minification() -> Option<bool> {
    Some(true)
}

fn default_enable_svg_compression() -> Option<bool> {
    Some(true)
}

fn default_enable_brotli() -> Option<bool> {
    Some(true)
}

fn default_brotli_level() -> Option<u32> {
    Some(11)
}

fn default_enable_file_cache() -> Option<bool> {
    Some(true)
}

fn default_cache_max_entries() -> Option<usize> {
    Some(10000)
}

fn default_cache_ttl_seconds() -> Option<u64> {
    Some(3600)
}

fn default_enable_file_watching() -> Option<bool> {
    Some(true)
}

fn default_watch_interval_ms() -> Option<u64> {
    Some(5000)
}

fn default_preload_on_startup() -> Option<bool> {
    Some(true)
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteStaticConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub default_root: Option<String>,
    #[serde(default)]
    pub default_cache_ttl: Option<u64>,
    #[serde(default)]
    pub max_file_size: Option<String>,
    #[serde(default)]
    pub allow_symlinks: Option<bool>,
    #[serde(default = "default_block_hidden_files")]
    pub block_hidden_files: Option<bool>,
    #[serde(default)]
    pub enable_compression: Option<bool>,
    #[serde(default)]
    pub compression_min_size: Option<usize>,
    #[serde(default = "default_gzip_on_the_fly")]
    pub gzip_on_the_fly: Option<bool>,
    #[serde(default = "default_gzip_level")]
    pub gzip_level: Option<u32>,
    #[serde(default = "default_gzip_min_size")]
    pub gzip_min_size: Option<usize>,
    #[serde(default = "default_gzip_types")]
    pub gzip_types: Option<Vec<String>>,
    #[serde(default)]
    pub directory_listing: Option<bool>,
    #[serde(default)]
    pub directory_listing_format: Option<String>,
    #[serde(default)]
    pub theme: Option<SiteThemeConfig>,
    #[serde(default)]
    pub locations: Vec<StaticLocation>,
    #[serde(default)]
    pub minified_dir: Option<String>,
    #[serde(default = "default_enable_minification")]
    pub enable_minification: Option<bool>,
    #[serde(default = "default_enable_html_minification")]
    pub enable_html_minification: Option<bool>,
    #[serde(default = "default_enable_css_minification")]
    pub enable_css_minification: Option<bool>,
    #[serde(default = "default_enable_js_minification")]
    pub enable_js_minification: Option<bool>,
    #[serde(default = "default_enable_svg_compression")]
    pub enable_svg_compression: Option<bool>,
    #[serde(default = "default_enable_brotli")]
    pub enable_brotli: Option<bool>,
    #[serde(default = "default_brotli_level")]
    pub brotli_level: Option<u32>,
    #[serde(default = "default_enable_file_cache")]
    pub enable_file_cache: Option<bool>,
    #[serde(default = "default_cache_max_entries")]
    pub cache_max_entries: Option<usize>,
    #[serde(default = "default_cache_ttl_seconds")]
    pub cache_ttl_seconds: Option<u64>,
    #[serde(default = "default_enable_file_watching")]
    pub enable_file_watching: Option<bool>,
    #[serde(default = "default_watch_interval_ms")]
    pub watch_interval_ms: Option<u64>,
    #[serde(default = "default_preload_on_startup")]
    pub preload_on_startup: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct StaticLocation {
    pub path: String,
    pub root: String,
    #[serde(default)]
    pub index: Option<String>,
    #[serde(default)]
    pub try_files: Option<Vec<String>>,
    #[serde(default)]
    pub cache_ttl: Option<u64>,
}
