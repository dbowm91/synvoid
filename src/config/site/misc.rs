use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteLoggingConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub format: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteWorkerPoolConfig {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub workers: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteImagePoisonConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default = "default_poison_level")]
    pub level: Option<String>,
    #[serde(default = "default_poison_intensity")]
    pub intensity: Option<f32>,
    #[serde(default)]
    pub seed: Option<u64>,
    #[serde(default = "default_max_dimension")]
    pub max_dimension: Option<u32>,
    #[serde(default = "default_jpeg_quality")]
    pub jpeg_quality: Option<u8>,
    #[serde(default)]
    pub whitelist_patterns: Option<Vec<String>>,
}

fn default_poison_level() -> Option<String> {
    Some("standard".to_string())
}

fn default_poison_intensity() -> Option<f32> {
    Some(0.5)
}

fn default_max_dimension() -> Option<u32> {
    Some(4096)
}

fn default_jpeg_quality() -> Option<u8> {
    Some(85)
}
