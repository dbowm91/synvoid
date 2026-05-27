use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpinManifest {
    pub spin_version: String,
    pub manifest_version: Option<String>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub authors: Option<Vec<String>>,
    #[serde(default)]
    pub triggers: HashMap<String, TriggerConfig>,
    #[serde(default)]
    pub components: Vec<ManifestComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerConfig {
    pub route: Option<String>,
    pub component: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WasiConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestComponent {
    pub id: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub files: Option<Vec<String>>,
    #[serde(default)]
    pub exclude_files: Vec<String>,
    #[serde(default)]
    pub build: Option<BuildConfig>,
    #[serde(default)]
    pub wasm: WasmConfig,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub wasi: Option<WasiConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildConfig {
    pub command: Option<String>,
    pub workdir: Option<String>,
    pub assets: Option<AssetsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetsConfig {
    pub watch: Option<Vec<String>>,
    pub config: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WasmConfig {
    pub module: Option<String>,
    pub adapter: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub trigger_type: String,
    #[serde(default)]
    pub components: Vec<ManifestComponent>,
}

impl Manifest {
    pub fn load(path: &Path) -> Result<Self, SpinManifestError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| SpinManifestError::IoError(format!("failed to read manifest: {}", e)))?;
        Self::parse(&content)
    }

    pub fn parse(content: &str) -> Result<Self, SpinManifestError> {
        let spin_manifest: SpinManifest =
            toml::from_str(content).map_err(|e| SpinManifestError::ParseError(e.to_string()))?;

        let trigger_type = spin_manifest
            .triggers
            .keys()
            .next()
            .cloned()
            .unwrap_or_else(|| "http".to_string());

        let components: Vec<ManifestComponent> = spin_manifest
            .components
            .into_iter()
            .map(|c| ManifestComponent {
                id: c.id,
                source: c.source,
                url: c.url,
                files: c.files,
                exclude_files: c.exclude_files,
                build: c.build,
                wasm: c.wasm,
                env: c.env,
                wasi: c.wasi,
            })
            .collect();

        if trigger_type == "http" && !components.iter().any(|c| c.url.is_some()) {
            return Err(SpinManifestError::NoHttpRoutes);
        }

        Ok(Manifest {
            name: spin_manifest.name,
            version: spin_manifest.version,
            trigger_type,
            components,
        })
    }

    pub fn get_component(&self, id: &str) -> Option<&ManifestComponent> {
        self.components.iter().find(|c| c.id == id)
    }

    pub fn get_routes(&self) -> Vec<(String, String)> {
        self.components
            .iter()
            .filter_map(|c| c.url.as_ref().map(|route| (c.id.clone(), route.clone())))
            .collect()
    }
}

#[derive(Debug, Clone, Error)]
pub enum SpinManifestError {
    #[error("IO error: {0}")]
    IoError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Missing required field: {0}")]
    MissingField(String),
    #[error("HTTP trigger requires at least one component with a url route defined")]
    NoHttpRoutes,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_MANIFEST: &str = r#"
spin_version = "2"
name = "my-app"
version = "1.0.0"
description = "A test Spin application"
authors = ["test@example.com"]

[triggers.http]
route = "/"
component = "main"

[[components]]
id = "main"
source = "target/wasm32-wasi/release/my_app.wasm"
url = "/"
[components.wasm]
module = "target/wasm32-wasi/release/my_app.wasm"
[components.build]
command = "cargo build --release --target wasm32-wasi"
workdir = "."

[components.env]
FOO = "bar"
"#;

    #[test]
    fn test_parse_manifest() {
        let manifest = Manifest::parse(SAMPLE_MANIFEST).unwrap();
        assert_eq!(manifest.name, "my-app");
        assert_eq!(manifest.version, "1.0.0");
        assert_eq!(manifest.trigger_type, "http");
        assert_eq!(manifest.components.len(), 1);
        assert_eq!(manifest.components[0].id, "main");
    }

    #[test]
    fn test_get_component() {
        let manifest = Manifest::parse(SAMPLE_MANIFEST).unwrap();
        let component = manifest.get_component("main").unwrap();
        assert_eq!(component.id, "main");
    }

    #[test]
    fn test_get_routes() {
        let manifest = Manifest::parse(SAMPLE_MANIFEST).unwrap();
        let routes = manifest.get_routes();
        assert_eq!(routes, vec![("main".to_string(), "/".to_string())]);
    }

    const MANIFEST_NO_ROUTES: &str = r#"
spin_version = "2"
name = "my-app"
version = "1.0.0"

[triggers.http]
route = "/"
component = "main"

[[components]]
id = "main"
source = "target/wasm32-wasi/release/my_app.wasm"
[components.wasm]
"#;

    #[test]
    fn test_http_trigger_requires_url() {
        let result = Manifest::parse(MANIFEST_NO_ROUTES);
        assert!(matches!(result, Err(SpinManifestError::NoHttpRoutes)));
    }
}
