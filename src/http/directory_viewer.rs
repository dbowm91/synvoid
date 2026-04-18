use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc};
use tokio::sync::RwLock as TokioRwLock;

use crate::admin::verify_admin_token;
use crate::config::ConfigManager;
use crate::static_files::directory::{render_directory_listing, DirectoryListingParams};
use crate::theme::ThemeConfig;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DirectoryViewerConfig {
    pub enabled: bool,
    pub root_path: String,
    pub default_format: String,
    pub require_auth: bool,
    pub allow_symlinks: bool,
    pub block_hidden_files: bool,
    pub theme_mode: Option<String>,
}

impl Default for DirectoryViewerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            root_path: String::new(),
            default_format: "html".to_string(),
            require_auth: false,
            allow_symlinks: false,
            block_hidden_files: true,
            theme_mode: None,
        }
    }
}

#[derive(Clone)]
struct DirectoryViewerState {
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    config: Arc<TokioRwLock<ConfigManager>>,
    viewer_config: DirectoryViewerConfig,
    admin_token_hash: String,
}

unsafe impl Send for DirectoryViewerState {}
unsafe impl Sync for DirectoryViewerState {}

fn require_auth(state: &DirectoryViewerState, headers: &HeaderMap) -> Result<(), StatusCode> {
    if !state.viewer_config.require_auth {
        return Ok(());
    }

    let token = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !verify_admin_token(token, &state.admin_token_hash) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct DirectoryQuery {
    pub path: Option<String>,
    pub format: Option<String>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub page: Option<usize>,
    pub limit: Option<usize>,
    pub filter: Option<String>,
}

async fn list_handler(
    State(state): State<Arc<DirectoryViewerState>>,
    Query(params): Query<DirectoryQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &headers)?;

    let path = params.path.unwrap_or_else(|| "/".to_string());
    let format = params
        .format
        .as_deref()
        .unwrap_or(&state.viewer_config.default_format);

    let root = Path::new(&state.viewer_config.root_path);
    let dir_path = root.join(&path);

    if !dir_path.exists() {
        return Err(StatusCode::NOT_FOUND);
    }

    if !dir_path.is_dir() {
        return Err(StatusCode::BAD_REQUEST);
    }

    if state.viewer_config.block_hidden_files {
        for component in dir_path.components() {
            if let std::path::Component::Normal(name) = component {
                if let Some(s) = name.to_str() {
                    if s.starts_with('.') {
                        return Err(StatusCode::FORBIDDEN);
                    }
                }
            }
        }
    }

    let theme_config = build_theme_config(&state.viewer_config);

    let listing_params = DirectoryListingParams {
        sort_by: params.sort.unwrap_or_else(|| "name".to_string()),
        sort_order: params.order.unwrap_or_else(|| "asc".to_string()),
        page: params.page.unwrap_or(1).max(1),
        limit: params.limit.unwrap_or(100).clamp(10, 1000),
        filter: params.filter,
    };

    let body = render_directory_listing(&dir_path, &path, format, &theme_config, &listing_params)
        .map_err(|_e| StatusCode::INTERNAL_SERVER_ERROR)?;

    let content_type = match format {
        "json" => "application/json",
        _ => "text/html",
    };

    Ok((StatusCode::OK, [("Content-Type", content_type)], body))
}

fn build_theme_config(viewer_config: &DirectoryViewerConfig) -> ThemeConfig {
    let mut theme_config = ThemeConfig::default();

    if let Some(ref mode) = viewer_config.theme_mode {
        theme_config.mode = match mode.to_lowercase().as_str() {
            "dark" => crate::theme::ThemeMode::Dark,
            "light" => crate::theme::ThemeMode::Light,
            _ => crate::theme::ThemeMode::Auto,
        };
    }

    theme_config
}

pub fn create_directory_viewer_router(
    config: Arc<TokioRwLock<ConfigManager>>,
    viewer_config: DirectoryViewerConfig,
    admin_token_hash: String,
) -> Router {
    let state = DirectoryViewerState {
        config,
        viewer_config,
        admin_token_hash,
    };

    Router::new()
        .route("/", get(list_handler))
        .route("/*path", get(list_handler))
        .with_state(Arc::new(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_directory_viewer_disabled() {
        let config = DirectoryViewerConfig {
            enabled: false,
            root_path: String::new(),
            default_format: "html".to_string(),
            require_auth: false,
            allow_symlinks: false,
            block_hidden_files: true,
            theme_mode: None,
        };

        assert!(!config.enabled);
    }

    #[tokio::test]
    async fn test_directory_viewer_default_config() {
        let config = DirectoryViewerConfig::default();
        assert_eq!(config.default_format, "html");
        assert!(!config.require_auth);
        assert!(config.block_hidden_files);
    }

    #[tokio::test]
    async fn test_directory_listing_json_format() {
        let temp_dir = TempDir::new().unwrap();
        let root_path = temp_dir.path().to_str().unwrap().to_string();

        std::fs::create_dir_all(temp_dir.path().join("subdir")).unwrap();
        let mut file = std::fs::File::create(temp_dir.path().join("test.txt")).unwrap();
        file.write_all(b"test content").unwrap();

        let config = DirectoryViewerConfig {
            enabled: true,
            root_path,
            default_format: "json".to_string(),
            require_auth: false,
            allow_symlinks: false,
            block_hidden_files: true,
            theme_mode: None,
        };

        assert!(config.enabled);
        assert_eq!(config.default_format, "json");
    }
}
