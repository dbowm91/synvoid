use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::super::state::AdminState;
use super::common::{OptionalAuth};
use crate::theme::{ThemeDefaults, ThemePreset, ThemeRenderer, ThemeConfig};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ThemeResponse {
    pub preset: String,
    pub mode: String,
    pub allow_only: String,
    pub colors: ThemeColorsResponse,
    pub presets_available: Vec<ThemePresetInfo>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ThemeColorsResponse {
    pub dark: DarkColors,
    pub light: LightColors,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DarkColors {
    pub background: String,
    pub surface: String,
    pub primary: String,
    pub text: String,
    pub border: String,
    pub accent: String,
    pub accent_primary: String,
    pub accent_secondary: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LightColors {
    pub background: String,
    pub surface: String,
    pub primary: String,
    pub text: String,
    pub border: String,
    pub accent: String,
    pub accent_primary: String,
    pub accent_secondary: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ThemePresetInfo {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateThemeRequest {
    #[serde(default)]
    pub preset: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub allow_only: Option<String>,
}

fn build_theme_response(theme: &ThemeDefaults) -> ThemeResponse {
    let colors = &theme.colors;
    ThemeResponse {
        preset: theme.preset.clone(),
        mode: theme.mode.clone(),
        allow_only: theme.allow_only.clone(),
        colors: ThemeColorsResponse {
            dark: DarkColors {
                background: colors.dark_background.clone(),
                surface: colors.dark_surface.clone(),
                primary: colors.dark_primary.clone(),
                text: colors.dark_text.clone(),
                border: colors.dark_border.clone(),
                accent: colors.dark_accent.clone(),
                accent_primary: colors.dark_accent_primary.clone(),
                accent_secondary: colors.dark_accent_secondary.clone(),
            },
            light: LightColors {
                background: colors.light_background.clone(),
                surface: colors.light_surface.clone(),
                primary: colors.light_primary.clone(),
                text: colors.light_text.clone(),
                border: colors.light_border.clone(),
                accent: colors.light_accent.clone(),
                accent_primary: colors.light_accent_primary.clone(),
                accent_secondary: colors.light_accent_secondary.clone(),
            },
        },
        presets_available: vec![
            ThemePresetInfo {
                id: "default".to_string(),
                name: "Default".to_string(),
            },
            ThemePresetInfo {
                id: "dark".to_string(),
                name: "Dark".to_string(),
            },
            ThemePresetInfo {
                id: "light".to_string(),
                name: "Light".to_string(),
            },
            ThemePresetInfo {
                id: "ocean".to_string(),
                name: "Ocean".to_string(),
            },
            ThemePresetInfo {
                id: "forest".to_string(),
                name: "Forest".to_string(),
            },
            ThemePresetInfo {
                id: "sunset".to_string(),
                name: "Sunset".to_string(),
            },
        ],
    }
}

#[utoipa::path(
    get,
    path = "/theme",
    tag = "Theme",
    responses(
        (status = 200, description = "Current theme configuration"),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    )
)]
pub async fn get_theme(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<ThemeResponse>, StatusCode> {

    let config = state.process.config.read().await;
    let theme = &config.main.defaults.theme;
    Ok(Json(build_theme_response(theme)))
}

#[utoipa::path(
    put,
    path = "/theme",
    tag = "Theme",
    responses(
        (status = 200, description = "Theme updated"),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    )
)]
pub async fn update_theme(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateThemeRequest>,
) -> Result<Json<ThemeResponse>, StatusCode> {

    let mut config = state.process.config.write().await;
    
    if let Some(preset) = req.preset {
        config.main.defaults.theme.preset = preset;
        config.main.defaults.theme.colors = ThemePreset::from(config.main.defaults.theme.preset.as_str()).colors();
    }
    if let Some(mode) = req.mode {
        config.main.defaults.theme.mode = mode;
    }
    if let Some(allow_only) = req.allow_only {
        config.main.defaults.theme.allow_only = allow_only;
    }

    let theme = config.main.defaults.theme.clone();
    let response = build_theme_response(&theme);

    let main_config = config.main.clone();
    let config_dir = config.config_dir.clone();
    drop(config);

    let toml_content = toml::to_string_pretty(&main_config)
        .map_err(|e| {
            tracing::error!("Failed to serialize config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let main_config_path = config_dir.join("main.toml");

    {
        let _guard = state.metrics.config_write_lock.write().await;
        tokio::fs::write(&main_config_path, toml_content)
            .await
            .map_err(|e| {
                tracing::error!("Failed to write main config: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    }

    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/theme/css",
    tag = "Theme",
    responses(
        (status = 200, description = "Generated theme CSS"),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    )
)]
pub async fn get_theme_css(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<String, StatusCode> {

    let config = state.process.config.read().await;
    let theme_config: ThemeConfig = config.main.defaults.theme.clone().into();
    let renderer = ThemeRenderer::new(theme_config);
    Ok(renderer.generate_css())
}

#[utoipa::path(
    get,
    path = "/theme/presets",
    tag = "Theme",
    responses(
        (status = 200, description = "Available theme presets", body = [ThemePresetInfo]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    )
)]
pub async fn get_theme_presets(
    _auth: OptionalAuth,
) -> Result<Json<Vec<ThemePresetInfo>>, StatusCode> {
    Ok(Json(vec![
        ThemePresetInfo {
            id: "default".to_string(),
            name: "Default".to_string(),
        },
        ThemePresetInfo {
            id: "dark".to_string(),
            name: "Dark".to_string(),
        },
        ThemePresetInfo {
            id: "light".to_string(),
            name: "Light".to_string(),
        },
        ThemePresetInfo {
            id: "ocean".to_string(),
            name: "Ocean".to_string(),
        },
        ThemePresetInfo {
            id: "forest".to_string(),
            name: "Forest".to_string(),
        },
        ThemePresetInfo {
            id: "sunset".to_string(),
            name: "Sunset".to_string(),
        },
    ]))
}
