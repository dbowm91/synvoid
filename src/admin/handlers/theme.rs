use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

use super::super::state::AdminState;
use super::common::OptionalAuth;
use crate::theme::{
    halloy::{
        halloy_bytes, halloy_lightness, halloy_pill_color, halloy_value, opaque_hex,
        selected_halloy_theme, HALLOY_NAMES,
    },
    ThemeColors, ThemeConfig, ThemeDefaults, ThemeRenderer, ThemeScheme,
};
use synvoid_core::admin_mutation::{
    AdminActor, AdminAuditEvent, AdminMutationAuthority, AdminMutationResult, AdminMutationStatus,
    PropagationStatus,
};

#[derive(Debug, Serialize, ToSchema)]
pub struct ThemeResponse {
    pub preset: String,
    pub mode: String,
    pub dark_theme: String,
    pub light_theme: String,
    pub scheme: String,
    pub allow_only: String,
    pub colors: ThemeColorsResponse,
    pub presets_available: Vec<ThemePresetInfo>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ThemeColorsResponse {
    pub dark: DarkColors,
    pub light: LightColors,
}

#[derive(Debug, Serialize, ToSchema)]
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

#[derive(Debug, Serialize, ToSchema)]
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

#[derive(Debug, Serialize, ToSchema)]
pub struct ThemePresetInfo {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateThemeRequest {
    #[serde(default)]
    pub preset: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub dark_theme: Option<String>,
    #[serde(default)]
    pub light_theme: Option<String>,
    #[serde(default)]
    pub scheme: Option<String>,
    #[serde(default)]
    pub allow_only: Option<String>,
}

fn theme_catalog() -> Vec<ThemePresetInfo> {
    let mut catalog = Vec::with_capacity(HALLOY_NAMES.len() + 1);
    catalog.push(ThemePresetInfo {
        id: "default".to_string(),
        name: "Default".to_string(),
    });
    catalog.extend(HALLOY_NAMES.iter().map(|name| ThemePresetInfo {
        id: (*name).to_string(),
        name: (*name).to_string(),
    }));
    catalog
}

struct TranslatedSide {
    background: String,
    surface: String,
    primary: String,
    text: String,
    border: String,
    accent: String,
    accent_primary: String,
    accent_secondary: String,
}

fn halloy_document(name: &str) -> Option<toml::Value> {
    let bytes = halloy_bytes(selected_halloy_theme(name))?;
    std::str::from_utf8(bytes).ok()?.parse::<toml::Value>().ok()
}

fn translate_side(document: &toml::Value) -> TranslatedSide {
    let general_background = halloy_value(document, &["general", "background"], "#1e1e2e");
    let page_background = opaque_hex(
        if halloy_lightness(general_background).unwrap_or(0.0) < 0.5 {
            halloy_value(document, &["buffer", "background"], general_background)
        } else {
            general_background
        },
    );
    let card_background = opaque_hex(halloy_value(document, &["buffer", "background"], "#1e1e2e"));
    let text_primary = halloy_value(document, &["text", "primary"], "#cdd6f4");
    TranslatedSide {
        background: page_background.clone(),
        surface: card_background.clone(),
        primary: opaque_hex(text_primary),
        text: opaque_hex(
            &halloy_pill_color(text_primary, &page_background, 0.36)
                .unwrap_or_else(|| text_primary.to_owned()),
        ),
        border: opaque_hex(halloy_value(document, &["general", "border"], "#2a2a3a")),
        accent: opaque_hex(halloy_value(
            document,
            &["buffer", "background_title_bar"],
            card_background.as_str(),
        )),
        accent_primary: opaque_hex(halloy_value(document, &["buffer", "action"], "#00d4aa")),
        accent_secondary: opaque_hex(halloy_value(document, &["buffer", "url"], "#00b894")),
    }
}

fn translated_theme_colors(dark_name: &str, light_name: &str) -> Option<ThemeColors> {
    let dark = translate_side(&halloy_document(dark_name)?);
    let light = translate_side(&halloy_document(light_name)?);
    Some(ThemeColors {
        dark_background: dark.background,
        dark_surface: dark.surface,
        dark_primary: dark.primary,
        dark_text: dark.text,
        dark_border: dark.border,
        dark_accent: dark.accent,
        dark_accent_primary: dark.accent_primary,
        dark_accent_secondary: dark.accent_secondary,
        light_background: light.background,
        light_surface: light.surface,
        light_primary: light.primary,
        light_text: light.text,
        light_border: light.border,
        light_accent: light.accent,
        light_accent_primary: light.accent_primary,
        light_accent_secondary: light.accent_secondary,
    })
}

fn build_theme_response(theme: &ThemeDefaults) -> ThemeResponse {
    let (dark_theme, light_theme, scheme) = theme.resolve_halloy_themes();
    let colors =
        translated_theme_colors(&dark_theme, &light_theme).unwrap_or_else(|| theme.colors.clone());
    ThemeResponse {
        preset: theme.preset.clone(),
        mode: theme.mode.clone(),
        dark_theme,
        light_theme,
        scheme: scheme.as_str().to_string(),
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
        presets_available: theme_catalog(),
    }
}

#[utoipa::path(
    get,
    path = "/theme",
    responses(
        (status = 200, description = "Theme configuration", body = ThemeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "theme"
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
    request_body = UpdateThemeRequest,
    responses(
        (status = 200, description = "Theme updated"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "theme"
)]
pub async fn update_theme(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateThemeRequest>,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let mut config = state.process.config.write().await;

    if let Some(preset) = req.preset {
        config
            .main
            .defaults
            .theme
            .apply_legacy_preset_selection(&preset);
    }
    if let Some(mode) = req.mode {
        let scheme = ThemeScheme::from(mode.as_str());
        config.main.defaults.theme.mode = mode;
        config.main.defaults.theme.scheme = scheme.as_str().to_string();
    }
    if let Some(scheme) = req.scheme {
        config.main.defaults.theme.scheme = ThemeScheme::from(scheme.as_str()).as_str().to_string();
    }
    if let Some(dark_theme) = req.dark_theme {
        config.main.defaults.theme.dark_theme = dark_theme;
    }
    if let Some(light_theme) = req.light_theme {
        config.main.defaults.theme.light_theme = light_theme;
    }
    if let Some(allow_only) = req.allow_only {
        config.main.defaults.theme.allow_only = allow_only;
    }

    let theme = config.main.defaults.theme.clone();
    let response = build_theme_response(&theme);

    let main_config = config.main.clone();
    let config_dir = config.config_dir.clone();
    drop(config);

    let toml_content = toml::to_string_pretty(&main_config).map_err(|e| {
        tracing::error!("Failed to serialize config: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let main_config_path = config_dir.join("main.toml");

    {
        let _guard = state.metrics.config_write_lock.write().await;
        super::common::write_config_file_secure(&main_config_path, toml_content)
            .await
            .map_err(|e| {
                tracing::error!("Failed to write main config: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    }

    let audit_id = uuid::Uuid::new_v4().to_string();

    let audit_event = AdminAuditEvent {
        audit_id: audit_id.clone(),
        timestamp: synvoid_utils::safe_unix_timestamp(),
        actor: AdminActor::new(AdminMutationAuthority::AdminManual),
        action: "update_theme".to_string(),
        target_kind: "theme".to_string(),
        target_id: "default".to_string(),
        prior_state: None,
        requested_state: Some(serde_json::json!({
            "preset": response.preset,
            "mode": response.mode,
            "dark_theme": response.dark_theme,
            "light_theme": response.light_theme,
            "scheme": response.scheme,
            "allow_only": response.allow_only,
        })),
        resulting_state: Some(serde_json::json!({
            "preset": response.preset,
            "mode": response.mode,
            "dark_theme": response.dark_theme,
            "light_theme": response.light_theme,
            "scheme": response.scheme,
            "allow_only": response.allow_only,
        })),
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::AppliedLocalOnly,
        event_id: None,
    };
    state.audit.log_audit_event(&audit_event);

    Ok(Json(AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: "theme".to_string(),
        local_store_mutated: true,
        propagation: PropagationStatus::AppliedLocalOnly,
        event_id: None,
        audit_id: Some(audit_id),
        message: format!(
            "Theme updated: dark={}, light={}, scheme={}",
            response.dark_theme, response.light_theme, response.scheme
        ),
    }))
}

#[utoipa::path(
    get,
    path = "/theme/css",
    responses(
        (status = 200, description = "Theme CSS", body = String),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "theme"
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
    responses(
        (status = 200, description = "Available theme presets", body = Vec<ThemePresetInfo>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "theme"
)]
pub async fn get_theme_presets(
    _auth: OptionalAuth,
) -> Result<Json<Vec<ThemePresetInfo>>, StatusCode> {
    Ok(Json(theme_catalog()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_lists_registry_plus_default_alias() {
        let catalog = theme_catalog();
        assert_eq!(catalog.len(), HALLOY_NAMES.len() + 1);
        assert_eq!(catalog[0].id, "default");
        assert!(
            catalog.iter().any(|entry| entry.id == "Nord"),
            "registry names must be listed"
        );
        let mut ids: Vec<&str> = catalog.iter().map(|entry| entry.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), catalog.len(), "catalog ids must be unique");
    }

    #[test]
    fn response_carries_dual_scheme_fields() {
        let response = build_theme_response(&ThemeDefaults::default());
        assert_eq!(response.dark_theme, "Catppuccin Mocha");
        assert_eq!(response.light_theme, "Catppuccin Latte");
        assert_eq!(response.scheme, "system");
        assert_eq!(response.preset, "default");
        assert_eq!(response.presets_available.len(), HALLOY_NAMES.len() + 1);
    }

    #[test]
    fn legacy_preset_resolves_through_response() {
        let mut theme = ThemeDefaults::default();
        theme.apply_legacy_preset_selection("dark");
        let response = build_theme_response(&theme);
        assert_eq!(response.dark_theme, "Catppuccin Mocha");
        assert_eq!(response.light_theme, "Catppuccin Mocha");
    }

    #[test]
    fn colors_derive_from_resolved_dark_theme() {
        let colors = translated_theme_colors("Cyber Red", "Catppuccin Latte")
            .expect("bundled themes translate");
        assert_eq!(colors.dark_background, "#090808");
        assert_eq!(colors.dark_primary, "#E41951");
        assert!(colors.light_background.starts_with('#'));
    }

    #[test]
    fn unknown_names_fall_back_without_error() {
        let fallback =
            translated_theme_colors("Cyber Red", "Cyber Red").expect("bundled themes translate");
        assert_eq!(
            translated_theme_colors("missing-nope", "missing-nope"),
            Some(fallback)
        );
    }
}
