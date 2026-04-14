use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteErrorPagesConfig {
    #[serde(default)]
    pub inherit: Option<bool>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub custom_directory: Option<String>,
    #[serde(default)]
    pub theme: Option<SiteThemeConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteThemeConfig {
    #[serde(default)]
    pub preset: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub allow_only: Option<String>,
    #[serde(default)]
    pub colors: Option<crate::theme::ThemeColors>,
}

impl SiteThemeConfig {
    pub fn to_theme_config(
        &self,
        default_theme: &crate::theme::ThemeConfig,
    ) -> crate::theme::ThemeConfig {
        let preset = self.preset.as_deref().unwrap_or("default");
        let preset_enum = crate::theme::ThemePreset::from(preset);

        let colors = self.colors.clone().unwrap_or_else(|| preset_enum.colors());

        crate::theme::ThemeConfig {
            mode: self
                .mode
                .as_deref()
                .map(|m| crate::theme::ThemeMode::from(m))
                .unwrap_or(default_theme.mode),
            restriction: self
                .allow_only
                .as_deref()
                .map(|a| crate::theme::ThemeRestriction::from(a))
                .unwrap_or(default_theme.restriction),
            colors,
            spacing: default_theme.spacing.clone(),
            effects: default_theme.effects.clone(),
            branding: default_theme.branding.clone(),
        }
    }
}
