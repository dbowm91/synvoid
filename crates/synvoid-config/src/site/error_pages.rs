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

        // An explicit legacy site preset resolves to its Halloy equivalent
        // names so the override actually takes effect; without one (or for
        // `"default"`/unknown names) the global pair is inherited, including
        // the unstyled `"default"` default.
        let (dark_theme, light_theme) = match crate::theme::legacy_halloy_equivalent(preset) {
            Some((dark, light)) => (dark, light),
            None => (
                default_theme.dark_theme.clone(),
                default_theme.light_theme.clone(),
            ),
        };

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
            dark_theme,
            light_theme,
            scheme: default_theme.scheme,
            colors,
            spacing: default_theme.spacing.clone(),
            effects: default_theme.effects.clone(),
            branding: default_theme.branding.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fallback() -> crate::theme::ThemeConfig {
        crate::theme::ThemeConfig::default()
    }

    #[test]
    fn site_preset_resolves_to_halloy_names() {
        let site = SiteThemeConfig {
            preset: Some("dark".to_string()),
            ..SiteThemeConfig::default()
        };
        let resolved = site.to_theme_config(&fallback());
        assert_eq!(resolved.dark_theme, "Catppuccin Mocha");
        assert_eq!(resolved.light_theme, "Catppuccin Mocha");
    }

    #[test]
    fn default_site_preset_inherits_global_pair() {
        let site = SiteThemeConfig {
            preset: None,
            mode: Some("dark".to_string()),
            ..SiteThemeConfig::default()
        };
        let mut global = fallback();
        global.dark_theme = "Nord".to_string();
        global.light_theme = "Dracula".to_string();
        let resolved = site.to_theme_config(&global);
        assert_eq!(resolved.dark_theme, "Nord");
        assert_eq!(resolved.light_theme, "Dracula");
        assert_eq!(resolved.mode, crate::theme::ThemeMode::Dark);
    }
}
