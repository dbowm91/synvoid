use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct ThemeDefaults {
    #[serde(default)]
    pub preset: String,
    #[serde(default = "default_theme_mode")]
    pub mode: String,
    #[serde(default = "default_allow_only")]
    pub allow_only: String,
    #[serde(default)]
    pub colors: ThemeColors,
    #[serde(default)]
    pub spacing: ThemeSpacing,
    #[serde(default)]
    pub effects: ThemeEffects,
    #[serde(default)]
    pub branding: ThemeBranding,
}

impl Default for ThemeDefaults {
    fn default() -> Self {
        let preset = ThemePreset::Default;
        Self {
            preset: "default".to_string(),
            mode: default_theme_mode(),
            allow_only: default_allow_only(),
            colors: preset.colors(),
            spacing: ThemeSpacing::default(),
            effects: ThemeEffects::default(),
            branding: ThemeBranding::default(),
        }
    }
}

impl ThemeDefaults {
    pub fn apply_preset(&mut self) {
        let preset = ThemePreset::from(self.preset.as_str());
        if preset != ThemePreset::Default || self.colors == ThemeColors::default() {
            self.colors = preset.colors();
        }
    }
}

fn default_theme_mode() -> String {
    "auto".to_string()
}

fn default_allow_only() -> String {
    "both".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, JsonSchema)]
pub struct ThemeColors {
    #[serde(default = "default_dark_background")]
    pub dark_background: String,
    #[serde(default = "default_dark_surface")]
    pub dark_surface: String,
    #[serde(default = "default_dark_primary")]
    pub dark_primary: String,
    #[serde(default = "default_dark_text")]
    pub dark_text: String,
    #[serde(default = "default_dark_border")]
    pub dark_border: String,
    #[serde(default = "default_dark_accent")]
    pub dark_accent: String,
    #[serde(default = "default_dark_accent_primary")]
    pub dark_accent_primary: String,
    #[serde(default = "default_dark_accent_secondary")]
    pub dark_accent_secondary: String,
    #[serde(default = "default_light_background")]
    pub light_background: String,
    #[serde(default = "default_light_surface")]
    pub light_surface: String,
    #[serde(default = "default_light_primary")]
    pub light_primary: String,
    #[serde(default = "default_light_text")]
    pub light_text: String,
    #[serde(default = "default_light_border")]
    pub light_border: String,
    #[serde(default = "default_light_accent")]
    pub light_accent: String,
    #[serde(default = "default_light_accent_primary")]
    pub light_accent_primary: String,
    #[serde(default = "default_light_accent_secondary")]
    pub light_accent_secondary: String,
}

impl Default for ThemeColors {
    fn default() -> Self {
        ThemePreset::Default.colors()
    }
}

fn default_dark_background() -> String {
    "#1a1a2e".to_string()
}
fn default_dark_surface() -> String {
    "#16213e".to_string()
}
fn default_dark_primary() -> String {
    "#e94560".to_string()
}
fn default_dark_text() -> String {
    "#f0f0f0".to_string()
}
fn default_dark_border() -> String {
    "rgba(233, 69, 96, 0.4)".to_string()
}
fn default_dark_accent() -> String {
    "#0f3460".to_string()
}
fn default_light_background() -> String {
    "#e8e8e8".to_string()
}
fn default_light_surface() -> String {
    "#ffffff".to_string()
}
fn default_light_primary() -> String {
    "#c41e3a".to_string()
}
fn default_light_text() -> String {
    "#1a1a2e".to_string()
}
fn default_light_border() -> String {
    "rgba(196, 30, 58, 0.3)".to_string()
}
fn default_light_accent() -> String {
    "#3a86ff".to_string()
}
fn default_dark_accent_primary() -> String {
    "#00d4aa".to_string()
}
fn default_dark_accent_secondary() -> String {
    "#00b894".to_string()
}
fn default_light_accent_primary() -> String {
    "#059669".to_string()
}
fn default_light_accent_secondary() -> String {
    "#10b981".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct ThemeSpacing {
    #[serde(default = "default_border_radius")]
    pub border_radius: String,
    #[serde(default = "default_padding")]
    pub padding: String,
    #[serde(default = "default_max_width")]
    pub max_width: String,
}

impl Default for ThemeSpacing {
    fn default() -> Self {
        Self {
            border_radius: default_border_radius(),
            padding: default_padding(),
            max_width: default_max_width(),
        }
    }
}

fn default_border_radius() -> String {
    "8px".to_string()
}
fn default_padding() -> String {
    "2rem".to_string()
}
fn default_max_width() -> String {
    "420px".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct ThemeEffects {
    #[serde(default = "default_glass_opacity")]
    pub glass_opacity: f32,
    #[serde(default = "default_blur")]
    pub blur: String,
    #[serde(default = "default_shadow")]
    pub shadow: String,
    #[serde(default = "default_neon_glow")]
    pub neon_glow: bool,
}

impl Default for ThemeEffects {
    fn default() -> Self {
        Self {
            glass_opacity: default_glass_opacity(),
            blur: default_blur(),
            shadow: default_shadow(),
            neon_glow: default_neon_glow(),
        }
    }
}

fn default_glass_opacity() -> f32 {
    0.9
}
fn default_blur() -> String {
    "12px".to_string()
}
fn default_shadow() -> String {
    "0 8px 32px rgba(0, 0, 0, 0.4)".to_string()
}
fn default_neon_glow() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct ThemeBranding {
    #[serde(default = "default_logo_url")]
    pub logo_url: Option<String>,
    #[serde(default = "default_title")]
    pub title: String,
    #[serde(default = "default_show_logo")]
    pub show_logo: bool,
}

impl Default for ThemeBranding {
    fn default() -> Self {
        Self {
            logo_url: default_logo_url(),
            title: default_title(),
            show_logo: default_show_logo(),
        }
    }
}

fn default_logo_url() -> Option<String> {
    None
}
fn default_title() -> String {
    "RustWAF".to_string()
}
fn default_show_logo() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThemePreset {
    Default,
    Dark,
    Light,
    Ocean,
    Forest,
    Sunset,
}

impl From<&str> for ThemePreset {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "dark" => ThemePreset::Dark,
            "light" => ThemePreset::Light,
            "ocean" => ThemePreset::Ocean,
            "forest" => ThemePreset::Forest,
            "sunset" => ThemePreset::Sunset,
            _ => ThemePreset::Default,
        }
    }
}

impl ThemePreset {
    pub fn colors(&self) -> ThemeColors {
        match self {
            ThemePreset::Default | ThemePreset::Dark => ThemeColors {
                dark_background: "#0a0a0f".to_string(),
                dark_surface: "#12121a".to_string(),
                dark_primary: "#e94560".to_string(),
                dark_text: "#f0f0f5".to_string(),
                dark_border: "#2a2a3a".to_string(),
                dark_accent: "#1a1a24".to_string(),
                dark_accent_primary: "#00d4aa".to_string(),
                dark_accent_secondary: "#00b894".to_string(),
                light_background: "#f8fafc".to_string(),
                light_surface: "#ffffff".to_string(),
                light_primary: "#c41e3a".to_string(),
                light_text: "#0f172a".to_string(),
                light_border: "#e2e8f0".to_string(),
                light_accent: "#f1f5f9".to_string(),
                light_accent_primary: "#059669".to_string(),
                light_accent_secondary: "#10b981".to_string(),
            },
            ThemePreset::Light => ThemeColors {
                dark_background: "#0a0a0f".to_string(),
                dark_surface: "#12121a".to_string(),
                dark_primary: "#e94560".to_string(),
                dark_text: "#f0f0f5".to_string(),
                dark_border: "#2a2a3a".to_string(),
                dark_accent: "#1a1a24".to_string(),
                dark_accent_primary: "#00d4aa".to_string(),
                dark_accent_secondary: "#00b894".to_string(),
                light_background: "#f8fafc".to_string(),
                light_surface: "#ffffff".to_string(),
                light_primary: "#c41e3a".to_string(),
                light_text: "#0f172a".to_string(),
                light_border: "#e2e8f0".to_string(),
                light_accent: "#f1f5f9".to_string(),
                light_accent_primary: "#059669".to_string(),
                light_accent_secondary: "#10b981".to_string(),
            },
            ThemePreset::Ocean => ThemeColors {
                dark_background: "#0c1929".to_string(),
                dark_surface: "#132f4c".to_string(),
                dark_primary: "#0ea5e9".to_string(),
                dark_text: "#e3f2fd".to_string(),
                dark_border: "#2d4a6f".to_string(),
                dark_accent: "#173a5e".to_string(),
                dark_accent_primary: "#0ea5e9".to_string(),
                dark_accent_secondary: "#38bdf8".to_string(),
                light_background: "#e3f2fd".to_string(),
                light_surface: "#ffffff".to_string(),
                light_primary: "#0284c7".to_string(),
                light_text: "#0c1929".to_string(),
                light_border: "#90caf9".to_string(),
                light_accent: "#f1f5f9".to_string(),
                light_accent_primary: "#0ea5e9".to_string(),
                light_accent_secondary: "#38bdf8".to_string(),
            },
            ThemePreset::Forest => ThemeColors {
                dark_background: "#0a1a0f".to_string(),
                dark_surface: "#132318".to_string(),
                dark_primary: "#22c55e".to_string(),
                dark_text: "#e8f5e9".to_string(),
                dark_border: "#2d4a3a".to_string(),
                dark_accent: "#1a2e21".to_string(),
                dark_accent_primary: "#22c55e".to_string(),
                dark_accent_secondary: "#4ade80".to_string(),
                light_background: "#e8f5e9".to_string(),
                light_surface: "#ffffff".to_string(),
                light_primary: "#16a34a".to_string(),
                light_text: "#0a1a0f".to_string(),
                light_border: "#a5d6a7".to_string(),
                light_accent: "#f1f5f9".to_string(),
                light_accent_primary: "#22c55e".to_string(),
                light_accent_secondary: "#4ade80".to_string(),
            },
            ThemePreset::Sunset => ThemeColors {
                dark_background: "#1a0f0a".to_string(),
                dark_surface: "#2a1a14".to_string(),
                dark_primary: "#f97316".to_string(),
                dark_text: "#fff1ec".to_string(),
                dark_border: "#4a3028".to_string(),
                dark_accent: "#3d261e".to_string(),
                dark_accent_primary: "#f97316".to_string(),
                dark_accent_secondary: "#fb923c".to_string(),
                light_background: "#fff1ec".to_string(),
                light_surface: "#ffffff".to_string(),
                light_primary: "#ea580c".to_string(),
                light_text: "#1a0f0a".to_string(),
                light_border: "#ffccbc".to_string(),
                light_accent: "#f1f5f9".to_string(),
                light_accent_primary: "#f97316".to_string(),
                light_accent_secondary: "#fb923c".to_string(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThemeMode {
    Dark,
    Light,
    Auto,
}

impl From<&str> for ThemeMode {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "dark" => ThemeMode::Dark,
            "light" => ThemeMode::Light,
            _ => ThemeMode::Auto,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThemeRestriction {
    Both,
    DarkOnly,
    LightOnly,
}

impl From<&str> for ThemeRestriction {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "dark" => ThemeRestriction::DarkOnly,
            "light" => ThemeRestriction::LightOnly,
            _ => ThemeRestriction::Both,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ThemeConfig {
    pub mode: ThemeMode,
    pub restriction: ThemeRestriction,
    pub colors: ThemeColors,
    pub spacing: ThemeSpacing,
    pub effects: ThemeEffects,
    pub branding: ThemeBranding,
}

impl From<ThemeDefaults> for ThemeConfig {
    fn from(defaults: ThemeDefaults) -> Self {
        Self {
            mode: ThemeMode::from(defaults.mode.as_str()),
            restriction: ThemeRestriction::from(defaults.allow_only.as_str()),
            colors: defaults.colors,
            spacing: defaults.spacing,
            effects: defaults.effects,
            branding: defaults.branding,
        }
    }
}

impl Default for ThemeConfig {
    fn default() -> Self {
        Self::from(ThemeDefaults::default())
    }
}
