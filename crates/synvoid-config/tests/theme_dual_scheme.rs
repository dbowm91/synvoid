//! Phase 02: `[defaults.theme]` dual-scheme selection (`dark_theme` /
//! `light_theme` / `scheme`) with legacy `preset` + `mode` compatibility.
//!
//! The resolution contract pinned here:
//! - Explicit new fields always win over the legacy `preset` / `mode`.
//! - When all three new fields are at their defaults but `preset` names a
//!   legacy preset, both resolve to that preset's Halloy equivalent and the
//!   scheme follows `mode` (`dark` / `light` forced, `auto` -> `system`).
//! - Name validation at this layer is shallow (non-empty, at most
//!   `MAX_THEME_NAME_BYTES` bytes). Strict allowlist matching lives in the
//!   `synvoid-theme` registry layer; unknown names resolve without error
//!   and fall back there, so a typo never fails the boot.

use synvoid_config::theme::{
    ThemeConfig, ThemeDefaults, ThemeMode, ThemePreset, ThemeScheme, MAX_THEME_NAME_BYTES,
};
use synvoid_config::MainConfig;

const MINIMAL_MAIN: &str = r#"
[server]
host = "127.0.0.1"
port = 8080

[fallback]
mode = "return_404"

[admin]
enabled = false
port = 8081
token = "fixture-only-low-entropy-value-0000000000"

[logging]
level = "info"

[metrics]
enabled = false
port = 9090

[defaults]
"#;

fn theme_section(body: &str) -> String {
    format!("{MINIMAL_MAIN}\n[defaults.theme]\n{body}\n")
}

#[test]
fn defaults_carry_blog_defaults() {
    let defaults = ThemeDefaults::default();
    assert_eq!(defaults.dark_theme, "Catppuccin Mocha");
    assert_eq!(defaults.light_theme, "Catppuccin Latte");
    assert_eq!(defaults.scheme, "system");

    let config = ThemeConfig::default();
    assert_eq!(config.dark_theme, "Catppuccin Mocha");
    assert_eq!(config.light_theme, "Catppuccin Latte");
    assert_eq!(config.scheme, ThemeScheme::System);
}

#[test]
fn old_config_resolves_to_legacy_equivalent_with_forced_scheme() {
    let parsed: ThemeDefaults = toml::from_str("preset = \"ocean\"\nmode = \"dark\"\n").unwrap();
    let config = ThemeConfig::from(parsed);
    assert_eq!(config.dark_theme, "ocean");
    assert_eq!(config.light_theme, "ocean");
    assert_eq!(config.scheme, ThemeScheme::Dark);
    assert_eq!(config.mode, ThemeMode::Dark);
    assert_eq!(
        config.colors,
        ThemePreset::Default.colors(),
        "bare deserialization leaves colors untouched; apply_preset() owns the preset fill"
    );
}

#[test]
fn legacy_mode_auto_resolves_to_system() {
    let parsed: ThemeDefaults = toml::from_str("preset = \"forest\"\nmode = \"auto\"\n").unwrap();
    let config = ThemeConfig::from(parsed);
    assert_eq!(config.dark_theme, "forest");
    assert_eq!(config.light_theme, "forest");
    assert_eq!(config.scheme, ThemeScheme::System);
}

#[test]
fn legacy_mode_light_forces_light() {
    let parsed: ThemeDefaults = toml::from_str("preset = \"sunset\"\nmode = \"light\"\n").unwrap();
    let config = ThemeConfig::from(parsed);
    assert_eq!(config.dark_theme, "sunset");
    assert_eq!(config.light_theme, "sunset");
    assert_eq!(config.scheme, ThemeScheme::Light);
}

#[test]
fn legacy_default_preset_resolves_to_blog_defaults() {
    let parsed: ThemeDefaults = toml::from_str("preset = \"default\"\n").unwrap();
    let config = ThemeConfig::from(parsed);
    assert_eq!(config.dark_theme, "Catppuccin Mocha");
    assert_eq!(config.light_theme, "Catppuccin Latte");
    assert_eq!(config.scheme, ThemeScheme::System);
}

#[test]
fn legacy_dark_and_light_presets_resolve_to_matching_blog_defaults() {
    let parsed: ThemeDefaults = toml::from_str("preset = \"dark\"\n").unwrap();
    let config = ThemeConfig::from(parsed);
    assert_eq!(config.dark_theme, "Catppuccin Mocha");
    assert_eq!(config.light_theme, "Catppuccin Mocha");

    let parsed: ThemeDefaults = toml::from_str("preset = \"light\"\n").unwrap();
    let config = ThemeConfig::from(parsed);
    assert_eq!(config.dark_theme, "Catppuccin Latte");
    assert_eq!(config.light_theme, "Catppuccin Latte");
}

#[test]
fn new_config_resolves_verbatim() {
    let parsed: ThemeDefaults = toml::from_str(
        "dark_theme = \"Gruvbox Dark\"\nlight_theme = \"Gruvbox Light\"\nscheme = \"light\"\n",
    )
    .unwrap();
    let config = ThemeConfig::from(parsed);
    assert_eq!(config.dark_theme, "Gruvbox Dark");
    assert_eq!(config.light_theme, "Gruvbox Light");
    assert_eq!(config.scheme, ThemeScheme::Light);
}

#[test]
fn explicit_new_fields_always_win_over_legacy_preset() {
    let parsed: ThemeDefaults =
        toml::from_str("preset = \"ocean\"\nmode = \"dark\"\ndark_theme = \"Dracula\"\n").unwrap();
    let config = ThemeConfig::from(parsed);
    assert_eq!(config.dark_theme, "Dracula");
    assert_eq!(config.light_theme, "Catppuccin Latte");
    assert_eq!(config.scheme, ThemeScheme::System);
}

#[test]
fn unknown_preset_leaves_new_fields_at_defaults() {
    let parsed: ThemeDefaults = toml::from_str("preset = \"not-a-preset\"\n").unwrap();
    let config = ThemeConfig::from(parsed);
    assert_eq!(config.dark_theme, "Catppuccin Mocha");
    assert_eq!(config.light_theme, "Catppuccin Latte");
    assert_eq!(config.scheme, ThemeScheme::System);
}

#[test]
fn unknown_names_fall_back_without_boot_failure() {
    let oversize = "x".repeat(MAX_THEME_NAME_BYTES + 1);
    let body = format!(
        "dark_theme = \"\"\nlight_theme = \"{oversize}\"\nscheme = \"bogus\"\npreset = \"ocean\"\n"
    );
    let main = MainConfig::from_toml_str(&theme_section(&body))
        .expect("unknown theme names must not fail the boot path");
    let config = ThemeConfig::from(main.defaults.theme);
    assert_eq!(config.dark_theme, "Catppuccin Mocha");
    assert_eq!(config.light_theme, "Catppuccin Latte");
    assert_eq!(config.scheme, ThemeScheme::System);
}

#[test]
fn scheme_validation_accepts_known_values_case_insensitively() {
    for (raw, expected) in [
        ("system", ThemeScheme::System),
        ("dark", ThemeScheme::Dark),
        ("light", ThemeScheme::Light),
        ("DARK", ThemeScheme::Dark),
        ("Light", ThemeScheme::Light),
        ("SYSTEM", ThemeScheme::System),
        ("bogus", ThemeScheme::System),
        ("", ThemeScheme::System),
        ("auto", ThemeScheme::System),
    ] {
        assert_eq!(
            ThemeScheme::from(raw),
            expected,
            "scheme {raw:?} must normalize to {expected:?}"
        );
        let parsed: ThemeDefaults = toml::from_str(&format!("scheme = \"{raw}\"\n")).unwrap();
        assert_eq!(ThemeConfig::from(parsed).scheme, expected);
    }
}

#[test]
fn name_length_boundary() {
    let at_limit = "y".repeat(MAX_THEME_NAME_BYTES);
    let parsed: ThemeDefaults = toml::from_str(&format!("dark_theme = \"{at_limit}\"\n")).unwrap();
    assert_eq!(ThemeConfig::from(parsed).dark_theme, at_limit);

    let over_limit = "y".repeat(MAX_THEME_NAME_BYTES + 1);
    let parsed: ThemeDefaults =
        toml::from_str(&format!("dark_theme = \"{over_limit}\"\n")).unwrap();
    assert_eq!(ThemeConfig::from(parsed).dark_theme, "Catppuccin Mocha");
}

#[test]
fn apply_preset_resolves_compat_and_is_idempotent() {
    let mut defaults: ThemeDefaults =
        toml::from_str("preset = \"ocean\"\nmode = \"dark\"\n").unwrap();
    defaults.apply_preset();
    assert_eq!(defaults.dark_theme, "ocean");
    assert_eq!(defaults.light_theme, "ocean");
    assert_eq!(defaults.scheme, "dark");

    let snapshot = (
        defaults.dark_theme.clone(),
        defaults.light_theme.clone(),
        defaults.scheme.clone(),
    );
    defaults.apply_preset();
    assert_eq!(
        (
            defaults.dark_theme.clone(),
            defaults.light_theme.clone(),
            defaults.scheme.clone(),
        ),
        snapshot,
        "a second apply_preset must be stable"
    );

    let config = ThemeConfig::from(defaults);
    assert_eq!(config.dark_theme, "ocean");
    assert_eq!(config.scheme, ThemeScheme::Dark);
}

#[test]
fn shipped_example_resolves_to_blog_defaults() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let text = std::fs::read_to_string(root.join("config/main.toml.example"))
        .expect("shipped example must exist");
    let parsed: MainConfig = toml::from_str(&text).expect("shipped example must deserialize");
    let config = ThemeConfig::from(parsed.defaults.theme);
    assert_eq!(config.dark_theme, "Catppuccin Mocha");
    assert_eq!(config.light_theme, "Catppuccin Latte");
    assert_eq!(config.scheme, ThemeScheme::System);
}

#[test]
fn site_theme_config_propagates_resolved_pair() {
    use synvoid_config::site::SiteThemeConfig;

    let defaults = ThemeDefaults {
        dark_theme: "Nord".to_string(),
        light_theme: "Nord Light".to_string(),
        scheme: "dark".to_string(),
        ..ThemeDefaults::default()
    };
    let default_theme = ThemeConfig::from(defaults);
    let site = SiteThemeConfig::default();
    let resolved = site.to_theme_config(&default_theme);
    assert_eq!(resolved.dark_theme, "Nord");
    assert_eq!(resolved.light_theme, "Nord Light");
    assert_eq!(resolved.scheme, ThemeScheme::Dark);
}
