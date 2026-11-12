use synvoid_config::theme::{ThemeColors, ThemeConfig, ThemeRestriction, ThemeScheme};

use super::halloy::{
    halloy_bytes, halloy_lightness, halloy_pill_color, halloy_relative_luminance, halloy_value,
    mix_halloy_colors, opaque_hex, selected_halloy_theme,
};

pub struct ThemeRenderer {
    config: ThemeConfig,
}

struct SchemeTokens {
    bg: String,
    surface: String,
    primary: String,
    text: String,
    border: String,
    accent: String,
    accent_primary: String,
    accent_secondary: String,
    selection_background: String,
    selection_text: String,
}

fn halloy_document(name: &str) -> Option<toml::Value> {
    let bytes = halloy_bytes(selected_halloy_theme(name))?;
    std::str::from_utf8(bytes).ok()?.parse::<toml::Value>().ok()
}

fn selection_pair(
    document: &toml::Value,
    text_primary: &str,
    page_background: &str,
) -> (String, String) {
    let raw = halloy_value(document, &["buffer", "selection"], "");
    let background = if halloy_relative_luminance(raw).is_some() {
        raw.to_owned()
    } else {
        let highlight = halloy_value(document, &["buffer", "highlight"], "");
        if halloy_relative_luminance(highlight).is_some() {
            highlight.to_owned()
        } else {
            mix_halloy_colors(page_background, text_primary, 0.25)
                .unwrap_or_else(|| page_background.to_owned())
        }
    };
    let opaque_background = opaque_hex(&background);
    let text = halloy_pill_color(text_primary, &opaque_background, 0.0)
        .unwrap_or_else(|| text_primary.to_owned());
    (background, text)
}

impl SchemeTokens {
    fn for_theme(name: &str, colors: &ThemeColors, dark: bool) -> Self {
        let parsed = halloy_document(name);
        let empty = toml::Value::Table(toml::map::Map::new());
        let document = parsed.as_ref().unwrap_or(&empty);
        let (
            legacy_bg,
            legacy_surface,
            legacy_text,
            legacy_border,
            legacy_accent_primary,
            legacy_accent_secondary,
        ) = if dark {
            (
                colors.dark_background.as_str(),
                colors.dark_surface.as_str(),
                colors.dark_text.as_str(),
                colors.dark_border.as_str(),
                colors.dark_accent_primary.as_str(),
                colors.dark_accent_secondary.as_str(),
            )
        } else {
            (
                colors.light_background.as_str(),
                colors.light_surface.as_str(),
                colors.light_text.as_str(),
                colors.light_border.as_str(),
                colors.light_accent_primary.as_str(),
                colors.light_accent_secondary.as_str(),
            )
        };
        let general_background = halloy_value(document, &["general", "background"], legacy_bg);
        let buffer_background = halloy_value(document, &["buffer", "background"], legacy_surface);
        let page_background = opaque_hex(
            if halloy_lightness(general_background).unwrap_or(0.0) < 0.5 {
                buffer_background
            } else {
                general_background
            },
        );
        let card_background = opaque_hex(buffer_background);
        let text_primary = halloy_value(document, &["text", "primary"], legacy_text);
        let text = opaque_hex(
            &halloy_pill_color(text_primary, &page_background, 0.36)
                .unwrap_or_else(|| text_primary.to_owned()),
        );
        let (selection_background, selection_text) =
            selection_pair(document, text_primary, &page_background);
        Self {
            bg: page_background,
            surface: card_background.clone(),
            primary: opaque_hex(text_primary),
            text,
            border: opaque_hex(halloy_value(
                document,
                &["general", "border"],
                legacy_border,
            )),
            accent: opaque_hex(halloy_value(
                document,
                &["buffer", "background_title_bar"],
                card_background.as_str(),
            )),
            accent_primary: opaque_hex(halloy_value(
                document,
                &["buffer", "action"],
                legacy_accent_primary,
            )),
            accent_secondary: opaque_hex(halloy_value(
                document,
                &["buffer", "url"],
                legacy_accent_secondary,
            )),
            selection_background,
            selection_text,
        }
    }

    fn declarations(&self) -> String {
        format!(
            "    --waf-bg: {};\n    --waf-surface: {};\n    --waf-primary: {};\n    --waf-text: {};\n    --waf-border: {};\n    --waf-accent: {};\n    --waf-accent-primary: {};\n    --waf-accent-secondary: {};",
            self.bg,
            self.surface,
            self.primary,
            self.text,
            self.border,
            self.accent,
            self.accent_primary,
            self.accent_secondary,
        )
    }

    fn selection_rule(&self) -> String {
        format!(
            "::selection {{\n    background: {};\n    color: {};\n}}",
            self.selection_background, self.selection_text,
        )
    }
}

fn indented(block: &str) -> String {
    block
        .lines()
        .map(|line| format!("    {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

impl ThemeRenderer {
    pub fn new(config: ThemeConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &ThemeConfig {
        &self.config
    }

    pub fn generate_css(&self) -> String {
        let _c = &self.config.colors;
        let s = &self.config.spacing;
        let e = &self.config.effects;

        let restriction_css = match (self.config.restriction, self.config.scheme) {
            (ThemeRestriction::DarkOnly, _) | (ThemeRestriction::Both, ThemeScheme::Dark) => {
                self.generate_dark_only_css()
            }
            (ThemeRestriction::LightOnly, _) | (ThemeRestriction::Both, ThemeScheme::Light) => {
                self.generate_light_only_css()
            }
            (ThemeRestriction::Both, ThemeScheme::System) => self.generate_auto_theme_css(),
        };

        format!(
            r#"/* SynVoid Unified Theme */
:root {{
    --waf-font-family: 'Courier New', 'Monaco', 'Consolas', monospace;
    --waf-border-radius: {border_radius};
    --waf-padding: {padding};
    --waf-max-width: {max_width};
    --waf-glass-opacity: {glass_opacity};
    --waf-blur: {blur};
    --waf-shadow: {shadow};
    --waf-transition: all 0.3s ease;
}}

{restriction_css}

/* Base Styles */
* {{
    box-sizing: border-box;
}}

body {{
    font-family: var(--waf-font-family);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0;
    padding: 1rem;
    background-color: var(--waf-bg);
    color: var(--waf-text);
    transition: var(--waf-transition);
}}

/* Container Box */
.waf-container {{
    background: var(--waf-surface);
    opacity: var(--waf-glass-opacity);
    padding: var(--waf-padding);
    border-radius: var(--waf-border-radius);
    box-shadow: var(--waf-shadow);
    backdrop-filter: blur(var(--waf-blur));
    max-width: var(--waf-max-width);
    width: 100%;
    text-align: center;
    border: 2px solid var(--waf-border);
    position: relative;
    overflow: hidden;
}}

.waf-container::before {{
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: var(--waf-surface);
    opacity: var(--waf-glass-opacity);
    z-index: -1;
    border-radius: var(--waf-border-radius);
}}

/* Neon Glow Effect */
{neon_styles}

/* Logo */
.waf-logo {{
    width: 64px;
    height: 64px;
    margin: 0 auto 1rem;
    display: block;
}}

.waf-logo svg {{
    width: 100%;
    height: 100%;
}}

/* Spinner */
.waf-spinner {{
    width: 48px;
    height: 48px;
    margin: 0 auto 1.5rem;
    position: relative;
}}

.waf-spinner svg {{
    width: 100%;
    height: 100%;
    animation: waf-spin 1s linear infinite;
}}

.waf-spinner-circle {{
    fill: none;
    stroke: var(--waf-primary);
    stroke-width: 4;
    stroke-linecap: round;
    stroke-dasharray: 80, 200;
    stroke-dashoffset: 0;
}}

@keyframes waf-spin {{
    0% {{ transform: rotate(0deg); }}
    100% {{ transform: rotate(360deg); }}
}}

/* Typography */
.waf-title {{
    color: var(--waf-primary);
    font-size: 1.5rem;
    font-weight: bold;
    margin: 0 0 0.5rem;
    text-transform: uppercase;
    letter-spacing: 2px;
}}

.waf-subtitle {{
    color: var(--waf-text);
    font-size: 0.9rem;
    margin: 0 0 1.5rem;
    opacity: 0.8;
}}

.waf-message {{
    color: var(--waf-text);
    line-height: 1.6;
    margin: 0 0 1rem;
}}

.waf-progress {{
    margin-top: 1rem;
    font-size: 0.8rem;
    color: var(--waf-primary);
    font-family: var(--waf-font-family);
}}

/* Form Elements */
.waf-form {{
    margin-top: 1.5rem;
}}

.waf-input {{
    width: 100%;
    padding: 0.75rem 1rem;
    margin-bottom: 1rem;
    border: 2px solid var(--waf-border);
    border-radius: calc(var(--waf-border-radius) / 2);
    background: rgba(0, 0, 0, 0.3);
    color: var(--waf-text);
    font-family: var(--waf-font-family);
    font-size: 1rem;
    transition: var(--waf-transition);
}}

.waf-input:focus {{
    outline: none;
    border-color: var(--waf-primary);
    box-shadow: 0 0 0 3px rgba(var(--waf-primary), 0.2);
}}

.waf-input::placeholder {{
    color: var(--waf-text);
    opacity: 0.5;
}}

.waf-button {{
    width: 100%;
    padding: 0.75rem 1.5rem;
    background: var(--waf-primary);
    color: #fff;
    border: none;
    border-radius: calc(var(--waf-border-radius) / 2);
    font-family: var(--waf-font-family);
    font-size: 1rem;
    font-weight: bold;
    text-transform: uppercase;
    letter-spacing: 1px;
    cursor: pointer;
    transition: var(--waf-transition);
}}

.waf-button:hover {{
    filter: brightness(1.2);
    transform: translateY(-2px);
}}

.waf-button:active {{
    transform: translateY(0);
}}

/* Error Message */
.waf-error {{
    color: var(--waf-primary);
    margin-bottom: 1rem;
    font-size: 0.9rem;
}}

/* Error Code Display */
.waf-error-code {{
    font-size: 5rem;
    font-weight: bold;
    color: var(--waf-primary);
    margin: 0;
    line-height: 1;
    text-shadow: 0 0 20px var(--waf-primary);
}}

/* Pixel Border Effect */
.waf-pixel-border {{
    position: relative;
}}

.waf-pixel-border::after {{
    content: '';
    position: absolute;
    top: -4px;
    left: -4px;
    right: -4px;
    bottom: -4px;
    border: 4px solid var(--waf-border);
    border-radius: var(--waf-border-radius);
    pointer-events: none;
    opacity: 0.5;
}}

/* Theme Toggle */
.waf-theme-toggle {{
    position: fixed;
    top: 1rem;
    right: 1rem;
    background: var(--waf-surface);
    border: 2px solid var(--waf-border);
    border-radius: 50%;
    width: 40px;
    height: 40px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: var(--waf-transition);
    z-index: 1000;
}}

.waf-theme-toggle:hover {{
    border-color: var(--waf-primary);
}}

.waf-theme-toggle svg {{
    width: 20px;
    height: 20px;
    fill: var(--waf-text);
}}

/* CAPTCHA Image */
.waf-captcha-img {{
    margin-bottom: 1rem;
    border: 2px solid var(--waf-border);
    border-radius: calc(var(--waf-border-radius) / 2);
    background: rgba(0, 0, 0, 0.2);
}}

/* Hidden/Verification */
.waf-hidden {{
    display: none;
}}

.waf-verification-area {{
    display: none;
}}

/* Responsive */
@media (max-width: 480px) {{
    .waf-container {{
        padding: 1.5rem;
    }}
    
    .waf-title {{
        font-size: 1.25rem;
    }}
}}"#,
            border_radius = s.border_radius,
            padding = s.padding,
            max_width = s.max_width,
            glass_opacity = e.glass_opacity,
            blur = e.blur,
            shadow = e.shadow,
            restriction_css = restriction_css,
            neon_styles = if e.neon_glow {
                self.generate_neon_css()
            } else {
                "".to_string()
            },
        )
    }

    fn dark_tokens(&self) -> SchemeTokens {
        SchemeTokens::for_theme(&self.config.dark_theme, &self.config.colors, true)
    }

    fn light_tokens(&self) -> SchemeTokens {
        SchemeTokens::for_theme(&self.config.light_theme, &self.config.colors, false)
    }

    fn theme_toggle_enabled(&self) -> bool {
        matches!(self.config.restriction, ThemeRestriction::Both)
            && matches!(self.config.scheme, ThemeScheme::System)
    }

    fn generate_auto_theme_css(&self) -> String {
        let dark = self.dark_tokens();
        let light = self.light_tokens();
        let dark_vars = dark.declarations();
        let light_vars = light.declarations();
        let dark_selection = dark.selection_rule();
        let light_selection = light.selection_rule();

        format!(
            r#"/* Dark Theme (Default) */
:root {{
{dark_vars}
}}

{dark_selection}

/* Light Theme */
@media (prefers-color-scheme: light) {{
{light_root}
{light_selection}
}}

/* Cookie Override - Dark */
[data-waf-theme="dark"] {{
{dark_vars}
}}

[data-waf-theme="dark"] ::selection {{
    background: {dark_sel_bg};
    color: {dark_sel_text};
}}

/* Cookie Override - Light */
[data-waf-theme="light"] {{
{light_vars}
}}

[data-waf-theme="light"] ::selection {{
    background: {light_sel_bg};
    color: {light_sel_text};
}}"#,
            dark_vars = dark_vars,
            dark_selection = dark_selection,
            light_root = indented(&format!(":root {{\n{light_vars}\n}}")),
            light_selection = indented(&light_selection),
            dark_sel_bg = dark.selection_background,
            dark_sel_text = dark.selection_text,
            light_vars = light_vars,
            light_sel_bg = light.selection_background,
            light_sel_text = light.selection_text,
        )
    }

    fn generate_dark_only_css(&self) -> String {
        let dark = self.dark_tokens();
        let vars = dark.declarations();
        let selection = dark.selection_rule();

        format!(
            r#":root {{
{vars}
}}

{selection}"#,
            vars = vars,
            selection = selection,
        )
    }

    fn generate_light_only_css(&self) -> String {
        let light = self.light_tokens();
        let vars = light.declarations();
        let selection = light.selection_rule();

        format!(
            r#":root {{
{vars}
}}

{selection}"#,
            vars = vars,
            selection = selection,
        )
    }

    fn generate_neon_css(&self) -> String {
        r#".waf-container {
    box-shadow: 
        var(--waf-shadow),
        0 0 20px rgba(var(--waf-primary), 0.3),
        inset 0 0 20px rgba(var(--waf-primary), 0.05);
}

.waf-title {
    text-shadow: 0 0 10px var(--waf-primary), 0 0 20px var(--waf-primary);
}

.waf-button {
    box-shadow: 0 0 15px rgba(var(--waf-primary), 0.5);
}

.waf-button:hover {
    box-shadow: 0 0 25px rgba(var(--waf-primary), 0.7);
}"#
        .to_string()
    }

    pub fn generate_spinner_svg(&self) -> String {
        r#"<svg viewBox="0 0 50 50">
    <circle class="waf-spinner-circle" cx="25" cy="25" r="20"/>
</svg>"#
            .to_string()
    }

    pub fn generate_logo_svg(&self) -> String {
        if let Some(ref url) = self.config.branding.logo_url {
            format!(r#"<img src="{}" alt="Logo" class="waf-logo-img">"#, url)
        } else {
            r#"<svg viewBox="0 0 64 64" class="waf-logo-svg">
    <defs>
        <linearGradient id="waf-logo-grad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style="stop-color:currentColor;stop-opacity:1" />
            <stop offset="100%" style="stop-color:currentColor;stop-opacity:0.6" />
        </linearGradient>
    </defs>
    <!-- Shield shape -->
    <path d="M32 4 L8 16 L8 32 C8 48 32 60 32 60 C32 60 56 48 56 32 L56 16 Z" 
          fill="none" 
          stroke="url(#waf-logo-grad)" 
          stroke-width="3"
          stroke-linejoin="round"/>
    <!-- Inner R -->
    <text x="32" y="42" 
          text-anchor="middle" 
          font-family="'Courier New', monospace" 
          font-size="24" 
          font-weight="bold" 
          fill="currentColor">R</text>
    <!-- Lock icon at bottom -->
    <rect x="28" y="46" width="8" height="6" rx="1" fill="currentColor" opacity="0.8"/>
    <path d="M30 46 L30 43 C30 41 32 40 32 40 C32 40 34 41 34 43 L34 46" 
          fill="none" 
          stroke="currentColor" 
          stroke-width="1.5"/>
</svg>"#
                .to_string()
        }
    }

    pub fn generate_theme_toggle_script(&self) -> String {
        if self.theme_toggle_enabled() {
            r#"<script>
(function() {
    const COOKIE_NAME = 'waf_theme';
    const COOKIE_MAX_AGE = 31536000;
    
    function getTheme() {
        const match = document.cookie.match(new RegExp('(^| )' + COOKIE_NAME + '=([^;]+)'));
        if (match) return match[2];
        return null;
    }
    
    function setTheme(theme) {
        document.documentElement.setAttribute('data-waf-theme', theme);
        document.cookie = COOKIE_NAME + '=' + theme + '; path=/; max-age=' + COOKIE_MAX_AGE + '; SameSite=Lax';
    }
    
    function initTheme() {
        const saved = getTheme();
        if (saved) {
            document.documentElement.setAttribute('data-waf-theme', saved);
        }
    }
    
    function toggleTheme() {
        const current = document.documentElement.getAttribute('data-waf-theme');
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        
        if (current === 'dark' || (!current && prefersDark)) {
            setTheme('light');
        } else {
            setTheme('dark');
        }
        
        updateToggleIcon();
    }
    
    function updateToggleIcon() {
        const toggle = document.querySelector('.waf-theme-toggle svg');
        if (!toggle) return;
        
        const current = document.documentElement.getAttribute('data-waf-theme');
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        const isDark = current === 'dark' || (!current && prefersDark);
        
        toggle.innerHTML = isDark 
            ? '<circle cx="10" cy="10" r="4"/><path d="M10 1v2M10 17v2M1 10h2M17 10h2M3.5 3.5l1.4 1.4M15.1 15.1l1.4 1.4M3.5 16.5l1.4-1.4M15.1 4.9l1.4-1.4"/>'
            : '<path d="M17 10a7 7 0 11-14 0 7 7 0 0114 0zM10 3v14M6.5 6.5l7 7M13.5 6.5l-7 7"/>';
    }
    
    initTheme();
    
    document.addEventListener('DOMContentLoaded', function() {
        updateToggleIcon();
        const toggle = document.querySelector('.waf-theme-toggle');
        if (toggle) {
            toggle.addEventListener('click', toggleTheme);
        }
    });
})();
</script>"#.to_string()
        } else {
            "".to_string()
        }
    }

    pub fn generate_theme_toggle_button(&self) -> String {
        if self.theme_toggle_enabled() {
            r#"<button class="waf-theme-toggle" type="button" aria-label="Toggle theme">
    <svg viewBox="0 0 20 20"></svg>
</button>"#
                .to_string()
        } else {
            "".to_string()
        }
    }

    pub fn generate_folder_icon_svg(&self) -> String {
        r#"<svg class="waf-dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/>
</svg>"#
            .to_string()
    }

    pub fn generate_file_icon_svg(&self) -> String {
        r#"<svg class="waf-dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
    <polyline points="14,2 14,8 20,8"/>
    <line x1="16" y1="13" x2="8" y2="13"/>
    <line x1="16" y1="17" x2="8" y2="17"/>
    <polyline points="10,9 9,9 8,9"/>
</svg>"#
            .to_string()
    }

    pub fn generate_file_type_icon_svg(&self, filename: &str) -> String {
        let ext = filename.split('.').next_back().map(|e| e.to_lowercase());
        match ext.as_deref() {
            Some("js") => r#"<svg class="waf-dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 9v6M15 9v6M9 15h6"/></svg>"#.to_string(),
            Some("ts") | Some("tsx") | Some("jsx") => r#"<svg class="waf-dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 9v6M15 9v6M9 15h6"/></svg>"#.to_string(),
            Some("py") => r#"<svg class="waf-dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>"#.to_string(),
            Some("rs") => r#"<svg class="waf-dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>"#.to_string(),
            Some("html") | Some("htm") => r#"<svg class="waf-dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="16,18 22,12 16,6"/><polyline points="8,6 2,12 8,18"/></svg>"#.to_string(),
            Some("css") | Some("scss") | Some("sass") | Some("less") => r#"<svg class="waf-dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>"#.to_string(),
            Some("json") | Some("yaml") | Some("yml") | Some("toml") => r#"<svg class="waf-dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6"/><path d="M8 13h8M8 17h8"/></svg>"#.to_string(),
            Some("md") | Some("txt") => r#"<svg class="waf-dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14,2 14,8 20,8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>"#.to_string(),
            Some("png") | Some("jpg") | Some("jpeg") | Some("gif") | Some("svg") | Some("webp") | Some("ico") => r#"<svg class="waf-dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21,15 16,10 5,21"/></svg>"#.to_string(),
            Some("pdf") => r#"<svg class="waf-dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14,2 14,8 20,8"/><path d="M9 15v-2h2a1 1 0 010 2H9zM9 11h2"/></svg>"#.to_string(),
            Some("zip") | Some("tar") | Some("gz") | Some("bz2") | Some("xz") | Some("7z") | Some("rar") => r#"<svg class="waf-dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/><path d="M12 11v6M9 14h6"/></svg>"#.to_string(),
            _ => self.generate_file_icon_svg(),
        }
    }

    pub fn generate_parent_dir_icon_svg(&self) -> String {
        r#"<svg class="waf-dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path d="M15 18l-6-6 6-6"/>
</svg>"#
            .to_string()
    }

    pub fn generate_directory_listing_css(&self) -> String {
        let s = &self.config.spacing;

        format!(
            r#"/* Directory Listing Styles */
.waf-dir-container {{
    max-width: 900px;
    margin: 0 auto;
    padding: {padding};
}}

.waf-dir-title {{
    color: var(--waf-primary);
    border-bottom: 1px solid var(--waf-border);
    padding-bottom: 0.5rem;
    margin-bottom: 1rem;
    font-weight: 400;
    font-size: 1.5rem;
    margin-top: 0;
}}

.waf-dir-breadcrumbs {{
    color: var(--waf-text);
    opacity: 0.7;
    margin-bottom: 1rem;
    font-size: 0.875rem;
}}

.waf-dir-breadcrumbs a {{
    color: var(--waf-primary);
    text-decoration: none;
}}

.waf-dir-breadcrumbs a:hover {{
    text-decoration: underline;
}}

.waf-dir-breadcrumbs span {{
    margin: 0 0.5rem;
    color: var(--waf-text);
    opacity: 0.5;
}}

.waf-dir-table {{
    width: 100%;
    border-collapse: collapse;
    background: var(--waf-surface);
    border-radius: var(--waf-border-radius);
    overflow: hidden;
    border: 1px solid var(--waf-border);
}}

.waf-dir-table th {{
    text-align: left;
    padding: 0.75rem 1rem;
    background: var(--waf-accent);
    color: var(--waf-primary);
    font-weight: 500;
    font-size: 0.875rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}}

.waf-dir-table th a {{
    color: var(--waf-primary);
    text-decoration: none;
}}

.waf-dir-table th a:hover {{
    text-decoration: underline;
}}

.waf-dir-table td {{
    padding: 0.75rem 1rem;
    border-bottom: 1px solid var(--waf-border);
    font-size: 0.9375rem;
}}

.waf-dir-icon {{
    width: 20px;
    height: 20px;
    vertical-align: middle;
    margin-right: 0.5rem;
    flex-shrink: 0;
}}

.waf-dir-table td:first-child {{
    display: flex;
    align-items: center;
}}

.waf-dir-table tr:last-child td {{
    border-bottom: none;
}}

.waf-dir-table tr:hover td {{
    background: var(--waf-accent);
}}

.waf-dir-table a {{
    color: var(--waf-primary);
    text-decoration: none;
    transition: color 0.2s;
}}

.waf-dir-table a:hover {{
    text-decoration: underline;
}}

.waf-dir-size {{
    text-align: right;
    color: var(--waf-text);
    opacity: 0.7;
    font-family: var(--waf-font-family);
    font-size: 0.875rem;
}}

/* Pagination */
.waf-dir-pagination {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 1rem;
    padding: 0.75rem;
    background: var(--waf-surface);
    border: 1px solid var(--waf-border);
    border-radius: var(--waf-border-radius);
}}

.waf-dir-pagination-info {{
    color: var(--waf-text);
    font-size: 0.875rem;
}}

.waf-dir-pagination-controls {{
    display: flex;
    gap: 0.5rem;
}}

.waf-dir-pagination-controls a {{
    padding: 0.5rem 0.75rem;
    background: var(--waf-accent);
    color: var(--waf-primary);
    border-radius: calc(var(--waf-border-radius) / 2);
    text-decoration: none;
    font-size: 0.875rem;
    transition: var(--waf-transition);
}}

.waf-dir-pagination-controls a:hover {{
    filter: brightness(1.2);
}}

.waf-dir-pagination-controls a.disabled {{
    opacity: 0.5;
    pointer-events: none;
}}

/* Sorting Controls */
.waf-dir-sort {{
    display: flex;
    gap: 1rem;
    margin-bottom: 1rem;
    font-size: 0.875rem;
}}

.waf-dir-sort a {{
    color: var(--waf-text);
    text-decoration: none;
    padding: 0.25rem 0.5rem;
    border-radius: calc(var(--waf-border-radius) / 4);
}}

.waf-dir-sort a:hover {{
    background: var(--waf-accent);
}}

.waf-dir-sort a.active {{
    color: var(--waf-primary);
    font-weight: 500;
}}

/* Filter Controls */
.waf-dir-filter {{
    margin-bottom: 1rem;
}}

.waf-dir-filter input {{
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--waf-border);
    border-radius: calc(var(--waf-border-radius) / 2);
    background: var(--waf-surface);
    color: var(--waf-text);
    font-family: var(--waf-font-family);
    font-size: 0.875rem;
    width: 200px;
}}

.waf-dir-filter input:focus {{
    outline: none;
    border-color: var(--waf-primary);
}}

/* Skip Link for Accessibility */
.waf-skip-link {{
    position: absolute;
    top: -40px;
    left: 0;
    background: var(--waf-primary);
    color: #fff;
    padding: 0.5rem 1rem;
    z-index: 9999;
    transition: top 0.2s;
    text-decoration: none;
    font-weight: bold;
    border-radius: var(--waf-border-radius);
}}

.waf-skip-link:focus {{
    top: 1rem;
    outline: 2px solid var(--waf-primary);
    outline-offset: 2px;
}}

/* Screen reader only class */
.waf-sr-only {{
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
}}

/* Focus Styles for Keyboard Navigation */
.waf-dir-table a:focus,
.waf-dir-sort a:focus,
.waf-dir-pagination-controls a:focus {{
    outline: 2px solid var(--waf-primary);
    outline-offset: 2px;
}}

/* High contrast focus indicator */
.waf-dir-pagination-controls a:focus {{
    box-shadow: 0 0 0 3px rgba(var(--waf-primary), 0.4);
}}

/* Mobile Responsiveness */
@media (max-width: 768px) {{
    .waf-dir-table {{
        display: block;
        overflow-x: auto;
        white-space: nowrap;
    }}

    .waf-dir-table th,
    .waf-dir-table td {{
        padding: 0.5rem 0.75rem;
        font-size: 0.875rem;
    }}

    .waf-dir-pagination {{
        flex-direction: column;
        gap: 0.75rem;
    }}

    .waf-dir-pagination-controls {{
        flex-wrap: wrap;
        justify-content: center;
    }}

    .waf-dir-sort {{
        flex-wrap: wrap;
        justify-content: center;
    }}
}}

@media (max-width: 480px) {{
    .waf-dir-table {{
        font-size: 0.8125rem;
    }}

    .waf-dir-table th,
    .waf-dir-table td {{
        padding: 0.4rem 0.5rem;
    }}

    .waf-container {{
        padding: 1rem;
    }}

    .waf-dir-title {{
        font-size: 1.25rem;
    }}

    .waf-dir-breadcrumbs {{
        font-size: 0.875rem;
    }}

    .waf-dir-pagination-controls a {{
        padding: 0.4rem 0.6rem;
        font-size: 0.8125rem;
    }}
}}"#,
            padding = s.padding,
        )
    }
}

impl Default for ThemeRenderer {
    fn default() -> Self {
        Self::new(ThemeConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::{SchemeTokens, ThemeRenderer};
    use crate::halloy::{halloy_relative_luminance, HALLOY_NAMES, PILL_MINIMUM_CONTRAST};
    use synvoid_config::theme::{ThemeConfig, ThemeDefaults, ThemeScheme};

    const TOKEN_VARS: [&str; 8] = [
        "--waf-bg",
        "--waf-surface",
        "--waf-primary",
        "--waf-text",
        "--waf-border",
        "--waf-accent",
        "--waf-accent-primary",
        "--waf-accent-secondary",
    ];

    fn config_for(dark: &str, light: &str, scheme: ThemeScheme) -> ThemeConfig {
        ThemeConfig::from(ThemeDefaults {
            dark_theme: dark.to_owned(),
            light_theme: light.to_owned(),
            scheme: scheme.as_str().to_owned(),
            ..ThemeDefaults::default()
        })
    }

    fn restricted_config(allow_only: &str, scheme: ThemeScheme) -> ThemeConfig {
        ThemeConfig::from(ThemeDefaults {
            allow_only: allow_only.to_owned(),
            scheme: scheme.as_str().to_owned(),
            ..ThemeDefaults::default()
        })
    }

    fn selection_contrast_ratio(background: &str, foreground: &str) -> Option<f64> {
        let bg = halloy_relative_luminance(background)?;
        let fg = halloy_relative_luminance(foreground)?;
        let (high, low) = if bg > fg { (bg, fg) } else { (fg, bg) };
        Some((high + 0.05) / (low + 0.05))
    }

    #[test]
    fn every_bundled_theme_renders_a_complete_token_set_per_scheme() {
        for name in HALLOY_NAMES {
            for scheme in [ThemeScheme::System, ThemeScheme::Dark, ThemeScheme::Light] {
                let css = ThemeRenderer::new(config_for(name, name, scheme)).generate_css();
                for var in TOKEN_VARS {
                    assert!(
                        css.contains(var),
                        "theme {name:?} scheme {scheme:?} is missing {var}"
                    );
                }
                assert!(
                    css.contains("::selection"),
                    "theme {name:?} scheme {scheme:?} is missing its selection rule"
                );
            }
        }
    }

    #[test]
    fn system_scheme_serves_both_sides_behind_the_media_query() {
        let css = ThemeRenderer::new(config_for(
            "Catppuccin Mocha",
            "Catppuccin Latte",
            ThemeScheme::System,
        ))
        .generate_css();
        assert!(
            css.contains("@media (prefers-color-scheme: light)"),
            "system output must carry the light-scheme media query"
        );
        assert!(css.contains("[data-waf-theme=\"dark\"]"));
        assert!(css.contains("[data-waf-theme=\"light\"]"));
        assert!(
            css.contains("#181825"),
            "system output must carry the dark (Mocha) page background"
        );
        assert!(
            css.contains("#DCE0E8"),
            "system output must carry the light (Latte) page background"
        );
        assert_eq!(
            css.matches("::selection").count(),
            4,
            "system output must scope one selection rule per scheme block"
        );
    }

    #[test]
    fn forced_schemes_emit_a_single_scheme() {
        let dark = ThemeRenderer::new(config_for("Nord", "Catppuccin Latte", ThemeScheme::Dark))
            .generate_css();
        assert!(
            !dark.contains("@media (prefers-color-scheme"),
            "forced dark output must not carry the media query"
        );
        assert!(
            !dark.contains("data-waf-theme"),
            "forced dark output must not carry cookie overrides"
        );
        assert!(dark.contains("::selection"));
        assert!(
            dark.contains("#3B4252"),
            "forced dark output must carry the Nord page background"
        );
        assert!(
            !dark.contains("#DCE0E8"),
            "forced dark output must not leak the light theme"
        );

        let light = ThemeRenderer::new(config_for("Nord", "Catppuccin Latte", ThemeScheme::Light))
            .generate_css();
        assert!(!light.contains("@media (prefers-color-scheme"));
        assert!(!light.contains("data-waf-theme"));
        assert!(light.contains("::selection"));
        assert!(light.contains("#DCE0E8"));
        assert!(!light.contains("#3B4252"));
    }

    #[test]
    fn restriction_keeps_single_scheme_semantics() {
        let dark_only =
            ThemeRenderer::new(restricted_config("dark", ThemeScheme::System)).generate_css();
        assert!(!dark_only.contains("@media (prefers-color-scheme"));
        assert!(!dark_only.contains("data-waf-theme"));
        assert!(dark_only.contains("::selection"));

        let light_only =
            ThemeRenderer::new(restricted_config("light", ThemeScheme::System)).generate_css();
        assert!(!light_only.contains("@media (prefers-color-scheme"));
        assert!(!light_only.contains("data-waf-theme"));
        assert!(light_only.contains("::selection"));

        let both_dark =
            ThemeRenderer::new(restricted_config("both", ThemeScheme::Dark)).generate_css();
        let dark_only_dark =
            ThemeRenderer::new(restricted_config("dark", ThemeScheme::Dark)).generate_css();
        assert_eq!(
            both_dark, dark_only_dark,
            "Both+Dark must collapse to the same single-scheme output as DarkOnly"
        );
    }

    #[test]
    fn theme_toggle_only_ships_with_dual_scheme_output() {
        let system = ThemeRenderer::new(restricted_config("both", ThemeScheme::System));
        assert!(!system.generate_theme_toggle_script().is_empty());
        assert!(!system.generate_theme_toggle_button().is_empty());

        let forced = ThemeRenderer::new(restricted_config("both", ThemeScheme::Dark));
        assert!(forced.generate_theme_toggle_script().is_empty());
        assert!(forced.generate_theme_toggle_button().is_empty());

        let restricted = ThemeRenderer::new(restricted_config("dark", ThemeScheme::System));
        assert!(restricted.generate_theme_toggle_script().is_empty());
        assert!(restricted.generate_theme_toggle_button().is_empty());
    }

    #[test]
    fn selection_pair_clears_the_contrast_floor_for_every_theme() {
        let colors = ThemeConfig::default().colors;
        for name in HALLOY_NAMES {
            for dark in [true, false] {
                let tokens = SchemeTokens::for_theme(name, &colors, dark);
                let ratio =
                    selection_contrast_ratio(&tokens.selection_background, &tokens.selection_text)
                        .expect("the selection pair must be colours");
                assert!(
                    ratio >= PILL_MINIMUM_CONTRAST,
                    "theme {name:?} dark={dark} selection {} on {} is {ratio:.2}:1",
                    tokens.selection_text,
                    tokens.selection_background,
                );
            }
        }
    }

    #[test]
    fn unknown_names_fall_back_to_the_default_theme() {
        let scheme = ThemeScheme::System;
        let expected =
            ThemeRenderer::new(config_for("Cyber Red", "Cyber Red", scheme)).generate_css();
        let unknown =
            ThemeRenderer::new(config_for("missing-nope", "missing-nope", scheme)).generate_css();
        assert_eq!(unknown, expected);
        let empty = ThemeRenderer::new(config_for("", "", scheme)).generate_css();
        let empty_expected =
            ThemeRenderer::new(config_for("Catppuccin Mocha", "Catppuccin Latte", scheme))
                .generate_css();
        assert_eq!(empty, empty_expected);
        let oversize = "x".repeat(129);
        let oversize_css =
            ThemeRenderer::new(config_for(&oversize, &oversize, scheme)).generate_css();
        assert_eq!(
            oversize_css, empty_expected,
            "oversize names normalize to the defaults at the config layer"
        );

        let mixed = ThemeRenderer::new(config_for("Nord", "missing-nope", ThemeScheme::Dark))
            .generate_css();
        let mixed_expected =
            ThemeRenderer::new(config_for("Nord", "Cyber Red", ThemeScheme::Dark)).generate_css();
        assert_eq!(mixed, mixed_expected);
    }
}
