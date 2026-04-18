use super::config::{ThemeConfig, ThemeRestriction};

pub struct ThemeRenderer {
    config: ThemeConfig,
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

        let restriction_css = match self.config.restriction {
            ThemeRestriction::DarkOnly => self.generate_dark_only_css(),
            ThemeRestriction::LightOnly => self.generate_light_only_css(),
            ThemeRestriction::Both => self.generate_auto_theme_css(),
        };

        format!(
            r#"/* RustWAF Unified Theme */
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

    fn generate_auto_theme_css(&self) -> String {
        let c = &self.config.colors;

        format!(
            r#"/* Dark Theme (Default) */
:root {{
    --waf-bg: {dark_bg};
    --waf-surface: {dark_surface};
    --waf-primary: {dark_primary};
    --waf-text: {dark_text};
    --waf-border: {dark_border};
    --waf-accent: {dark_accent};
    --waf-accent-primary: {dark_accent_primary};
    --waf-accent-secondary: {dark_accent_secondary};
}}

/* Light Theme */
@media (prefers-color-scheme: light) {{
    :root {{
        --waf-bg: {light_bg};
        --waf-surface: {light_surface};
        --waf-primary: {light_primary};
        --waf-text: {light_text};
        --waf-border: {light_border};
        --waf-accent: {light_accent};
        --waf-accent-primary: {light_accent_primary};
        --waf-accent-secondary: {light_accent_secondary};
    }}
}}

/* Cookie Override - Dark */
[data-waf-theme="dark"] {{
    --waf-bg: {dark_bg};
    --waf-surface: {dark_surface};
    --waf-primary: {dark_primary};
    --waf-text: {dark_text};
    --waf-border: {dark_border};
    --waf-accent: {dark_accent};
    --waf-accent-primary: {dark_accent_primary};
    --waf-accent-secondary: {dark_accent_secondary};
}}

/* Cookie Override - Light */
[data-waf-theme="light"] {{
    --waf-bg: {light_bg};
    --waf-surface: {light_surface};
    --waf-primary: {light_primary};
    --waf-text: {light_text};
    --waf-border: {light_border};
    --waf-accent: {light_accent};
    --waf-accent-primary: {light_accent_primary};
    --waf-accent-secondary: {light_accent_secondary};
}}"#,
            dark_bg = c.dark_background,
            dark_surface = c.dark_surface,
            dark_primary = c.dark_primary,
            dark_text = c.dark_text,
            dark_border = c.dark_border,
            dark_accent = c.dark_accent,
            dark_accent_primary = c.dark_accent_primary,
            dark_accent_secondary = c.dark_accent_secondary,
            light_bg = c.light_background,
            light_surface = c.light_surface,
            light_primary = c.light_primary,
            light_text = c.light_text,
            light_border = c.light_border,
            light_accent = c.light_accent,
            light_accent_primary = c.light_accent_primary,
            light_accent_secondary = c.light_accent_secondary,
        )
    }

    fn generate_dark_only_css(&self) -> String {
        let c = &self.config.colors;

        format!(
            r#":root {{
    --waf-bg: {dark_bg};
    --waf-surface: {dark_surface};
    --waf-primary: {dark_primary};
    --waf-text: {dark_text};
    --waf-border: {dark_border};
    --waf-accent: {dark_accent};
    --waf-accent-primary: {dark_accent_primary};
    --waf-accent-secondary: {dark_accent_secondary};
}}"#,
            dark_bg = c.dark_background,
            dark_surface = c.dark_surface,
            dark_primary = c.dark_primary,
            dark_text = c.dark_text,
            dark_border = c.dark_border,
            dark_accent = c.dark_accent,
            dark_accent_primary = c.dark_accent_primary,
            dark_accent_secondary = c.dark_accent_secondary,
        )
    }

    fn generate_light_only_css(&self) -> String {
        let c: &super::config::ThemeColors = &self.config.colors;

        format!(
            r#":root {{
    --waf-bg: {light_bg};
    --waf-surface: {light_surface};
    --waf-primary: {light_primary};
    --waf-text: {light_text};
    --waf-border: {light_border};
    --waf-accent: {light_accent};
    --waf-accent-primary: {light_accent_primary};
    --waf-accent-secondary: {light_accent_secondary};
}}"#,
            light_bg = c.light_background,
            light_surface = c.light_surface,
            light_primary = c.light_primary,
            light_text = c.light_text,
            light_border = c.light_border,
            light_accent = c.light_accent,
            light_accent_primary = c.light_accent_primary,
            light_accent_secondary = c.light_accent_secondary,
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
        match self.config.restriction {
            ThemeRestriction::Both => {
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
            }
            ThemeRestriction::DarkOnly | ThemeRestriction::LightOnly => "".to_string(),
        }
    }

    pub fn generate_theme_toggle_button(&self) -> String {
        match self.config.restriction {
            ThemeRestriction::Both => {
                r#"<button class="waf-theme-toggle" type="button" aria-label="Toggle theme">
    <svg viewBox="0 0 20 20"></svg>
</button>"#
                    .to_string()
            }
            ThemeRestriction::DarkOnly | ThemeRestriction::LightOnly => "".to_string(),
        }
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
