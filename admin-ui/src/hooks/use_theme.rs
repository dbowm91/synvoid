const STORAGE_KEY: &str = "synvoid-theme";

#[derive(Clone, Copy, PartialEq, Default)]
pub enum Theme {
    #[default]
    Dark,
    Light,
    Ocean,
    Forest,
    Sunset,
}

impl Theme {
    pub fn class(&self) -> &'static str {
        match self {
            Theme::Dark => "",
            Theme::Light => "light",
            Theme::Ocean => "theme-ocean",
            Theme::Forest => "theme-forest",
            Theme::Sunset => "theme-sunset",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Theme::Dark => "Dark",
            Theme::Light => "Light",
            Theme::Ocean => "Ocean",
            Theme::Forest => "Forest",
            Theme::Sunset => "Sunset",
        }
    }

    pub fn from_preset(preset: &str) -> Self {
        match preset {
            "light" => Theme::Light,
            "ocean" => Theme::Ocean,
            "forest" => Theme::Forest,
            "sunset" => Theme::Sunset,
            _ => Theme::Dark,
        }
    }

    #[allow(clippy::wrong_self_convention)] // reason: 'to_' returns borrowed &str, not a consuming conversion
    pub fn to_preset(&self) -> &'static str {
        match self {
            Theme::Dark => "dark",
            Theme::Light => "light",
            Theme::Ocean => "ocean",
            Theme::Forest => "forest",
            Theme::Sunset => "sunset",
        }
    }

    pub fn toggle(&self) -> Self {
        match self {
            Theme::Dark => Theme::Light,
            Theme::Light => Theme::Dark,
            Theme::Ocean => Theme::Ocean,
            Theme::Forest => Theme::Forest,
            Theme::Sunset => Theme::Sunset,
        }
    }

    pub fn from_storage() -> Option<Self> {
        let window = web_sys::window()?;
        let storage = window.local_storage().ok()??;
        let preset = storage.get(STORAGE_KEY).ok()?;
        let preset = preset?;

        Some(Theme::from_preset(&preset))
    }

    pub fn save_to_storage(&self) {
        let window = match web_sys::window() {
            Some(w) => w,
            None => return,
        };
        let storage = match window.local_storage() {
            Ok(Some(s)) => s,
            _ => return,
        };

        let _ = storage.set(STORAGE_KEY, self.to_preset());
    }
}

pub(crate) fn apply_theme_class(theme: Theme) {
    let document = match web_sys::window().and_then(|w| w.document()) {
        Some(d) => d,
        None => return,
    };

    if let Some(root) = document.document_element() {
        let class = theme.class();
        root.set_class_name(class);
    }
}

/// A translated Halloy side (dark or light) mapped onto the panel's surface
/// tokens. Only surfaces, borders, text and accents are overridden: the
/// action ramp and the status colors stay static so buttons, focus rings
/// and severity cues never shift with the theme.
///
/// Contrast note: every text token resolves to the translated `text`
/// colour, which the server derives for contrast against `background`.
/// The de-emphasis hierarchy (secondary/tertiary) flattens under a Halloy
/// theme rather than risk an unreadable muted tone.
pub(crate) struct PanelPalette<'a> {
    pub background: &'a str,
    pub surface: &'a str,
    pub text: &'a str,
    pub border: &'a str,
    pub accent: &'a str,
    pub accent_primary: &'a str,
    pub accent_secondary: &'a str,
}

/// Apply (`Some`) or clear (`None`, revealing the static palette) the
/// panel's Halloy override. Applied as CSS custom properties through the
/// CSSOM, which the admin `style-src 'self'` CSP permits; `None` removes
/// each property so no stale value survives a switch back to built-in.
pub(crate) fn apply_panel_palette(palette: Option<PanelPalette<'_>>) {
    use wasm_bindgen::JsCast;
    let root = match web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.document_element())
        .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok())
    {
        Some(root) => root,
        None => return,
    };
    let style = root.style();
    match palette {
        Some(p) => {
            let _ = style.set_property("--bg-primary", p.background);
            let _ = style.set_property("--bg-secondary", p.surface);
            let _ = style.set_property("--bg-card", p.surface);
            let _ = style.set_property("--bg-tertiary", p.accent);
            let _ = style.set_property("--border-color", p.border);
            let _ = style.set_property("--text-primary", p.text);
            let _ = style.set_property("--text-secondary", p.text);
            let _ = style.set_property("--text-tertiary", p.text);
            let _ = style.set_property("--accent-primary", p.accent_primary);
            let _ = style.set_property("--accent-secondary", p.accent_secondary);
            let _ = style.set_property("--accent-glow", &glow_from_hex(p.accent_primary));
        }
        None => {
            for name in [
                "--bg-primary",
                "--bg-secondary",
                "--bg-card",
                "--bg-tertiary",
                "--border-color",
                "--text-primary",
                "--text-secondary",
                "--text-tertiary",
                "--accent-primary",
                "--accent-secondary",
                "--accent-glow",
            ] {
                let _ = style.remove_property(name);
            }
        }
    }
}

fn glow_from_hex(hex: &str) -> String {
    let hex = hex.strip_prefix('#').unwrap_or(hex);
    if hex.len() == 6 {
        if let (Ok(r), Ok(g), Ok(b)) = (
            u8::from_str_radix(&hex[0..2], 16),
            u8::from_str_radix(&hex[2..4], 16),
            u8::from_str_radix(&hex[4..6], 16),
        ) {
            return format!("rgba({r}, {g}, {b}, 0.35)");
        }
    }
    "rgba(0, 212, 170, 0.35)".to_string()
}
