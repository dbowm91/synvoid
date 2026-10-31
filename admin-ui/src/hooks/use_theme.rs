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
