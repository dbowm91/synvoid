use yew::prelude::*;
use crate::types::{ThemeResponse, UpdateThemeRequest};

const STORAGE_KEY: &str = "maluwaf-theme";

#[derive(Clone, Copy, PartialEq)]
pub enum Theme {
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

impl Default for Theme {
    fn default() -> Self {
        Theme::Dark
    }
}

fn apply_theme_class(theme: Theme) {
    let document = match web_sys::window().and_then(|w| w.document()) {
        Some(d) => d,
        None => return,
    };
    
    if let Some(root) = document.document_element() {
        let class = theme.class();
        let _ = root.set_class_name(class);
    }
}

#[hook]
pub fn use_api_theme() -> (Option<ThemeResponse>, Callback<UpdateThemeRequest>) {
    let theme_data = use_state(|| None::<ThemeResponse>);
    let theme = use_state(|| {
        Theme::from_storage().unwrap_or_default()
    });
    
    let initial_theme = (*theme).clone();
    
    apply_theme_class(initial_theme);
    
    let theme_data_clone = theme_data.clone();
    let theme_clone = theme.clone();
    
    use_effect_with((), move |_| {
        wasm_bindgen_futures::spawn_local(async move {
            let api = crate::services::ApiService::new();
            match api.get_theme().await {
                Ok(data) => {
                    let theme_enum = Theme::from_preset(&data.preset);
                    theme_clone.set(theme_enum);
                    apply_theme_class(theme_enum);
                    theme_data_clone.set(Some(data));
                }
                Err(e) => {
                    tracing::error!("Failed to fetch theme: {}", e);
                }
            }
        });
        || {}
    });

    let update_callback = {
        let theme_data = theme_data.clone();
        let theme = theme.clone();
        Callback::from(move |request: UpdateThemeRequest| {
            let theme_data = theme_data.clone();
            let theme = theme.clone();
            
            if let Some(preset) = &request.preset {
                let theme_enum = Theme::from_preset(preset);
                theme_enum.save_to_storage();
                apply_theme_class(theme_enum);
            }
            
            wasm_bindgen_futures::spawn_local(async move {
                let api = crate::services::ApiService::new();
                match api.update_theme(&request).await {
                    Ok(data) => {
                        let theme_enum = Theme::from_preset(&data.preset);
                        theme.set(theme_enum);
                        apply_theme_class(theme_enum);
                        theme_enum.save_to_storage();
                        theme_data.set(Some(data));
                    }
                    Err(e) => {
                        tracing::error!("Failed to update theme: {}", e);
                    }
                }
            });
        })
    };

    ((*theme_data).clone(), update_callback)
}
