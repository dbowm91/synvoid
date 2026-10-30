pub const HALLOY_NAMES: &[&str] = &[
    "Booberry",
    "Catppuccin Latte",
    "Catppuccin Macchiato",
    "Catppuccin Mocha",
    "Cyber Red",
    "Cyberpunk",
    "Dark Green",
    "Discord",
    "Discord (80_ Saturation)",
    "Dracula",
    "Ferra Light",
    "Flexor Dark",
    "Gruvbox",
    "Halcyon Dark",
    "IntelliJ Light",
    "Kanagawa",
    "Macaw Dark",
    "Macaw Light",
    "Matrix",
    "Noctis Lilac",
    "Nord",
    "Nostromo Terminal",
    "One Dark",
    "Oxocarbon",
    "Rose Pine",
    "Rose Pine Dawn",
    "Rose Pine Moon",
    "Solarized Dark",
    "Sonokai",
    "Tokyo Night Storm",
    "VESPER",
    "Zenburn",
    "acton",
    "bam",
    "base16-atelier-forest-light",
    "berlin",
    "black but with important highlights",
    "broc",
    "cork",
    "ferra",
    "forest",
    "lisbon",
    "midnight",
    "oslo",
    "plum",
    "portland",
    "sunset",
    "tofino",
    "vanimo",
    "vik",
];

pub const DEFAULT_HALLOY_THEME: &str = "Cyber Red";

pub const MAX_HALLOY_THEME_NAME_BYTES: usize = 128;

pub const PILL_MINIMUM_CONTRAST: f64 = 4.5;

const PILL_CONTRAST_MARGIN: f64 = 0.05;

#[cfg(test)]
const PILL_ROLES: [(&str, f64); 6] = [
    ("neutral", 0.00),
    ("success", 0.18),
    ("info", 0.36),
    ("warning", 0.54),
    ("sparse", 0.72),
    ("error", 0.90),
];

pub fn selected_halloy_theme(configured: &str) -> &str {
    if configured.len() <= MAX_HALLOY_THEME_NAME_BYTES && HALLOY_NAMES.contains(&configured) {
        configured
    } else {
        DEFAULT_HALLOY_THEME
    }
}

pub fn halloy_relative_luminance(color: &str) -> Option<f64> {
    let (red, green, blue) = parse_halloy_rgb(color)?;
    let channel = |value: f64| {
        if value <= 0.03928 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    };
    Some(0.2126 * channel(red) + 0.7152 * channel(green) + 0.0722 * channel(blue))
}

pub fn halloy_pill_color(base: &str, card_background: &str, ladder: f64) -> Option<String> {
    let card_luminance = halloy_relative_luminance(card_background)?;
    let floor = PILL_MINIMUM_CONTRAST + PILL_CONTRAST_MARGIN;
    let target = if card_luminance >= 0.175 {
        let edge = (card_luminance + 0.05) / floor - 0.05;
        (edge * (1.0 - ladder)).max(0.0)
    } else {
        let low = floor * (card_luminance + 0.05) - 0.05;
        (low + (1.0 - low) * ladder).min(1.0)
    };
    let base_luminance = halloy_relative_luminance(base)?;
    if target < base_luminance {
        let mut low = 0.0_f64;
        let mut high = 1.0_f64;
        for _ in 0..48 {
            let mid = (low + high) / 2.0;
            let candidate = darken_halloy_color(base, mid)?;
            if halloy_relative_luminance(&candidate)? > target {
                high = mid;
            } else {
                low = mid;
            }
        }
        darken_halloy_color(base, high)
    } else {
        let mut low = 0.0_f64;
        let mut high = 1.0_f64;
        for _ in 0..48 {
            let mid = (low + high) / 2.0;
            let candidate = lighten_halloy_color(base, mid)?;
            if halloy_relative_luminance(&candidate)? < target {
                low = mid;
            } else {
                high = mid;
            }
        }
        lighten_halloy_color(base, high)
    }
}

fn darken_halloy_color(color: &str, factor: f64) -> Option<String> {
    let (red, green, blue) = parse_halloy_rgb(color)?;
    let channel = |value: f64| (value * factor * 255.0).round().clamp(0.0, 255.0) as u8;
    Some(format!(
        "#{:02x}{:02x}{:02x}",
        channel(red),
        channel(green),
        channel(blue)
    ))
}

fn lighten_halloy_color(color: &str, amount: f64) -> Option<String> {
    let (red, green, blue) = parse_halloy_rgb(color)?;
    let channel = |value: f64| {
        (value * 255.0 + (255.0 - value * 255.0) * amount)
            .round()
            .clamp(0.0, 255.0) as u8
    };
    Some(format!(
        "#{:02x}{:02x}{:02x}",
        channel(red),
        channel(green),
        channel(blue)
    ))
}

pub fn parse_halloy_rgb(color: &str) -> Option<(f64, f64, f64)> {
    let color = color.strip_prefix('#')?;
    if !color.is_ascii() {
        return None;
    }
    let color = if color.len() == 8 {
        color.get(..6)?
    } else if color.len() == 6 {
        color
    } else {
        return None;
    };
    Some((
        u8::from_str_radix(color.get(0..2)?, 16).ok()? as f64 / 255.0,
        u8::from_str_radix(color.get(2..4)?, 16).ok()? as f64 / 255.0,
        u8::from_str_radix(color.get(4..6)?, 16).ok()? as f64 / 255.0,
    ))
}

pub fn halloy_lightness(color: &str) -> Option<f64> {
    let (red, green, blue) = parse_halloy_rgb(color)?;
    Some((red.max(green).max(blue) + red.min(green).min(blue)) / 2.0)
}

pub fn mix_halloy_colors(base: &str, target: &str, ratio: f64) -> Option<String> {
    let channels = |color: &str| -> Option<(i32, i32, i32)> {
        let color = color.strip_prefix('#')?;
        if !color.is_ascii() {
            return None;
        }
        let color = if color.len() == 8 {
            color.get(..6)?
        } else {
            color
        };
        if color.len() != 6 {
            return None;
        }
        Some((
            i32::from_str_radix(color.get(0..2)?, 16).ok()?,
            i32::from_str_radix(color.get(2..4)?, 16).ok()?,
            i32::from_str_radix(color.get(4..6)?, 16).ok()?,
        ))
    };
    let (base_red, base_green, base_blue) = channels(base)?;
    let (target_red, target_green, target_blue) = channels(target)?;
    let channel = |base: i32, target: i32| (base as f64 + (target - base) as f64 * ratio) as u8;
    Some(format!(
        "#{:02x}{:02x}{:02x}",
        channel(base_red, target_red),
        channel(base_green, target_green),
        channel(base_blue, target_blue),
    ))
}

pub fn adjust_halloy_lightness(color: &str, factor: f64) -> Option<String> {
    let (red, green, blue) = parse_halloy_rgb(color)?;
    let max = red.max(green).max(blue);
    let min = red.min(green).min(blue);
    let lightness = (max + min) / 2.0;
    let delta = max - min;
    if delta == 0.0 {
        let channel = (lightness * factor).clamp(0.0, 1.0);
        return Some(format!(
            "#{:02x}{:02x}{:02x}",
            (channel * 255.0) as u8,
            (channel * 255.0) as u8,
            (channel * 255.0) as u8,
        ));
    }

    let saturation = if lightness <= 0.5 {
        delta / (max + min)
    } else {
        delta / (2.0 - max - min)
    };
    let hue = if max == red {
        ((green - blue) / delta + if green < blue { 6.0 } else { 0.0 }) / 6.0
    } else if max == green {
        ((blue - red) / delta + 2.0) / 6.0
    } else {
        ((red - green) / delta + 4.0) / 6.0
    };
    let lightness = (lightness * factor).clamp(0.0, 1.0);
    let q = if lightness < 0.5 {
        lightness * (1.0 + saturation)
    } else {
        lightness + saturation - lightness * saturation
    };
    let p = 2.0 * lightness - q;
    let hue_to_rgb = |mut hue: f64| {
        if hue < 0.0 {
            hue += 1.0;
        } else if hue > 1.0 {
            hue -= 1.0;
        }
        if hue < 1.0 / 6.0 {
            p + (q - p) * 6.0 * hue
        } else if hue < 0.5 {
            q
        } else if hue < 2.0 / 3.0 {
            p + (q - p) * (2.0 / 3.0 - hue) * 6.0
        } else {
            p
        }
    };
    Some(format!(
        "#{:02x}{:02x}{:02x}",
        (hue_to_rgb(hue + 1.0 / 3.0) * 255.0) as u8,
        (hue_to_rgb(hue) * 255.0) as u8,
        (hue_to_rgb(hue - 1.0 / 3.0) * 255.0) as u8,
    ))
}

pub fn halloy_bytes(name: &str) -> Option<&'static [u8]> {
    Some(match name {
        "Booberry" => include_bytes!("../themes/Booberry.toml"),
        "Catppuccin Latte" => include_bytes!("../themes/Catppuccin Latte.toml"),
        "Catppuccin Macchiato" => include_bytes!("../themes/Catppuccin Macchiato.toml"),
        "Catppuccin Mocha" => include_bytes!("../themes/Catppuccin Mocha.toml"),
        "Cyber Red" => include_bytes!("../themes/Cyber Red.toml"),
        "Cyberpunk" => include_bytes!("../themes/Cyberpunk.toml"),
        "Dark Green" => include_bytes!("../themes/Dark Green.toml"),
        "Discord (80_ Saturation)" => {
            include_bytes!("../themes/Discord (80_ Saturation).toml")
        }
        "Discord" => include_bytes!("../themes/Discord.toml"),
        "Dracula" => include_bytes!("../themes/Dracula.toml"),
        "Ferra Light" => include_bytes!("../themes/Ferra Light.toml"),
        "Flexor Dark" => include_bytes!("../themes/Flexor Dark.toml"),
        "Gruvbox" => include_bytes!("../themes/Gruvbox.toml"),
        "Halcyon Dark" => include_bytes!("../themes/Halcyon Dark.toml"),
        "IntelliJ Light" => include_bytes!("../themes/IntelliJ Light.toml"),
        "Kanagawa" => include_bytes!("../themes/Kanagawa.toml"),
        "Macaw Dark" => include_bytes!("../themes/Macaw Dark.toml"),
        "Macaw Light" => include_bytes!("../themes/Macaw Light.toml"),
        "Matrix" => include_bytes!("../themes/Matrix.toml"),
        "Noctis Lilac" => include_bytes!("../themes/Noctis Lilac.toml"),
        "Nord" => include_bytes!("../themes/Nord.toml"),
        "Nostromo Terminal" => include_bytes!("../themes/Nostromo Terminal.toml"),
        "One Dark" => include_bytes!("../themes/One Dark.toml"),
        "Oxocarbon" => include_bytes!("../themes/Oxocarbon.toml"),
        "Rose Pine Dawn" => include_bytes!("../themes/Rose Pine Dawn.toml"),
        "Rose Pine Moon" => include_bytes!("../themes/Rose Pine Moon.toml"),
        "Rose Pine" => include_bytes!("../themes/Rose Pine.toml"),
        "Solarized Dark" => include_bytes!("../themes/Solarized Dark.toml"),
        "Sonokai" => include_bytes!("../themes/Sonokai.toml"),
        "Tokyo Night Storm" => include_bytes!("../themes/Tokyo Night Storm.toml"),
        "VESPER" => include_bytes!("../themes/VESPER.toml"),
        "Zenburn" => include_bytes!("../themes/Zenburn.toml"),
        "acton" => include_bytes!("../themes/acton.toml"),
        "bam" => include_bytes!("../themes/bam.toml"),
        "base16-atelier-forest-light" => {
            include_bytes!("../themes/base16-atelier-forest-light.toml")
        }
        "berlin" => include_bytes!("../themes/berlin.toml"),
        "black but with important highlights" => {
            include_bytes!("../themes/black but with important highlights.toml")
        }
        "broc" => include_bytes!("../themes/broc.toml"),
        "cork" => include_bytes!("../themes/cork.toml"),
        "ferra" => include_bytes!("../themes/ferra.toml"),
        "forest" => include_bytes!("../themes/forest.toml"),
        "lisbon" => include_bytes!("../themes/lisbon.toml"),
        "midnight" => include_bytes!("../themes/midnight.toml"),
        "oslo" => include_bytes!("../themes/oslo.toml"),
        "plum" => include_bytes!("../themes/plum.toml"),
        "portland" => include_bytes!("../themes/portland.toml"),
        "sunset" => include_bytes!("../themes/sunset.toml"),
        "tofino" => include_bytes!("../themes/tofino.toml"),
        "vanimo" => include_bytes!("../themes/vanimo.toml"),
        "vik" => include_bytes!("../themes/vik.toml"),
        _ => return None,
    })
}

pub fn halloy_value<'a>(value: &'a toml::Value, path: &[&str], fallback: &'a str) -> &'a str {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
        .and_then(toml::Value::as_str)
        .unwrap_or(fallback)
}

pub fn opaque_hex(color: &str) -> String {
    let trimmed = color.strip_prefix('#').unwrap_or(color);
    if trimmed.len() == 8 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        color
            .get(..7)
            .map(str::to_owned)
            .unwrap_or_else(|| color.to_owned())
    } else {
        color.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn halloy_document(name: &str) -> toml::Value {
        let bytes = halloy_bytes(name).expect("bundled theme bytes");
        std::str::from_utf8(bytes)
            .expect("bundled theme utf8")
            .parse::<toml::Value>()
            .expect("bundled theme toml")
    }

    fn served_page_background(document: &toml::Value) -> String {
        let general_background = halloy_value(document, &["general", "background"], "#1e1e2e");
        opaque_hex(
            if halloy_lightness(general_background).unwrap_or(0.0) < 0.5 {
                halloy_value(document, &["buffer", "background"], general_background)
            } else {
                general_background
            },
        )
    }

    fn served_card_background(document: &toml::Value) -> String {
        opaque_hex(halloy_value(document, &["buffer", "background"], "#1e1e2e"))
    }

    fn served_text_bases(document: &toml::Value) -> [String; 2] {
        [
            halloy_value(document, &["text", "primary"], "#cdd6f4").to_owned(),
            halloy_value(document, &["text", "secondary"], "#a6adc8").to_owned(),
        ]
    }

    fn served_pill_bases(document: &toml::Value) -> [String; 6] {
        let text_primary = halloy_value(document, &["text", "primary"], "#cdd6f4");
        let text_secondary = halloy_value(document, &["text", "secondary"], "#a6adc8");
        let text_success = halloy_value(document, &["text", "success"], "#a6e3a1");
        let text_error = halloy_value(document, &["text", "error"], "#f38ba8");
        let info = halloy_value(document, &["buffer", "url"], "#89b4fa");
        let warning = halloy_value(document, &["buffer", "action"], "#fab387");
        let muted = {
            let topic = halloy_value(document, &["buffer", "topic"], "#7f849c");
            if topic == text_primary {
                text_secondary.to_owned()
            } else {
                topic.to_owned()
            }
        };
        let sparse =
            mix_halloy_colors(warning, text_error, 0.5).unwrap_or_else(|| warning.to_owned());
        [
            muted,
            text_success.to_owned(),
            info.to_owned(),
            warning.to_owned(),
            sparse,
            text_error.to_owned(),
        ]
    }

    fn served_foregrounds(document: &toml::Value) -> Vec<(String, String, String)> {
        let page_background = served_page_background(document);
        let card_background = served_card_background(document);
        let text_bases = served_text_bases(document);
        let mut foregrounds = vec![
            (
                "--waf-text".to_owned(),
                halloy_pill_color(&text_bases[0], &page_background, 0.36)
                    .expect("served text foreground derives"),
                page_background.clone(),
            ),
            (
                "--waf-text-muted".to_owned(),
                halloy_pill_color(&text_bases[1], &page_background, 0.00)
                    .expect("served muted text foreground derives"),
                page_background.clone(),
            ),
        ];
        foregrounds.extend(
            PILL_ROLES
                .iter()
                .zip(served_pill_bases(document).iter())
                .map(|((role, ladder), base)| {
                    let derived = halloy_pill_color(base, &card_background, *ladder)
                        .expect("served pill foreground derives");
                    (
                        format!("--waf-pill-{role}"),
                        derived,
                        card_background.clone(),
                    )
                }),
        );
        foregrounds
    }

    fn halloy_contrast_ratio(first: &str, second: &str) -> Option<f64> {
        let first = halloy_relative_luminance(first)?;
        let second = halloy_relative_luminance(second)?;
        let (high, low) = if first > second {
            (first, second)
        } else {
            (second, first)
        };
        Some((high + 0.05) / (low + 0.05))
    }

    fn contrast_violations(name: &str) -> Vec<String> {
        let document = halloy_document(name);
        foreground_violations(&served_foregrounds(&document))
    }

    fn foreground_violations(foregrounds: &[(String, String, String)]) -> Vec<String> {
        let mut violations = Vec::new();
        for (usage, foreground, background) in foregrounds {
            match halloy_contrast_ratio(foreground, background) {
                Some(ratio) if ratio >= PILL_MINIMUM_CONTRAST => {}
                Some(ratio) => violations.push(format!(
                    "{usage} {foreground} on {background} is {ratio:.2}:1"
                )),
                None => violations.push(format!("{usage} is not a colour")),
            }
        }
        violations
    }

    fn pill_color_distance(first: &str, second: &str) -> Option<f64> {
        let (first, second) = (parse_halloy_rgb(first)?, parse_halloy_rgb(second)?);
        let distance = (first.0 - second.0).powi(2)
            + (first.1 - second.1).powi(2)
            + (first.2 - second.2).powi(2);
        Some(distance.sqrt() * 255.0)
    }

    const PILL_MINIMUM_DISTANCE: f64 = 12.0;

    fn distinguishability_violations(name: &str) -> Vec<String> {
        let document = halloy_document(name);
        pill_violations(&served_pill_colors(&document))
    }

    fn served_pill_colors(document: &toml::Value) -> Vec<(String, String)> {
        let card_background = served_card_background(document);
        PILL_ROLES
            .iter()
            .zip(served_pill_bases(document).iter())
            .map(|((role, ladder), base)| {
                let derived = halloy_pill_color(base, &card_background, *ladder)
                    .expect("served pill foreground derives");
                (format!("--waf-pill-{role}"), derived)
            })
            .collect()
    }

    fn pill_violations(colors: &[(String, String)]) -> Vec<String> {
        let mut violations = Vec::new();
        for (index, (first_name, first)) in colors.iter().enumerate() {
            for (second_name, second) in colors.iter().skip(index + 1) {
                match pill_color_distance(first, second) {
                    Some(distance) if distance >= PILL_MINIMUM_DISTANCE => {}
                    Some(distance) => violations.push(format!(
                        "{first_name} {first} and {second_name} {second} are {distance:.1} apart"
                    )),
                    None => {
                        violations.push(format!("{first_name} or {second_name} is not a colour"))
                    }
                }
            }
        }
        violations
    }

    #[test]
    fn registry_lists_fifty_themes_without_a_default_entry() {
        assert_eq!(HALLOY_NAMES.len(), 50);
        assert!(!HALLOY_NAMES.contains(&"default"));
        assert!(HALLOY_NAMES.contains(&DEFAULT_HALLOY_THEME));
    }

    #[test]
    fn selection_falls_back_to_the_default_theme() {
        assert_eq!(selected_halloy_theme("Nord"), "Nord");
        assert_eq!(selected_halloy_theme("missing"), DEFAULT_HALLOY_THEME);
        assert_eq!(selected_halloy_theme(""), DEFAULT_HALLOY_THEME);
        assert_eq!(
            selected_halloy_theme(&"x".repeat(MAX_HALLOY_THEME_NAME_BYTES + 1)),
            DEFAULT_HALLOY_THEME
        );
    }

    #[test]
    fn every_bundled_theme_resolves_to_parseable_toml() {
        for name in HALLOY_NAMES {
            halloy_document(name);
        }
        assert_eq!(halloy_bytes("missing"), None);
    }

    #[test]
    fn lookup_returns_the_fallback_for_missing_or_untyped_paths() {
        let document = halloy_document(DEFAULT_HALLOY_THEME);
        assert_eq!(
            halloy_value(&document, &["text", "primary"], "fallback"),
            halloy_value(&document, &["text", "primary"], "fallback")
        );
        assert_ne!(
            halloy_value(&document, &["text", "primary"], "fallback"),
            "fallback"
        );
        assert_eq!(
            halloy_value(&document, &["text", "absent"], "fallback"),
            "fallback"
        );
        assert_eq!(halloy_value(&document, &["text"], "fallback"), "fallback");
    }

    #[test]
    fn opaque_hex_strips_only_an_alpha_channel() {
        assert_eq!(opaque_hex("#27273DE2"), "#27273D");
        assert_eq!(opaque_hex("#cdd6f4"), "#cdd6f4");
        assert_eq!(opaque_hex("not-a-colour"), "not-a-colour");
        assert_eq!(opaque_hex(""), "");
    }

    #[test]
    fn every_bundled_theme_carries_the_schema_subset_the_renderer_consumes() {
        let paths: [&[&str]; 12] = [
            &["general", "background"],
            &["text", "primary"],
            &["text", "secondary"],
            &["text", "success"],
            &["text", "error"],
            &["buffer", "background"],
            &["buffer", "url"],
            &["buffer", "action"],
            &["buffer", "topic"],
            &["buffer", "selection"],
            &["buttons", "primary", "background"],
            &["buttons", "secondary", "background"],
        ];
        for name in HALLOY_NAMES {
            let document = halloy_document(name);
            for path in paths {
                assert_ne!(
                    halloy_value(&document, path, ""),
                    "",
                    "theme {name:?} is missing {}",
                    path.join(".")
                );
            }
        }
    }

    #[test]
    fn every_bundled_theme_serves_contrast_safe_foregrounds() {
        for name in HALLOY_NAMES {
            assert_eq!(
                contrast_violations(name),
                Vec::<String>::new(),
                "theme {name:?} serves a foreground that misses the contrast floor"
            );
        }
    }

    #[test]
    fn every_bundled_theme_keeps_its_pill_roles_distinguishable() {
        for name in HALLOY_NAMES {
            assert_eq!(
                distinguishability_violations(name),
                Vec::<String>::new(),
                "theme {name:?} collapses two pill roles onto one colour"
            );
        }
    }

    #[test]
    fn the_contrast_guard_rejects_a_deliberate_regression() {
        let name = DEFAULT_HALLOY_THEME;
        assert_eq!(contrast_violations(name), Vec::<String>::new());
        let document = halloy_document(name);
        let card_background = served_card_background(&document);
        let regressed = served_foregrounds(&document)
            .into_iter()
            .map(|(usage, _, background)| (usage, card_background.clone(), background))
            .collect::<Vec<_>>();
        assert!(
            !foreground_violations(&regressed).is_empty(),
            "the guard accepted foregrounds that match the card background"
        );
    }

    #[test]
    fn the_distinguishability_guard_rejects_a_collapsed_role() {
        let document = halloy_document(DEFAULT_HALLOY_THEME);
        let mut collapsed = served_pill_colors(&document);
        let warning = collapsed[1].1.clone();
        collapsed[3].1 = warning;
        assert!(
            !pill_violations(&collapsed).is_empty(),
            "the guard accepted two pill roles that render the same colour"
        );
    }

    #[test]
    fn the_served_foregrounds_are_derived_from_the_theme_not_from_a_fixed_table() {
        let light = halloy_document("Catppuccin Latte");
        let dark = halloy_document("Nord");
        let light_card = served_card_background(&light);
        let dark_card = served_card_background(&dark);
        let light_bases = served_pill_bases(&light);
        let dark_bases = served_pill_bases(&dark);
        assert_ne!(
            halloy_pill_color(&light_bases[1], &light_card, 0.18),
            halloy_pill_color(&dark_bases[1], &dark_card, 0.18)
        );
    }
}
