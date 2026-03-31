use crate::config::logging::LoggingConfig;
use crate::log_controller;

pub fn init_logging(config: &LoggingConfig, log_level_override: Option<String>) {
    let level = log_level_override.unwrap_or_else(|| config.level.clone());
    log_controller::init_logging_with_dynamic_level(&level);
}

pub fn init_logging_simple() {
    log_controller::init_logging_with_dynamic_level("info");
}

pub fn print_test_mode_warning(test_flags: &[String]) {
    let mut disabled = Vec::new();

    for flag in test_flags {
        match flag.as_str() {
            "challenge-off" | "challenge_off" => disabled.push("challenge"),
            "ratelimit-off" | "ratelimit_off" => disabled.push("ratelimit"),
            "attack-off" | "attack_off" => disabled.push("attack"),
            "bot-off" | "bot_off" => disabled.push("bot"),
            "flood-off" | "flood_off" => disabled.push("flood"),
            "all-off" | "all_off" => {
                disabled.clear();
                disabled.push("ALL");
                break;
            }
            _ => {}
        }
    }

    if disabled.is_empty() {
        disabled.push("ALL");
    }

    let is_all_disabled = disabled.iter().any(|s| s.to_lowercase() == "all");
    let disabled_str = if is_all_disabled {
        "ALL".to_string()
    } else {
        disabled.join(", ")
    };

    tracing::warn!("TEST MODE ENABLED - Protections DISABLED: {}", disabled_str);
    tracing::warn!(
        "This mode is intended for throughput/capacity testing only. DO NOT use in production."
    );
}
