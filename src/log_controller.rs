use once_cell::sync::Lazy;
use parking_lot::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub static LOG_LEVEL: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new("info".to_string()));

pub fn init_logging_with_dynamic_level(level: &str) {
    *LOG_LEVEL.write() = level.to_string();

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

pub fn get_log_level() -> String {
    LOG_LEVEL.read().clone()
}

pub fn set_log_level(level: &str) -> Result<String, String> {
    let valid_levels = ["trace", "debug", "info", "warn", "error"];
    let level_lower = level.to_lowercase();

    if !valid_levels.contains(&level_lower.as_str()) {
        return Err(format!(
            "Invalid log level: {}. Valid levels: {:?}",
            level, valid_levels
        ));
    }

    *LOG_LEVEL.write() = level_lower.clone();
    tracing::info!("Log level changed to {}", level_lower);
    Ok(level_lower)
}
