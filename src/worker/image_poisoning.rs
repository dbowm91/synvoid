use super::StaticWorkerState;

use cloakrs::{process_image_bytes, ProtectionContext, ProtectionLevel};

fn parse_protection_level(level: &str) -> ProtectionLevel {
    match level.to_lowercase().as_str() {
        "disabled" => ProtectionLevel::Disabled,
        "light" => ProtectionLevel::Light,
        "standard" => ProtectionLevel::Standard,
        "enhanced" => ProtectionLevel::Enhanced,
        "strong" => ProtectionLevel::Strong,
        _ => {
            tracing::warn!(level = %level, "Unknown image poison protection level, defaulting to Standard");
            ProtectionLevel::Standard
        }
    }
}

pub(super) fn poison_image_sync(
    state: &StaticWorkerState,
    site_id: &str,
    body: Vec<u8>,
    _last_modified: Option<String>,
) -> Vec<u8> {
    if body.is_empty() {
        return body;
    }

    let (enabled, level, intensity, seed, max_dimension, jpeg_quality) = {
        let config_manager = match state.config_manager.read() {
            Ok(guard) => guard,
            Err(_) => {
                tracing::warn!("Config lock poisoned, using default image poison config");
                return body;
            }
        };
        if let Some(site_config) = config_manager.sites.get(site_id) {
            let cfg = &site_config.image_poison;
            let enabled = cfg.enabled.unwrap_or(false);
            let level = cfg
                .level
                .as_deref()
                .map(parse_protection_level)
                .unwrap_or(ProtectionLevel::Standard);
            let intensity = cfg.intensity.unwrap_or(0.5).clamp(0.0, 1.0);
            let seed = cfg.seed;
            let max_dimension = cfg.max_dimension;
            let jpeg_quality = cfg.jpeg_quality;
            (enabled, level, intensity, seed, max_dimension, jpeg_quality)
        } else {
            (false, ProtectionLevel::Standard, 0.5, None, None, None)
        }
    };

    if !enabled {
        return body;
    }

    let mut ctx = ProtectionContext::default().with_intensity(intensity);
    if let Some(seed) = seed {
        ctx = ctx.with_seed(seed);
    }
    if let Some(max_dim) = max_dimension {
        ctx = ctx.with_max_dimension(max_dim);
    }
    if let Some(quality) = jpeg_quality {
        ctx = ctx.with_jpeg_quality(quality);
    }

    match process_image_bytes(&body, level, &ctx) {
        Ok(protected) => protected,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Image poisoning failed, returning original body (fail-open)"
            );
            body
        }
    }
}
