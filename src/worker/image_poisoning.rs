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
    level_override: Option<String>,
    intensity_override: Option<f32>,
    seed_override: Option<u64>,
    max_dimension_override: Option<u32>,
    jpeg_quality_override: Option<u8>,
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
            let level = level_override
                .as_deref()
                .map(parse_protection_level)
                .unwrap_or_else(|| {
                    cfg.level
                        .as_deref()
                        .map(parse_protection_level)
                        .unwrap_or(ProtectionLevel::Standard)
                });
            let intensity = intensity_override
                .unwrap_or(cfg.intensity.unwrap_or(0.5))
                .clamp(0.0, 1.0);
            let seed = seed_override.or(cfg.seed);
            let max_dimension = max_dimension_override.or(cfg.max_dimension);
            let jpeg_quality = jpeg_quality_override.or(cfg.jpeg_quality);
            (enabled, level, intensity, seed, max_dimension, jpeg_quality)
        } else {
            (
                false,
                level_override
                    .as_deref()
                    .map(parse_protection_level)
                    .unwrap_or(ProtectionLevel::Standard),
                intensity_override.unwrap_or(0.5).clamp(0.0, 1.0),
                seed_override,
                max_dimension_override,
                jpeg_quality_override,
            )
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
