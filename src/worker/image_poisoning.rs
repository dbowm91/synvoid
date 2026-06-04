use super::cpu_task::state::StaticWorkerState;

use stegoeggo::{ProtectionContext, ProtectionLevel, process_image_bytes};

fn parse_protection_level(level: &str) -> ProtectionLevel {
    match level.to_lowercase().as_str() {
        "disabled" => ProtectionLevel::Disabled,
        "l1" | "light" => ProtectionLevel::Light,
        "l2" | "standard" | "l3" | "enhanced" | "strong" => ProtectionLevel::Standard,
        _ => {
            tracing::warn!(level = %level, "Unknown image poison protection level, defaulting to Standard");
            ProtectionLevel::Standard
        }
    }
}

pub(in crate::worker) fn poison_image_sync(
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

    let (enabled, level) = {
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
            (enabled, level)
        } else {
            (
                false,
                level_override
                    .as_deref()
                    .map(parse_protection_level)
                    .unwrap_or(ProtectionLevel::Standard),
            )
        }
    };

    if !enabled {
        return body;
    }

    let mut ctx = ProtectionContext::default();
    if let Some(intensity) = intensity_override {
        ctx = ctx.with_intensity(intensity);
    }
    if let Some(seed) = seed_override {
        ctx = ctx.with_seed(seed);
    }
    if let Some(max_dim) = max_dimension_override {
        ctx = ctx.with_max_dimension(max_dim);
    }
    if let Some(quality) = jpeg_quality_override {
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
