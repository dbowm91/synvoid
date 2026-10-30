use crate::config::site::SiteAttackDetectionConfig;
use crate::waf::attack_detection::{AttackDetectionConfig, AttackType};

pub fn effective_flag(site: Option<bool>, global: bool) -> bool {
    site.unwrap_or(global)
}

pub fn attack_globally_disabled(
    site: Option<&SiteAttackDetectionConfig>,
    global: &AttackDetectionConfig,
) -> bool {
    !effective_flag(site.and_then(|s| s.enabled), global.enabled)
}

pub fn attack_type_enabled(
    site: Option<&SiteAttackDetectionConfig>,
    global: &AttackDetectionConfig,
    attack_type: AttackType,
) -> bool {
    match attack_type {
        AttackType::Sqli => effective_flag(site.and_then(|s| s.sqli.enabled), global.sqli.enabled),
        AttackType::Xss => effective_flag(site.and_then(|s| s.xss.enabled), global.xss.enabled),
        AttackType::PathTraversal => effective_flag(
            site.and_then(|s| s.path_traversal.enabled),
            global.path_traversal.enabled,
        ),
        AttackType::Rfi => effective_flag(site.and_then(|s| s.rfi.enabled), global.rfi.enabled),
        AttackType::Ssrf => effective_flag(site.and_then(|s| s.ssrf.enabled), global.ssrf.enabled),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site_with_rfi_disabled() -> SiteAttackDetectionConfig {
        SiteAttackDetectionConfig {
            enabled: None,
            paranoia_level: None,
            action: None,
            sqli: Default::default(),
            xss: Default::default(),
            path_traversal: Default::default(),
            rfi: crate::config::site::SiteRfiConfig {
                enabled: Some(false),
                custom_patterns: Vec::new(),
            },
            ssrf: Default::default(),
        }
    }

    #[test]
    fn site_false_beats_global_true() {
        let site = site_with_rfi_disabled();
        let global = AttackDetectionConfig::default();
        assert!(global.rfi.enabled);
        assert!(!attack_type_enabled(Some(&site), &global, AttackType::Rfi));
    }

    #[test]
    fn absent_site_key_inherits_global() {
        let site = SiteAttackDetectionConfig::default();
        let global = AttackDetectionConfig::default();
        assert!(attack_type_enabled(Some(&site), &global, AttackType::Rfi));
        assert!(attack_type_enabled(None, &global, AttackType::Rfi));
        assert!(!attack_globally_disabled(Some(&site), &global));
    }

    #[test]
    fn site_top_level_disable_suppresses_all() {
        let mut site = SiteAttackDetectionConfig::default();
        site.enabled = Some(false);
        let global = AttackDetectionConfig::default();
        assert!(attack_globally_disabled(Some(&site), &global));
    }

    #[test]
    fn detectors_without_site_subtable_inherit_global() {
        let site = site_with_rfi_disabled();
        let global = AttackDetectionConfig::default();
        assert!(attack_type_enabled(Some(&site), &global, AttackType::Ssti));
    }
}
