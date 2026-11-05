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

/// Detectors the site turned off while the global config leaves on, written
/// into `buf` (capacity 5: the detectors with site subtables) and returned as
/// a slice. Only the five site-able types are ever emitted; the detector
/// dispatch ignores anything else.
pub fn site_disabled_list<'b>(
    site: Option<&SiteAttackDetectionConfig>,
    global: &AttackDetectionConfig,
    buf: &'b mut [AttackType; 5],
) -> &'b [AttackType] {
    let mut n = 0;
    if let Some(site) = site {
        let mut consider = |site_flag: Option<bool>, global_flag: bool, attack_type: AttackType| {
            if global_flag && site_flag.is_some_and(|v| !v) {
                buf[n] = attack_type;
                n += 1;
            }
        };
        consider(site.sqli.enabled, global.sqli.enabled, AttackType::Sqli);
        consider(site.xss.enabled, global.xss.enabled, AttackType::Xss);
        consider(
            site.path_traversal.enabled,
            global.path_traversal.enabled,
            AttackType::PathTraversal,
        );
        consider(site.rfi.enabled, global.rfi.enabled, AttackType::Rfi);
        consider(site.ssrf.enabled, global.ssrf.enabled, AttackType::Ssrf);
    }
    &buf[..n]
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

pub fn attack_log_only_for_path(
    path: &str,
    site: Option<&SiteAttackDetectionConfig>,
) -> bool {
    let site = match site {
        Some(site) => site,
        None => return false,
    };
    let mut best_action: Option<&str> = None;
    let mut best_len = 0;
    for rule in &site.per_path {
        let prefix = rule.path_prefix.as_str();
        let matches = path == prefix
            || (path.starts_with(prefix)
                && (prefix.ends_with('/') || path.as_bytes().get(prefix.len()) == Some(&b'/')));
        if matches && prefix.len() >= best_len {
            best_len = prefix.len();
            best_action = rule.action.as_deref();
        }
    }
    matches!(best_action, Some("log"))
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
            per_path: Vec::new(),
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

    #[test]
    fn disabled_list_contains_only_site_turned_off_detectors() {
        let site = site_with_rfi_disabled();
        let global = AttackDetectionConfig::default();
        let mut buf = [AttackType::Sqli; 5];
        let list = site_disabled_list(Some(&site), &global, &mut buf);
        assert_eq!(list, &[AttackType::Rfi]);

        let mut buf_none = [AttackType::Sqli; 5];
        assert!(site_disabled_list(None, &global, &mut buf_none).is_empty());

        let mut buf_default = [AttackType::Sqli; 5];
        let default_site = SiteAttackDetectionConfig::default();
        assert!(site_disabled_list(Some(&default_site), &global, &mut buf_default).is_empty());
    }

    fn site_with_per_path(rules: &[(&str, &str)]) -> SiteAttackDetectionConfig {
        use crate::config::site::SiteAttackPathRule;

        let mut site = SiteAttackDetectionConfig::default();
        site.per_path = rules
            .iter()
            .map(|(prefix, action)| SiteAttackPathRule {
                path_prefix: (*prefix).to_string(),
                action: Some((*action).to_string()),
            })
            .collect();
        site
    }

    #[test]
    fn per_path_defaults_to_block() {
        let site = SiteAttackDetectionConfig::default();
        assert!(!attack_log_only_for_path("/admin/new", Some(&site)));
        assert!(!attack_log_only_for_path("/admin/new", None));
    }

    #[test]
    fn per_path_prefix_match_is_segment_aware() {
        let site = site_with_per_path(&[("/admin/", "log")]);
        let site = Some(&site);
        assert!(attack_log_only_for_path("/admin/", site));
        assert!(attack_log_only_for_path("/admin/new", site));
        assert!(attack_log_only_for_path("/admin/posts/1", site));
        assert!(!attack_log_only_for_path("/administrator", site));
        assert!(!attack_log_only_for_path("/public", site));

        let bare = site_with_per_path(&[("/admin", "log")]);
        let bare = Some(&bare);
        assert!(attack_log_only_for_path("/admin", bare));
        assert!(attack_log_only_for_path("/admin/new", bare));
        assert!(!attack_log_only_for_path("/administrator", bare));
    }

    #[test]
    fn per_path_longest_prefix_wins() {
        let site = site_with_per_path(&[("/admin/", "log"), ("/admin/login", "block")]);
        let site = Some(&site);
        assert!(attack_log_only_for_path("/admin/new", site));
        assert!(!attack_log_only_for_path("/admin/login", site));
    }
}
