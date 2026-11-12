use crate::config::site::{SiteAttackDetectionConfig, SiteHeaderScanConfig};
use crate::waf::attack_detection::{AttackDetectionConfig, AttackType};

use std::borrow::Cow;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Resolved action for a detected attack.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AttackAction {
    #[default]
    Block,
    Stall,
    Log,
}

impl AttackAction {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "block" => Some(Self::Block),
            "stall" => Some(Self::Stall),
            "log" => Some(Self::Log),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Stall => "stall",
            Self::Log => "log",
        }
    }
}

/// One resolved attack policy: site value > global value > built-in default.
///
/// `detector_config` borrows the global config on the no-override path, so the
/// common case keeps using the single global detector. A site that changes
/// detector construction inputs gets an owned merged config and a per-policy
/// fingerprint for the bounded detector cache.
pub struct ResolvedAttackPolicy<'a> {
    pub enabled: bool,
    pub action: AttackAction,
    pub detector_config: Cow<'a, AttackDetectionConfig>,
    pub log_only: bool,
    /// `None` means use the global detector; `Some` keys the site detector
    /// cache and includes the configuration generation.
    pub fingerprint: Option<u64>,
}

impl ResolvedAttackPolicy<'_> {
    /// Log-only includes both the explicit `log` action and the higher-priority
    /// per-path `log` rule.
    pub fn is_log(&self) -> bool {
        self.action == AttackAction::Log || self.log_only
    }

    pub fn uses_global_detector(&self) -> bool {
        self.fingerprint.is_none()
    }
}

pub fn resolve_attack_policy<'a>(
    site: Option<&SiteAttackDetectionConfig>,
    global: &'a AttackDetectionConfig,
    path: &str,
    config_generation: u64,
) -> ResolvedAttackPolicy<'a> {
    let enabled = effective_flag(site.and_then(|s| s.enabled), global.enabled);
    let action = resolve_action(site, global);
    let log_only = attack_log_only_for_path(path, site) || action == AttackAction::Log;

    if !has_detector_overrides(site, global) {
        return ResolvedAttackPolicy {
            enabled,
            action,
            detector_config: Cow::Borrowed(global),
            log_only,
            fingerprint: None,
        };
    }

    let detector_config = merge_detector_config(global, site);
    let fingerprint = policy_fingerprint(site, config_generation);
    ResolvedAttackPolicy {
        enabled,
        action,
        detector_config: Cow::Owned(detector_config),
        log_only,
        fingerprint: Some(fingerprint),
    }
}

fn resolve_action(
    site: Option<&SiteAttackDetectionConfig>,
    global: &AttackDetectionConfig,
) -> AttackAction {
    site.and_then(|s| s.action.as_deref())
        .and_then(AttackAction::parse)
        .or_else(|| AttackAction::parse(&global.action))
        .unwrap_or_default()
}

fn has_detector_overrides(
    site: Option<&SiteAttackDetectionConfig>,
    global: &AttackDetectionConfig,
) -> bool {
    let Some(site) = site else {
        return false;
    };

    site.paranoia_level
        .is_some_and(|level| level != global.paranoia_level)
        || !site.sqli.custom_patterns.is_empty()
        || !site.xss.custom_patterns.is_empty()
        || !site.path_traversal.custom_patterns.is_empty()
        || !site.rfi.custom_patterns.is_empty()
        || !site.ssrf.custom_patterns.is_empty()
        || site
            .ssrf
            .block_private_ips
            .is_some_and(|value| value != global.ssrf.block_private_ips)
        || !site.ssrf.allowed_domains.is_empty()
        || site
            .ssrf
            .allowlist_only_mode
            .is_some_and(|value| value != global.ssrf.allowlist_only_mode)
        || !site.headers.scan.is_empty()
        || !site.headers.skip.is_empty()
}

fn merge_detector_config(
    global: &AttackDetectionConfig,
    site: Option<&SiteAttackDetectionConfig>,
) -> AttackDetectionConfig {
    let mut merged = global.clone();
    let Some(site) = site else {
        return merged;
    };

    if let Some(level) = site.paranoia_level {
        merged.paranoia_level = level;
    }

    append_unique(&mut merged.sqli.custom_patterns, &site.sqli.custom_patterns);
    append_unique(&mut merged.xss.custom_patterns, &site.xss.custom_patterns);
    append_unique(
        &mut merged.path_traversal.custom_patterns,
        &site.path_traversal.custom_patterns,
    );
    append_unique(&mut merged.rfi.custom_patterns, &site.rfi.custom_patterns);
    append_unique(&mut merged.ssrf.custom_patterns, &site.ssrf.custom_patterns);

    if let Some(block_private_ips) = site.ssrf.block_private_ips {
        merged.ssrf.block_private_ips = block_private_ips;
    }
    append_unique(&mut merged.ssrf.allowed_domains, &site.ssrf.allowed_domains);
    if let Some(allowlist_only_mode) = site.ssrf.allowlist_only_mode {
        merged.ssrf.allowlist_only_mode = allowlist_only_mode;
    }

    let SiteHeaderScanConfig { scan, skip } = &site.headers;
    append_unique(&mut merged.header_scan.scan, scan);
    append_unique(&mut merged.header_scan.skip, skip);

    merged
}

fn append_unique(target: &mut Vec<String>, values: &[String]) {
    for value in values {
        if !target.iter().any(|existing| existing == value) {
            target.push(value.clone());
        }
    }
}

fn policy_fingerprint(site: Option<&SiteAttackDetectionConfig>, config_generation: u64) -> u64 {
    let mut hasher = DefaultHasher::new();
    config_generation.hash(&mut hasher);

    if let Some(site) = site {
        site.paranoia_level.hash(&mut hasher);
        site.sqli.custom_patterns.hash(&mut hasher);
        site.xss.custom_patterns.hash(&mut hasher);
        site.path_traversal.custom_patterns.hash(&mut hasher);
        site.rfi.custom_patterns.hash(&mut hasher);
        site.ssrf.custom_patterns.hash(&mut hasher);
        site.ssrf.block_private_ips.hash(&mut hasher);
        site.ssrf.allowed_domains.hash(&mut hasher);
        site.ssrf.allowlist_only_mode.hash(&mut hasher);
        site.headers.scan.hash(&mut hasher);
        site.headers.skip.hash(&mut hasher);
    }

    hasher.finish()
}

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

pub fn attack_log_only_for_path(path: &str, site: Option<&SiteAttackDetectionConfig>) -> bool {
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
            headers: Default::default(),
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

    #[test]
    fn action_precedence_is_site_then_global_then_block() {
        let global = AttackDetectionConfig::default();
        let empty = SiteAttackDetectionConfig::default();

        let resolved = resolve_attack_policy(None, &global, "/", 0);
        assert_eq!(resolved.action, AttackAction::Block);
        assert!(resolved.uses_global_detector());

        let resolved = resolve_attack_policy(Some(&empty), &global, "/", 0);
        assert_eq!(resolved.action, AttackAction::Block);

        let mut global_stall = global.clone();
        global_stall.action = "stall".to_string();
        let resolved = resolve_attack_policy(Some(&empty), &global_stall, "/", 0);
        assert_eq!(resolved.action, AttackAction::Stall);

        let mut site_log = empty.clone();
        site_log.action = Some("log".to_string());
        let resolved = resolve_attack_policy(Some(&site_log), &global_stall, "/", 0);
        assert_eq!(resolved.action, AttackAction::Log);
        assert!(resolved.is_log());
    }

    #[test]
    fn per_path_log_beats_site_action() {
        let global = AttackDetectionConfig::default();
        let site = site_with_per_path(&[("/admin", "log")]);
        let resolved = resolve_attack_policy(Some(&site), &global, "/admin/new", 0);
        assert_eq!(resolved.action, AttackAction::Block);
        assert!(resolved.log_only);
        assert!(resolved.is_log());
    }

    #[test]
    fn site_detector_overrides_merge_with_global() {
        let mut global = AttackDetectionConfig::default();
        global.sqli.custom_patterns = vec!["global-pattern".to_string()];
        global.ssrf.allowed_domains = vec!["global.example".to_string()];

        let mut site = SiteAttackDetectionConfig::default();
        site.paranoia_level = Some(3);
        site.sqli.custom_patterns = vec!["site-pattern".to_string()];
        site.ssrf.block_private_ips = Some(false);
        site.ssrf.allowed_domains = vec!["site.example".to_string()];
        site.ssrf.allowlist_only_mode = Some(true);
        site.headers.scan = vec!["x-app-header".to_string()];

        let resolved = resolve_attack_policy(Some(&site), &global, "/", 7);
        assert!(!resolved.uses_global_detector());
        let config = resolved.detector_config.as_ref();
        assert_eq!(config.paranoia_level, 3);
        assert_eq!(
            config.sqli.custom_patterns,
            vec!["global-pattern".to_string(), "site-pattern".to_string()]
        );
        assert!(!config.ssrf.block_private_ips);
        assert_eq!(
            config.ssrf.allowed_domains,
            vec!["global.example".to_string(), "site.example".to_string()]
        );
        assert!(config.ssrf.allowlist_only_mode);
        assert_eq!(config.header_scan.scan, vec!["x-app-header".to_string()]);
        assert!(resolved.fingerprint.is_some());
    }

    #[test]
    fn action_only_override_keeps_global_detector() {
        let global = AttackDetectionConfig::default();
        let mut site = SiteAttackDetectionConfig::default();
        site.action = Some("stall".to_string());
        let resolved = resolve_attack_policy(Some(&site), &global, "/", 0);
        assert_eq!(resolved.action, AttackAction::Stall);
        assert!(resolved.uses_global_detector());
    }

    #[test]
    fn fingerprint_changes_with_generation_and_policy() {
        let global = AttackDetectionConfig::default();
        let mut site = SiteAttackDetectionConfig::default();
        site.paranoia_level = Some(3);
        let a = resolve_attack_policy(Some(&site), &global, "/", 1)
            .fingerprint
            .expect("override");
        let b = resolve_attack_policy(Some(&site), &global, "/", 2)
            .fingerprint
            .expect("override");
        assert_ne!(a, b);

        site.paranoia_level = Some(1);
        let c = resolve_attack_policy(Some(&site), &global, "/", 1)
            .fingerprint
            .expect("override");
        assert_ne!(a, c);
    }
}
