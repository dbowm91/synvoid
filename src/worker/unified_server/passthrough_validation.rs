use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use synvoid_config::site::SiteConfig;

/// Classification results for TLS passthrough validation.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PassthroughClassification {
    pub passthrough_sites: Vec<String>,
    pub passthrough_with_waf: Vec<String>,
    pub bypass_sites: Vec<String>,
    pub bypass_sites_without_rate_limit: Vec<String>,
}

/// Structured policy violations from TLS passthrough evaluation.
#[derive(Debug, PartialEq, Eq)]
pub enum PassthroughPolicyViolation {
    WafBypassed { site_id: String },
    BypassWithoutRateLimit { site_id: String },
}

/// Structured policy evaluation combining classification with violation detection.
#[derive(Debug)]
pub struct PassthroughPolicyEvaluation {
    pub classification: PassthroughClassification,
    pub violations: Vec<PassthroughPolicyViolation>,
}

/// Determine whether a site has meaningful rate limiting configured.
///
/// A site is considered rate-limited when:
/// - `mode` is set to a recognized value, **or**
/// - `ip` overrides are present with at least one non-zero limit, **or**
/// - `global` overrides are present with at least one non-zero limit, **or**
/// - `endpoints` has at least one entry with a configured limit.
pub fn site_has_rate_limit(site: &SiteConfig) -> bool {
    let rl = &site.ratelimit;

    if rl.mode.is_some() {
        return true;
    }

    if let Some(ref ip) = rl.ip {
        if ip.per_second.is_some()
            || ip.per_minute.is_some()
            || ip.per_5min.is_some()
            || ip.per_hour.is_some()
            || ip.per_day.is_some()
            || ip.burst.is_some()
        {
            return true;
        }
    }

    if let Some(ref global) = rl.global {
        if global.per_second.is_some()
            || global.per_minute.is_some()
            || global.per_5min.is_some()
            || global.max_connections.is_some()
        {
            return true;
        }
    }

    if !rl.endpoints.is_empty() {
        return true;
    }

    false
}

/// Pure classification of passthrough sites from a site map.
///
/// # Classification rules
///
/// - `passthrough_sites`: all sites with `tls_passthrough == Some(true)`
/// - `passthrough_with_waf`: subset that also have `tls_passthrough_enforce_waf == Some(true)`
/// - `bypass_sites`: passthrough sites **without** WAF enforcement (subset of `passthrough_sites` \ `passthrough_with_waf`)
/// - `bypass_sites_without_rate_limit`: bypass sites where `site_has_rate_limit()` returns `false`
pub fn classify_passthrough_sites(
    sites: &HashMap<String, SiteConfig>,
) -> PassthroughClassification {
    let passthrough_sites: Vec<String> = sites
        .iter()
        .filter(|(_, site)| site.proxy.tls_passthrough == Some(true))
        .map(|(id, _)| id.clone())
        .collect();

    let passthrough_with_waf: Vec<String> = sites
        .iter()
        .filter(|(_, site)| {
            site.proxy.tls_passthrough == Some(true)
                && site.proxy.tls_passthrough_enforce_waf == Some(true)
        })
        .map(|(id, _)| id.clone())
        .collect();

    let bypass_sites: Vec<String> = passthrough_sites
        .iter()
        .filter(|s| !passthrough_with_waf.contains(s))
        .cloned()
        .collect();

    let bypass_sites_without_rate_limit: Vec<String> = bypass_sites
        .iter()
        .filter(|s| {
            sites
                .get(*s)
                .map_or(false, |site| !site_has_rate_limit(site))
        })
        .cloned()
        .collect();

    PassthroughClassification {
        passthrough_sites,
        passthrough_with_waf,
        bypass_sites,
        bypass_sites_without_rate_limit,
    }
}

/// Pure policy evaluation: classify sites and detect violations.
///
/// This function performs no I/O and produces no side effects.
pub fn evaluate_passthrough_policy(
    sites: &HashMap<String, SiteConfig>,
    strict_mode: bool,
) -> PassthroughPolicyEvaluation {
    let classification = classify_passthrough_sites(sites);
    let mut violations = Vec::new();

    for site_id in &classification.bypass_sites {
        violations.push(PassthroughPolicyViolation::WafBypassed {
            site_id: site_id.clone(),
        });
    }

    for site_id in &classification.bypass_sites_without_rate_limit {
        violations.push(PassthroughPolicyViolation::BypassWithoutRateLimit {
            site_id: site_id.clone(),
        });
    }

    if strict_mode && !violations.is_empty() {
        return PassthroughPolicyEvaluation {
            classification,
            violations,
        };
    }

    PassthroughPolicyEvaluation {
        classification,
        violations,
    }
}

/// Perform TLS passthrough validation: classify sites, emit logs and metrics.
///
/// When strict mode is enabled (via `security.strict_tls_passthrough_policy`),
/// validation returns an error for any passthrough bypass site that lacks both
/// WAF enforcement and rate limiting.
pub async fn validate_tls_passthrough_waf_policy(
    config: &Arc<RwLock<synvoid_config::ConfigManager>>,
) -> Result<(), String> {
    let guard = config.read().await;
    let sites = &guard.sites;
    let strict_mode = guard.main.security.strict_tls_passthrough_policy;
    let evaluation = evaluate_passthrough_policy(sites, strict_mode);
    drop(guard);

    if evaluation.classification.passthrough_sites.is_empty() {
        return Ok(());
    }

    if !evaluation.classification.passthrough_with_waf.is_empty() {
        tracing::info!(
            "TLS passthrough with WAF enforcement enabled for sites: {:?}. WAF will inspect L7 traffic.",
            evaluation.classification.passthrough_with_waf
        );
    }

    if !evaluation.classification.bypass_sites.is_empty() {
        tracing::error!(
            "TLS passthrough is enabled for sites: {:?}. WAF inspection is BYPASSED for these sites - L7 attacks will not be blocked. Set tls_passthrough_enforce_waf = true to enable WAF inspection for passthrough traffic.",
            evaluation.classification.bypass_sites
        );
        crate::metrics::record_tls_passthrough_waf_bypassed();
    }

    if !evaluation
        .classification
        .bypass_sites_without_rate_limit
        .is_empty()
    {
        tracing::error!(
            "TLS passthrough sites {:?} do not have rate limiting configured. Rate limiting is required for passthrough sites to prevent abuse.",
            evaluation.classification.bypass_sites_without_rate_limit
        );
    }

    if strict_mode {
        let mut error_sites: Vec<String> = evaluation
            .classification
            .bypass_sites_without_rate_limit
            .clone();
        error_sites.sort();
        if !error_sites.is_empty() {
            return Err(format!(
                "Strict TLS passthrough policy: sites {:?} have TLS passthrough enabled without WAF enforcement and without rate limiting. Either set tls_passthrough_enforce_waf = true or configure rate limiting (security.strict_tls_passthrough_policy = true).",
                error_sites
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use synvoid_config::site::proxy::SiteProxyConfig;
    use synvoid_config::site::SiteRateLimitConfig;
    use synvoid_config::site::{
        EndpointRateLimitConfig, GlobalRateLimitOverride, IpRateLimitOverride,
    };

    fn make_site(
        tls_passthrough: Option<bool>,
        tls_passthrough_enforce_waf: Option<bool>,
    ) -> SiteConfig {
        SiteConfig {
            proxy: SiteProxyConfig {
                tls_passthrough,
                tls_passthrough_enforce_waf,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn make_site_with_ratelimit(
        tls_passthrough: Option<bool>,
        tls_passthrough_enforce_waf: Option<bool>,
        ratelimit: SiteRateLimitConfig,
    ) -> SiteConfig {
        SiteConfig {
            proxy: SiteProxyConfig {
                tls_passthrough,
                tls_passthrough_enforce_waf,
                ..Default::default()
            },
            ratelimit,
            ..Default::default()
        }
    }

    fn site_map(entries: Vec<(&str, SiteConfig)>) -> HashMap<String, SiteConfig> {
        entries
            .into_iter()
            .map(|(id, cfg)| (id.to_string(), cfg))
            .collect()
    }

    // --- site_has_rate_limit tests ---

    #[test]
    fn site_has_rate_limit_default() {
        let site = make_site(Some(true), Some(false));
        assert!(!site_has_rate_limit(&site));
    }

    #[test]
    fn site_has_rate_limit_mode() {
        let site = make_site_with_ratelimit(
            Some(true),
            Some(false),
            SiteRateLimitConfig {
                mode: Some("token_bucket".to_string()),
                ..Default::default()
            },
        );
        assert!(site_has_rate_limit(&site));
    }

    #[test]
    fn site_has_rate_limit_ip() {
        let site = make_site_with_ratelimit(
            Some(true),
            Some(false),
            SiteRateLimitConfig {
                ip: Some(IpRateLimitOverride {
                    per_second: None,
                    per_minute: Some(100),
                    per_5min: None,
                    per_hour: None,
                    per_day: None,
                    burst: None,
                }),
                ..Default::default()
            },
        );
        assert!(site_has_rate_limit(&site));
    }

    #[test]
    fn site_has_rate_limit_global() {
        let site = make_site_with_ratelimit(
            Some(true),
            Some(false),
            SiteRateLimitConfig {
                global: Some(GlobalRateLimitOverride {
                    per_second: None,
                    per_minute: None,
                    per_5min: None,
                    max_connections: Some(1000),
                }),
                ..Default::default()
            },
        );
        assert!(site_has_rate_limit(&site));
    }

    #[test]
    fn site_has_rate_limit_endpoints() {
        let site = make_site_with_ratelimit(
            Some(true),
            Some(false),
            SiteRateLimitConfig {
                endpoints: vec![EndpointRateLimitConfig {
                    path_pattern: "/api/*".to_string(),
                    per_minute: Some(60),
                    per_hour: None,
                    burst: None,
                }],
                ..Default::default()
            },
        );
        assert!(site_has_rate_limit(&site));
    }

    #[test]
    fn site_has_rate_limit_empty_ip_override() {
        let site = make_site_with_ratelimit(
            Some(true),
            Some(false),
            SiteRateLimitConfig {
                ip: Some(IpRateLimitOverride {
                    per_second: None,
                    per_minute: None,
                    per_5min: None,
                    per_hour: None,
                    per_day: None,
                    burst: None,
                }),
                ..Default::default()
            },
        );
        assert!(!site_has_rate_limit(&site));
    }

    #[test]
    fn site_has_rate_limit_empty_endpoints() {
        let site = make_site_with_ratelimit(
            Some(true),
            Some(false),
            SiteRateLimitConfig {
                endpoints: vec![],
                ..Default::default()
            },
        );
        assert!(!site_has_rate_limit(&site));
    }

    // --- classify_passthrough_sites tests ---

    #[test]
    fn empty_site_map() {
        let sites = HashMap::new();
        let result = classify_passthrough_sites(&sites);
        assert_eq!(result, PassthroughClassification::default());
    }

    #[test]
    fn passthrough_with_waf_enforcement() {
        let sites = site_map(vec![("site-a", make_site(Some(true), Some(true)))]);
        let result = classify_passthrough_sites(&sites);
        assert_eq!(result.passthrough_sites, vec!["site-a"]);
        assert_eq!(result.passthrough_with_waf, vec!["site-a"]);
        assert!(result.bypass_sites.is_empty());
        assert!(result.bypass_sites_without_rate_limit.is_empty());
    }

    #[test]
    fn passthrough_without_waf_enforcement_no_rate_limit() {
        let sites = site_map(vec![("site-b", make_site(Some(true), Some(false)))]);
        let result = classify_passthrough_sites(&sites);
        assert_eq!(result.passthrough_sites, vec!["site-b"]);
        assert!(result.passthrough_with_waf.is_empty());
        assert_eq!(result.bypass_sites, vec!["site-b"]);
        assert_eq!(result.bypass_sites_without_rate_limit, vec!["site-b"]);
    }

    #[test]
    fn passthrough_without_waf_with_rate_limit() {
        let sites = site_map(vec![(
            "site-d",
            make_site_with_ratelimit(
                Some(true),
                Some(false),
                SiteRateLimitConfig {
                    mode: Some("token_bucket".to_string()),
                    ..Default::default()
                },
            ),
        )]);
        let result = classify_passthrough_sites(&sites);
        assert_eq!(result.passthrough_sites, vec!["site-d"]);
        assert!(result.passthrough_with_waf.is_empty());
        assert_eq!(result.bypass_sites, vec!["site-d"]);
        assert!(result.bypass_sites_without_rate_limit.is_empty());
    }

    #[test]
    fn passthrough_with_waf_and_no_rate_limit() {
        let sites = site_map(vec![(
            "site-c",
            make_site_with_ratelimit(Some(true), Some(true), SiteRateLimitConfig::default()),
        )]);
        let result = classify_passthrough_sites(&sites);
        assert_eq!(result.passthrough_sites, vec!["site-c"]);
        assert_eq!(result.passthrough_with_waf, vec!["site-c"]);
        assert!(result.bypass_sites.is_empty());
        assert!(result.bypass_sites_without_rate_limit.is_empty());
    }

    #[test]
    fn mixed_sites() {
        let sites = site_map(vec![
            ("waf-on", make_site(Some(true), Some(true))),
            ("waf-off", make_site(Some(true), Some(false))),
            ("no-passthrough", make_site(Some(false), Some(false))),
        ]);
        let result = classify_passthrough_sites(&sites);
        assert_eq!(result.passthrough_sites.len(), 2);
        assert!(result.passthrough_sites.contains(&"waf-on".to_string()));
        assert!(result.passthrough_sites.contains(&"waf-off".to_string()));
        assert_eq!(result.passthrough_with_waf, vec!["waf-on"]);
        assert_eq!(result.bypass_sites, vec!["waf-off"]);
    }

    #[test]
    fn bypass_without_rate_limit_detected() {
        let sites = site_map(vec![
            (
                "no-rl",
                make_site_with_ratelimit(Some(true), Some(false), SiteRateLimitConfig::default()),
            ),
            (
                "has-rl",
                make_site_with_ratelimit(
                    Some(true),
                    Some(false),
                    SiteRateLimitConfig {
                        mode: Some("token_bucket".to_string()),
                        ..Default::default()
                    },
                ),
            ),
        ]);
        let result = classify_passthrough_sites(&sites);
        assert_eq!(result.bypass_sites.len(), 2);
        assert_eq!(result.bypass_sites_without_rate_limit, vec!["no-rl"]);
    }

    #[test]
    fn no_passthrough_flags() {
        let sites = site_map(vec![("normal", make_site(Some(false), Some(false)))]);
        let result = classify_passthrough_sites(&sites);
        assert_eq!(result, PassthroughClassification::default());
    }

    #[test]
    fn all_none_flags() {
        let sites = site_map(vec![("default", make_site(None, None))]);
        let result = classify_passthrough_sites(&sites);
        assert_eq!(result, PassthroughClassification::default());
    }

    // --- evaluate_passthrough_policy tests ---

    #[test]
    fn policy_no_violations_when_no_passthrough() {
        let sites = site_map(vec![("normal", make_site(Some(false), Some(false)))]);
        let eval = evaluate_passthrough_policy(&sites, false);
        assert!(eval.violations.is_empty());
    }

    #[test]
    fn policy_violations_for_bypass_sites() {
        let sites = site_map(vec![("bypass", make_site(Some(true), Some(false)))]);
        let eval = evaluate_passthrough_policy(&sites, false);
        // Bypass site with no WAF enforcement and no rate limiting generates two violations
        assert_eq!(eval.violations.len(), 2);
        assert!(eval.violations.iter().any(|v| matches!(
            v,
            PassthroughPolicyViolation::WafBypassed { site_id } if site_id == "bypass"
        )));
        assert!(eval.violations.iter().any(|v| matches!(
            v,
            PassthroughPolicyViolation::BypassWithoutRateLimit { site_id } if site_id == "bypass"
        )));
    }

    #[test]
    fn policy_no_rate_limit_violation() {
        let sites = site_map(vec![(
            "bypass",
            make_site_with_ratelimit(Some(true), Some(false), SiteRateLimitConfig::default()),
        )]);
        let eval = evaluate_passthrough_policy(&sites, false);
        assert_eq!(eval.violations.len(), 2);
        assert!(eval
            .violations
            .iter()
            .any(|v| matches!(v, PassthroughPolicyViolation::WafBypassed { site_id } if site_id == "bypass")));
        assert!(eval
            .violations
            .iter()
            .any(|v| matches!(v, PassthroughPolicyViolation::BypassWithoutRateLimit { site_id } if site_id == "bypass")));
    }

    #[test]
    fn policy_no_violations_for_waf_enforced() {
        let sites = site_map(vec![("waf-on", make_site(Some(true), Some(true)))]);
        let eval = evaluate_passthrough_policy(&sites, false);
        assert!(eval.violations.is_empty());
    }

    #[test]
    fn strict_mode_preserves_violations() {
        let sites = site_map(vec![("bypass", make_site(Some(true), Some(false)))]);
        let eval = evaluate_passthrough_policy(&sites, true);
        assert!(!eval.violations.is_empty());
    }

    #[test]
    fn strict_mode_bypass_without_rate_limit_has_both_violations() {
        let sites = site_map(vec![("bypass", make_site(Some(true), Some(false)))]);
        let eval = evaluate_passthrough_policy(&sites, true);
        assert_eq!(eval.violations.len(), 2);
        assert!(eval.violations.iter().any(|v| matches!(
            v,
            PassthroughPolicyViolation::WafBypassed { site_id } if site_id == "bypass"
        )));
        assert!(eval.violations.iter().any(|v| matches!(
            v,
            PassthroughPolicyViolation::BypassWithoutRateLimit { site_id } if site_id == "bypass"
        )));
    }

    #[test]
    fn strict_mode_bypass_with_rate_limit_only_waf_violation() {
        let sites = site_map(vec![(
            "bypass",
            make_site_with_ratelimit(
                Some(true),
                Some(false),
                SiteRateLimitConfig {
                    mode: Some("token_bucket".to_string()),
                    ..Default::default()
                },
            ),
        )]);
        let eval = evaluate_passthrough_policy(&sites, true);
        assert_eq!(eval.violations.len(), 1);
        assert!(eval.violations.iter().any(|v| matches!(
            v,
            PassthroughPolicyViolation::WafBypassed { site_id } if site_id == "bypass"
        )));
    }

    #[test]
    fn strict_mode_passthrough_with_waf_no_violations() {
        let sites = site_map(vec![("waf-on", make_site(Some(true), Some(true)))]);
        let eval = evaluate_passthrough_policy(&sites, true);
        assert!(eval.violations.is_empty());
    }

    #[test]
    fn strict_mode_mixed_sites_only_problematic_violations() {
        let sites = site_map(vec![
            ("waf-on", make_site(Some(true), Some(true))),
            (
                "bypass-rl",
                make_site_with_ratelimit(
                    Some(true),
                    Some(false),
                    SiteRateLimitConfig {
                        mode: Some("token_bucket".to_string()),
                        ..Default::default()
                    },
                ),
            ),
            ("bypass-no-rl", make_site(Some(true), Some(false))),
        ]);
        let eval = evaluate_passthrough_policy(&sites, true);
        // waf-on: no violations
        // bypass-rl: WafBypassed only
        // bypass-no-rl: WafBypassed + BypassWithoutRateLimit
        assert_eq!(eval.violations.len(), 3);
        let waf_bypassed: Vec<_> = eval
            .violations
            .iter()
            .filter(|v| matches!(v, PassthroughPolicyViolation::WafBypassed { .. }))
            .collect();
        assert_eq!(waf_bypassed.len(), 2);
        let no_rl: Vec<_> = eval
            .violations
            .iter()
            .filter(|v| matches!(v, PassthroughPolicyViolation::BypassWithoutRateLimit { .. }))
            .collect();
        assert_eq!(no_rl.len(), 1);
    }
}
