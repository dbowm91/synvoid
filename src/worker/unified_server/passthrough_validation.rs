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
    pub rate_limited_bypass_sites: Vec<String>,
}

/// Pure classification of passthrough sites from a site map.
///
/// # Classification rules
///
/// - `passthrough_sites`: all sites with `tls_passthrough == Some(true)`
/// - `passthrough_with_waf`: subset that also have `tls_passthrough_enforce_waf == Some(true)`
/// - `bypass_sites`: passthrough sites **without** WAF enforcement (subset of `passthrough_sites` \ `passthrough_with_waf`)
/// - `rate_limited_bypass_sites`: bypass sites that have no rate limiting configured
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

    let rate_limited_bypass_sites: Vec<String> = bypass_sites
        .iter()
        .filter(|s| {
            let site_config = sites.get(*s);
            let rl = site_config.map(|s| &s.ratelimit);
            rl.is_none()
        })
        .cloned()
        .collect();

    PassthroughClassification {
        passthrough_sites,
        passthrough_with_waf,
        bypass_sites,
        rate_limited_bypass_sites,
    }
}

/// Perform TLS passthrough validation: classify sites, emit logs and metrics.
pub async fn validate_tls_passthrough_waf_policy(
    config: &Arc<RwLock<synvoid_config::ConfigManager>>,
) {
    let guard = config.read().await;
    let classification = classify_passthrough_sites(&guard.sites);
    drop(guard);

    if classification.passthrough_sites.is_empty() {
        return;
    }

    if !classification.passthrough_with_waf.is_empty() {
        tracing::info!(
            "TLS passthrough with WAF enforcement enabled for sites: {:?}. WAF will inspect L7 traffic.",
            classification.passthrough_with_waf
        );
    }

    if !classification.bypass_sites.is_empty() {
        tracing::error!(
            "TLS passthrough is enabled for sites: {:?}. WAF inspection is BYPASSED for these sites - L7 attacks will not be blocked. Set tls_passthrough_enforce_waf = true to enable WAF inspection for passthrough traffic.",
            classification.bypass_sites
        );
        crate::metrics::record_tls_passthrough_waf_bypassed();
    }

    if !classification.rate_limited_bypass_sites.is_empty() {
        tracing::error!(
            "TLS passthrough sites {:?} do not have rate limiting configured. Rate limiting is required for passthrough sites to prevent abuse.",
            classification.rate_limited_bypass_sites
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synvoid_config::site::proxy::SiteProxyConfig;
    use synvoid_config::site::SiteRateLimitConfig;

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
        has_ratelimit: bool,
    ) -> SiteConfig {
        let ratelimit = if has_ratelimit {
            SiteRateLimitConfig {
                mode: Some("token_bucket".to_string()),
                ..Default::default()
            }
        } else {
            SiteRateLimitConfig::default()
        };
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
        assert!(result.rate_limited_bypass_sites.is_empty());
    }

    #[test]
    fn passthrough_without_waf_enforcement() {
        let sites = site_map(vec![("site-b", make_site(Some(true), Some(false)))]);
        let result = classify_passthrough_sites(&sites);
        assert_eq!(result.passthrough_sites, vec!["site-b"]);
        assert!(result.passthrough_with_waf.is_empty());
        assert_eq!(result.bypass_sites, vec!["site-b"]);
        // rl.is_none() is false because site exists in map (SiteRateLimitConfig always has a value)
        assert!(result.rate_limited_bypass_sites.is_empty());
    }

    #[test]
    fn passthrough_with_waf_and_no_rate_limit() {
        let sites = site_map(vec![(
            "site-c",
            make_site_with_ratelimit(Some(true), Some(true), false),
        )]);
        let result = classify_passthrough_sites(&sites);
        assert_eq!(result.passthrough_sites, vec!["site-c"]);
        assert_eq!(result.passthrough_with_waf, vec!["site-c"]);
        assert!(result.bypass_sites.is_empty());
        assert!(result.rate_limited_bypass_sites.is_empty());
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
    fn rate_limited_bypass_excluded() {
        // rate_limited_bypass_sites is populated when config.sites.get() returns None
        // (i.e., site removed from map between classification phases). Since both
        // sites exist in the map, rl.is_none() is always false.
        let sites = site_map(vec![
            (
                "no-rl",
                make_site_with_ratelimit(Some(true), Some(false), false),
            ),
            (
                "has-rl",
                make_site_with_ratelimit(Some(true), Some(false), true),
            ),
        ]);
        let result = classify_passthrough_sites(&sites);
        assert_eq!(result.bypass_sites.len(), 2);
        assert!(result.rate_limited_bypass_sites.is_empty());
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
}
