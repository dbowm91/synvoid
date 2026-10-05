//! Composition-owned adapters implementing the DNS country-lookup capability
//! over the concrete `synvoid-geoip` provider (Phase 135).
//!
//! `synvoid-dns` declares `CountryLookup` and knows nothing about GeoIP
//! databases. This module is where the two meet, and it is the only place in
//! the tree that maps the provider's result type into the DNS-owned one.
//!
//! ## The mapping is deliberately narrow
//!
//! `CountryLookup::asn` returns `Option<u32>`, not the provider's `AsnInfo`,
//! because the firewall compares the number and never reads the organization
//! string. Carrying `AsnInfo` across would put a provider type in the request
//! path for no reader.
//!
//! The adapter does **not** reproduce the provider's second country lookup.
//! `GeoIpManager::get_country_info` applies `?` to both `lookup_country` and
//! `lookup_country_info`, and both decode the identical `country.iso_code` path
//! (Phase 133 F-9), so the second traversal cannot change the answer. Calling
//! the provider as-is is therefore the cheapest correct choice, and the
//! redundant traversal stays the provider's business.

use std::net::IpAddr;
use std::sync::Arc;

use synvoid_dns::geo::{CountryInfo, CountryLookup};

/// Adapts a `GeoIpManager` to the DNS-owned `CountryLookup`.
#[derive(Clone)]
pub struct GeoIpCountryLookup {
    manager: Arc<synvoid_geoip::GeoIpManager>,
}

impl GeoIpCountryLookup {
    pub fn new(manager: Arc<synvoid_geoip::GeoIpManager>) -> Self {
        Self { manager }
    }

    /// The wrapped provider, for root code that still needs the concrete type.
    pub fn manager(&self) -> &Arc<synvoid_geoip::GeoIpManager> {
        &self.manager
    }

    /// Whether a database is actually loaded.
    ///
    /// Exposed because "a provider exists" and "a provider can answer" are
    /// different states, and an operator debugging a fail-closed geo rule needs
    /// to tell them apart. Phase 133 F-2 showed the firewall cannot report this
    /// on its own, because the capability's `None` deliberately means "no answer
    /// for this address".
    pub fn database_loaded(&self) -> bool {
        self.manager.status().database_loaded
    }
}

impl CountryLookup for GeoIpCountryLookup {
    fn country_info(&self, ip: IpAddr) -> Option<CountryInfo> {
        self.manager.get_country_info(ip).map(|info| CountryInfo {
            code: info.code,
            name: info.name,
            subdivision: info.subdivision,
            city: info.city,
        })
    }

    fn asn(&self, ip: IpAddr) -> Option<u32> {
        self.manager.get_asn_info(ip).map(|asn| asn.asn)
    }
}

/// Wrap a provider handle for the DNS geo rules and mesh steering.
///
/// A `None` manager stays `None`: Phase 135 F-2 made a geo rule fail closed when
/// it cannot be evaluated, so a *disabled* GeoIP section must not be turned into
/// a provider that appears present but cannot answer — that would silently
/// convert a fail-closed block into an evaluated "no match" and allow traffic.
pub fn as_country_lookup(
    manager: Option<Arc<synvoid_geoip::GeoIpManager>>,
) -> Option<Arc<dyn CountryLookup>> {
    manager.map(|manager| Arc::new(GeoIpCountryLookup::new(manager)) as Arc<dyn CountryLookup>)
}

/// Build the DNS country-lookup capability from persisted configuration.
///
/// Phase 138. Returns `None` when `[geoip]` is disabled, which is the normal
/// case and must stay distinguishable from "enabled but cannot answer" — a
/// *disabled* provider and a *database-less* one are different states, and
/// Phase 135 F-2 made that distinction load-bearing for fail-closed geo rules.
///
/// ## What this does not do
///
/// It does **not** refuse to start when `[geoip]` is enabled but no database is
/// usable, and it does not warn. Two reasons, both evidence-based:
///
/// 1. `GeoIpManager::new` returns `Option` and **never reports a load failure** —
///    an unparseable database yields a manager with no reader and a `warn!`
///    only (`crates/synvoid-geoip/src/manager.rs:48-58`), and
///    `GeoIpLookup::new` returns `Ok(reader: None)` for a non-existent path
///    (`crates/synvoid-geoip/src/lookup.rs:19-22`). Composition therefore cannot
///    tell "no path configured" from "path typo" from "corrupt database", so a
///    refusal would have to reject all three.
/// 2. A refusal would be **unobservable and harmful today**: no DNS firewall
///    rule can be declared at all, because `DnsFirewallConfig` has no `rules`
///    field and every `add_rule` call site is a hardcoded `Subnet`/`Block` rule
///    inside `DnsServer::new`. Refusing startup for a section nothing reads
///    would break a currently-harmless configuration for no benefit.
///
/// `database_loaded()` exists so an operator can tell the two states apart, and
/// so whoever adds the firewall-rule config path inherits a capability that can
/// be interrogated rather than guessed at.
pub fn country_lookup_from_config(
    config: &synvoid_config::geoip::GeoIpConfig,
    site_configs: &[synvoid_config::site::SiteGeoipConfig],
) -> Option<Arc<dyn CountryLookup>> {
    if !config.enabled {
        return None;
    }

    let manager = Arc::new(synvoid_geoip::GeoIpManager::new(
        config.clone(),
        site_configs,
        None,
    )?);

    // Built as the concrete adapter first, because `database_loaded` is an
    // inherent method: it is not part of the DNS-owned `CountryLookup`
    // capability, which must stay exactly two methods wide.
    let lookup = GeoIpCountryLookup::new(manager);
    if !lookup.database_loaded() {
        // Loud, but not fatal. See the doc comment: the provider cannot
        // distinguish the failure modes, and no DNS geo rule can be declared
        // today, so refusing to start would reject valid configurations.
        tracing::warn!(
            "geoip enabled but no database is loaded; DNS GeoLocation rules \
             cannot be evaluated and a restrictive rule will fail closed"
        );
    }

    Some(Arc::new(lookup) as Arc<dyn CountryLookup>)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use synvoid_config::geoip::GeoIpConfig;

    fn manager_without_database() -> Arc<synvoid_geoip::GeoIpManager> {
        let config = GeoIpConfig {
            enabled: true,
            database_path: None,
            update_enabled: false,
            edition_ids: Vec::new(),
            ..Default::default()
        };
        Arc::new(
            synvoid_geoip::GeoIpManager::new(config, &[], None).expect("enabled yields a manager"),
        )
    }

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))
    }

    /// A disabled GeoIP section must not produce a capability, because a
    /// fail-closed geo rule and a provider that answers "no" are opposite
    /// behaviors.
    #[test]
    fn a_disabled_section_yields_no_capability() {
        let config = GeoIpConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(synvoid_geoip::GeoIpManager::new(config, &[], None).is_none());
        assert!(as_country_lookup(None).is_none());
    }

    /// The wrapper must pass the provider's `None` through rather than
    /// manufacturing an empty result, so the firewall can tell "no answer" from
    /// "no country".
    #[test]
    fn a_provider_without_a_database_answers_none() {
        let lookup = as_country_lookup(Some(manager_without_database())).expect("wrapped");
        assert!(lookup.country_info(ip()).is_none());
        assert!(lookup.asn(ip()).is_none());
    }

    /// The adapter surfaces the loaded-database state, which is the only way an
    /// operator can distinguish "no provider" from "provider that cannot answer".
    #[test]
    fn the_adapter_reports_whether_a_database_is_loaded() {
        let manager = manager_without_database();
        let adapter = GeoIpCountryLookup::new(Arc::clone(&manager));
        assert!(!adapter.database_loaded());
        assert!(Arc::ptr_eq(adapter.manager(), &manager));
    }

    // ---- Phase 138: construction from persisted configuration --------------

    /// A disabled section must produce no capability. This is the whole basis of
    /// the Phase 135 F-2 fail-closed posture: a *disabled* provider and a
    /// *provider that answers "no"* are opposite behaviors, and manufacturing the
    /// latter from a disabled section would convert a fail-closed block into a
    /// silent allow.
    #[test]
    fn a_disabled_section_yields_no_capability_from_the_config_path() {
        let config = GeoIpConfig {
            enabled: false,
            database_path: Some("/nonexistent/GeoLite2-City.mmdb".to_string()),
            ..Default::default()
        };

        assert!(
            country_lookup_from_config(&config, &[]).is_none(),
            "a disabled section must not construct a provider even when a path is set"
        );
    }

    /// An enabled section with no database constructs a provider. It answers
    /// `None` rather than erroring, which is why Phase 138 chose a loud warning
    /// over a startup refusal — see the function's doc comment.
    #[test]
    fn an_enabled_section_without_a_database_still_constructs_a_provider() {
        let config = GeoIpConfig {
            enabled: true,
            database_path: None,
            update_enabled: false,
            edition_ids: Vec::new(),
            ..Default::default()
        };

        let lookup =
            country_lookup_from_config(&config, &[]).expect("an enabled section constructs");

        // Present but unable to answer. This is the state a naive wiring turns
        // into a silent allow, so it is pinned explicitly.
        assert!(
            lookup.country_info(ip()).is_none(),
            "a database-less provider must answer `None`, never a country"
        );
    }

    /// A path that does not exist is indistinguishable from no path, because
    /// `GeoIpLookup::new` returns `Ok(reader: None)` for a missing file. This
    /// test records that limitation rather than asserting a distinction the
    /// provider cannot make — it is the reason the phase warns instead of
    /// refusing to start.
    #[test]
    fn a_typo_in_the_database_path_is_indistinguishable_from_no_path() {
        let typo = GeoIpConfig {
            enabled: true,
            database_path: Some("/var/lib/synvoid/geoip/GeoLite2-City.mmdb".to_string()),
            update_enabled: false,
            edition_ids: Vec::new(),
            ..Default::default()
        };
        let absent = GeoIpConfig {
            database_path: None,
            ..typo.clone()
        };

        let from_typo = country_lookup_from_config(&typo, &[]).expect("constructs");
        let from_absent = country_lookup_from_config(&absent, &[]).expect("constructs");

        assert!(from_typo.country_info(ip()).is_none());
        assert!(from_absent.country_info(ip()).is_none());
        // Both are "present but cannot answer". A future fix that separates these
        // two states would legitimately change this test.
    }
}
