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
}
