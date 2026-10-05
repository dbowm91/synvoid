//! DNS-owned country-lookup capability (Phase 135).
//!
//! Phase 133 proved the `synvoid-geoip` seam is exactly two methods —
//! `get_country_info` and `get_asn_info` — reached at four sites, and narrower
//! than the provider's own types suggest: `GeoLocation::matches_ip` reads only
//! `AsnInfo::asn` and discards `organization`.
//!
//! This module therefore declares the smallest capability that covers those
//! reads, with a **DNS-owned** result type. `CountryInfo` here is a new type,
//! not a re-export of `synvoid_geoip::CountryInfo` — a re-export would keep the
//! dependency edge alive, which is exactly the mistake the source-level gate in
//! `tools/synvoid-repo-guards/tests/dns_dependency_edges.rs` exists to catch.
//!
//! Implementations live in composition and own the database. `synvoid-dns` no
//! longer depends on `synvoid-geoip` at all.
//!
//! ## Why `asn` returns `Option<u32>`
//!
//! The firewall compares `asn_info.asn != asn` and never reads the
//! organization string. Returning the number keeps the provider's struct out of
//! the request path and keeps the seam one field wide.

use std::net::IpAddr;

/// A country lookup, as the DNS firewall and mesh steering need it.
///
/// ## Contract
///
/// - `None` means "this provider has no answer for this address". It is
///   returned for an address outside the database, for an address the database
///   does not cover, and for a provider with no database loaded. Callers must
///   not conflate the three.
/// - Implementations **must not** log the queried address. These methods run per
///   request from the DNS query path, so any logging would turn a country lookup
///   into a client-IP disclosure channel. Phase 133 proved the real provider
///   satisfies this and pinned it at the source level.
/// - An absent provider is expressed by the `Option` at the call site, not by
///   returning `None` here. The firewall needs to tell "cannot evaluate" apart
///   from "evaluated and does not match", so a provider that exists but cannot
///   answer is materially different from no provider at all.
pub trait CountryLookup: Send + Sync {
    /// Country, name, and optional region/city for an address.
    fn country_info(&self, ip: IpAddr) -> Option<CountryInfo>;

    /// Autonomous system number for an address.
    fn asn(&self, ip: IpAddr) -> Option<u32>;
}

/// A DNS-owned country result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountryInfo {
    /// ISO 3166-1 alpha-2 country code, as the provider reports it.
    pub code: String,
    /// Human-readable country name.
    pub name: String,
    /// First-level subdivision, when the database carries one.
    pub subdivision: Option<String>,
    /// City, when the database carries one.
    pub city: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    struct Always {
        country: &'static str,
        answer: bool,
    }

    impl CountryLookup for Always {
        fn country_info(&self, _ip: IpAddr) -> Option<CountryInfo> {
            self.answer.then(|| CountryInfo {
                code: self.country.to_string(),
                name: "Testland".to_string(),
                subdivision: None,
                city: None,
            })
        }

        fn asn(&self, _ip: IpAddr) -> Option<u32> {
            self.answer.then_some(64500)
        }
    }

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))
    }

    /// The trait must be usable as `Arc<dyn CountryLookup>`, which is the shape
    /// every DNS call site uses. If it stopped being dyn compatible this fails
    /// here rather than at each field.
    #[test]
    fn the_capability_is_usable_as_a_trait_object() {
        let lookup: Arc<dyn CountryLookup> = Arc::new(Always {
            country: "RU",
            answer: true,
        });
        assert_eq!(
            lookup.country_info(ip()).map(|c| c.code),
            Some("RU".to_string())
        );
        assert_eq!(lookup.asn(ip()), Some(64500));
    }

    /// A provider that exists but cannot answer returns `None` for both
    /// methods. Phase 133 established this case is the real provider's
    /// behavior when no database is loaded; after inversion it is directly
    /// constructible here, which is what made the test possible.
    #[test]
    fn a_provider_that_cannot_answer_returns_none() {
        let lookup: Arc<dyn CountryLookup> = Arc::new(Always {
            country: "RU",
            answer: false,
        });
        assert!(lookup.country_info(ip()).is_none());
        assert!(lookup.asn(ip()).is_none());
    }
}
