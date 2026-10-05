//! Root composition for the DNS country-lookup capability (Phase 135).
//!
//! `synvoid-geoip` is a provider crate, not a DNS concern. The DNS crate asks a
//! narrow question — what country and ASN is this address? — through the
//! DNS-owned `CountryLookup` capability, and this module is where the concrete
//! provider is adapted to it.
//!
//! Everything GeoIP-specific that composition still needs (status reporting,
//! database management, country block/allow sets) stays on the concrete
//! `GeoIpManager` in `src/server/` and `src/admin/`. Only the DNS seam is
//! inverted.

#[cfg(feature = "dns")]
pub mod dns_provider;

#[cfg(feature = "dns")]
pub use dns_provider::{as_country_lookup, GeoIpCountryLookup};
