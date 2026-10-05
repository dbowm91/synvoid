//! Phase 138 — the geo seam is wired through the DNS construction path.
//!
//! ## What this suite proves, and what it deliberately does not
//!
//! Before this phase, `DnsServer::new` contained `let geoip_lookup = None;` —
//! a hardcoded `None` that made the entire `CountryLookup` capability
//! unreachable, and left all three `with_country_lookup` builders with zero
//! callers outside a test. This suite pins that an injected handle now reaches
//! **both** consumers: the server's own `geoip_lookup` field (read by the mesh
//! geo-derivation path) and the firewall's separate `country_lookup` field.
//!
//! It deliberately does **not** claim that a geo firewall rule can be
//! evaluated in production, because none can be declared. The evidence is:
//!
//! - `DnsFirewallConfig` (`crates/synvoid-config/src/dns/dns_firewall.rs:139`)
//!   has no `rules` field — only `enabled`, `default_action`,
//!   `block_internal_ips`, `block_zone_transfers`, `max_rules`, and
//!   `rebinding_protection`.
//! - the `firewall_runtime` adapter
//!   (`src/server/dns_runtime_config.rs:253`) projects only `enabled` and the
//!   two booleans, so rules never cross into the runtime DTO.
//! - every `add_rule` call site in the repository is the hardcoded
//!   `Subnet`/`Block` block inside `DnsServer::new`.
//!
//! So the capability is **wired, not yet load-bearing**. The honest assertion
//! is that a provider is *present and reachable*, not that a rule consumed it.

mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use synvoid_dns::geo::{CountryInfo, CountryLookup};
use synvoid_dns::runtime_config::DnsFirewallRuntimeConfig;
use synvoid_dns::server::DnsServer;

/// A DNS-owned country lookup that answers from a fixed table.
///
/// The provider crate is not reachable from this crate (that is the point of
/// the Phase 135 inversion), so the double stands in for it. `synvoid-geoip`
/// proves its own behavior separately in
/// `crates/synvoid-geoip/tests/geoip_provider_evidence.rs`.
struct FixedLookup {
    country: &'static str,
}

impl CountryLookup for FixedLookup {
    fn country_info(&self, _ip: IpAddr) -> Option<CountryInfo> {
        Some(CountryInfo {
            code: self.country.to_string(),
            name: self.country.to_string(),
            subdivision: None,
            city: None,
        })
    }

    fn asn(&self, _ip: IpAddr) -> Option<u32> {
        Some(64500)
    }
}

fn client_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))
}

fn with_firewall(
    mut runtime: synvoid_dns::runtime_config::DnsRuntimeConfig,
) -> synvoid_dns::runtime_config::DnsRuntimeConfig {
    runtime.authoritative.firewall = DnsFirewallRuntimeConfig {
        enabled: true,
        block_internal_ips: false,
        block_zone_transfers: true,
    };
    runtime
}

/// The core assertion: an injected handle reaches the server's own field, which
/// is the one the mesh geo-derivation path reads.
#[test]
fn an_injected_lookup_reaches_the_server_field() {
    let server = DnsServer::new(
        support::dns_runtime(),
        None,
        Some(Arc::new(FixedLookup { country: "RU" })),
    );

    let context = server.query_context();
    let lookup = context
        .geoip_lookup
        .expect("the injected capability must be present on the query context");

    assert_eq!(
        lookup.country_info(client_ip()).map(|c| c.code),
        Some("RU".to_string()),
        "the handle on the query context must be the one that was injected"
    );
}

/// The firewall holds a **separate** `country_lookup` field from the server's
/// `geoip_lookup` (`firewall.rs` vs `server/mod.rs`), so setting one does not
/// set the other. This pins that the constructor wires both from the same
/// handle rather than leaving the firewall behind.
#[test]
fn an_injected_lookup_also_reaches_the_firewall() {
    let server = DnsServer::new(
        with_firewall(support::dns_runtime()),
        None,
        Some(Arc::new(FixedLookup { country: "RU" })),
    );

    let context = server.query_context();
    assert!(
        context.geoip_lookup.is_some(),
        "the server field must carry the capability"
    );

    let firewall = context
        .firewall
        .as_ref()
        .expect("the firewall is enabled by this fixture");
    assert!(
        firewall.read().can_evaluate_geo_rules(),
        "the firewall must be able to evaluate geo rules once a provider is \
         injected; its capability field is separate from the server's"
    );
}

/// The `None` case must stay `None`. A geo rule that cannot be evaluated is
/// fail-closed for a restrictive action (Phase 135 F-2), and that posture
/// depends on no provider being present when none was supplied.
#[test]
fn no_injected_lookup_leaves_both_sides_unable_to_evaluate() {
    let server = DnsServer::new(with_firewall(support::dns_runtime()), None, None);

    let context = server.query_context();
    assert!(
        context.geoip_lookup.is_none(),
        "no capability may be fabricated when none was injected"
    );

    let firewall = context.firewall.as_ref().expect("firewall enabled");
    assert!(
        !firewall.read().can_evaluate_geo_rules(),
        "a firewall with no provider must report that it cannot evaluate geo rules"
    );
}

/// A disabled firewall is not a place a provider could hide. This pins that
/// enabling the capability and enabling the firewall stay independent decisions,
/// so a future change cannot quietly couple them.
#[test]
fn the_capability_is_injected_even_when_the_firewall_is_disabled() {
    let server = DnsServer::new(
        support::dns_runtime(),
        None,
        Some(Arc::new(FixedLookup { country: "RU" })),
    );

    let context = server.query_context();
    assert!(
        context.geoip_lookup.is_some(),
        "the server keeps the capability"
    );
    assert!(
        context.firewall.is_none(),
        "a disabled firewall is not constructed, so there is nothing to wire"
    );
}

/// `DnsServer` is `Clone`, and the cloned server must not lose the capability —
/// the mesh path clones the server, so a clone that dropped the handle would
/// reintroduce exactly the dead seam this phase removed.
#[test]
fn cloning_the_server_preserves_the_capability() {
    let server = DnsServer::new(
        with_firewall(support::dns_runtime()),
        None,
        Some(Arc::new(FixedLookup { country: "RU" })),
    );

    let cloned = server.clone();
    let context = cloned.query_context();
    assert!(
        context.geoip_lookup.is_some(),
        "a cloned DnsServer must keep the injected capability"
    );
    let firewall = context
        .firewall
        .as_ref()
        .expect("firewall enabled on the clone");
    assert!(
        firewall.read().can_evaluate_geo_rules(),
        "and must keep the firewall's separate capability"
    );
}
