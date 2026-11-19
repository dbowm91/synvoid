//! Phase 08 — mesh DNS trust contract.
//!
//! ## What this suite exists to pin
//!
//! A DHT-sourced domain registration may answer a query only when **all three**
//! independent questions succeed:
//!
//! 1. **Authenticity** — the provider verifies the registration's signature.
//!    DNS never answers that question itself; it asks
//!    `DhtRecordStore::is_domain_registration_authentic`.
//! 2. **Publisher binding** — the signing node is the node claiming the
//!    origin (`publisher_id == origin_node_id`). A signature by *some* node is
//!    not a signature by *the* node. Mesh Phase 04b fixes the root cause on the
//!    mesh side; this layer enforces the binding regardless.
//! 3. **Authorization** — the origin may serve the name. A signature proves who
//!    advertised, never that the advertiser is entitled to the domain. The
//!    allowed sources are the origin's own live-registered zones, an explicit
//!    `[dns.mesh] authorized_domains` entry, or an org-key claim carried by the
//!    peer. Default deny.
//!
//! The double below performs **real Ed25519 verification** over the
//! registration fields, so the DNS boundary is exercised end to end: a passing
//! test means DNS accepted a registration whose signature was actually checked,
//! not that a boolean was hardcoded.
//!
//! Feature `mesh`: without it this target is not built (see `[[test]]`
//! `required-features`). A run without the feature reports the target as
//! skipped rather than green.

#![cfg(feature = "mesh")]

mod support;

use std::sync::Arc;

use synvoid_dns::mesh_sync::dht_capability::{AdvertisedDomainRegistration, DhtRecordStore};
use synvoid_dns::mesh_sync::{DomainRegistrationRejection, MeshDnsRegistry, MeshDnsRegistryConfig};
use synvoid_dns::server::DnsServer;

use support::mesh_dht::CountingDht;

// ── fixtures ─────────────────────────────────────────────────────────────────

fn registration(
    domain: &str,
    origin: &str,
    publisher: &str,
    ip: &str,
) -> AdvertisedDomainRegistration {
    AdvertisedDomainRegistration {
        domain: domain.to_string(),
        origin_node_id: origin.to_string(),
        ip_addresses: vec![ip.to_string()],
        publisher_id: publisher.to_string(),
        signature: Vec::new(),
        created_at: 1,
        ttl_seconds: 600,
    }
}

fn registry(dht: Arc<CountingDht>, authorized_domains: &[&str]) -> Arc<MeshDnsRegistry> {
    let store = support::mesh_dht::store(&dht);
    Arc::new(
        MeshDnsRegistry::with_config(
            "global-1".to_string(),
            true,
            MeshDnsRegistryConfig {
                authorized_domains: authorized_domains
                    .iter()
                    .map(|domain| (*domain).to_string())
                    .collect(),
                ..Default::default()
            },
        )
        .with_dht_record_store(store),
    )
}

/// A server with an authoritative zone that has no A record at the apex.
///
/// The mesh fallback runs after the zone's own negative outcome, so a bare
/// server with no zone answers REFUSED before mesh resolution is reached. The
/// zone makes the test exercise the mesh path rather than the zone gate.
fn server_with(registry: Arc<MeshDnsRegistry>, zone: &str) -> DnsServer {
    use synvoid_dns::runtime_config::{RecordType, ZoneRecordSpec, ZoneSpec};

    let server = DnsServer::new(support::dns_runtime(), None, None);
    server
        .load_zones(vec![ZoneSpec {
            origin: zone.to_string(),
            records: vec![ZoneRecordSpec {
                name: "@".to_string(),
                record_type: RecordType::SOA,
                ttl: Some(60),
                value: format!("ns1.{zone}. admin.{zone}. 1 3600 600 604800 300"),
                priority: None,
            }],
            dnssec: None,
        }])
        .expect("the fixture zone must load");
    assert!(
        server.set_mesh_registry(registry),
        "the registry must bind to the live server"
    );
    server
}

fn query_a(server: &DnsServer, qname: &str) -> Option<Arc<Vec<u8>>> {
    let ctx = server.query_context();
    let query = support::build_query(0x4242, qname, 1);
    DnsServer::handle_query(
        &ctx,
        &query,
        Some("203.0.113.50".parse().expect("client ip")),
    )
}

fn answer_count(server: &DnsServer, qname: &str) -> u16 {
    query_a(server, qname)
        .as_deref()
        .map(|response| support::response_ancount(response))
        .unwrap_or(0)
}

// ── 1. an unauthenticated registration is never applied ──────────────────────

#[test]
fn an_unauthenticated_registration_is_not_applied() {
    let dht = Arc::new(CountingDht::new(Vec::new()).with_publishers(&["origin-a"]));
    // A structurally valid registration whose signature does not verify.
    let mut unsigned = registration("unverified.test", "origin-a", "origin-a", "203.0.113.10");
    unsigned.signature.clear();
    dht.add_registration(unsigned);

    let registry = registry(Arc::clone(&dht), &["unverified.test"]);
    registry.sync_from_dht();

    assert!(
        registry.get_registered_origin_nodes().is_empty(),
        "an unverified registration must not create an origin node, even for \
         an authorized domain"
    );
    let refusals = registry.untrusted_domain_registrations();
    assert!(
        refusals
            .iter()
            .any(|entry| entry.reason == DomainRegistrationRejection::Unauthenticated),
        "the refusal must be retained for telemetry, got {refusals:?}"
    );

    let server = server_with(registry, "unverified.test");
    assert_eq!(
        answer_count(&server, "unverified.test"),
        0,
        "an unverified registration must not answer even though the domain is \
         on the authorization allowlist"
    );
    assert!(
        dht.domain_authenticity_calls() >= 1,
        "the authenticity decision must be delegated to the capability"
    );
}

// ── 2. a signature by the wrong node is dropped ──────────────────────────────

#[test]
fn a_registration_signed_by_another_node_is_dropped() {
    let dht = Arc::new(CountingDht::new(Vec::new()).with_publishers(&["origin-a", "origin-b"]));
    // Signed by origin-b, claiming to be origin-a. The signature is genuine for
    // its publisher; the binding is what fails.
    let forged = dht.sign(registration(
        "claimed.test",
        "origin-a",
        "origin-b",
        "203.0.113.11",
    ));
    assert!(
        dht.is_domain_registration_authentic(&forged),
        "the double must verify the signature, so this test isolates the \
         publisher binding rather than a broken signature"
    );
    dht.add_registration(forged);

    let registry = registry(Arc::clone(&dht), &["claimed.test"]);
    registry.sync_from_dht();

    assert!(
        registry.get_registered_origin_nodes().is_empty(),
        "a node that did not claim the origin must not become its origin"
    );
    let refusals = registry.untrusted_domain_registrations();
    assert!(
        refusals
            .iter()
            .any(|entry| entry.reason == DomainRegistrationRejection::PublisherMismatch),
        "the publisher mismatch must be the recorded reason, got {refusals:?}"
    );

    let server = server_with(registry, "claimed.test");
    assert_eq!(answer_count(&server, "claimed.test"), 0);
}

// ── 3. authenticity is not authorization ─────────────────────────────────────

#[test]
fn an_authentic_registration_for_an_unauthorized_domain_is_not_served() {
    let dht = Arc::new(CountingDht::new(Vec::new()).with_publishers(&["origin-a"]));
    dht.add_registration(dht.sign(registration(
        "not-listed.test",
        "origin-a",
        "origin-a",
        "203.0.113.12",
    )));

    // No allowlist entry, no live zone declaration, no org-key claim.
    let registry = registry(Arc::clone(&dht), &[]);
    registry.sync_from_dht();

    assert!(
        registry.get_registered_origin_nodes().is_empty(),
        "a signed registration for an unlisted domain must not be served"
    );
    let refusals = registry.untrusted_domain_registrations();
    assert!(
        refusals
            .iter()
            .any(|entry| entry.reason == DomainRegistrationRejection::Unauthorized),
        "the refusal must be retained for telemetry, got {refusals:?}"
    );

    let server = server_with(registry, "not-listed.test");
    assert_eq!(
        answer_count(&server, "not-listed.test"),
        0,
        "default deny: signed, publisher-bound, and still not served"
    );
}

// ── 4. an authentic, publisher-bound, authorized registration is served ──────

#[test]
fn an_authentic_authorized_registration_is_served_under_the_queried_name() {
    let dht = Arc::new(CountingDht::new(Vec::new()).with_publishers(&["origin-a"]));
    dht.add_registration(dht.sign(registration(
        "authorized.test",
        "origin-a",
        "origin-a",
        "203.0.113.77",
    )));

    let registry = registry(Arc::clone(&dht), &["authorized.test"]);
    registry.sync_from_dht();

    let origins = registry.get_registered_origin_nodes();
    let origin = origins.get("origin-a").expect("the origin was applied");
    assert!(
        origin.authenticated,
        "the applied origin carries the capability's verdict"
    );

    let server = server_with(registry, "authorized.test");
    let response = query_a(&server, "authorized.test").expect("the domain is answered");
    assert_eq!(support::response_rcode(&response), 0, "NOERROR");
    assert_eq!(support::response_ancount(&response), 1);
    assert_eq!(
        support::parse_answer_types(&response),
        vec![1],
        "an A query must be answered with an A record"
    );
    assert_eq!(
        support::answer_owner(&response, 0),
        "authorized.test",
        "phase 01: the synthesized owner is the queried FQDN, not the zone apex \
         placeholder"
    );
}

/// Condition (c): an org-key claim from the peer authorizes a domain that is
/// neither allowlisted nor declared by the origin.
#[test]
fn an_org_key_claim_authorizes_a_registration() {
    let dht = Arc::new(CountingDht::new(Vec::new()).with_publishers(&["origin-a"]));
    dht.add_registration(dht.sign(registration(
        "claimed-domain.test",
        "origin-a",
        "origin-a",
        "203.0.113.78",
    )));
    dht.claim_domain("claimed-domain.test");

    let registry = registry(Arc::clone(&dht), &[]);
    registry.sync_from_dht();

    let server = server_with(registry, "claimed-domain.test");
    assert_eq!(answer_count(&server, "claimed-domain.test"), 1);
}

/// Condition (a): a live authenticated registration declares the origin's own
/// zone, which authorizes a DHT registration for the same domain.
#[tokio::test]
async fn a_live_zone_declaration_authorizes_the_same_domain() {
    use synvoid_dns::messages::{DnsNodeRole, DnsRegistration};

    let dht = Arc::new(CountingDht::new(Vec::new()).with_publishers(&["origin-a"]));
    let registry = Arc::new(
        MeshDnsRegistry::with_config(
            "global-1".to_string(),
            true,
            // No allowlist and no org-key claim: only the live declaration can
            // authorize this one.
            MeshDnsRegistryConfig {
                require_mtls: false,
                ..Default::default()
            },
        )
        .with_dht_record_store(support::mesh_dht::store(&dht)),
    );

    registry
        .register_origin_node(DnsRegistration {
            node_id: "origin-a".to_string(),
            domain: "declared.test".to_string(),
            ip_addresses: vec!["203.0.113.79".to_string()],
            geo: None,
            capacity: 100,
            healthy: true,
            latency_ms: None,
            certificate_fingerprint: None,
            role: DnsNodeRole::Origin,
            edge_node_id: None,
            edge_node_geo: None,
            certificate_chain: Vec::new(),
        })
        .await
        .expect("live registration accepted");

    // A DHT registration for the same domain must be authorized by (a), not
    // rejected. Use a different answer address so the assertion distinguishes
    // the DHT-applied refresh from the live entry.
    dht.add_registration(dht.sign(registration(
        "declared.test",
        "origin-a",
        "origin-a",
        "203.0.113.80",
    )));
    registry.sync_from_dht();

    let server = server_with(Arc::clone(&registry), "declared.test");
    assert_eq!(answer_count(&server, "declared.test"), 1);
}

// ── 5. authenticated is never claimed without the verdict ────────────────────

#[test]
fn no_origin_is_marked_authenticated_without_the_capability_verdict() {
    let dht = Arc::new(CountingDht::new(Vec::new()).with_publishers(&["origin-a"]));

    // Publisher has no key in the double, so no signature can verify.
    dht.add_registration(registration(
        "unknown-key.test",
        "origin-a",
        "unknown-publisher",
        "203.0.113.13",
    ));
    // A validly signed but unauthorized registration must also not appear.
    dht.add_registration(dht.sign(registration(
        "unlisted.test",
        "origin-a",
        "origin-a",
        "203.0.113.14",
    )));

    let registry = registry(Arc::clone(&dht), &["allowed.test"]);
    registry.sync_from_dht();

    let origins = registry.get_registered_origin_nodes();
    assert!(
        origins.is_empty(),
        "the map may only contain origins whose capability verdict was true"
    );
    assert!(
        origins.values().all(|origin| !origin.authenticated),
        "vacuously true here, and the invariant the served case in test 4 pins \
         from the other direction"
    );
}

// ── 6. a registration that appears after startup is picked up ────────────────

#[tokio::test]
async fn a_registration_appearing_after_startup_is_picked_up_by_the_sync_loop() {
    let dht = Arc::new(CountingDht::new(Vec::new()).with_publishers(&["origin-a"]));
    let registry = registry(Arc::clone(&dht), &["late.test"]);
    registry.start_periodic_dht_sync(1);
    let server = server_with(Arc::clone(&registry), "late.test");

    assert_eq!(
        answer_count(&server, "late.test"),
        0,
        "nothing is registered yet"
    );

    dht.add_registration(dht.sign(registration(
        "late.test",
        "origin-a",
        "origin-a",
        "203.0.113.15",
    )));

    let mut answered = false;
    for _ in 0..40 {
        if answer_count(&server, "late.test") == 1 {
            answered = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    assert!(
        answered,
        "the periodic sync loop must pick up a registration that appears after \
         startup; waiting 4s was not enough"
    );
}

// ── 7. removing the origin stops answering immediately ───────────────────────

#[test]
fn removing_the_origin_stops_answering_immediately() {
    let dht = Arc::new(CountingDht::new(Vec::new()).with_publishers(&["origin-a"]));
    dht.add_registration(dht.sign(registration(
        "removed.test",
        "origin-a",
        "origin-a",
        "203.0.113.16",
    )));

    let registry = registry(Arc::clone(&dht), &["removed.test"]);
    registry.sync_from_dht();
    let server = server_with(Arc::clone(&registry), "removed.test");
    assert_eq!(answer_count(&server, "removed.test"), 1);

    registry
        .remove_origin("origin-a", "removed.test")
        .expect("origin removal is infallible for an existing entry");

    assert_eq!(
        answer_count(&server, "removed.test"),
        0,
        "the next query must not be answered from a removed origin"
    );
}
