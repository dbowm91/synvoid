//! Phase 139 — DNS-owned capabilities for the mesh DHT (Workstream B inversion).
//!
//! ## What this is
//!
//! `MeshDnsRegistry` used to hold two concrete `synvoid-mesh` types:
//! `RecordStoreManager` and `DhtRoutingManager`. Both are now `Arc<dyn …>` of
//! the DNS-owned traits below, implemented in composition. `synvoid-dns` still
//! links `synvoid-mesh` for the protobuf and the *live* verification transport;
//! what this module removes is the **advisory DHT surface** naming concrete
//! provider types.
//!
//! ## Why every method takes and returns DNS-owned types
//!
//! The inversion is only real if no `synvoid-mesh` type appears in a trait
//! signature. Two provider methods forced projection rather than a direct
//! signature change:
//!
//! - `get_anycast_nodes_for_zone` returns `Vec<AnycastNode>` and
//!   `get_all_anycast_records` returns `Vec<DhtRecord>`. Returning them would
//!   have kept the concrete types in the seam, so the traits return the
//!   projections [`AdvertisedAnycastNode`] and [`AdvertisedAnycastRecord`].
//! - `get_record_verifier().verify(&SignedDhtRecord)` needs DNS to *construct*
//!   the signed record. That is the seam's hardest case, and it is resolved by
//!   inverting the direction of the question: instead of DNS building a record
//!   and asking a verifier, DNS hands over the fields it read and asks
//!   **whether the advertisement is authentic**
//!   ([`DhtRecordStore::is_anycast_advertisement_authentic`]). The provider owns
//!   constructing `SignedDhtRecord` and running the verifier.
//!
//! ## The binding contract
//!
//! `architecture/distributed_state_contract.md` holds: the DHT answers "what has
//! been advertised?" and must never become policy authority or a fallback. This
//! trait is a **read of advertisements**, and Phase 139's wiring is the case
//! that needed an explicit, narrow amendment to that contract — see
//! `architecture/dns_provider_inversion_phase139_closeout.md`.
//!
//! The types here are deliberately inert data. No behaviour, no I/O, no
//! provider state.

use async_trait::async_trait;

/// A mesh peer returned by a global-node routing lookup.
///
/// DNS needs only the identity; the provider decides what "closest" means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtGlobalPeer {
    pub node_id: String,
}

/// A DNS-owned projection of an anycast node advertisement.
#[derive(Debug, Clone)]
pub struct AdvertisedAnycastNode {
    pub node_id: String,
    pub anycast_ips: Vec<String>,
    pub geo: Option<String>,
    pub capacity: u32,
    pub healthy: bool,
    pub dns_zones: Vec<String>,
    pub registered_at: u64,
}

/// A DNS-owned projection of an origin-domain advertisement.
#[derive(Debug, Clone)]
pub struct AdvertisedDomainRegistration {
    pub domain: String,
    pub origin_node_id: String,
    pub ip_addresses: Vec<String>,
}

/// The fields of an advertised anycast record, exactly as DNS reads them.
///
/// This is **not** a mesh record. It carries the raw material so the provider
/// can build and verify whatever signed type it uses, without DNS naming it.
#[derive(Debug, Clone)]
pub struct AdvertisedAnycastRecord {
    pub key: String,
    pub value: Vec<u8>,
    pub publisher_id: String,
    pub signature: Vec<u8>,
    pub created_at: u64,
    pub ttl_seconds: u64,
    pub source_node_id: String,
    /// Absent when the advertisement is unsigned, which is itself meaningful:
    /// an unsigned advertisement is not authenticated. Carried as the
    /// provider's own string encoding rather than re-encoded to bytes, so the
    /// projection loses nothing on the way to verification.
    pub signer_public_key: Option<String>,
}

/// Read and write access to mesh-advertised DNS state.
///
/// Every method is a thin projection of one `RecordStoreManager` method. The
/// `bool` returns are the provider's own acceptance decision — for example
/// `store_dns_domain_registration` refuses on a non-global node — and are passed
/// through unchanged rather than reinterpreted, so DNS never has to re-derive
/// the provider's own admission rules.
pub trait DhtRecordStore: Send + Sync {
    /// Every origin-domain advertisement the DHT currently holds.
    fn all_dns_domain_registrations(&self) -> Vec<AdvertisedDomainRegistration>;

    /// Every anycast advertisement the DHT currently holds, unverified.
    ///
    /// Authenticity is a separate question — see
    /// [`Self::is_anycast_advertisement_authentic`]. Returning them raw is what
    /// makes that separation possible, and the DNS caller must ask before it
    /// trusts one.
    fn all_anycast_advertisements(&self) -> Vec<AdvertisedAnycastRecord>;

    /// Advertised anycast nodes for one zone.
    fn anycast_nodes_for_zone(&self, zone: &str) -> Vec<AdvertisedAnycastNode>;

    /// Whether an advertisement is authentic.
    ///
    /// Returns `false` for an unsigned advertisement, and `false` when the
    /// provider has no verifier available — the caller must treat both as
    /// "not authenticated" rather than inferring trust from absence.
    fn is_anycast_advertisement_authentic(&self, advertisement: &AdvertisedAnycastRecord) -> bool;

    fn store_dns_domain_registration(
        &self,
        domain: String,
        origin_node_id: String,
        ip_addresses: Vec<String>,
        ttl_seconds: u64,
    ) -> bool;

    fn store_anycast_node(
        &self,
        node_id: String,
        anycast_ips: Vec<String>,
        geo: Option<String>,
        capacity: u32,
        healthy: bool,
        dns_zones: Vec<String>,
    ) -> bool;

    fn remove_anycast_node(&self, node_id: &str) -> bool;
}

/// Locating global nodes through the mesh routing table.
///
/// One method, because DNS uses one. This is the narrowest seam in the crate,
/// and it is the clearest example of why the concrete `DhtRoutingManager` was
/// never needed here: DNS asks "who are the nearest global nodes", not anything
/// about routing policy, penalties, or the routing table itself.
#[async_trait]
pub trait DhtGlobalLocator: Send + Sync {
    async fn find_closest_global(&self, count: usize) -> Vec<DhtGlobalPeer>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// The seam is only inverted if a provider type can be substituted and the
    /// call sites cannot tell. A double proves both traits are dyn-safe and
    /// usable as `Arc<dyn …>`, which is the shape every field uses.
    #[test]
    fn both_capabilities_are_usable_as_trait_objects() {
        let store: Arc<dyn DhtRecordStore> = Arc::new(EmptyStore);

        assert!(store.all_dns_domain_registrations().is_empty());
        assert!(store.all_anycast_advertisements().is_empty());
        assert!(store.anycast_nodes_for_zone("example.com").is_empty());
        assert!(!store.is_anycast_advertisement_authentic(&unauthenticated()));
    }

    /// The locator trait is `async`; dyn-safety under `#[async_trait]` is the
    /// property that matters, since the only field holding it is an
    /// `Arc<dyn …>`. A real poll pins that.
    #[tokio::test]
    async fn locator_is_dyn_safe_through_an_async_trait_object() {
        let locator: Arc<dyn DhtGlobalLocator> = Arc::new(EmptyLocator);
        assert!(locator.find_closest_global(4).await.is_empty());
    }

    struct EmptyStore;

    impl DhtRecordStore for EmptyStore {
        fn all_dns_domain_registrations(&self) -> Vec<AdvertisedDomainRegistration> {
            Vec::new()
        }
        fn all_anycast_advertisements(&self) -> Vec<AdvertisedAnycastRecord> {
            Vec::new()
        }
        fn anycast_nodes_for_zone(&self, _zone: &str) -> Vec<AdvertisedAnycastNode> {
            Vec::new()
        }
        fn is_anycast_advertisement_authentic(
            &self,
            _advertisement: &AdvertisedAnycastRecord,
        ) -> bool {
            false
        }
        fn store_dns_domain_registration(
            &self,
            _domain: String,
            _origin_node_id: String,
            _ip_addresses: Vec<String>,
            _ttl_seconds: u64,
        ) -> bool {
            false
        }
        fn store_anycast_node(
            &self,
            _node_id: String,
            _anycast_ips: Vec<String>,
            _geo: Option<String>,
            _capacity: u32,
            _healthy: bool,
            _dns_zones: Vec<String>,
        ) -> bool {
            false
        }
        fn remove_anycast_node(&self, _node_id: &str) -> bool {
            false
        }
    }

    struct EmptyLocator;

    #[async_trait]
    impl DhtGlobalLocator for EmptyLocator {
        async fn find_closest_global(&self, _count: usize) -> Vec<DhtGlobalPeer> {
            Vec::new()
        }
    }

    /// An unsigned advertisement carries no signer key, and the capability must
    /// treat that as "not authenticated" rather than "nothing to check".
    fn unauthenticated() -> AdvertisedAnycastRecord {
        AdvertisedAnycastRecord {
            key: "anycast_node:edge-1".to_string(),
            value: b"{}".to_vec(),
            publisher_id: "edge-1".to_string(),
            signature: Vec::new(),
            created_at: 1,
            ttl_seconds: 600,
            source_node_id: "edge-1".to_string(),
            signer_public_key: None,
        }
    }
}
