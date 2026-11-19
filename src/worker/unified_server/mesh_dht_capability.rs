//! Phase 139 — composition adapters for the DNS-owned mesh DHT capabilities.
//!
//! `synvoid-dns` declares the traits (`synvoid_dns::mesh_sync::dht_capability`)
//! and this is where they are implemented, over the concrete `synvoid-mesh`
//! types. The inversion is only complete when the concrete types appear *here*
//! and nowhere in the request path.
//!
//! ## The interesting one
//!
//! [`DhtRecordStoreAdapter::is_anycast_advertisement_authentic`] is where the
//! seam would have leaked. Before Phase 139, DNS built a
//! `SignedDhtRecord` itself and called a verifier obtained from the store, so a
//! mesh record type appeared in DNS's own call body. Now DNS hands over the
//! advertised fields and gets a `bool`; building and verifying the signed record
//! is the provider's business.
//!
//! ## Trust boundary
//!
//! `architecture/distributed_state_contract.md` holds that the DHT answers
//! "what has been advertised" and must never become policy authority. This
//! adapter is a **read of advertisements** and preserves the distinction: an
//! advertisement is surfaced unverified via
//! [`DhtRecordStore::all_anycast_advertisements`], and authenticity is a
//! separate call the DNS caller must make. An unsigned advertisement, or a
//! provider with no verifier, is reported as **not authentic** — absence of a
//! check is never treated as success.
//!
//! The domain-registration half is stricter on purpose:
//! [`DhtRecordStore::is_domain_registration_authentic`] returns `false` for
//! every registration until mesh Phase 04b binds a record's signer to its
//! publisher. See that method's documentation.

use std::sync::Arc;

use async_trait::async_trait;
use synvoid_dns::mesh_sync::dht_capability::{
    AdvertisedAnycastNode, AdvertisedAnycastRecord, AdvertisedDomainRegistration, DhtGlobalLocator,
    DhtGlobalPeer, DhtRecordStore,
};
use synvoid_mesh::dht::routing::manager::DhtRoutingManager;
use synvoid_mesh::dht::RecordStoreManager;

/// Adapts the concrete `RecordStoreManager` to the DNS-owned capability.
pub struct DhtRecordStoreAdapter(Arc<RecordStoreManager>);

impl DhtRecordStoreAdapter {
    /// Erase the concrete `RecordStoreManager` into the DNS-owned capability.
    ///
    /// Named `from_store` rather than `new` because this is a conversion, not a
    /// constructor: the return type is the trait object, not `Self`.
    pub fn from_store(store: Arc<RecordStoreManager>) -> Arc<dyn DhtRecordStore> {
        Arc::new(Self(store))
    }
}

impl DhtRecordStore for DhtRecordStoreAdapter {
    fn all_dns_domain_registrations(&self) -> Vec<AdvertisedDomainRegistration> {
        self.0
            .get_all_dns_domain_registrations()
            .into_iter()
            .map(|record| AdvertisedDomainRegistration {
                domain: record.domain,
                origin_node_id: record.origin_node_id,
                ip_addresses: record.ip_addresses,
                publisher_id: record.publisher_id,
                signature: record.signature,
                created_at: record.created_at,
                ttl_seconds: record.ttl_seconds,
            })
            .collect()
    }

    fn all_anycast_advertisements(&self) -> Vec<AdvertisedAnycastRecord> {
        self.0
            .get_all_anycast_records()
            .into_iter()
            .map(|record| AdvertisedAnycastRecord {
                key: record.key,
                value: record.value,
                publisher_id: record.source_node_id.clone(),
                signature: record.signature,
                created_at: record.timestamp,
                ttl_seconds: record.ttl_seconds,
                source_node_id: record.source_node_id,
                signer_public_key: record.signer_public_key,
            })
            .collect()
    }

    fn anycast_nodes_for_zone(&self, zone: &str) -> Vec<AdvertisedAnycastNode> {
        self.0
            .get_anycast_nodes_for_zone(zone)
            .into_iter()
            .map(|node| AdvertisedAnycastNode {
                node_id: node.node_id,
                anycast_ips: node.anycast_ips,
                geo: node.geo,
                capacity: node.capacity,
                healthy: node.healthy,
                dns_zones: node.dns_zones,
                registered_at: node.registered_at,
            })
            .collect()
    }

    /// Builds the signed record here, on the provider side, and asks the
    /// provider's own verifier.
    ///
    /// The early returns are all deliberate and all report "not authentic":
    /// an unsigned advertisement, an advertisement with no signer key, an empty
    /// signer key, and a store with no verifier. Collapsing them into `false`
    /// means the DNS caller has exactly one thing to check, and cannot mistake
    /// "there was nothing to verify" for "verification passed".
    fn is_anycast_advertisement_authentic(&self, advertisement: &AdvertisedAnycastRecord) -> bool {
        if advertisement.signature.is_empty() {
            tracing::warn!(
                key = %advertisement.key,
                "anycast advertisement is unsigned; treating as unauthenticated"
            );
            return false;
        }

        let Some(signer_key) = advertisement
            .signer_public_key
            .as_ref()
            .filter(|key| !key.is_empty())
        else {
            tracing::warn!(
                key = %advertisement.key,
                "anycast advertisement carries no signer key; treating as unauthenticated"
            );
            return false;
        };

        let signed = synvoid_mesh::dht::SignedDhtRecord {
            key: advertisement.key.clone(),
            value: advertisement.value.clone(),
            publisher_id: advertisement.publisher_id.clone(),
            signature: advertisement.signature.clone(),
            created_at: advertisement.created_at,
            expires_at: Some(advertisement.created_at + advertisement.ttl_seconds),
            record_type: synvoid_mesh::dht::SignedRecordType::AnycastNode,
            sequence_number: 0,
            source_node_id: advertisement.source_node_id.clone(),
            ttl_seconds: advertisement.ttl_seconds,
            signer_public_key: Some(signer_key.clone()),
        };

        match self.0.get_record_verifier() {
            Some(verifier) => verifier.verify(&signed),
            None => {
                tracing::warn!(
                    key = %advertisement.key,
                    "no record verifier is configured; treating as unauthenticated"
                );
                false
            }
        }
    }

    fn store_dns_domain_registration(
        &self,
        domain: String,
        origin_node_id: String,
        ip_addresses: Vec<String>,
        ttl_seconds: u64,
    ) -> bool {
        self.0
            .store_dns_domain_registration(domain, origin_node_id, ip_addresses, ttl_seconds)
    }

    /// Fail closed until mesh Phase 04b lands.
    ///
    /// The store verifies a DHT record against the record's own
    /// `signer_public_key`, without binding that key to `source_node_id`.
    /// "The signature verifies" therefore means "whoever published this signed
    /// it", not "the node claiming the domain signed it" — the gap campaign
    /// finding B4 fixed in mesh 04b. Reporting `true` here would hand DNS a
    /// trust claim the mesh layer has not earned, so composition reports
    /// `false` for every registration. The publisher-binding check in
    /// `sync_from_dht` is independent and still runs; a future provider
    /// override must not be a second signature scheme.
    fn is_domain_registration_authentic(
        &self,
        registration: &AdvertisedDomainRegistration,
    ) -> bool {
        if registration.signature.is_empty() {
            tracing::warn!(
                domain = %registration.domain,
                "domain registration is unsigned; treating as unauthenticated"
            );
            return false;
        }

        tracing::warn!(
            domain = %registration.domain,
            publisher = %registration.publisher_id,
            origin = %registration.origin_node_id,
            "domain registration authenticity is unavailable until mesh Phase 04b \
             binds the signer to the publisher; treating as unauthenticated"
        );
        false
    }

    fn store_anycast_node(
        &self,
        node_id: String,
        anycast_ips: Vec<String>,
        geo: Option<String>,
        capacity: u32,
        healthy: bool,
        dns_zones: Vec<String>,
    ) -> bool {
        self.0
            .store_anycast_node(node_id, anycast_ips, geo, capacity, healthy, dns_zones)
    }

    fn remove_anycast_node(&self, node_id: &str) -> bool {
        self.0.remove_anycast_node(node_id)
    }
}

/// Adapts the concrete `DhtRoutingManager` to the DNS-owned capability.
pub struct DhtGlobalLocatorAdapter(Arc<DhtRoutingManager>);

impl DhtGlobalLocatorAdapter {
    /// Erase the concrete `DhtRoutingManager` into the DNS-owned capability.
    pub fn from_manager(manager: Arc<DhtRoutingManager>) -> Arc<dyn DhtGlobalLocator> {
        Arc::new(Self(manager))
    }
}

#[async_trait]
impl DhtGlobalLocator for DhtGlobalLocatorAdapter {
    async fn find_closest_global(&self, count: usize) -> Vec<DhtGlobalPeer> {
        self.0
            .find_closest_global(count)
            .await
            .into_iter()
            .map(|node| DhtGlobalPeer {
                node_id: node.node_id.to_string(),
            })
            .collect()
    }
}

/// Attach the DHT capabilities to a registry, when mesh actually built them.
///
/// Both handles are `Option`: the DHT record store is only created when the
/// mesh is configured for it, and the routing manager only when
/// `dht.routing_enabled` is set. An absent one leaves the registry with no
/// capability, which is the correct state — every read site is guarded, and a
/// missing DHT degrades to "no advertisements" rather than to an error.
///
/// Kept as a function because both the edge and global wiring sites need it, and
/// repeating the `Option` match twice was where the first attempt went wrong.
pub fn attach_dht_capabilities(
    registry: synvoid_dns::mesh_sync::MeshDnsRegistry,
    record_store: Option<Arc<RecordStoreManager>>,
    routing_manager: Option<Arc<DhtRoutingManager>>,
) -> synvoid_dns::mesh_sync::MeshDnsRegistry {
    let registry = match record_store {
        Some(store) => registry.with_dht_record_store(DhtRecordStoreAdapter::from_store(store)),
        None => registry,
    };
    match routing_manager {
        Some(manager) => {
            registry.with_routing_manager(DhtGlobalLocatorAdapter::from_manager(manager))
        }
        None => registry,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The adapters are constructible and dyn-safe, which is the whole point of
    /// the inversion: the DNS crate holds `Arc<dyn …>`, and these are the only
    /// places the concrete types appear.
    ///
    /// They are built over a real (empty) store rather than a double, so a
    /// signature drift on the provider side fails here at compile time instead
    /// of at a wiring site.
    #[test]
    fn both_adapters_are_constructible() {
        let mesh_config = synvoid_mesh::config::MeshConfig::default();
        let store = Arc::new(RecordStoreManager::new(
            Default::default(),
            "test-node".to_string(),
            synvoid_mesh::config::MeshNodeRole::EDGE,
            None,
            synvoid_mesh::dht::DhtAccessControl::new(&mesh_config),
            None,
        ));
        let capability = DhtRecordStoreAdapter::from_store(Arc::clone(&store));
        // A store with no verifier must not report an unsigned advertisement as
        // authentic — the trust boundary must hold even in a degenerate config.
        assert!(capability.all_dns_domain_registrations().is_empty());
        assert!(capability.anycast_nodes_for_zone("example.com").is_empty());
        assert!(!capability.is_anycast_advertisement_authentic(&unsigned()));
        assert!(
            !capability.is_domain_registration_authentic(&unsigned_registration()),
            "a registration cannot be authentic before mesh Phase 04b binds the \
             signer to the publisher; returning true here would be an unearned \
             trust claim"
        );
        assert!(
            !capability.has_domain_authorization_claim(&unsigned_registration()),
            "no org-key domain claim exists today; authorization defaults to deny"
        );
    }

    fn unsigned() -> AdvertisedAnycastRecord {
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

    fn unsigned_registration() -> AdvertisedDomainRegistration {
        AdvertisedDomainRegistration {
            domain: "example.com".to_string(),
            origin_node_id: "origin-1".to_string(),
            ip_addresses: vec!["203.0.113.10".to_string()],
            publisher_id: "origin-1".to_string(),
            signature: Vec::new(),
            created_at: 1,
            ttl_seconds: 600,
        }
    }
}
