//! Fixture contract for the two-node loopback mesh harness.
//!
//! These tests pin the properties every later harness test depends on: two
//! distinct realized identities, leaves whose SANs carry the realized id and
//! loopback, and strict mutual-peer configs. They stop at configuration; no
//! transport is assembled here.

mod support;

use support::fixture::{two_node_pair, FixtureNode, TwoNodePair, SERVICE_ID};
use synvoid_mesh::mesh::config::{MeshNodeRole, MeshTlsMode};
use x509_parser::prelude::GeneralName;

const LOOPBACK_V4: [u8; 4] = [127, 0, 0, 1];

fn both(pair: &TwoNodePair) -> [&FixtureNode; 2] {
    [&pair.origin, &pair.edge]
}

#[test]
fn fixture_realizes_two_distinct_identities() {
    let pair = two_node_pair();

    assert_ne!(pair.origin.node_id, pair.edge.node_id);
    assert_ne!(pair.origin.identity_path, pair.edge.identity_path);
    assert_ne!(pair.origin.cert_path, pair.edge.cert_path);
    assert_ne!(pair.origin.key_path, pair.edge.key_path);

    for node in both(&pair) {
        assert!(
            node.node_id.starts_with("node-"),
            "realized id {} is not node-prefixed",
            node.node_id
        );
        assert!(
            node.identity_path.starts_with(node.dir.path()),
            "identity {} escapes its node dir",
            node.identity_path.display()
        );
        assert!(
            node.identity_path.is_file(),
            "identity {} missing",
            node.identity_path.display()
        );
        assert!(node.cert_path.is_file(), "leaf cert missing");
        assert!(node.key_path.is_file(), "leaf key missing");
        assert!(node.ca_path.is_file(), "CA anchor missing");
    }

    // No shared key material: each node wrote its own secret.
    let origin_key = std::fs::read(&pair.origin.identity_path).expect("read origin identity");
    let edge_key = std::fs::read(&pair.edge.identity_path).expect("read edge identity");
    assert_ne!(origin_key, edge_key);
}

#[test]
fn fixture_certificates_carry_node_id_sans() {
    let pair = two_node_pair();

    for node in both(&pair) {
        let ca_pem = std::fs::read(&node.ca_path).expect("read CA anchor");
        let (_, ca_pem) = x509_parser::pem::parse_x509_pem(&ca_pem).expect("CA anchor is PEM");
        let (_, ca) =
            x509_parser::parse_x509_certificate(&ca_pem.contents).expect("CA anchor is DER");

        let leaf_pem = std::fs::read(&node.cert_path).expect("read leaf");
        let (_, leaf_pem) = x509_parser::pem::parse_x509_pem(&leaf_pem).expect("leaf is PEM");
        let (_, leaf) =
            x509_parser::parse_x509_certificate(&leaf_pem.contents).expect("leaf is DER");

        assert_eq!(
            leaf.issuer().to_string(),
            ca.subject().to_string(),
            "leaf must be issued by the fixture CA, not self-signed"
        );

        let san = leaf
            .subject_alternative_name()
            .expect("SAN extension parses")
            .expect("leaf carries a SAN extension");

        let dns: Vec<&str> = san
            .value
            .general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::DNSName(dns) => Some(*dns),
                _ => None,
            })
            .collect();
        let ips: Vec<&[u8]> = san
            .value
            .general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::IPAddress(ip) => Some(*ip),
                _ => None,
            })
            .collect();

        assert_eq!(
            dns,
            vec![node.node_id.as_str()],
            "DNS SAN must be the realized node id"
        );
        assert_eq!(
            ips,
            vec![LOOPBACK_V4.as_slice()],
            "IP SAN must be 127.0.0.1"
        );
    }
}

#[test]
fn fixture_configs_are_strict_and_peer_each_other() {
    let pair = two_node_pair();

    assert_eq!(pair.origin.config.role, MeshNodeRole::ORIGIN);
    assert_eq!(pair.edge.config.role, MeshNodeRole::EDGE);

    for (node, peer) in [(&pair.origin, &pair.edge), (&pair.edge, &pair.origin)] {
        assert_eq!(node.config.tls.mode, Some(MeshTlsMode::Strict));
        assert_eq!(node.config.tls.effective_mode(), MeshTlsMode::Strict);
        assert!(
            node.config.tls.enforce_mutual_tls,
            "strict mode must enforce mTLS"
        );
        assert!(node.config.enabled);
        assert_eq!(node.config.bind_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(node.config.port, 0);

        assert_eq!(
            node.config.tls.cert_path.as_deref(),
            node.cert_path.to_str()
        );
        assert_eq!(node.config.tls.key_path.as_deref(), node.key_path.to_str());
        assert_eq!(node.config.tls.ca_path.as_deref(), node.ca_path.to_str());

        let upstream = node
            .config
            .local_upstreams
            .get(SERVICE_ID)
            .expect("service is wired on both nodes");
        assert!(
            upstream
                .peered_wafs
                .iter()
                .any(|waf| waf.node_id == peer.node_id && waf.allowed),
            "{} must authorize peer {}",
            node.node_id,
            peer.node_id
        );
        assert!(upstream.can_be_routed_by(&peer.node_id));
        assert!(
            !upstream.can_be_routed_by(&node.node_id),
            "a node must not authorize itself as a peer"
        );
    }

    // The edge dials the origin; the origin has nothing to dial yet.
    assert!(pair.origin.config.seeds.is_empty());
    assert_eq!(pair.edge.config.seeds.len(), 1);
    let seed = &pair.edge.config.seeds[0];
    assert!(seed.address.starts_with("127.0.0.1:"));
    assert_eq!(seed.public_key, None);
}
