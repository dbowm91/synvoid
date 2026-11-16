//! Phase 03: authenticated peer identity.
//!
//! Every test here drives the same functions the accept and dial paths call
//! (`authenticate_inbound_hello`, or the exported pieces it composes) with real
//! identity material — a key, its derived node id, a mined PoW nonce, and an
//! Ed25519 role signature. Nothing is stubbed: the fixture supplies live configs
//! and the adversarial cases only substitute the peer's claimed identity.

mod support;

use std::collections::HashMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

use support::fixture::{two_node_pair, TwoNodePair};
use synvoid_mesh::mesh::config::{
    MeshConfig, MeshNodeRole, MeshPeerRoleGrant, MeshTlsMode, MeshUpstreamConfig, MeshUpstreamPeer,
};
use synvoid_mesh::mesh::dht::routing::node_id::NodeId;
use synvoid_mesh::mesh::organization::{MemberCertificate, OrgKey, OrgPublicKey};
use synvoid_mesh::mesh::transport::{
    authenticate_inbound_hello, bind_node_id_to_public_key, verify_peer_network_id,
    AuthenticatedHello,
};
use synvoid_mesh::protocol::{MeshCapabilities, MeshMessage, MESH_MESSAGE_VERSION};
use synvoid_mesh::transport::MeshTransportError;

/// A node-shaped identity whose id is derived from its published key, exactly
/// as the handshake derives it.
///
/// A production identity publishes its Ed25519 verifying key and derives the
/// node id from that key, so this test identity is shaped the same way: the
/// published key can sign the role challenge the accept path verifies.
struct TestIdentity {
    signing_key: SigningKey,
    public_key: String,
    node_id: String,
    pow_nonce: u64,
}

impl TestIdentity {
    fn generate(seed: u8) -> Self {
        let mut secret = [0u8; 32];
        secret[0] = seed;
        secret[31] = 0x5a;
        let signing_key = SigningKey::from_bytes(&secret);
        let key_bytes = signing_key.verifying_key().to_bytes();
        let public_key = URL_SAFE_NO_PAD.encode(key_bytes);
        let node_id = synvoid_mesh::mesh::config::node_id_from_public_key(&key_bytes)
            .expect("a 32-byte key always derives a node id");
        let pow_nonce = NodeId::find_pow_nonce(&key_bytes).expect("PoW nonce");
        Self {
            signing_key,
            public_key,
            node_id,
            pow_nonce,
        }
    }

    /// `edge:{node_id}:{timestamp}`, signed with this identity's key.
    fn edge_signature(&self, node_id: &str, timestamp: u64) -> String {
        let challenge = format!("edge:{}:{}", node_id, timestamp);
        URL_SAFE_NO_PAD.encode(self.signing_key.sign(challenge.as_bytes()).to_bytes())
    }
}

/// Runs the accept path's real authentication decision for `identity`.
fn authenticate_as(
    config: &MeshConfig,
    node_id: &str,
    claimed_role: MeshNodeRole,
    identity: &TestIdentity,
    network_id: Option<&str>,
) -> Result<AuthenticatedHello, MeshTransportError> {
    let timestamp = synvoid_mesh::safe_unix_timestamp();
    let signature = identity.edge_signature(node_id, timestamp);
    authenticate_inbound_hello(
        config,
        None,
        MESH_MESSAGE_VERSION,
        node_id,
        claimed_role,
        network_id,
        Some(&identity.public_key),
        Some(&signature),
        timestamp,
        Some(identity.pow_nonce),
        Some(&identity.public_key),
        None,
        None,
        None,
        None,
    )
}

/// Replaces the service map with one upstream whose allowlist is `grants`.
fn config_with_grants(grants: &[(&str, MeshPeerRoleGrant)]) -> MeshUpstreamConfig {
    let peered_wafs: Vec<MeshUpstreamPeer> = grants
        .iter()
        .map(|(node_id, role)| MeshUpstreamPeer {
            node_id: (*node_id).to_string(),
            allowed: true,
            role: Some(*role),
        })
        .collect();
    let mut upstream: MeshUpstreamConfig =
        serde_json::from_value(serde_json::json!({ "upstream_url": "http://127.0.0.1:0" }))
            .expect("mesh upstream fixture");
    upstream.peered_wafs = peered_wafs;
    upstream
}

fn config_granting(grants: &[(&str, MeshPeerRoleGrant)]) -> MeshConfig {
    let TwoNodePair { origin, .. } = two_node_pair();
    let mut config = origin.config;
    config.local_upstreams =
        HashMap::from([("fixture-service".to_string(), config_with_grants(grants))]);
    config
}

#[test]
fn forged_hello_is_rejected_in_all_modes() {
    let TwoNodePair { origin, edge } = two_node_pair();

    // The fixture's PKI is real on disk; the identity paths are what the
    // transport loads, so a forged Hello is being judged against live config.
    for node in [&origin, &edge] {
        assert!(node.identity_path.starts_with(node.dir.path()));
        for path in [&node.cert_path, &node.key_path, &node.ca_path] {
            assert!(path.is_file(), "missing transport input {}", path.display());
        }
    }

    for mode in [
        MeshTlsMode::Strict,
        MeshTlsMode::Tofu,
        MeshTlsMode::Permissive,
    ] {
        let mut config = origin.config.clone();
        config.tls.mode = Some(mode);
        let attacker = TestIdentity::generate(0x41);

        // Claiming the listed peer's id with a key the attacker controls: the
        // allowlist lists that id, so only the key/id binding can stop it.
        let error = authenticate_as(
            &config,
            &edge.node_id,
            MeshNodeRole::EDGE,
            &attacker,
            config.network_id.as_deref(),
        )
        .expect_err("forged node id must be rejected");
        assert!(
            matches!(error, MeshTransportError::AuthFailed(_)),
            "{mode:?}: {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("does not match the presented public key"),
            "{mode:?}: {error}"
        );

        // Impersonating the node that owns the endpoint, with its role.
        let error = authenticate_as(
            &config,
            &origin.node_id,
            MeshNodeRole::ORIGIN,
            &attacker,
            config.network_id.as_deref(),
        )
        .expect_err("forged origin claim must be rejected");
        assert!(
            error
                .to_string()
                .contains("does not match the presented public key"),
            "{mode:?}: {error}"
        );

        // Control: the identical call succeeds once the operator lists the
        // attacker's own id. The rejection above is the binding, not a blanket
        // "deny everything" that would make the test vacuous.
        let mut listed = config.clone();
        listed.local_upstreams = HashMap::from([(
            "fixture-service".to_string(),
            config_with_grants(&[(&attacker.node_id, MeshPeerRoleGrant::Edge)]),
        )]);
        let accepted = authenticate_as(
            &listed,
            &attacker.node_id,
            MeshNodeRole::EDGE,
            &attacker,
            listed.network_id.as_deref(),
        )
        .unwrap_or_else(|error| panic!("{mode:?}: listed identity rejected: {error}"));
        assert_eq!(accepted.role, MeshNodeRole::EDGE);
        assert!(accepted.trusted, "{mode:?}: listed peer must be trusted");
    }
}

#[test]
fn role_escalation_is_rejected() {
    let attacker = TestIdentity::generate(0x52);
    let config = config_granting(&[]);

    for claimed in [MeshNodeRole::ORIGIN, MeshNodeRole::GLOBAL] {
        let error = config
            .resolve_peer_role(&attacker.node_id, claimed)
            .expect_err("an unlisted peer cannot claim a privileged role");
        assert!(error.contains("claimed role"), "{error}");

        let error = authenticate_as(
            &config,
            &attacker.node_id,
            claimed,
            &attacker,
            config.network_id.as_deref(),
        )
        .expect_err("privileged claim from an unlisted peer must be rejected");
        assert!(error.to_string().contains("claimed role"), "{error}");
    }

    // The same unlisted peer claiming EDGE joins, subject to PoW + signature.
    let accepted = authenticate_as(
        &config,
        &attacker.node_id,
        MeshNodeRole::EDGE,
        &attacker,
        config.network_id.as_deref(),
    )
    .expect("an unlisted peer may join as an edge");
    assert_eq!(accepted.role, MeshNodeRole::EDGE);
    assert!(!accepted.trusted, "an unlisted peer must not be trusted");

    // A listed peer may not claim a role other than the granted one.
    let listed = config_granting(&[(&attacker.node_id, MeshPeerRoleGrant::Edge)]);
    let error = listed
        .resolve_peer_role(&attacker.node_id, MeshNodeRole::GLOBAL)
        .expect_err("listed EDGE cannot claim GLOBAL");
    assert!(error.contains("claimed role"), "{error}");

    // Grants resolve to their role, and `None` means edge.
    let granted = config_granting(&[
        ("node-origin", MeshPeerRoleGrant::Origin),
        ("node-global", MeshPeerRoleGrant::Global),
    ]);
    assert_eq!(
        granted.resolve_peer_role("node-origin", MeshNodeRole::ORIGIN),
        Ok(MeshNodeRole::ORIGIN)
    );
    assert_eq!(
        granted.resolve_peer_role("node-global", MeshNodeRole::GLOBAL),
        Ok(MeshNodeRole::GLOBAL)
    );
    let mut defaulted = config_granting(&[("node-def", MeshPeerRoleGrant::Edge)]);
    if let Some(upstream) = defaulted.local_upstreams.get_mut("fixture-service") {
        upstream.peered_wafs[0].role = None;
    }
    assert_eq!(
        defaulted.resolve_peer_role("node-def", MeshNodeRole::EDGE),
        Ok(MeshNodeRole::EDGE)
    );

    // Conflicting grants for the same id are an error, not a race.
    let mut conflicting = config_granting(&[("node-conflict", MeshPeerRoleGrant::Edge)]);
    conflicting.local_upstreams.insert(
        "second-service".to_string(),
        config_with_grants(&[("node-conflict", MeshPeerRoleGrant::Global)]),
    );
    let error = conflicting
        .resolve_peer_role("node-conflict", MeshNodeRole::EDGE)
        .expect_err("conflicting grants must be rejected");
    assert!(error.contains("conflicting roles"), "{error}");
    assert!(error.contains("node-conflict"), "{error}");
}

#[test]
fn missing_network_id_is_rejected_when_configured() {
    let peer = "node-network-test";

    // No local network id: nothing to enforce.
    assert!(verify_peer_network_id(None, None, peer).is_ok());

    // Configured: absent, empty and different values are all hard failures.
    for peer_value in [None, Some(""), Some("staging")] {
        let error = verify_peer_network_id(Some("production"), peer_value, peer)
            .expect_err("network isolation must be enforced");
        assert!(
            matches!(error, MeshTransportError::AuthFailed(_)),
            "{error:?}"
        );
    }
    assert!(verify_peer_network_id(Some("production"), Some("production"), peer).is_ok());

    // End to end through the accept-path decision.
    let attacker = TestIdentity::generate(0x63);
    let mut config = config_granting(&[(&attacker.node_id, MeshPeerRoleGrant::Edge)]);
    config.network_id = Some("production".to_string());

    let error = authenticate_as(
        &config,
        &attacker.node_id,
        MeshNodeRole::EDGE,
        &attacker,
        None,
    )
    .expect_err("a peer without a network id must be rejected");
    assert!(
        error.to_string().contains("did not declare a network id"),
        "{error}"
    );

    authenticate_as(
        &config,
        &attacker.node_id,
        MeshNodeRole::EDGE,
        &attacker,
        Some("production"),
    )
    .expect("a matching network id must be accepted");
}

#[test]
fn auth_token_is_ignored() {
    let attacker = TestIdentity::generate(0x74);
    let config = config_granting(&[(&attacker.node_id, MeshPeerRoleGrant::Edge)]);

    // The field is still on the wire so an older peer parses, but the accept
    // decision has no token input: `authenticate_inbound_hello` takes none, and
    // the accept path only logs the first one it sees.
    let hello = MeshMessage::Hello {
        version: MESH_MESSAGE_VERSION,
        node_id: attacker.node_id.clone().into(),
        role: MeshNodeRole::EDGE,
        capabilities: MeshCapabilities::from_config(&config, MeshNodeRole::EDGE),
        upstreams: HashMap::new(),
        auth_token: Some("legacy-shared-secret".into()),
        network_id: None,
        global_node_key: None,
        timestamp: Some(synvoid_mesh::safe_unix_timestamp()),
        nonce: None,
        is_trusted: false,
        quic_port: None,
        wireguard_port: None,
        public_key: Some(attacker.public_key.clone().into()),
        pow_nonce: Some(attacker.pow_nonce),
        pow_public_key: Some(attacker.public_key.clone().into()),
        member_certificate: None,
        org_public_key: None,
    };
    let encoded = hello.encode().expect("Hello encodes");
    let decoded = MeshMessage::decode(&encoded).expect("Hello decodes");

    match decoded {
        MeshMessage::Hello {
            auth_token,
            node_id,
            public_key,
            ..
        } => {
            assert_eq!(auth_token.as_deref(), Some("legacy-shared-secret"));
            assert_eq!(node_id.as_str(), attacker.node_id);
            assert_eq!(public_key.as_deref(), Some(attacker.public_key.as_str()));
        }
        other => panic!("expected Hello, got {other:?}"),
    }

    // A Hello carrying that field still authenticates.
    let accepted = authenticate_as(
        &config,
        &attacker.node_id,
        MeshNodeRole::EDGE,
        &attacker,
        None,
    )
    .expect("a Hello with a retired token must still establish");
    assert_eq!(accepted.role, MeshNodeRole::EDGE);
}

#[test]
fn org_revoked_certificate_does_not_fall_through_to_pow() {
    let attacker = TestIdentity::generate(0x85);
    let config = config_granting(&[]);

    // Control: without a certificate the unlisted peer authenticates with PoW
    // plus its role signature.
    authenticate_as(
        &config,
        &attacker.node_id,
        MeshNodeRole::EDGE,
        &attacker,
        None,
    )
    .expect("PoW + signature must authenticate an unlisted edge");

    // An expired member certificate used to fall through to the PoW branch.
    // It is now terminal even though the PoW and signature are valid.
    let org_key = OrgKey::generate(None);
    let org_public_key = OrgPublicKey::new("test-org".to_string(), &org_key);
    let expired = MemberCertificate::new(
        attacker.node_id.clone(),
        "test-org".to_string(),
        &org_key,
        0,
    );
    assert!(!expired.is_valid(), "fixture certificate must be expired");

    let timestamp = synvoid_mesh::safe_unix_timestamp();
    let signature = attacker.edge_signature(&attacker.node_id, timestamp);
    let error = authenticate_inbound_hello(
        &config,
        None,
        MESH_MESSAGE_VERSION,
        &attacker.node_id,
        MeshNodeRole::EDGE,
        None,
        Some(&attacker.public_key),
        Some(&signature),
        timestamp,
        Some(attacker.pow_nonce),
        Some(&attacker.public_key),
        Some(&expired),
        Some(&org_public_key),
        None,
        None,
    )
    .expect_err("an expired member certificate must be terminal");
    assert!(
        error.to_string().contains("expired or not yet valid"),
        "{error}"
    );
}

#[test]
fn config_bridge_preserves_peer_role_grants() {
    // The operator schema (`synvoid-config`) is bridged into the runtime config
    // by a JSON round-trip, so both structs must carry `role`. A node that
    // gains the field on only one side silently loses the grant.
    let dto: synvoid_config::mesh::MeshConfig = serde_json::from_value(serde_json::json!({
        "local_upstreams": {
            "blog-public": {
                "upstream_url": "http://127.0.0.1:0",
                "peered_wafs": [
                    {"node_id": "node-origin-1", "allowed": true, "role": "origin"},
                    {"node_id": "node-edge-1", "allowed": true},
                ],
            }
        }
    }))
    .expect("operator schema accepts role = \"origin\"");

    let runtime: MeshConfig =
        serde_json::from_str(&serde_json::to_string(&dto).expect("operator schema serializes"))
            .expect("runtime config accepts the bridged grant");

    assert_eq!(
        runtime.resolve_peer_role("node-origin-1", MeshNodeRole::ORIGIN),
        Ok(MeshNodeRole::ORIGIN)
    );
    assert!(runtime
        .resolve_peer_role("node-origin-1", MeshNodeRole::EDGE)
        .is_err());
    assert_eq!(
        runtime.resolve_peer_role("node-edge-1", MeshNodeRole::EDGE),
        Ok(MeshNodeRole::EDGE)
    );
    assert!(runtime.is_peer_allowlisted("node-origin-1"));
    assert!(!runtime.is_peer_allowlisted("node-unlisted"));
}

#[test]
fn identity_binding_rejects_a_missing_key() {
    let TwoNodePair { origin, .. } = two_node_pair();

    for public_key in [None, Some(""), Some("not-a-key")] {
        let error = bind_node_id_to_public_key(&origin.node_id, public_key)
            .expect_err("an unbound node id must be rejected");
        assert!(
            matches!(error, MeshTransportError::AuthFailed(_)),
            "{error:?}"
        );
    }

    // A real key binds only to its own id.
    let identity = TestIdentity::generate(0x96);
    assert!(bind_node_id_to_public_key(&identity.node_id, Some(&identity.public_key)).is_ok());
    assert!(bind_node_id_to_public_key(&origin.node_id, Some(&identity.public_key)).is_err());
}
