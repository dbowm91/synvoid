//! Two-node mesh fixture: realized identities, a throwaway PKI, and strict
//! peer configs.
//!
//! The fixture stops at configuration. Transport assembly is a separate
//! concern, so nothing here constructs a `MeshTransport` or binds a port.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use synvoid_mesh::mesh::config::{
    MeshConfig, MeshNodeRole, MeshSeedNode, MeshTlsMode, MeshUpstreamConfig,
};
use tempfile::TempDir;

/// Service id the origin exposes to the mesh.
///
/// Later phases attach a real backend to it; this slice only needs the
/// identity/authorization wiring that lets the peer be routed through it.
pub const SERVICE_ID: &str = "blog-public";

/// Placeholder for the origin's bound port.
///
/// Port 0 is what the config asks the listener to bind, so the real port is
/// only known after the transport binds. The transport slice rewrites the seed
/// with that port.
pub const SEED_PLACEHOLDER_PORT: u16 = 0;

/// Placeholder upstream target for [`SERVICE_ID`], replaced when the origin
/// backend is assembled.
const UPSTREAM_PLACEHOLDER_URL: &str = "http://127.0.0.1:0";

const IDENTITY_FILE: &str = "identity.key";
const CA_FILE: &str = "ca.crt";
const CERT_FILE: &str = "node.crt";
const KEY_FILE: &str = "node.key";

/// One fully configured mesh node: a live temp dir, a realized identity, a
/// CA-signed leaf certificate, and the config that points at all of it.
pub struct FixtureNode {
    /// Kept alive for the duration of the test; dropping it deletes the node dir.
    pub dir: TempDir,
    pub config: MeshConfig,
    /// Realized id, `node-<hex>`.
    pub node_id: String,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_path: PathBuf,
    pub identity_path: PathBuf,
}

/// The two nodes of the loopback world.
pub struct TwoNodePair {
    /// Node A: `MeshNodeRole::ORIGIN`, no seeds.
    pub origin: FixtureNode,
    /// Node B: `MeshNodeRole::EDGE`, seeded with the origin's loopback address.
    pub edge: FixtureNode,
}

/// Builds two nodes with distinct identities, one shared CA, and mutual peer
/// authorization.
pub fn two_node_pair() -> TwoNodePair {
    let ca = TestCa::generate();

    let origin_dir = TempDir::new().expect("origin temp dir");
    let edge_dir = TempDir::new().expect("edge temp dir");

    let mut origin = NodeDraft::realize(origin_dir, MeshNodeRole::ORIGIN);
    let mut edge = NodeDraft::realize(edge_dir, MeshNodeRole::EDGE);

    let origin_pki = ca.write_pki(origin.dir.path(), &origin.node_id);
    let edge_pki = ca.write_pki(edge.dir.path(), &edge.node_id);

    let origin_id = origin.node_id.clone();
    let edge_id = edge.node_id.clone();

    // Each node's peered_wafs entry grants the other its real role: the edge
    // resolves the origin as ORIGIN, the origin resolves the edge as EDGE.
    origin.apply(origin_pki, &edge_id, "edge");
    edge.apply(edge_pki, &origin_id, "origin");

    // The edge dials the origin. The port is a placeholder until the listener
    // binds; `public_key` stays at its default (None) for TOFU-style discovery.
    edge.config.seeds.push(MeshSeedNode {
        address: format!("127.0.0.1:{SEED_PLACEHOLDER_PORT}"),
        ..MeshSeedNode::default()
    });

    TwoNodePair {
        origin: origin.finish(),
        edge: edge.finish(),
    }
}

/// A node directory that has realized its identity but has no PKI or mesh
/// fields yet.
struct NodeDraft {
    dir: TempDir,
    config: MeshConfig,
    node_id: String,
    identity_path: PathBuf,
    /// Set by [`NodeDraft::apply`], consumed by [`NodeDraft::finish`].
    pki: Option<PkiPaths>,
}

impl NodeDraft {
    fn realize(dir: TempDir, role: MeshNodeRole) -> Self {
        let identity_path = dir.path().join(IDENTITY_FILE);

        // `MeshConfig` has a private field, so struct-update syntax is not
        // available outside the crate; start from `Default` and set the mesh
        // fields the fixture owns.
        #[allow(clippy::field_reassign_with_default)]
        let mut config = MeshConfig::default();
        config.role = role;
        config.node_identity.private_key_path = Some(identity_path.to_string_lossy().into_owned());
        config
            .load_node_identity()
            .expect("mesh node identity must realize");

        let node_id = config.node_id();
        Self {
            dir,
            config,
            node_id,
            identity_path,
            pki: None,
        }
    }

    fn apply(&mut self, pki: PkiPaths, peer_id: &str, peer_role: &str) {
        self.config.enabled = true;
        self.config.bind_address = Some("127.0.0.1".to_string());
        self.config.port = 0;
        self.config.tls.mode = Some(MeshTlsMode::Strict);
        self.config.tls.enforce_mutual_tls = true;
        self.config.tls.ca_path = Some(pki.ca.to_string_lossy().into_owned());
        self.config.tls.cert_path = Some(pki.cert.to_string_lossy().into_owned());
        self.config.tls.key_path = Some(pki.key.to_string_lossy().into_owned());
        self.config
            .local_upstreams
            .insert(SERVICE_ID.to_string(), upstream_config(peer_id, peer_role));
        self.pki = Some(pki);
    }

    fn finish(self) -> FixtureNode {
        let pki = self.pki.expect("PKI written before finish");
        FixtureNode {
            dir: self.dir,
            config: self.config,
            node_id: self.node_id,
            cert_path: pki.cert,
            key_path: pki.key,
            ca_path: pki.ca,
            identity_path: self.identity_path,
        }
    }
}

/// A throwaway certificate authority held in memory.
///
/// The CA key never touches disk: only the CA certificate is written, once per
/// node dir, as the trust anchor each config points at.
struct TestCa {
    cert: Certificate,
    key: KeyPair,
}

impl TestCa {
    fn generate() -> Self {
        let mut params = CertificateParams::new(vec!["synvoid-mesh-test-ca".to_string()])
            .expect("CA subject alt name");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "SynVoid Mesh Test CA");
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        let key = KeyPair::generate().expect("CA key pair");
        let cert = params.self_signed(&key).expect("self-signed CA");

        Self { cert, key }
    }

    /// Issues a leaf for `node_id` and writes `ca.crt`, `node.crt`, `node.key`
    /// into `dir`.
    fn write_pki(&self, dir: &Path, node_id: &str) -> PkiPaths {
        // `CertificateParams::new` turns a non-IP string into a DNS SAN; the
        // loopback IP is added explicitly so rustls can also match `127.0.0.1`.
        let mut params =
            CertificateParams::new(vec![node_id.to_string()]).expect("leaf subject alt name");
        params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        params.distinguished_name.push(DnType::CommonName, node_id);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];

        let key = KeyPair::generate().expect("leaf key pair");
        let cert = params
            .signed_by(&key, &self.cert, &self.key)
            .expect("CA-signed leaf");

        let pki = PkiPaths {
            ca: dir.join(CA_FILE),
            cert: dir.join(CERT_FILE),
            key: dir.join(KEY_FILE),
        };
        write(&pki.ca, self.cert.pem());
        write(&pki.cert, cert.pem());
        write(&pki.key, key.serialize_pem());
        pki
    }
}

#[derive(Clone)]
struct PkiPaths {
    ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
}

/// Builds the per-node upstream that authorizes `peer_id` to route through it.
///
/// `peer_role` is the allowlist grant (`edge`, `origin`, or `global`), which is
/// what the handshake resolves the peer's claimed role against.
fn upstream_config(peer_id: &str, peer_role: &str) -> MeshUpstreamConfig {
    // `MeshUpstreamConfig` has no `Default` impl, so build it from its
    // serialized shape; every field not named here keeps its serde default.
    serde_json::from_value(serde_json::json!({
        "upstream_url": UPSTREAM_PLACEHOLDER_URL,
        "peered_wafs": [{"node_id": peer_id, "allowed": true, "role": peer_role}],
    }))
    .expect("mesh upstream fixture")
}

fn write(path: &Path, contents: String) {
    std::fs::write(path, contents).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}
