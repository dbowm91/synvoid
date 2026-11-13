//! Regression coverage for `realize_mesh_runtime_config`.
//!
//! The documented Basic Mesh Setup in `docs/WAF_MESH.md` enables
//! `[tunnel.mesh]` without an `[tunnel.mesh.authority_freshness]` table. That
//! path used to be fatal: `AuthorityFreshnessConfig` derived `Default`, so the
//! omitted table produced `canonical_snapshot_stale_mode = ""`, serialisation
//! carried the empty string into the mesh-owned runtime config, and the typed
//! `CanonicalSnapshotStaleMode` rejected it as an unknown variant. Mesh then
//! refused to start with a log line that pointed at nothing the operator had
//! written.
#![cfg(feature = "mesh")]

use synvoid::supervisor::mesh::realize_mesh_runtime_config;
use synvoid_config::mesh::{AuthorityFreshnessConfig, MeshConfig};

/// The omitted table must realize into a runtime config.
#[test]
fn mesh_enabled_without_authority_freshness_realizes() {
    let model: MeshConfig = toml::from_str(
        r#"
enabled = true
node_id = "origin-node"
role = 4
"#,
    )
    .expect("the documented minimal mesh section must parse");

    let runtime = realize_mesh_runtime_config(&model)
        .expect("a mesh config without [authority_freshness] must realize");

    assert!(runtime.enabled);
    // Node identity material is authoritative: `load_node_identity()` derives
    // the runtime id from the signing key and overwrites the configured value.
    // This test only pins that realization succeeds and yields an id.
    assert!(
        !runtime.node_id().is_empty(),
        "realized config must carry a node id"
    );
}

/// The struct default must satisfy the mesh-side contract on its own, without
/// going through TOML. A derived default previously produced `""`.
#[test]
fn authority_freshness_default_is_a_valid_stale_mode() {
    let default = AuthorityFreshnessConfig::default();
    assert_eq!(
        default.canonical_snapshot_stale_mode, "fail_open_defer",
        "the struct default must match the documented stale mode"
    );
    assert_eq!(default.canonical_snapshot_fresh_max_age_ms, 60_000);
    assert_eq!(default.canonical_snapshot_stale_grace_max_age_ms, 300_000);
    assert!(
        default.canonical_snapshot_stale_grace_max_age_ms
            > default.canonical_snapshot_fresh_max_age_ms
    );
}

/// Serialising the default into JSON must not emit an empty stale mode; this
/// is the exact bridge `realize_mesh_runtime_config` uses.
#[test]
fn authority_freshness_default_serializes_a_valid_variant() {
    let json =
        serde_json::to_value(AuthorityFreshnessConfig::default()).expect("default must serialize");
    let mode = json
        .get("canonical_snapshot_stale_mode")
        .and_then(|v| v.as_str())
        .expect("stale mode must be a string");
    assert!(
        matches!(
            mode,
            "fail_open_defer" | "fail_closed_not_actionable" | "allow_stale_with_warning"
        ),
        "stale mode must be a known variant, got {mode:?}"
    );
}
