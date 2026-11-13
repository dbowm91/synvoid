//! Root feature wiring for mesh routing.
//!
//! `synvoid-proxy` carries its own `mesh` feature, and the router's
//! `BackendConfig::Mesh` arm is `#[cfg(feature = "mesh")]`. When the root
//! `mesh` feature does not forward to `synvoid-proxy/mesh`, that arm compiles
//! to the empty `#[cfg(not(feature = "mesh"))]` branch: a site configured with
//! `[proxy.backend] type = "mesh"` silently proxies to its own
//! `[site.upstream]` instead of the mesh, with no error anywhere.
//!
//! The unit tests for that arm live behind the same cfg, so a build that
//! disables it also reports `running 0 tests` — green CI, dead routing. This
//! guard pins the manifest edge.
#![cfg(feature = "mesh")]

/// The root `mesh` feature must enable `synvoid-proxy/mesh`.
#[test]
fn root_mesh_feature_enables_proxy_mesh() {
    let manifest = include_str!("../Cargo.toml");
    let mesh_feature = manifest
        .lines()
        .find(|line| line.starts_with("mesh = ["))
        .expect("root Cargo.toml must declare a `mesh` feature");

    assert!(
        mesh_feature.contains("\"synvoid-proxy/mesh\""),
        "root `mesh` must enable `synvoid-proxy/mesh`, otherwise mesh-backed sites \
         fall through to their direct upstream. Found: {mesh_feature}"
    );
}
