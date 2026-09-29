use std::fs;
use synvoid_config::{MainConfig, SiteConfig};

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

#[test]
fn tracked_main_config_fixtures_round_trip() {
    let root = repo_root();
    for fixture in ["config/main.toml", "config/main.toml.example"] {
        let text = fs::read_to_string(root.join(fixture)).expect("read config fixture");
        let mut parsed: MainConfig = toml::from_str(&text)
            .unwrap_or_else(|error| panic!("{fixture} must deserialize: {error}"));
        // The shipped operator config points to /var/log/synvoid. Keep this
        // fixture test hermetic while still validating the active config. The
        // .example intentionally contains a weak placeholder admin token and
        // is a schema/serialization fixture until an operator replaces it.
        if fixture == "config/main.toml" {
            parsed.logging.access_log_dir = None;
            parsed
                .validate()
                .unwrap_or_else(|error| panic!("{fixture}: {error}"));
        }
        let serialized = toml::to_string(&parsed).expect("serialize parsed main config");
        let mut reparsed: MainConfig = toml::from_str(&serialized)
            .unwrap_or_else(|error| panic!("serialized {fixture} must deserialize: {error}"));
        if fixture == "config/main.toml" {
            reparsed.logging.access_log_dir = None;
            reparsed
                .validate()
                .unwrap_or_else(|error| panic!("serialized {fixture}: {error}"));
        }
        assert_eq!(parsed.server.port, reparsed.server.port, "{fixture}");
        assert_eq!(
            parsed.http.max_request_size, reparsed.http.max_request_size,
            "{fixture}"
        );
    }
}

#[test]
fn tracked_site_config_fixtures_round_trip() {
    let root = repo_root();
    let sites = root.join("config/sites");
    let mut fixtures = fs::read_dir(sites)
        .expect("read tracked site fixtures")
        .map(|entry| entry.expect("site fixture entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .collect::<Vec<_>>();
    fixtures.sort();
    assert!(
        !fixtures.is_empty(),
        "at least one tracked site fixture is required"
    );
    for path in fixtures {
        let text = fs::read_to_string(&path).expect("read site fixture");
        let parsed = SiteConfig::from_toml_str(&text)
            .unwrap_or_else(|error| panic!("{} must parse: {error}", path.display()));
        let serialized = toml::to_string(&parsed).expect("serialize parsed site config");
        let reparsed = SiteConfig::from_toml_str(&serialized)
            .unwrap_or_else(|error| panic!("serialized {} must parse: {error}", path.display()));
        assert_eq!(parsed.site_id(), reparsed.site_id(), "{}", path.display());
        assert_eq!(
            parsed.site.domains,
            reparsed.site.domains,
            "{}",
            path.display()
        );
    }
}

#[cfg(all(feature = "mesh", feature = "dns", feature = "icmp-filter"))]
#[test]
fn tracked_mesh_and_tunnel_examples_deserialize() {
    let root = repo_root();
    let mesh = fs::read_to_string(root.join("config/mesh-example.toml")).unwrap();
    let parsed: synvoid_config::mesh::MeshConfig = toml::from_str(&mesh).unwrap();
    parsed.validate().expect("mesh example remains valid");

    let tunnel = fs::read_to_string(root.join("config/tunnel-example.toml")).unwrap();
    let parsed: synvoid_config::tunnel::TunnelConfig = toml::from_str(&tunnel).unwrap();
    parsed.validate().expect("tunnel example remains valid");
}
