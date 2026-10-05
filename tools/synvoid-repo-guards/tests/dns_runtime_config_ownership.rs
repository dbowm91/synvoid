//! DNS runtime-DTO ownership guards (Phases 125–130).
//!
//! Two contracts are enforced here (Phase 125 Workstream C/F):
//!
//! 1. `src/dns/` stays a **pure re-export facade**. The persisted-config →
//!    runtime-DTO conversion adapter is application-owned composition and
//!    lives in `src/server/dns_runtime_config.rs`; it must never migrate into
//!    the facade.
//! 2. `synvoid-dns` runtime configuration types must not depend on the
//!    persistence schema. The runtime DTO module is a runtime vocabulary, not
//!    a second persisted schema.
//!
//! The removed `synvoid-config` / `synvoid-core` / `synvoid-utils` dependency
//! edges are gated separately in `dns_dependency_edges.rs`, which lands with
//! the Phases 128/129 removals it protects.

use std::fs;
use std::path::Path;

use synvoid_repo_guards::{workspace_root, Violations};

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// 1. `src/dns/` remains a pure re-export facade
// ---------------------------------------------------------------------------

#[test]
fn dns_facade_gains_no_adapter_implementation() {
    let root = workspace_root();
    let facade = root.join("src/dns");

    let mut violations = Violations::new();

    // The facade must not import the conversion adapter.
    for source in [facade.join("mod.rs")].iter().chain(
        fs::read_dir(&facade)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "rs"))
            .collect::<Vec<_>>()
            .iter(),
    ) {
        let text = read(source);
        for forbidden in [
            "dns_runtime_config",
            "dns_runtime_config_from_persisted",
            "DnsRuntimeConversionError",
            "synvoid_config::dns",
        ] {
            if text.contains(forbidden) {
                violations.push(format!(
                    "{} references `{forbidden}`; the persisted->runtime conversion \
                     adapter belongs in src/server/dns_runtime_config.rs",
                    source.strip_prefix(&root).unwrap_or(source).display()
                ));
            }
        }
    }

    violations.assert_ok("dns_facade_gains_no_adapter_implementation");
}

// ---------------------------------------------------------------------------
// 2. The runtime DTO must stay persistence-free
// ---------------------------------------------------------------------------

#[test]
fn dns_runtime_config_module_has_no_persistence_dependency() {
    let root = workspace_root();
    let module = root.join("crates/synvoid-dns/src/runtime_config.rs");
    let text = read(&module);

    let mut violations = Violations::new();

    for forbidden in [
        "synvoid_config",
        "serde::",
        "Serialize",
        "Deserialize",
        "JsonSchema",
        "ToSchema",
        "utoipa",
        "schemars",
    ] {
        // Doc comments may *name* the persistence crate to explain the
        // boundary; only real code references are forbidden.
        for (index, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("///") {
                continue;
            }
            if trimmed.contains(forbidden) {
                violations.push(format!(
                    "crates/synvoid-dns/src/runtime_config.rs:{} references `{forbidden}`; \
                     the DNS runtime DTO must not own persisted-schema derives",
                    index + 1
                ));
            }
        }
    }

    violations.assert_ok("dns_runtime_config_module_has_no_persistence_dependency");
}
