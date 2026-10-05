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
use std::path::{Path, PathBuf};

use synvoid_repo_guards::{collect_rs_files, workspace_root, Violations};

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

/// The persistence sections that are allowed to pass through untouched until
/// their owning phase converts them. Phase 127 removes `recursive`; Phase 128
/// removes `dnssec` and `zones` and deletes the module.
const ALLOWED_DEFERRED_FIELDS: &[&str] = &["recursive", "dnssec", "zones"];

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

// ---------------------------------------------------------------------------
// 3. The deferred passthrough stays minimal and self-describing
// ---------------------------------------------------------------------------

#[test]
fn deferred_config_module_exists_with_only_the_planned_passthroughs() {
    let root = workspace_root();
    let path = root.join("crates/synvoid-dns/src/runtime_config_deferred.rs");
    let text = read(&path);

    let mut violations = Violations::new();

    // Every persisted type referenced by the passthrough must be one Phase
    // 127/128 has an explicit plan to convert.
    let allowed_types = ["RecursiveDnsConfig", "DnsSecConfig", "DnsZonesConfig"];
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("pub ") {
            continue;
        }
        if !trimmed.contains("synvoid_config::dns::") {
            continue;
        }
        let name = trimmed
            .rsplit("::")
            .next()
            .unwrap_or_default()
            .trim_end_matches(",");
        if !allowed_types.contains(&name) {
            violations.push(format!(
                "runtime_config_deferred.rs exposes `{name}`, which has no owning \
                 conversion phase; add a plan before widening the passthrough"
            ));
        }
    }

    // The field set must not grow without a phase.
    for required in ALLOWED_DEFERRED_FIELDS {
        if !text.contains(&format!("pub {required}:")) {
            violations.push(format!(
                "runtime_config_deferred.rs no longer carries `{required}`; it is \
                 expected to be removed by its owning phase together with this test"
            ));
        }
    }

    violations.assert_ok("deferred_config_module_exists_with_only_the_planned_passthroughs");
}

#[test]
fn deferred_module_is_documented_as_temporary() {
    let root = workspace_root();
    let text = read(&root.join("crates/synvoid-dns/src/runtime_config_deferred.rs"));
    let mut violations = Violations::new();
    for required in ["Phase 127", "Phase 128", "NOT runtime DTO"] {
        if !text.contains(required) {
            violations.push(format!(
                "runtime_config_deferred.rs must document `{required}` so the \
                 temporary nature of the passthrough stays visible"
            ));
        }
    }
    violations.assert_ok("deferred_module_is_documented_as_temporary");
}

#[test]
fn authoritative_runtime_module_never_mentions_deferred_config() {
    // The authoritative runtime vocabulary and the passthrough must not be
    // entangled: a phase cannot "accidentally" satisfy its cutover by reading
    // a deferred value.
    let root = workspace_root();
    let text = read(&root.join("crates/synvoid-dns/src/runtime_config.rs"));
    let mut violations = Violations::new();
    for forbidden in ["DeferredDnsConfig", "runtime_config_deferred"] {
        if text.contains(forbidden) {
            violations.push(format!(
                "runtime_config.rs references `{forbidden}`; the authoritative \
                 runtime vocabulary must be self-contained"
            ));
        }
    }
    violations.assert_ok("authoritative_runtime_module_never_mentions_deferred_config");
}

// ---------------------------------------------------------------------------
// 4. Phase 126 gate: the authoritative runtime has no persistence DTO
// ---------------------------------------------------------------------------

/// The only production file allowed to name `synvoid_config::dns::DnsConfig`
/// after the Phase 126 cutover. Phases 127/128 shrink this to zero and delete
/// the file.
const DRS_CONFIG_ALLOWED_FILE: &str = "crates/synvoid-dns/src/runtime_config_deferred.rs";

#[test]
fn authoritative_runtime_has_no_persisted_config_dto() {
    let root = workspace_root();
    let src = root.join("crates/synvoid-dns/src");

    let files = collect_rs_files(&src);

    let mut violations = Violations::new();
    for file in files {
        for (index, line) in read(&file).lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            // The composite persisted root type must not reach production code
            // anywhere except the documented passthrough module. Match the
            // whole token so `DeferredDnsConfig` (the passthrough type itself)
            // does not trip the gate.
            let names_root_config = trimmed
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|token| token == "DnsConfig");
            if names_root_config && trimmed.contains("synvoid_config") {
                let rel = file
                    .strip_prefix(&root)
                    .unwrap_or(&file)
                    .display()
                    .to_string();
                if rel != DRS_CONFIG_ALLOWED_FILE {
                    violations.push(format!(
                        "{rel}:{} references the persisted root DNS config; after the \
                         Phase 126 cutover only `{DRS_CONFIG_ALLOWED_FILE}` may, and \
                         Phases 127/128 remove even that",
                        index + 1
                    ));
                }
            }
        }
    }

    violations.assert_ok("authoritative_runtime_has_no_persisted_config_dto");
}

#[test]
fn dns_server_constructor_takes_runtime_values() {
    // Regression gate for the Phase 126 acceptance criterion "Remove any
    // public constructor that requires a `synvoid_config::dns::DnsConfig`".
    let root = workspace_root();
    let text = read(&root.join("crates/synvoid-dns/src/server/mod.rs"));

    let mut violations = Violations::new();
    // Anchor inside `impl DnsServer` so a different `pub fn new` elsewhere in
    // the file cannot satisfy the check.
    let impl_at = match text.find("impl DnsServer {") {
        Some(at) => at,
        None => {
            violations.push("`impl DnsServer` block not found".to_string());
            violations.assert_ok("dns_server_constructor_takes_runtime_values");
            return;
        }
    };
    let after_impl = &text[impl_at..];
    let signature = match after_impl.find("pub fn new(\n        authoritative") {
        Some(at) => at,
        None => {
            violations.push(
                "DnsServer::new must take `authoritative: AuthoritativeRuntimeConfig` \
                 as its first argument"
                    .to_string(),
            );
            violations.assert_ok("dns_server_constructor_takes_runtime_values");
            return;
        }
    };
    // Only the parameter list matters, not the body.
    let rest = &after_impl[signature..];
    let params = match rest.find(") -> Self {") {
        Some(end) => &rest[..end],
        None => &rest[..rest.len().min(600)],
    };
    // The signature may name `DeferredDnsConfig` (the Phase 127/128
    // passthrough type); a bare persisted `DnsConfig` parameter is what this
    // gate forbids.
    let names_persisted_root = params
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|token| token == "DnsConfig");
    if names_persisted_root {
        violations.push("DnsServer::new must not accept a persistence DTO parameter".to_string());
    }
    violations.assert_ok("dns_server_constructor_takes_runtime_values");
}
