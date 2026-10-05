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
//! edges are gated in `dns_dependency_edges.rs`: the `synvoid-config` edge
//! landed with Phase 128, and the `synvoid-core` / `synvoid-utils` edges land
//! with Phase 129.

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
/// their owning phase converts them. Phase 127 removed `recursive`; Phase 128
/// removes `dnssec` and `zones` and deletes the module.
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
// 3. Phase 128 gate: the deferred passthrough is gone for good
// ---------------------------------------------------------------------------

#[test]
fn deferred_passthrough_module_does_not_exist() {
    // Phase 128 converted the last persisted sections (`dnssec`, `zones`) and
    // deleted `runtime_config_deferred.rs`. The module must not come back: it
    // existed only to keep the runtime DTO module strictly persistence-free
    // while the recursive cutover was still in flight.
    let root = workspace_root();
    let path = root.join("crates/synvoid-dns/src/runtime_config_deferred.rs");
    let mut violations = Violations::new();

    if path.exists() {
        violations.push(format!(
            "{} exists; Phase 128 deleted it once the recursive, DNSSEC and zone \
             sections were converted",
            path.display()
        ));
    }

    let lib = read(&root.join("crates/synvoid-dns/src/lib.rs"));
    for forbidden in ["runtime_config_deferred", "DeferredDnsConfig"] {
        if lib.contains(forbidden) {
            violations.push(format!(
                "crates/synvoid-dns/src/lib.rs still wires `{forbidden}`; the \
                 deferred passthrough was removed in Phase 128"
            ));
        }
    }

    violations.assert_ok("deferred_passthrough_module_does_not_exist");
}

#[test]
fn authoritative_runtime_module_never_mentions_deferred_config() {
    // The authoritative runtime vocabulary must stay self-contained: a later
    // phase cannot "accidentally" satisfy its cutover by reading a deferred
    // value.
    let root = workspace_root();
    let text = read(&root.join("crates/synvoid-dns/src/runtime_config.rs"));
    let mut violations = Violations::new();
    for forbidden in ["DeferredDnsConfig", "runtime_config_deferred"] {
        if text.contains(forbidden) {
            violations.push(format!(
                "runtime_config.rs references `{forbidden}`; the runtime vocabulary \
                 must be self-contained"
            ));
        }
    }
    violations.assert_ok("authoritative_runtime_module_never_mentions_deferred_config");
}

// ---------------------------------------------------------------------------
// 4. Phase 126 gate: the authoritative runtime has no persistence DTO
// ---------------------------------------------------------------------------

/// No production file may name the persisted root DNS config after Phase 128.
/// Phases 126 and 127 shrank the allowance to one module; Phase 128 deleted
/// that module, so the allowance is now empty.
#[test]
fn no_production_file_names_the_persisted_root_dns_config() {
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
                violations.push(format!(
                    "{rel}:{} references the persisted root DNS config; after the \
                     Phase 128 cutover no file in `synvoid-dns` may. Persisted \
                     schema is converted by `src/server/dns_runtime_config.rs`",
                    index + 1
                ));
            }
        }
    }

    violations.assert_ok("no_production_file_names_the_persisted_root_dns_config");
}

#[test]
fn dns_server_constructor_takes_runtime_values() {
    // Regression gate for the Phase 126 acceptance criterion "Remove any
    // public constructor that requires a `synvoid_config::dns::DnsConfig`",
    // extended by Phase 128 to the whole-DNS runtime projection.
    let root = workspace_root();
    let text = read(&root.join("crates/synvoid-dns/src/server/mod.rs"));

    let mut violations = Violations::new();

    // `server/mod.rs` holds more than one `impl DnsServer` block and also
    // holds `impl Zone`, so scanning from the first `impl DnsServer` to the
    // end of the file would happily match some other type's constructor.
    // Scan each `impl DnsServer` block on its own.
    let mut inspected = 0usize;
    let mut cursor = 0usize;
    while let Some(offset) = text[cursor..].find("impl DnsServer {") {
        let block_start = cursor + offset;
        // The block ends at the next top-level `impl`/`fn`/`struct` item.
        let block_end = text[block_start..]
            .find("\nimpl ")
            .map(|rel| block_start + rel)
            .unwrap_or(text.len());
        let block = &text[block_start..block_end];
        cursor = block_start + "impl DnsServer {".len();

        let Some(sig_rel) = block.find("pub fn new(") else {
            continue;
        };
        inspected += 1;

        let rest = &block[sig_rel..];
        let params = match rest.find(") -> Self {") {
            Some(end) => &rest[..end],
            None => &rest[..rest.len().min(600)],
        };

        // A bare persisted `DnsConfig` parameter is what this gate forbids.
        let names_persisted_root = params
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|token| token == "DnsConfig");
        if names_persisted_root {
            violations
                .push("DnsServer::new must not accept a persistence DTO parameter".to_string());
        }
        // Phase 128: the whole-DNS runtime projection is the only
        // configuration input.
        if !params.contains("DnsRuntimeConfig") {
            violations.push(
                "DnsServer::new must accept a `DnsRuntimeConfig`; after the Phase 128 \
                 cutover the whole-DNS runtime projection is the only configuration input"
                    .to_string(),
            );
        }
    }

    if inspected == 0 {
        violations.push("no `DnsServer::new` constructor found in `impl DnsServer`".to_string());
    }

    violations.assert_ok("dns_server_constructor_takes_runtime_values");
}

// ---------------------------------------------------------------------------
// 5. Phase 127 gate: the recursive runtime is persistence-free
// ---------------------------------------------------------------------------

#[test]
fn recursive_runtime_module_has_no_persistence_dependency() {
    // Regression gate for the Phase 127 acceptance criterion: recursive
    // upstream/cache/ACL/circuit-breaker/depth/ECS policy must live in
    // DNS-owned runtime values.
    let root = workspace_root();
    let module = root.join("crates/synvoid-dns/src/runtime_config.rs");
    let text = read(&module);

    let mut violations = Violations::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        // Whole-token match so `RecursiveClientAclRuntime` (the DNS-owned
        // type) does not trip the gate on `RecursiveClientAcl`.
        let tokens: Vec<&str> = trimmed
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .collect();
        for forbidden in [
            "RecursiveDnsConfig",
            "RecursiveCacheConfig",
            "CircuitBreakerConfig",
            "RecursiveEcsConfig",
            "RecursiveUpstreamProvider",
            "RecursiveClientAcl",
            "EcsForwardingPolicy",
        ] {
            if tokens.contains(&forbidden) {
                violations.push(format!(
                    "runtime_config.rs:{} references `{forbidden}`; the recursive \
                     runtime vocabulary must be DNS-owned",
                    index + 1
                ));
            }
        }
    }
    violations.assert_ok("recursive_runtime_module_has_no_persistence_dependency");
}

#[test]
fn recursive_server_takes_runtime_config() {
    let root = workspace_root();
    let text = read(&root.join("crates/synvoid-dns/src/recursive.rs"));

    let mut violations = Violations::new();
    for signature in [
        "pub async fn new(\n        config: RecursiveRuntimeConfig,",
        "pub async fn new_with_global_nodes(\n        config: RecursiveRuntimeConfig,",
        "fn create_resolver(\n        config: &RecursiveRuntimeConfig,",
    ] {
        if !text.contains(signature) {
            violations.push(format!(
                "recursive.rs must declare `{signature}` so the recursive runtime \
                 cannot regress to a persistence DTO"
            ));
        }
    }
    if text.contains("synvoid_config::dns::RecursiveUpstreamProvider") {
        violations.push(
            "recursive.rs must not match on the persisted upstream-provider enum".to_string(),
        );
    }
    violations.assert_ok("recursive_server_takes_runtime_config");
}

#[test]
fn recursive_cache_takes_runtime_config() {
    let root = workspace_root();
    let text = read(&root.join("crates/synvoid-dns/src/recursive_cache.rs"));
    let mut violations = Violations::new();
    if !text.contains("cache_config: &crate::runtime_config::RecursiveCacheRuntimeConfig") {
        violations
            .push("RecursiveDnsCache::new must take &RecursiveCacheRuntimeConfig".to_string());
    }
    violations.assert_ok("recursive_cache_takes_runtime_config");
}

#[test]
fn forwarder_modes_cannot_claim_local_dnssec_validation() {
    // The truthfulness signal is part of the runtime contract: only true
    // recursion may claim local DNSSEC validation.
    let root = workspace_root();
    let module = root.join("crates/synvoid-dns/src/runtime_config.rs");
    let text = read(&module);

    let mut violations = Violations::new();
    if !text.contains("performs_local_dnssec_validation: bool") {
        violations
            .push("RecursiveRuntimeConfig must carry performs_local_dnssec_validation".to_string());
    }
    if !text.contains("pub fn upstream_ips(&self) -> Vec<IpAddr>") {
        violations.push(
            "RecursiveRuntimeConfig must own upstream_ips(); the resolver build path \
             must not call a persistence helper"
                .to_string(),
        );
    }
    violations.assert_ok("forwarder_modes_cannot_claim_local_dnssec_validation");
}
