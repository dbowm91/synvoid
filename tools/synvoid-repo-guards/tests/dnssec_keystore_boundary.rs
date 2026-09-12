//! Phase 30 DNSSEC key-custody boundary guards.
//!
//! Pins the one-way extraction: `synvoid-dnssec-keystore` owns private-key
//! generation/sealed storage/rotation/signing/HSM backing behind a narrow
//! contract, while `synvoid-dns` keeps wire/transport/resolver behavior,
//! public-only validation, NSEC/NSEC3 proofs, and RFC 5011 trust anchors.
//!
//! - The keystore must stay free of transport/control-plane dependencies
//!   (no DNS impl, mesh, admin, Hickory, Hyper, Quinn, SQLite); `cryptoki`
//!   is allowed only as an optional `pkcs11`-gated dependency.
//! - `synvoid-dns` request-path code must never touch raw private key
//!   material (`private_key` tokens) nor `cryptoki` directly.
//! - Mesh trust anchors carry public metadata only (never private keys).
//! - HSM-required zones fail closed: no silent software fallback strings.
//! - Admin DTOs never carry private key material.

use std::fs;
use synvoid_repo_guards::{collect_rs_files, prepare_for_scanning, workspace_root, Violations};

fn read_repo(rel: &str) -> String {
    let repo = workspace_root();
    fs::read_to_string(repo.join(rel)).unwrap_or_else(|_| panic!("read {rel}"))
}

fn manifest_declares(manifest: &str, needle: &str) -> bool {
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        let code = t.split('#').next().unwrap_or("").trim();
        if !code.contains('=') {
            continue;
        }
        let mut search_from = 0;
        while let Some(pos) = code[search_from..].find(needle) {
            let abs = search_from + pos;
            let after = abs + needle.len();
            let next_is_continuation = code[after..]
                .chars()
                .next()
                .is_some_and(|c| c == '-' || c == '_' || c.is_alphanumeric());
            if !next_is_continuation {
                return true;
            }
            search_from = after;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// keystore dependency budget
// ---------------------------------------------------------------------------

const PROHIBITED_KEYSTORE_DEPS: &[&str] = &[
    "synvoid-dns",
    "synvoid-mesh",
    "synvoid-admin",
    "synvoid-config",
    "hickory-proto",
    "hickory-resolver",
    "hyper",
    "quinn",
    "rusqlite",
    "openraft",
    "tonic",
    "axum",
    "yara-x",
];

#[test]
fn dnssec_keystore_dependency_budget() {
    let manifest = read_repo("crates/synvoid-dnssec-keystore/Cargo.toml");
    let mut violations = Violations::new();
    for dep in PROHIBITED_KEYSTORE_DEPS {
        if manifest_declares(&manifest, dep) {
            violations.push(format!(
                "crates/synvoid-dnssec-keystore/Cargo.toml declares prohibited dep '{dep}' \
                 (Phase 30 budget: custody-only, no transport/control-plane)"
            ));
        }
    }
    // `cryptoki` may exist only as an optional pkcs11-gated dependency
    // edge (the `[features] pkcs11 = ["dep:cryptoki"]` line is the gate
    // itself, not an edge, and is exempt).
    let mut in_dependencies = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_dependencies =
                t.starts_with("[dependencies") || t.starts_with("[target.") || t.starts_with("[[");
            continue;
        }
        if !in_dependencies {
            continue;
        }
        if t.starts_with('#') {
            continue;
        }
        let code = t.split('#').next().unwrap_or("");
        if code.contains("cryptoki") && code.contains('=') && !code.contains("optional") {
            violations.push(format!(
                "cryptoki edge must be optional (pkcs11-gated): {t}"
            ));
        }
    }
    violations.assert_ok("dnssec_keystore_dependency_budget");
}

#[test]
fn dnssec_keystore_imports_stay_custody_only() {
    let repo = workspace_root();
    let dir = repo.join("crates/synvoid-dnssec-keystore/src");
    let files = collect_rs_files(&dir);
    let mut violations = Violations::new();
    let forbidden = [
        "synvoid_dns",
        "synvoid_mesh",
        "synvoid_admin",
        "synvoid_config",
        "hickory",
        "hyper::",
        "quinn::",
        "rusqlite",
        "openraft",
        "tonic::",
        "axum::",
    ];
    for file in &files {
        let content = fs::read_to_string(file).unwrap_or_default();
        let code = prepare_for_scanning(&content);
        for token in &forbidden {
            if code.contains(token) {
                violations.push(format!(
                    "{} imports prohibited dependency '{token}'",
                    file.display()
                ));
            }
        }
    }
    violations.assert_ok("dnssec_keystore_imports_stay_custody_only");
}

// ---------------------------------------------------------------------------
// synvoid-dns side: no raw private-key reachability, no direct PKCS#11
// ---------------------------------------------------------------------------

#[test]
fn dns_request_path_has_no_private_key_tokens() {
    let repo = workspace_root();
    let dir = repo.join("crates/synvoid-dns/src");
    let files = collect_rs_files(&dir);
    let mut violations = Violations::new();
    for file in &files {
        let content = fs::read_to_string(file).unwrap_or_default();
        let code = prepare_for_scanning(&content);
        // `private_key` (field, binding, or string literal) must not appear:
        // sealed handles expose `sign()`/metadata only.
        if code.contains("private_key") {
            violations.push(format!(
                "{} touches raw private key material ('private_key')",
                file.display()
            ));
        }
        if code.contains("cryptoki") {
            violations.push(format!(
                "{} uses PKCS#11 directly (must go through synvoid-dnssec-keystore)",
                file.display()
            ));
        }
    }
    violations.assert_ok("dns_request_path_has_no_private_key_tokens");
}

#[test]
fn dns_hsm_backend_is_feature_gated() {
    let manifest = read_repo("crates/synvoid-dns/Cargo.toml");
    if !manifest.contains("synvoid-dnssec-keystore") {
        panic!("synvoid-dns must depend on synvoid-dnssec-keystore (Phase 30)");
    }
    if manifest_declares(&manifest, "cryptoki") {
        panic!("synvoid-dns must not depend on cryptoki directly (use keystore `hsm` feature)");
    }
    if !manifest.contains("hsm = [") {
        panic!("synvoid-dns must expose an `hsm` feature forwarding to keystore pkcs11");
    }
}

// ---------------------------------------------------------------------------
// mesh / admin: public metadata only
// ---------------------------------------------------------------------------

#[test]
fn mesh_trust_anchors_carry_no_private_keys() {
    let content = read_repo("crates/synvoid-dns/src/mesh_dnssec.rs");
    let code = prepare_for_scanning(&content);
    let mut violations = Violations::new();
    if code.contains("private_key") {
        violations
            .push("crates/synvoid-dns/src/mesh_dnssec.rs touches private key material".to_string());
    }
    if !code.contains("Vec<KeyMetadata>") {
        violations.push(
            "MeshTrustAnchor.dnskeys must be Vec<KeyMetadata> (public-only, Phase 30 Part F)"
                .to_string(),
        );
    }
    violations.assert_ok("mesh_trust_anchors_carry_no_private_keys");
}

#[test]
fn admin_dtos_carry_no_private_key_material() {
    let repo = workspace_root();
    let dir = repo.join("crates/synvoid-admin/src");
    if !dir.exists() {
        return;
    }
    let files = collect_rs_files(&dir);
    let mut violations = Violations::new();
    for file in &files {
        let content = fs::read_to_string(file).unwrap_or_default();
        let code = prepare_for_scanning(&content);
        if code.contains("private_key") {
            violations.push(format!(
                "{} carries private key material in admin code",
                file.display()
            ));
        }
    }
    violations.assert_ok("admin_dtos_carry_no_private_key_material");
}

// ---------------------------------------------------------------------------
// HSM fail-closed: no silent software fallback
// ---------------------------------------------------------------------------

#[test]
fn hsm_has_no_silent_software_fallback() {
    let repo = workspace_root();
    let dir = repo.join("crates/synvoid-dnssec-keystore/src");
    let files = collect_rs_files(&dir);
    let mut violations = Violations::new();
    // Historical silent-fallback markers from the pre-extraction HSM manager.
    let forbidden = [
        "falling back to SoftHSM",
        "fallback to SoftHSM",
        "falling back to software",
    ];
    for file in &files {
        let content = fs::read_to_string(file).unwrap_or_default();
        let code = prepare_for_scanning(&content);
        for marker in &forbidden {
            if code.contains(marker) {
                violations.push(format!(
                    "{} contains silent-fallback path '{marker}' (must fail closed)",
                    file.display()
                ));
            }
        }
    }
    violations.assert_ok("hsm_has_no_silent_software_fallback");
}

#[test]
fn root_has_no_direct_cryptoki_edge() {
    let manifest = read_repo("Cargo.toml");
    if manifest_declares(&manifest, "cryptoki") {
        panic!("root Cargo.toml must not depend on cryptoki (Phase 30: keystore owns it)");
    }
}
