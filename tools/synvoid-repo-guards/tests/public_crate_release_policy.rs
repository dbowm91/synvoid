//! Phase 47 public-crate release policy guards.
//!
//! Pins the class-3 promotion boundary from
//! `architecture/public_crate_release_readiness_phase47.md`:
//! - `synvoid-rate-limit` is the single externally supported crate and keeps
//!   its release metadata (MSRV, readme, keywords, categories, docs URL),
//!   consumer docs (README/CHANGELOG, slot-hashing decision), and leaf shape
//!   (no `path =` workspace deps);
//! - deferred/internal candidates carry no `rust-version` (no implied MSRV
//!   or support promise);
//! - `docs/releasing.md` and the root README record the external-support
//!   order honestly (rate-limit only).

use synvoid_repo_guards::workspace_root;

fn read_repo(rel: &str) -> String {
    let repo = workspace_root();
    std::fs::read_to_string(repo.join(rel))
        .unwrap_or_else(|_| panic!("public_crate_release_policy_guard: read {rel}"))
}

fn package_table(manifest_src: &str, rel: &str) -> toml::map::Map<String, toml::Value> {
    let manifest: toml::Value = manifest_src
        .parse()
        .unwrap_or_else(|_| panic!("public_crate_release_policy_guard: {rel} is not valid TOML"));
    manifest
        .get("package")
        .and_then(|v| v.as_table())
        .cloned()
        .unwrap_or_else(|| panic!("public_crate_release_policy_guard: {rel} has no [package]"))
}

fn package_str(table: &toml::map::Map<String, toml::Value>, key: &str) -> Option<String> {
    table.get(key).and_then(|v| v.as_str()).map(str::to_string)
}

// ---------------------------------------------------------------------------
// synvoid-rate-limit: release metadata (Workstreams A/B)
// ---------------------------------------------------------------------------

#[test]
fn rate_limit_release_metadata() {
    let src = read_repo("crates/synvoid-rate-limit/Cargo.toml");
    let pkg = package_table(&src, "crates/synvoid-rate-limit/Cargo.toml");

    assert_eq!(
        package_str(&pkg, "rust-version").as_deref(),
        Some("1.81"),
        "public_crate_release_policy_guard: synvoid-rate-limit rust-version must stay 1.81 \
         (packaged-tarball MSRV evidence; lower only with new evidence)"
    );
    assert_eq!(
        package_str(&pkg, "readme").as_deref(),
        Some("README.md"),
        "public_crate_release_policy_guard: synvoid-rate-limit must point at its crate README"
    );
    assert!(
        package_str(&pkg, "documentation").is_some(),
        "public_crate_release_policy_guard: synvoid-rate-limit needs a documentation URL"
    );
    for key in ["keywords", "categories"] {
        let len = pkg
            .get(key)
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        assert!(
            len > 0,
            "public_crate_release_policy_guard: synvoid-rate-limit needs non-empty {key}"
        );
    }
    assert!(
        package_str(&pkg, "description").is_some(),
        "public_crate_release_policy_guard: synvoid-rate-limit needs a description"
    );
}

// ---------------------------------------------------------------------------
// synvoid-rate-limit: consumer docs exist and pin the slot decision
// ---------------------------------------------------------------------------

#[test]
fn rate_limit_consumer_docs() {
    for rel in [
        "crates/synvoid-rate-limit/README.md",
        "crates/synvoid-rate-limit/CHANGELOG.md",
    ] {
        let body = read_repo(rel);
        assert!(
            body.len() > 200,
            "public_crate_release_policy_guard: {rel} must be a real consumer doc"
        );
    }
    let readme = read_repo("crates/synvoid-rate-limit/README.md");
    assert!(
        readme.contains("1.81"),
        "public_crate_release_policy_guard: crate README must state the MSRV"
    );
    assert!(
        readme.contains("implementation detail"),
        "public_crate_release_policy_guard: crate README must record the \
         slot-hashing implementation-detail decision"
    );
    let lib = read_repo("crates/synvoid-rate-limit/src/lib.rs");
    assert!(
        lib.contains("Quickstart") && lib.contains("```rust"),
        "public_crate_release_policy_guard: crate rustdoc must carry a runnable quickstart"
    );
    let slot_docs = read_repo("crates/synvoid-rate-limit/src/slot.rs");
    assert!(
        slot_docs.contains("implementation detail") || slot_docs.contains("behaviorally identical"),
        "public_crate_release_policy_guard: slot.rs must document the duplication/stability story"
    );
}

// ---------------------------------------------------------------------------
// synvoid-rate-limit: leaf shape (Workstream C)
// ---------------------------------------------------------------------------

#[test]
fn rate_limit_stays_leaf() {
    let src = read_repo("crates/synvoid-rate-limit/Cargo.toml");
    for line in src.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        let code = t.split('#').next().unwrap_or("").trim();
        assert!(
            !code.contains("path"),
            "public_crate_release_policy_guard: synvoid-rate-limit must have no `path =` \
             workspace deps (offending line: {code})"
        );
    }
    let manifest: toml::Value = src.parse().expect("rate-limit manifest is valid TOML");
    assert!(
        manifest.get("dependencies").is_none(),
        "public_crate_release_policy_guard: synvoid-rate-limit must stay dependency-free \
         (std only); normal [dependencies] would void the MSRV/leaf evidence"
    );
}

// ---------------------------------------------------------------------------
// Deferred/internal candidates: no rust-version, no implied promise
// ---------------------------------------------------------------------------

const NO_PROMISE_CRATES: &[&str] = &[
    "crates/synvoid-mesh-protocol/Cargo.toml",
    "crates/synvoid-proxy-cache/Cargo.toml",
    "crates/synvoid-dnssec-keystore/Cargo.toml",
    "crates/synvoid-platform/Cargo.toml",
    "crates/synvoid-yara/Cargo.toml",
    "crates/synvoid-http-client/Cargo.toml",
    "crates/synvoid-utils/Cargo.toml",
    "crates/synvoid-core/Cargo.toml",
];

#[test]
fn deferred_crates_carry_no_msrv() {
    let mut violations = Vec::new();
    for rel in NO_PROMISE_CRATES {
        let src = read_repo(rel);
        let pkg = package_table(&src, rel);
        if pkg.contains_key("rust-version") {
            violations.push(format!(
                "{rel} declares rust-version without a class-3 promotion \
                 (see architecture/public_crate_release_readiness_phase47.md §2)"
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "public_crate_release_policy_guard: rust-version implies an MSRV contract; \
         only promoted crates may declare one:\n  {}",
        violations.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// releasing.md + root README: external-support order is rate-limit only
// ---------------------------------------------------------------------------

#[test]
fn releasing_docs_external_order() {
    let doc = read_repo("docs/releasing.md");
    assert!(
        doc.contains("Externally supported library order"),
        "public_crate_release_policy_guard: docs/releasing.md must carry the \
         externally supported library order (Phase 47 Workstream G)"
    );
    assert!(
        doc.contains("only `synvoid-rate-limit`"),
        "public_crate_release_policy_guard: the externally supported order must name \
         only synvoid-rate-limit as class 3"
    );
}

#[test]
fn root_readme_documents_support_boundary() {
    let readme = read_repo("README.md");
    assert!(
        readme.contains("synvoid-rate-limit") && readme.contains("externally supported"),
        "public_crate_release_policy_guard: root README must document the \
         externally supported library boundary (Phase 47)"
    );
}
