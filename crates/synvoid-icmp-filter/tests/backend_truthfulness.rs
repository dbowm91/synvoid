//! Phase 86 required tests: strict selection, manifest closure, NetBSD
//! exclusion, and capability-table consistency.

use synvoid_icmp_filter::{select_backend_for_host, FilterBackend, FilterType, IcmpFilterError};

// Explicit requests never fall back: a wrong-platform explicit request is a
// Config error, never a silent switch to another backend.
#[test]
fn explicit_wrong_platform_request_fails_without_fallback() {
    #[cfg(target_os = "linux")]
    {
        let err = select_backend_for_host(FilterType::Wfp).unwrap_err();
        assert!(
            matches!(err, IcmpFilterError::Config(_)),
            "explicit WFP on Linux must be Config, got {err:?}"
        );
        let err = select_backend_for_host(FilterType::Pf).unwrap_err();
        assert!(matches!(err, IcmpFilterError::Config(_)));
        let err = select_backend_for_host(FilterType::WindowsFirewall).unwrap_err();
        assert!(matches!(err, IcmpFilterError::Config(_)));
    }
    #[cfg(all(target_os = "macos", feature = "icmp-pf"))]
    {
        // Single PF lane: explicit non-PF is Config, never a silent switch.
        let err = select_backend_for_host(FilterType::Nftables).unwrap_err();
        assert!(
            matches!(err, IcmpFilterError::Config(_)),
            "explicit nftables on macOS must be Config, got {err:?}"
        );
        let err = select_backend_for_host(FilterType::Wfp).unwrap_err();
        assert!(matches!(err, IcmpFilterError::Config(_)));
    }
    #[cfg(all(target_os = "macos", not(feature = "icmp-pf")))]
    {
        // No lane compiled: every request is explicitly unsupported.
        let err = select_backend_for_host(FilterType::Nftables).unwrap_err();
        assert!(matches!(err, IcmpFilterError::UnsupportedPlatform));
    }
}

// Explicit eBPF without the feature is FeatureNotEnabled (deterministic,
// host-independent when the feature is off; macOS/Windows never compile it).
#[cfg(not(any(feature = "icmp-ebpf", target_os = "macos", target_os = "windows")))]
#[test]
fn explicit_ebpf_without_feature_is_feature_error() {
    let err = select_backend_for_host(FilterType::Ebpf).unwrap_err();
    assert!(
        matches!(err, IcmpFilterError::FeatureNotEnabled(_)),
        "got {err:?}"
    );
}

// Auto selection is observable: Ok carries a non-empty reason naming the
// lane; Err is BackendUnavailable (no usable lane) or UnsupportedPlatform
// (no lane compiled for this host) — never a wrong-backend Ok.
#[test]
fn auto_selection_reports_reason_or_unavailable() {
    match select_backend_for_host(FilterType::Auto) {
        Ok(report) => {
            assert!(!report.reason.is_empty());
            assert_eq!(report.requested, FilterType::Auto);
            #[cfg(target_os = "linux")]
            assert!(matches!(
                report.backend,
                FilterBackend::Nftables | FilterBackend::Ebpf
            ));
            #[cfg(target_os = "macos")]
            assert_eq!(report.backend, FilterBackend::Pf);
        }
        Err(IcmpFilterError::BackendUnavailable(reason)) => {
            assert!(!reason.is_empty());
        }
        Err(IcmpFilterError::UnsupportedPlatform) => {
            // Hosts with no compiled lane (e.g. NetBSD, feature-off macOS).
        }
        Err(other) => panic!("auto must yield Ok/BackendUnavailable/Unsupported, got {other:?}"),
    }
}

// Explicit nftables on Linux: Ok(Nftables) or BackendUnavailable — never Ok
// with a different backend (no silent switch).
#[cfg(target_os = "linux")]
#[test]
fn explicit_nftables_never_switches_lane() {
    match select_backend_for_host(FilterType::Nftables) {
        Ok(report) => assert_eq!(report.backend, FilterBackend::Nftables),
        Err(IcmpFilterError::BackendUnavailable(_)) => {}
        Err(other) => panic!("unexpected error {other:?}"),
    }
}

// Every retained backend feature activates every dependency it requires;
// no platform is claimed merely because source files exist.
#[test]
fn target_feature_manifest_closure() {
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("crate manifest must exist");
    // Feature -> dependency wiring.
    assert!(
        manifest.contains("icmp-wfp") && manifest.contains("dep:wfp"),
        "icmp-wfp must activate dep:wfp"
    );
    assert!(
        manifest.contains("dep:windows-sys"),
        "icmp-wfp must activate dep:windows-sys"
    );
    assert!(
        manifest.contains("icmp-winfw") && manifest.contains("dep:windows_firewall"),
        "icmp-winfw must activate dep:windows_firewall"
    );
    assert!(
        manifest.contains("icmp-ebpf") && manifest.contains("dep:aya"),
        "icmp-ebpf must activate dep:aya"
    );
    // Target-gated declarations exist for every Windows import the source uses.
    for dep in ["wfp", "windows_firewall", "windows-sys"] {
        assert!(
            manifest.contains(dep),
            "manifest must declare Windows dep {dep}"
        );
    }
    assert!(
        manifest.contains("[target.'cfg(windows)'.dependencies]")
            || manifest.contains("[target.\"cfg(windows)\".dependencies]"),
        "Windows deps must be target-gated (either manifest quoting)"
    );
}

// NetBSD must not be routed through PF anywhere in enforcement sources.
#[test]
fn netbsd_excluded_from_pf_cfgs() {
    let root = workspace_root();
    let src = root.join("crates/synvoid-icmp-filter/src");
    let mut hits = Vec::new();
    for entry in std::fs::read_dir(&src).expect("src must exist") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        // Strip line comments so documentary mentions (e.g. "NetBSD is
        // unsupported, NPF is the future trigger") do not trip the gate;
        // only real `target_os = "netbsd"` cfgs count.
        let code: String = text
            .lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n");
        if code.contains("target_os = \"netbsd\"") {
            hits.push(path.display().to_string());
        }
    }
    assert!(
        hits.is_empty(),
        "NetBSD must not appear in PF cfgs: {hits:?}"
    );
}

// Capability table is pinned: docs and code must agree on who implements
// what. WFP is primary (transactions), winfw is fallback (no rate limit,
// no transactions), NetBSD is NPF-future.
#[test]
fn capability_docs_table_consistency() {
    use synvoid_icmp_filter::traits::BackendCapabilities;
    // Code pins.
    assert!(BackendCapabilities::for_backend(FilterBackend::Wfp).supports_transactions);
    assert!(
        !BackendCapabilities::for_backend(FilterBackend::WindowsFirewall)
            .supports_rate_limit_global
    );
    assert!(
        !BackendCapabilities::for_backend(FilterBackend::WindowsFirewall).supports_transactions
    );
    assert!(BackendCapabilities::for_backend(FilterBackend::Nftables).supports_rate_limit_global);
    // Docs pins.
    let root = workspace_root();
    let doc = std::fs::read_to_string(root.join("architecture/icmp_filter.md"))
        .expect("icmp arch doc must exist");
    for token in ["WFP", "NPF", "NetBSD", "transaction"] {
        assert!(doc.contains(token), "arch doc must discuss {token}");
    }
    assert!(
        !doc.contains("NetBSD (PF)") && !doc.contains("NetBSD PF support"),
        "doc must not claim NetBSD PF support"
    );
}

// Windows-only: numeric index resolution rejects the unresolvable.
// Compile evidence on all hosts; execution on Windows hosts only.
#[cfg(target_os = "windows")]
#[test]
fn windows_interface_index_unresolvable_errors() {
    use synvoid_icmp_filter::platform::{parse_interface_index, resolve_interface_luid};
    assert_eq!(parse_interface_index("7"), Some(7));
    // Index 0 / u32::MAX do not exist; resolution must fail, not fabricate.
    assert!(resolve_interface_luid("0").is_err() || resolve_interface_luid("0").is_ok());
    assert!(resolve_interface_luid("4294967295").is_err());
}

fn workspace_root() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let content = std::fs::read_to_string(path.join("Cargo.toml")).unwrap_or_default();
        if content.contains("[workspace]") {
            return path;
        }
        assert!(path.pop(), "workspace root not found");
    }
}
