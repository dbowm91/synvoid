//! Phase 90 Finding D: backend inventory reports probe truth.
//!
//! The admin `/icmp/backends` endpoint projects this inventory: each entry
//! exposes compiled/usable/reason, `available` is only a compatibility alias
//! for `usable`, and the selected backend comes from the manager report —
//! never from requested config or a hardcoded `available: true`.

use synvoid_icmp_filter::{probe_backend_inventory, traits::FilterBackend};

#[test]
fn inventory_never_hardcodes_available() {
    let inventory = probe_backend_inventory();
    for entry in &inventory {
        // `usable` is derived from probe state, never hardcoded true.
        if !entry.usable {
            assert!(
                !entry.reason.is_empty(),
                "{:?} is unusable but carries no reason",
                entry.backend
            );
        } else {
            assert_eq!(entry.reason, "usable");
        }
        // Compiled flag is honest: an entry can be compiled-but-unusable
        // (privilege) or relevant-but-not-compiled (feature).
        if !entry.compiled {
            assert!(
                !entry.usable,
                "{:?} not compiled yet reported usable",
                entry.backend
            );
        }
    }
}

#[test]
fn inventory_distinguishes_requested_from_selected() {
    // Requested `Auto` and selected concrete backend are different facts.
    // The inventory carries no "selected" notion at all: selection comes
    // from the manager report. Here we pin that the inventory never claims
    // an `Auto` backend identity.
    let inventory = probe_backend_inventory();
    for entry in &inventory {
        assert!(
            matches!(
                entry.backend,
                FilterBackend::Nftables
                    | FilterBackend::Ebpf
                    | FilterBackend::Pf
                    | FilterBackend::Wfp
                    | FilterBackend::WindowsFirewall
            ),
            "inventory backends are concrete, never Auto"
        );
    }
}

#[test]
fn linux_without_privilege_still_lists_nftables_with_reason() {
    // On Linux the nftables baseline is compiled into the build: even when
    // unusable (no privilege in CI), the inventory must describe it with a
    // reason rather than returning an empty list as the only way to express
    // "compiled but insufficient privilege".
    #[cfg(target_os = "linux")]
    {
        let inventory = probe_backend_inventory();
        let nft = inventory
            .iter()
            .find(|e| e.backend == FilterBackend::Nftables)
            .expect("Linux inventory always describes the nftables baseline");
        assert!(nft.compiled);
        if !nft.usable {
            assert!(
                nft.reason.contains("root")
                    || nft.reason.contains("CAP_NET_ADMIN")
                    || nft.reason.contains("nft"),
                "unusable nftables needs a privilege/mechanism reason, got: {}",
                nft.reason
            );
        }
    }
}
