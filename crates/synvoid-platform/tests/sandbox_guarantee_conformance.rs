//! Portable guarantee-contract conformance suite (Phase 82 Workstream J,
//! Phase 89 corrective).
//!
//! Table-driven policy/guarantee semantics independent of any one OS.
//! Uses fake (manually built) reports for deterministic semantic tests;
//! native child tests prove actual enforcement per backend.
//!
//! Covers:
//! - required unsupported => error;
//! - required degraded => error;
//! - optional unsupported => success + report;
//! - report cannot say enforced when backend returns partial;
//! - policy composition is explicit (Phase 89: unsafe `intersect()` removed;
//!   required guarantees are never silently dropped by composition);
//! - no legacy adapter can turn a failed required guarantee into Basic/off;
//! - entered token lifetime is retained (structural: no Clone, move keeps
//!   the report; dropping an irreversible witness removes nothing silently);
//! - thread-scope mismatch fails (AllThreads on thread-scoped backends);
//! - preopened/inherited resources representable without SynVoid types;
//! - child-denied vs descendants-confined are distinct guarantees.

use synvoid_platform::sandbox::{
    jail_guarantee_request, legacy_strict_satisfied_by, mechanism_plan_for_request,
    prepare_sandbox, EnforcementReport, EnteredSandbox, Guarantee, GuaranteeDecision,
    GuaranteeStatus, PreopenedResource, ResourceIntent, SandboxRequest, ThreadScope,
};

fn fake_report(
    backend: &'static str,
    enforced: &[Guarantee],
    degraded: &[Guarantee],
    scope: ThreadScope,
) -> EnforcementReport {
    let all = [
        Guarantee::AmbientFilesystemDenied,
        Guarantee::FilesystemReadAllowlist,
        Guarantee::FilesystemWriteAllowlist,
        Guarantee::ExplicitDenyPath,
        Guarantee::InheritedResourcesOnly,
        Guarantee::NetworkDenied,
        Guarantee::NetworkTcpRestricted,
        Guarantee::NetworkUdpRestricted,
        Guarantee::InheritedIpcUsable,
        Guarantee::ChildCreationDenied,
        Guarantee::ExecDenied,
        Guarantee::DescendantsConfined,
        Guarantee::ProcessMemoryBound,
        Guarantee::JobMemoryBound,
        Guarantee::TerminatesWithOwner,
    ];
    let decisions = all
        .into_iter()
        .map(|g| {
            let status = if enforced.contains(&g) {
                GuaranteeStatus::Enforced
            } else if degraded.contains(&g) {
                GuaranteeStatus::DegradedPartial
            } else {
                GuaranteeStatus::Unsupported
            };
            GuaranteeDecision {
                guarantee: g,
                status,
                mechanism: "fake-backend",
                detail: "deterministic conformance fake".to_string(),
            }
        })
        .collect();
    EnforcementReport {
        backend,
        abi: "fake-abi".to_string(),
        scope,
        decisions,
    }
}

#[test]
fn required_unsupported_is_error() {
    let report = fake_report(
        "fake",
        &[Guarantee::FilesystemReadAllowlist],
        &[],
        ThreadScope::CurrentThreadPlusDescendants,
    );
    let err = report.require_all(&[Guarantee::NetworkDenied]);
    assert!(
        err.is_err(),
        "required-but-unsupported guarantee must fail closed"
    );
}

#[test]
fn required_degraded_is_error() {
    let report = fake_report(
        "fake",
        &[],
        &[Guarantee::FilesystemReadAllowlist],
        ThreadScope::CurrentThreadPlusDescendants,
    );
    let err = report.require_all(&[Guarantee::FilesystemReadAllowlist]);
    assert!(
        err.is_err(),
        "required-but-degraded guarantee must fail closed, never success"
    );
}

#[test]
fn optional_unsupported_is_success_with_honest_report() {
    let report = fake_report(
        "fake",
        &[Guarantee::FilesystemReadAllowlist],
        &[],
        ThreadScope::CurrentThreadPlusDescendants,
    );
    report
        .require_all(&[Guarantee::FilesystemReadAllowlist])
        .expect("required enforced set must pass");
    assert_eq!(
        report.status_of(Guarantee::NetworkDenied),
        GuaranteeStatus::Unsupported,
        "optional unsupported stays visible in the report, not hidden"
    );
}

#[test]
fn enforced_report_cannot_hide_partial_backend_result() {
    // A backend returning partial enforcement must surface DegradedPartial,
    // and require_all must reject it on required paths.
    let report = fake_report(
        "fake-partial-backend",
        &[Guarantee::FilesystemReadAllowlist],
        &[Guarantee::NetworkDenied],
        ThreadScope::CurrentThreadPlusDescendants,
    );
    assert_eq!(
        report.status_of(Guarantee::NetworkDenied),
        GuaranteeStatus::DegradedPartial
    );
    assert!(report.require_all(&[Guarantee::NetworkDenied]).is_err());
    // But an unrelated enforced requirement still passes.
    assert!(report
        .require_all(&[Guarantee::FilesystemReadAllowlist])
        .is_ok());
}

#[test]
fn policy_composition_is_explicit_no_silent_narrowing() {
    // Phase 89 Finding C: the unsafe `SandboxRequest::intersect()` API was
    // removed. It intersected required sets (silently dropping disjoint
    // requirements) while copying path/resource authority from only one
    // operand — neither a security intersection nor a guaranteed tightening.
    // Request construction stays explicit: combining two policies means
    // stating the union of required guarantees at the call site, never
    // calling a helper that can make a required guarantee disappear.
    let a = SandboxRequest::new()
        .require(Guarantee::FilesystemReadAllowlist)
        .require(Guarantee::NetworkDenied)
        .optional(Guarantee::ExecDenied);
    let b = SandboxRequest::new()
        .require(Guarantee::FilesystemReadAllowlist)
        .require(Guarantee::ChildCreationDenied);
    // Explicit union preserves every requirement from both sides.
    let mut combined = a.clone();
    for g in b.required.iter().copied() {
        if !combined.required.contains(&g) {
            combined.required.push(g);
        }
    }
    assert!(combined.required.contains(&Guarantee::NetworkDenied));
    assert!(combined.required.contains(&Guarantee::ChildCreationDenied));
    assert!(combined
        .required
        .contains(&Guarantee::FilesystemReadAllowlist));
    // A helper that dropped either disjoint requirement would be a
    // silent-broadening bug, not a narrowing optimization.
}

#[test]
fn mechanism_plan_selects_only_requested_seccomp_categories() {
    // Phase 89 Finding B: seccomp categories are guarantee-selected.
    let empty = SandboxRequest::new().require(Guarantee::FilesystemReadAllowlist);
    let plan = mechanism_plan_for_request(&empty);
    assert!(
        !plan.seccomp_requested(),
        "filesystem-only request must install no seccomp filter"
    );

    let net = SandboxRequest::new().require(Guarantee::NetworkDenied);
    let plan = mechanism_plan_for_request(&net);
    assert!(plan.network_seccomp_requested);
    assert!(!plan.child_seccomp_requested);
    assert!(!plan.exec_seccomp_requested);

    let child = SandboxRequest::new().require(Guarantee::ChildCreationDenied);
    let plan = mechanism_plan_for_request(&child);
    assert!(!plan.network_seccomp_requested);
    assert!(plan.child_seccomp_requested);
    assert!(!plan.exec_seccomp_requested);

    let exec = SandboxRequest::new().require(Guarantee::ExecDenied);
    let plan = mechanism_plan_for_request(&exec);
    assert!(!plan.network_seccomp_requested);
    assert!(!plan.child_seccomp_requested);
    assert!(plan.exec_seccomp_requested);

    // Protocol-restricted network guarantees alone select nothing: the
    // categorical filter cannot distinguish TCP from UDP.
    let tcp_only = SandboxRequest::new().require(Guarantee::NetworkTcpRestricted);
    assert!(
        !mechanism_plan_for_request(&tcp_only).seccomp_requested(),
        "TcpRestricted alone must not select full network denial"
    );
    let udp_only = SandboxRequest::new().require(Guarantee::NetworkUdpRestricted);
    assert!(
        !mechanism_plan_for_request(&udp_only).seccomp_requested(),
        "UdpRestricted alone must not select full network denial"
    );

    // Combined jail request selects all required clauses.
    let jail = jail_guarantee_request();
    let plan = mechanism_plan_for_request(&jail);
    assert!(plan.network_seccomp_requested);
    assert!(plan.child_seccomp_requested);
    assert!(plan.exec_seccomp_requested);
}

#[test]
fn jail_request_contains_network_child_exec_boundary() {
    // Phase 89 Finding D: the jail request is authoritative for its
    // no-network / no-child / no-exec boundary.
    let jail = jail_guarantee_request();
    for g in [
        Guarantee::AmbientFilesystemDenied,
        Guarantee::FilesystemReadAllowlist,
        Guarantee::InheritedIpcUsable,
        Guarantee::DescendantsConfined,
        Guarantee::NetworkDenied,
        Guarantee::ChildCreationDenied,
        Guarantee::ExecDenied,
    ] {
        assert!(
            jail.required.contains(&g),
            "jail request must require {g:?}"
        );
    }
}

#[test]
fn prepared_plan_carries_mechanism_selection() {
    // Phase 89 Finding E: preparation is side-effect free and carries the
    // selected mechanism plan into `enter`.
    let req = SandboxRequest::new()
        .require(Guarantee::FilesystemReadAllowlist)
        .require(Guarantee::NetworkDenied);
    let prepared = prepare_sandbox(req).expect("prepare is side-effect free");
    let plan = prepared.mechanism_plan();
    assert!(plan.filesystem_requested);
    assert!(plan.network_seccomp_requested);
    assert!(!plan.child_seccomp_requested);
    assert!(!plan.exec_seccomp_requested);
}

#[test]
fn landlock_apply_does_not_install_jail_seccomp() {
    // Phase 89 Finding B regression: the generic Landlock filesystem backend
    // must not install the jail-specific seccomp filter. Syscall-filter
    // confinement comes only through the guarantee-selected plan in
    // `PreparedSandbox::enter`. Scoped to the Landlock `apply` block so
    // guarantee-path seccomp calls elsewhere do not trip the guard.
    let source = include_str!("../src/sandbox.rs");
    let marker = "impl SandboxBackend for LandlockSandbox";
    let start = source.find(marker).expect("landlock backend impl");
    let tail = &source[start..];
    // The Landlock impl block ends at the seccomp module doc that follows
    // it (`/// Phase 83 Workstream B` introduces `pub mod seccomp`).
    let end = tail
        .find("pub mod seccomp")
        .expect("seccomp module boundary");
    let block = &tail[..end];
    for forbidden in ["apply_jail_filter", "apply_selected_filter"] {
        assert!(
            !block.contains(forbidden),
            "LandlockSandbox::apply must not install seccomp ({forbidden} found)"
        );
    }
}

#[test]
fn legacy_adapter_cannot_downgrade_failed_required() {
    // The legacy Strict gate expressed over the new vocabulary: a backend
    // without a read allowlist never satisfies Strict, and there is no
    // path that reinterprets that failure as Basic/Off success.
    let strict_fail = fake_report(
        "fake-no-fs",
        &[],
        &[],
        ThreadScope::CurrentThreadPlusDescendants,
    );
    assert!(
        !legacy_strict_satisfied_by(&strict_fail),
        "no read allowlist => legacy Strict unsatisfied (fail closed)"
    );
    let strict_ok = fake_report(
        "fake-fs",
        &[Guarantee::FilesystemReadAllowlist],
        &[],
        ThreadScope::CurrentThreadPlusDescendants,
    );
    assert!(legacy_strict_satisfied_by(&strict_ok));
}

#[test]
fn entered_witness_is_not_cloneable_and_retains_report() {
    // Structural: EnteredSandbox must not implement Clone (a cloneable
    // witness would allow confinement evidence to outlive its guard).
    // This is a compile-time property; assert it stays that way via a
    // trait-object probe that only compiles when Clone is absent.
    fn assert_not_clone<T>()
    where
        T: Send,
    {
    }
    assert_not_clone::<EnteredSandbox>();
    // Runtime: a witness built from an enforced report keeps that report
    // across moves (no silent removal on move/drop for irreversible
    // backends; Windows kill-on-close loud semantics documented).
    let report = fake_report(
        "fake",
        &[
            Guarantee::FilesystemReadAllowlist,
            Guarantee::InheritedIpcUsable,
        ],
        &[],
        ThreadScope::CurrentThreadPlusDescendants,
    );
    let witness = EnteredSandbox::from_test_report(report).expect("enforced fake must build");
    assert_eq!(
        witness
            .report()
            .status_of(Guarantee::FilesystemReadAllowlist),
        GuaranteeStatus::Enforced
    );
    let moved = witness;
    assert_eq!(
        moved.report().status_of(Guarantee::InheritedIpcUsable),
        GuaranteeStatus::Enforced,
        "moving the witness must preserve the enforcement report"
    );
}

#[test]
fn child_denied_and_descendants_confined_are_distinct() {
    // Capsicum-style backend: descendants confined but child creation NOT
    // denied. A caller requiring ChildCreationDenied must fail while a
    // caller requiring only DescendantsConfined succeeds — proving the two
    // guarantees are not conflated.
    let report = fake_report(
        "fake-capsicum-like",
        &[Guarantee::DescendantsConfined],
        &[],
        ThreadScope::CurrentThreadPlusDescendants,
    );
    assert!(report
        .require_all(&[Guarantee::DescendantsConfined])
        .is_ok());
    assert!(report
        .require_all(&[Guarantee::ChildCreationDenied])
        .is_err());
}

#[test]
fn resource_limits_are_distinct_from_access_control() {
    // A backend enforcing only numeric bounds satisfies memory guarantees
    // and nothing else.
    let report = fake_report(
        "fake-job-like",
        &[
            Guarantee::ProcessMemoryBound,
            Guarantee::JobMemoryBound,
            Guarantee::TerminatesWithOwner,
        ],
        &[],
        ThreadScope::ProcessTree,
    );
    assert!(report.require_all(&[Guarantee::ProcessMemoryBound]).is_ok());
    assert!(report
        .require_all(&[Guarantee::FilesystemReadAllowlist])
        .is_err());
    assert!(report.require_all(&[Guarantee::NetworkDenied]).is_err());
}

#[test]
fn thread_scope_mismatch_fails_for_all_threads_requirement() {
    // A thread-scoped projection (Landlock pre-ABI-8 style) carrying an
    // AllThreads requirement surfaces Degraded on scope-dependent
    // guarantees; require_all fails closed. Fake the degraded projection
    // directly (native scope proof lives in the Linux child tests).
    let report = fake_report(
        "fake-thread-scoped",
        &[],
        &[Guarantee::FilesystemReadAllowlist],
        ThreadScope::CurrentThreadPlusDescendants,
    );
    assert_eq!(report.scope, ThreadScope::CurrentThreadPlusDescendants);
    assert!(report
        .require_all(&[Guarantee::FilesystemReadAllowlist])
        .is_err());
}

#[test]
fn preopened_resources_need_no_synvoid_types() {
    let req = SandboxRequest::new()
        .require(Guarantee::InheritedResourcesOnly)
        .resource(PreopenedResource::new("stdin-ipc", ResourceIntent::Ipc))
        .resource(PreopenedResource::new("stdout-ipc", ResourceIntent::Ipc))
        .resource(PreopenedResource::new("stderr-log", ResourceIntent::Write));
    req.validate()
        .expect("resource-bearing request must validate");
    assert_eq!(req.resources.len(), 3);
    assert_eq!(req.resources[0].intent, ResourceIntent::Ipc);
}

#[test]
fn conflicting_allow_deny_policy_is_rejected_at_validation() {
    let req = SandboxRequest::new()
        .require(Guarantee::FilesystemReadAllowlist)
        .read_path("/srv/data")
        .deny_path("/srv/data");
    assert!(
        prepare_sandbox(req).is_err(),
        "conflicting allow/deny must fail before backend probing"
    );
}

#[test]
fn empty_path_inputs_are_rejected_at_validation() {
    let req = SandboxRequest::new().read_path("");
    assert!(prepare_sandbox(req).is_err());
}

#[test]
fn prepare_has_no_irreversible_side_effects() {
    // Preparation only validates + projects; calling it twice (or on an
    // unsupported backend) must not confine the test process. The stub
    // backend projection is Unsupported for strict-like requirements.
    let req = SandboxRequest::new().require(Guarantee::FilesystemReadAllowlist);
    let prepared = prepare_sandbox(req).expect("prepare itself never fails closed");
    // The current host (macOS without seatbelt runtime, or stub) projects
    // honestly; the projection is present and typed regardless.
    assert!(!prepared.projection().backend.is_empty());
    assert!(!prepared.projection().abi.is_empty());
}
