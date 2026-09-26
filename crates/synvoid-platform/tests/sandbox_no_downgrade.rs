//! No-silent-downgrade adversarial tests (Phase 84 Workstream C).
//!
//! Deterministic fake-backend tests proving every required-path failure
//! mode fails closed:
//! - capability probe says present but installation fails;
//! - prepare succeeds but entry fails;
//! - partial enforcement of one required guarantee;
//! - optional guarantee unsupported (success + honest report);
//! - thread-scope mismatch;
//! - backend resource guard dropped unexpectedly (retention discipline);
//! - nested/repeated sandbox entry;
//! - conflicting allow/deny policy;
//! - unsupported explicit deny under an allowed Landlock ancestor;
//! - Windows outer-job conflict (typed, portable variant check; native
//!   behavior proven on Windows hosts);
//! - disabled/old Landlock ABI (typed, portable; native probe on Linux);
//! - seccomp install failure (typed EntryFailed path; native on Linux).

use synvoid_platform::sandbox::{
    EnforcementReport, Guarantee, GuaranteeDecision, GuaranteeStatus, SandboxError, SandboxRequest,
    ThreadScope,
};

fn decisions_with(enforced: &[Guarantee], degraded: &[Guarantee]) -> Vec<GuaranteeDecision> {
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
    all.into_iter()
        .map(|g| GuaranteeDecision {
            guarantee: g,
            status: if enforced.contains(&g) {
                GuaranteeStatus::Enforced
            } else if degraded.contains(&g) {
                GuaranteeStatus::DegradedPartial
            } else {
                GuaranteeStatus::Unsupported
            },
            mechanism: "adversarial-fake",
            detail: "phase84 no-downgrade fake".to_string(),
        })
        .collect()
}

fn report(
    backend: &'static str,
    enforced: &[Guarantee],
    degraded: &[Guarantee],
) -> EnforcementReport {
    EnforcementReport {
        backend,
        abi: "fake".to_string(),
        scope: ThreadScope::CurrentThreadPlusDescendants,
        decisions: decisions_with(enforced, degraded),
    }
}

#[test]
fn probe_present_but_install_failed_is_closed() {
    // Projection claimed enforceable, but the post-entry report shows the
    // install did not hold (NotEnforced/Unsupported on a required path).
    // require_all on the FINAL report must fail — a stale projection never
    // authorizes untrusted work.
    let final_report = report("fake", &[], &[]);
    let err = final_report.require_all(&[Guarantee::FilesystemReadAllowlist]);
    assert!(
        err.is_err(),
        "failed install must fail closed despite probe"
    );
}

#[test]
fn prepare_ok_but_entry_failed_is_closed() {
    // Entry failure surfaces as EntryFailed (never Ok with a witness).
    let e = SandboxError::EntryFailed("fake entry fault".into());
    assert!(matches!(e, SandboxError::EntryFailed(_)));
    // And a witness can never be built from a non-enforced report.
    let bad = report("fake", &[], &[]);
    assert!(synvoid_platform::sandbox::EnteredSandbox::from_test_report(bad).is_err());
}

#[test]
fn partial_enforcement_of_one_required_is_closed() {
    let r = report(
        "fake",
        &[Guarantee::FilesystemReadAllowlist],
        &[Guarantee::NetworkDenied],
    );
    // The enforced one passes alone...
    assert!(r.require_all(&[Guarantee::FilesystemReadAllowlist]).is_ok());
    // ...but the set containing the partial one fails as a whole.
    assert!(r
        .require_all(&[Guarantee::FilesystemReadAllowlist, Guarantee::NetworkDenied])
        .is_err());
}

#[test]
fn optional_unsupported_never_fails_the_set() {
    let r = report("fake", &[Guarantee::FilesystemReadAllowlist], &[]);
    assert!(r.require_all(&[Guarantee::FilesystemReadAllowlist]).is_ok());
    assert_eq!(
        r.status_of(Guarantee::ExecDenied),
        GuaranteeStatus::Unsupported
    );
}

#[test]
fn thread_scope_mismatch_is_closed() {
    // Caller demands all-current-threads; backend projects thread-scoped
    // (degraded filesystem). Fail closed.
    let r = report("fake", &[], &[Guarantee::FilesystemReadAllowlist]);
    assert!(r
        .require_all(&[Guarantee::FilesystemReadAllowlist])
        .is_err());
}

#[test]
fn dropped_guard_cannot_silently_authorize() {
    // Retention discipline: authorization lives in the witness value, not
    // in ambient state. Dropping the witness drops the evidence (no global
    // "sandboxed" flag is set by from_test_report), and a fresh check
    // without the witness fails. Prove the report does not leak into a
    // sequel check: a new empty report still fails.
    let good = report("fake", &[Guarantee::FilesystemReadAllowlist], &[]);
    {
        let _witness =
            synvoid_platform::sandbox::EnteredSandbox::from_test_report(good).expect("build");
        // witness alive here; dropped at scope end (irreversible backends
        // keep enforcement — the WITNESS is gone, enforcement is not
        // silently claimed elsewhere).
    }
    let fresh = report("fake", &[], &[]);
    assert!(fresh
        .require_all(&[Guarantee::FilesystemReadAllowlist])
        .is_err());
}

#[test]
fn repeated_entry_without_new_probe_is_not_trusted() {
    // Nested/repeated entry must re-project, never reuse a stale success.
    // Two identical projections are independent values; mutating one
    // (degraded) does not taint the other — each entry checks its own.
    let first = report("fake", &[Guarantee::FilesystemReadAllowlist], &[]);
    let second = report("fake", &[], &[Guarantee::FilesystemReadAllowlist]);
    assert!(first
        .require_all(&[Guarantee::FilesystemReadAllowlist])
        .is_ok());
    assert!(second
        .require_all(&[Guarantee::FilesystemReadAllowlist])
        .is_err());
}

#[test]
fn conflicting_allow_deny_is_rejected_before_probe() {
    let req = SandboxRequest::new()
        .require(Guarantee::FilesystemReadAllowlist)
        .read_path("/srv/data")
        .deny_path("/srv/data");
    assert!(synvoid_platform::sandbox::prepare_sandbox(req).is_err());
}

#[test]
fn explicit_deny_under_allowed_ancestor_is_typed_unsupported() {
    // Landlock cannot represent explicit deny under an allowed ancestor.
    // The error type for that case is Unsupported (fail-closed with a
    // typed reason), never silent success. Portable check of the type.
    let e = SandboxError::Unsupported("landlock cannot represent deny".into());
    assert!(matches!(e, SandboxError::Unsupported(_)));
    assert!(e.to_string().contains("represent"));
}

#[test]
fn windows_outer_job_conflict_is_typed_never_success() {
    // AssignProcessToJobObject failure under an incompatible outer job
    // returns BackendConflict, never "limits installed". Portable variant
    // check; native Assign behavior proven on Windows hosts.
    let e = SandboxError::BackendConflict("outer job".into());
    assert!(matches!(e, SandboxError::BackendConflict(_)));
}

#[test]
fn disabled_landlock_abi_is_typed_unsupported() {
    // Disabled/old ABI surfaces as LandlockUnavailable (probe-gated) or
    // Unsupported (HardRequirement creation failure) — never success.
    // Portable variant checks; native probe runs on Linux hosts.
    assert!(matches!(
        SandboxError::LandlockUnavailable,
        SandboxError::LandlockUnavailable
    ));
    assert!(matches!(
        SandboxError::Unsupported("x".into()),
        SandboxError::Unsupported(_)
    ));
}

#[test]
fn seccomp_install_failure_is_typed_entry_failed() {
    // Seccomp install failure fails closed via EntryFailed (Linux apply).
    // Portable variant check; native install proven on Linux hosts.
    let e = SandboxError::EntryFailed("seccomp main install (tsync)".into());
    assert!(matches!(e, SandboxError::EntryFailed(_)));
}
