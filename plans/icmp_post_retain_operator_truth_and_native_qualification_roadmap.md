# ICMP Post-RETAIN Operator Truth and Native Qualification Roadmap (Phases 90–91)

Status: closed 2026-09-26 (Phase 90 operator truth closed; Phase 91 harness/preparation closed with no privileged run available; RETAIN unchanged, no Phase 92 registered).

Registered in: `plans/roadmap.md`.

Baseline: `main` at `0c8d3cac2fb214932c22dc360057acdad3c44c98`.

Predecessor: Phases 85–88 are closed **RETAIN** in
`architecture/icmp_policy_enforcement_extraction_readiness.md`. That
extraction disposition remains in force. This campaign improves SynVoid's
internal ICMP boundary and prepares safe native qualification; it does not
publish, split, or externalize the crate.

## Why another focused campaign is justified

Phase 88 intentionally left two classes of residual work:

1. the enforcement core now has `EnforcementReport` and `verify_live()`, but
   the operator/admin surface still reports the pre-Phase-87 compatibility
   view;
2. privileged kernel qualification is still a re-evaluation trigger, but the
   repository has no dedicated safe harness for producing that evidence.

Current-head review also found a consumer contract defect not captured by the
Phase 88 closeout: the admin UI's ICMP page still models a ping/health-probe
domain (`active`, `backends_count`, `last_ping`, node/address/latency)
while the server endpoint represents firewall enforcement and
`/icmp/backends` returns an object with `backends` plus
`current_backend`. The UI therefore cannot be treated as a truthful consumer
of the current server contract.

A second lifecycle gap is adjacent to the status problem:
`IcmpFilterManager::update_config()` uses the Phase 87 transactional driver,
but manager `enable()` / `disable()` still call the backend directly. Those
operations can therefore change kernel state without advancing the same
desired/applied/verified driver state exposed by `report()`.

## Binding principles

1. Operator-visible status is derived from verified enforcement truth, not a
   compatibility `enabled` boolean.
2. Requested backend and selected backend are different facts and must not be
   conflated.
3. An unsupported packet counter is absent/unknown, never fabricated as zero.
4. Enable, disable, and config replacement must all update one lifecycle state
   machine.
5. A GET/status path may perform bounded read-only verification, but must not
   mutate firewall policy.
6. Existing admin wire fields may be retained temporarily for compatibility,
   but their semantics must be documented and no new consumer may depend on
   ambiguous legacy meanings.
7. Native qualification must never run in the host/default network namespace
   when a disposable network namespace can provide equivalent proof.
8. A privileged harness must fail closed on missing prerequisites, use
   collision-resistant owned object names, and clean up on success/failure.
9. Building the qualification harness is executable work now. Passing the
   privileged matrix is not a Phase 91 closure requirement when no suitable
   host is available.
10. Phases 85–88 remain closed and the RETAIN extraction decision remains
    authoritative until its documented re-evaluation triggers are actually met.

## Execution order

### Phase 90 — Operator Enforcement Truth and Admin Contract Reconciliation

Plan:
`plans/phase_90_icmp_operator_enforcement_truth_and_admin_contract.md`.

Make the Phase 87 state machine authoritative across enable/disable/config
operations, expose live enforcement truth through the admin API, reconcile the
backend-list endpoint, and rewrite the ICMP admin UI against the actual
filtering domain.

### Phase 91 — Privileged Native Qualification Harness Preparation

Plan:
`plans/phase_91_icmp_privileged_native_qualification_harness.md`.

Build a safe, opt-in Linux nftables qualification harness using disposable
network namespaces/veth topology so the Phase 88 native-proof trigger can be
run reproducibly on a suitable privileged Linux host. Phase 91 closes when the
harness, safety gates, fixtures, and non-privileged behavior are implemented
and tested; actual privileged evidence is recorded when a host is available.

No Phase 92 native-qualification decision is registered now. Register it only
after there is an available host/environment capable of producing the required
evidence.

## Campaign acceptance criteria

- manager enable/disable/config mutation share one desired/applied/verified
  lifecycle;
- admin status exposes selected backend and
  Applied/Absent/Drifted/Unknown truth;
- live verification failures remain visible rather than becoming "enabled";
- fabricated all-zero packet statistics are removed;
- backend inventory reports probe/availability truth rather than hardcoded
  `available: true`;
- admin UI consumes the real status/backends contract and no longer displays
  probe-node/latency concepts;
- OpenAPI/admin contract tests pin the resulting wire shape;
- a Linux qualification harness exists that isolates firewall state in network
  namespaces, has deterministic cleanup, and is opt-in;
- non-root/routine CI can exercise harness validation/dry-run behavior without
  changing firewall state;
- the privileged matrix remains an explicit future evidence trigger rather
  than being falsely marked passed;
- no extraction/publication status changes in this campaign.
