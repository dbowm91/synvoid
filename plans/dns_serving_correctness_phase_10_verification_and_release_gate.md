# Phase 10 Plan: Verification and Release Gate

Status: **IMPLEMENTED** (2026-11-19; gate evidence and the exact command/
count matrix are in `architecture/dns_serving_correctness_closeout.md`).
Audit: `plans/dns_capability_audit.md` (D1–D39; this phase closes none of them
by itself and gates the campaign).
Registered in: `plans/roadmap.md`.
Campaign: `plans/dns_serving_correctness_roadmap.md`.
Predecessor: Phases 01–09.
Depends on: every phase being implemented; this phase changes no DNS behavior
except documentation and CI.

## Objective

Prove the campaign's claims with evidence a reviewer can rerun, and correct every
document that currently overstates DNS readiness. The audit's core criticism is
that the suite was green while the server was wrong; this phase exists so the
same thing cannot happen again.

## Work

### W1 — Verification matrix, executed and recorded

Run, in order, and record the exact counts and SHA:

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-dns -p synvoid-config -p synvoid-http --profile ci --all-targets -- -D warnings
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-dns --release --test dns_wire_contract \
  --test dns_envelope_contract --test dns_admission_contract \
  --test dnssec_signature_contract --test dnssec_denial_contract \
  --test dns_recursive_contract --test dns_control_plane_contract \
  --test dns_truthfulness_contract --test dns_authoritative_lookup
cargo test -p synvoid-dns --release --features mesh --test dns_mesh_trust_contract
cargo build --profile ci --bin synvoid
cargo xtask verify
```

The mesh-trust suite is `#[cfg(feature = "mesh")]`; running it without the
feature compiles the file and executes zero tests, which is a false green. Its
`verify_steps()` entry and its conformance lane must pass `--features mesh`.

The release-profile run is the one `scripts/dns/conformance.sh --release`
already performs for its enumerated lanes; extend that script's internal lane
list to include the ten new suites so the conformance run and the matrix
cannot drift.

### W2 — CI registration audit

For each new suite, confirm a `dns-*` step exists in `verify_steps()`
(`tools/xtask/src/verify.rs:131`; the routine lane CI runs) with a `--list`
count guard. Today CI has exactly one test step, `cargo xtask verify`, and no
DNS suite is named anywhere in `.github/workflows/ci.yml`; a suite that is not in
`verify_steps()` is invisible. The phase is not complete while any of the ten
suites runs only locally.

### W3 — External interop, actually executed

`scripts/dns/conformance.sh:136` detects `dig`, `kdig`, `delv`,
`ldns-verify-zone`, `named-checkzone`, and `curl`, but every external check is a
`[READY]/[SKIP]` placeholder. Replace the placeholders with real runs against a
server the script starts:

- `delv @127.0.0.1 -p <port> +root=... example.com A` for a signed zone, and
  `+cd` to show the difference;
- `ldns-verify-zone` on a zone the server exports, when the tool is present;
- `dig` for A, AAAA, NXDOMAIN, NODATA, `+dnssec`, `+bufsize=512`, and a TCP
  query;
- `kdig +tls` / `+https` when a DoT/DoH listener is configured.

Absent tools stay `[SKIP]` with the exact command printed, and the script's exit
code does not depend on them. The campaign's claim in phase 10's evidence is
"external validation: <tool> <version>, <commands>", or "not available in this
environment" — never "validated" when the tool was skipped.

### W4 — Fuzz registration and smoke

`fuzz/dns_edns_options.rs` and `fuzz/dns_tsig_parse.rs` are registered as
`[[bin]]` in `fuzz/Cargo.toml`, with corpus seeds committed. Record a 60-second
smoke run per target in the closeout. Fuzz is not in CI; say so in the evidence
rather than implying coverage.

### W5 — Documentation truth

- `docs/FEATURE_STATUS.md`: until this phase's matrix is green, the DNS row
  moves from "Yes" to "No — correctness campaign in progress" with a pointer to
  the roadmap. After green, restore "Yes" with a link to the closeout and the
  exact SHA.
- `docs/dns-dnssec-architecture.md`: validation is local only for
  `upstream_provider = Recursive`; forwarding delegates and the server reports
  `delegated`; NSEC3 hashing and proof construction described as implemented and
  vector-tested; RFC 5011 removed (or implemented, per phase 06's decision).
- `docs/RFC5011_TRUST_ANCHOR.md`: either deleted (if T5 is taken) or rewritten
  with the signature-by-anchor requirement and a pointer to the code.
- `docs/CONFIGURATION.md`: the fail-closed list stays; add the new
  `require_cookie`, `allow_unvalidated_forwarding`, and
  `authorized_domains` knobs if the phases add them, and state that transfers
  and updates remain rejected.
- `docs/testing/verification-contract.md`: fix the stale lane names
  (`dns_interop_encrypted` and `dns_stress` no longer exist) and add the eight
  new suites.
- `plans/dns_capability_audit.md`: flip each finding to "closed in <phase>" with
  the test that proves it, or "deferred — <reason>" and an owner decision.
- `plans/roadmap.md`: move the campaign section to its terminal status with the
  closeout pointer.

### W6 — Closeout evidence

Write `architecture/dns_serving_correctness_closeout.md` with: baseline SHA,
per-phase implementation SHAs, the command list above with outputs summarized,
counts per suite, external tool versions and commands (or the skip reason),
fuzz smoke results, any deferred finding with its rationale, and the exact list
of behaviors that changed for operators (owner names now FQDNs, EDNS sizes
honored, stale policy, TSIG canonical, health flags).

## Gate criteria

The campaign closes only when all of these hold:

1. D1–D39 are closed, or explicitly deferred by an owner decision recorded in
   the audit document.
2. `cargo xtask verify` is green on the closeout SHA, and every new suite is in
   `verify_steps()`.
3. The release-profile run of the ten suites is green, executed through
   `scripts/dns/conformance.sh --release`.
4. At least one external validator (`delv` or `ldns-verify-zone`) accepts a
   signed zone served by this binary, or the closeout states that no validator
   was available and the evidence is the in-process verification.
5. No document claims a control that the runtime does not realize; `/health`
   capability flags are covered by a test that toggles each control.
6. The audit document and `plans/roadmap.md` are updated.

## Risks

- **Wire changes are not backward compatible.** Responses change from malformed
  to well-formed; a client that somehow parsed the old bytes (there is no such
  client) is not supported. No version negotiation is added.
- **Signing changes invalidate cached RRSIGs.** Operators must flush caches;
  the closeout lists it.
- **Cookie enforcement and `allow_unvalidated_forwarding` default changes** can
  break an existing config; both are opt-in with a startup error that names the
  knob.
- **History rewrite is not needed**: the audit and plans are additive.

## Out of scope

- New DNS features (RPZ, anycast, prefetch, DoH JSON changes).
- Lifting the transfer/update config gates (separate product decision).
- Performance tuning beyond the clone removal from phase 09.

## Deliverables

- `architecture/dns_serving_correctness_closeout.md`
- updated `docs/FEATURE_STATUS.md`, `docs/dns-dnssec-architecture.md`,
  `docs/CONFIGURATION.md`, `docs/testing/verification-contract.md`
- updated `plans/dns_capability_audit.md` and `plans/roadmap.md`
- ten new suites registered in `verify_steps()` and in
  `scripts/dns/conformance.sh`
