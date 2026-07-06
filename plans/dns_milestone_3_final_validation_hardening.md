# DNS Milestone 3 Final Validation and Hardening Plan

## Context

DNS Milestone 3 is now substantially implemented. Recent work added deeper zone activation validation, stronger AXFR/IXFR tests, authorized UPDATE tests, NOTIFY behavior tests, DNSSEC known-vector tests, control-plane exclusion tests, and CI coverage for the new suites.

The remaining risk is not broad missing architecture. It is proof quality: CI observability, live signed-DNSSEC validation, valid TSIG success fixtures, record-by-record IXFR delta validation, and release-grade documentation of deferred behavior.

## Objective

Close DNS Milestone 3 with a hard validation pass that proves the advanced DNS feature layer is safe enough to hand off into Milestone 4 operability/performance/conformance work.

## Non-goals

Do not expand into Milestone 4 load testing, full production deployment profiles, anycast/mesh validation, HSM ceremony, or recursive resolver parity. Keep this pass limited to proving or explicitly deferring the remaining Milestone 3 correctness items.

## Current state to preserve

- `dns-tests` CI job includes Milestone 2 and Milestone 3 suites.
- `validate_zone_for_activation` rejects malformed zones before publication.
- AXFR tests assert SOA bracketing, expected records, TCP-only behavior, TSIG absence refusal, allowlist denial, unknown-zone denial, and coalescing exclusion.
- IXFR tests assert current-serial, older-retained serial, fallback/refusal, TSIG absence refusal, malformed SOA handling, and RFC1982 serial comparison.
- UPDATE tests assert authorized add/delete, prerequisite failure, SOA protection, CNAME conflict refusal, TSIG absence refusal, cache invalidation, and serial increment.
- NOTIFY and control-plane exclusion suites exist.
- DNSSEC known-vector tests cover key tags, digest lengths, canonical name/RDATA, and response flag encoding.

## Workstream 1: CI observability and status proof

Tasks:

- Inspect GitHub Actions workflow runs for the latest `main` commit.
- Confirm the `dns-tests` job actually ran after the newest suites were added.
- Capture pass/fail state for:
  - DNS fmt;
  - DNS clippy;
  - `cargo test -p synvoid-dns --release`;
  - each DNS integration suite;
  - `cargo check -p synvoid-dns --all-features`.
- If GitHub combined status remains empty, determine whether the issue is connector visibility, repository settings, direct-push behavior, or missing branch protection/status publication.
- Add a final validation note to `architecture/dns.md`, `architecture/dns_zone_lifecycle.md`, or the relevant plan file with the observed CI status.

Acceptance criteria:

- Latest DNS CI execution is confirmed passing, or exact failures are captured.
- If status visibility is unavailable, the cause is documented and not confused with DNS test failure.

## Workstream 2: Live signed DNSSEC response validation

Current risk:

- DNSSEC primitive tests are stronger, but live signed-answer behavior is not externally proven.

Tasks:

- Build or add a minimal signed authoritative test zone fixture.
- Start the DNS server on an ephemeral local port in a test or documented smoke script.
- Query signed records with DO=true and DO=false.
- Verify DO=true includes expected DNSSEC records where supported.
- Verify DO=false omits DNSSEC extras where policy requires.
- Verify authoritative signed responses do not set AD merely because the zone is locally signed.
- Verify DNSKEY query response shape.
- Verify NODATA/NXDOMAIN NSEC proof shape for supported cases.
- Add a local smoke script or ignored integration test for external tooling:

```bash
dig +dnssec @127.0.0.1 -p <port> <name> A
ldns-verify-zone <zonefile>
named-checkzone <origin> <zonefile>
```

- If `ldns-verify-zone` or `named-checkzone` cannot be included in CI, document local-only status.

Acceptance criteria:

- DNSSEC live response behavior is tested through the actual query path or explicitly deferred.
- External-tool smoke path is documented.
- Docs do not claim full production DNSSEC beyond the verified scope.

## Workstream 3: Valid TSIG success fixtures

Current risk:

- Tests prove TSIG-required paths reject absent TSIG. They do not yet prove valid TSIG success.

Tasks:

- Audit current TSIG implementation and supported algorithms.
- Add deterministic TSIG key fixture for tests.
- Build valid TSIG-signed UPDATE, AXFR, IXFR, and NOTIFY fixtures where handlers support TSIG verification.
- Test valid TSIG succeeds when client/source is authorized and feature is enabled.
- Test invalid MAC, wrong key name, wrong algorithm, and stale time are refused.
- Ensure TSIG material is redacted from logs/errors.

Required tests:

- valid TSIG UPDATE succeeds.
- valid TSIG AXFR succeeds.
- valid TSIG IXFR succeeds.
- valid TSIG NOTIFY succeeds or is explicitly deferred if NOTIFY TSIG is not wired.
- invalid TSIG variants fail deterministically.

Acceptance criteria:

- TSIG-required mode has both negative and positive coverage.
- If positive TSIG is not implemented, docs/config matrix mark it as partial rather than production-ready.

## Workstream 4: Record-by-record IXFR delta validation

Current risk:

- IXFR delta tests assert message counts and SOA structure, but not the exact delete/add RR semantics.

Tasks:

- Extend IXFR test parser to recover RR owner, type, TTL, and RDATA.
- Assert old SOA/delete section contains expected old serial and removed records.
- Assert new SOA/add section contains expected new serial and added records.
- Verify record ordering is deterministic and documented.
- Verify unrelated records are not included in deltas unless full fallback is intentionally used.
- Verify too-old fallback response is distinguishable from IXFR delta response.
- Add malformed IXFR additional SOA assertion that requires a deterministic error rather than ignoring the result.

Acceptance criteria:

- IXFR tests prove semantic deltas, not only structural shape.

## Workstream 5: UPDATE mutation atomicity and rollback proof

Current risk:

- UPDATE tests prove several refused cases leave serial unchanged, but every mutation path should be atomic with rollback on validation failure.

Tasks:

- Audit UPDATE implementation for clone-validate-swap behavior.
- Ensure mutations are applied to a candidate copy first.
- Validate candidate with `validate_zone_for_activation` before publication.
- Swap only after validation success.
- Prove failed update leaves records, serial, history, and cache unchanged unless policy says otherwise.
- Test multi-record update where first RR is valid and later RR invalid; no partial mutation should publish.
- Test cache invalidation happens only after successful update.

Acceptance criteria:

- UPDATE cannot partially mutate a zone.
- Failed update does not invalidate cache unnecessarily unless explicitly documented.

## Workstream 6: NOTIFY transfer scheduling semantics

Current risk:

- NOTIFY tests exist, but the exact accepted-newer-serial behavior should be explicit.

Tasks:

- Define whether accepted NOTIFY triggers immediate transfer, schedules transfer, or only records metadata.
- Add test for authorized newer serial matching that policy.
- Add test for equal/stale serial ignored.
- Add test for unknown zone policy.
- Add test for duplicate NOTIFY/rate limiting/dedupe if implemented.
- Document behavior in config matrix and architecture docs.

Acceptance criteria:

- NOTIFY cannot be interpreted as stronger than it is.
- Transfer scheduling behavior is deterministic.

## Workstream 7: Control-plane cache/coalescing proof completion

Tasks:

- Confirm `control_plane_exclusion` proves UPDATE, NOTIFY, AXFR, and IXFR never enter ordinary query coalescing.
- Confirm successful UPDATE invalidates positive and negative cache variants.
- Confirm failed UPDATE does not invalidate cache unless configured.
- Confirm transfer apply invalidates zone variants when implemented.
- Add tests for DNSSEC-shaped cache invalidation on zone key/signature changes if supported.

Acceptance criteria:

- Advanced control-plane operations cannot leave stale ordinary-answer cache state.

## Workstream 8: Documentation and deferral lock-down

Update:

- `architecture/dns.md`
- `architecture/dns_config_runtime_matrix.md`
- `architecture/dns_zone_lifecycle.md`
- `docs/dns-dnssec-architecture.md`
- `.opencode/skills/dns_dnssec/SKILL.md`
- `crates/synvoid-dns/AGENTS.override.md`

Document:

- DNSSEC verified scope and external validation status.
- TSIG positive/negative coverage status.
- IXFR semantic delta guarantees.
- UPDATE atomicity and rollback guarantees.
- NOTIFY scheduling/recording behavior.
- Any NSEC3 closest-encloser limitations.
- Any CI visibility limitations.

Acceptance criteria:

- No doc claims unsupported production behavior.
- Deferrals are explicit and test-backed where possible.

## Final commands

Run and record:

```bash
cargo fmt --all --check
cargo test -p synvoid-config dns
cargo test -p synvoid-dns
cargo test -p synvoid-dns --test axfr_ixfr_transfer_semantics
cargo test -p synvoid-dns --test update_authorized_semantics
cargo test -p synvoid-dns --test notify_behavior
cargo test -p synvoid-dns --test dnssec_known_vectors
cargo test -p synvoid-dns --test control_plane_exclusion
cargo test -p synvoid-dns --test encrypted_transport
cargo test -p synvoid-dns --test verification_gate
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

Optional external commands if tooling exists:

```bash
dig +dnssec @127.0.0.1 -p <port> <name> A
ldns-verify-zone <zonefile>
named-checkzone <origin> <zonefile>
```

## Completion criteria

Milestone 3 final validation is complete when:

- DNS CI status is confirmed or visibility limits are documented.
- Live signed DNSSEC response behavior is tested or explicitly deferred.
- TSIG-required success paths are covered or marked partial.
- IXFR deltas are verified record-by-record.
- UPDATE rollback is atomic for multi-record failure.
- NOTIFY accepted behavior is deterministic and documented.
- cache/coalescing exclusion proof is complete.
- docs/config matrix match the tested behavior.
