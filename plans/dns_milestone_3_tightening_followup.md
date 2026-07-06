# DNS Milestone 3 Tightening Follow-up Plan

## Context

The Milestone 3 corrective semantics pass substantially improved the DNS subsystem. It added Milestone 3 suites to CI, introduced a validated reload helper, moved zone activation validation into config/store load paths, rewrote the verification-gate reload tests to assert failed-reload preservation, and added a `control_plane_authorization` suite for UPDATE/NOTIFY/AXFR/IXFR deny-by-default behavior.

Remaining gaps are now narrower and mostly about turning partial assertions into stronger protocol-level proof:

- GitHub Actions status is not yet confirmed through the connector, even though the workflow now defines the right DNS job.
- Zone activation validation is still intentionally minimal: origin sanity plus exactly one apex SOA.
- AXFR success is only weakly asserted as non-empty/longer-than-header, not as a true SOA-bracketed ordered transfer.
- UPDATE tests still emphasize disabled/malformed/nonexistent-zone cases and do not fully prove authorized success, prerequisite failure, TSIG policy, or SOA protection.
- IXFR behavior is tested mostly for default denial, not current-serial no-op, fallback/refusal, or delta ordering.
- DNSSEC tests are better, but still need known-vector DS/key-tag/RRSIG/denial-proof verification and external-tool smoke coverage where feasible.

## Objective

Finish the next tightening layer for Milestone 3 by replacing weak protocol assertions with strict, behavior-level tests and targeted implementation fixes. This pass should leave zone mutation/transfer and DNSSEC test coverage strong enough that future changes cannot regress core advanced DNS semantics silently.

## Non-goals

Do not broaden into high-scale DNS performance testing, full recursive resolver parity, HSM production ceremony, anycast/mesh DNS deployment validation, or complete NSEC3 closest-encloser production support. Keep this pass focused on the remaining correctness gaps observed after the latest corrective pass.

## Workstream 1: Confirm CI execution and make DNS job observable

Current state:

- `dns-tests` includes DNS unit tests, key integration suites, Milestone 3 `encrypted_transport`, `verification_gate`, `control_plane_authorization`, and `cargo check -p synvoid-dns --all-features`.
- Connector status checks still appeared empty for `main`.

Tasks:

- Inspect GitHub Actions runs for the latest `main` commit.
- Confirm the `dns-tests` job runs on push and pull request.
- Confirm the job includes:
  - `cargo fmt -p synvoid-dns -- --check`
  - `cargo clippy -p synvoid-dns --all-targets -- -D warnings`
  - `cargo test -p synvoid-dns --release`
  - `authoritative_negative`
  - `dns_config_fidelity`
  - `dns_recursive_isolation`
  - `transport_lifecycle`
  - `encrypted_transport`
  - `verification_gate`
  - `control_plane_authorization`
  - `cargo check -p synvoid-dns --all-features`
- If status checks remain unavailable, document whether repository settings, direct pushes, or connector limitations are responsible.
- Add a completion record to the relevant plan or architecture note with the observed CI result.

Acceptance criteria:

- Latest DNS CI run is confirmed passing or exact failure is documented.
- If unavailable, the reason for missing status visibility is documented.
- DNS CI signal is distinct from unrelated workspace jobs.

## Workstream 2: Deepen zone activation validation

Current state:

- `validate_zone_for_activation` enforces non-empty printable origin and exactly one apex SOA.
- `load_zones`, `load_zones_from_store`, and `replace_zone_with_validation` call it before publication.

Tasks:

- Extend validation beyond SOA count:
  - reject owner names with illegal label length or empty interior labels;
  - reject names outside the zone origin unless explicitly supported as glue/target values;
  - reject unsupported `RecordType::NULL` records from config `Other` unless explicitly allowed;
  - validate TTL bounds against configured min/max where available;
  - validate MX/SRV priority range at the activation gate, not only while loading config;
  - validate SOA numeric fields and ensure this logic is shared by config/store/update paths;
  - validate A and AAAA values parse as IP addresses;
  - validate CNAME exclusivity: no other data at an owner with CNAME except DNSSEC records if policy permits;
  - validate NS/MX/SRV/CNAME target names are syntactically valid.
- Keep validation conservative: reject ambiguous records rather than accepting and relying on encoder failure.
- Add a validation error enum if string errors become hard to test.

Required tests:

- invalid A address rejected.
- invalid AAAA address rejected.
- invalid owner label rejected.
- owner with CNAME and A rejected.
- unsupported `Other`/NULL config record rejected.
- MX/SRV priority over u16 max rejected in validated activation path.
- SOA field parsing shared and tested for config and store candidates.
- valid glue-like target names accepted if policy allows.

Acceptance criteria:

- invalid authoritative data cannot become active through config, store, transfer, or update paths.
- validation errors are deterministic enough for tests and operator diagnostics.

## Workstream 3: Strengthen AXFR response assertions

Current state:

- AXFR denied-by-default and allowed-client success are tested.
- Allowed success is only asserted as non-empty and longer than one DNS header.

Tasks:

- Add a transfer response parser/test helper that can parse AXFR response message sequence or at minimum scan the wire response into resource records.
- Assert opening SOA exists and is first transfer RR.
- Assert closing SOA exists and is last transfer RR.
- Assert the opening and closing SOA records match expected zone serial.
- Assert all expected zone records appear exactly once between SOA brackets, unless the implementation intentionally repeats SOA only at boundaries.
- Assert AXFR is TCP-only when configured.
- Assert AXFR refuses when TSIG is required and absent.
- Assert allowed AXFR with required TSIG succeeds only with valid TSIG if test fixtures can build one; otherwise add a precise deferral.
- Assert AXFR never enters cache/coalescing path.

Required tests:

- allowed AXFR is SOA-bracketed.
- allowed AXFR includes expected A/NS/SOA records.
- AXFR over UDP refused when tcp-only.
- AXFR require-TSIG absent refused.
- AXFR unauthorized client refused.
- AXFR unknown zone refused or returns deterministic error.

Acceptance criteria:

- AXFR success test proves actual transfer semantics rather than response size.

## Workstream 4: Strengthen IXFR behavior tests

Current state:

- IXFR denied by default is tested.
- Current-serial, too-old serial, fallback/refusal, and delta ordering are not yet strongly proven.

Tasks:

- Add fixtures with zone history entries and serial progression.
- Test IXFR request where client serial equals current serial.
- Test IXFR from older retained serial returns ordered deltas.
- Test IXFR from too-old serial follows configured fallback policy:
  - fallback to AXFR when enabled and authorized;
  - refusal/error when fallback disabled.
- Test IXFR respects allowlist and TSIG policy independently from AXFR.
- Test malformed IXFR additional SOA is rejected deterministically.
- Test IXFR uses RFC1982 serial comparison, including wraparound cases.

Required tests:

- current-serial IXFR no-op/deterministic response.
- older retained serial returns ordered delta response.
- too-old serial fallback to AXFR when enabled.
- too-old serial refused when fallback disabled.
- malformed IXFR SOA refused.
- IXFR require-TSIG absent refused.
- serial wraparound comparison covered in IXFR path.

Acceptance criteria:

- IXFR behavior is bounded, authorized, and serial-aware.

## Workstream 5: Authorized UPDATE and prerequisite semantics

Current state:

- UPDATE disabled-by-default, malformed/nonexistent-zone mutation safety, and error RCODE behavior are tested.
- Authorized success, prerequisite failure, TSIG policy, duplicate/final-SOA protection, and cache invalidation need stronger coverage.

Tasks:

- Build realistic UPDATE wire fixtures with prerequisite and update sections.
- Add helper functions for prerequisite-only, add-record, delete-record, and SOA mutation attempts.
- Test authorized update success when enabled and client policy permits.
- Test prerequisite failure leaves zone unchanged.
- Test update that removes the final SOA is refused.
- Test update that creates duplicate apex SOA is refused.
- Test update that creates invalid CNAME coexistence is refused.
- Test update requiring TSIG refuses absent/invalid TSIG.
- Test successful update invalidates affected positive and negative cache entries.
- Test accepted update increments serial or follows documented serial policy.

Required tests:

- authorized add A record succeeds.
- authorized delete A record succeeds.
- prerequisite NXRRSET/YXRRSET failure leaves zone unchanged.
- final SOA deletion refused.
- duplicate SOA add refused.
- invalid record value refused.
- TSIG required absent refused.
- successful update invalidates cache.
- successful update serial policy tested.

Acceptance criteria:

- UPDATE is safe to enable only under explicit config and cannot corrupt zone invariants.

## Workstream 6: NOTIFY behavior tightening

Current state:

- NOTIFY disabled-by-default and source allowlist non-mutation are tested.

Tasks:

- Test authorized NOTIFY with newer serial schedules or triggers the intended reload/transfer behavior.
- Test authorized NOTIFY with stale/equal serial is ignored.
- Test unknown zone NOTIFY policy.
- Test NOTIFY requiring TSIG refuses absent/invalid TSIG if supported.
- Test NOTIFY rate limiting or dedupe if implemented.
- Document if NOTIFY currently records/schedules only and does not perform transfer.

Required tests:

- authorized newer serial accepted/scheduled.
- stale serial ignored.
- unknown zone refused/ignored according to policy.
- unauthorized source refused/ignored.
- TSIG-required absent refused if supported.

Acceptance criteria:

- NOTIFY cannot cause unauthorized mutation or transfer storms.

## Workstream 7: DNSSEC known-vector and response-shape verification

Current state:

- Tests assert algorithm/digest constants and some NSEC bitmap encoding.
- Key manager scaffolding exists, but DNSSEC correctness is not externally proven.

Tasks:

- Add known-vector tests for:
  - DNSKEY key tag;
  - DS digest generation using canonical owner name + DNSKEY RDATA;
  - RRSIG RDATA fields;
  - canonical RRset ordering;
  - canonical owner-name casing;
  - NSEC type bitmap for multiple windows if supported.
- Separate CDS generation from parent DS generation. If current CDS helper does not include owner-name digest context, document and test it as CDS RDATA only, not DS digest output.
- Test DO=true signed response includes DNSSEC records.
- Test DO=false signed response omits DNSSEC extras.
- Test authoritative signed response AD=false.
- Test DNSKEY query returns DNSKEY and RRSIG when signed and DO=true.
- Test NODATA/NXDOMAIN denial proofs for NSEC-supported cases.
- Explicitly mark NSEC3 closest-encloser production proofs as deferred unless fully implemented and tested.

External/tooling smoke:

- Add a documented local script or ignored integration test for:

```bash
dig +dnssec @127.0.0.1 -p <port> <name> A
ldns-verify-zone <zonefile>
named-checkzone <origin> <zonefile>
```

Acceptance criteria:

- DNSSEC tests verify protocol output rather than only object scaffolding.
- Unsupported DNSSEC proof modes are explicit deferrals.

## Workstream 8: Control-plane cache/coalescing exclusion proof

Tasks:

- Add tests proving AXFR, IXFR, UPDATE, and NOTIFY never use ordinary query coalescing.
- Add tests proving successful UPDATE/transfer apply invalidates authoritative cache variants.
- Add tests proving failed update/failed reload does not invalidate cache unnecessarily unless policy says otherwise.
- Add tests proving negative cache entries are invalidated on record creation.
- Add tests proving positive cache entries are invalidated on record deletion.

Acceptance criteria:

- control-plane operations cannot reuse or leave stale data in ordinary answer cache/coalescing paths.

## Workstream 9: Documentation and config matrix reconciliation

Update after behavior changes:

- `architecture/dns.md`
- `architecture/dns_config_runtime_matrix.md`
- `architecture/dns_zone_lifecycle.md`
- `.opencode/skills/dns_dnssec/SKILL.md`
- `crates/synvoid-dns/AGENTS.override.md`

Document:

- validated zone activation invariants;
- production-safe reload helper behavior;
- raw store insert boundary;
- AXFR/IXFR test guarantees;
- UPDATE prerequisite and SOA protection policy;
- DNSSEC known-vector coverage and deferrals;
- CI status/observability.

Acceptance criteria:

- docs no longer imply unsupported transfer/update/DNSSEC behavior.
- future agents are directed to production-safe helpers, not raw insert paths.

## Workstream 10: Final verification record

Run and record:

```bash
cargo fmt --all --check
cargo test -p synvoid-config dns
cargo test -p synvoid-dns
cargo test -p synvoid-dns --test encrypted_transport
cargo test -p synvoid-dns --test verification_gate
cargo test -p synvoid-dns --test control_plane_authorization
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

If external DNSSEC tools are available, also record:

```bash
ldns-verify-zone <zonefile>
named-checkzone <origin> <zonefile>
```

Acceptance criteria:

- DNS-specific local checks pass.
- DNS CI job status is recorded or absence is explained.
- Remaining DNSSEC/IXFR/TSIG deferrals are explicit.

## Completion criteria

This tightening pass is complete when:

- DNS CI execution is confirmed or status visibility gap is documented.
- zone activation rejects malformed records beyond SOA count/origin sanity.
- AXFR success tests prove SOA-bracketed ordered transfer semantics.
- IXFR current/old/too-old/fallback/refusal behavior is tested.
- UPDATE authorized success, prerequisites, TSIG policy, SOA protection, serial policy, and cache invalidation are tested.
- NOTIFY authorized/stale/unknown-zone policy is tested.
- DNSSEC has known-vector and response-shape tests, with NSEC3/external-tool limitations clearly documented.
- control-plane cache/coalescing exclusions are proven.
- docs and config matrix match the strengthened behavior.
