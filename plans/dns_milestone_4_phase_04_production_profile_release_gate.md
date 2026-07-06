# DNS Milestone 4 Phase 4: Production Profile and Release Gate

## Objective

Define and verify a production-ready DNS deployment profile for Synvoid. This phase turns the preceding observability, performance, and conformance work into a release gate with safe defaults, documented operational profiles, and explicit deferrals.

## Context

DNS is now protocol-hardened enough to require a production posture decision: what is supported, what is safe by default, what is experimental, and what operators must configure explicitly. This phase closes Milestone 4 only when those answers are encoded in config, docs, examples, CI, and release notes.

## Non-goals

Do not add new DNS features. Do not claim parity with mature authoritative/recursive DNS servers beyond tested scope. Do not hide limitations; unsupported behavior must remain explicit.

## Workstream 1: Production profile definition

Tasks:

- Define supported deployment profiles:
  - authoritative-only public profile;
  - local recursive profile;
  - internal recursive profile;
  - transfer-enabled primary profile;
  - transfer-enabled secondary profile if supported;
  - DNSSEC-signed authoritative profile;
  - encrypted-transport profile.
- For each profile, document required config, defaults, risks, and verification commands.
- Define which profiles are production-supported, beta, or experimental.

Acceptance criteria:

- production support status is explicit and operator-facing.

## Workstream 2: Safe defaults audit

Tasks:

- Confirm recursion disabled by default.
- Confirm UPDATE disabled by default.
- Confirm NOTIFY disabled or harmless by default.
- Confirm AXFR/IXFR deny-by-default.
- Confirm TSIG-required modes are documented for control-plane operations.
- Confirm DNSSEC incomplete modes cannot be accidentally advertised as production-ready.
- Confirm encrypted transports fail closed on invalid cert/config.
- Confirm anycast/mesh DNS settings are explicit and not accidentally enabled.

Acceptance criteria:

- default DNS config is safe for production startup without exposing control-plane or open-recursive behavior.

## Workstream 3: Example config pruning and hardening

Tasks:

- Review DNS example config files.
- Remove aspirational or unsupported options from production examples.
- Add separate advanced examples for DNSSEC, transfer, recursive, and encrypted transports.
- Add comments warning about UPDATE/AXFR/IXFR/recursive exposure.
- Ensure example config validates and can be used by tests or smoke scripts.

Acceptance criteria:

- example configs are safe, accurate, and not cluttered with unsupported options.

## Workstream 4: Release checklist and command gate

Required commands:

```bash
cargo fmt --all --check
cargo test -p synvoid-config dns
cargo test -p synvoid-dns
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

Milestone 4-specific commands:

```bash
cargo test -p synvoid-dns --test axfr_ixfr_transfer_semantics
cargo test -p synvoid-dns --test update_authorized_semantics
cargo test -p synvoid-dns --test notify_behavior
cargo test -p synvoid-dns --test dnssec_known_vectors
cargo test -p synvoid-dns --test control_plane_exclusion
cargo test -p synvoid-dns --test encrypted_transport
cargo test -p synvoid-dns --test verification_gate
```

Optional but desired:

```bash
./scripts/dns/conformance.sh
./scripts/dns/benchmark.sh
```

Acceptance criteria:

- release checklist records pass/fail and exact deferrals.

## Workstream 5: Security review

Tasks:

- Review open-recursive risk.
- Review control-plane authorization risk.
- Review TSIG logging/secret handling.
- Review DNSSEC key file permissions and private-key logging.
- Review DoH trusted proxy header policy.
- Review cache poisoning and bailiwick status.
- Review denial-of-service surfaces: TCP connections, transfers, recursive upstream, encrypted transport handshakes.
- Review unsafe code policy for `crates/synvoid-dns`.

Acceptance criteria:

- release notes include known security posture and limitations.

## Workstream 6: Upgrade/restart behavior

Tasks:

- Verify zone load from store after restart.
- Verify cache starts cleanly or restores according to policy.
- Verify DNSSEC key load after restart.
- Verify listeners bind/rebind after shutdown.
- Verify failed zone reload after restart does not publish corrupt zone.
- Verify config changes apply deterministically.

Acceptance criteria:

- restart/upgrade path is deterministic and documented.

## Workstream 7: Documentation closure

Update:

- `README.md` DNS section.
- `architecture/dns.md`.
- `architecture/dns_config_runtime_matrix.md`.
- `architecture/dns_zone_lifecycle.md`.
- DNSSEC docs.
- operations/conformance/performance docs.
- AGENTS and skill files.

Document:

- supported profiles;
- unsupported/deferred features;
- security posture;
- release checklist;
- diagnostic commands;
- benchmark/conformance commands;
- config examples.

Acceptance criteria:

- docs are consistent, operator-safe, and not aspirational.

## Workstream 8: Final Milestone 4 verification record

Create or update a final verification record containing:

- commit SHA tested;
- commands run;
- CI result;
- conformance result;
- benchmark baseline location;
- supported profiles;
- explicit deferrals;
- known non-DNS workspace failures if any.

Acceptance criteria:

- release readiness can be assessed from a single record.

## Completion criteria

Milestone 4 is complete when:

- observability/health/logging are operator-ready;
- performance baselines and overload behavior are documented;
- conformance/interoperability suite exists and is runnable;
- production profiles are defined and safe by default;
- example configs are accurate and hardened;
- security posture is documented;
- final release gate commands pass or failures are explicitly classified;
- DNS docs and config matrix match tested behavior.
