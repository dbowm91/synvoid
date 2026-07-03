# DNS Milestone 2 Phase 5: Verification and Release Gate

## Objective

Create a hard release gate for DNS Milestone 2. This phase verifies that transport/runtime, config fidelity, cache integration, coalescing policy, and duplicate-tree cleanup are complete enough to support the next milestone without carrying hidden regressions.

## Scope

This is a verification and polish phase. It should not add new DNS feature scope. Fix only issues discovered by the gate.

## Gate areas

1. Compile and test baseline.
2. Deleted duplicate tree verification.
3. Config-runtime matrix accuracy.
4. Transport runtime behavior.
5. Cache key/TTL/invalidation behavior.
6. Query coalescing key/lifecycle behavior.
7. Recursive isolation and safe defaults.
8. Documentation accuracy.

## Gate 1: Compile and test baseline

Required commands:

```bash
cargo fmt --all --check
cargo test -p synvoid-config dns
cargo test -p synvoid-dns
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

Recommended targeted commands:

```bash
cargo test -p synvoid-dns authoritative_negative
cargo test -p synvoid-dns dns_config_fidelity
cargo test -p synvoid-dns dns_recursive_isolation
cargo test -p synvoid-dns cache
cargo test -p synvoid-dns query_coalesce
cargo test -p synvoid-dns transport
```

Acceptance criteria:

- All DNS-specific commands pass.
- workspace command passes or unrelated failures are documented with exact details.

## Gate 2: Deleted duplicate DNS tree

Tasks:

- Verify `src/dns` is absent or contains no implementation code.
- Verify docs and skills point to `crates/synvoid-dns`.
- Verify no code imports deleted modules.

Commands:

```bash
rg "src/dns|crate::dns|mod dns|dns/server" .
```

Acceptance criteria:

- there is exactly one canonical DNS implementation.

## Gate 3: Config-runtime matrix

Tasks:

- Review `architecture/dns_config_runtime_matrix.md` for every config field.
- Ensure each implemented row has at least one test or a clear reason why not.
- Ensure partial/deferred rows are explicitly labeled.
- Ensure high-risk controls are not marked implemented without runtime effect.

Acceptance criteria:

- matrix is trustworthy enough for operators and future agents.

## Gate 4: Transport/runtime behavior

Verify:

- invalid bind address fails fast;
- port zero fails validation/startup;
- TCP lifecycle policy is documented and tested;
- TCP hard-limit response is valid;
- UDP truncation is byte-size based;
- shutdown is idempotent;
- coalescer cleanup observes shutdown;
- connection guard lifetime is correct.

Acceptance criteria:

- runtime startup/shutdown behavior is deterministic.

## Gate 5: Cache behavior

Verify:

- full `CacheKey` dimensions are used in server paths;
- authoritative and recursive cache namespaces cannot collide;
- DO bit affects cache key;
- qclass affects cache key;
- transport class affects cache key;
- TTL extraction is compression-safe;
- negative TTL uses SOA policy;
- SERVFAIL/REFUSED are not cached by default;
- mutation invalidation clears all response-shape variants.

Acceptance criteria:

- cache cannot serve wrong response shape across key dimensions.

## Gate 6: Coalescing behavior

Verify:

- coalescing key policy is documented;
- key dimensions cover output-affecting fields;
- unsafe query classes bypass coalescing;
- owner/waiter success path works;
- cancellation and timeout clean up state;
- metrics types are semantically correct.

Acceptance criteria:

- coalescing is safe to enable under documented conditions.

## Gate 7: Recursive isolation

Verify:

- default config is not an open resolver;
- authoritative no-zone behavior remains REFUSED;
- recursive mode requires explicit enablement and allow policy;
- trust-anchor config status is accurate.

Acceptance criteria:

- recursive capability is isolated from authoritative default operation.

## Gate 8: Documentation and milestone status

Update docs with a final Milestone 2 status section:

- Closed items.
- Partial items.
- Deferred items.
- Verification command results.
- Known limitations.

Docs to check:

- `architecture/dns.md`
- `architecture/dns_config_runtime_matrix.md`
- `architecture/dns_deep_dive.md`
- `.opencode/skills/dns_dnssec/SKILL.md`
- `AGENTS.md`
- `crates/synvoid-dns/AGENTS.override.md`

Acceptance criteria:

- docs match implementation.
- no production-readiness overclaim remains.

## Final Milestone 2 close criteria

Milestone 2 may be considered closed when:

- DNS-specific test/check commands pass.
- duplicate DNS tree cleanup is verified.
- transport startup/shutdown behavior is deterministic.
- config-runtime matrix is accurate.
- cache key and invalidation semantics are production-safe.
- coalescing is safe and tested or clearly documented as conditional.
- recursive defaults remain safe.
- docs accurately state remaining deferrals.

## Deferrals to later milestones

These remain outside Milestone 2 unless discovered as direct regressions:

- full DNSSEC production validation;
- full NSEC3 closest-encloser proofs;
- DoT/DoH/DoQ conformance matrix;
- RPZ policy expansion;
- high-scale load testing;
- recursive resolver feature expansion;
- DNSSEC key rollover and HSM production workflows.
