# DNS Milestone 4 Phase 3: Interoperability and Conformance Suite

## Objective

Build a repeatable interoperability and conformance suite for the DNS subsystem. This phase validates Synvoid DNS behavior against common DNS clients/tools, RFC-oriented packet expectations, and practical resolver/operator workflows.

## Context

Earlier milestones focused on internal correctness and targeted regression tests. Production readiness requires proving behavior against external tools and protocol expectations, especially for DNSSEC, transfers, encrypted DNS transports, truncation/TCP fallback, and recursive safe defaults.

## Non-goals

Do not attempt full formal RFC certification. Do not add new DNS features only to satisfy optional tests. Mark unsupported features explicitly rather than silently broadening scope.

## Workstream 1: Tooling inventory and harness

Tasks:

- Identify external tools available locally and in CI:
  - `dig`;
  - `kdig`;
  - `drill`;
  - `delv`;
  - `ldns-verify-zone`;
  - `named-checkzone`;
  - `dnsperf`/`resperf` for load-adjacent smoke if available.
- Add a conformance runner script that detects tools and skips unavailable optional checks with clear output.
- Keep required CI checks limited to tools available in the CI environment unless installation is cheap and stable.
- Produce machine-readable and human-readable output if feasible.

Acceptance criteria:

- conformance checks are repeatable and can run partially when optional tools are unavailable.

## Workstream 2: Basic authoritative interoperability

Tasks:

- Start test server on ephemeral ports.
- Query A, AAAA, NS, SOA, MX, TXT, CNAME, NODATA, NXDOMAIN.
- Validate QR, AA, RA, RD echo, RCODE, counts, and answer/authority shape.
- Validate no-zone behavior remains REFUSED unless recursion is enabled and client is allowed.
- Validate malformed query handling.

Acceptance criteria:

- common DNS tools receive protocol-valid authoritative responses.

## Workstream 3: Truncation and TCP fallback

Tasks:

- Generate large responses that exceed UDP512.
- Verify TC bit is set for truncated UDP responses.
- Verify TCP response returns full answer or configured limit error.
- Verify oversized TCP response behavior returns valid SERVFAIL when configured.
- Test EDNS buffer-size behavior.

Acceptance criteria:

- truncation and TCP fallback are interoperable with standard clients.

## Workstream 4: DNSSEC interoperability

Tasks:

- Validate signed zone with `dig +dnssec`.
- Validate DNSKEY query shape.
- Validate signed positive response shape.
- Validate NODATA/NXDOMAIN denial proof shape for supported NSEC cases.
- Run `delv` where validation is feasible.
- Run `ldns-verify-zone` and/or `named-checkzone` on generated zone fixtures if available.
- Document any NSEC3 limitations and disable production claims for unverified modes.

Acceptance criteria:

- DNSSEC supported scope is externally smoke-verified or explicitly deferred.

## Workstream 5: AXFR/IXFR interoperability

Tasks:

- Query AXFR using `dig AXFR` against allowed and denied clients where feasible.
- Validate SOA bracketing and expected records externally.
- Query IXFR using tool support or internal wire harness.
- Validate fallback/refusal policy for too-old serials.
- Validate TSIG success and failure if valid TSIG fixtures are available.

Acceptance criteria:

- transfer behavior works with standard tooling for supported cases.

## Workstream 6: UPDATE and NOTIFY interoperability

Tasks:

- Use `nsupdate` where available for dynamic UPDATE tests.
- Validate authorized add/delete and refused unauthorized operations.
- Validate prerequisite behavior externally where feasible.
- Use `dig +notify` or a custom fixture if standard tooling is insufficient for NOTIFY.
- Document any tool gaps.

Acceptance criteria:

- control-plane operations are externally validated or have clear fixture-based substitutes.

## Workstream 7: Encrypted transport interoperability

Tasks:

- Test DoT with `kdig +tls` where available.
- Test DoH with `curl` and DNS message body fixtures.
- Test DoQ with available client tooling if supported, otherwise mark experimental/deferred.
- Validate certificate/config failure behavior.
- Validate content type, HTTP status, body size, and transport-class semantics.

Acceptance criteria:

- encrypted transports interoperate with at least one standard client/tool per supported transport.

## Workstream 8: Recursive safe-default interoperability

Tasks:

- Verify recursion disabled by default via standard query tools.
- Verify recursion enabled only for allowed clients.
- Verify RA semantics match recursive availability.
- Verify cache behavior and upstream failure behavior with controlled/mock upstream.
- Verify ECS not forwarded by default if observable.

Acceptance criteria:

- recursive mode is externally visible as safe by default and controlled when enabled.

## Workstream 9: Documentation and fixtures

Tasks:

- Add conformance fixtures under a stable test/fixture path.
- Document external tool requirements.
- Document exact commands used for each supported feature.
- Record expected output patterns.
- Ensure docs identify optional/deferred checks.

## Verification commands

```bash
cargo fmt --all --check
cargo test -p synvoid-dns
cargo check -p synvoid-dns --all-features
./scripts/dns/conformance.sh
cargo check --workspace
```

Script path may differ, but it must be documented.

## Completion criteria

Phase 3 is complete when supported DNS behaviors have repeatable internal and external interoperability checks, optional tooling gaps are handled cleanly, unsupported modes are marked as deferred, and maintainers can run the suite locally without reading source code first.
