# Phase 108 Plan: DNS Hickory Delegation and Ownership Simplification

Status: **PLANNED / READY** (Phase 105 CLOSED QUALIFIED).

Registered in: `plans/roadmap.md` and
`plans/subsystem_boundary_extraction_roadmap.md`.

Planning baseline for registration: `main` at `19c0636535f3728e80b7c6777ec6a552c38c61a0` (2026-10-01).
Qualified Hickory baseline and evidence: `architecture/dns_hickory_patch_requalification.md`, proof-bearing SHA `857d2e76dd453dc9dd0c84aa89bc1293cc8a1e1b`.

Owner: DNS / architecture / security.

## Goal

Reduce SynVoid's DNS maintenance surface by determining which current DNS
mechanisms should be delegated to the qualified Hickory 0.26.3 line, which
require a narrow SynVoid adapter, and which are genuinely differentiated
SynVoid behavior that should remain owned by the DNS subsystem.

This phase is a measured simplification campaign, not a rewrite. No supported DNS
capability may be removed because upstream overlap exists.

## Current state

`synvoid-dns` owns modules for:

- wire parsing/building;
- authoritative serving and zones;
- recursive resolution;
- positive/negative caches and coalescing;
- DNSSEC validation/signing/trust-anchor handling;
- DNS-over-TLS/HTTPS/QUIC;
- TSIG;
- dynamic update;
- transfer/notify;
- RPZ/firewall policy;
- DNS64;
- anycast/platform integration;
- Geo steering;
- HSM/keystore integration;
- metrics/security events;
- mesh registration/health integration.

Hickory now covers substantial baseline DNS protocol/server/resolver behavior.
The maintenance target is to stop owning baseline machinery twice while
preserving SynVoid's specialized policy, security, and distributed integration.

## Workstream A — build a source-and-test capability matrix

For every public DNS module, classify its production responsibility and tests.

At minimum include:

- `wire`;
- `parsed_query` / query validation;
- `resolver` / recursive resolver;
- `recursive_cache`;
- `server` / zone handling;
- `dnssec_validation`;
- `dnssec_signing`;
- `trust_anchor`;
- `tsig`;
- `update`;
- `transfer` / `notify`;
- `dot`, `doh`, `doq`;
- `cache`, `query_coalesce`;
- `dns64`;
- `rpz` / `firewall`;
- `anycast`;
- Geo steering/global resolver;
- mesh message/adapters;
- HSM/keystore boundary.

For each capability record:

1. SynVoid owner/module;
2. actual production call sites;
3. current tests/benchmarks;
4. Hickory 0.26.3 capability/API;
5. semantics SynVoid adds beyond Hickory;
6. security/compatibility constraints;
7. disposition: **DELEGATE**, **WRAP**, **RETAIN**, or **DEFER**.

No disposition may be based on module name alone.

## Workstream B — prioritize baseline protocol machinery

Presume delegation/wrapping is desirable for standard mechanisms where Hickory
has a mature implementation and SynVoid adds no unique policy.

Strong candidates to evaluate first:

- baseline DNS message parsing/encoding;
- ordinary resolver request/response mechanics;
- standard DNSSEC validation primitives;
- standard TSIG/update handling;
- encrypted DNS transport plumbing where Hickory's server APIs provide required
  semantics;
- standard authoritative catalog/zone machinery where compatible.

A RETAIN decision needs a concrete reason such as:

- required behavior absent upstream;
- stricter security semantics;
- measurable performance requirement;
- SynVoid wire/config compatibility requirement;
- specialized anycast/health/Geo/distributed behavior;
- upstream feature remains experimental below SynVoid's support bar.

## Workstream C — protect differentiated SynVoid semantics

The following should not be deleted merely because Hickory offers adjacent
features:

- health-aware/Geo steering;
- mesh-fed dynamic record/control data;
- SynVoid DNS firewall/RPZ policy where semantics differ;
- DNSSEC private-key custody/HSM abstraction;
- node-health/anycast integration;
- SynVoid security-event classification;
- bounded cache/coalescing behavior if it carries explicit anti-abuse semantics;
- application-specific metrics/control-plane contracts.

Prefer these as policy/adapters around upstream mechanisms rather than duplicate
protocol engines.

## Workstream D — execute only evidence-backed simplifications

For each DELEGATE/WRAP item:

1. add differential/golden tests before deleting code;
2. introduce the upstream-backed implementation behind the existing internal
   interface;
3. run focused parity/security tests;
4. remove duplicate code only after parity;
5. remove no-longer-needed dependencies/modules;
6. update public re-exports deliberately.

Do not perform a mass module deletion followed by test repair.

If Hickory behavior is stricter for malformed/insecure input, preserve the
stricter behavior and document the compatibility/security distinction instead of
reintroducing permissiveness.

## Workstream E — dependency and footprint reduction

After simplification recompute:

```bash
cargo tree -p synvoid-dns
cargo metadata --format-version 1 --no-deps
```

Record direct/transitive dependency and binary-size deltas attributable to the
DNS changes.

Specifically check whether direct dependencies such as `hyper`, `quinn`,
crypto/parsing/storage helpers, or duplicated cache utilities can be removed
because Hickory now owns the corresponding mechanism. Do not remove a dependency
solely for aesthetics if SynVoid's differentiated implementation still needs it.

## Workstream F — API and compatibility reconciliation

Keep supported SynVoid-facing configuration and admin behavior compatible.

Where an internal public re-export maps directly to a removed implementation,
choose explicitly among:

- preserve via type/function adapter;
- deprecate with migration path;
- migrate workspace-only consumers if no external compatibility promise exists.

Do not expose broad Hickory implementation types through SynVoid's public API
merely to reduce adapter LOC; that would couple the future extraction boundary
to Hickory internals unnecessarily.

## Workstream G — security qualification

Re-run hostile-input and DNSSEC suites after each ownership move.

At minimum verify:

- malformed/truncated packets fail safely;
- allocation/recursion/query limits remain bounded;
- DNSSEC validation cannot silently downgrade;
- cache keys/negative caching remain poisoning-safe;
- encrypted transports retain authentication;
- updates/transfers remain authorization-gated;
- mesh/health input cannot bypass canonical policy.

## Workstream H — Phase 109 handoff

Produce a current architecture record identifying the post-simplification DNS
core and its remaining SynVoid application dependencies.

Phase 109 may begin only after that record shows which dependencies are true
domain requirements versus adapters that can be inverted.

## Verification

At minimum:

```bash
cargo fmt --all -- --check
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-dns --profile ci --features mesh
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
cargo xtask verify
cargo xtask verify-full
cargo deny check
cargo audit
```

Run DNS benches for touched hot paths and differential fixtures for every
delegated mechanism.

## Acceptance criteria

- every significant DNS module has a documented DELEGATE/WRAP/RETAIN/DEFER
  decision;
- duplicate baseline protocol machinery is removed where upstream ownership is
  proven equivalent or better;
- specialized SynVoid DNS policy/integration semantics remain intact;
- no DNSSEC or transport-security downgrade occurs;
- dependency/LOC/footprint changes are measured rather than assumed;
- Phase 109 receives an accurate post-simplification graph.

## Rejection criteria

Reject implementation that:

- deletes custom code solely because Hickory has a similarly named feature;
- wraps Hickory without removing any maintenance burden;
- leaks Hickory internals into SynVoid's stable compatibility surface;
- treats experimental upstream behavior as production parity without evidence;
- changes zone/update/transfer/DNSSEC semantics incidentally;
- mixes application-boundary extraction into this simplification phase.
