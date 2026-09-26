# Phase 92 Plan: Eggbench Security Qualification Asset Contract

Status: planned (2026-09-26).

Registered in: `plans/roadmap.md`.

Baseline: `main` at `49b4624b696b4c3aa0172b0326a04ae9e275ca3f`.

Dependency position: independent of the ICMP Phase 90-91 line. This phase may
execute without reopening or waiting on the ICMP RETAIN follow-up.

Consumer: `eggstack/eggbench` Security Qualification M002.

## Goal

Provide one SynVoid-owned, deterministic, machine-readable qualification asset
contract that Eggbench can consume without importing SynVoid Rust crates or
reinterpreting SynVoid WAF semantics.

The upstream contract must materialize:

1. a loopback-only minimal SynVoid configuration tree suitable for a controlled
   Eggbench origin;
2. an Eggbench HTTP security corpus derived from an explicit supported subset
   of SynVoid's authoritative WAF request fixtures;
3. a provenance manifest binding the generated artifacts to this SynVoid source
   revision, source-fixture digests, mapping policy, and generated config/corpus
   digests;
4. a non-destructive check mode proving the generated config and corpus are
   internally coherent.

This phase is qualification support. It must not change production WAF
detection semantics merely to make Eggbench pass.

## Research basis

Current SynVoid state at planning:

- package version `1.1.0`;
- Linux is the primary production target;
- `--no-default-features` is the supported minimal WAF/proxy data-plane
  build;
- `--foreground --config-path <dir>` is the operator-owned foreground
  lifecycle;
- `--configtest --config-path <dir>` validates a materialized config tree;
- the data-plane listen port is configuration-owned and may not be zero;
- a site's `site.upstream.default` is configuration-owned;
- the canonical WAF fixture corpus lives under
  `crates/synvoid-waf/tests/fixtures/waf`;
- source fixtures declare stable case IDs, request data, owner-authored
  `detect|pass` expectations, and attack-family labels;
- the current corpus also contains forms that Eggbench M001 intentionally does
  not accept, including cases requiring forbidden/hop-by-hop headers,
  request-smuggling semantics, or non-UTF8/binary material.

No existing `eggbench` qualification/export surface exists.

## Ownership boundary

SynVoid owns:

- which source fixtures are representative and exportable;
- the meaning of source `detect|pass`;
- conversion of those meanings into the chosen externally observable live
  behavior;
- the qualification configuration tree;
- source-fixture provenance;
- exclusions and their reasons.

Eggbench owns:

- parsing its own normalized corpus schema;
- content/config hashing and workspace confinement;
- HTTP case execution;
- performance workload execution;
- correctness/performance receipts and suite aggregation.

Do not add an Eggbench Rust dependency to SynVoid.

## Qualification policy v1

Create and document an immutable owner policy identifier:

~~~text
synvoid.eggbench-qualification.v1
~~~

V1 is deliberately narrow:

- SynVoid attack detection is enabled;
- terminal attack action is configured as `block`;
- a source fixture with `expected_result = detect` maps to an expected live
  HTTP block status;
- a source fixture with `expected_result = pass` maps to the controlled
  origin's success status;
- the initial externally observable expectations are HTTP status only;
- challenge, stall, tarpit, drop, log-only, internal reason codes, threat-level
  escalation, rate limiting, bot controls, and distributed-state semantics are
  outside v1.

Recommended live mapping:

~~~text
detect -> 403
pass   -> 200
~~~

If the actual canonical block response differs, record and use the real stable
status. Do not patch the data plane merely to force 403.

Any semantic mapping change requires a new policy identifier.

## Workstream A — authoritative export allowlist

Add a repository-owned allowlist/manifest of WAF fixture IDs eligible for the
Eggbench v1 export.

Selection requirements:

- include benign/pass controls;
- include representative SQLi, XSS, path traversal, SSRF, SSTI, command
  injection, XXE, LDAP/XPath/open-redirect classes where the live HTTP request
  is representable;
- preserve stable fixture IDs;
- preserve attack-family label as opaque provenance;
- require deterministic source ordering.

Explicitly exclude, with a checked-in reason:

- request-smuggling/hop-by-hop cases that require headers Eggbench correctly
  forbids;
- credential-bearing headers;
- non-UTF8/binary request bodies not representable by the initial Eggbench
  corpus contract;
- fixtures whose expectation depends on internal-only entry-point semantics
  not reproduced by the live proxy path;
- serverless bypass fixtures or known internal bypass probes that are not a
  stable ordinary reverse-proxy request contract;
- timing/challenge/drop/tarpit semantics.

The allowlist is a product-owned compatibility surface. A fixture may not
silently disappear from it.

## Workstream B — asset materializer

Add a small repository-local qualification tool, preferably as an `xtask`
subcommand.

Recommended interface:

~~~text
cargo xtask eggbench-qualification export   --output <dir>   --listen-port <port>   --origin-port <port>

cargo xtask eggbench-qualification check --input <dir>
~~~

The exact spelling may follow current xtask conventions.

The export must be deterministic for the same:

- SynVoid source tree;
- selected fixture set;
- listen/origin ports;
- policy version.

No network request occurs during export/check.

The tool may parse SynVoid's test fixture format because SynVoid owns it.

## Workstream C — loopback-only minimal runtime config

Materialize a complete temporary config tree for the supported minimal binary:

~~~text
cargo build --locked --release --no-default-features
synvoid --foreground --config-path <generated-config>
~~~

Requirements:

- HTTP data plane binds only `127.0.0.1:<listen-port>`;
- upstream is exactly `http://127.0.0.1:<origin-port>`;
- attack detection enabled;
- action set to the policy-v1 block behavior;
- TLS disabled;
- HTTP/3 disabled;
- admin disabled;
- mesh/DNS/socket-handoff feature-specific configuration absent;
- honeypot, tarpit, bot challenge, rate limiting, flood/ICMP, tunnel, plugins,
  app/serverless paths, and other unrelated security behavior disabled where
  configuration requires explicit disablement;
- logging paths remain inside the generated qualification directory or are
  disabled;
- persistence/cache/temp state remains inside the generated directory;
- no public bind;
- no credential/token required for the data plane;
- site host matching accepts the loopback qualification request without
  requiring Eggbench to inject a forbidden `Host` override.

The config must pass:

~~~text
synvoid --configtest --config-path <generated-config>
~~~

using the same minimal binary profile.

If minimal runtime still requires an IPC signing value, the qualification
launcher/materializer must provide a clearly test-only non-secret mechanism
without requiring Eggbench to persist a production secret.

## Workstream D — Eggbench corpus export

Emit a JSON corpus matching Eggbench HTTP security corpus schema v1.

For every exported case:

- `id` = stable SynVoid fixture ID;
- `category` = opaque SynVoid attack-family label;
- method/path/query/header/body are derived losslessly from the source fixture
  within the supported subset;
- source `detect/pass` is converted to the policy-v1 observable HTTP status
  expectation;
- no absolute target URL is embedded;
- no `Host`, proxy, hop-by-hop, credential, cookie, or authorization header
  is emitted;
- inline/body-file representation follows Eggbench v1 bounds;
- generated case order is deterministic.

Do not emit raw source notes/descriptions when they can reveal unnecessary
payload context; the normalized corpus itself necessarily contains request
payloads because it is the executable input, but the eventual Eggbench bundle
will retain only case/request digests.

## Workstream E — provenance manifest

Emit a bounded machine-readable manifest containing at least:

- schema version;
- policy identifier;
- SynVoid package version;
- exact git SHA;
- selected source fixture IDs;
- source fixture relative paths and SHA-256 values;
- explicit excluded-case IDs/reasons or a digest-addressed exclusion manifest;
- generated config-tree SHA-256;
- generated corpus SHA-256;
- listen/origin ports;
- expected block/pass statuses;
- materializer version.

Do not include arbitrary environment variables or secrets.

## Workstream F — self-qualification

Add deterministic tests proving:

1. every allowlisted source fixture exists;
2. every allowlisted fixture remains parseable;
3. every exported request satisfies the intended Eggbench v1 restrictions;
4. exported IDs are unique;
5. mapping policy is exhaustive for `detect/pass`;
6. output is byte-deterministic for identical inputs;
7. changing a selected fixture changes the provenance digest;
8. generated config binds loopback only;
9. generated config contains the exact requested ports;
10. `--configtest` succeeds with the minimal binary in an integration test
    or explicit qualification command;
11. no excluded unsupported source fixture is silently exported.

## Workstream G — live local semantic proof

Provide an opt-in/live qualification that starts:

~~~text
controlled loopback origin
      ^
      |
SynVoid minimal WAF/proxy
      ^
      |
exported corpus requests
~~~

It must prove at least:

- one exported Pass control reaches the origin and returns the configured
  success status;
- representative exported Detect cases return the configured block status and
  do not reach the origin;
- all exported cases agree with the generated observable expectation.

This may be a specialist/local qualification target rather than routine PR CI
if runtime cost is material.

A source fixture/live-path mismatch is a real finding. Do not weaken the
export expectation to conceal it; either fix the production path or remove the
fixture from v1 with a documented compatibility reason and review the mapping.

## Workstream H — performance fixture support

The same generated config must be usable for later Eggbench benign performance
scenarios.

Provide deterministic origin-facing paths for:

- small response;
- larger response / streaming proxy path;

or document the controlled-origin path contract expected from Eggbench if
SynVoid itself need not define those paths.

Do not build a new performance harness in SynVoid. Eggbench owns external/native
load generation in M002.

## Routine verification

At minimum:

~~~text
cargo fmt --all -- --check
cargo test -p synvoid-waf --profile ci
cargo xtask test guards
cargo xtask verify
cargo build --locked --release --no-default-features
~~~

Plus the materializer tests/check mode.

Do not add a permanent broad benchmark job to routine CI.

## Acceptance criteria

Phase 92 closes only when:

- an explicit SynVoid-owned Eggbench qualification policy v1 exists;
- a stable allowlisted fixture subset is checked in;
- unsupported fixture exclusions are explicit;
- a deterministic asset materializer exists;
- loopback-only minimal SynVoid config is generated and config-tested;
- an Eggbench-v1 corpus is generated without importing Eggbench Rust code;
- provenance binds source fixtures, source SHA, config, corpus, and mapping;
- live local proof shows exported Pass/Detect behavior matches observable
  responses;
- minimal no-default-features runtime remains supported;
- routine verification stays green;
- no production WAF semantic is weakened for the qualification harness.

## Rejection criteria

Reject implementation that:

- copies the entire internal corpus into Eggbench and makes Eggbench translate
  `detect/pass`;
- exports request-smuggling/hop-by-hop cases through a contract that forbids
  them;
- binds SynVoid to a public interface;
- enables unrelated security controls that make WAF results ambiguous;
- requires an Eggbench Rust dependency;
- treats an internal detector-unit result as proof of live reverse-proxy
  enforcement without a live semantic check;
- adds a second SynVoid load generator;
- stores production secrets in qualification assets.
