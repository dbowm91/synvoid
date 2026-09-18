# Phase 45 Plan: DNS Runtime Contract and Protocol Completeness

Status: detailed handoff plan.

Roadmap: `plans/runtime_truthfulness_security_publication_roadmap.md`.

Baseline: `03cec2235fb250e64c33f29b66258eeb0607cdbc`.

## Primary goal

Make the DNS configuration surface truthful before expanding it further: every supported setting must have a runtime consumer and test, while deferred/unsupported activation must fail validation rather than be accepted and ignored. After that contract is closed, implement the highest-value protocol gaps that improve standards behavior without exploding scope.

## Current evidence

`architecture/dns_config_runtime_matrix.md` already records substantial residuals. Examples include:

- `dns.doq.bind_address` not fully honored in startup;
- RPZ configuration with no runtime consumer;
- custom trust-anchor configuration with no runtime consumer;
- prefetch configuration with no runtime consumer;
- anycast subfields not consumed;
- dynamic UPDATE handler exists but is not wired into `DnsServer::new()`;
- NOTIFY handler exists but is not wired;
- zone-transfer policy/IXFR controls are partially staged but not fully wired;
- QNAME privacy helper exists but is not called;
- EDNS padding implementation exists but is not wired;
- persistent DNS-over-TCP/DoT connection reuse is intentionally not implemented.

The correct next step is not to implement all of these simultaneously.

## Workstream A — Recompute the matrix against current code

Before editing behavior, regenerate/verify the matrix from:

- `crates/synvoid-config/src/dns/**`;
- `crates/synvoid-dns/src/**`;
- startup/listener construction;
- admin DNS mutation/config surfaces;
- example configs and production profiles.

For each public field classify exactly:

1. implemented and tested;
2. implemented but missing direct config-fidelity test;
3. partial — some values ignored;
4. deferred/unsupported;
5. validation-only/metadata-only by design.

Update the matrix during implementation, not only at closeout.

## Workstream B — Reject unsupported activation

Add `DnsConfig::validate()` rules for deferred settings.

Principle: a default/inactive value may remain parseable for compatibility, but an operator must not be able to enable a feature that does nothing.

Examples:

- `rpz.enabled = true` => explicit unsupported error until RPZ engine exists;
- `prefetch.enabled = true` => unsupported error until runtime consumer exists;
- custom trust-anchor `enabled = true` => unsupported error until trust-anchor manager exists;
- anycast activation => reject unless all required runtime pieces for the selected mode are wired;
- dynamic update/notify => reject until Workstream E intentionally enables them;
- QNAME privacy/padding => reject enabled modes until wired;
- non-default ignored knobs inside a partially supported feature should be rejected or made effective.

Use typed config paths in errors.

Do not silently coerce unsupported settings back to defaults.

## Workstream C — DoQ bind fidelity and encrypted transport tests

Wire `dns.doq.bind_address` through the same address-validation semantics as UDP/TCP/DoT/DoH.

Add tests for:

- explicit IPv4 loopback;
- explicit IPv6 where supported;
- invalid address fails before listener startup;
- port collision/bind failure is surfaced;
- disabled DoQ does not bind.

Add missing direct DoT/DoH/DoQ config fidelity tests identified in the matrix.

## Workstream D — Persistent DNS-over-TCP and DoT

Current TCP query handling processes one framed request and closes the connection. RFC 7766 expects connection reuse and modern clients can send multiple queries over a connection.

Implement a bounded connection loop:

- two-byte DNS message length framing per query;
- maximum message size before allocation;
- per-read idle timeout;
- total/connection idle policy;
- connection-level maximum queries or lifetime if needed to bound abuse;
- per-query concurrency policy: start sequential unless pipelining support is explicitly designed;
- active TCP connection permit held for the full connection lifetime;
- graceful shutdown closes/drains loops predictably.

Align DoT with the same message lifecycle after TLS handshake.

Do not add request pipelining/multiplexed response reordering in the first pass unless interoperability tests require it. A sequential persistent connection is a useful, bounded improvement.

Wire EDNS keepalive only after persistent connection semantics exist.

## Workstream E — Decide authoritative mutation support

Dynamic UPDATE, NOTIFY, AXFR/IXFR are security-sensitive and stateful. Before enabling existing handlers, require a small design gate covering:

- authoritative zone ownership;
- TSIG requirement and algorithm policy;
- allowed transfer/update clients;
- journal/serial update durability;
- NOTIFY retry/backoff;
- IXFR history retention and fallback;
- mesh/distributed authority interactions;
- admin audit/provenance;
- restart persistence.

If these guarantees can be satisfied by existing handlers with limited wiring, implement and test them.

If not, leave activation rejected and create a later dedicated mutation/zone-lifecycle plan. Do not wire handlers merely to make config fields "used."

## Workstream F — Recursive resolver roadmap decision

Choose which deferred recursive features are strategically part of SynVoid.

Highest-value candidates:

1. custom trust anchors / RFC 5011-style lifecycle if SynVoid aims to be a serious validating resolver;
2. RPZ if DNS security policy is a product goal;
3. QNAME privacy/minimization and padding if privacy is an explicit goal;
4. prefetch only after correctness/security features.

Do not implement these inside this phase unless the design is already present and bounded. Record explicit support tier and a future trigger.

## Workstream G — External interoperability

Expand `scripts/dns/conformance.sh` or focused scripts to cover persistent TCP/DoT and DoQ bind behavior.

Where tools are available, exercise:

- `dig +tcp` with multiple queries/connections;
- `kdig +tls`;
- DoQ-capable client if available;
- `delv` for DNSSEC paths;
- malformed length framing/idle clients.

Keep CI proportionate: hermetic Rust tests are mandatory; external tool interop can be a release/native validation gate if installing the tools in routine CI is too costly.

## Workstream H — Documentation and admin UI/API

Reconcile:

- `architecture/dns.md`;
- `architecture/dns_deep_dive.md`;
- `architecture/dns_config_runtime_matrix.md`;
- `architecture/dns_production_profiles.md`;
- `docs/CONFIGURATION.md`;
- DNS examples;
- admin settings schema/UI.

The admin surface must not offer a toggle that the backend rejects without clearly marking it unsupported/experimental.

## Verification

```bash
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-dns --test dns_config_fidelity --profile ci
cargo test -p synvoid-dns --test dns_recursive_isolation --profile ci
cargo test -p synvoid-dns --test dns_stress --profile ci
./scripts/dns/conformance.sh
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
cargo xtask verify
```

## Acceptance criteria

- No DNS feature can be enabled/configured with meaningful non-default behavior that the runtime ignores.
- DoQ bind address is honored.
- Persistent sequential DNS-over-TCP/DoT behavior is documented and tested if implemented.
- Transfer/update/notify remain rejected until their security/durability contract is actually satisfied.
- Production-profile labels match current tests and runtime behavior.
- The matrix contains no unexplained "unsupported but accepted" entries.
