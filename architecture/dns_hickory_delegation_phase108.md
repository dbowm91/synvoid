# DNS and Hickory ownership audit — Phase 108

Status: **CLOSED QUALIFIED** (2026-10-01). Hickory remains pinned at 0.26.3,
qualified by Phase 105. This is a source-based ownership audit with focused
package verification. No protocol implementation was deleted: the audit found
no further candidate whose behavioral/security parity had already been proven.
That conservative result is intentional; it provides Phase 109 a reliable
ownership baseline without treating adjacent upstream APIs as parity evidence.

## Capability matrix

| Capability / source owner | Production use and tests | Hickory relationship | Disposition and constraints |
| --- | --- | --- | --- |
| Wire message parse (`wire::parse_dns_message`) | Calls `hickory_proto::op::Message::from_vec`; exercised by wire/property/integration tests. | Already delegated. | **DELEGATE** parsing to Hickory; retain SynVoid error adapter and compatibility exports. |
| Wire name/header helpers and response encoding (`wire`, `messages`) | Used by authoritative and recursive request paths; wire benches and protocol fixtures cover current byte output. | Custom names, response headers, errors and encoders coexist with Hickory parsing. | **WRAP/RETAIN** until differential vectors cover compression, malformed input, flags, EDNS and all emitted RR types. Preserve current wire output. |
| Parsed query / validation (`parsed_query`, `query_validator`, `qname`, `edns`, `cookie`, `compression`) | Validates opcode, sections, names, source/client policy, EDNS and cookies before dispatch. Covered by parser/property and integration tests. | Hickory types are consumed, but SynVoid adds request admission and response-authority policy. | **RETAIN** admission/policy; delegate primitives only behind differential tests. Never relax malformed-input rejection or query bounds. |
| Recursive resolver (`resolver`, `recursive`) | `HickoryResolver` and `HickoryRecursor` back upstream requests; `RecursiveDnsServer` adds firewall, rate limiting, limits, circuit breaker, cache and metrics. Recursive isolation/interoperability tests exist. | Resolver/recursor mechanism already delegated; global-node path is SynVoid-specific. | **WRAP** Hickory resolver APIs. Preserve DNSSEC mode distinction: only the validating recursive provider reports validation; forwarders do not claim local validation. Retain global-node semantics. |
| Recursive cache/coalescing (`recursive_cache`, `cache`, `sharded_cache`, `query_coalesce`) | Positive/negative entries, transport and namespace separation, invalidation, in-flight work and cancellation are covered by unit, stress and coalescer tests/benches. | No current Hickory cache is wired into these SynVoid contracts. | **RETAIN** anti-poisoning, boundedness, transport namespace, and coalescing semantics. Do not replace based on feature-name overlap. |
| Authoritative query and zone handling (`server/*`, `store`, `zone_*`, `secure_server`) | SynVoid listener/query lifecycle, zone state, response policy, hard response limits, reload and health; authoritative negative/interop/lifecycle tests. | Hickory server crate is not a direct dependency; Hickory protocol types alone do not prove server parity. | **RETAIN/WRAP**. No Hickory server migration without wire/config/lifecycle differential evidence. |
| DNSSEC recursive validation (`resolver`, Hickory recursor) | Validating recursive mode configures Hickory's `ValidateWithStaticKey`; vectors and recursive tests cover behavior. | Uses Hickory validation path. | **DELEGATE** recursive chain validation to Hickory while keeping fail-closed provider selection and truthful validation status. |
| DNSSEC signing, proofs and compatibility glue (`dnssec_signing`, `dnssec_validation`, `dnssec`) | Builds RRSIG/NSEC/NSEC3 records; verification helpers and vectors cover algorithms and wire records. Signing keys are sealed. | Some record primitives overlap, but these paths are not routed through Hickory and use the SynVoid key-custody API. | **RETAIN/WRAP** until canonical-byte/signature and proof-chain differential vectors are established. No private-key logic may move back into DNS. |
| Key metadata, custody and HSM (`trust_anchor`, `dnssec_key_mgmt`, `hsm`) | Trust-anchor state and metadata adapters use `synvoid-dnssec-keystore`; HSM is opt-in and fail-closed. | Not a Hickory ownership target. | **RETAIN** the keystore sibling boundary. Hickory must never acquire private-key or PKCS#11 authority through a convenience migration. |
| TSIG, UPDATE, transfer and NOTIFY (`tsig`, `update`, `transfer`, `notify`) | Custom authorization, atomic rollback, scheduling and IXFR delta tests exist. Current capability validation rejects deferred activation knobs (Phase 45 contract). | No Hickory integration currently owns these runtime paths. | **DEFER** production activation. Retain test/design code and authorization semantics; do not claim these features are supported or replace them without parity and release-scope decision. |
| DoT (`dot`, `secure_server`) | SynVoid TCP/TLS, sequential framing, deadlines and shutdown; transport lifecycle/interoperability tests. | Uses SynVoid `tokio-rustls` and TLS certificate resolver; Hickory server API is not a dependency. | **RETAIN/WRAP** TLS and lifecycle. Maintain SNI/ALPN, authenticated certificate behavior and bounded framing. |
| DoH (`doh`) | SynVoid Hyper HTTP/2 handler, DNS media/query bounds and TLS integration; encrypted transport and interop tests. | No Hickory DoH server adapter is currently wired. | **RETAIN** until full HTTP behavior and limit parity are tested. |
| DoQ (`doq`) | Direct Quinn endpoint/stream handling, configured timeouts and bounds; tests exist, while release docs mark production validation deferred. | No Hickory DoQ server adapter is currently wired. | **DEFER** production support; keep current internal behavior and do not infer Hickory parity. |
| DNS64 (`dns64`) | Stateless translation helper with local DNS64 tests. | No active Hickory path shown in the DNS production source. | **RETAIN**; compare semantics only if Hickory resolver integration can preserve prefix and DNSSEC policy. |
| Firewall/RPZ (`firewall`, `rpz`) | Firewall admission/policy is used by recursive path; RPZ activation is rejected by config validation. | SynVoid policy and status contract. | Firewall **RETAIN** as policy; RPZ **DEFER** until supported. |
| Anycast, Geo and global resolver (`anycast`, `anycast_sync`, `resolver_global`, health) | Platform socket handling, Geo selection, node health and global-node recursion. Anycast config remains deferred. | Application/platform integration, not baseline DNS protocol. | **RETAIN** policy/adapter; anycast activation **DEFER**. No Hickory replacement removes mesh/health semantics. |
| Mesh DNS (`mesh_sync/*`, `mesh_dnssec`, messages) | Optional `synvoid-mesh` transport/message integration; config and control-plane inputs are application-owned. | Not a Hickory protocol responsibility. | **WRAP/RETAIN** as optional app integration; preserve canonical/advisory authority boundaries. |
| Metrics and security events (`metrics`) | DNS-specific outcomes and security events; tests verify selected wiring. | SynVoid operator semantics. | **RETAIN** adapter and event vocabulary; do not expose them as Hickory API. |

## Simplification result and compatibility boundary

The verified simplification is already in the implementation: complete DNS
message decoding and ordinary recursive resolution use Hickory 0.26.3. SynVoid
keeps its adapter/error types and differentiated policy. Hickory is not a direct
DNS server dependency, so deleting the zone server, TCP/DoT lifecycle, DoH/DoQ,
custom validation, caches, UPDATE/transfer code or RR encoders would be a new
runtime migration, not removal of a proven duplicate.

No manifest, source, public export, or lockfile changes were justified in this
phase. Accordingly the attributable delta is 0 direct edges, 0 modules and 0
LOC removed; no benchmark or binary-size improvement is claimed. At this head,
`cargo tree -p synvoid-dns --depth 1` lists 48 active normal direct dependency
entries (including seven required SynVoid siblings); the optional mesh edge is
not active in that graph. The expanded normal tree has 864 package lines. This
is the Phase 109 input graph, not a before/after reduction.
The release-policy package graph continues to classify `synvoid-dns` behind
internal predecessors.

## Phase 109 handoff: actual sibling coupling

| Sibling edge | Current source use | Boundary disposition for Phase 109 |
| --- | --- | --- |
| `synvoid-config` | DNS structs and enums appear throughout recursive configuration, DoT, EDNS and HSM mapping; `mod.rs` re-exports application DNS DTOs. | Invert through DNS-owned runtime config plus exhaustive root/persisted-config adapter. This is a broad compatibility migration. |
| `synvoid-core` | Time helpers, restricted-address policy and IPv4 masks. | Separate generic DNS policy from app config; keep local DNS domain helpers or a narrow neutral policy input, after parity. |
| `synvoid-tls` | `CertResolver` for DoT and secure-server paths. | Replace with DNS-owned neutral certificate/provider contract or rustls primitives; preserve reload, SNI, ALPN and secret custody. |
| `synvoid-geoip` | DNS steering consumes app Geo lookup. | Invert to a narrow lookup/input trait; preserve absent-database/fallback behavior. |
| `synvoid-platform` | The manifest listed this sibling, but a source search found no `synvoid_platform` reference. DNS implements its own local `platform::AnycastSocketPlatform`. | Not a justified retained edge; Phase 109 removes the unused direct dependency. |
| `synvoid-utils` | Safe Unix timestamp helper in mesh sync and related utility calls. | Use `std`/DNS-owned safe timestamp helper where semantics match; do not create a common crate for trivial code. |
| `synvoid-dnssec-keystore` | Sealed signing handles, key metadata, trust state, HSM. | Deliberate sibling in any future repository topology; preserve low-capability custody boundary, never absorb private-key storage into DNS. |
| optional `synvoid-mesh` | Mesh transport and typed message/config in optional mesh sync. | Invert behind minimal dynamic-record, health and event capabilities; canonical/advisory provenance remains application-owned. |

The Phase 109 target is not a repository move of today's crate. DNS runtime
config, Geo/TLS/mesh/platform adapters and tests must be addressed first.
Potential delegation candidates are now explicit: query decoding and ordinary
resolver mechanics are already delegated; other baseline items remain only
candidates until source-level Hickory behavior and SynVoid parity are tested.

## Verification

- `cargo test -p synvoid-dns --profile ci` — passed, 1,262 tests across 37
  suites;
- `cargo test -p synvoid-dns --profile ci --features mesh` — passed, 1,274
  tests across 37 suites;
- focused mesh DNSSEC, TSIG, recursive isolation and transport lifecycle suites
  — passed, 155 tests;
- `cargo tree -p synvoid-dns --depth 1` and expanded normal graph recorded
  above;
- Phase 106 `cargo xtask verify-full` already passed against the same
  implementation base; Phase 107 `cargo xtask verify-release` passed all 14
  release gates, including Hickory 0.26.3 all-feature clippy/release checks,
  full workspace tests and audit;
- `cargo audit` reported six allowed unmaintained warnings and no vulnerability.

Phase 109 is now **unblocked**: Phase 108 provides the dependency-specific
source map and explicit preservation/delegation decisions it needs.
