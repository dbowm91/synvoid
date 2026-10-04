# DNS application-neutral readiness — Phase 109

Status: **CLOSED DEFER** (2026-10-02). No independent DNS repository or
publication is authorized by this disposition.

## Phase 108 input

Hickory 0.26.3 owns DNS message decoding and ordinary recursive resolver/
recursor mechanics. SynVoid retains its established adapters and differentiated
server, policy, transport, cache and custody behavior. Phase 108 removed no
source code; it recorded 48 active normal direct dependency entries, 864
expanded normal-tree lines and the sibling source map.

## Dependency findings

| Sibling dependency | Production uses found | Required disposition |
| --- | --- | --- |
| `synvoid-config` | DNS config types are imported in `config`, `dnssec`, DoH/DoQ/DoT, EDNS, firewall, HSM, notify, recursive resolver/cache, server and TSIG modules. `mod.rs` publicly re-exports DTOs. | Move runtime model ownership to `synvoid-dns`; keep persisted config/schema in SynVoid and translate exhaustively at the application root. This is not one adapter: many constructors currently accept config-model types. |
| `synvoid-core` | Shared time functions in signing, trust anchors, TSIG, firewall, server and prefetch; restricted-IP policy and IPv4 masks in DNS validators/firewall/QNAME/EDNS paths. | Separate neutral DNS logic from app policy and preserve exact time/IP semantics. Only replace with std/local helpers after parity tests. |
| `synvoid-tls` | `CertResolver` is used by DoH, DoQ, DoT and secure-server paths; `AcmeDnsChallenge` appears in server startup/context. | Introduce DNS-owned certificate material/provider capability while preserving reload, SNI, ALPN, ACME challenge and key-custody behavior. |
| `synvoid-geoip` | `GeoIpManager` is carried by DNS config/zone/server/firewall and mesh registry. | Replace with narrow lookup/value input; preserve missing database and fallback behavior and keep raw location data out of telemetry. |
| `synvoid-platform` | No source reference exists. DNS has its own `platform::AnycastSocketPlatform` and Linux implementation. | Removed unused direct dependency in this phase. This is the sole coupling reduction implemented here. |
| `synvoid-utils` | `DrainFlag`/`RunningFlag` in connection limits; timestamps in mesh registration, verification, query, DHT and DNSSEC mesh code. | Replace lifecycle flags with a DNS-owned or Tokio-neutral contract, and localize safe timestamp helpers where semantics match. Mesh-facing timestamp sites should disappear with mesh adapter inversion. |
| optional `synvoid-mesh` | Concrete `MeshTransport`, `MeshMessage`, `MeshNodeRole`, DHT record store and routing manager occur in sync/registry; DNSSEC mesh consumes canonical metadata. | Define minimum record-source, health-source and registration/event capabilities; the SynVoid composition root supplies adapters. Preserve authority, provenance, replay, freshness and partition rules. |
| `synvoid-dnssec-keystore` | Sealed signing handles, `KeyMetadata`, keystore and HSM adapter types are used by signing, validation, key management, trust and HSM modules. | Retain as an explicitly paired low-capability sibling in any future DNS repository. Never merge private-key storage back into the DNS runtime. |

The standalone package target still has multiple active SynVoid application
edges. `cargo tree -p synvoid-dns --depth 1` now contains 47 active normal
direct dependencies, including six required SynVoid sibling crates; optional
mesh is inactive by default. The expanded normal tree has 853 package lines
(down 11 from the Phase 108 input's 864). The only attributable removal is one
unused direct edge (`synvoid-platform`); this did not remove DNS functionality,
source LOC or an active transitive subtree. No binary-size/performance gain is
claimed.

## Why extraction is deferred

The independent-service proof cannot be built from this phase's current API
without first changing many public constructor/config types and moving DNS
composition away from SynVoid runtime objects. The candidate also has no
DNS-owned config model or root translation adapter, still depends on config,
core, TLS, GeoIP, utils and optional mesh, and carries the separate DNSSEC
keystore boundary. The required proof (standalone zone/resolver/DNSSEC/encrypted
transport consumer with fake Geo/health/record-source adapters) would therefore
not be an independent consumer today.

The ownership work is large enough to require an owned implementation phase;
this closeout does not characterize those edges as permanently unavoidable.
Future work should proceed in ordered increments: runtime config + golden root
adapter; TLS/Geo/health interfaces; mesh capabilities; neutral helper
replacement; then packaged consumer and threat/security qualification. Do not
introduce a Git dependency or create a repository until those boundaries and
the DNSSEC keystore topology are proven.

## Verification

- `cargo check -p synvoid-dns --profile ci` — passed after removal;
- `cargo check -p synvoid-dns --features mesh --profile ci` — passed after
  removal;
- `cargo test -p synvoid-dns --profile ci` — 1,262 passed after removal;
- `cargo test -p synvoid-dns --profile ci --features mesh` — 1,274 passed
  after removal;
- `cargo test -p synvoid-dnssec-keystore --profile ci` — 40 passed;
- Phase 107 `cargo xtask verify-release` passed 14/14 and package inspection
  immediately before this single manifest-edge deletion. No DNS source, wire,
  config or lock-resolved third-party version changed afterward.

Disposition: **DEFER extraction / retain the in-workspace service**. Phase 110
is independently eligible and may proceed. A future implementation plan must
own the six active application sibling inversions before this extraction gate
can be reconsidered.

## Current-status pointer (Phase 124, 2026-10-04)

The Phase 109 findings and DEFER disposition above remain the historical result
at their date; the dependency table and test counts are unchanged. Later
phases own the current position:

- Phase 116 (`architecture/standalone_crate_phase116_closeout.md`) **CLOSED
  DEFER** — the runtime-DTO/adapter/parity gate was not delivered, so the
  `synvoid-config` / `synvoid-core` / `synvoid-utils` edges still exist;
- Phase 117 (`architecture/standalone_crate_phase116_closeout.md`) **CLOSED
  DEFER** — provider inversion never became independently eligible;
- Phase 123 (`architecture/standalone_crate_phase123_closeout.md`) reconfirmed
  `synvoid-dns` as class 1 with 7 direct SynVoid edges and 838 expanded
  normal-tree lines, unchanged from Phase 115.

The Phase 116 design blocker is now answered at research level in
`architecture/dns_runtime_dto_conversion_research.md`: persisted
`synvoid-config` DNS DTOs stay application-owned, the conversion adapter is
composition code under `src/server/` (never the guard-enforced pure `src/dns/`
facade), and `synvoid-dns` owns only parsed runtime values. That record is
**research complete / implementation not registered** — it is not a DNS
extraction approval.
