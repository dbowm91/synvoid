# DNS Runtime-DTO Conversion Research

Status: **RESEARCH COMPLETE / IMPLEMENTATION NOT REGISTERED** (2026-10-04).

Research baseline: `main` at
`cacd44bffe097d7c62e3ddb0c5816967498a7bde`.

Related historical decisions:

- Phase 109: DNS application-neutral extraction readiness — DEFER.
- Phase 116: DNS runtime-config/core neutralization — CLOSED DEFER because the
  complete runtime DTO/adapters/parity gate was not established.
- Phase 117: provider inversion — CLOSED DEFER behind Phase 116.
- Phase 123: campaign gate — DNS remains class 1; 7 direct SynVoid edges and
  838 expanded normal-tree lines were unchanged.

This record answers the Phase 116 blocker at design/research level. It does not
authorize implementation, package promotion, or repository extraction.

## 1. Current dependency boundary

`synvoid-dns` currently has required normal SynVoid dependencies on:

- `synvoid-config`;
- `synvoid-core`;
- `synvoid-tls`;
- `synvoid-utils`;
- `synvoid-geoip`;
- `synvoid-dnssec-keystore`;

and optional `synvoid-mesh`.

The runtime-DTO conversion should target the first three application/helper
couplings in a strict order:

1. remove `synvoid-config` from production DNS source;
2. remove `synvoid-core` by moving the tiny DNS-required time/network semantics
   behind DNS-owned helpers with differential tests;
3. remove `synvoid-utils` where only lifecycle/timestamp helpers remain.

TLS, GeoIP and mesh are provider-capability work and remain the separate
Phase-117-style successor after the DTO/core conversion proves stable.
`synvoid-dnssec-keystore` is a deliberate low-capability sibling and is not a
removal target.

Source inventory at this baseline:

- 15 `crates/synvoid-dns/src/**` files reference `synvoid_config`;
- 9 reference `synvoid_core`;
- 6 reference `synvoid_utils`.

The config dependency is therefore behavioral, not a manifest-only edge.

## 2. Why a mechanical mirror of DnsConfig is the wrong boundary

The persisted `synvoid-config::dns::DnsConfig` tree serves multiple concerns at
once:

1. TOML / admin API schema;
2. defaults and feature-aware validation;
3. fail-closed representation of deferred/unsupported features;
4. runtime values consumed by DNS;
5. composition settings for TLS, Geo, mesh, ACME and process startup.

A standalone DNS runtime should not inherit concerns 1, 3 or 5.

In particular, Phase 45 deliberately keeps unsupported fields parseable while
rejecting their activation in `DnsConfig::validate()`. Examples include RPZ,
prefetch, custom trust-anchor lifecycle, response padding, QNAME privacy,
rebinding knobs, portions of transfer/update/notify, and unsupported anycast
activation. Copying these fields into a DNS-owned runtime DTO would re-create an
API for behavior the runtime intentionally does not support.

The conversion should instead be **lossy by design**:

```text
persisted SynVoid DnsConfig
        |
        | validate() -- retains typed TOML/admin fail-closed errors
        v
application-owned conversion adapter
        |
        | parse/normalize only implemented runtime values
        v
synvoid_dns::DnsRuntimeConfig
```

Unsupported persisted fields never appear in `DnsRuntimeConfig`. The adapter
must reject conversion unless the persisted config has already passed its
existing fail-closed validation.

## 3. Composition boundary

Do not put the adapter in `src/dns/`.

`src/dns/mod.rs` is a guard-enforced pure re-export facade. Current
`AGENTS.md` explicitly permits application composition/adapters in
`src/server/`, `src/worker/` and other composition roots while reusable
domain DTOs belong in the owning crate.

The natural seam is therefore:

```text
crates/synvoid-config/src/dns/**      persisted schema / Serde / OpenAPI
                 |
                 v
src/server/dns_runtime_config.rs      SynVoid adapter; application-owned
                 |
                 v
crates/synvoid-dns/src/runtime_config.rs
                                     runtime-only values
```

`src/server/resources.rs` already constructs `DnsServer`, wires
`CertResolver`, configures TSIG/transfer behavior and owns the activation gate.
It should consume the adapter rather than pass `DnsConfig` into the DNS crate.

This avoids either bad dependency direction:

- `synvoid-dns -> synvoid-config` (current coupling), or
- `synvoid-config -> synvoid-dns` (would make persistence depend on runtime).

## 4. Top-level runtime shape

Recommended initial library-owned shape:

```rust
pub struct DnsRuntimeConfig {
    pub bind: SocketAddr,
    pub rate_limit: DnsRateLimitRuntimeConfig,
    pub rrl: DnsRrlRuntimeConfig,
    pub firewall: DnsFirewallRuntimeConfig,
    pub cache: DnsCacheRuntimeConfig,
    pub limits: DnsLimitsRuntimeConfig,
    pub dnssec: DnssecRuntimeConfig,
    pub dot: Option<DotRuntimeConfig>,
    pub doh: Option<DohRuntimeConfig>,
    pub doq: Option<DoqRuntimeConfig>,
    pub dns64: Option<Dns64RuntimeConfig>,
    pub recursive: Option<RecursiveRuntimeConfig>,
    pub ecs_filter: EcsFilterRuntimeConfig,
    pub query_coalescing: Option<QueryCoalescingRuntimeConfig>,
    pub default_ttl: u32,
    pub min_geo_ttl: u32,
    pub negative_cache_ttl: u32,
}
```

Names are illustrative; implementation should follow existing crate vocabulary.

Important omissions:

- no `enabled`: the composition root already decides whether to construct/start
  DNS via `UnifiedServerStartupPlan::dns_enabled`;
- no persisted `DnsMode`: it currently has validation/settings significance
  but no production runtime dispatch in `synvoid-dns`; mesh capabilities
  should be injected later instead of encoded as application mode;
- no `rpz`, `prefetch`, custom `trust_anchors`, padding or QNAME-privacy
  fields until those have real runtime behavior;
- no `tls_cert_path`, `tls_key_path` or `use_system_cert_store`: current
  DNS transport code receives a concrete `CertResolver`; searches show these
  persisted transport fields are not production consumers in the DNS crate;
- no Serde, Schemars or Utoipa derives by default.

The runtime DTO should prefer parsed/validated domain types:

- `SocketAddr` instead of bind-address `String + u16`;
- `Duration` for timeouts where arithmetic is not serialized;
- `PathBuf` for file paths actually owned by DNS;
- parsed `IpNetwork` entries for ACLs rather than CIDR strings;
- `NonZero*` only where it improves invariants without creating awkward
  conversions;
- explicit enums rather than free-form strings.

## 5. Runtime subtrees and conversion dispositions

### 5.1 Activation and mode

`dns.enabled` is composition-only. Existing tests already state
`DnsServer::start()` does not use it; the caller skips construction/startup.

`dns.mode` is currently only observed by `DnsSettings::is_mesh_mode()` and
config validation. Do not carry it into the neutral runtime merely to preserve a
field. Later mesh-provider inversion should decide behavior by supplied
capability, not a SynVoid application mode enum.

### 5.2 Authoritative bind, cache, limits, rate limiting and RRL

These are genuine runtime inputs and should move first.

Convert:

- bind address + port -> `SocketAddr`;
- cache enabled/capacity/min/max TTL/negative TTL;
- serve-stale enabled/max age/max count;
- connection/query/response limits and UDP buffer size;
- dedicated/shared DNS rate-limit mode and rates;
- RRL enable/rate/window/max/TTL;
- query coalescing enable/wait/entries/entry TTL/cleanup interval;
- default TTL/min Geo TTL/negative-cache TTL;
- ECS filtering settings.

Validation that protects runtime invariants should exist on the runtime values
as constructor validation even though persisted config also validates them.
This is necessary for standalone programmatic consumers.

### 5.3 Firewall and rebinding

Only currently enforced values belong in the initial runtime DTO.

The present query path consumes:

- firewall enabled;
- block-internal-IP rule installation;
- block-zone-transfer rule installation.

`default_action`, `max_rules` and rebinding settings are currently
fail-closed/deferred in persisted config and should not be represented as active
runtime knobs.

The existing `check_rebinding_protection()` function may remain internal
mechanism code, but its persisted settings must not become a public runtime API
until it is actually wired.

### 5.4 Encrypted DNS transports

Define DNS-owned transport DTOs containing only values the transport actually
uses:

```text
DotRuntimeConfig
  bind: SocketAddr

DohRuntimeConfig
  bind: SocketAddr
  path: String
  [json_path only if a real consumer is proven]

DoqRuntimeConfig
  bind: SocketAddr
  max_concurrent_streams: u32
  idle_timeout: Duration
```

Certificate selection remains an injected provider/concrete `CertResolver`
until the later provider-inversion phase. This conversion must not duplicate
TLS ownership inside DNS.

Hickory 0.26.3 supports library integration for authoritative/forwarding/
recursive service and DoT/DoH/DoQ/DoH3. Its resolver configuration types such as
`ResolverConfig`, `NameServerConfig` and `ResolverOpts` are
`#[non_exhaustive]`. Do not expose Hickory config structs as SynVoid's public
runtime contract: own the stable DNS-domain DTO and lower it to Hickory types
internally. That insulates SynVoid from Hickory config evolution while retaining
Hickory as the protocol engine.

### 5.5 Recursive resolver

This is the largest self-contained DTO subtree and should be converted as one
unit rather than field-by-field.

Recommended runtime values:

```rust
pub struct RecursiveRuntimeConfig {
    pub bind: SocketAddr,
    pub upstream: RecursiveUpstream,
    pub cache: RecursiveCacheRuntimeConfig,
    pub dnssec_validation: bool,
    pub qname_minimization: bool,
    pub query_timeout: Duration,
    pub max_concurrent_queries: usize,
    pub rate_limit: DnsRateLimitRuntimeConfig,
    pub firewall: DnsFirewallRuntimeConfig,
    pub root_hints: PathBuf,
    pub trust_anchor: PathBuf,
    pub client_acl: Option<RecursiveClientAcl>,
    pub max_cname_depth: u8,
    pub max_recursion_depth: u8,
    pub max_per_client_queries: u32,
    pub circuit_breaker: CircuitBreakerRuntimeConfig,
    pub ecs: RecursiveEcsRuntimeConfig,
}
```

`RecursiveClientAcl` should own parsed networks, not CIDR strings. Its
`is_client_allowed()` behavior currently lives in `synvoid-config` and must
move with the runtime policy.

`RecursiveCacheConfig` is directly passed into `RecursiveDnsCache::new()`;
that constructor must become config-crate independent.

For upstreams, preserve current semantics but normalize representation:

- System;
- Google;
- Cloudflare;
- Custom endpoints;
- true Recursive (root hints);
- GlobalNodes as a temporary neutral variant only if required to preserve
  behavior before provider inversion.

Custom endpoints should distinguish parsed IP endpoints from hostnames instead of
keeping an ambiguous `address + optional ip + port` triple.

The current resolver path already lowers to Hickory. Keep that lowering private.

### 5.6 DNSSEC / HSM / TSIG

Do not duplicate the already extracted custody boundary.

`DnssecRuntimeConfig` should contain DNS runtime policy (enabled, domain,
key-path, rollover, algorithm, key sizes, NSEC/NSEC3 policy) while HSM material
should use the keystore-owned `synvoid_dnssec_keystore::HsmConfig` where
possible.

The current `synvoid-dns::hsm::keystore_config_from_dns()` exists solely
because DNS depends on persisted config. After conversion, the application
adapter can build the keystore config directly and the DNS facade conversion can
be deleted.

TSIG is more involved because `TsigAlgorithm` and `TsigKeyConfig` are
currently persisted-config types used by runtime verification. The DNS crate
should own its TSIG algorithm and key-spec runtime types. The persisted adapter
must decode/validate base64 into the runtime representation rather than making
base64 encoding part of the standalone DNS API.

Do not weaken secret handling during this move. If a zeroizing wrapper is added,
treat it as a focused security improvement with tests, not an undocumented side
effect of DTO migration.

### 5.7 Zone definitions

`DnsServer::load_zones(Vec<DnsZoneEntry>)` is currently a public config-crate
leak and must be converted before the normal dependency can disappear.

Add DNS-owned zone input types, for example:

```rust
pub struct ZoneSpec {
    pub origin: String,
    pub records: Vec<ZoneRecordSpec>,
    pub dnssec: Option<ZoneDnssecSpec>,
}

pub struct ZoneRecordSpec {
    pub name: String,
    pub record_type: hickory_proto::rr::RecordType,
    pub value: String,
    pub ttl: Option<u32>,
    pub priority: Option<u32>,
}
```

Using the already-public Hickory `RecordType` avoids a second runtime record
enum. The application adapter performs the persisted
`DnsRecordType -> RecordType` mapping.

Keep existing zone activation validation authoritative. The conversion should
not make invalid records valid or move validation into the persistence layer.

### 5.8 Unsupported persisted surfaces

These stay in `synvoid-config` and are intentionally absent from the initial
runtime API:

- RPZ;
- prefetch;
- custom trust-anchor lifecycle;
- response padding;
- QNAME privacy;
- unwired rebinding policy;
- unwired anycast activation;
- any transfer/update/notify knobs that remain rejected by
  `DnsConfig::validate()`.

If later work makes one of these real, add a runtime field in that feature's own
implementation plan.

## 6. synvoid-core removal

Nine DNS source files use `synvoid-core`, but the required surface is tiny:

- `current_timestamp_secs()`;
- `is_restricted_ip()`;
- `ipv4_prefix_mask()`.

Do not create another shared utility crate.

Add DNS-owned internal helpers with behavior copied intentionally and prove
differential parity before removing the dependency.

Important restricted-IP semantics to preserve include:

- IPv4 0/8, RFC1918, CGNAT 100.64/10, loopback, link-local, selected
  documentation/benchmark/special-use ranges, multicast/reserved;
- IPv4-mapped IPv6 recursion;
- IPv6 unspecified/loopback/ULA/link-local/multicast/documentation range;
- /0 and /32-safe IPv4 masks.

Time-before-epoch must continue to return 0 rather than panic.

A later testability improvement may inject a clock into TSIG/key/zone operations,
but dependency removal does not require introducing a public clock trait.

## 7. synvoid-utils removal

The production non-mesh coupling is principally `DrainFlag` /
`RunningFlag` in connection limits; mesh-gated code also uses timestamp
helpers.

The flags are two Arc<AtomicBool> wrappers. Either:

- make equivalent private DNS-owned lifecycle state, or
- refactor the owning limits/runtime object so callers do not need generic
  flag types at all.

Do not create a public utility abstraction merely to remove the edge.

For mesh-gated timestamps, use the same DNS-owned time helper so the optional
feature does not restore `synvoid-utils`.

## 8. Test migration and parity strategy

The current DNS test suite frequently constructs
`synvoid_config::dns::*` directly. Those tests cannot remain if
`synvoid-config` is removed as a normal dependency and standalone packaged
tests are expected to work.

Split testing into two layers.

### DNS crate tests

Use only DNS-owned runtime types. Cover:

- runtime constructor/default invariants;
- authoritative bind/cache/limit/rate/RRL behavior;
- zone specs and DNSSEC behavior;
- recursive runtime values;
- encrypted transport runtime configs;
- TSIG/HSM runtime inputs;
- no root-relative files or SynVoid config environment.

### SynVoid composition tests

Under `src/server/` unit tests, construct persisted `DnsConfig`, run the
application adapter, and compare the resulting runtime DTO.

Add table/golden coverage for:

- all supported shipped example profiles;
- `DnsConfig::default()`;
- authoritative-only;
- recursive;
- DNSSEC;
- encrypted transport configurations;
- cache/serve-stale/ECS/DNS64;
- invalid bind/port/open-recursive cases;
- all Phase-45 unsupported activation paths.

The adapter test must prove unsupported persisted settings fail before runtime
construction.

The existing `architecture/dns_config_runtime_matrix.md` should gain an
additional ownership column:

`persisted schema -> adapter -> runtime DTO field / absent-by-design`.

This becomes the exhaustive migration ledger.

## 9. Recommended implementation sequence

Do not attempt the conversion as one mechanical rename.

### Slice A — runtime DTO foundation + adapter parity

- create DNS-owned runtime DTO module;
- create private application adapter under `src/server/`;
- implement typed parsing/normalization;
- add exhaustive adapter parity tests;
- keep current `DnsServer` constructor temporarily while proving DTO
  equivalence internally.

No dependency is removed yet.

### Slice B — authoritative runtime constructor

- change `DnsServer` to consume `DnsRuntimeConfig`;
- migrate cache/limits/rate/RRL/firewall/ECS/DNS64/coalescing;
- migrate transport runtime settings;
- migrate root `src/server/resources.rs`;
- migrate DNS crate tests.

At the end of this slice, no public constructor should require
`synvoid_config::dns::DnsConfig`.

### Slice C — zones, recursive, DNSSEC/TSIG/HSM

- replace `DnsZoneEntry` public API with DNS-owned zone specs;
- replace recursive config/cache/ACL/circuit-breaker types;
- replace TSIG config types;
- remove `keystore_config_from_dns` in favor of application conversion;
- migrate remaining tests.

At the end of this slice, production DNS source should have zero
`synvoid_config` references.

### Slice D — core/utils neutralization

- add differential DNS-local net/time tests;
- migrate timestamps/restricted-IP/prefix-mask callers;
- move lifecycle flags to DNS-owned internals;
- remove normal `synvoid-core` and `synvoid-utils` edges.

### Slice E — qualification

Required evidence:

```bash
cargo tree -p synvoid-dns -e normal
cargo check -p synvoid-dns --profile ci
cargo test -p synvoid-dns --profile ci
cargo check -p synvoid-dns --profile ci --features mesh
cargo test -p synvoid-dns --profile ci --features mesh
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
cargo test -p synvoid-config --profile ci
cargo test -p synvoid-dnssec-keystore --profile ci
cargo xtask standalone consumer synvoid-dns
cargo xtask verify
cargo xtask verify-full
cargo deny check
cargo audit
```

The outside-workspace DNS consumer should remain a later final gate until TLS/
Geo/mesh provider inversion is complete; the DTO phase can prove packaging and
core authoritative operation without prematurely claiming standalone class 2.

## 10. Dependency target after DTO conversion

Expected normal topology after the DTO/core work, before provider inversion:

```text
synvoid-dns
  -> synvoid-tls                 # still concrete; next provider phase
  -> synvoid-geoip               # still concrete; next provider phase
  -> synvoid-dnssec-keystore     # deliberate security leaf
  -> synvoid-mesh (optional)     # still concrete; next provider phase
  -> third-party DNS/runtime deps

removed:
  - synvoid-config
  - synvoid-core
  - synvoid-utils
```

This would reduce direct SynVoid edges from 7 to 4 (three required plus optional
mesh) before provider inversion, subject to final `cargo metadata` proof.

## 11. Main risks

1. **Configuration semantic drift.** Defaults currently live in persisted config.
   The adapter must preserve effective values exactly.
2. **Fail-open unsupported settings.** The conversion must never bypass
   `DnsConfig::validate()`.
3. **Test illusion.** Replacing config types in unit tests without root adapter
   parity could hide real deployment drift.
4. **Secret handling regression.** TSIG/HSM conversion must not expose/log
   secrets more broadly.
5. **Hickory API leakage.** Hickory's non-exhaustive resolver config types should
   stay an internal lowering target rather than becoming the standalone API.
6. **Scope creep.** Provider inversion, mesh extraction, RPZ/prefetch/anycast
   implementation and OpenRaft/network changes are not part of this conversion.
7. **Facade violation.** `src/dns/` must remain a pure facade; composition
   conversion belongs under `src/server/`.

## 12. Planning conclusion

The Phase 116 blocker is now sufficiently understood to write an implementation
plan. The safest plan should be staged around the slices above and require an
exhaustive field-ownership matrix before the constructor cutover.

No Phase 125 implementation plan is registered by this research artifact. A
future plan should use this record as its evidence baseline and should not reopen
provider inversion until the normal `synvoid-config`, `synvoid-core` and
`synvoid-utils` edges are removed with parity proof.
