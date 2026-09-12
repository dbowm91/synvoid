# Crate Granularity Audit

Status: Phase 31 closeout audit (Track 4 deltas in §Phase 31; per-crate rows
re-verified, count corrected to 42 `synvoid-*` members). One row per workspace
crate from the actual final dependency graph (generated from each `Cargo.toml`
plus root `Cargo.toml`; LOC via `wc -l` over each crate `src/`).

Retain rule (from the phase plan): keep a crate when it provides one or more
of independently testable invariants/security boundary, reusable/public API,
dependency isolation, feature/build isolation, or compile-time ownership
boundary. Flag a merge candidate only when it is primarily a naming/module
wrapper with no independent invariants and meaningful cross-crate
churn/boilerplate.

Outcome: **no merge executed in this phase**. Every member crate clears the
retain bar on at least one axis. Two thin crates are recorded as future
simplification candidates; both stay until a scoped pass with a stability
review. One stale empty directory (`crates/synvoid-testkit/`, no manifest,
no sources, not a workspace member, zero references) was removed.

## Workspace (non-crate) members

| Member | Responsibility | Verdict |
|--------|----------------|---------|
| root `synvoid` | Application/runtime composition (supervisor, workers, facades) | Keep (composition root) |
| `pqc` (1062 LOC) | Post-quantum crypto primitives (isolates `rand` 0.6/0.9 shim + aws-lc) | Keep (dependency isolation for crypto) |
| `admin-ui` | Yew/WASM admin frontend (Trunk, not a Rust lib dep) | Keep (build isolation) |
| `examples/*` (2) | Dynamic-plugin and embedded-app examples | Keep (not shipped) |
| `fuzz` | cargo-fuzz harness (20 targets after Phase 24) | Keep (build isolation; excluded from publish) |
| `tools/xtask` (1999 LOC) | `cargo xtask verify*` CI orchestration | Keep (tooling isolation) |
| `tools/synvoid-repo-guards` (226 LOC) | Static repo guards run by CI + `verify_architecture.sh` | Keep (tooling isolation) |

## `synvoid-*` crates (42 members; Phase 26 adds `synvoid-yara`, Phase 27 adds `synvoid-mesh-protocol`, Phase 28 adds `synvoid-native-extension`, Phase 29 adds `synvoid-jail-runtime`, Phase 30 adds `synvoid-dnssec-keystore`)

Columns: LOC ≈ `src/` lines; "In-crate rev" = other workspace crates
depending on it (root app crate depends on all of them as composition
inputs, so it is not listed per row).

| Crate | Responsibility | LOC | Independent invariants? | External/reuse value? | In-crate rev deps | Internal deps | Keep / Merge candidate | Rationale |
|-------|----------------|-----|-------------------------|-----------------------|-------------------|---------------|------------------------|-----------|
| synvoid-core | Canonical contracts: enforcement, streaming-WAF, block provenance, admin mutation, verdict | 2274 | Yes — reducer precedence/idempotence, fail-closed mappings | Yes — every request-path crate builds on it | 11 | none | Keep | Contract crate by design; zero-dep so it creates no cycles |
| synvoid-utils | Shared buffers, serialization, time, strings, errors | 1816 | Yes — serialization round-trips, buffer pool ABA safety | Yes | 18 | none | Keep | Lowest-level shared crate; `buffer` feature isolates pool |
| synvoid-config | All configuration types + validation | 12467 | Yes — parse/validate fail-closed, config matrix | Limited (operator-facing) | 21 | pqc | Keep | Single config owner; `dns`/`mesh` features isolate heavy deps |
| synvoid-auth | Auth/session/CSRF/lockout (Phase 18 canonical) | 1302 | Yes — session, CSRF, lockout semantics | Yes | root only | config, utils | Keep | Security boundary extracted from root; tested independently |
| synvoid-challenge | Challenge orchestration + mesh-PoW (Phase 18 canonical) | 2249 | Yes — challenge verify/state machine | Yes | http, waf | theme, utils | Keep | Security boundary; directional rendering dep only |
| synvoid-waf | Canonical WAF engine: detectors, policy, sliding limits, adapters (Phase 19) | 14640 | Yes — detection, reducer adapters, flood/bot/endpoint | Yes | 6 | challenge, config, core, mesh, utils | Keep | Largest domain engine; request-path capability boundary |
| synvoid-proxy | Reverse-proxy engine: routing, headers, dispatch, protocols | 6861 | Yes — routing, header filter, protocol adapters | Yes | 3 | 11 (see graph) | Keep | Second engine crate; narrow-trait consumers in http/http3 |
| synvoid-http | Canonical HTTP parse/normalize/framing/dispatch (Phase 20) | 11084 | Yes — fail-closed framing, normalization ownership | Yes | http3 | 16 (composition surface) | Keep | Canonical HTTP owner; wide fan-in is composition, not wrapper |
| synvoid-http3 | HTTP/3 QUIC server + WAF boundary | 418 | Yes — QUIC/H3 dispatch, H3 WAF prelude | Limited | root only | config, core, http, http-client, metrics, platform, proxy, waf | Keep | Feature/build isolation for QUIC stack (h3/quinn) |
| synvoid-mesh | DHT, transport, Raft, trust, policy gates (Phase 23 authority) | 100655 | Yes — consensus, key policy, partition semantics | Limited (mesh deployments) | 6 | 13 (incl. mesh-protocol) | Keep | Control-plane boundary; `mesh` feature isolates openraft/proto; depends downward on `synvoid-mesh-protocol` (Phase 27) |
| synvoid-mesh-protocol | Stable mesh wire/identity vocabulary: constants, `HybridSignature` envelope, Ed25519 `ProtocolSigner` verification, replay protection, threat taxonomy, framing (Phase 27) | ~900 | Yes — wire-compat golden vectors, fail-closed framing, deterministic verification | Yes — verification-only consumers without DHT/Raft/SQLite/YARA | 1 (mesh) + root feed verification | none (leaf by design) | Keep | Dependency-isolation boundary; strict budget guard (`mesh_protocol_boundary`); `synvoid-mesh` re-exports compat paths |
| synvoid-block-store | Enforcement block state + provenance + cursors | 8530 | Yes — capacity, expiry, replay, concurrency | Limited | root only | config, core, mesh, utils, waf | Keep | Enforcement-state boundary; worker admission reads this, not TIM |
| synvoid-ipc | IPC transport + jail protocol/supervision/binary resolution (Phase 22, Phase 29 exe-dir lookup) | 12420 | Yes — framed protocol, digests, restart bounds, fail-closed routing, deterministic helper resolution | Limited | 5 (incl. jail-runtime) | config, metrics, platform, tls, utils | Keep | Trust boundary for process isolation; versioned wire protocol |
| synvoid-plugin-runtime | WASM runtime, sandbox, instance pool, manifests (+ optional native facade) | 19736 | Yes — capability gating, ABI boundary, reload prepare-commit | Limited | 4 | utils (+ optional native-extension) | Keep | Sandbox boundary; wasmtime version patch point; default graph links no shared-library loader (Phase 28) |
| synvoid-native-extension | Explicit unsafe in-process native loader + narrow backend trait + non-executing external-host seam (Phase 28) | ~2400 | Yes — production/path/hash/permission gates, ABI checks, generation-aware lifetime, contract-bound validation | Limited (opt-in native deployments) | 0-1 (plugin-runtime optional; root optional) | none (leaf: axum/libloading/metrics only) | Keep | Capability-isolation boundary; `unsafe-native-extensions` feature off by default; `synvoid-mesh`/`synvoid-upload` must never depend on it |
| synvoid-jail-runtime | Child-side jail execution + dedicated binaries (Phase 29): `WasmJailService`/`YaraJailService`, sandbox-entry sequencing, `synvoid-wasm-jail` + `synvoid-yara-jail` binaries | ~1500 | Yes — digest re-verification, hook-only capabilities, strict sandbox ordering, wrong-kind rejection, fail-closed entry | Limited (jail deployments) | 1 (root facades/shims) | ipc, platform, plugin-runtime (wasm), yara (yara) | Keep | Process-boundary isolation; `wasm`/`yara` features separate engines per binary; never imports root/supervisor/admin/mesh |
| synvoid-admin | Transport-neutral admin handler logic + DTOs (Phase 21) | 3315 | Yes — mutation/audit contract alignment | Limited | root only | app-server, config, core, ipc, metrics, static-files, waf | Keep | Lets root stay transport composition; frontend contract tested |
| synvoid-dns | Authoritative/recursive DNS + DNSSEC protocol/transport (feature-gated; private-key custody extracted Phase 30) | ~35400 | Yes — wire codec, public-only DNSSEC validation/proofs, zone lifecycle | Yes | root only | config, core, dnssec-keystore, geoip, mesh, platform, tls, utils | Keep | `dns` feature isolates hickory; `hsm` feature gates PKCS#11 via the keystore; largest optional surface |
| synvoid-dnssec-keystore | DNSSEC private-key custody: sealed generation/storage/rotation/signing/HSM (Phase 30) | ~2600 | Yes — opaque sealed handles, 0600/atomic persistence, fail-closed HSM, KAT/rotation/permission/redaction tests | Limited (DNS deployments) | 1 (dns) | core | Keep | Security boundary; one-way leaf (no hickory/hyper/quinn/sqlite/mesh); `pkcs11`/`hsm` features off by default so normal builds carry no `cryptoki` |
| synvoid-tls | TLS termination core + ACME | 1963 | Yes — cert lifecycle, ACME DNS/HTTP | Limited | 3 | config | Keep | Crypto-facing boundary; root keeps only server integration |
| synvoid-http-client | Egress HTTP client pool (+ QUIC marker) | 2131 | Yes — pool, retry, PQC marker | Yes | 9 | config, core | Keep | Egress chokepoint; rustls-native-certs owner |
| synvoid-upstream | Upstream pool, balancing, health | 2401 | Yes — selection, health gating | Limited | 2 | http-client, utils | Keep | Narrow egress boundary consumed by proxy/tunnel |
| synvoid-tunnel | QUIC/WireGuard tunnel transports | 11426 | Yes — tunnel lifecycle, routing | Limited | 2 | config, upstream, utils | Keep | `wireguard`/`tun-rs` features isolate heavy transports |
| synvoid-proxy-cache | Proxy response cache | 1905 | Yes — cache key/TTL/revalidation | Limited | 2 | none | Keep | Zero-dep cache semantics; reusable without proxy engine |
| synvoid-honeypot | Deception responders + intel extraction | 8199 | Yes — rotation, detection, budgets | Limited | root only | config, http-client, mesh, utils | Keep | Optional deception layer with own invariants |
| synvoid-tarpit | Markov-chain tarpit core | 1349 | Yes — generation budgets | Limited | root only | none | Keep | Zero-dep generator core; root owns handler/manager |
| synvoid-serverless | Serverless function runtime | 2951 | Yes — function lifecycle, mesh serverless | Limited | 3 | config, plugin-runtime | Keep | Runtime boundary over plugin-runtime |
| synvoid-app-handlers | CGI/FastCGI/PHP/MIME app handlers | 3005 | Yes — handler protocols | Limited | 3 | config, core, http-client, plugin-runtime, serverless | Keep | App-protocol boundary shared by http/static/upload |
| synvoid-app-server | Granian app-server integration | 1163 | Limited — backend dispatch | Limited | 2 | http-client, utils | Keep | Dependency isolation for app-server deps |
| synvoid-static-files | Static serving, minification, file manager | 4668 | Yes — path traversal prevention, caching | Limited | 3 | app-handlers, config, ipc, theme, utils | Keep | Owns minification dep tree (build isolation) |
| synvoid-upload | Upload validation + YARA policy/orchestration (facade over `synvoid-yara`) | 10538 | Yes — validation, in-jail scanning | Limited | 1 | app-handlers, config, http-client, mesh, platform, utils, yara | Keep | Upload trust boundary; engine implementation moved to `synvoid-yara` (Phase 26) |
| synvoid-yara | Canonical YARA execution boundary: engine, artifact binding, executor contract (Phase 26) | ~2600 | Yes — bounded compile/scan, digest/version binding, narrow executor | Limited (upload/mesh/jail consumers) | 2 (upload, root jail/cpu) | none (leaf; yara-x isolated here) | Keep | Security boundary; single `yara-x` production owner; mesh has no compiler reference |
| synvoid-platform | OS abstraction, paths, sandbox backends (Phase 29 canonical) | 4309 | Yes — platform detection, secure dirs, Landlock/Capsicum/Pledge/Job-Object/Seatbelt enforcement | Yes | 8 (incl. jail-runtime) | ipc | Keep | Platform isolation; `macos-sandbox` surface |
| synvoid-metrics | Metrics registry + recorder | 3806 | Yes — observability boundary, label cardinality | Yes | 5 | core, utils, waf | Keep | Single metrics owner; security_observability guard target |
| synvoid-theme | Templates, error pages, captcha widget | 2043 | Limited — rendering | Yes | 2 | config | Keep | Rendering isolation; challenge depends directionally |
| synvoid-geoip | GeoIP lookups | 1227 | Yes — lookup semantics | Yes | 2 | config, http-client | Keep | Isolates maxminddb dep |
| synvoid-integrity | Integrity checking, origin-key exchange | 2521 | Yes — verification | Limited | 1 | pqc | Keep | Crypto-adjacent; `origin_key_exchange` feature gate |
| synvoid-icmp-filter | ICMP filtering (feature-gated) | 4457 | Yes — filter semantics | Limited | root only | none | Keep | `icmp-filter` feature isolates raw-socket/aya surface |
| synvoid-vpn-client | VPN client (`synvoid-vpn` binary support) | 1591 | Yes — client lifecycle | Limited | root only | config, platform, tunnel, utils | Keep | Binary-support boundary |
| synvoid-filter | Protocol allow/deny admission traits | 134 | Limited — thin trait/config vocabulary | Limited | root only | none | Keep (future candidate) | Smallest crate; kept because it is a stable narrow-trait boundary consumed at admission control. Revisit only in a scoped pass with stability review — do not merge for count alone. |
| synvoid-cli | CLI arg/error types (clap) | 210 | Limited — arg parsing | Limited | root only | none | Keep | Dependency isolation for clap; zero-dep keeps builds cheap |
| synvoid-wasm-pow | WASM proof-of-work | 769 | Yes — PoW verify (constant-time) | Limited | root only | (leaf) | Keep | Security primitive isolation |

## Dependency direction notes

- No cycles: `synvoid-core` and `synvoid-utils` are zero-dep roots;
  `synvoid-http` has the widest fan-in (16 internal deps) because it is the
  HTTP composition surface, not a wrapper — its invariants (framing,
  normalization ownership) are crate-level tests.
- `synvoid-mesh` is the largest crate (100 kLOC) but is feature-gated out
  of default-minimal builds; splitting it further is explicitly out of
  scope (rejected: new crates solely to reduce LOC). Phase 27 extracts only
  the low-capability wire/identity vocabulary (`synvoid-mesh-protocol`) so
  verification-only consumers avoid DHT/Raft/SQLite/YARA — success is measured
  by reduced consumer dependencies, not LOC.
- `synvoid-waf` ↔ `synvoid-mesh` edge: WAF depends on mesh types only for
  threat-intel policy gating (narrow), while mesh depends on nothing from
  WAF at the type level except stubs via block-store; the request-path
  capability guards (`boundary_composition_guard`,
  `mesh_id_boundary_guard`) pin this direction.

## Future simplification candidates (not executed)

1. `synvoid-filter` → fold into `synvoid-proxy` (admission consumer) or
   `synvoid-core` (trait home) only if the semver review concludes no
   downstream consumer pins the path. Thin but stable; count-only merging
   is rejected by the phase criteria.
2. Egress layering (`http-client` / `upstream` / `tunnel`): three crates
   with clean layering today; any collapse needs a scoped dependency-flow
   plan, not a Phase 24 drive-by.
3. `synvoid-app-server` ↔ `synvoid-app-handlers`: adjacent app runtimes;
   kept separate for dependency isolation (app-server dep tree vs handler
   protocols).

No other crate qualifies as a merge candidate: each carries independent
invariants, a reusable surface, dependency isolation, feature isolation,
or a compile-time ownership boundary.

## Phase 31 closeout deltas (Track 4)

Recomputed 2026-09-12 (`cargo metadata --all-features`, `cargo tree
--workspace`, `cargo tree -d`, `cargo tree -i
wasmtime/wasmtime-wasi/yara-x/libloading/cryptoki/synvoid-mesh/mesh-protocol`).
No crate created or removed in this phase; all four Track 4 additions
re-verified against the retain bar (no "keep" solely for being new):

- `synvoid-yara` (Phase 26): dependency isolation (single `yara-x` owner;
  mesh has no compiler ref) + security boundary (bounded compile/scan,
  digest/version binding). Reverse deps: upload, jail-runtime, root.
- `synvoid-mesh-protocol` (Phase 27): dependency isolation (leaf: no
  DHT/Raft/SQLite/YARA) + wire-compat invariants. Reverse deps: mesh + root
  feed verification.
- `synvoid-native-extension` (Phase 28): capability isolation (explicit
  unsafe loader, off-by-default feature). Reverse deps: 0-1 (optional).
- `synvoid-jail-runtime` (Phase 29): process-boundary isolation (child
  services + dedicated binaries, never imports root/mesh). Reverse deps: root.
- `synvoid-dnssec-keystore` (Phase 30): security boundary (sealed custody,
  one-way leaf, HSM opt-in). Reverse deps: dns only.

Root direct surface: 38 unused edges removed, 3 test-only moved to
`[dev-dependencies]`, `prost`/`tonic-prost` retained as codegen runtimes with
guard exceptions (see `root_dependency_ownership.md`). Default/minimal
feature behavior unchanged (defaults stay full-featured for compatibility;
`--no-default-features` is the supported hardened profile).

Previously rejected extractions re-evaluated on the final graph (verdict: no
change — see `track4_dependency_security_closeout.md` §5): no
`synvoid-admin-server`, no `synvoid-waf-runtime`, no egress collapse, no
`synvoid-filter` merge, no app-server/handlers merge, and no `synvoid-sdk`
umbrella (explicitly deferred: pre-1.0 internal crates, no external
aggregation demand, remaining root deps are live composition).
