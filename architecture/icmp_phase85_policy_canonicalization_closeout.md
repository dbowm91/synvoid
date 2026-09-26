# Phase 85 Closeout: ICMP Policy Model and Config Canonicalization

Status: closed 2026-09-26.

Planning baseline: `81638c251592913579bd9bbce51d013c44d67910`
(campaign baseline; implementation built on `44116c1f` post-Phase-84 head).
Implementation SHA: `20dfc148df6ac522db6b3439cf5102a6015257b5`.

Plan: `plans/phase_85_icmp_policy_model_and_config_canonicalization.md`.
Roadmap: `plans/icmp_policy_enforcement_extraction_preparation_roadmap.md`.

## Decision

One canonical semantic policy owner exists: `synvoid-icmp-filter::policy`
(`IcmpPolicy` and its vocabulary). Both serialization DTOs — the
enforcement-crate `config::IcmpFilterConfig` and the application
`synvoid_config::icmp_filter::IcmpFilterConfig` — convert to it through
exhaustive typed adapters. No model-to-model `serde_json::Value` bridge
remains in active code. No publication or external-repo change occurred.

## Workstream dispositions

- **A (portable model):** `crates/synvoid-icmp-filter/src/policy.rs` owns
  `IcmpPolicy`, `IcmpRule`, `IcmpSelector` (family-bound), `IcmpFamily`,
  `IcmpVerdict`, `PolicyDirection`, `InterfaceSelector`, `RateLimitPolicy`
  (explicit `RateLimitScope::Global`, `strict` defaults true),
  `RequestedBackend`, `BackendOptions` (table identity + eBPF path, outside
  protocol policy), `PolicyRequirements` (backend capability input for
  Phase 86), and canonical/legacy table constants. No TOML/OpenAPI,
  admin, metrics, tracing, path, or runtime imports.
- **B (exhaustive adapter):** `compat::adapt_config_to_policy` (crate DTO)
  and root `src/icmp_filter/adapt.rs::adapt_app_config_to_policy`
  (application DTO, composition boundary) map every field or return typed
  errors (`AdaptError` / `ConfigAdaptError`); exempt IPs parse exactly
  once; direction/interface intent preserved; v4/v6 lists map under their
  documented families (legacy v4 never reinterpreted as v6); rate-limit
  semantics explicit; backend fields validated separately. Admin PUT
  (`src/admin/handlers/icmp.rs`) parses the application wire shape,
  adapts with typed errors, surfaces validation findings, builds the
  enforcement DTO field-by-field, and persists the app DTO directly.
- **C (canonical defaults):** canonical table `synvoid-icmp`
  (`BackendOptions::canonicalize_table_name` maps legacy `synvoid_icmp`);
  eBPF path spellings aliased both directions; interface rule unified to
  the operational 1-15 charset on both DTOs (table rule unchanged at 64);
  enum casing dual-read (Pascal persisted, lowercase accepted) on both
  DTOs; rate-limit absent/disabled maps to `None`, enabled-zero rejected.
  Golden fixtures: `tests/fixtures/legacy_default.toml`,
  `tests/fixtures/canonical_policy.json`. Enforcement DTO gains the same
  TOML `skip_serializing_if` null fix the app DTO already had.
- **D (family vocabulary):** `IcmpV4Type` (15 named + `Raw(u8)`),
  `IcmpV6Type` (11 named incl. Packet Too Big, Echo, RS/RA, NS/NA,
  Redirect + `Raw(u8)`); `IcmpSelector::{V4,V6}` keeps numeric type
  family-bound; unknown values representable, never rejected for being
  unnamed.
- **E (RFC validation):** `src/validation.rs` (`validate_policy` with
  `ValidationRole::{Host,RouterTransit}`, strict flag, `ValidationOverride`
  per-hazard opt-in) flags `icmpv6_ptb_blocked` (RFC 8201, strict→error),
  `icmpv6_nd_blocked` (RFC 4890, host-critical), and advisory
  `icmpv6_diagnostic_blocked`. Never rewrites rules; default migration is
  non-strict (preserve behavior, surface diagnostics).
- **F (rate scope):** `RateLimitScope::Global` documents current backend
  truth; `strict: true` default forces hard error on inexpressible scope
  rather than silent emulation. App DTO carries `scope` (default global).
- **G (app concerns out):** policy/validation import only `serde` +
  `std::net`; admin DTOs, OpenAPI wrappers, metrics, tracing, paths,
  runtime handles, and artifact discovery stay out. Backend selection
  lives beside enforcement as `RequestedBackend`, not in the policy value.

## Acceptance mapping

- One canonical semantic owner: `policy.rs` (DTOs documented as
  serialization-only). ✓
- No JSON round-trip between ICMP config models: admin bridge deleted;
  `no_json_bridge_between_icmp_models` invariant pins it. Wire JSON
  (HTTP ↔ one DTO) remains and is explicitly distinguished. ✓
- Backend options separated from protocol policy: `BackendOptions`. ✓
- Persisted/default configs readable: aliases/defaults + legacy tests. ✓
- v4/v6 cannot confuse implicitly: family-bound selector + tests. ✓
- Typed messages + raw escape: v4/v6 enums + `Raw(u8)`. ✓
- RFC validation detects PMTUD/ND hazards: PTB + ND findings. ✓
- Rate scope defined: `Global` + strict. ✓
- Typed conversion errors: `AdaptError` / `ConfigAdaptError`. ✓
- No publication: none occurred. ✓

## Verification evidence (implementation head)

- `cargo fmt --all -- --check`: pass.
- `cargo test -p synvoid-icmp-filter --profile ci`: 37 unit + 12
  integration (`policy_canonicalization`) pass.
- `cargo test -p synvoid-config --profile ci`: 98 pass (incl. 5 new
  compat tests).
- `cargo check --no-default-features --features icmp-filter --profile ci`:
  pass.
- `cargo clippy --profile ci --all-targets -- -D warnings`: pass.
- Admin contract with `--features mesh,dns,icmp-filter`: 22 + 18 + 24
  pass.
- `cargo xtask test guards`: 3/3 steps pass (incl. repo-guards 108/108
  after ledgering `icmp_filter` as a `synvoid-config` consumer for the
  composition-boundary adapter).
- Ledger: `architecture/root_dependency_ownership.md` adds `icmp_filter`
  to the `synvoid-config` allowlist with this closeout as justification.

## Residuals / Phase 86 unblocked

- Backend capability is now evaluable against `PolicyRequirements`
  (rate-global, iface, type/code, v6) instead of a static boolean; the
  Phase 86 capability/privilege work is unblocked.
- `RequestedBackend` is recorded but strict no-fallback selection,
  operation-specific probes, Windows dependency truth, and NetBSD PF
  removal belong to Phase 86 and are untouched here.
- Compile-before-mutate, receipts, readback/drift (Phase 87) and native
  qualification (Phase 88) are untouched.
- Full `cargo xtask verify` was not re-run end-to-end in this phase
  beyond the listed suites + guards; Phase 88 owns final campaign-wide
  verification.
