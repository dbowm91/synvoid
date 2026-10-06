# Agent Knowledge Maintenance

How `AGENTS.md`, `.opencode/skills/`, `docs/`, `README.md`, and `plans/`
stay accurate. For agents, by an agent audit (2026-09-11, follow-up 2026-09-13,
Phase 37 pass 2026-09-17, Phase 40 pass 2026-09-18, Phase 47 pass 2026-09-19,
skills/architecture/docs refresh 2026-09-22, tooling/CI pass 2026-10-06,
skills+advisory pass 2026-10-06).

## What was audited (skills + advisory remediation, 2026-10-06)

The skills directory had never been covered by the systematic verification pass
that repaired `architecture/*.md` (commit `d255106e`). All **48** skills were
re-verified against source in four disjoint slices (one agent per slice, strict
file ownership), then every correction was re-checked by the parent agent against
the source symbol before acceptance. **45 skills were edited; 3 were verified
accurate and left byte-identical.** Two new skills were added.

### Dependency advisories (resolved first, documented as precedent)

Three open Dependabot alerts were resolved and recorded in
`architecture/dependency_advisory_remediation.md`:

- `xxhash-rust` GHSA-6g2r-675j-hx59 (runtime scope) 0.8.15 → 0.8.19, lockfile
  only, transitive via `notify` / `iscc-lib`.
- `source-map-js` GHSA-68fv-2mgg-jv7q 1.2.1 → 1.2.2, by raising the
  `admin-ui` `postcss` floor to `^8.5.29` (the committed lock had drifted to
  8.5.10 and did not even satisfy the declared `^8.5.23` range).
- `postcss-selector-parser` GHSA-rj75-hqrm-r3gf 6.1.4 → 7.1.6 via an npm
  `overrides` entry, because Tailwind 3.4.19 pins `^6.1.2` and no 6.x satisfies
  the advisory. Verified by diffing the regenerated `admin-ui/dist/styles.css`
  selector-by-selector: 0 lost, 9 added — all real usage, i.e. the committed CSS
  was **stale**, not degraded.

`cargo audit` is now clean (exit 0; 6 allowed `unmaintained` warnings). The npm
`braces` advisory has **no upstream patch** (range `<= 3.0.3`,
`first_patched_version: null`) and is reachable only through the Tailwind build
toolchain; it is **recorded, not suppressed**, because the only fix is a
breaking Tailwind 4 migration. See checklist item 13.

### Skills: the drift classes that actually occurred

- **Fabricated APIs presented as live.** `serverless_wasm` documented
  `ServerlessManager` and `FunctionDefinition` struct layouts that never existed
  (5 + 7 invented public fields) plus three invented APIs
  (`reload_function`, `deploy_function`, `start_event_consumer`).
  `rule_feed_persistence` cited a non-existent `RulePatternUpdate`.
  `admin_api` listed 8 non-existent metric names and a dead Prometheus owner
  (`start_prometheus_exporter` is `#[allow(dead_code)]`, zero callers).
  `windows_service` cited `inject_https_firewall_rule`, which does not exist.
  In every case the fabricated API was **replaced with the real one** rather
  than deleted, since a gap is less useful to an agent than a correct path.
- **Removed subsystems documented as active.** `dht_persistence` documented
  DHT two-phase commit (`commit_record_after_quorum` / `abort_pending_record`,
  zero call sites) and durable quorum recovery (a `tracing::info!` no-op) as
  live; `dns_dnssec` documented the `dns_interop_encrypted` conformance lane
  removed in Phase 128 and four non-existent example-config filenames.
- **Wrong-but-plausible signatures.** `TunnelConnector::connect` (real:
  `open_tunnel_stream_to_peer`), `HealthCheckMethod::{Http,None}` (real:
  `Head`/`Get`/`Tcp`), `TunnelTransport` wrong on five points, and
  `scan_chunk_utf8` on `StreamingWafCore` — which does not exist anywhere.
- **Unreachable capability described as active.** `broadcast_rule_patterns_update`
  and `set_on_apply_callback` have zero callers, so the supervisor side of rule-feed
  broadcast never triggers while the worker side is live.
- **Silently restructured types.** `StreamingWafCore` moved from
  `state: RwLock<StreamingState>` with `&self` methods to owned state with
  `&mut self`, gaining multipart handling and `PooledBuf` fields.

### Deletion candidates investigated and rejected

Two skills looked dead on a naive grep and were **kept**, after the grep premise
was disproved by reading the source:

- `org_key_trust_chain` — `grep "org_key_trust_chain"` returns 0 files, but the
  identifier is Rust-cased (`OrgKeyManager` in
  `crates/synvoid-mesh/src/mesh/org_key_manager.rs`). The whole trust chain —
  `OrgPublicKey::verify_quorum`, `MemberCertificate::verify_with_public_key`,
  `validate_member_certificate` — exists with matching signatures. **Skill kept
  byte-identical.**
- `topology_visualizer` — no `topolog` match anywhere in `admin-ui/src`, but the
  backend is fully real (`src/admin/handlers/mesh_topology.rs`, routes at
  `src/admin/routes.rs`, `crates/synvoid-mesh/src/mesh/topology.rs`). The only
  drift is that the frontend was never built. Corrected to "backend-only".

**Lesson (now checklist item 14): a zero-hit grep is not evidence of absence.**
Confirm with a Rust-cased / symbol search before proposing a deletion.

### eBPF/XDP recorded as unreachable

`src/waf/flood/ebpf_flood.rs` compiles only under
`#[cfg(all(target_os = "linux", feature = "flood-ebpf"))]`, `flood-ebpf` is not a
default feature, `EbpfFlood` has **no construction site**, and the kernel crate
`ebpf-flood/` is **not a workspace member** (`cargo build --package ebpf-flood`
cannot resolve). `set_ebpf_block_hook` is gone. Recorded in `AGENTS.md` Known
Issues so no agent describes XDP dropping as active.

### New skills added (48 → 50)

- `threat_intel_enforcement` — the observation-vs-enforcement split
  (`lookup_*` diagnostic-only vs `lookup_*_policy_strict`), the five
  `ThreatIntelConsumerKind` variants, provenance rules, and the six
  `tests/security_guard.rs` functions that pin the boundary. Previously smeared
  across `synvoid_mesh`, `block_store`, and `waf_engine`.
- `dns_trust_anchor_rfc5011` — the RFC 5011 state machine
  (`crates/synvoid-dns/src/trust_anchor.rs`, 6 states), `Missing`→`Pending`
  restoration gated on `trust_point == 0`, the unsynchronized
  `TrustAnchorManager` / `hickory_proto::TrustAnchors` limitation, and why
  `[dns] trust_anchors.enabled` currently fails validation with typed
  `Unsupported`. Previously fragmented inside `dns_dnssec`.

Both were authored from source read directly by the parent agent, **not** from
subagent prose — one subagent summary claimed 7 anchor states (there are 6) and
placed `ShadowOnly` on the wrong enum. That correction is the reason new skills
were verified by hand.

### `AGENTS.md`, `SECURITY.md`, `docs/` repairs

- `AGENTS.md`: the facade table cited `src/admin/authority.rs` as the
  non-canonical home for admin mutation authority — **that file does not
  exist**. The whole vocabulary (`AdminMutationAuthority`, `AdminActor`,
  `AdminMutationStatus`, `PropagationStatus`, `AdminMutationResult`,
  `BlockMutationTarget`, `AdminAuditEvent`, `AdminAuditSink`) lives in
  `crates/synvoid-core/src/admin_mutation.rs`; `src/admin/` holds only
  router/middleware/handler wiring. Also corrected
  `DnsServer::new(DnsRuntimeConfig, CertResolver)` to its real 3-arg form
  (adds `Option<Arc<dyn CountryLookup>>`), added the advisory + eBPF Known
  Issues, and added the supply-chain index row for the new remediation record.
- `SECURITY.md`: the YARA transitive Wasmtime line was stated as **48.0.3** in
  four present-tense places while `Cargo.lock` and the `yara-x-compat` fork pin
  **48.0.5**; the RUSTSEC-2026-0326/-0327 remediation had no entry at all.
  Corrected, plus a new triage section for 0326/-0327. Also repaired the rkyv
  section, which pointed at `src/serialization_rkyv.rs` and `src/mesh/config.rs`
  (both nonexistent) — direct `rkyv` was removed from the root package in
  Phase 31, and two rkyv majors are resolved (0.8.18 for SynVoid code, 0.7.46
  transitively via `parcel_sourcemap` → `lightningcss` → the minify fork).
- `architecture/dependency_security_baseline_phase25.md`: the guard
  `wasmtime_transitive_matches_baseline` asserts the literal substring
  `"transitive 48.0.3 line is patched"`. Rather than edit the guard — which
  would weaken a security gate — a **naming note** was added after the sentence
  recording that the line has since advanced to 48.0.5, that 48.0.5 still
  satisfies every patched range listed, and that the 48.0.3 wording must not be
  "corrected" without updating the guard in the same change.
- `docs/README.md`: `FEATURE_STATUS.md` and `HONEYPOT.md` were unlinked from the
  index, and the whole `docs/testing/` (4) and `docs/adr/` (4) trees were absent.
  Added, plus a pointer to `architecture/overview.md` as the internal index.
- `docs/API_REFERENCE.md` was checked and found **correct**: its `config/overseer`
  / `logs/realtime` mentions are in an explicit "removed paths that must stay
  absent" section, not presented as live routes.
- `docs/testing/verification-contract.md` references `testing/lanes.toml` and
  `scripts/ci/select-affected.py`, neither of which exists — **correct as
  written**: that table documents files deliberately deleted in Phase 3, and
  `tools/xtask/src/` confirms no live reference. Left untouched.

### False positives worth recording

A naive path-existence scan over `docs/` produced ~200 "missing" hits. Nearly all
were HTTP routes, MIME types, or traversal examples. Two looked alarming and were
both correct as written: the frozen verification contract above, and
`architecture/overview.md`'s doc count. Do not let an automated sweep trigger
edits without reading the surrounding sentence.

## What was audited (tooling/CI + boundary docs drift repair, 2026-10-06)

Present-state claims in the tooling/CI and boundary/governance docs were
re-verified against source and repaired where they had drifted:

- `developer_tooling.md`: the `verify` lane list omitted `dependency-policy`
  (`cargo deny check`) and `admin-contract`; `verify-full` omitted the
  `icmp-filter` profile and the minimal-profile tests. Added a CI section
  (four jobs, not one), corrected the guard-suite location/count
  (`tools/synvoid-repo-guards/tests/`, 25 files — root `tests/` holds 58
  integration files), and added the bench inventory (16 files, 12 registered
  `[[bench]]` targets, none run in routine CI).
- `ci_fuzz_failure_injection.md`: replaced the "single Ubuntu job" CI claim
  with the current four-job topology (none runs fuzzing).
- `root_dependency_ownership.md`: the `synvoid-geoip` row still cited the
  F-17 tripwire `geoip_provider_is_still_unwired_by_composition`, deleted in
  Phase 138; replaced with the positive gate
  `geoip_capability_is_wired_through_composition`.
- `request_path_capability_boundary.md`: header pointed at a deleted guard file
  (`tests/request_path_capability_boundary_guard.rs`); now names
  `composition_boundary.rs` + `tests/boundary_composition_guard.rs`.
- Checklist item 8 below carried pre-Phase-103/123 Wasmtime versions
  (36.0.15 / 47.0.4); corrected to the lock-resolved 36.0.16 / 48.0.5.
- Workspace split re-measured: 53 members = 47 `synvoid-*` + 6 non-`synvoid-*`
  (root app, `pqc`, `admin-ui`, two examples, `xtask`). Older records that
  split these 44/9 or 43/8 now carry correction pointers.

Checklist item 12 added (see below).

## What was audited (skills/architecture/docs refresh, 2026-09-22)

- Skills 42 → 48: fixed stale pointers in `ipc_hardening` (`crate::process::`
  paths → `synvoid_ipc::`, `sign()` returns `[u8; HMAC_SIZE]`, `from_secret()`
  is `#[cfg(test)]`), `topology_visualizer` (routes live in
  `src/admin/routes.rs:617-622`), `ebpf_blocking` (removed `set_ebpf_block_hook`
  wiring — `GlobalBlockHook` type exists but is unwired; canonical write is
  `block_ip_with_provenance`), `streaming_waf` (resolved `.clear()` vs
  `.resize(0)` contradiction against `streaming.rs:114-143`), `h3_proxy`
  (`synvoid_http_client::send_request_streaming`), `rule_feed_persistence`
  (top-level `[rule_feed]`, Supervisor terminology), `crypto_dependencies`
  (aws-lc-rs 1.18.1, quinn 0.11.9, ML-DSA-44 variant authority), plus scope
  banners on `security_patterns` (fix-log-is-history), `dht_persistence`,
  `dns_dnssec`, `serverless_wasm`, `synvoid_mesh`, and typo/verification-command
  fixes in `raft_consensus`, `implementation_patterns` (worktree section removed).
  The `crates/synvoid-mesh/src/mesh/yara_rules.rs` "missing file" report was
  verified false (file exists, 2490 lines) — only line numbers had drifted.
- New skills (previously uncovered subsystems): `upload_security`,
  `yara_scanning`, `metrics_observability`, `http_client`, `challenge_pow`,
  `icmp_filter`. `AGENTS.md` skills count + facade table updated.
- `architecture/overview.md`: WAF detector count reconciled to canonical
  **13 `AttackType` policy detectors + HeaderValidator + behavioral engine**
  (`waf.md` was already correct; `waf_engine` skill fixed from 16); DNS
  capabilities line no longer lists RPZ/dynamic updates as live (Phase 45
  fail-closed `Unsupported`); Documentation Map Historical row now indexes all
  closeout/phase/track reports with supersession notes; Boundaries row gains the
  ledger→facade-matrix→dependency-ownership hierarchy + perf closeouts.
- `docs/`: `GETTING_STARTED.md` CLI section aligned to flag-based CLI;
  `FEATURE_STATUS.md` `--all-features` line removed + missing operator flags
  noted; `RELEASE.md` pre-release gate aligned to the verification contract;
  `nextest-policy.md` install snippet pinned; `ARCHITECTURE.md` stale
  quick-start/nginx-model lines fixed; `UPGRADE.md` gains 1.0→1.1; security-doc
  cross-pointers added; `plans/release_handoff_note.md` marked historical.
- New checklist item 11 (perf-campaign semantics + skill-count truthfulness).

## What was audited (Phase 48 corrective closeout, 2026-09-19)

- Closed the Phase 41–47 campaign as a historical unit: umbrella roadmap +
  Phase 41–47 plans marked implemented/closed (intent preserved; closeout
  footers point at `architecture/runtime_truthfulness_security_publication_closeout.md`,
  the new canonical evidence record); `plans/roadmap.md` post-Phase-40 section
  completed; `architecture/overview.md` index points at the closeout.
- Re-audited all Phase 41–47 acceptance criteria against landed code/tests/
  guards/binding docs: no concrete mismatch found, no runtime changes.
  Recorded two accepted test/contract-granularity notes (DoT lifecycle covered
  by the shared bounded loop, no DoT-specific integration; `BackendBusy`→503
  is a typed library contract with no current HTTP consumer) — neither blocks
  closeout.
- Corrected stale time-sensitive claims without making a migration decision:
  `architecture/public_crate_release_readiness_phase47.md` §http-client,
  `AGENTS.md` Known Issues, and this file no longer say "eggfetch still
  0.1.4 / no 0.1.5+" as present-tense fact; they record the Phase 47
  0.1.4-era baseline as dated history and point at the open follow-up
  `plans/eggfetch_current_line_parity_review.md`. Fixed `AGENTS.md`
  `src/pqc.rs` → `crates/synvoid-wasm-pow/src/pqc.rs` and the stale
  `dns.doq.bind_address` matrix row in `architecture/dns.md`.
- Added narrow `runtime_truthfulness_closeout` repo-guard (status drift +
  stale eggfetch literal in current-state surfaces); historical `plans/`
  text explicitly out of scope. New checklist item 10.

## What was audited (2026-09-19, Phase 47 public-crate release readiness)

- Promoted `synvoid-rate-limit` 0.1.0 to class 3 (first externally supported
  library; MSRV 1.81 with packaged-tarball evidence): new
  `architecture/public_crate_release_policy.md` (binding semver/MSRV/support
  bar) + `architecture/public_crate_release_readiness_phase47.md` (per-candidate
  decisions), crate README/CHANGELOG/rustdoc quickstart/property tests,
  `docs/releasing.md` §1a externally supported order (rate-limit only), root
  `README.md` Reusable libraries section, `AGENTS.md` Known Issues + index,
  new `public_crate_release_policy` repo-guard test, this file + new checklist
  item 9.
- Deferred with recorded reasons (no metadata implying support):
  mesh-protocol (wire-versioning/`non_exhaustive` policy), proxy-cache (object
  cache, NOT RFC 9111), dnssec-keystore (threat model/PKCS#11 CI/RSA advisory),
  platform (MSRV/semver/examples), yara (compat fork), http-client (internal
  pending a fresh current-line eggfetch review; the 0.1.4-era matrix is dated
  history — see `plans/eggfetch_current_line_parity_review.md`),
  utils/core (permanently internal).
- Skills: no stale publication claims found (only `supply_chain` mentions
  `cargo publish`, correctly as manual-only) — no skill changes needed.
- Historical records deliberately NOT rewritten: `plans/*` phase history,
  `architecture/crate_boundary_reuse_closeout.md` (Phase 35 class-2 table
  stays as the pre-promotion record; the Phase 47 doc records the delta).

## What was audited (2026-09-18, Phase 40 YARA-X 1.20 upgrade)

- YARA engine 1.15 → 1.20.0 (temporary `third-party/yara-x-compat` fork,
  wasmtime 40.0.4 → 47.0.4): updated `AGENTS.md` Known Issues (new Phase 40
  entry; Phase 36 entry kept with version-remediation noted),
  `architecture/dependency_security_baseline_phase25.md` (title, §2/§3/§5/§6,
  transitive anchor 40.0.4 → 47.0.4, new §11 addendum),
  `architecture/{release_profile_matrix,layer_3_5_deep_dive}.md`,
  `docs/RELEASE.md`, `CHANGELOG.md` (`[Unreleased]` entry; 1.1.0 history
  untouched), `.opencode/skills/supply_chain/SKILL.md` (ignore count
  16 → 2, fork ownership), and this file's checklist item 8.
- `deny.toml` + `.cargo/audit.toml`: 14 retired 40.x-only ignores removed
  (0085–0096, 0114, 0222, 0269); retained 0071 (`rsa`, no upstream fix) and
  0235 (`rkyv` via minify chain).
- Historical records deliberately NOT rewritten: `plans/*` phase/closeout
  history (superseded by `plans/phase_40_closeout_results.md`),
  `architecture/track4_*`, `docs/testing/verification-contract.md` (frozen).
- Pruned: stale "bumpalo-blocked / Phase 40 owns the upgrade" forward
  references in `crates/synvoid-yara` (manifest comment, `artifact.rs` doc,
  boundary-test comment) — replaced with landed-state documentation.

## What was audited (2026-09-17, Phase 37 Wasmtime LTS migration)

- Direct runtime 42.0.2 → 36.0.15 LTS: updated `AGENTS.md` Known Issues,
  `SECURITY.md` (triage rows, dependency-policy, patch sections, limitations),
  `architecture/dependency_security_baseline_phase25.md` (§1/§3/§4/§6 + anchors),
  `architecture/{plugin_wasm,spin,layer_3_5_deep_dive}.md`, `docs/RELEASE.md`,
  `.opencode/skills/supply_chain/SKILL.md`.
- Pruned `.opencode/skills/serverless_wasm/SKILL.md` "WASI Support (Wave 4.6)":
  the `wasmtime_wasi::WasiCtxBuilder` sample described code that does not exist
  (no `wasmtime_wasi` import anywhere; `wasi_enabled` is inert `false`
  plumbing) and contradicted the guard-enforced WASI-absence invariant.
  Replaced with the absence-by-design statement.
- `README.md`: no version-pinned wasmtime content — correctly untouched.
- Historical records deliberately NOT rewritten: `plans/*` phase/closeout
  history, `architecture/track4_*`, `architecture/crate_boundary_reuse_closeout.md`,
  the 2026-09-11/13 audit entries in this file.
- New recurring checklist item 8 (wasmtime direct/transitive versions +
  guard anchors) so the next audit catches version drift mechanically.

## What was audited (2026-09-13 follow-up)

- All 37 skills re-checked; thin (<100-line) skills verified as intentional
  pointer-style guides with correct canonical paths — kept, not bulk-expanded.
- 2 skill fixes: `dht_persistence` dangling code fence + Cyrillic typo;
  `proxy_upstream` dropped a nonexistent `crates/synvoid-proxy/AGENTS.override.md`
  reference.
- 1 skill rewritten: `supply_chain_hashes` (single-fix record) →
  `supply_chain` (deny/audit gates, ignore-metadata rules, wasmtime baseline,
  pip `require_hashes`).
- 5 skills added (previously uncovered guard-enforced subsystems):
  `block_store`, `tls_termination`, `waf_engine`, `plugin_runtime`, `auth`
  — 42 total.
- 5 stale `skills/<name>.md` references fixed in `AGENTS.override.md` files
  (`src/worker/`, `src/http3/`, `src/waf/`, `crates/synvoid-dns/`; the
  `performance_patterns` ref mapped to the existing `implementation_patterns`
  skill). Canonical form is `.opencode/skills/<name>/SKILL.md`.
- `docs/`: 5 precision fixes — `PERFORMANCE.md` invalid `distributed`
  rate-limit mode → `shared` (only `shared`|`isolated` validate);
  `DEPLOYMENT.md` Docker healthcheck `/api/health` → `/health`;
  `DEVELOPER.md` `unified_server_workers` 1 → 4 (shipped `config/main.toml`);
  `CONFIGURATION.md` PQ `prefer_post_quantum` clarified as config-default-true
  but requiring `--features post-quantum` at build, empty Threat Level heading
  restructured; `WAF_MESH.md` compiled-by-default vs runtime-disabled note.
  Claims checked and left alone: `MeshConfig::enabled` defaults `false`
  (WAF_MESH "disabled by default" correct), gRPC control-plane TLS is a real
  `control_api_tls` path (DEVELOPER.md checklist kept), `wasmtime` 40.0.4 +
  42.0.2 still in `Cargo.lock` (AGENTS.md Known Issues current).
- `architecture/`: 15 one-time phase/closure reports deliberately NOT moved
  to `_archived/` — `overview.md` already labels them "Historical / closure
  reports" in the Documentation Map, and moves would churn external links for
  no agent value. Revisit only if a report starts getting cited as authority.
- `README.md`, `plans/` (completed handoff history): no action needed.

## What was audited (2026-09-11)

- All 35 skills in `.opencode/skills/*/SKILL.md` checked against the
  codebase. Result: no fully stale skills; 5 fixed stale paths and 2 new
  skills added (`config_system`, `admin_contract`) — 37 total.
- `architecture/` (136 docs): one live stale import fixed
  (`waf.md` `crate::upload::UploadValidator` → `synvoid_upload::…`;
  `crate::upload` was removed in Phase 03). Remaining
  `crate::auth|cgi|…` hits are intentional historical context in
  `facade_disposition_matrix.md` / `root_module_burndown_report.md`.
- `docs/` + `README.md`: no removed-facade or stale-path references.
  `README.md` gained the `protobuf-compiler` prerequisite (default `mesh`
  feature needs `protoc`; previously only `AGENTS.md` said so).
- `plans/` (186 files): completed-phase handoff artifacts retained as
  history by decision — not moved/archived to avoid a noisy rewrite.
  They are development artifacts, not operator docs (`README.md`
  says so explicitly).
- `CHANGELOG.md` member counts left untouched: `43` was correct for the
  1.1.0 release window, not a staleness bug.

## Recurring checklist for future audits

1. `grep -rn "src/config/main\|src/config/site\|src/proxy\.rs\|src/serverless/\|src/waf/attack_detection/" .opencode/skills/`
   — root `src/config/` holds only override docs; `src/serverless/`,
   `src/proxy/`, `src/waf/attack_detection/`, `src/dns/` are facades.
   Canonical code lives in `crates/synvoid-*/src/`.
2. `grep -rn "crate::auth\|crate::cgi\|crate::challenge\|crate::filter\|crate::integrity\|crate::php\|crate::proxy_cache\|crate::upload" architecture/ .opencode/skills/ docs/`
   — outside the two intentional history docs above, any hit is a bug
   (map to `synvoid_auth`, `synvoid_app_handlers::{cgi,php}`,
   `synvoid_challenge`, `synvoid_filter`, `synvoid_integrity`,
   `synvoid_proxy_cache`, `synvoid_upload`).
3. New `synvoid-*` crate or guard-enforced contract without a skill is a
   gap candidate — check the Skills list in `AGENTS.md`.
4. Skill cross-references use the canonical form
   `.opencode/skills/<name>/SKILL.md` — bare `skills/<name>.md` refs in
   `AGENTS.override.md` files are stale (audit 2026-09-13 fixed five).
   Skill directory names must match the `name:` front-matter field.
5. `README.md` Build section vs `AGENTS.md` Build & Setup: prerequisites
   (`protoc`, feature matrix) must agree.
6. `AGENTS.md` process-model line vs `src/supervisor/process.rs`
   (`spawn_unified_server_workers(config.unified_server_workers)`) and
   `config/main.toml` (`[defaults.worker_pool] workers`).
7. Operator docs vs config validation: rate-limit modes (`shared`|`isolated`
   in `crates/synvoid-config/src/site/ratelimit.rs`), health path (`/health`,
   no `/api` prefix), shipped worker count (`config/main.toml`), and
   config defaults that look feature-gated but are not
   (`prefer_post_quantum` is telemetry and does **not** need the
   `post-quantum` feature — inbound PQ KEX is always compiled in;
   corrected in Phase 140, which is how this stale item was found).
8. Wasmtime versions vs `Cargo.lock`: `rg -n '36\.0\.1[0-9]|wasmtime.*36' AGENTS.md
   SECURITY.md deny.toml .cargo/audit.toml architecture/dependency_security_baseline_phase25.md
   .opencode/skills/` — any reference to the retired `42.0.2` direct line or
   `40.0.4`/`47.0.4` transitive line outside historical
   phase/closeout reports is a bug (direct is 36.0.16 LTS; transitive is
   **48.0.5** via the `third-party/yara-x-compat` fork, advanced 47.0.4 → 48.0.3
   → 48.0.5 for RUSTSEC-2026-0315/-0316 and RUSTSEC-2026-0326/-0327). Guard
   anchors in the baseline doc (`wasmtime-direct-version`,
   `wasmtime-transitive-version`, `wasmtime-wasi-absent-from-lock`) must match
   the lock.
9. Public-crate boundary: `rg -ln 'rust-version' crates/*/Cargo.toml` must
   list only class-3 crates (currently just `synvoid-rate-limit`); any
   "externally supported"/"published"/"stable API" claim for another
   `synvoid-*` crate in `architecture/`, `.opencode/skills/`, `docs/`, or
   `README.md` is a bug unless `public_crate_release_readiness_phase47.md`
   (or a successor promotion record) names it class 3.
10. Campaign-status truthfulness: the Phase 41–47 umbrella roadmap and
    Phase 41–47 plans must read implemented/closed (not active handoff);
    current-state surfaces (`AGENTS.md`,
    `architecture/public_crate_release_readiness_phase47.md`,
    `architecture/agent_knowledge_maintenance.md`) must not present the
    0.1.4-era eggfetch version claim as current fact (historical `plans/`
    and dated Phase 34/35 decision records may describe their own baseline).
     Enforced by the `runtime_truthfulness_closeout` repo-guard test.
11. Perf-campaign + skill-count truthfulness: `AGENTS.md` Known Issues,
     `architecture/overview.md`, and skills must preserve the Phase 49–57
     non-default semantics (`check_request_sync` inline, `BufferPool::acquire`
     length-not-capacity, `resize(0)`-not-`clear()`, TeeBody exact-once
     governor release, one honeypot-runner per lifecycle) and the current
     skill count wherever a count is stated — **re-derive it, do not increment
     it** (see item 15; 50 as of 2026-10-06). New subsystem coverage without a
     skill is a gap — re-run the missing-skill scan from the 2026-09-22 entry
     (remaining uncovered: geoip, integrity, vpn-client, app-server/theme,
     cli-dispatch).
12. Tooling/CI + boundary doc truthfulness (added 2026-10-06):
     - `cargo xtask verify` is 10 steps — fmt, clippy, dependency-policy
       (`cargo deny check`), core-compile, repo-guards, security-regression
       (single-threaded), root-guards (`--features mesh`), core-admin-tests,
       admin-contract (`--features mesh,dns,icmp-filter`), failure-injection.
       Any doc lane list omitting `deny` or the admin contract is stale.
     - `.github/workflows/ci.yml` has four jobs (`ci`, `dependency-security`,
       `sandbox-native-qualification`, `icmp-native-qualification`); only the
       first two run on push/PR. "Single job"/"single Ubuntu job" wording is
       stale.
     - Fuzz: 21 targets declared flat in `fuzz/*.rs`, never
       `fuzz/fuzz_targets/`. Benches: 16 files in `benches/`, 12 registered
       `[[bench]]` targets, none executed by `verify` or `verify-full`.
       Transport benches in `benchmarks/http_transport/` stay manual-only and
       are never compared across hosts.
     - Guard names cited in docs must resolve: root guards are `tests/*.rs`
       files, repo guards are `tools/synvoid-repo-guards/tests/*.rs` files, and
       some cited names are test *functions* inside those files
       (`root_dependency_entitlement_guard`, `deny_ignore_metadata_guard`,
       `yara_fork_is_temporary_guard`, `request_path_capability_boundary_guard`).
       A guard that has been deleted or renamed must not still be cited as a
       live gate.
     - Facade thinness is asserted from `src/`, not assumed: `src/platform/`,
       `src/dns/`, `src/process/`, and `src/utils/ratelimit/` are alias/re-export
       facades, but `src/icmp_filter/` also holds a real 232-line `adapt.rs`
       adapter, so it is not a bare re-export.
13. Advisory triage by **scope and reachability**, not severity alone (added
    2026-10-06): `gh api repos/dbowm91/synvoid/dependabot/alerts` is the source
    of truth for open alerts; the advisory detail (vulnerable range,
    `first_patched_version`) comes from `gh api /advisories/<GHSA>`. Classify
    each as runtime / dev-scope and note whether a patch exists at all before
    choosing a remediation. Current posture: `cargo audit` clean; `xxhash-rust`
    0.8.19; npm `braces` has **no upstream patch** (range `<= 3.0.3`) and is
    recorded, not suppressed — an unpatched advisory is documented with its
    removal condition, never silenced. `deny.toml` ignore rules are Rust-scoped
    and cannot govern an npm advisory. Record:
    `architecture/dependency_advisory_remediation.md`.
14. A zero-hit grep is **not** evidence of absence (added 2026-10-06). Two
    skills were nearly deleted on this basis in the 2026-10-06 pass and both
    were fully intact: `org_key_trust_chain` (the literal string is
    snake_case; the code is Rust-cased `OrgKeyManager`) and
    `topology_visualizer` (backend real, frontend never built). Before
    proposing a skill deletion, re-search by Rust symbol / enum variant /
    PascalCase, and read the referenced source file. A deletion proposal must
    cite a file you opened, not a grep that returned nothing.
15. Doc counts and skill counts stated anywhere must be re-derived, not
    incremented: `ls architecture/*.md | wc -l` (224 as of 2026-10-06) and
    `ls -d .opencode/skills/*/ | wc -l` (50 as of 2026-10-06).

## Index

Indexed from `AGENTS.md` → Architecture Index ("Agent knowledge" row).
Binding detail lives with each subsystem's primary doc; this file is
process, not authority.
