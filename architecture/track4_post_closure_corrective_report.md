# Track 4 Post-Closure Corrective Report

Status: complete (implementation committed; closure commit records verify-release + final SHA). Plan: `plans/track4_post_closure_corrective.md` (now marked complete).
Corrective base SHA: `b779fe3d` (plans: register Track 4 post-closure corrective handoff).
Implementation commit: see git log for `track4-corrective` (this report amended with the result in the closure commit).

This report records only current reproducible evidence for the corrective pass.
It does not duplicate the Phase 31 closeout (`architecture/track4_dependency_security_closeout.md`).

## 1. Phase 25-31 plan-status reconciliation

All seven executed phase plans now carry a completion preamble with landing SHA
and closure evidence, preserving the historical handoff bodies unchanged:

| Plan | Landing commit | Status line |
|------|---------------|-------------|
| `plans/phase_25_dependency_security_baseline_and_entitlement.md` | `4d5cb580` | complete (2026-09-12) |
| `plans/phase_26_yara_execution_boundary_consolidation.md` | `390af6ab` | complete (2026-09-12) |
| `plans/phase_27_mesh_protocol_contract_extraction.md` | `ac3b8e87` | complete (2026-09-12) |
| `plans/phase_28_native_extension_capability_isolation.md` | `d3ad2bc2` | complete (2026-09-12) |
| `plans/phase_29_jail_runtime_package_and_process_split.md` | `fd101145` | complete (2026-09-12) |
| `plans/phase_30_dnssec_keystore_boundary_extraction.md` | `6351b39d` | complete (2026-09-12) |
| `plans/phase_31_dependency_surface_closeout_and_release_verification.md` | `688fa74e` | complete (2026-09-12), final Track 4 closeout |

No new plan-status lint framework was added (no suitable seam existed).

## 2. Advisory metadata / re-audit state

- Every `deny.toml` ignore now has `Owner:`, `Reviewed: 2026-09-13`,
  a single machine-readable `Re-audit: 2026-10-01`, and an explicit
  `Remove condition:` (upstream event, not a date). All `Remove-by: Phase XX`
  milestone promises removed from current policy docs.
- `RUSTSEC-2026-0269` wording exact everywhere: 42.0.2 and 40.0.4 affected,
  `wasmtime-wasi` absent from lock/graph, capability absence + bumpalo-blocked
  upgrade — never "patched".
- Ownership recomputed 2026-09-13: `bincode` is transitive-only (admin-ui yew
  chain 1.3.3 + `yara-x` 2.0.1; no direct root/workspace edge since Phase 31);
  `rsa` has no direct root edge (Phase 31 removed it; via
  synvoid-dns/keystore/tls/yara-x). `SECURITY.md`, baseline §2/§6, and
  `deny.toml` comments corrected accordingly.
- `.cargo/audit.toml` and `deny.toml` advisory sets synchronized (16/16 both
  directions; guard now checks both ways).
- Upstream blockers unchanged (no silent extensions): wasmtime ≥46.0.3 blocked
  by the `bumpalo` =3.19.0 vs ^3.20.2 conflict; yara-x still on wasmtime 40.x;
  rkyv 0.7 via parcel_sourcemap. Next re-audit: 2026-10-01.

## 3. Effective-date guard

`tools/synvoid-repo-guards/tests/dependency_security.rs`:

- Pure helpers: `parse_ymd` (chrono `NaiveDate`, leap-year correct),
  `re_audit_dates_in_block`, `evaluate_advisory_block(id, block, as_of)`.
- Production `as_of` = current UTC date (`chrono::Utc::now().date_naive`);
  deterministic override `SYNVOID_SECURITY_REVIEW_AS_OF=YYYY-MM-DD` (malformed
  override fails closed). `SOURCE_DATE_EPOCH` deliberately ignored for review
  time (contract §reproducibility note).
- Guard rejects: missing `Owner:`, missing `Re-audit:`, malformed dates,
  `Re-audit` on/before `as_of`, conflicting dates in one block, and
  deny↔audit set mismatch in either direction.
- Unit tests: valid/leap/malformed dates, year boundary, before/on/after
  deadline (on-day = expired), missing fields, malformed/conflicting dates,
  extraction ignoring `Reviewed:`/`Remove condition:`.
- Verified live: `SYNVOID_SECURITY_REVIEW_AS_OF=2026-10-01` (and later) fails
  all 16 ignores; malformed override fails closed; `SOURCE_DATE_EPOCH=0` still
  passes (epoch ignored).
- New tool-only dev-dependency: `chrono 0.4` for repo-guards (already in the
  workspace; smallest correct UTC civil-date source). `Cargo.lock` updated.
- `docs/testing/verification-contract.md` documents the
  reproducibility-vs-review-time distinction.

## 4. Bounded fuzz evidence (final corrective tree, no code changed after)

Toolchain: `rustc 1.100.0-nightly (a69a63265 2026-09-03)`, `cargo-fuzz 0.13.2`.
Harness check: each target drives its production seam (frame reader +
request/response validators; `MeshMessage::decode_compressed`;
`PluginManifest::parse_toml`) — no stale harness.

| Target | Command | Result |
|--------|---------|--------|
| `jail_ipc_frame_decode` (Phase 29 wire boundary) | `cargo +nightly fuzz run jail_ipc_frame_decode -- -runs=1000` (in `fuzz/`) | DONE 1000 runs, cov 227 ft 353, no crash/hang |
| `mesh_protocol_compressed_decode` (Phase 27 wire surface) | `cargo +nightly fuzz run mesh_protocol_compressed_decode -- -runs=1000` | DONE 1000 runs, cov 512 ft 569, no crash/hang |
| `plugin_manifest` (Phase 28 trust metadata) | `cargo +nightly fuzz run plugin_manifest -- -runs=1000` | DONE 1000 runs, cov 677 ft 915, no crash/hang |

No minimized artifacts (no crashes). No new CI fuzz matrix added.

## 5. Mesh-to-YARA ingress / trust-order table and disposition

**Decision: Outcome 1 — retain direct supervisor validation** (proven safe, documented in `architecture/mesh.md` §13).

Full validator call sites: exactly one — `submit_rule_for_approval`
(edge-local submit) after role gate (edge + `allow_edge_submissions`, default
false) and size/content gates (`validate_rules_content`). No remote ingress
invokes the compiler.

| Ingress | Trust domain | Bounds before compiler/storage | Sig / replay | Role / approval | Full validator? | Effect |
|---------|-------------|-------------------------------|--------------|-----------------|-----------------|--------|
| Operator direct apply (`apply_rules_direct`) | local operator | none (operator-grade input) | N/A (local) | global required | NO | publish + broadcast + persist |
| Edge-local submit (`submit_rule_for_approval`) | local edge operator | ≤`max_rules_size_kb` (1024KB), `rule ` present, ≤100 rules | signed after (local origin); fresh UUID+ts | edge + allow-list flag | YES, after all gates | Pending + broadcast submission |
| Inbound `YaraRuleSubmission` (peer → global) | remote peer (untrusted) | size/content-gated before storage (corrective hardening; explicit `rejected` response) | none verified at receipt (approval is the gate) | receiver must be global | NO | Pending store + disk (≤1000, 7-day expiry) |
| Global approval (`approve_submission`) | global operator decision | via stored-submission gate above | approval is the trust gate | global + Pending state | NO | version `edge-<id8>-<ts>`, publish + broadcast |
| `YaraRuleAnnounce` / `YaraCompiledRuleAnnounce` | remote peer | size + version-newer via `handle_incoming_rules`; compiled bytes checksum-verified then ignored (never deserialized) | verified when `require_signature` (default true) + trusted-signer check for non-globals | N/A (distribution) | NO | apply text |
| DHT sync (`sync_from_dht`, incl. chunked) | DHT (advisory) | manifest ts bounds (±), single-record fetch bounded, reassembled chunks bounded (corrective hardening) | manifest sig + multi-sig quorum / trusted-signer check | global skips single-sig trust check (authority) | NO | apply text |
| Feed apply (`apply_rules_from_feed`) | operator-configured feed | feed-manager owned | feed owned | global broadcasts | NO | store + conditional broadcast |
| Disk reload (global, at construction) | local disk (operator) | none | N/A | global-only load | NO | in-memory state |
| Admin API (`approve/submit/apply_direct` handlers) | authenticated admin | maps to rows above | session auth (transport layer) | maps to rows above | only via submit row | — |

Corrective code changes (`crates/synvoid-mesh/src/mesh/yara_rules.rs`):

1. `YaraRuleSubmission` receipt: `validate_rules_content` before storage
   (was unbounded peer-controlled storage).
2. Chunk reassembly: decompressed-size bound before use (bomb gate).
3. DHT single-record fetch: size bound before apply.
4. **DoS fix found by the new tests**: `approve_submission` sliced
   `&submission_id[..8]` on peer-supplied IDs — short IDs panicked the
   supervisor process. Now truncates safely (`len().min(8)`). Remaining
   `[..N]` slices in the file are on fixed 64-char hex digests (safe).
5. Testability seam: `new_with_mesh_config` constructor (no behavior change).

Regression tests (`crates/synvoid-mesh/tests/yara_approval_boundary.rs`, 10/10):
oversized submit never compiles; unauthorized roles never compile; unsigned
announce rejected pre-compiler without applying; oversized peer submission
rejected pre-storage/pre-compiler; rejected submission cannot be promoted;
valid approval propagates as text with zero compiler calls.
`synvoid-mesh` still links no `yara-x`/Wasmtime (`yara_execution_boundary`
guard green).

Why not the jail (Outcome 2 rejected): no untrusted text reaches the compiler,
so there is no oracle to move; routing the single local-operator validation
through IPC would add failure modes without removing any reachable risk. Cheap
structural gates stay inline; `yara-x` stays solely in `synvoid-yara`/jail.

## 6. Canonical verification results (final tree)

- `cargo fmt --all -- --check`: PASS
- `cargo xtask verify`: PASS (10/10 steps, 505s)
- `cargo xtask verify-full`: PASS (10/10 steps incl. all 4 feature profiles, full workspace nextest, doctests; 708s)
- `cargo xtask verify-release`: pending clean-tree run after implementation commit (recorded in closure commit)
- `cargo deny check`: advisories/bans/licenses/sources ok
- `cargo audit`: 0 errors, 9 allowed transitive warnings (unchanged baseline)
- `cargo nextest run -p synvoid-mesh`: 1075 passed
- `cargo nextest run -p synvoid-yara -p synvoid-jail-runtime`: 64 passed
- `cargo nextest run -p synvoid-repo-guards`: 74 passed

## 7. Remaining accepted upstream blockers (Re-audit: 2026-10-01)

1. Wasmtime ≥46.0.3 upgrade blocked by `bumpalo` conflict (minify-html →
   oxc_allocator pins =3.19.0; wasmtime 46 needs ^3.20.2).
2. yara-x 1.15 on wasmtime 40.0.4 (12 advisories, exposure evidence in baseline).
3. rkyv 0.7.46 via parcel_sourcemap + macOS BUG-002 linker segfault (retry succeeds; Linux CI unaffected).
4. Prereleases with no stable line: dashmap 7.0.0-rc2, notify 9.0.0-rc.3, openraft 0.10.0-alpha.18.

Track 4 capability boundaries intact: no crate created/merged/split, no YARA
compiler moved, no jail/native-extension/mesh-protocol/keystore boundary weakened,
no new CI matrix, no forced dependency upgrade.
