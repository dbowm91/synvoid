# Dependency Security Re-audit and Wasmtime Remediation Closeout (Phase 103)

Status: **CLOSED QUALIFIED** (2026-10-01).

Final disposition: dependency-security contract restored to green by
removing the blocking Wasmtime RUSTSEC-2026-0315 and RUSTSEC-2026-0316
findings via version remediation (no new advisory ignores), refreshing
the two retained advisory exceptions and the two temporary
compatibility-fork review deadlines with re-triaged capability
evidence, and hardening the temporary-fork guards to be semantically
time-aware (machine-enforced via `SYNVOID_SECURITY_REVIEW_AS_OF`) so
the next review deadline is enforced without hard-coding a date into
the Rust source. No advisory ignore is added for 0315 or 0316; both
are version-remediated, not capability-gated.

## Final dependency graph

```text
wasmtime-direct-version        = "36.0.16"   # 36 LTS in-line patch from 36.0.15
wasmtime-transitive-version    = "48.0.3"    # 48 LTS line (was 47.0.4 in Phase 40)
wasmtime-wasi-absent-from-lock = true        # unchanged
rsa 0.9.10   (RUSTSEC-2023-0071)  → ignored; Marvin decrypt unreachable
rkyv 0.7.46 (RUSTSEC-2026-0235)  → ignored; minifier-internal sourcemaps only
```

> Superseded anchor (2026-10-02, Phase 123): the transitive line is now
> **48.0.5**, not 48.0.3 — advanced for RUSTSEC-2026-0326/-0327. The live guard
> anchors in `architecture/dependency_security_baseline_phase25.md` are
> `wasmtime-direct-version = "36.0.16"` and
> `wasmtime-transitive-version = "48.0.5"`, both matching `Cargo.lock`. The
> direct 36.0.16 line and the two retained ignores above are unchanged.

## Advisories

| ID | Crate | Resolved version | Disposition |
|---|---|---|---|
| RUSTSEC-2026-0315 | `wasmtime` 47.0.4 (via yara-x) | 48.0.3 | Remediated (transitive YARA line moved 47.0.4 → 48.0.3; direct 36.0.16 unaffected; versions below 47 explicitly unaffected); **no ignore** |
| RUSTSEC-2026-0316 | `wasmtime` 36.0.15 (direct) + 47.0.4 (via yara-x) | 36.0.16 / 48.0.3 | Remediated (direct 36.0.15 → 36.0.16 LTS patch; transitive 47.0.4 → 48.0.3 via the same YARA fork); **no ignore** |
| RUSTSEC-2023-0071 | `rsa` 0.9.10 | unchanged | Retained (Reviewed: 2026-10-01; Re-audit: 2026-11-01) — Marvin Attack (PKCS#1 v1.5 decrypt timing) unreachable; rsa is used only for signing/verification/key-parsing paths across `synvoid-yara` / `synvoid-dns` / `synvoid-dnssec-keystore` / `synvoid-tls`. Zero `RsaPrivateKey::decrypt(...)` invocations. |
| RUSTSEC-2026-0235 | `rkyv` 0.7.46 | unchanged | Retained (Reviewed: 2026-10-01; Re-audit: 2026-11-01) — confined to `parcel_sourcemap` → `lightningcss` → `minify-html` chain (minifier-internal sourcemaps); SynVoid code uses rkyv 0.8.x. |

## Wasmtime / Cranelift lock delta (47 → 48 LTS family)

```text
wasmtime 47.0.4 → 48.0.3
wasmtime-environ 47.0.4 → 48.0.3
wasm-encoder 0.252.0 → 0.254.0
wasmparser 0.252.0 → 0.254.0
wasmprinter 0.252.0 → 0.254.0
pulley-interpreter 47.0.4 → 48.0.3
pulley-macros 47.0.4 → 48.0.3
wasmtime-internal-{component-util,core,fiber,jit-debug,jit-icache-coherence,unwinder} 47.0.4 → 48.0.3
cranelift-* family 0.134.4 → 0.135.3
```

Direct 36 LTS patch delta (36.0.15 → 36.0.16):

```text
wasmtime 36.0.15 → 36.0.16
wasmtime-environ 36.0.15 → 36.0.16
pulley-interpreter 36.0.15 → 36.0.16
pulley-macros 36.0.15 → 36.0.16
cranelift-* family 0.123.15 → 0.123.16
```

No unrelated package movement; the 47 → 48 major version change accounts
for the wasmtime/Cranelift family delta only.

## Temporary compatibility forks (Phase 103 Workstream E + Workstream F)

Both temporary forks (minify-html + yara-x) carry Reviewed: 2026-10-01
and Re-audit: 2026-11-01 in both the root `[patch.crates-io]` section
metadata AND the fork's vendored `Cargo.toml`. The fork-review guards
(`minify_fork_is_temporary_guard`, `yara_fork_is_temporary_guard`) now
reuse a shared `evaluate_fork_block` helper that:

- extracts one `Reviewed:` date and one `Re-audit:` date per fork
  metadata block;
- validates strict calendar format (`parse_ymd` rejects malformed
  dates including wrong shape, month overflow, non-leap Feb 29);
- requires `Re-audit > Reviewed`;
- requires `Re-audit > effective_review_date()` (overridable for
  deterministic tests via `SYNVOID_SECURITY_REVIEW_AS_OF=YYYY-MM-DD`;
  same override used by `deny_ignore_metadata_guard`);
- checks `Owner:` and `Removal condition:` markers.

Hard-coding future review dates into the Rust guard is now impossible
— the deadline is computed at test time. 8 new unit tests cover valid,
expired, malformed, and conflicting date scenarios plus the
`fork_metadata_block` / `patch_section_metadata_block` extractors.

## Removal-condition review

| Fork | Removal condition | Upstream release reviewed | Removal status |
|---|---|---|---|
| `third-party/minify-html-compat/` | Official minify-html release eliminates the Oxc 0.95 / external bumpalo 3.19 path and passes `crates/synvoid-static-files/tests/minify_parity.rs` | Latest crates.io minify-html = **0.18.1** (unchanged 2026-10-01); no upstream release satisfies the condition | **Not removable** — retained |
| `third-party/yara-x-compat/` | Official crates.io yara-x ≥ 1.19 resolves a Wasmtime line patched for all advisories relevant to the enabled feature set (currently ≥ 48.0.3 for RUSTSEC-2026-0315 / -0316, or a supported LTS successor) | Latest crates.io yara-x = **1.21.0** (released 2026-09-29, verified via crates.io dependency API: still `wasmtime ^45.0.3`) | **Not removable** — retained; manifest-only Phase 103 delta (47.0.4 → 48.0.3) re-applies the same security-only patch shape, no source divergence |

## Resolved feature graph (Phase 103 cross-check)

| Capability | Test target | Result |
| --- | --- | --- |
| `wasmtime-wasi` absent from `Cargo.lock` | `cargo tree -i wasmtime-wasi` | no match |
| `wasi-filesystem` absent from `Cargo.lock` | `cargo tree -i wasi-filesystem` | no match |
| YARA-X transitive Wasmtime line = 48.0.3 | `cargo tree -i wasmtime@48.0.3` | resolves via `third-party/yara-x-compat` |
| Direct Wasmtime line = 36.0.16 | `cargo tree -i wasmtime@36.0.16` | resolves via `synvoid-plugin-runtime` + root bench dev-dep |
| No `git+` source in `Cargo.lock` | grep on lockfile (wasmtime blocks) | none |
| `rkyv 0.7.46` chain | `cargo tree -i rkyv@0.7.46` | single chain to `synvoid-static-files` via vendored minify-html-compat |
| `rsa 0.9.10` chain | `cargo tree -i rsa@0.9.10` | `synvoid-dns` (mesh_dnssec verify) → `synvoid-dnssec-keystore` (key parsing + SIGN) → `synvoid-tls` (cert parsing) + `synvoid-yara` (yara-x `crypto` feature RSA VERIFY); zero decrypt calls across all four paths |

## YARA runtime performance (Phase 103 Workstream G; corrected by Phase 104)

> Correction note (Phase 104, 2026-10-01): the original Phase 103 section
> below recorded only the post-change probe and compared it to Phase 40
> different-fixture numbers. That comparison is retained only as explicitly
> non-comparable historical context. Regression acceptance now rests on the
> Phase 104 same-host, same-fixture paired comparison across
> `d960f473` (Wasmtime 47.0.4) → `aeeebc7b` (Wasmtime 48.0.3), recorded in
> `architecture/dependency_security_phase104_corrective_closeout.md`.
> No production dependency or runtime change was made by Phase 104.

Original Phase 103 current-state measurement (retained; NOT acceptance proof).
Probe lived in `crates/synvoid-yara/tests/yara_phase103_perf_probe.rs`
and was removed before commit; numbers were captured via stderr.
Single-sided (post-change only, 50 iterations, release profile):

| Operation | n | median | min | max |
| --- | --- | --- | --- | --- |
| Compile (`reload_with_rules`) | 50 | 1049 µs | 1001 µs | 1613 µs |
| Clean scan (~512 B payload, 13 rules, no match) | 50 | 198 µs | 182 µs | 361 µs |
| Matching scan (~512 B payload, 13 rules, 1 forced match) | 50 | 183 µs | 170 µs | 246 µs |
| Reload (fresh generation) | 50 | 1121 µs | 1014 µs | 1593 µs |

Phase 104 paired evidence (acceptance proof). Deterministic 13-rule fixture
(`P104_FIXTURE sha256=8892c2d7274dd6183b6843203b76c57c02b69f9f89fc5a97e8697c998cf1cc39`,
`rule_bytes=1850`, `payload_len=512`, `warmup=5`), release profile, same host
(Apple M4 Pro, macOS 26.6.2, Darwin 25.6.0, rustc 1.98.1). Full methodology
and rerun adjudication in the Phase 104 closeout.

Pass 1 (primary, n=50 each):

| Operation | Before `d960f473` (47.0.4) median / min / max (µs) | After `aeeebc7b` (48.0.3) median / min / max (µs) | Delta_pct `(after-before)/before*100` |
| --- | --- | --- | --- |
| Compile (`reload_with_rules`) | 1050 / 898 / 1597 | 996 / 909 / 1383 | -5.14% (improvement; rerun required by >5% shift rule) |
| Clean scan | 204 / 165 / 524 | 197 / 179 / 707 | -3.43% (within ±5% tolerance) |
| Matching scan | 208 / 165 / 833 | 186 / 178 / 303 | -10.58% (improvement; rerun required) |
| Reload (fresh `YaraScanner::new`) | 1040 / 857 / 1622 | 1021 / 947 / 1399 | -1.83% (within ±5% tolerance) |

Rerun (pass 2, n=50 each; required because two pass-1 shifts exceeded ±5%):

| Operation | Before rerun median / min / max (µs) | After rerun median / min / max (µs) | Delta_pct |
| --- | --- | --- | --- |
| Compile (`reload_with_rules`) | 1025 / 888 / 1397 | 990 / 852 / 1490 | -3.41% |
| Clean scan | 183 / 171 / 465 | 191 / 164 / 579 | +4.37% |
| Matching scan | 187 / 166 / 256 | 186 / 169 / 271 | -0.53% |
| Reload (fresh `YaraScanner::new`) | 959 / 879 / 1388 | 957 / 853 / 1622 | -0.21% |

Regression disposition: no repeatable >10% regression; all rerun deltas lie
within ±5% host/noise tolerance, with opposite-direction movement on clean
scan (+4.37% vs -3.43%) confirming noise rather than directional regression.
The pass-1 improvements did not reproduce as regressions. Docs-only closure
justified; no runtime corrective required.

Historical context only (explicitly non-comparable; NOT acceptance evidence).
Qualitative comparison to Phase 40 closeout
(`architecture/dependency_security_baseline_phase25.md` §11):

- Phase 40 bundled 14-rule compile: **8.0 ms**.
- Phase 40 clean 64 KiB scan: **0.216 ms** (288.7 MiB/s).
- Phase 40 match-heavy scan: **0.203 ms** (307.5 MiB/s).
- Phase 40 reload: **3.6 ms**.

Different rule corpus and payload size rule out a strict apples-to-apples
comparison. The ballpark proximity below is historical context only and is
not regression proof; acceptance rests on the Phase 104 paired data above.
No source divergence (manifest-only delta under the same fork), so the
Cranelift JIT cost change between wasmtime 47 and wasmtime 48 remains the
dominant expected delta.

## Final qualification ledger

| Command | Result |
|---|---|
| `cargo update -p wasmtime@36.0.15 --precise 36.0.16` | Clean in-line LTS patch update |
| `cargo update -p wasmtime@47.0.4 --precise 48.0.3` | Clean YARA transitive line move |
| `cargo tree -i wasmtime@36.0.16 --workspace` | Resolves via `synvoid-plugin-runtime` + root bench dev-dep |
| `cargo tree -i wasmtime@48.0.3 --workspace` | Resolves via `third-party/yara-x-compat` → `synvoid-yara` |
| `cargo tree -i wasmtime-wasi --workspace` | no match |
| `cargo tree -i wasi-filesystem --workspace` | no match |
| `cargo tree -i rsa@0.9.10 --workspace` | 4 reverse paths; zero decrypt invocations |
| `cargo tree -i rkyv@0.7.46 --workspace` | single chain to `synvoid-static-files` |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --profile ci --all-targets -- -D warnings` | clean |
| `cargo check --no-default-features --profile ci` | clean |
| `cargo deny check` | advisories ok, bans ok, licenses ok, sources ok |
| `cargo audit` | zero vulnerabilities (6 pre-existing unmaintained warnings) |
| `cargo test -p synvoid-yara --profile ci` | 54/54 unit + 8/8 boundary |
| `cargo test -p synvoid-upload --profile ci` | 124/124 |
| `cargo test -p synvoid-jail-runtime --profile ci` | 4/4 + 3/3 |
| `cargo test -p synvoid-plugin-runtime --profile ci` | 351/351 + 7/7 + 6/6 |
| `cargo test -p synvoid-static-files --profile ci` | 23/23 + 16/16 parity |
| `cargo test --test security_regression --profile ci -- --test-threads=1` | 15/15 |
| `cargo test -p synvoid-repo-guards --profile ci` | all pass (including 8 new fork-block unit tests) |
| `cargo xtask verify` | 10/10 steps (458 s) |
| `cargo xtask verify-full` | 10/10 steps (1307 s) |

## Proof-bearing SHAs

- Planning baseline: `d960f473` (2026-10-01, "register Phase 103 dependency
  security maintenance" — the plan + roadmap registration commit).
- Proof-bearing implementation SHA:
  `aeeebc7bac38b1dcc441b06f53c838a74582cd24` (2026-10-01, "wasmtime:
  phase 103 dependency security re-audit and remediation"). This
  commit contains the code changes (manifest pins, Cargo.lock delta,
  fork metadata refresh, time-aware guard refactor, current-authority
  documentation updates, Phase 102 docs cleanup) and was pushed as the
  proof-bearing implementation commit.
- Hosted CI run: `36891196284` on `aeeebc7b…` (`main` push).
  - `ci`: **success** (29 m 13 s).
  - `dependency-security`: **success** (48 s).
  - `icmp-native-qualification`: skipped (not in scope for Phase 103).
  - `sandbox-native-qualification`: skipped (not in scope for Phase 103).
  - URL: https://github.com/dbowm91/synvoid/actions/runs/36891196284
- Closeout commit (this document + plan/roadmap status updates): the
  SHA following this commit on `main`.

## Documentation cleanup (Phase 102 docs cleanup, Phase 103 Workstream H)

- `architecture/eggfetch_0_2_1_patch_adoption_closeout.md`: removed the
  duplicate "Hosted CI / native qualification: not invoked" bullet.
  The single remaining bullet is the canonical statement.
- `plans/roadmap.md`: Phase 64 heading corrected from "Runtime/Performance
  Closed; Phase 64 Docs Correction Active" to "Runtime/Performance/Docs
  Closed". The heading previously implied Phase 64 was still active
  despite the section body and Phase 64 closeout recording it as
  complete/closed.

No historical Phase 102 / Phase 63 evidence was rewritten; no
Phase 63 performance authority was re-adjudicated.

## Future plans / unblocking

No registered SynVoid plan was found blocked on Phase 103. Phase 103
itself is the dependency-security re-audit phase, and the next review
deadline (2026-11-01) is now enforced machine-side via
`effective_review_date()` / `SYNVOID_SECURITY_REVIEW_AS_OF` for both
advisory ignores and temporary-fork metadata.

The next event-driven triggers documented in the baseline §11 remain:

- an official yara-x release that resolves a Wasmtime line ≥ 48.0.3
  patched for all relevant advisories would retire the yara-x
  compat fork (stock 1.21.0 still resolves 45.0.3 as of 2026-10-01);
- an official minify-html release that eliminates the Oxc 0.95 /
  external bumpalo 3.19 path would retire the minify-html compat
  fork (still 0.18.1 as of 2026-10-01);
- a RustSec advisory on rsa 0.9.x or rkyv 0.7.x with a patched
  release would let the corresponding ignore be removed;
- the Wasmtime 36 LTS line approaching end of support (2027-08-20)
  would trigger a future plugin-runtime 36 → 48 LTS move under its
  own validation campaign;
- SynVoid intentionally adding WASI filesystem capability (none
  planned) would force a re-validation against
  `wasmtime_baseline_guard` and §3 of the baseline.

No previously-blocked plan is unblocked by Phase 103; the pre-existing
research disposition ("no independently supported public
`synvoid-http-client` until the current eggfetch line is re-evaluated")
is unchanged. The post-Phase-101 architecture maintenance campaign
remains closed with the recorded residual candidates (mesh-consensus
DEFER, process-manager/IPC DEFER, `synvoid-filter` RETAIN) — these are
not implicitly authorized or unblocked by Phase 103.

Final verdict: **CLOSED QUALIFIED**. The dependency-security contract
is green on the exact-SHA hosted proof, no new advisory ignores are
added, the temporary-fork policy is semantically time-aware, and no
remediation step was skipped.
