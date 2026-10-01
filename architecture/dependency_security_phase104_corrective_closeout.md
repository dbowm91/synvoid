# Dependency Security Phase 104 Corrective Closeout: Phase 103 Qualification Evidence

Status: **CLOSED QUALIFIED** (2026-10-01).

Plan: `plans/phase_104_phase103_qualification_evidence_corrective_closeout.md`
(now marked CLOSED QUALIFIED at the top).

Registered in: `plans/roadmap.md` (Phase 104 CLOSED QUALIFIED).

Planning baseline: `136bc2143a849b0941b48c80afcb1add2d90a975` (2026-10-01,
Phase 103 closeout commit).

Owner: security / release.

Predecessor: Phase 103 dependency-security re-audit and Wasmtime remediation,
implementation SHA `aeeebc7bac38b1dcc441b06f53c838a74582cd24`, closeout SHA
`136bc2143a849b0941b48c80afcb1add2d90a975`.

## Goal (recap)

Correct two residual qualification defects without reopening the
dependency-security remediation:

1. replace the non-comparable YARA performance evidence with an actual
   apples-to-apples same-host, same-fixture before/after comparison of the
   Phase 103 Wasmtime 47.0.4 → 48.0.3 change;
2. correct the inaccurate Wasmtime 48 LTS support-date statement in the YARA
   compatibility-fork provenance documentation.

No production dependency or runtime change expected. No material regression
was found, so this phase closes as docs/evidence-only with no runtime
corrective.

## Workstream A — reconstructed exact pre/post YARA benchmark pair

Comparison points (as required by the plan):

- **Before:** Phase 103 planning baseline
  `d960f473aa1ea1b21d2c9e2adc23848addd8de54`, where the YARA fork resolves
  Wasmtime 47.0.4 (direct 36.0.15).
- **After:** Phase 103 proof-bearing implementation
  `aeeebc7bac38b1dcc441b06f53c838a74582cd24`, where the YARA fork resolves
  Wasmtime 48.0.3 (direct 36.0.16).

Do-not-compare rule honored: Phase 40 numbers are not used for regression
acceptance (retained only as explicitly non-comparable historical context in
the corrected Phase 103 closeout).

### Benchmark fixture identity

Temporary probe (removed before commit, same pattern as Phase 103):
`crates/synvoid-yara/tests/yara_phase104_probe_tmp.rs`, byte-identical in
both worktrees (`sha256:3bcb384fe4151c9cd1f663f16c1386afd93d7447a1997009cd44f98d3cc90f10`).

Deterministic fixture, byte-identical between runs:

- 13 YARA rules (`rule_bytes=1850`): 12 non-matching markers
  `SYNVOID_P104_R01_7a1f` … `SYNVOID_P104_R12_6b03` plus one forced-match
  marker `SYNVOID_P104_FORCED_MATCH_9f3c` (30 bytes) in rule `p104_match`.
  Each rule shape:
  `rule p104_XX { meta: description/severity/category strings: $s = "<marker>" condition: $s }`.
- Clean payload: 512 bytes of `0x41` (`A`), 0 matches asserted.
- Matching payload: 512 bytes of `0x41` with the 30-byte forced marker
  spliced at offset 200, exactly 1 match (`p104_match`) asserted.
- Combined fixture identity printed by the harness:
  `P104_FIXTURE sha256=8892c2d7274dd6183b6843203b76c57c02b69f9f89fc5a97e8697c998cf1cc39 rule_bytes=1850 payload_len=512 rules=13 warmup=5`.
  The SHA covers rule text + clean payload + matching payload with domain
  separators, so any fixture drift changes the hash.

Four operations on both SHAs (same code path both sides):

1. compile via `YaraScanner::reload_with_rules(PHASE104_RULES, None)` on a
   live scanner;
2. clean scan via `scanner.scan_bytes(&clean, &[])`;
3. matching scan via `scanner.scan_bytes(&matching, &[])`;
4. reload via fresh `YaraScanner::new(Inline(PHASE104_RULES))` (new
   generation; `get_generation_hash` black-boxed to prevent elision).

### Host / build / iteration methodology

- Host (same for all four runs): Apple M4 Pro, 14 CPUs,
  `Darwin nos-MacBook-Pro.local 25.6.0 Darwin Kernel Version 25.6.0`,
  macOS 26.6.2 (Build 25G83), `rustc 1.98.1 (48a229cea 2026-09-01)`.
- Worktrees: `/tmp/synvoid-p104-before` (detached `d960f473`) and
  `/tmp/synvoid-p104-after` (detached `aeeebc7b`); probe file copied
  byte-identical (`sha256` match verified before runs).
- Build profile: `release` (`lto=true`, `codegen-units=1`, `strip=true`;
  the `ci` profile was used only for a pre-flight logic check on the
  implementation head, not for acceptance numbers).
- Iterations: 5 warm-up discarded + 50 measured per operation (as required).
  Median for even n=50 is the mean of the two middle sorted samples;
  min/max retained. `std::time::Instant` deltas in microseconds.
- Ordering: before-pass-1, after-pass-1, before-pass-2 (rerun),
  after-pass-2 (rerun), sequentially (no parallel load) on the same host.
- Cache/JIT note: `max_us` outliers (e.g. 1597 µs compile, 833 µs matching
  scan) appear on both lines and shrink on rerun; medians are stable. No
  cross-run cache is shared between worktrees (separate `target/release`
  dirs); each binary warms its own JIT/allocator in the 5 discarded
  iterations. The YARA string-rule fixture does not stress the Wasmtime
  Cranelift JIT heavily by itself, but it exercises the landed
  compile/scan/reload path identically on both lines, which is the
  regression question Phase 103 posed.
- Ownership proof: `cargo tree -i wasmtime@47.0.4` resolves only via
  `third-party/yara-x-compat` on the before SHA; `cargo tree -i
  wasmtime@48.0.3` resolves only via the same fork on the after SHA
  (direct 36.0.15 → 36.0.16 moves in lockstep but does not touch the YARA
  path).

## Workstream B — before/after delta and adjudication

`delta_pct = (after_median - before_median) / before_median * 100`.
Raw medians retained so percentages cannot hide small absolute changes.
Negative delta is an improvement (faster after); only repeatable positive
(regression) deltas block docs-only closure.

Pass 1 (primary):

| Operation | Before `d960f473` median / min / max (µs) | After `aeeebc7b` median / min / max (µs) | Delta |
| --- | --- | --- | --- |
| Compile (`reload_with_rules`) | 1050 / 898 / 1597 | 996 / 909 / 1383 | -5.14% = (996-1050)/1050 |
| Clean scan | 204 / 165 / 524 | 197 / 179 / 707 | -3.43% = (197-204)/204 |
| Matching scan | 208 / 165 / 833 | 186 / 178 / 303 | -10.58% = (186-208)/208 |
| Reload (fresh generation) | 1040 / 857 / 1622 | 1021 / 947 / 1399 | -1.83% = (1021-1040)/1040 |

Two pass-1 shifts exceed the ±5% review threshold (compile -5.14%,
matching -10.58%, both improvements). Per the plan, the affected sets were
rerun to determine reproducibility. A repeatable >10% *regression* would
have blocked docs-only closure; improvements still require rerun to rule
out methodology artifact.

Pass 2 (rerun, n=50 each, same fixture/host/profile):

| Operation | Before rerun median / min / max (µs) | After rerun median / min / max (µs) | Delta |
| --- | --- | --- | --- |
| Compile (`reload_with_rules`) | 1025 / 888 / 1397 | 990 / 852 / 1490 | -3.41% = (990-1025)/1025 |
| Clean scan | 183 / 171 / 465 | 191 / 164 / 579 | +4.37% = (191-183)/183 |
| Matching scan | 187 / 166 / 256 | 186 / 169 / 271 | -0.53% = (186-187)/187 |
| Reload (fresh generation) | 959 / 879 / 1388 | 957 / 853 / 1622 | -0.21% = (957-959)/959 |

Run-to-run host noise on the same SHA is itself ~3–10% on medians
(before compile 1050→1025, clean 204→183, matching 208→187, reload
1040→959), confirming the ±5% tolerance is correctly calibrated for this
host. The pass-1 improvements did not reproduce as regressions:

- compile: -5.14% → -3.41% (within tolerance on rerun);
- matching: -10.58% → -0.53% (within tolerance on rerun; the large
  pass-1 improvement was noise, not a methodology break);
- clean flips sign (-3.43% → +4.37%), confirming noise rather than
  directional change;
- reload stays within tolerance on both passes (-1.83%, -0.21%).

No tuning of YARA, Wasmtime, allocator, rule structure, or scan behavior
was performed to make numbers pass. The fixture was fixed before the first
run and never adjusted between passes.

Regression disposition: **no repeatable >10% regression; all rerun deltas
within ±5%. Docs-only closure justified. No separate runtime corrective
required. The corrective trigger (leave Phase 104 open on repeatable >10%
regression) did not fire.**

## Workstream C — Phase 103 closeout performance section corrected

File: `architecture/dependency_security_reaudit_phase103_closeout.md`
(proof-bearing implementation commit `e0032cd1`, see below).

- Replaced the ambiguous “Focused same-host before/after probe” section
  with exact paired data: retained the original single-sided Phase 103
  probe as explicitly NOT acceptance proof, added the Phase 104 pass-1 /
  pass-2 tables with raw medians/min/max and percentage deltas, recorded
  rerun requirement and final disposition.
- Demoted the Phase 40 different-fixture comparison to explicitly labeled
  historical context only (`Historical context only (explicitly
  non-comparable; NOT acceptance evidence)`); the ballpark paragraph no
  longer claims “show no material regression” as acceptance.
- The closeout no longer claims same-fixture before/after evidence without
  both sides recorded; acceptance now references this Phase 104 document.

## Workstream D — Wasmtime 48 LTS provenance corrected

File: `third-party/yara-x-compat/README.SYNVOID.md`
(proof-bearing implementation commit `e0032cd1`).

- Before: `Wasmtime 48.0.3 (48 LTS line, supported for 24 months from 2026-06-04, ...)`.
- After: `Wasmtime 48.0.3 (48 LTS line, released 2026-08-20 and supported for 24 months, ...)`.
- Grounding (verified at implementation time):
  - Upstream release policy (`https://docs.wasmtime.dev/stability-release.html`):
    majors divisible by 12 are LTS releases supported for 24 months;
    releases ship on the 20th of the month.
  - Wasmtime 48.0.0 release record: Released 2026-08-20
    (`bytecodealliance/wasmtime` releases; RFC LTS gantt shows
    `48.0.0 : 2026-08-20, 720d`).
  - The erroneous `2026-06-04` is not a Wasmtime release date (releases
    fall on the 20th) and does not match the 48 line; `2026-06-20` would be
    the 46.0.0 normal release window, not 48 LTS.
  - No authoritative upstream EOL table entry for the 48 line beyond the
    24-month policy was found at implementation time, so no arithmetic EOL
    date is invented; the correction uses the plan’s minimum acceptable
    wording (release date + policy duration).
- Repository search for `2026-06-04`: only the README (fixed), the Phase 104
  plan defect description (historical record of what was wrong, retained),
  and the roadmap defect summary (retained as scope history, updated to
  CLOSED below). No other current-authority statement about Wasmtime 48
  support carries the wrong date. Phase 103 plan §“Wasmtime 48 is an LTS
  line (major divisible by 12, supported for 24 months)” has no date and
  needed no change. Historical Phase 40 / baseline §11 47.0.4 text is left
  as the record of its own release event per the do-not-rewrite rule.

## Workstream E — Phase 103 security state preserved

Expected unchanged graph confirmed on the implementation head
(`e0032cd1`; `git diff --name-only` shows only the two docs files above,
no `Cargo.toml`/`Cargo.lock` change):

- direct Wasmtime: `36.0.16` (`cargo tree -i wasmtime@36.0.16` resolves via
  `synvoid-plugin-runtime` + root bench dev-dep);
- YARA Wasmtime: `48.0.3` (`cargo tree -i wasmtime@48.0.3` resolves via
  `third-party/yara-x-compat` → `synvoid-yara`);
- YARA source base: official `yara-x 1.20.0`, manifest-only SynVoid delta
  (`src/`/`build.rs` byte-identical; verified by the fork’s documented
  `diff -r` contract, unchanged by this phase);
- `wasmtime-wasi`: absent (`cargo tree -i wasmtime-wasi` → no match);
- `wasi-filesystem`: absent (`cargo tree -i wasi-filesystem` → no match);
- no git source (`git+` absent from `Cargo.lock`; `[patch.crates-io]`
  holds only the two temporary fork entries);
- no advisory ignore for RUSTSEC-2026-0315 or RUSTSEC-2026-0316
  (`cargo deny check` + `cargo audit` green without them);
- retained RSA/rkyv exceptions unchanged (Reviewed 2026-10-01, Re-audit
  2026-11-01; `cargo audit` reports zero vulnerabilities, 6 pre-existing
  unmaintained warnings);
- temporary-fork review deadline remains 2026-11-01 (time-aware guards
  unchanged; no guard source touched).

Any `Cargo.toml`/`Cargo.lock` dependency change would have been unexpected;
none occurred.

## Workstream F — verification

Focused set on the implementation head (docs-only change, so identical
expectations to Phase 103 green):

| Command | Result |
|---|---|
| `cargo test -p synvoid-yara --profile ci` | 54/54 unit + 8/8 boundary pass |
| `cargo test -p synvoid-repo-guards --profile ci` | all pass |
| `cargo tree -i wasmtime@36.0.16 --workspace` | resolves via `synvoid-plugin-runtime` + root bench dev-dep |
| `cargo tree -i wasmtime@48.0.3 --workspace` | resolves via `third-party/yara-x-compat` → `synvoid-yara` |
| `cargo tree -i wasmtime-wasi --workspace` | no match |
| `cargo tree -i wasi-filesystem --workspace` | no match |
| `cargo deny check` | advisories ok, bans ok, licenses ok, sources ok |
| `cargo audit` | zero vulnerabilities (6 pre-existing unmaintained warnings) |
| `cargo fmt --all -- --check` | clean |
| `cargo xtask verify` | 10/10 steps pass (1204.5 s on Apple M4 Pro: fmt, clippy 306.9 s, dependency-policy, core-compile, repo-guards, security-regression 538.3 s, root-guards, core-admin-tests, admin-contract 251.1 s, failure-injection) |

Temporary harness removed before commit: the `yara_phase104_probe_tmp.rs`
file existed only in `/tmp/synvoid-p104-before` and
`/tmp/synvoid-p104-after` worktrees, never in the main-repo commit. No
permanent test-surface growth.

## Proof-bearing SHAs and hosted proof

- Planning baseline: `136bc2143a849b0941b48c80afcb1add2d90a975`.
- Benchmark before SHA: `d960f473aa1ea1b21d2c9e2adc23848addd8de54`
  (Wasmtime 47.0.4).
- Benchmark after SHA: `aeeebc7bac38b1dcc441b06f53c838a74582cd24`
  (Wasmtime 48.0.3).
- Proof-bearing corrective (implementation) SHA:
  `e0032cd176cd1061a3aa5877555f49ebc4f46a3b` (2026-10-01, “phase 104:
  correct Phase 103 perf evidence and Wasmtime 48 LTS provenance”). Contains
  the two docs corrections (Workstreams C/D); no dependency change.
- Hosted CI run: `36901352762` on `e0032cd1…` (`main` push).
  - `ci`: **success**.
  - `dependency-security`: **success**.
  - `icmp-native-qualification` / `sandbox-native-qualification`: skipped
    (out of scope for Phase 104; docs/evidence-only).
  - URL: https://github.com/dbowm91/synvoid/actions/runs/36901352762
- Closeout commit (this document + plan/roadmap status updates): the SHA
  following this commit on `main`.

## Future plans / unblocking

No registered SynVoid plan was found blocked on Phase 104. Phase 104 itself
owns only the two residual qualification defects above; the underlying
Phase 103 security remediation remains the accepted production state.

The next event-driven triggers remain those recorded in the Phase 103
closeout (unchanged by this corrective):

- an official yara-x release resolving a Wasmtime line ≥ 48.0.3 patched for
  all relevant advisories would retire the yara-x compat fork;
- an official minify-html release eliminating the Oxc 0.95 / external
  bumpalo path would retire the minify-html compat fork;
- a RustSec advisory on rsa 0.9.x or rkyv 0.7.x with a patched release
  would let the corresponding ignore be removed;
- the Wasmtime 36 LTS line approaching end of support (2027-08-20) would
  trigger a future plugin-runtime 36 → 48 LTS move under its own campaign;
- SynVoid intentionally adding WASI filesystem capability (none planned)
  would force re-validation.

No previously-blocked plan is unblocked by Phase 104; the pre-existing
research disposition (“no independently supported public
`synvoid-http-client` until the current eggfetch line is re-evaluated”) is
unchanged. The post-Phase-101 residual candidates (mesh-consensus DEFER,
process-manager/IPC DEFER, `synvoid-filter` RETAIN) are not implicitly
authorized or unblocked by Phase 104.

Final verdict: **CLOSED QUALIFIED**. The paired same-fixture evidence shows
no repeatable regression across the Wasmtime 47.0.4 → 48.0.3 transition,
the Wasmtime 48 LTS provenance is corrected to the authoritative
release/support timeline, the dependency graph is unchanged, focused and
full verification pass, and exact-SHA hosted proof is green.
