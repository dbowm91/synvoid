# Same-tree diagnostic runs (NOT immutable revision evidence)

These files are retained for honesty, not authority. They were produced by
manual invocations of the in-tree harness binary (current tree only), NOT
by `scripts/run_comparison.sh` worktree overlays:

- `h1-sequential-300k-*.json`: back-to-back 300 000-request H1 sequential
  runs on each lane (warmup 2000). Both lanes ran in the current tree: the
  "legacy" lane used the frozen compatibility API present in the current
  tree (`revision_sha` is the literal string `prof`, i.e. no revision
  claim). Cited in the Phase 63 evidence record only for the long
  steady-state parity observation (12479 vs 12641 rps, -1.3%).
- `rep*-*.json`: pilot of the `stream-64k-phases` workload, same-tree,
  superseded by the immutable phased session in `../2026-09-22T204937Z/`
  (true `7083f339` vs current worktrees). Retained so the pilot numbers
  quoted during analysis remain inspectable; do not cite them as
  revision evidence.

Adjudication authority rests solely with the `2026-09-22T*` worktree
sessions.
