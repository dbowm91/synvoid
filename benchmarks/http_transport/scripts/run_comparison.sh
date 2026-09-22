#!/usr/bin/env bash
# Phase 63 immutable-revision transport comparison (manual-only, never CI).
#
# Overlays the committed harness onto detached worktrees of the immutable
# legacy revision and the current proof-bearing revision, builds each
# independently, and runs the same workload matrix with ABBA lane ordering.
#
# Usage:
#   scripts/run_comparison.sh [--legacy-rev SHA] [--current-rev REV]
#     [--reps N] [--profile ci|release] [--out DIR] [--keep-worktrees] [--smoke]
#
# Requirements: clean working tree, network for first-time dep fetch.
set -u
# (no `set -e`: failures are recorded per-run, then the script exits nonzero.)

LEGACY_REV="7083f339a43dd13d6c8f65e7acc9d03ee555b6ef"
CURRENT_REV="HEAD"
REPS=5
PROFILE="ci"
OUT=""
KEEP=0
SMOKE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --legacy-rev) LEGACY_REV="$2"; shift 2 ;;
    --current-rev) CURRENT_REV="$2"; shift 2 ;;
    --reps) REPS="$2"; shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --keep-worktrees) KEEP=1; shift ;;
    --smoke) SMOKE=1; shift ;;
    *) echo "unknown arg $1" >&2; exit 2 ;;
  esac
done

TOP="$(git rev-parse --show-toplevel)"
HARNESS_SRC="$TOP/benchmarks/http_transport"
[ -d "$HARNESS_SRC/src" ] || { echo "harness not found at $HARNESS_SRC" >&2; exit 2; }

# 1. Refuse a dirty production tree: overlay fidelity requires a clean HEAD.
if [ -n "$(git -C "$TOP" status --porcelain)" ]; then
  echo "refusing: working tree is dirty (commit or stash first)" >&2
  exit 2
fi

# Validate the requested revisions before building anything.
LEGACY_SHA="$(git -C "$TOP" rev-parse --verify "$LEGACY_REV^{commit}")" \
  || { echo "bad legacy rev $LEGACY_REV" >&2; exit 2; }
CURRENT_SHA="$(git -C "$TOP" rev-parse --verify "$CURRENT_REV^{commit}")" \
  || { echo "bad current rev $CURRENT_REV" >&2; exit 2; }
echo "legacy  : $LEGACY_SHA"
echo "current : $CURRENT_SHA"

STAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"
[ -n "$OUT" ] || OUT="$HARNESS_SRC/results/$STAMP"
mkdir -p "$OUT"

# Provenance inputs. The committed Cargo.lock is overlaid verbatim, so both
# revisions build against identical transitive dependency versions.
HARNESS_SHA="$(cd "$TOP" && find benchmarks/http_transport/Cargo.toml benchmarks/http_transport/Cargo.lock benchmarks/http_transport/src benchmarks/http_transport/adapters -type f | sort | xargs shasum -a 256 | shasum -a 256 | cut -d' ' -f1)"
LEGACY_ADAPTER_SHA="$(shasum -a 256 "$HARNESS_SRC/adapters/legacy_7083f339.rs" | cut -d' ' -f1)"
EGGFETCH_ADAPTER_SHA="$(shasum -a 256 "$HARNESS_SRC/adapters/eggfetch_current.rs" | cut -d' ' -f1)"
TOOLCHAIN="$(rustc -V)"
HOST="$(uname -smr) $(sysctl -n machdep.cpu.brand_string 2>/dev/null || cat /proc/cpuinfo 2>/dev/null | grep -m1 'model name' | cut -d: -f2)"
TARGET="$(rustc -vV | grep host | cut -d' ' -f2)"

WT_BASE="$(mktemp -d "${TMPDIR:-/tmp}/phase63-wt.XXXXXX")"
cleanup() {
  if [ "$KEEP" -eq 1 ]; then
    echo "keeping worktrees in $WT_BASE"
    return
  fi
  git -C "$TOP" worktree remove --force "$WT_BASE/legacy" 2>/dev/null || true
  git -C "$TOP" worktree remove --force "$WT_BASE/current" 2>/dev/null || true
  rm -rf "$WT_BASE"
}
trap cleanup EXIT

echo "creating worktrees in $WT_BASE"
git -C "$TOP" worktree add --detach "$WT_BASE/legacy" "$LEGACY_SHA" --quiet \
  || { echo "legacy worktree failed" >&2; exit 2; }
git -C "$TOP" worktree add --detach "$WT_BASE/current" "$CURRENT_SHA" --quiet \
  || { echo "current worktree failed" >&2; exit 2; }

# 3. Overlay ONLY the committed benchmark files. Production source in the
# old worktree stays immutable; no production patch is applied anywhere.
for wt in legacy current; do
  mkdir -p "$WT_BASE/$wt/benchmarks/http_transport"
  cp "$HARNESS_SRC/Cargo.toml" "$HARNESS_SRC/Cargo.lock" "$WT_BASE/$wt/benchmarks/http_transport/"
  cp -r "$HARNESS_SRC/src" "$WT_BASE/$wt/benchmarks/http_transport/"
  cp -r "$HARNESS_SRC/adapters" "$WT_BASE/$wt/benchmarks/http_transport/"
  cp -r "$HARNESS_SRC/certs" "$WT_BASE/$wt/benchmarks/http_transport/"
done

# 5. Build each revision independently.
echo "building legacy harness (no eggfetch feature)..."
if ! cargo build --profile "$PROFILE" --no-default-features \
    --manifest-path "$WT_BASE/legacy/benchmarks/http_transport/Cargo.toml" 2>&1 | tail -3; then
  echo "LEGACY BUILD FAILED" >&2; exit 2
fi
echo "building current harness..."
if ! cargo build --profile "$PROFILE" \
    --manifest-path "$WT_BASE/current/benchmarks/http_transport/Cargo.toml" 2>&1 | tail -3; then
  echo "CURRENT BUILD FAILED" >&2; exit 2
fi

LEGACY_BIN="$WT_BASE/legacy/benchmarks/http_transport/target/$PROFILE/http-transport-bench"
CURRENT_BIN="$WT_BASE/current/benchmarks/http_transport/target/$PROFILE/http-transport-bench"
# Cargo names the profile dir `debug` for dev-inherited profiles like `ci`.
[ -x "$LEGACY_BIN" ] || LEGACY_BIN="$WT_BASE/legacy/benchmarks/http_transport/target/debug/http-transport-bench"
[ -x "$CURRENT_BIN" ] || CURRENT_BIN="$WT_BASE/current/benchmarks/http_transport/target/debug/http-transport-bench"

WORKLOADS="h1-sequential h1-concurrent h2-multiplexed stream-1k stream-64k stream-1m stream-concurrent stream-slow-producer early-drop cold-construct"

# Portable per-run watchdog (macOS bash 3.2 has no `timeout` builtin).
run_guarded() {
  local limit="$1"; shift
  "$@" &
  local pid=$!
  ( sleep "$limit" && kill -9 "$pid" 2>/dev/null ) &
  local watcher=$!
  wait "$pid"
  local rc=$?
  kill "$watcher" 2>/dev/null || true
  return $rc
}

FAIL=0
RUNLOG="$OUT/commands.log"
: > "$RUNLOG"

rep=1
while [ "$rep" -le "$REPS" ]; do
  # ABBA alternation: odd reps run legacy-first, even reps eggfetch-first.
  if [ $((rep % 2)) -eq 1 ]; then ORDER="legacy eggfetch"; else ORDER="eggfetch legacy"; fi
  for w in $WORKLOADS; do
    for lane in $ORDER; do
      if [ "$lane" = "legacy" ]; then
        BIN="$LEGACY_BIN"; REV="$LEGACY_SHA"; ADSHA="$LEGACY_ADAPTER_SHA"
        CERTS="$WT_BASE/legacy/benchmarks/http_transport/certs"
      else
        BIN="$CURRENT_BIN"; REV="$CURRENT_SHA"; ADSHA="$EGGFETCH_ADAPTER_SHA"
        CERTS="$WT_BASE/current/benchmarks/http_transport/certs"
      fi
      out="$OUT/rep${rep}-${w}-${lane}.json"
      # Smoke mode shrinks every workload for pipeline testing only
      # (never adjudication evidence).
      EXTRA=""
      if [ "$SMOKE" -eq 1 ]; then
        case "$w" in
          h1-sequential) EXTRA="--requests 2000 --concurrency 1 --warmup 200" ;;
          h1-concurrent) EXTRA="--requests 8000 --concurrency 8 --warmup 500" ;;
          h2-multiplexed) EXTRA="--requests 4000 --concurrency 8 --warmup 300" ;;
          stream-1m) EXTRA="--requests 10 --warmup 2" ;;
          stream-64k|stream-concurrent) EXTRA="--requests 20 --warmup 5" ;;
          *) EXTRA="--requests 10 --warmup 2" ;;
        esac
      fi
      # shellcheck disable=SC2086
      BENCH_REVISION_SHA="$REV" BENCH_HARNESS_SHA="$HARNESS_SHA" \
      BENCH_ADAPTER_SHA="$ADSHA" BENCH_TOOLCHAIN="$TOOLCHAIN" \
      BENCH_HOST="$HOST" BENCH_PROFILE="$PROFILE" BENCH_TARGET="$TARGET" \
      run_guarded 1200 "$BIN" --lane "$lane" --workload "$w" \
        --certs "$CERTS" --out "$out" $EXTRA
      rc=$?
      echo "rep=$rep workload=$w lane=$lane rev=$REV rc=$rc out=$out" | tee -a "$RUNLOG"
      echo "  cmd: BENCH_REVISION_SHA=$REV ... $BIN --lane $lane --workload $w --certs $CERTS --out $out $EXTRA" >> "$RUNLOG"
      [ $rc -eq 0 ] || FAIL=1
    done
  done
  rep=$((rep + 1))
done

# Aggregate.
"$CURRENT_BIN" summarize "$OUT"/rep*-*.json --out "$OUT/summary.md"
rc=$?
[ $rc -eq 0 ] || FAIL=1

cat > "$OUT/RUN.md" <<EOF
# Run metadata

- date (UTC): $STAMP
- legacy revision: $LEGACY_SHA
- current revision: $CURRENT_SHA
- harness SHA: $HARNESS_SHA
- legacy adapter SHA-256: $LEGACY_ADAPTER_SHA
- eggfetch adapter SHA-256: $EGGFETCH_ADAPTER_SHA
- toolchain: $TOOLCHAIN
- host: $HOST
- target: $TARGET
- build profile: $PROFILE
- reps: $REPS (ABBA lane alternation per workload)
- smoke: $SMOKE
- per-run command lines: commands.log
- aggregated: summary.md
EOF

echo "results in $OUT (failures: $FAIL)"
exit $FAIL
