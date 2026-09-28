# Eggbench Security Qualification Asset Contract — Closeout

Final disposition: **CLOSED** (2026-09-28). The SynVoid-owned qualification
asset contract for the `eggstack/eggbench` Security Qualification M002
consumer is implemented, self-tested, config-tested, and live-proven
against the real minimal binary. No registered SynVoid future plan was
blocked on this handoff; its only downstream is the external Eggbench
M002 full closure.

Plan: `plans/eggbench_security_qualification_asset_contract.md`.
Roadmap registration: `plans/roadmap.md` ("Independent Cross-Repo Handoff"
section, now marked closed).

- Planning baseline: `49b4624b696b4c3aa0172b0326a04ae9e275ca3f`.
- Implementation re-audit baseline: `fb2acbc1c918f8706fc7c65676efe5b275995bfe`.
- Implementation SHA: `ae045481752b8f750d6e6079b185c526a09c91d5`
  (executable code + fixtures + tests; this closeout, roadmap, and plan
  status in the follow-up commit — same convention as Phase 80).
- Package version: `1.1.0`.
- Cargo.lock SHA-256 prefix: `426c6124dc450b9e54b16d3698f36911`
  (only delta: `sha2`/`hex`/`toml` for xtask — all already in the
  workspace graph, no new supply-chain surface; `cargo deny check` clean
  inside `cargo xtask verify`).

## 1. Qualification policy v1 (Workstream policy)

Identifier: `synvoid.eggbench-qualification.v1` (immutable; any semantic
mapping change requires a new identifier).

- Source `detect` → live HTTP block status **403** (the canonical SynVoid
  block response for `attack_detection.action = "block"`:
  `WafDecision::Block(403, …)`; verified, not invented — no data-plane
  code was patched to force it).
- Source `pass` → controlled origin success **200**.
- Observable surface is HTTP status only. Challenge, stall, tarpit, drop,
  log-only, reason codes, threat-level escalation, rate limiting, bot
  controls, and distributed-state semantics are out of v1 scope.
- Checked-in policy document:
  `crates/synvoid-waf/tests/fixtures/eggbench_qualification/policy_v1.json`
  (includes `transport_rules` and `perf_paths`, see §§5–6).

## 2. Export allowlist + exclusion manifest (Workstream A)

- Allowlist: `crates/synvoid-waf/tests/fixtures/eggbench_qualification/v1_allowlist.json`
  — **15 cases**: 5 benign/pass controls (`benign_json_body`,
  `benign_overlong_unicode`, `benign_percent_encoded_unicode`,
  `benign_query_strings`, `benign_url_encoding`); 10 attack-detection
  cases across SQLi (`query_string_proxy_path`, `sqli_invalid_utf8`),
  XSS (`xss_invalid_utf8`, `xss_mixed_overlong_canonical`,
  `xss_percent_encoded`), path traversal (`path_traversal_literal`), and
  SSRF (`ssrf_decimal_private_ip`, `ssrf_encoded_private_ip`,
  `ssrf_localhost_variations`, `ssrf_octal_private_ip`). Stable fixture
  IDs preserved; attack family kept as opaque provenance.
- Exclusion manifest: `…/v1_exclusions.json` — **12 cases** with
  checked-in reasons (request-smuggling/hop-by-hop ×3, credential-bearing
  headers/body ×3, binary/multipart bodies ×3, serverless bypass probe
  ×1, proxy/forwarding headers ×2).
- Completeness: 15 + 12 = 27 = every fixture under
  `crates/synvoid-waf/tests/fixtures/waf/requests/`. No fixture can
  silently disappear (unit-tested both directions).

## 3. Asset materializer (Workstream B)

`cargo xtask eggbench-qualification` (`tools/xtask/src/eggbench_qualification.rs`,
dispatched from `tools/xtask/src/main.rs`):

- `export --output <dir> --listen-port <p> --origin-port <p> [--configtest [--configtest-binary <path>]]`
- `check --input <dir> [--configtest [--configtest-binary <path>]]`
- Deterministic for identical source tree + fixture set + ports + policy
  (canonical-JSON serialization, id-sorted iteration). No network, no
  spawned processes except opt-in `--configtest`. Parses SynVoid's own
  fixture format (both header encodings); no Eggbench code imported.

## 4. Loopback-only minimal runtime config (Workstream C)

Generated tree (`<output>/config/{main.toml,sites/loopback.qualification.local.toml}`):

- Data plane binds `127.0.0.1:<listen-port>` only; upstream is exactly
  `http://127.0.0.1:<origin-port>`; attack detection enabled with
  `action = "block"`; TLS/HTTP-3/admin/metrics off; rate limiting
  neutralized via `isolated` + saturating limits (`disabled` is not an
  accepted mode); honeypot/tarpit/challenges/suspicious-words/upload/
  serverless/app-server off; persistence/logging/state inside the
  generated directory; no `[dns]`/`[mesh]`/`[tunnel.mesh]`/`[icmp_filter]`
  sections (fail-closed preflight clean); no credentials.
- Site accepts the natural loopback Host (`127.0.0.1`,
  `127.0.0.1:<listen-port>`, `localhost…`) plus a `[[site.listen]]`
  default-server entry — no forbidden Host override required.
- Site whitelist is empty (whitelisted loopback IPs would bypass all WAF
  checks and mask Detect cases — caught during implementation).
- `--configtest` passes on the minimal binary:
  `cargo build --locked --release --no-default-features` →
  `synvoid --configtest --config-path <generated-config>` →
  "All configuration files are valid" (exit 0).

## 5. Corpus export (Workstream D)

`<output>/corpus.json`, schema
`eggbench.security_qualification.corpus.v1`: 15 cases, deterministic
order, `id` = stable fixture ID, `category` = opaque attack-family
label, no absolute URLs, no Host/proxy/hop-by-hop/credential/cookie/
authorization headers (forbidden set enforced by construction and by
test), inline UTF-8 bodies only. Digest (ports 18181/18282):
`edddaba98557ec265766d3483c33f01a71cce4392e81f5a6409968346a371eca`.

## 6. Provenance manifest (Workstream E)

`<output>/provenance.json`, schema
`eggbench.security_qualification.provenance.v1`: schema/policy/package
versions, exact git SHA, per-fixture relative paths + SHA-256 (15),
verbatim exclusion list (12), config/corpus/site SHA-256 digests,
ports, block/pass statuses, materializer version. `check` re-hashes
every artifact and fails closed on any mismatch. No environment or
secrets included.

## 7. Self-qualification (Workstream F)

15 unit tests in the materializer (`cargo test -p xtask`): allowlist/
exclusion/policy load + id binding, no allow/exclude overlap, every
allowlisted fixture exists + parses, every excluded fixture exists
(anti-drift), byte-determinism, header-contract satisfaction, unique
IDs, exhaustive detect/pass mapping, provenance sensitivity to fixture
change, loopback binding + exact ports + empty whitelist + block action,
excluded-fixture absence, end-to-end export→check coherence. All green.

## 8. Live local semantic proof (Workstream G) — MANDATORY, DONE

`tests/eggbench_qualification_live_proof.rs` (ignored, opt-in via
`SYNVOID_EGGBENCH_LIVE_PROOF=1`; OWNERSHIP.toml `qualification` entry;
never a routine-CI gate). It materializes via the owner `export`,
configtests, spawns the real minimal binary `--foreground`, drives all
15 cases over raw HTTP/1.1 against a controlled loopback origin, and
asserts status agreement + origin reachability per case, plus the two
perf paths.

Result against pinned minimal binary
(`target/debug/synvoid`, SHA-256
`d4d4cc17cb7f48770bb21473c5aacec227a44852631daf729e25989d651fb3d1`,
built `cargo build --locked --no-default-features`):
**15/15 corpus cases agree** (5 pass → 200 + origin hit; 10 detect →
403 + zero origin hits) and **2/2 perf paths proxy clean** (manual
17/17 probe corroborates; `SYNVOID_EGGBENCH_LIVE_PROOF=1 cargo test
--locked --no-default-features --profile ci --test
eggbench_qualification_live_proof -- --ignored` → ok).

Transport findings (contract, not weakenings — recorded in
`policy_v1.json` `transport_rules`):

- The driver must send a neutral User-Agent. SynVoid's UA bot stage
  (`isbot`) has no config kill-switch and 403s known-bot UAs (e.g.
  `curl/*`) independent of site bot settings. Proof UA:
  `synvoid-eggbench-qualification/1.0`.
- ASCII SP in a request-target must be `%20`-encoded on the wire (raw SP
  is illegal HTTP); the normalizer decodes before detection
  (`query_string_proxy_path` → 403 confirmed).

## 9. Performance fixture support (Workstream H)

No SynVoid load generator added (per rejection criteria). The site
template pins `[site.upstream.routes]` for `/qualbench/small` (small
response) and `/qualbench/stream` (64 KiB streaming response) at the
bare origin (route targets carry no path suffix — the proxy appends the
full request path, and a suffixed target duplicated it during
implementation). Both paths are exercised through the proxy in the live
proof (200 + origin hit). Eggbench owns load generation; the origin
path contract is documented here and in `policy_v1.json` `perf_paths`.

## 10. Production-path repairs (no WAF semantic change)

The live proof exposed three harness-blocking defects; all are narrow
runtime-truthfulness repairs, none touch detection semantics
(`cargo test -p synvoid-waf` green: 197 + 17 + 12 + 103):

1. `crates/synvoid-ipc/src/manager.rs` — `blocking_send` → `try_send`
   on six runtime-reachable event sends. The supervisor panicked on
   EVERY foreground spawn (`record_spawn` runs on Tokio runtime
   threads). Telemetry-only; matches the file's existing `try_send`
   pattern.
2. `src/http/server.rs` + `src/server/mod.rs` — the minimal profile
   never served HTTP: `serve()` was mesh-gated and
   `run_http_server_inner` dropped the server under
   `#[cfg(not(feature = "mesh"))]` (stub dates to May 2026 core-profile
   compile fixes). Ungated; the accept loop carries no mesh dependency.
   This restores the documented "supported minimal WAF/proxy
   data-plane build" contract.
3. `crates/synvoid-platform/src/socket_bind.rs` — `bind_tcp_reuse` /
   `bind_udp_reuse` now return nonblocking sockets. Every production
   caller feeds them to `tokio::from_std`, which panics on blocking
   sockets; the worker died on first listen. Contract documented on the
   functions; regression tests added
   (`test_socket_reuse_bind_{tcp,udp}_is_tokio_compatible`).

## 11. Routine verification

- `cargo fmt --all -- --check` clean.
- `cargo test -p synvoid-waf --profile ci` green (incl. 17/17 corpus).
- `cargo test -p xtask --profile ci` green (34/34, incl. 15 new).
- `cargo test -p synvoid-platform --test socket_handoff_test` green.
- `cargo xtask test guards` green (3/3 steps).
- `cargo xtask verify` green (**10/10 steps**).
- `cargo build --locked --release --no-default-features` green;
  release minimal binary SHA-256:
  `153869ecfd2c111e361f9b1232ae7820b0acc174559cd1e3f9ecce4a61d0ec2a`.
- Clippy `--all-targets`: no warnings in touched files (remaining
  warnings are pre-existing third-party compat forks).

## 12. Acceptance / rejection checklist

Accepted: policy v1 exists; stable allowlist checked in; exclusions
explicit (12/12 with reasons); deterministic materializer exists;
loopback-only minimal config generated + config-tested on the minimal
release binary; Eggbench-v1 corpus generated with no Eggbench import;
provenance binds fixtures + git SHA + config + corpus + mapping; live
proof shows Pass/Detect agreement on the wire; minimal profile serves;
routine verification green; no production WAF semantic weakened
(detection suites unchanged-green; repairs are supervisor/listener
plumbing + documented contract restorations).

Rejected (none present): no full-corpus copy, no smuggling export, no
public bind, no unrelated controls enabled, no Eggbench dependency, no
unit-result-as-proof (live proof mandatory and done), no load
generator, no secrets in assets.

## 13. Residuals / unresolved findings

1. Threat-level SQLite (`/var/lib/synvoid/threat_level/history.db`) and
   the port-honeypot DB (`/var/lib/synvoid/honeypot.db`) use hardcoded
   absolute paths outside the generated directory. Both fail closed to
   in-memory operation under the qualification config (observed in
   worker logs; behavior stays deterministic for the qual window), but a
   future config-plumbing pass should route them through
   `defaults.persistence.data_dir`. Not blocking: no state escapes and
   no failure occurs.
2. `[tokio] worker_threads = "auto"` (table form) is rejected by
   `TokioConfig`'s scalar-oriented custom deserializer — the shipped
   `config/main.toml` trips the same error on any binary. The
   materializer omits `[tokio]` (defaults apply). Pre-existing config
   bug, recorded here, not opened as a plan (operator configs in the
   wild presumably already avoid the table form or hit the same error).
3. `defaults.ratelimit.mode = "disabled"` is not an accepted value
   (validator requires shared|isolated); the materializer uses
   `isolated` + saturating limits. Same class of note as (2).
4. Honeypot endpoints file / error-pages directory fall back to
   built-ins with warnings when absent — fine for qualification.
5. Eggbench-side remainders (out of SynVoid scope): neutral-UA driver
   discipline per §8 transport rules; origin implementation of
   `/qualbench/small` + `/qualbench/stream`; M002 receipt aggregation.

## 14. Future-plan impact

No registered SynVoid future plan was blocked on this handoff (verified
by repository search: only the plan, the roadmap section, and this
closeout reference eggbench). Its sole downstream is the external
`eggstack/eggbench` M002 full closure, which this contract unblocks.
No roadmap status besides the handoff section itself required an
update.
