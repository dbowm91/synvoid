# WAF/Admin Deployment-Truthfulness Roadmap

Status: **PROPOSED**.

Registered in: `plans/roadmap.md`.

Origin: test deployment of the DevLog blog behind SynVoid (blog direct on
`0.0.0.0:5000`, WAF data plane on `0.0.0.0:8082`, IP-based site with no
domain). Three gaps found by running traffic, not by reading code:

1. Browser asset loads (`Referer: http://192.168.x:8082/`) are blocked as
   `Rfi ... at header:referer` (score 100) while `curl` without `Referer`
   returns 200. Root cause is the RFI IP regex matching any IP URL, with no
   same-origin exception.
2. `sites/<name>.toml [attack_detection.rfi] enabled=false` (site and global)
   has no effect — the running WAF is always built from
   `AttackDetectionConfig::default()`. Site attack config parses and validates
   but is never wired into detection.
3. The admin HTTP API (`[admin] port 8081`) never listens — `create_admin_router`
   has no production caller. `architecture/admin_control_plane_authority.md`
   records `NOT MOUNTED IN THE BINARY`.

Phases (in order — 01 unblocks browser testing, 02 makes site policy real,
03 mounts the control plane):

| Phase | File | Status |
|---|---|---|
| 01 | `waf_admin_deployment_truthfulness_phase_01_rfi_referer.md` | **Proposed** — RFI/SSRF Referer same-origin exemption |
| 02 | `waf_admin_deployment_truthfulness_phase_02_site_attack_config_wiring.md` | **Proposed** — wire `SiteAttackDetectionConfig` into WAF dispatch |
| 03 | `waf_admin_deployment_truthfulness_phase_03_admin_mounting.md` | **Proposed** — mount `create_admin_router` in the worker data-plane composition root |

Run 01 first (smallest blast radius, unblocks IP-based browser testing).
02 depends on 01 only for verification cleanliness (Referer traffic must pass
before per-site RFI toggles are observable). 03 is independent of 01–02 but
largest; it may proceed in parallel on a separate branch.

Binding constraints for all three phases:

- Request-path capability boundary (`architecture/request_path_capability_boundary.md`,
  guard `request_path_capability_boundary_guard`): request-path code consumes
  narrow traits only (`BlockListStore`/`WafProcessor`, `ThreatIntelLookup`);
  concrete `ThreatIntelligenceManager`, `BlockStore`, mesh/DHT, supervisor,
  `verify_admin_token`, `crate::admin::handlers` stay in composition roots.
  New capability = narrow trait in `crates/synvoid-waf/src/traits.rs` or
  `synvoid-core`, implemented in a composition root, passed as `Arc<dyn Trait>`.
- Facade dispositions (`architecture/facade_disposition_matrix.md`, guard
  `facade_disposition_guard`): `admin` is `keep_app_root` transport/composition;
  reusable logic goes in `synvoid-admin`, root stays thin adapter. Removed root
  paths stay removed. New crates only if `architecture/root_module_ledger.md`
  says so.
- Admin authority (`architecture/admin_control_plane_authority.md`): mutations
  return typed `AdminMutationResult`, never generic success; quorum loss is
  `QuorumUnavailable`; mesh propagation is best-effort; emit `AdminAuditEvent`;
  never store raw session tokens. Browser = HttpOnly session + CSRF, bearer
  only for session exchange; WebSocket auth per connection at exactly
  `/api/ws/metrics` + `/api/ws/logs`.
- Reduced-feature binaries fail closed (Phase 41): capability-bearing sections
  (`[dns]`, `[mesh]`, `[tunnel.mesh]`, `[icmp_filter]`, even inert
  `enabled = false`) are rejected. Deferred DNS features fail with typed
  `Unsupported`. Do not add new capability sections without the feature gate.
- Historical closeouts corrected by pointer only, never rewritten.
- Every new root `tests/*.rs` file needs a `tests/OWNERSHIP.toml` entry in the
  same commit (`root_test_ownership_guard`); `class = "domain"` rejected —
  single-crate tests belong in the owning crate's `tests/`.

Verification strategy (all phases):

```bash
./target/release/synvoid --configtest --config-path ./config
cargo fmt --all -- --check
cargo clippy --workspace --profile ci --all-targets -- -D warnings
cargo check --no-default-features --profile ci
cargo check --no-default-features --features mesh --profile ci
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features icmp-filter --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
cargo test -p synvoid-waf --profile ci
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci
cargo nextest run --cargo-profile ci --profile ci \
  --test admin_route_contract --test admin_router_composition --test admin_smoke_flow \
  --features mesh,dns,icmp-filter
cargo test --test security_regression --profile ci -- --test-threads=1
cargo xtask verify        # full gate before merge
cargo xtask verify-full   # before risky merges
```

Test-deployment evidence kept out of the repo: the `~/prodtest` blog + WAF
configs that exposed these gaps are operator-local, not committed.
