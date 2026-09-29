# Phase 98 — HTTP/3 Ownership Realignment Closeout

Status: implemented and closed 2026-09-28.

## Result

All HTTP/3 request and stream state-machine modules now live in
`crates/synvoid-http3/`. The protocol-neutral HTTP crate retains shared
parsing, headers, WAF body/scanner helpers, response policy, and the generic
connection-token guard. The thin per-site HTTP/3 connection-limit adapter now
lives beside H3 route dispatch. `synvoid-http` no longer depends on `h3` and
does not depend on `synvoid-http3`; the dependency remains one-way from H3 to
shared HTTP helpers. Root WAF composition implements the moved narrow H3 WAF
trait without changing the runtime server boundary.

H1 EggServe and H2 Hyper ownership were not moved. The moved modules continue
to cover buffered and streaming upstreams, body scanning, routing, terminal
responses, and H3 WAF decision mapping.

## Verification

- `cargo test -p synvoid-http --profile ci` — passed (131 tests).
- `cargo test -p synvoid-http3 --profile ci` — passed (11 tests).
- `cargo test --test http_transport_neutrality_guard --profile ci` — passed (8 tests).
- `cargo test --test boundary_composition_guard --profile ci` — passed (55 tests).
- `cargo test --test http_normalization_ownership_guard --profile ci` — passed (5 tests).
- `cargo test --test http_differential_closure --profile ci` — passed (7 tests).
- `cargo check --no-default-features --profile ci` — passed.
- `cargo check --no-default-features --features mesh --profile ci` — passed.
- `cargo check --no-default-features --features dns --profile ci` — passed.
- `cargo check --no-default-features --features mesh,dns --profile ci` — passed.
- `cargo fmt --all -- --check` and `cargo metadata --no-deps --format-version 1` — passed.
- `cargo xtask verify` — passed all 10 steps on the corrected tree (2026-09-28).

The plan references `http3_waf_boundary_guard`, which is not a registered
test target in this workspace. Its active equivalent coverage is provided by
the boundary-composition, transport-neutrality, and HTTP differential guards
listed above. Exact-SHA hosted CI and dependency-security qualification remain
part of campaign Phase 101.

## Next phase

Phase 99 is unblocked: Phases 96–98 are implemented and their focused boundary
verification passed. Phase 100 remains ordered after Phase 99. Phase 101 remains
the final campaign qualification and requires all implementation phases plus
exact-SHA hosted CI and dependency-security evidence.
