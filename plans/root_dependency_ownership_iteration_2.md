# Root Dependency Ownership — Iteration 2 Audit

Audited from `plans/architecture_boundary_cleanup_iteration_2.md`.

| Dependency | Current owner | Root direct? | Root `src/` usage | Reason / next action |
|------------|---------------|--------------|-------------------|----------------------|
| quinn | root + 6 subcrates | yes | `src/dns/doq.rs` (feature-gated), `src/tcp/listener.rs` (single match arm) | Root uses are minimal/near-duplicates; 6 subcrates declare independently. Consider removing root dep if `src/dns/doq.rs` migrates to `synvoid-dns`. |
| h3 | synvoid-http3, synvoid-http | no | none | HTTP/3 implementation owns it. Correctly not root-owned. |
| h3-quinn | synvoid-http3 | no | none | HTTP/3 implementation owns it. Correctly not root-owned. |
| webpki-roots | synvoid-http-client | no | none (typed_pool removed in iteration 5) | Now only used by `crates/synvoid-http-client/src/tls.rs` as native cert fallback. Root no longer depends on it. |
