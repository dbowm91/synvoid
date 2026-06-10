# Root Dependency Ownership — Iteration 2 Audit

Audited from `plans/architecture_boundary_cleanup_iteration_2.md`.

| Dependency | Current owner | Root direct? | Root `src/` usage | Reason / next action |
|------------|---------------|--------------|-------------------|----------------------|
| quinn | root + 6 subcrates | yes | `src/dns/doq.rs` (feature-gated), `src/tcp/listener.rs` (single match arm) | Root uses are minimal/near-duplicates; 6 subcrates declare independently. Consider removing root dep if `src/dns/doq.rs` migrates to `synvoid-dns`. |
| h3 | synvoid-http3, synvoid-http | no | none | HTTP/3 implementation owns it. Correctly not root-owned. |
| h3-quinn | synvoid-http3 | no | none | HTTP/3 implementation owns it. Correctly not root-owned. |
| webpki-roots | root + synvoid-http-client | yes | `src/http_client/typed_pool.rs` — TLS root cert loading (near-duplicate of `synvoid-http-client` version; consider migrating to crate) | Root correctly owns it for `src/http_client/typed_pool.rs`. |
