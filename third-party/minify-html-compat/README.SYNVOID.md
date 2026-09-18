# SynVoid temporary `minify-html` compatibility fork

Base: official `minify-html 0.18.1` (crates.io; upstream tag `v0.18.1` at
https://github.com/wilsonzlin/minify-html).

Vendored: 2026-09-18 by copying the exact released crate source
(`src/`, `README.md`, `LICENSE`) into this directory. The vendored
`Cargo.lock` and `.cargo-checksum.json` were removed; `Cargo.toml` was
rewritten from the normalized registry manifest with full provenance in its
header comment.

## Delta from upstream 0.18.1 (complete)

Manifest-only. No file under `src/` is modified:

```diff
-oxc_allocator = "0.95"
-oxc_codegen = "0.95"
-oxc_minifier = "0.95"
-oxc_parser = "0.95"
-oxc_span = "0.95"
+oxc_allocator = "0.111"
+oxc_codegen = "0.111"
+oxc_minifier = "0.111"
+oxc_parser = "0.111"
+oxc_span = "0.111"
```

Verification that no source adaptation was needed: the only Oxc consumers in
this crate are the imports and calls in `src/minify/js.rs`
(`Allocator::default`, `Parser::new(..).parse()`, `Minifier::new(..).minify`,
`Codegen::new().with_options(..).build(..)`, `SourceType::mjs()/default()`,
`CompressOptions::safest()`, `MangleOptions::default()`). That exact call
shape compiles unchanged against Oxc 0.111 (proven in an isolated scratch
crate during Phase 39 implementation).

## Why 0.111

- First researched Oxc line whose `oxc_allocator` has no external `bumpalo`
  dependency (proven from the crates.io dependency API during Phase 39).
- Upstream minify-html PR #270 independently selected the same 0.111 target.
- Minimizes API distance from the existing 0.95 integration; jumping to
  0.150+ adds compatibility risk with no resolver benefit.
- Oxc 0.111 declares `rust-version = 1.91.0`; SynVoid pins Rust 1.98.1.

## Removal

See `Cargo.toml` header and
`architecture/dependency_security_baseline_phase25.md` §10: remove this fork
as soon as an official minify-html release eliminates the Oxc 0.95 /
external bumpalo 3.19 path and passes
`crates/synvoid-static-files/tests/minify_parity.rs`.
