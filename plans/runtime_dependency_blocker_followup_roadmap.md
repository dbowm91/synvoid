# Runtime Dependency Blocker Follow-up Roadmap

Status: planned (2026-09-18).

Predecessor: Phase 38 closeout at `f21e059f94785e121058231c535fdd52b807de3a`.

Primary goal: remove the workspace dependency-resolution blocker that currently prevents SynVoid from moving `synvoid-yara` off YARA-X 1.15, then reopen the YARA-X security upgrade without regressing the plugin runtime, minification semantics, or supply-chain policy.

## Current researched state

The Phase 38 closeout is still accurate about the landed graph:

- direct plugin runtime: Wasmtime 36.0.15 LTS;
- YARA-X: 1.15;
- YARA-X transitive Wasmtime: 40.0.4;
- remote/mesh compiled YARA bytes are non-executable after Phase 36 trust-model closure;
- the YARA-X upgrade remains blocked by the workspace `bumpalo` constraint.

The blocker is now sufficiently localized:

```text
synvoid-static-files
└── minify-html 0.18.1
    └── Oxc 0.95 family
        └── oxc_allocator 0.95
            └── bumpalo =3.19.x

yara-x 1.20
└── wasmtime 45.0.3
    └── bumpalo >=3.20.x
```

Cargo cannot satisfy those semver-compatible but disjoint requirements in the current graph.

Relevant upstream state as of 2026-09-18:

- `minify-html` latest release and current master remain on 0.18.1 / Oxc 0.95.
- `minify-html` PR #270 previously attempted an Oxc 0.95 -> 0.111 update across the five Oxc dependencies. It was closed without merge.
- Oxc 0.111 is the first researched target where `oxc_allocator` no longer depends on the external `bumpalo` crate and declares Rust 1.91 MSRV, below SynVoid's pinned Rust 1.98.1.
- YARA-X 1.20.0 currently declares Wasmtime 45.0.3.
- YARA-X PR #769 is open and changes Wasmtime 45.0.3 -> 47.0.4 plus MSRV 1.93 -> 1.94 in response to RUSTSEC-2026-0222 and RUSTSEC-2026-0269. It is not merged or released yet.
- SynVoid's direct plugin runtime should remain on Wasmtime 36.0.15 LTS during this work. Converging all Wasmtime users is not a prerequisite.

## Sequencing

### Phase 39 — Minifier/Oxc blocker remediation

Remove the `minify-html -> Oxc 0.95 -> bumpalo 3.19` constraint without changing SynVoid's user-visible minification semantics.

Preferred implementation:

1. freeze SynVoid's current HTML/inline-JS/inline-CSS minification behavior with a parity corpus;
2. validate a minimal `minify-html 0.18.1` compatibility fork whose primary change is Oxc 0.95 -> 0.111;
3. pin the fork by immutable revision behind an explicitly temporary supply-chain exception;
4. prove the `bumpalo 3.19` path from `minify-html` is gone;
5. prove `cargo update -p yara-x --precise 1.20.0` reaches dependency resolution rather than the old bumpalo conflict.

Do not replace the HTML minifier or vendor a browser parser into SynVoid merely to solve this resolver problem.

### Phase 40 — YARA-X upgrade reopening

After Phase 39, move YARA-X off 1.15 using a security-clean upstream line.

Preferred order:

1. official YARA-X release containing the Wasmtime fix from PR #769 or equivalent;
2. if upstream instead moves directly to Wasmtime 48 LTS, prefer that released line;
3. only if an immediate upgrade is necessary before an official release, use a project-controlled, minimal, audited fork based on the official YARA-X release and the upstream fix; never depend directly on an arbitrary contributor fork.

Do not upgrade to stock YARA-X 1.20.0 solely to replace Wasmtime 40 with known-affected Wasmtime 45.0.3.

## Explicit non-goals

This roadmap does not:

- move the plugin runtime from Wasmtime 36 LTS just for version convergence;
- replace `minify-html` with a custom SynVoid parser/minifier;
- vendor Oxc or YARA-X into the SynVoid tree without a separate decision;
- re-enable remote compiled YARA execution;
- weaken cargo-deny source policy permanently;
- create another generic minifier crate;
- treat duplicate Wasmtime majors as a correctness bug by themselves.

## Completion condition

This roadmap is complete when:

- the `minify-html` path no longer pins external `bumpalo 3.19`;
- minification parity is verified;
- YARA-X resolves to a release >=1.19 with a security-fixed Wasmtime line;
- Wasmtime 40.0.4 is absent from the final lockfile;
- YARA engine identifiers and tests are updated;
- obsolete YARA/Wasmtime advisory ignores are removed;
- any temporary git/source exception has an owner, immutable revision, review date, and removal trigger;
- full project verification is green.
