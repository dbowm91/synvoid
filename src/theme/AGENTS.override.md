# Theme Root Compatibility Path

`src/theme` is a compatibility facade. The canonical theme implementation lives in `crates/synvoid-theme`.

Do not add new theme implementation here. Add implementation to `crates/synvoid-theme` and expose only compatibility re-exports from this directory when needed.
