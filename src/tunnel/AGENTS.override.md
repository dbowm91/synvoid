# Tunnel Root Compatibility Path

`src/tunnel` is a compatibility facade. The canonical tunnel implementation lives in `crates/synvoid-tunnel`.

Do not add new tunnel implementation here. Add protocol implementation to `crates/synvoid-tunnel` and expose only compatibility re-exports from this directory when needed.
