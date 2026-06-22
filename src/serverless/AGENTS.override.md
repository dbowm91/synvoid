# Serverless Root Compatibility Path

`src/serverless` is a compatibility facade. The canonical serverless implementation lives in `crates/synvoid-serverless`.

Do not add new serverless implementation here. Add implementation to `crates/synvoid-serverless` and expose only compatibility re-exports from this directory when needed.
