#![no_main]

//! Fuzz target for plugin manifest parsing.
//!
//! Feeds arbitrary bytes interpreted as UTF-8 TOML to
//! [`PluginManifest::parse_toml`] to verify that malformed or adversarial
//! manifests are rejected with typed errors rather than panicking.

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use synvoid_plugin_runtime::PluginManifest;

fuzz_target!(|data: &[u8]| {
    let toml_str = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    let _ = PluginManifest::parse_toml(toml_str, Path::new("fuzz.toml"));
});
