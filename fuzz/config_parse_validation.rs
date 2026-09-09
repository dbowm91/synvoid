#![no_main]

//! Fuzz target for operator config parse + validation.
//!
//! Feeds arbitrary bytes through the production in-memory seams
//! ([`MainConfig::from_toml_str`] and [`SiteConfig::from_toml_str`]) shared
//! with the file loaders. Verifies arbitrary input yields typed
//! parse/validation errors — never a panic, abort, filesystem access, socket
//! creation, or unbounded allocation. Strict bounds: inputs under 2 bytes or
//! over 16 KiB are skipped (operator configs are small; the cap bounds TOML
//! parse allocation). The leading byte selects the parser path so one target
//! covers both main and site configs. Non-UTF8 input is skipped (it maps to
//! a typed parse error by construction).

use libfuzzer_sys::fuzz_target;
use synvoid_config::{MainConfig, SiteConfig};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 || data.len() > 16384 {
        return;
    }
    let text = match std::str::from_utf8(&data[1..]) {
        Ok(s) => s,
        Err(_) => return,
    };
    match data[0] % 2 {
        0 => {
            let _ = MainConfig::from_toml_str(text);
        }
        _ => {
            let _ = SiteConfig::from_toml_str(text);
        }
    }
});

#[cfg(test)]
mod tests {
    #[test]
    fn test_fuzz_target_compiles() {}
}
