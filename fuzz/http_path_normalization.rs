#![no_main]

//! Fuzz target for HTTP path normalization.
//!
//! Feeds arbitrary bytes (interpreted as a URL-encoded path string) through
//! [`urlencoding_decode_result`] and [`url_decode_all`] to verify that
//! path decoding never panics on adversarial or malformed input.

use libfuzzer_sys::fuzz_target;
use synvoid::utils::{url_decode_all, urlencoding_decode_result};

fuzz_target!(|data: &[u8]| {
    let path_str = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    let _ = urlencoding_decode_result(path_str);
    let _ = url_decode_all(path_str);
});
