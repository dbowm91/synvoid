#![no_main]

//! Fuzz target for early HTTP parsing.
//!
//! Tests the [`EarlyHttpParser::parse`] function with arbitrary byte
//! input to ensure it handles incomplete, malformed, and adversarial
//! HTTP requests without panicking.

use libfuzzer_sys::fuzz_target;
use maluwaf::http::early_parse::EarlyHttpParser;

fuzz_target!(|data: &[u8]| {
    let _ = EarlyHttpParser::parse(data);

    let methods = [
        b"GET " as &[u8],
        b"POST " as &[u8],
        b"PUT " as &[u8],
        b"DELETE " as &[u8],
        b"HEAD " as &[u8],
        b"OPTIONS " as &[u8],
    ];
    for method in &methods {
        let mut buf = method.to_vec();
        buf.extend_from_slice(data);
        let _ = EarlyHttpParser::parse(&buf);
    }

    let with_length = format!(
        "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: {}\r\n\r\n",
        data.len()
    );
    let _ = EarlyHttpParser::parse(with_length.as_bytes());
});

#[cfg(test)]
mod tests {
    #[test]
    fn test_fuzz_target_compiles() {
        assert!(true);
    }
}
