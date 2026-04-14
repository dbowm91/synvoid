use proptest::prelude::*;

/// URL encoding roundtrip: decode(encode(x)) == x for ASCII-safe strings
proptest! {
    #[test]
    fn url_decode_encode_roundtrip(input in "[a-zA-Z0-9 _.-]{1,50}") {
        // Encode manually: replace spaces with + and non-alnum with %XX
        let mut encoded = String::new();
        for b in input.bytes() {
            match b {
                b' ' => encoded.push('+'),
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' => {
                    encoded.push(b as char);
                }
                _ => {
                    encoded.push_str(&format!("%{:02X}", b));
                }
            }
        }
        let decoded = maluwaf::utils::urlencoding_decode(&encoded);
        prop_assert_eq!(decoded, input);
    }

    /// urlencoding_decode preserves strings without percent encoding
    #[test]
    fn url_decode_no_encoding_preserved(input in "[a-zA-Z0-9]{1,50}") {
        let decoded = maluwaf::utils::urlencoding_decode(&input);
        prop_assert_eq!(decoded, input);
    }

    /// urlencoding_decode converts + to space
    #[test]
    fn url_decode_plus_to_space(word1 in "[a-z]{1,5}", word2 in "[a-z]{1,5}") {
        let input = format!("{}+{}", word1, word2);
        let decoded = maluwaf::utils::urlencoding_decode(&input);
        prop_assert_eq!(decoded, format!("{} {}", word1, word2));
    }

    /// InputNormalizer normalize idempotency: normalize(normalize(x)) == normalize(x)
    #[test]
    fn normalizer_idempotent(input in "[a-zA-Z0-9/._?=&%-]{1,100}") {
        use maluwaf::waf::attack_detection::normalizer::InputNormalizer;
        let normalizer = InputNormalizer::new();
        let first = normalizer.normalize(&input);
        let second = normalizer.normalize(first.as_str());
        prop_assert_eq!(first.as_str(), second.as_str());
    }

    /// InputNormalizer normalize produces non-empty output for non-empty input
    #[test]
    fn normalizer_preserves_nonempty(input in "[a-zA-Z0-9]{1,50}") {
        use maluwaf::waf::attack_detection::normalizer::InputNormalizer;
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize(&input);
        prop_assert!(!result.as_str().is_empty());
    }

    /// InputNormalizer percent decoding
    #[test]
    fn normalizer_decodes_percent(
        prefix in "[a-z]{1,5}",
        suffix in "[a-z]{1,5}",
    ) {
        use maluwaf::waf::attack_detection::normalizer::InputNormalizer;
        let normalizer = InputNormalizer::new();
        // %20 is space
        let input = format!("{}%20{}", prefix, suffix);
        let result = normalizer.normalize(&input);
        prop_assert!(result.as_str().contains(' '));
    }
}
