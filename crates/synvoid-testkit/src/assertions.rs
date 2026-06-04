/// Assert that a string contains a substring (convenience macro).
#[macro_export]
macro_rules! assert_contains {
    ($haystack:expr, $needle:expr) => {
        assert!(
            $haystack.contains($needle),
            "Expected '{}' to contain '{}'",
            $haystack,
            $needle
        );
    };
}

/// Assert that a string does not contain a substring.
#[macro_export]
macro_rules! assert_not_contains {
    ($haystack:expr, $needle:expr) => {
        assert!(
            !$haystack.contains($needle),
            "Expected '{}' to NOT contain '{}'",
            $haystack,
            $needle
        );
    };
}
