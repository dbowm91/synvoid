/// Assert that `haystack` contains `needle` as a substring.
///
/// Produces a descriptive panic message showing both values on failure.
///
/// # Examples
///
/// ```rust,ignore
/// assert_contains!("hello world", "world");
/// ```
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

/// Assert that `haystack` does **not** contain `needle` as a substring.
///
/// Produces a descriptive panic message showing both values on failure.
///
/// # Examples
///
/// ```rust,ignore
/// assert_not_contains!("hello world", "xyz");
/// ```
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
