# Location Matcher Architecture

## 1. Purpose and Responsibility

The Location Matcher module (`src/location_matcher.rs`) provides **nginx-style URI location matching** with four match types using a three-tier lookup structure for O(1) exact + longest-prefix + ordered-regex matching.

**Core Responsibilities:**
- Nginx-compatible location pattern parsing
- Four match types: Exact, PreferentialPrefix, Regex, Prefix
- O(1) exact match, sorted prefix, ordered regex
- ReDoS prevention via complexity checking

---

## 2. Key Data Structures

```rust
pub struct LocationMatcher {
    exact_matches: HashMap<String, usize>,      // O(1) exact lookup
    prefix_matches: Vec<LocationMatch>,          // Sorted by length (longest first)
    regex_matches: Vec<LocationMatch>,           // Ordered by declaration
}

pub struct LocationMatch {
    pattern: String,
    compiled_regex: Option<Regex>,
    match_type: LocationMatchType,
    original_order: usize,
}

pub enum LocationMatchType {
    Exact,            // "= /path"
    PreferentialPrefix, // "^~ /prefix"
    Regex,            // "~ pattern" or "~* pattern"
    Prefix,           // "/prefix" (plain)
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `LocationMatcher::new(patterns)` | Parse nginx-style patterns |
| `match_uri(uri) -> Option<(usize, LocationMatchType)>` | Best match |
| `is_empty()`, `len()` | Collection queries |
| `LocationMatch::new(pattern, order)` | Parse single pattern |
| `LocationMatch::matches(uri) -> bool` | Test match |

---

## 4. Matching Priority

1. **Exact match** (`= /path`) — O(1) HashMap lookup
2. **Preferential prefix** (`^~ /prefix`) — Longest match, stops regex search
3. **Regex** (`~ pattern`, `~* pattern`) — First match in declaration order
4. **Prefix** (`/prefix`) — Longest match among plain prefixes

---

## 5. Integration Points

- **HTTP Server**: Route/location matching in request handling
- **Config**: Nginx-compatible location configuration parsing
- **Utils**: Uses `check_regex_complexity()` for ReDoS prevention

---

## 6. Security Considerations

- **ReDoS Prevention**: Regex patterns validated for complexity before compilation
- **Pattern Validation**: Rejects patterns with excessive backtracking potential
- **Input Sanitization**: Patterns normalized before matching
