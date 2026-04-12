//! Miscellaneous utility functions and types.
//!
//! This module provides common utilities used across the MaluWAF codebase:
//!
//! # Submodules
//! - [`ratelimit`] - Rate limiting utilities
//! - [`errors`] - Structured error message formatters
//!
//! # Types
//! - [`ArcStr`] - Atomically reference-counted string for efficient cloning
//! - [`RunningFlag`] - Thread-safe running state flag
//! - [`DrainFlag`] - Thread-safe drain state flag
//!
//! # Extension Traits
//! - [`ResultExt`] - Extension methods for `Result` types
//! - [`OptionExt`] - Extension methods for `Option` types
//!
//! # Functions
//! - [`current_timestamp()`] - Returns seconds since UNIX epoch
//! - [`parse_host_port()`] - Parse host:port strings into `SocketAddr`
//! - [`ip_to_slot()`] / [`hash_ip()`] - IP hashing for consistent slot assignment
//! - [`parse_duration()`] / [`format_duration()`] - Parse/format duration strings
//! - [`urlencoding_decode()`] - Decode URL-encoded strings
//! - [`is_newer_version()`] - Compare semantic version strings

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub mod ratelimit;
pub mod errors {
    pub mod ipc {
        pub fn connect_failed(e: &impl std::fmt::Display) -> String {
            format!("Failed to connect to IPC socket: {}", e)
        }
        pub fn send_failed(e: &impl std::fmt::Display) -> String {
            format!("Failed to send IPC message: {}", e)
        }
        pub fn recv_failed(e: &impl std::fmt::Display) -> String {
            format!("Failed to receive IPC message: {}", e)
        }
        pub fn timeout(timeout_ms: u64) -> String {
            format!("Timeout waiting for IPC response after {}ms", timeout_ms)
        }
        pub fn unexpected_response(msg: &impl std::fmt::Debug) -> String {
            format!("Unexpected IPC response: {:?}", msg)
        }
    }

    pub mod process {
        pub fn process_exited(status: &impl std::fmt::Display) -> String {
            format!("Process exited unexpectedly with status: {}", status)
        }
        pub fn process_not_found(pid: &impl std::fmt::Display) -> String {
            format!("Process not found: {}", pid)
        }
        pub fn spawn_failed(e: &impl std::fmt::Display) -> String {
            format!("Failed to spawn process: {}", e)
        }
    }

    pub mod health {
        pub fn check_failed(e: &impl std::fmt::Display) -> String {
            format!("Health check failed: {}", e)
        }
        pub fn worker_not_ready(worker_id: impl std::fmt::Display, attempts: u32) -> String {
            format!("Worker {} not ready after {} attempts", worker_id, attempts)
        }
        pub fn validation_failed(unhealthy: usize, total: usize) -> String {
            format!(
                "Health validation failed: {}/{} workers unhealthy",
                unhealthy, total
            )
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ArcStr(Arc<str>);

impl ArcStr {
    #[inline]
    pub fn new(s: impl Into<String>) -> Self {
        Self(Arc::from(s.into()))
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[inline]
    pub fn as_arc(&self) -> &Arc<str> {
        &self.0
    }
}

impl std::fmt::Display for ArcStr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<String> for ArcStr {
    fn from(s: String) -> Self {
        Self(Arc::from(s))
    }
}

impl From<&str> for ArcStr {
    fn from(s: &str) -> Self {
        Self(Arc::from(s))
    }
}

impl std::ops::Deref for ArcStr {
    type Target = str;
    #[inline]
    fn deref(&self) -> &str {
        &self.0
    }
}

impl serde::Serialize for ArcStr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for ArcStr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self(Arc::from(s)))
    }
}

/// Extension trait for Result types providing additional utility methods.
pub trait ResultExt<T, E> {
    /// Executes a closure if the result is an error, without changing the result.
    fn inspect_err(self, f: impl FnOnce(&E)) -> Self;
    /// Converts an Err to None, logging the error with debug level tracing.
    fn ok_or_trace(self, context: &str) -> Option<T>
    where
        E: std::fmt::Debug;
}

impl<T, E> ResultExt<T, E> for Result<T, E> {
    #[inline]
    fn inspect_err(self, f: impl FnOnce(&E)) -> Self {
        if let Err(ref e) = self {
            f(e);
        }
        self
    }

    #[inline]
    fn ok_or_trace(self, context: &str) -> Option<T>
    where
        E: std::fmt::Debug,
    {
        match self {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::debug!("{}: {:?}", context, e);
                None
            }
        }
    }
}

/// Extension trait for Option types providing additional utility methods.
pub trait OptionExt<T> {
    /// Executes a closure if the option contains a value.
    fn if_some<F: FnOnce(&T)>(self, f: F);
    /// Placeholder for logic when option is None.
    fn if_none(self);
    /// Converts None to an Err with the given context message.
    fn require(self, context: &str) -> Result<T, String>;
}

impl<T> OptionExt<T> for Option<T> {
    #[inline]
    fn if_some<F: FnOnce(&T)>(self, f: F) {
        if let Some(ref t) = self {
            f(t);
        }
    }

    #[inline]
    fn if_none(self) {
        if self.is_none() {}
    }

    #[inline]
    fn require(self, context: &str) -> Result<T, String> {
        self.ok_or_else(|| context.to_string())
    }
}

#[derive(Clone, Debug)]
pub struct RunningFlag {
    inner: Arc<AtomicBool>,
}

impl RunningFlag {
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicBool::new(true)),
        }
    }

    #[inline]
    pub fn is_running(&self) -> bool {
        self.inner.load(Ordering::SeqCst)
    }

    #[inline]
    pub fn get(&self) -> bool {
        self.inner.load(Ordering::SeqCst)
    }

    #[inline]
    pub fn stop(&self) {
        self.inner.store(false, Ordering::SeqCst);
    }

    #[inline]
    pub fn set(&self, value: bool) {
        self.inner.store(value, Ordering::SeqCst);
    }
}

impl Default for RunningFlag {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct DrainFlag {
    inner: Arc<AtomicBool>,
}

impl DrainFlag {
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicBool::new(false)),
        }
    }

    #[inline]
    pub fn is_draining(&self) -> bool {
        self.inner.load(Ordering::SeqCst)
    }

    #[inline]
    pub fn get(&self) -> bool {
        self.inner.load(Ordering::SeqCst)
    }

    #[inline]
    pub fn start_drain(&self) {
        self.inner.store(true, Ordering::SeqCst);
    }

    #[inline]
    pub fn end_drain(&self) {
        self.inner.store(false, Ordering::SeqCst);
    }

    #[inline]
    pub fn set(&self, value: bool) {
        self.inner.store(value, Ordering::SeqCst);
    }
}

impl Default for DrainFlag {
    fn default() -> Self {
        Self::new()
    }
}

const DURATION_SUFFIXES: &[(&str, &str, u64)] = &[
    ("milliseconds", "ms", 1),
    ("seconds", "s", 1),
    ("minutes", "m", 60),
    ("hours", "h", 3600),
    ("days", "d", 86400),
];

const DURATION_SUFFIX_SHORT: &[(char, u64)] = &[('s', 1), ('m', 60), ('h', 3600), ('d', 86400)];

pub fn parse_duration(s: &str) -> Option<u64> {
    let s = s.trim();

    if s.is_empty() {
        return None;
    }

    if s.eq_ignore_ascii_case("never")
        || s.eq_ignore_ascii_case("permanent")
        || s.eq_ignore_ascii_case("0")
    {
        return Some(0);
    }

    if let Ok(num) = s.parse::<u64>() {
        return Some(num);
    }

    if s.len() < 2 {
        return None;
    }

    for (long_suffix, _short_suffix, multiplier) in DURATION_SUFFIXES {
        let suffix_len = long_suffix.len();
        if s.len() > suffix_len && s[s.len() - suffix_len..].eq_ignore_ascii_case(long_suffix) {
            let value = s[..s.len() - suffix_len].parse::<u64>().ok()?;
            return Some(value * multiplier);
        }
    }

    let last_char = s.chars().last()?;
    for (short_suffix, multiplier) in DURATION_SUFFIX_SHORT {
        if last_char.eq_ignore_ascii_case(short_suffix) {
            let value = s[..s.len() - 1].parse::<u64>().ok()?;
            return Some(value * multiplier);
        }
    }

    if let Some(stripped) = s.strip_suffix("ms") {
        let value = stripped.parse::<u64>().ok()?;
        return Some(value / 1000);
    }

    None
}

pub fn format_duration(seconds: u64) -> String {
    if seconds == 0 {
        return "never".to_string();
    }
    if seconds < 60 {
        return format!("{}s", seconds);
    }
    if seconds < 3600 {
        return format!("{}m", seconds / 60);
    }
    if seconds < 86400 {
        return format!("{}h", seconds / 3600);
    }
    format!("{}d", seconds / 86400)
}

/// URL decode a string.
///
/// This function handles:
/// - Percent-encoding (%XX)
/// - Plus-to-space conversion
///
/// # Arguments
/// * `input` - The URL-encoded string to decode
///
/// # Returns
/// The decoded string
pub fn urlencoding_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    if byte.is_ascii() {
                        result.push(byte as char);
                        continue;
                    }
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    result
}

#[allow(clippy::result_unit_err)]
pub fn urlencoding_decode_result(input: &str) -> Result<String, ()> {
    Ok(urlencoding_decode(input))
}

pub fn url_decode_all(input: &str) -> String {
    let mut result = input.to_string();

    for _ in 0..10 {
        let decoded = urlencoding_decode(&result);
        if decoded == result {
            break;
        }
        result = decoded;
    }

    result
}

pub fn now_ms() -> u64 {
    safe_unix_duration().as_millis() as u64
}

/// Returns a `Duration` since UNIX_EPOCH, defaulting to zero on error.
pub fn safe_unix_duration() -> std::time::Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
}

/// Returns seconds since UNIX_EPOCH, defaulting to 0 on error (e.g. clock skew).
pub fn safe_unix_timestamp() -> u64 {
    safe_unix_duration().as_secs()
}

pub fn current_timestamp() -> u64 {
    safe_unix_timestamp()
}

use std::net::{IpAddr, SocketAddr};

pub fn parse_host_port(host: &str, port: u16) -> Result<SocketAddr, String> {
    if host.starts_with('[') {
        if let Some(end_bracket) = host.find(']') {
            let ip_str = &host[1..end_bracket];
            let ip: IpAddr = ip_str
                .parse()
                .map_err(|e| format!("Invalid IPv6 address: {}", e))?;
            return Ok(SocketAddr::new(ip, port));
        }
        return Err("Unclosed bracket in IPv6 address".to_string());
    }

    if host.contains(':') {
        let ip: IpAddr = host
            .parse()
            .map_err(|e| format!("Invalid IP address: {}", e))?;
        return Ok(SocketAddr::new(ip, port));
    }

    let ip: IpAddr = host
        .parse()
        .map_err(|e| format!("Invalid IP address: {}", e))?;
    Ok(SocketAddr::new(ip, port))
}

pub fn is_ipv6_host(host: &str) -> bool {
    host.contains(':')
}

#[inline]
fn hash_ipv6(ipv6: std::net::Ipv6Addr) -> u64 {
    let segments = ipv6.segments();
    let mut hash: u64 = 0;
    for seg in &segments {
        hash = hash.wrapping_mul(0x9e3779b9).wrapping_add(u64::from(*seg));
    }
    hash
}

#[inline]
pub fn ip_to_slot(ip: IpAddr, num_slots: usize) -> usize {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            let hash = ((u32::from(octets[0]) << 24)
                | (u32::from(octets[1]) << 16)
                | (u32::from(octets[2]) << 8)
                | u32::from(octets[3]))
            .wrapping_mul(0x9e3779b9);
            (hash >> 16) as usize % num_slots
        }
        IpAddr::V6(ipv6) => {
            let hash = hash_ipv6(ipv6);
            (hash >> 32) as usize % num_slots
        }
    }
}

#[inline]
pub fn hash_ip(ip: IpAddr) -> usize {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            ((u32::from(octets[0]) << 24)
                | (u32::from(octets[1]) << 16)
                | (u32::from(octets[2]) << 8)
                | u32::from(octets[3])) as usize
        }
        IpAddr::V6(ipv6) => hash_ipv6(ipv6) as usize,
    }
}

#[cfg(test)]
mod ip_tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_ip_to_slot_consistency() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let slot1 = ip_to_slot(ip, 65536);
        let slot2 = ip_to_slot(ip, 65536);
        assert_eq!(slot1, slot2, "Same IP should produce same slot");
    }

    #[test]
    fn test_ip_to_slot_different_ips() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let slot1 = ip_to_slot(ip1, 65536);
        let slot2 = ip_to_slot(ip2, 65536);
        assert_ne!(
            slot1, slot2,
            "Different IPs should likely produce different slots"
        );
    }

    #[test]
    fn test_ipv6_to_slot() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let slot = ip_to_slot(ip, 65536);
        assert!(slot < 65536);
    }

    #[test]
    fn test_hash_ip_ipv4() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let hash1 = hash_ip(ip);
        let hash2 = hash_ip(ip);
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, 0);
    }

    #[test]
    fn test_hash_ip_ipv6() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let hash1 = hash_ip(ip);
        let hash2 = hash_ip(ip);
        assert_eq!(hash1, hash2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("30"), Some(30), "30");
        assert_eq!(parse_duration("30s"), Some(30), "30s");
        assert_eq!(parse_duration("30sec"), Some(30), "30sec");
        assert_eq!(parse_duration("30m"), Some(1800), "30m");
        assert_eq!(parse_duration("30min"), Some(1800), "30min");
        assert_eq!(parse_duration("2h"), Some(7200), "2h");
        assert_eq!(parse_duration("2hr"), Some(7200), "2hr");
        assert_eq!(parse_duration("2hours"), Some(7200), "2hours");
        assert_eq!(parse_duration("1d"), Some(86400), "1d");
        assert_eq!(parse_duration("1day"), Some(86400), "1day");
        assert_eq!(parse_duration("2days"), Some(172800), "2days");
        assert_eq!(parse_duration("never"), Some(0), "never");
        assert_eq!(parse_duration("permanent"), Some(0), "permanent");
        assert_eq!(parse_duration("0"), Some(0), "0");
    }

    #[test]
    fn test_parse_host_port_ipv4() {
        assert_eq!(
            parse_host_port("127.0.0.1", 8080).unwrap(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
        );
        assert_eq!(
            parse_host_port("0.0.0.0", 80).unwrap(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 80)
        );
    }

    #[test]
    fn test_parse_host_port_ipv6() {
        assert_eq!(
            parse_host_port("::1", 8080).unwrap(),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8080)
        );
        assert_eq!(
            parse_host_port("[::1]", 8080).unwrap(),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8080)
        );
        assert_eq!(
            parse_host_port("::", 443).unwrap(),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 443)
        );
        assert_eq!(
            parse_host_port("[::]", 443).unwrap(),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 443)
        );
    }

    #[test]
    fn test_parse_host_port_invalid() {
        assert!(parse_host_port("invalid", 8080).is_err());
        assert!(parse_host_port("[invalid", 8080).is_err());
    }

    #[test]
    fn test_is_ipv6_host() {
        assert!(!is_ipv6_host("127.0.0.1"));
        assert!(!is_ipv6_host("192.168.1.1"));
        assert!(is_ipv6_host("::1"));
        assert!(is_ipv6_host("[::1]"));
        assert!(is_ipv6_host("2001:db8::1"));
    }
}

pub fn get_first_non_loopback_ip() -> Result<IpAddr, String> {
    // Try to connect to a public DNS server to get the local IP
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("Failed to bind socket: {}", e))?;

    socket
        .connect("8.8.8.8:53")
        .map_err(|e| format!("Failed to connect: {}", e))?;

    let local_addr = socket
        .local_addr()
        .map_err(|e| format!("Failed to get local addr: {}", e))?;

    Ok(local_addr.ip())
}

const REGEX_SIZE_LIMIT: usize = 1024;
const REGEX_MAX_QUANTIFIERS: usize = 10;
const REGEX_MAX_GROUPS: usize = 20;

#[derive(Debug, Clone)]
pub struct RegexComplexityResult {
    pub safe: bool,
    pub reason: Option<String>,
}

impl RegexComplexityResult {
    pub fn safe() -> Self {
        Self {
            safe: true,
            reason: None,
        }
    }

    pub fn unsafe_(reason: impl Into<String>) -> Self {
        Self {
            safe: false,
            reason: Some(reason.into()),
        }
    }
}

pub fn check_regex_complexity(pattern: &str) -> RegexComplexityResult {
    if pattern.len() > REGEX_SIZE_LIMIT {
        return RegexComplexityResult::unsafe_(format!(
            "Pattern too long ({} bytes, max {})",
            pattern.len(),
            REGEX_SIZE_LIMIT
        ));
    }

    let nested_quantifiers = [
        (r"(.*)+", "nested .*"),
        (r"(.+)+", "nested .+"),
        (r"([^]]*)+", "nested [^]]*"),
        (r"([^]]*)*", "nested [^]]**"),
    ];

    for (pat, desc) in &nested_quantifiers {
        if pattern.contains(pat) {
            return RegexComplexityResult::unsafe_(format!(
                "ReDoS risk: nested quantifiers ({})",
                desc
            ));
        }
    }

    let quant_count = pattern.chars().filter(|c| *c == '+' || *c == '*').count();
    if quant_count > REGEX_MAX_QUANTIFIERS {
        return RegexComplexityResult::unsafe_(format!(
            "Too many quantifiers ({} > {}), may cause catastrophic backtracking",
            quant_count, REGEX_MAX_QUANTIFIERS
        ));
    }

    let group_count = pattern.matches('(').count();
    if group_count > REGEX_MAX_GROUPS {
        return RegexComplexityResult::unsafe_(format!(
            "Too many capture groups ({} > {})",
            group_count, REGEX_MAX_GROUPS
        ));
    }

    let dangerous_lookarounds = [r"(?=", r"(?!", r"(?<=", r"(?<!"];
    for da in &dangerous_lookarounds {
        if pattern.contains(da) {
            let count = pattern.matches(da).count();
            if count > 5 {
                return RegexComplexityResult::unsafe_(format!(
                    "Many lookarounds ({}), potential performance issue",
                    count
                ));
            }
        }
    }

    RegexComplexityResult::safe()
}

#[cfg(test)]
mod regex_tests {
    use super::*;

    #[test]
    fn test_safe_regex() {
        let result = check_regex_complexity(r"\.php$");
        assert!(result.safe);
    }

    #[test]
    fn test_nested_quantifiers() {
        let result = check_regex_complexity(r"(.*)+");
        assert!(!result.safe);
        assert!(result.reason.unwrap().contains("ReDoS"));
    }

    #[test]
    fn test_too_many_quantifiers() {
        let pattern = "a+b+c+d+e+f+g+h+i+j+k+l+m+n+o+p+".to_string();
        let result = check_regex_complexity(&pattern);
        assert!(!result.safe);
    }

    #[test]
    fn test_long_pattern() {
        let pattern = "a".repeat(2000);
        let result = check_regex_complexity(&pattern);
        assert!(!result.safe);
    }
}

#[cfg(test)]
mod running_flag_tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_running_flag_default_is_running() {
        let flag = RunningFlag::new();
        assert!(flag.is_running());
        assert!(flag.get());
    }

    #[test]
    fn test_running_flag_stop() {
        let flag = RunningFlag::new();
        assert!(flag.is_running());
        flag.stop();
        assert!(!flag.is_running());
        assert!(!flag.get());
    }

    #[test]
    fn test_running_flag_set() {
        let flag = RunningFlag::new();
        assert!(flag.is_running());
        flag.set(false);
        assert!(!flag.is_running());
        flag.set(true);
        assert!(flag.is_running());
    }

    #[test]
    fn test_running_flag_clone() {
        let flag = RunningFlag::new();
        let cloned = flag.clone();
        assert!(flag.is_running());
        assert!(cloned.is_running());
        flag.stop();
        assert!(!flag.is_running());
        assert!(!cloned.is_running());
    }

    #[test]
    fn test_running_flag_concurrent() {
        let flag = Arc::new(RunningFlag::new());
        let flag2 = flag.clone();

        let handle = thread::spawn(move || {
            while flag2.is_running() {
                std::thread::yield_now();
            }
        });

        flag.stop();
        handle.join().unwrap();
        assert!(!flag.is_running());
    }
}

#[cfg(test)]
mod drain_flag_tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_drain_flag_default_not_draining() {
        let flag = DrainFlag::new();
        assert!(!flag.is_draining());
        assert!(!flag.get());
    }

    #[test]
    fn test_drain_flag_start_end_drain() {
        let flag = DrainFlag::new();
        assert!(!flag.is_draining());

        flag.start_drain();
        assert!(flag.is_draining());
        assert!(flag.get());

        flag.end_drain();
        assert!(!flag.is_draining());
        assert!(!flag.get());
    }

    #[test]
    fn test_drain_flag_set() {
        let flag = DrainFlag::new();
        assert!(!flag.is_draining());

        flag.set(true);
        assert!(flag.is_draining());

        flag.set(false);
        assert!(!flag.is_draining());
    }

    #[test]
    fn test_drain_flag_clone() {
        let flag = DrainFlag::new();
        let cloned = flag.clone();

        flag.start_drain();
        assert!(flag.is_draining());
        assert!(cloned.is_draining());

        cloned.end_drain();
        assert!(!flag.is_draining());
        assert!(!cloned.is_draining());
    }

    #[test]
    fn test_drain_flag_concurrent() {
        let flag = Arc::new(DrainFlag::new());
        let flag2 = flag.clone();

        let handle = thread::spawn(move || {
            while !flag2.is_draining() {
                std::thread::yield_now();
            }
        });

        flag.start_drain();
        handle.join().unwrap();
        assert!(flag.is_draining());
    }
}

#[cfg(test)]
mod result_ext_tests {
    use super::*;

    #[test]
    fn test_inspect_err_calls_closure_on_err() {
        let mut called = false;
        let result: Result<i32, &str> = Err("error");
        result.inspect_err(|e| {
            assert_eq!(e, &"error");
            called = true;
        });
        assert!(called);
    }

    #[test]
    fn test_inspect_err_does_nothing_on_ok() {
        let mut called = false;
        let result: Result<i32, &str> = Ok(42);
        result.inspect_err(|_| called = true);
        assert!(!called);
    }

    #[test]
    fn test_ok_or_trace_returns_ok_value() {
        let result: Result<i32, &str> = Ok(42);
        assert_eq!(result.ok_or_trace("context"), Some(42));
    }

    #[test]
    fn test_ok_or_trace_returns_none_on_err() {
        let result: Result<i32, &str> = Err("error");
        assert_eq!(result.ok_or_trace("context"), None);
    }
}

#[cfg(test)]
mod option_ext_tests {
    use super::*;

    #[test]
    fn test_if_some_calls_closure() {
        let mut called = false;
        let value = Some(42);
        value.if_some(|v| {
            assert_eq!(*v, 42);
            called = true;
        });
        assert!(called);
    }

    #[test]
    fn test_if_some_does_nothing_on_none() {
        let mut called = false;
        let value: Option<i32> = None;
        value.if_some(|_| called = true);
        assert!(!called);
    }

    #[test]
    fn test_require_returns_value() {
        let value = Some(42);
        assert_eq!(value.require("context").unwrap(), 42);
    }

    #[test]
    fn test_require_returns_err_on_none() {
        let value: Option<i32> = None;
        assert_eq!(value.require("context"), Err("context".to_string()));
    }
}

#[cfg(test)]
mod error_helpers_tests {
    use super::errors;

    #[test]
    fn test_ipc_connect_failed() {
        let msg = errors::ipc::connect_failed(&"connection refused");
        assert!(msg.contains("connection refused"));
    }

    #[test]
    fn test_ipc_send_failed() {
        let msg = errors::ipc::send_failed(&"broken pipe");
        assert!(msg.contains("broken pipe"));
    }

    #[test]
    fn test_health_check_failed() {
        let msg = errors::health::check_failed(&"timeout");
        assert!(msg.contains("timeout"));
    }

    #[test]
    fn test_health_worker_not_ready() {
        let msg = errors::health::worker_not_ready("worker-1", 5);
        assert!(msg.contains("worker-1"));
        assert!(msg.contains("5"));
    }

    #[test]
    fn test_health_validation_failed() {
        let msg = errors::health::validation_failed(3, 10);
        assert!(msg.contains("3"));
        assert!(msg.contains("10"));
    }
}

pub fn is_newer_version(new: &str, current: &str) -> bool {
    if new == current {
        return false;
    }

    let new_parts: Vec<u32> = new.split('.').filter_map(|s| s.parse().ok()).collect();
    let current_parts: Vec<u32> = current.split('.').filter_map(|s| s.parse().ok()).collect();

    for i in 0..new_parts.len().max(current_parts.len()) {
        let new_part = new_parts.get(i).unwrap_or(&0);
        let current_part = current_parts.get(i).unwrap_or(&0);

        if new_part > current_part {
            return true;
        } else if new_part < current_part {
            return false;
        }
    }
    false
}
