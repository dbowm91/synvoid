use crate::config::EffectiveUploadConfig;
use crate::malware_scanner::{MalwareMatch, ScanContext};
use crate::MalwareScanner;
use std::io::Cursor;
use thiserror::Error;
use tracing::warn;
use zip::read::ZipArchive;

/// Configuration for archive inspection limits.
#[derive(Debug, Clone)]
pub struct ArchiveInspectionConfig {
    pub enabled: bool,
    pub max_depth: u32,
    pub max_entries: u32,
    pub max_total_uncompressed_bytes: u64,
    pub max_entry_uncompressed_bytes: u64,
    pub max_compression_ratio: f64,
    pub max_nested_archives: u32,
}

impl ArchiveInspectionConfig {
    pub fn from_effective_config(config: &EffectiveUploadConfig) -> Self {
        Self {
            enabled: config.archive_inspection_enabled,
            max_depth: config.archive_max_depth,
            max_entries: config.archive_max_entries,
            max_total_uncompressed_bytes: config.archive_max_total_uncompressed_bytes,
            max_entry_uncompressed_bytes: config.archive_max_entry_uncompressed_bytes,
            max_compression_ratio: config.archive_max_compression_ratio,
            max_nested_archives: config.archive_max_nested_archives,
        }
    }
}

/// Result of archive inspection.
#[derive(Debug, Clone)]
pub struct ArchiveInspectionResult {
    /// Whether the archive was successfully inspected.
    pub inspected: bool,
    /// Archive format detected (e.g., "zip").
    pub archive_type: String,
    /// Total entries encountered in the archive.
    pub entries_seen: u32,
    /// Entries whose contents were scanned for malware.
    pub entries_scanned: u32,
    /// Number of nested archives found.
    pub nested_archives_seen: u32,
    /// Maximum nesting depth reached.
    pub max_depth_reached: u32,
    /// Total uncompressed bytes across all entries.
    pub total_uncompressed_bytes_seen: u64,
    /// Whether inspection was truncated due to limits.
    pub truncated: bool,
    /// Malware matches found in archive entries.
    pub matches: Vec<ArchiveEntryMatch>,
    /// Warnings generated during inspection.
    pub warnings: Vec<String>,
    /// Whether recursive inspection is enabled (currently always false).
    pub recursive_inspection_enabled: bool,
    /// Whether the archive was truncated.
    pub archive_error: Option<String>,
}

/// A malware match with entry context.
#[derive(Debug, Clone)]
pub struct ArchiveEntryMatch {
    /// The inner malware match details.
    pub malware_match: MalwareMatch,
    /// The entry path within the archive.
    pub entry_path: String,
    /// Entry index in the archive.
    pub entry_index: u32,
}

/// Errors during archive inspection.
#[derive(Debug, Error)]
pub enum ArchiveInspectionError {
    #[error("Archive inspection disabled")]
    Disabled,

    #[error("Invalid ZIP archive: {0}")]
    InvalidZip(String),

    #[error("Path traversal detected: {0}")]
    PathTraversal(String),

    #[error("Absolute path rejected: {0}")]
    AbsolutePath(String),

    #[error("UNC path rejected: {0}")]
    UncPath(String),

    #[error("Symlink rejected: {0}")]
    SymlinkRejected(String),

    #[error("Too many entries: {count} exceeds limit {limit}")]
    TooManyEntries { count: u32, limit: u32 },

    #[error("Entry too large: {size} exceeds limit {limit}")]
    EntryTooLarge { size: u64, limit: u64 },

    #[error("Compression ratio too high: {ratio:.1} exceeds limit {limit:.1}")]
    CompressionRatioTooHigh { ratio: f64, limit: f64 },

    #[error("Total uncompressed size exceeds limit: {total} exceeds {limit}")]
    TotalSizeExceeded { total: u64, limit: u64 },

    #[error("Too many nested archives: {count} exceeds limit {limit}")]
    TooManyNestedArchives { count: u32, limit: u32 },

    #[error("Depth exceeded: {depth} exceeds limit {limit}")]
    DepthExceeded { depth: u32, limit: u32 },

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Known archive file extensions for nested archive detection.
const NESTED_ARCHIVE_EXTENSIONS: &[&str] = &[
    ".zip", ".jar", ".war", ".ear", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub",
];

/// Check if a filename looks like a nested archive.
fn is_nested_archive_filename(name: &str) -> bool {
    let lower = name.to_lowercase();
    NESTED_ARCHIVE_EXTENSIONS
        .iter()
        .any(|ext| lower.ends_with(ext))
}

/// Sanitize a ZIP entry path. Returns the normalized form or an error if unsafe.
///
/// Rejection criteria:
/// - Contains `..` path component (traversal)
/// - Starts with `/` or `\` (absolute)
/// - Starts with `\\` (UNC)
/// - Windows drive letter (e.g., `C:\`)
/// - Null bytes
/// - Backslashes converted to forward slashes for normalization
fn sanitize_entry_path(entry_name: &str) -> Result<String, ArchiveInspectionError> {
    if entry_name.contains('\0') {
        return Err(ArchiveInspectionError::PathTraversal(format!(
            "null byte in path: {entry_name}"
        )));
    }

    let normalized = entry_name.replace('\\', "/");

    // Reject UNC paths: starts with //
    if normalized.starts_with("//") {
        return Err(ArchiveInspectionError::UncPath(entry_name.to_string()));
    }

    // Reject absolute paths: starts with /
    if normalized.starts_with('/') {
        return Err(ArchiveInspectionError::AbsolutePath(entry_name.to_string()));
    }

    // Reject Windows drive letter paths: C:/ or C:\
    if normalized.len() >= 2 {
        let bytes = normalized.as_bytes();
        if bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            return Err(ArchiveInspectionError::AbsolutePath(entry_name.to_string()));
        }
    }

    // Reject .. components
    for component in normalized.split('/') {
        if component == ".." {
            return Err(ArchiveInspectionError::PathTraversal(format!(
                ".. component in path: {entry_name}"
            )));
        }
    }

    Ok(normalized)
}

/// Check if a ZIP entry is a directory (ends with /).
fn is_directory(entry_name: &str) -> bool {
    entry_name.ends_with('/')
}

/// An entry collected from a ZIP archive, with owned content bytes.
///
/// This struct is used to decouple synchronous ZIP reading from async
/// malware scanning. The `zip` crate's `ZipArchive`/`ZipFile` types are
/// `!Send` (they contain `&mut dyn Read`), so we must fully read all
/// entry data before crossing any `.await` boundary.
struct CollectedEntry {
    entry_name: String,
    entry_index: u32,
    uncompressed_size: u64,
    content: Vec<u8>,
}

/// Inspect a ZIP archive from in-memory bytes.
///
/// This iterates ZIP entries without extracting to disk. For each entry:
/// - Path is sanitized (reject traversal, absolute, UNC, symlinks)
/// - Size limits are enforced
/// - Content is scanned for malware via the provided scanner
/// - Nested archive detection via filename extension
///
/// Returns `Err` for limits violations or malformed archives.
///
/// # Send safety
///
/// The `zip` crate's `ZipArchive` and `ZipFile` types are `!Send` (they
/// contain `&mut dyn Read`). This function is split into two phases:
/// 1. **Sync**: Read all entry metadata and content into owned `CollectedEntry`
///    values, then drop the `ZipArchive`.
/// 2. **Async**: Scan the collected content for malware.
///
/// This ensures no `ZipArchive`/`ZipFile` state is live across `.await`
/// points, making the returned future `Send`-safe.
#[allow(clippy::too_many_arguments)]
pub async fn inspect_zip_archive(
    data: &[u8],
    config: &ArchiveInspectionConfig,
    scanner: &MalwareScanner,
    current_depth: u32,
    _outer_filename: Option<&str>,
) -> Result<ArchiveInspectionResult, ArchiveInspectionError> {
    if !config.enabled {
        return Err(ArchiveInspectionError::Disabled);
    }

    if current_depth > config.max_depth {
        return Err(ArchiveInspectionError::DepthExceeded {
            depth: current_depth,
            limit: config.max_depth,
        });
    }

    // ── Phase 1 (sync): Read all entries into owned data ──────────────
    // This scope drops `archive` before we touch any `.await`.
    let (collected, mut result, entry_count) = {
        let cursor = Cursor::new(data);
        let mut archive = ZipArchive::new(cursor)
            .map_err(|e| ArchiveInspectionError::InvalidZip(format!("failed to open ZIP: {e}")))?;

        let mut result = ArchiveInspectionResult {
            inspected: true,
            archive_type: "zip".to_string(),
            entries_seen: 0,
            entries_scanned: 0,
            nested_archives_seen: 0,
            max_depth_reached: current_depth,
            total_uncompressed_bytes_seen: 0,
            truncated: false,
            matches: Vec::new(),
            warnings: Vec::new(),
            recursive_inspection_enabled: false,
            archive_error: None,
        };

        let entry_count = archive.len() as u32;
        if entry_count > config.max_entries {
            return Err(ArchiveInspectionError::TooManyEntries {
                count: entry_count,
                limit: config.max_entries,
            });
        }

        let mut collected: Vec<CollectedEntry> = Vec::new();

        for i in 0..archive.len() {
            let mut entry = match archive.by_index(i) {
                Ok(e) => e,
                Err(e) => {
                    warn!(
                        entry_index = i,
                        error = %e,
                        "Failed to read ZIP entry, skipping"
                    );
                    result.warnings.push(format!("entry {i}: read error: {e}"));
                    continue;
                }
            };

            let entry_name = entry.name().to_string();
            let uncompressed_size = entry.size();
            let compressed_size = entry.compressed_size();
            result.entries_seen += 1;

            // Sanitize path
            let _sanitized_path = sanitize_entry_path(&entry_name)?;

            // Skip directories
            if is_directory(&entry_name) {
                continue;
            }

            // Check for symlinks via Unix external attributes
            if let Some(mode) = entry.unix_mode() {
                if mode & 0o170000 == 0o120000 {
                    return Err(ArchiveInspectionError::SymlinkRejected(entry_name));
                }
            }

            // Check individual entry size
            if uncompressed_size > config.max_entry_uncompressed_bytes {
                return Err(ArchiveInspectionError::EntryTooLarge {
                    size: uncompressed_size,
                    limit: config.max_entry_uncompressed_bytes,
                });
            }

            // Check compression ratio
            if compressed_size > 0 {
                let ratio = uncompressed_size as f64 / compressed_size as f64;
                if ratio > config.max_compression_ratio {
                    return Err(ArchiveInspectionError::CompressionRatioTooHigh {
                        ratio,
                        limit: config.max_compression_ratio,
                    });
                }
            } else if uncompressed_size > 0 {
                result.warnings.push(format!(
                    "entry {i}: stored without compression: {entry_name}"
                ));
            }

            // Track totals
            result.total_uncompressed_bytes_seen = result
                .total_uncompressed_bytes_seen
                .saturating_add(uncompressed_size);

            if result.total_uncompressed_bytes_seen > config.max_total_uncompressed_bytes {
                return Err(ArchiveInspectionError::TotalSizeExceeded {
                    total: result.total_uncompressed_bytes_seen,
                    limit: config.max_total_uncompressed_bytes,
                });
            }

            // Detect nested archives by filename
            if is_nested_archive_filename(&entry_name) {
                result.nested_archives_seen += 1;
                if result.nested_archives_seen > config.max_nested_archives {
                    return Err(ArchiveInspectionError::TooManyNestedArchives {
                        count: result.nested_archives_seen,
                        limit: config.max_nested_archives,
                    });
                }
            }

            // Read entry content into owned bytes
            let mut entry_content = Vec::new();
            if let Err(e) = std::io::Read::read_to_end(&mut entry, &mut entry_content) {
                warn!(
                    entry_index = i,
                    error = %e,
                    "Failed to read ZIP entry content"
                );
                result
                    .warnings
                    .push(format!("entry {i}: content read error: {e}"));
                continue;
            }

            // Update max depth reached
            if current_depth > result.max_depth_reached {
                result.max_depth_reached = current_depth;
            }

            collected.push(CollectedEntry {
                entry_name,
                entry_index: i as u32,
                uncompressed_size,
                content: entry_content,
            });
        }

        // `archive` and all `ZipFile` borrows are dropped here, before any
        // `.await` point. This is critical for `Send`-safety.
        (collected, result, entry_count)
    };

    // ── Phase 2 (async): Scan collected entry content for malware ─────
    for ce in collected {
        let scan_context = ScanContext {
            filename: Some(ce.entry_name.clone()),
            declared_mime: None,
            detected_mime: None,
            size: Some(ce.uncompressed_size),
        };

        match scanner
            .scan_bytes_with_context(&ce.content, &scan_context)
            .await
        {
            Ok(scan_result) => {
                result.entries_scanned += 1;
                for m in scan_result.matches {
                    result.matches.push(ArchiveEntryMatch {
                        entry_index: ce.entry_index,
                        entry_path: ce.entry_name.clone(),
                        malware_match: m,
                    });
                }
            }
            Err(e) => {
                result
                    .warnings
                    .push(format!("entry {}: scan error: {e}", ce.entry_index));
            }
        }
    }

    // If we hit the entry limit during iteration, mark as truncated
    if entry_count >= config.max_entries {
        result.truncated = true;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    fn create_test_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut writer = ZipWriter::new(Cursor::new(&mut buf));
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            for (name, content) in entries {
                writer.start_file(name, options).unwrap();
                writer.write_all(content).unwrap();
            }
            writer.finish().unwrap();
        }
        buf
    }

    fn test_config() -> ArchiveInspectionConfig {
        ArchiveInspectionConfig {
            enabled: true,
            max_depth: 3,
            max_entries: 1000,
            max_total_uncompressed_bytes: 512 * 1024 * 1024,
            max_entry_uncompressed_bytes: 100 * 1024 * 1024,
            max_compression_ratio: 100.0,
            max_nested_archives: 5,
        }
    }

    fn test_scanner() -> MalwareScanner {
        MalwareScanner::new()
    }

    #[test]
    fn test_sanitize_entry_path_ok() {
        assert_eq!(sanitize_entry_path("file.txt").unwrap(), "file.txt");
        assert_eq!(sanitize_entry_path("dir/file.txt").unwrap(), "dir/file.txt");
        assert_eq!(
            sanitize_entry_path("dir\\file.txt").unwrap(),
            "dir/file.txt"
        );
    }

    #[test]
    fn test_sanitize_entry_path_traversal() {
        assert!(sanitize_entry_path("../etc/passwd").is_err());
        assert!(sanitize_entry_path("dir/../../etc/passwd").is_err());
        assert!(sanitize_entry_path("dir/..").is_err());
    }

    #[test]
    fn test_sanitize_entry_path_absolute() {
        assert!(sanitize_entry_path("/etc/passwd").is_err());
        assert!(sanitize_entry_path("/file.txt").is_err());
    }

    #[test]
    fn test_sanitize_entry_path_unc() {
        assert!(sanitize_entry_path("//server/share").is_err());
    }

    #[test]
    fn test_sanitize_entry_path_windows_drive() {
        assert!(sanitize_entry_path("C:\\Windows\\System32").is_err());
        assert!(sanitize_entry_path("D:/data/file.txt").is_err());
    }

    #[test]
    fn test_sanitize_entry_path_null_byte() {
        assert!(sanitize_entry_path("file\0.txt").is_err());
    }

    #[tokio::test]
    async fn test_inspect_benign_zip() {
        let data = create_test_zip(&[
            ("hello.txt", b"Hello, world!"),
            ("data.json", b"{\"key\": \"value\"}"),
        ]);
        let config = test_config();
        let scanner = test_scanner();
        let result = inspect_zip_archive(&data, &config, &scanner, 0, None)
            .await
            .unwrap();

        assert!(result.inspected);
        assert_eq!(result.archive_type, "zip");
        assert_eq!(result.entries_seen, 2);
        assert_eq!(result.entries_scanned, 2);
        assert!(result.matches.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[tokio::test]
    async fn test_inspect_zip_with_pe_entry() {
        // Create a ZIP with a PE executable entry
        let pe_data = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff";
        let data = create_test_zip(&[("malware.exe", pe_data)]);
        let config = test_config();
        let scanner = test_scanner();
        let result = inspect_zip_archive(&data, &config, &scanner, 0, None)
            .await
            .unwrap();

        assert!(result.inspected);
        assert!(!result.matches.is_empty());
        assert!(result.matches.iter().any(|m| m.entry_path == "malware.exe"));
    }

    #[tokio::test]
    async fn test_inspect_zip_traversal_rejected() {
        let data = create_test_zip(&[("../escape.txt", b"bad")]);
        let config = test_config();
        let scanner = test_scanner();
        let result = inspect_zip_archive(&data, &config, &scanner, 0, None).await;
        assert!(result.is_err());
        matches!(
            result.unwrap_err(),
            ArchiveInspectionError::PathTraversal(_)
        );
    }

    #[tokio::test]
    async fn test_inspect_zip_absolute_path_rejected() {
        let data = create_test_zip(&[("/etc/passwd", b"root:x:0:0:root:/root:/bin/bash")]);
        let config = test_config();
        let scanner = test_scanner();
        let result = inspect_zip_archive(&data, &config, &scanner, 0, None).await;
        assert!(result.is_err());
        matches!(result.unwrap_err(), ArchiveInspectionError::AbsolutePath(_));
    }

    #[tokio::test]
    async fn test_inspect_zip_too_many_entries() {
        let data = create_test_zip(&[("a.txt", b"a"), ("b.txt", b"b")]);
        let mut config = test_config();
        config.max_entries = 1;
        let scanner = test_scanner();

        let result = inspect_zip_archive(&data, &config, &scanner, 0, None).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ArchiveInspectionError::TooManyEntries { count, limit } => {
                assert_eq!(count, 2);
                assert_eq!(limit, 1);
            }
            other => panic!("Expected TooManyEntries, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_inspect_zip_entry_too_large() {
        let data = create_test_zip(&[("big.txt", b"x")]);
        let mut config = test_config();
        config.max_entry_uncompressed_bytes = 0;
        let scanner = test_scanner();

        let result = inspect_zip_archive(&data, &config, &scanner, 0, None).await;
        assert!(result.is_err());
        matches!(
            result.unwrap_err(),
            ArchiveInspectionError::EntryTooLarge { .. }
        );
    }

    #[tokio::test]
    async fn test_inspect_zip_depth_exceeded() {
        let data = create_test_zip(&[("nested.zip", b"not-a-real-zip")]);
        let config = test_config();
        let scanner = test_scanner();

        let result = inspect_zip_archive(&data, &config, &scanner, 4, None).await;
        assert!(result.is_err());
        matches!(
            result.unwrap_err(),
            ArchiveInspectionError::DepthExceeded { .. }
        );
    }

    #[tokio::test]
    async fn test_inspect_disabled() {
        let data = create_test_zip(&[("file.txt", b"hello")]);
        let mut config = test_config();
        config.enabled = false;
        let scanner = test_scanner();

        let result = inspect_zip_archive(&data, &config, &scanner, 0, None).await;
        assert!(matches!(
            result.unwrap_err(),
            ArchiveInspectionError::Disabled
        ));
    }

    #[tokio::test]
    async fn test_inspect_malformed_zip() {
        let data = b"not a zip file at all";
        let config = test_config();
        let scanner = test_scanner();

        let result = inspect_zip_archive(data, &config, &scanner, 0, None).await;
        assert!(result.is_err());
        matches!(result.unwrap_err(), ArchiveInspectionError::InvalidZip(_));
    }

    #[test]
    fn test_is_nested_archive_filename() {
        assert!(is_nested_archive_filename("test.zip"));
        assert!(is_nested_archive_filename("test.JAR"));
        assert!(is_nested_archive_filename("test.docx"));
        assert!(!is_nested_archive_filename("test.txt"));
        assert!(!is_nested_archive_filename("test.pdf"));
    }

    #[tokio::test]
    async fn test_inspect_total_size_exceeded() {
        let data = create_test_zip(&[("a.txt", b"hello world")]);
        let mut config = test_config();
        config.max_total_uncompressed_bytes = 5;
        let scanner = test_scanner();

        let result = inspect_zip_archive(&data, &config, &scanner, 0, None).await;
        assert!(result.is_err());
        matches!(
            result.unwrap_err(),
            ArchiveInspectionError::TotalSizeExceeded { .. }
        );
    }

    #[tokio::test]
    async fn test_inspect_empty_zip() {
        let data = create_test_zip(&[]);
        let config = test_config();
        let scanner = test_scanner();

        let result = inspect_zip_archive(&data, &config, &scanner, 0, None)
            .await
            .unwrap();
        assert!(result.inspected);
        assert_eq!(result.entries_seen, 0);
        assert!(result.matches.is_empty());
    }

    #[tokio::test]
    async fn test_inspect_directories_skipped() {
        let mut buf = Vec::new();
        {
            let mut writer = ZipWriter::new(Cursor::new(&mut buf));
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            writer.start_file("dir/", options).unwrap();
            writer.write_all(b"").unwrap();
            writer.start_file("dir/file.txt", options).unwrap();
            writer.write_all(b"content").unwrap();
            writer.finish().unwrap();
        }
        let config = test_config();
        let scanner = test_scanner();
        let result = inspect_zip_archive(&buf, &config, &scanner, 0, None)
            .await
            .unwrap();

        assert_eq!(result.entries_seen, 2);
        assert_eq!(result.entries_scanned, 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_inspect_zip_symlink_rejected() {
        let mut buf = Vec::new();
        {
            let mut writer = ZipWriter::new(Cursor::new(&mut buf));
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            writer
                .add_symlink("link.txt", "/etc/passwd", options)
                .unwrap();
            writer.finish().unwrap();
        }
        let config = test_config();
        let scanner = test_scanner();
        let result = inspect_zip_archive(&buf, &config, &scanner, 0, None).await;
        assert!(result.is_err());
        matches!(
            result.unwrap_err(),
            ArchiveInspectionError::SymlinkRejected(_)
        );
    }

    #[tokio::test]
    async fn test_inspect_zip_directory_not_symlink() {
        let mut buf = Vec::new();
        {
            let mut writer = ZipWriter::new(Cursor::new(&mut buf));
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            writer.start_file("dir/", options).unwrap();
            writer.write_all(b"").unwrap();
            writer.start_file("dir/file.txt", options).unwrap();
            writer.write_all(b"content").unwrap();
            writer.finish().unwrap();
        }
        let config = test_config();
        let scanner = test_scanner();
        let result = inspect_zip_archive(&buf, &config, &scanner, 0, None).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.entries_seen, 2);
        assert_eq!(result.entries_scanned, 1);
    }

    #[tokio::test]
    async fn test_inspect_zip_nested_archive_detected_not_inspected() {
        let inner_zip = create_test_zip(&[("inner.txt", b"inner content")]);
        let outer_zip =
            create_test_zip(&[("data.txt", b"outer content"), ("nested.zip", &inner_zip)]);
        let config = test_config();
        let scanner = test_scanner();
        let result = inspect_zip_archive(&outer_zip, &config, &scanner, 0, None)
            .await
            .unwrap();

        assert!(result.inspected);
        assert_eq!(result.entries_seen, 2);
        assert_eq!(result.entries_scanned, 2);
        assert_eq!(result.nested_archives_seen, 1);
        assert_eq!(result.max_depth_reached, 0);
        assert!(result.warnings.is_empty() || result.warnings.iter().all(|w| w.contains("nested")));
    }
}
