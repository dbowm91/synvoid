// Compression handling is integrated into mod.rs
// This module provides additional compression utilities if needed

use std::path::Path;

pub fn find_precompressed_path(
    path: &Path,
    accept_encoding: &str,
) -> Option<(std::path::PathBuf, &'static str)> {
    let extension = path.extension()?.to_str()?;
    let stem = path.file_stem()?.to_str()?;

    let br_path = path.with_file_name(format!("{}.{}.br", stem, extension));
    if accept_encoding.contains("br") && br_path.exists() {
        return Some((br_path, "br"));
    }

    let gz_path = path.with_file_name(format!("{}.{}.gz", stem, extension));
    if accept_encoding.contains("gzip") && gz_path.exists() {
        return Some((gz_path, "gzip"));
    }

    None
}
