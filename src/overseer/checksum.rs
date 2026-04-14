use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;

use sha2::{Digest, Sha256};

pub fn compute_sha256(path: &PathBuf) -> std::io::Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    Ok(hex::encode(result))
}

pub fn compute_sha256_async(path: &PathBuf) -> std::io::Result<String> {
    compute_sha256(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_sha256_computation() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"hello world").unwrap();

        let hash = compute_sha256(&file.path().to_path_buf()).unwrap();

        // SHA-256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_empty_file() {
        let file = NamedTempFile::new().unwrap();

        let hash = compute_sha256(&file.path().to_path_buf()).unwrap();

        // SHA-256 of empty string
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
