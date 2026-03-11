use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct FileSignature {
    pub magic_bytes: &'static [u8],
    pub mime_types: Vec<&'static str>,
    pub category: FileCategory,
    pub offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileCategory {
    Image,
    Video,
    Audio,
    Document,
    Archive,
    Executable,
    Font,
    Code,
    Unknown,
}

impl FileCategory {
    pub fn is_executable(&self) -> bool {
        matches!(self, FileCategory::Executable | FileCategory::Code)
    }
}

pub struct SignatureRegistry {
    signatures: Vec<FileSignature>,
    magic_to_mime: HashMap<Vec<u8>, Vec<&'static str>>,
}

impl Default for SignatureRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureRegistry {
    pub fn new() -> Self {
        let signatures = Self::default_signatures();
        let magic_to_mime = Self::build_magic_map(&signatures);

        Self {
            signatures,
            magic_to_mime,
        }
    }

    fn default_signatures() -> Vec<FileSignature> {
        vec![
            FileSignature {
                magic_bytes: b"\xFF\xD8\xFF",
                mime_types: vec!["image/jpeg"],
                category: FileCategory::Image,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\x89PNG\r\n\x1a\n",
                mime_types: vec!["image/png"],
                category: FileCategory::Image,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"GIF87a",
                mime_types: vec!["image/gif"],
                category: FileCategory::Image,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"GIF89a",
                mime_types: vec!["image/gif"],
                category: FileCategory::Image,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"RIFF",
                mime_types: vec!["image/webp", "audio/wav", "video/webm"],
                category: FileCategory::Image,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\x00\x00\x01\x00",
                mime_types: vec!["image/x-icon"],
                category: FileCategory::Image,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"BM",
                mime_types: vec!["image/bmp"],
                category: FileCategory::Image,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"II\x2a\x00",
                mime_types: vec!["image/tiff"],
                category: FileCategory::Image,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"MM\x00\x2a",
                mime_types: vec!["image/tiff"],
                category: FileCategory::Image,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\x00\x00\x00\x18\x66\x74\x79\x70",
                mime_types: vec!["image/avif"],
                category: FileCategory::Image,
                offset: 4,
            },
            FileSignature {
                magic_bytes: b"ftypavif",
                mime_types: vec!["image/avif"],
                category: FileCategory::Image,
                offset: 4,
            },
            FileSignature {
                magic_bytes: b"ftypmif1",
                mime_types: vec!["image/heic", "image/heif"],
                category: FileCategory::Image,
                offset: 4,
            },
            FileSignature {
                magic_bytes: b"ftypMSF1",
                mime_types: vec!["image/heic", "image/heif"],
                category: FileCategory::Image,
                offset: 4,
            },
            FileSignature {
                magic_bytes: b"ftypheic",
                mime_types: vec!["image/heic"],
                category: FileCategory::Image,
                offset: 4,
            },
            FileSignature {
                magic_bytes: b"%PDF",
                mime_types: vec!["application/pdf"],
                category: FileCategory::Document,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
                mime_types: vec![
                    "application/msword",
                    "application/vnd.ms-excel",
                    "application/vnd.ms-powerpoint",
                ],
                category: FileCategory::Document,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"PK\x03\x04",
                mime_types: vec![
                    "application/zip",
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                ],
                category: FileCategory::Archive,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"PK\x05\x06",
                mime_types: vec!["application/zip"],
                category: FileCategory::Archive,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"PK\x07\x08",
                mime_types: vec!["application/zip"],
                category: FileCategory::Archive,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"Rar!\x1a\x07",
                mime_types: vec!["application/x-rar-compressed"],
                category: FileCategory::Archive,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\x1f\x8b",
                mime_types: vec!["application/gzip"],
                category: FileCategory::Archive,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"BZh",
                mime_types: vec!["application/x-bzip2"],
                category: FileCategory::Archive,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"7z\xbc\xaf\x27\x1c",
                mime_types: vec!["application/x-7z-compressed"],
                category: FileCategory::Archive,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"MZ\x90",
                mime_types: vec!["application/x-msdownload"],
                category: FileCategory::Executable,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\x7fELF",
                mime_types: vec!["application/x-executable"],
                category: FileCategory::Executable,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\xca\xfe\xba\xbe",
                mime_types: vec!["application/x-java-applet"],
                category: FileCategory::Executable,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\xfe\xed\xfa\xce",
                mime_types: vec!["application/x-mach-binary"],
                category: FileCategory::Executable,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\xfe\xed\xfa\xcf",
                mime_types: vec!["application/x-mach-binary"],
                category: FileCategory::Executable,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\xce\xfa\xed\xfe",
                mime_types: vec!["application/x-mach-binary"],
                category: FileCategory::Executable,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\xcf\xfa\xed\xfe",
                mime_types: vec!["application/x-mach-binary"],
                category: FileCategory::Executable,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"wOFF",
                mime_types: vec!["font/woff"],
                category: FileCategory::Font,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"wOF2",
                mime_types: vec!["font/woff2"],
                category: FileCategory::Font,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"OTTO",
                mime_types: vec!["font/otf"],
                category: FileCategory::Font,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"true",
                mime_types: vec!["font/ttf"],
                category: FileCategory::Font,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\x00\x01\x00\x00",
                mime_types: vec!["font/ttf"],
                category: FileCategory::Font,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\x4f\x54\x54\x4f",
                mime_types: vec!["font/otf"],
                category: FileCategory::Font,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\x1aE\xdf\xa3",
                mime_types: vec!["application/x-7z-compressed"],
                category: FileCategory::Archive,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"gzip",
                mime_types: vec!["application/gzip"],
                category: FileCategory::Archive,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\x1f\x8b\x08",
                mime_types: vec!["application/gzip"],
                category: FileCategory::Archive,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\x00\x00\x00",
                mime_types: vec!["image/avif"],
                category: FileCategory::Image,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\x00\x00\x00\x18\x66\x74\x79\x70",
                mime_types: vec!["image/avif"],
                category: FileCategory::Image,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"ID3",
                mime_types: vec!["audio/mpeg"],
                category: FileCategory::Audio,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\xff\xfb",
                mime_types: vec!["audio/mpeg"],
                category: FileCategory::Audio,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\xff\xfa",
                mime_types: vec!["audio/mpeg"],
                category: FileCategory::Audio,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\xff\xf3",
                mime_types: vec!["audio/mpeg"],
                category: FileCategory::Audio,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\xff\xf2",
                mime_types: vec!["audio/mpeg"],
                category: FileCategory::Audio,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"OggS",
                mime_types: vec!["audio/ogg", "video/ogg"],
                category: FileCategory::Audio,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"fLaC",
                mime_types: vec!["audio/flac"],
                category: FileCategory::Audio,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"RIFF",
                mime_types: vec!["audio/wav", "video/avi"],
                category: FileCategory::Audio,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\x00\x00\x00\x14ftypmp4",
                mime_types: vec!["video/mp4"],
                category: FileCategory::Video,
                offset: 4,
            },
            FileSignature {
                magic_bytes: b"\x00\x00\x00\x08",
                mime_types: vec!["video/mp4"],
                category: FileCategory::Video,
                offset: 4,
            },
            FileSignature {
                magic_bytes: b"\x00\x00\x00\x1cftypisom",
                mime_types: vec!["video/mp4"],
                category: FileCategory::Video,
                offset: 4,
            },
            FileSignature {
                magic_bytes: b"\x00\x00\x00\x20ftypavc1",
                mime_types: vec!["video/mp4"],
                category: FileCategory::Video,
                offset: 4,
            },
            FileSignature {
                magic_bytes: b"\x1aE\xdf\xa3",
                mime_types: vec!["video/x-matroska"],
                category: FileCategory::Video,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"#!",
                mime_types: vec!["text/x-shellscript"],
                category: FileCategory::Code,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"#!/",
                mime_types: vec!["text/x-shellscript"],
                category: FileCategory::Code,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"<?xml",
                mime_types: vec!["application/xml", "text/xml"],
                category: FileCategory::Document,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\xef\xbb\xbf",
                mime_types: vec!["text/plain"],
                category: FileCategory::Document,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\xff\xfe",
                mime_types: vec!["text/plain"],
                category: FileCategory::Document,
                offset: 0,
            },
            FileSignature {
                magic_bytes: b"\xfe\xff",
                mime_types: vec!["text/plain"],
                category: FileCategory::Document,
                offset: 0,
            },
        ]
    }

    fn build_magic_map(signatures: &[FileSignature]) -> HashMap<Vec<u8>, Vec<&'static str>> {
        let mut map = HashMap::new();
        for sig in signatures {
            map.insert(sig.magic_bytes.to_vec(), sig.mime_types.clone());
        }
        map
    }

    pub fn detect(&self, data: &[u8]) -> Option<SignatureMatch> {
        if data.len() < 4 {
            return None;
        }

        for signature in &self.signatures {
            let offset = signature.offset;
            if data.len() > offset + signature.magic_bytes.len() {
                let slice = &data[offset..offset + signature.magic_bytes.len()];
                if slice == signature.magic_bytes {
                    return Some(SignatureMatch {
                        detected_mime_types: signature.mime_types.clone(),
                        category: signature.category,
                        confidence: SignatureConfidence::High,
                    });
                }
            }
        }

        None
    }

    pub fn verify_mime(&self, data: &[u8], claimed_mime: &str) -> SignatureVerificationResult {
        let detected = self.detect(data);

        match detected {
            Some(signature_match) => {
                let claimed_normalized = claimed_mime.to_lowercase();
                let matches = signature_match
                    .detected_mime_types
                    .iter()
                    .any(|m| *m == claimed_normalized);

                if matches {
                    SignatureVerificationResult::Valid {
                        detected_mime: signature_match
                            .detected_mime_types
                            .first()
                            .unwrap()
                            .to_string(),
                    }
                } else {
                    SignatureVerificationResult::Mismatch {
                        claimed: claimed_mime.to_string(),
                        detected: signature_match.detected_mime_types,
                        category: signature_match.category,
                    }
                }
            }
            None => SignatureVerificationResult::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SignatureMatch {
    pub detected_mime_types: Vec<&'static str>,
    pub category: FileCategory,
    pub confidence: SignatureConfidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureConfidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone)]
pub enum SignatureVerificationResult {
    Valid {
        detected_mime: String,
    },
    Mismatch {
        claimed: String,
        detected: Vec<&'static str>,
        category: FileCategory,
    },
    Unknown,
}

impl SignatureVerificationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, SignatureVerificationResult::Valid { .. })
    }

    pub fn is_mismatch(&self) -> bool {
        matches!(self, SignatureVerificationResult::Mismatch { .. })
    }
}

pub fn create_signature_registry() -> SignatureRegistry {
    SignatureRegistry::new()
}

pub static SIGNATURE_REGISTRY: once_cell::sync::Lazy<Arc<SignatureRegistry>> =
    once_cell::sync::Lazy::new(|| Arc::new(SignatureRegistry::new()));

pub fn global_signature_registry() -> &'static Arc<SignatureRegistry> {
    &SIGNATURE_REGISTRY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_jpeg() {
        let registry = SignatureRegistry::new();
        let jpeg_data = b"\xFF\xD8\xFF\xE0\x00\x10JFIF";
        let result = registry.detect(jpeg_data);
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.detected_mime_types.contains(&"image/jpeg"));
    }

    #[test]
    fn test_detect_png() {
        let registry = SignatureRegistry::new();
        let png_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        let result = registry.detect(png_data);
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.detected_mime_types.contains(&"image/png"));
    }

    #[test]
    fn test_detect_pdf() {
        let registry = SignatureRegistry::new();
        let pdf_data = b"%PDF-1.4";
        let result = registry.detect(pdf_data);
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.detected_mime_types.contains(&"application/pdf"));
    }

    #[test]
    fn test_detect_zip() {
        let registry = SignatureRegistry::new();
        let zip_data = b"PK\x03\x04\x14\x00\x00\x00";
        let result = registry.detect(zip_data);
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.detected_mime_types.contains(&"application/zip"));
    }

    #[test]
    fn test_detect_executable() {
        let registry = SignatureRegistry::new();
        let exe_data = b"MZ\x90\x00\x03\x00\x00\x00";
        let result = registry.detect(exe_data);
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result
            .detected_mime_types
            .contains(&"application/x-msdownload"));
    }

    #[test]
    fn test_detect_elf() {
        let registry = SignatureRegistry::new();
        let elf_data = b"\x7fELF\x02\x01\x01\x00";
        let result = registry.detect(elf_data);
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result
            .detected_mime_types
            .contains(&"application/x-executable"));
    }

    #[test]
    fn test_verify_mime_match() {
        let registry = SignatureRegistry::new();
        let jpeg_data = b"\xFF\xD8\xFF\xE0\x00\x10JFIF";
        let result = registry.verify_mime(jpeg_data, "image/jpeg");
        assert!(result.is_valid());
    }

    #[test]
    fn test_verify_mime_mismatch() {
        let registry = SignatureRegistry::new();
        let png_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        let result = registry.verify_mime(png_data, "image/jpeg");
        assert!(result.is_mismatch());
    }

    #[test]
    fn test_category_classification() {
        let registry = SignatureRegistry::new();

        let exe_data = b"MZ\x90\x00\x03\x00\x00\x00";
        let result = registry.detect(exe_data).unwrap();
        assert!(result.category.is_executable());

        let jpeg_data = b"\xFF\xD8\xFF\xE0";
        let result = registry.detect(jpeg_data).unwrap();
        assert!(!result.category.is_executable());
    }
}
