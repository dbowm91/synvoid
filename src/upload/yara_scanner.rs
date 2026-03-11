use parking_lot::RwLock;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use yara_x::{Compiler, Rules, Scanner};

const DEFAULT_RULES: &str = include_str!("../../rules/default.yar");

static RULES_CACHE: RwLock<Option<Arc<Rules>>> = RwLock::new(None);

#[derive(Debug, Error)]
pub enum YaraError {
    #[error("YARA compilation error: {0}")]
    CompilationError(String),

    #[error("YARA scan error: {0}")]
    ScanError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Rules not loaded")]
    RulesNotLoaded,
}

#[derive(Debug, Clone)]
pub struct YaraMatch {
    pub rule_name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct YaraScanResult {
    pub matches: Vec<YaraMatch>,
    pub warning_count: usize,
}

impl YaraScanResult {
    pub fn is_clean(&self) -> bool {
        self.matches.is_empty()
    }

    pub fn has_high_severity(&self) -> bool {
        self.matches.iter().any(|m| {
            m.meta
                .get("severity")
                .map(|s| s.to_lowercase() == "high" || s.to_lowercase() == "critical")
                .unwrap_or(false)
        })
    }

    pub fn matched_rule_names(&self) -> Vec<String> {
        self.matches.iter().map(|m| m.rule_name.clone()).collect()
    }
}

#[derive(Clone)]
pub struct YaraScanner {
    rules: Arc<Rules>,
}

impl YaraScanner {
    pub fn with_embedded_rules() -> Result<Self, YaraError> {
        let cached = RULES_CACHE.read().clone();
        if let Some(rules) = cached {
            return Ok(Self { rules });
        }

        let rules = Self::compile_rules(DEFAULT_RULES)?;
        let scanner = Self {
            rules: Arc::new(rules),
        };

        *RULES_CACHE.write() = Some(scanner.rules.clone());
        Ok(scanner)
    }

    pub fn with_rules(rules_source: &str) -> Result<Self, YaraError> {
        let rules = Self::compile_rules(rules_source)?;
        Ok(Self {
            rules: Arc::new(rules),
        })
    }

    pub fn with_rules_from_file<P: AsRef<Path>>(path: P) -> Result<Self, YaraError> {
        let content = std::fs::read_to_string(path)?;
        Self::with_rules(&content)
    }

    pub fn with_rules_from_dir<P: AsRef<Path>>(dir: P) -> Result<Self, YaraError> {
        let dir = dir.as_ref();
        if !dir.exists() {
            return Self::with_embedded_rules();
        }

        let mut sources = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path
                .extension()
                .map(|e| e == "yar" || e == "yara")
                .unwrap_or(false)
            {
                let content = std::fs::read_to_string(&path)?;
                sources.push(content);
            }
        }

        if sources.is_empty() {
            return Self::with_embedded_rules();
        }

        let combined_source = sources.join("\n\n");
        Self::with_rules(&combined_source)
    }

    fn compile_rules(source: &str) -> Result<Rules, YaraError> {
        let mut compiler = Compiler::new();
        compiler
            .add_source(source)
            .map_err(|e| YaraError::CompilationError(e.to_string()))?;
        Ok(compiler.build())
    }

    pub fn scan_bytes(&self, data: &[u8]) -> Result<YaraScanResult, YaraError> {
        let mut scanner = Scanner::new(&self.rules);
        let results = scanner
            .scan(data)
            .map_err(|e| YaraError::ScanError(e.to_string()))?;

        let matches = results
            .matching_rules()
            .map(|rule| {
                let mut meta = std::collections::HashMap::new();
                for (key, value) in rule.metadata() {
                    let value_str = match value {
                        yara_x::MetaValue::Integer(i) => i.to_string(),
                        yara_x::MetaValue::Float(f) => f.to_string(),
                        yara_x::MetaValue::Bool(b) => b.to_string(),
                        yara_x::MetaValue::String(s) => s.to_string(),
                        _ => "unknown".to_string(),
                    };
                    meta.insert(key.to_string(), value_str);
                }

                let namespace = rule.namespace();
                let tags: Vec<String> = rule.tags().map(|t| t.identifier().to_string()).collect();

                YaraMatch {
                    rule_name: rule.identifier().to_string(),
                    namespace: namespace.to_string(),
                    tags,
                    meta,
                }
            })
            .collect();

        Ok(YaraScanResult {
            matches,
            warning_count: 0,
        })
    }

    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<YaraScanResult, YaraError> {
        use memmap2::Mmap;
        use std::fs::File;

        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        self.scan_bytes(&mmap)
    }

    pub fn scan_file_with_fallback<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<YaraScanResult, YaraError> {
        match self.scan_file(&path) {
            Ok(result) => Ok(result),
            Err(YaraError::IoError(_)) => {
                let content = std::fs::read(path)?;
                self.scan_bytes(&content)
            }
            Err(e) => Err(e),
        }
    }

    pub fn rules_count(&self) -> usize {
        0
    }
}

pub fn create_scanner_with_defaults() -> Result<YaraScanner, YaraError> {
    YaraScanner::with_embedded_rules()
}

pub fn preload_rules() -> Result<(), YaraError> {
    YaraScanner::with_embedded_rules()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let scanner = YaraScanner::with_embedded_rules().unwrap();
    }

    #[test]
    fn test_scan_clean_data() {
        let scanner = YaraScanner::with_embedded_rules().unwrap();
        let result = scanner.scan_bytes(b"Hello, World!").unwrap();
        assert!(result.is_clean());
    }

    #[test]
    fn test_scan_executable_signature() {
        let scanner = YaraScanner::with_embedded_rules().unwrap();
        let mz_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff";
        let result = scanner.scan_bytes(mz_header).unwrap();
        assert!(!result.is_clean());
        assert!(result
            .matched_rule_names()
            .iter()
            .any(|n| n.contains("executable")));
    }
}
