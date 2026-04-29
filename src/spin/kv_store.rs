use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct SpinKvEntry {
    pub value: Vec<u8>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct SpinKvStore {
    store: Arc<RwLock<HashMap<String, SpinKvEntry>>>,
}

impl SpinKvStore {
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let store = self.store.read();
        if let Some(entry) = store.get(key) {
            if let Some(expires_at) = entry.expires_at {
                let now = crate::utils::safe_unix_timestamp();
                if now > expires_at {
                    return None;
                }
            }
            Some(entry.value.clone())
        } else {
            None
        }
    }

    pub fn set(&self, key: &str, value: Vec<u8>, expires_at: Option<u64>) {
        let mut store = self.store.write();
        let now = crate::utils::safe_unix_timestamp();
        store.insert(
            key.to_string(),
            SpinKvEntry {
                value,
                created_at: now,
                expires_at,
            },
        );
    }

    pub fn delete(&self, key: &str) -> bool {
        self.store.write().remove(key).is_some()
    }

    pub fn exists(&self, key: &str) -> bool {
        let store = self.store.read();
        if let Some(entry) = store.get(key) {
            if let Some(expires_at) = entry.expires_at {
                let now = crate::utils::safe_unix_timestamp();
                if now > expires_at {
                    return false;
                }
            }
            true
        } else {
            false
        }
    }

    pub fn list_keys(&self, prefix: Option<&str>) -> Vec<String> {
        let store = self.store.read();
        store
            .keys()
            .filter(|k| {
                if let Some(prefix) = prefix {
                    k.starts_with(prefix)
                } else {
                    true
                }
            })
            .cloned()
            .collect()
    }

    pub fn clear(&self) {
        self.store.write().clear();
    }

    pub fn len(&self) -> usize {
        self.store.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.store.read().is_empty()
    }
}

impl Default for SpinKvStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum SpinKvStoreError {
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Store error: {0}")]
    StoreError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kv_store_basic() {
        let store = SpinKvStore::new();
        store.set("key1", b"value1".to_vec(), None);
        assert_eq!(store.get("key1"), Some(b"value1".to_vec()));
    }

    #[test]
    fn test_kv_store_delete() {
        let store = SpinKvStore::new();
        store.set("key1", b"value1".to_vec(), None);
        assert!(store.delete("key1"));
        assert_eq!(store.get("key1"), None);
    }

    #[test]
    fn test_kv_store_exists() {
        let store = SpinKvStore::new();
        store.set("key1", b"value1".to_vec(), None);
        assert!(store.exists("key1"));
        assert!(!store.exists("nonexistent"));
    }

    #[test]
    fn test_kv_store_list_keys() {
        let store = SpinKvStore::new();
        store.set("foo:bar", b"value".to_vec(), None);
        store.set("foo:baz", b"value".to_vec(), None);
        store.set("other:key", b"value".to_vec(), None);

        let foo_keys = store.list_keys(Some("foo:"));
        assert_eq!(foo_keys.len(), 2);
    }
}
