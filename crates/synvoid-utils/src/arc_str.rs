use std::sync::Arc;

/// An atomically reference-counted string type.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Display for ArcStr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for ArcStr {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for ArcStr {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ArcStr {
    fn from(s: &str) -> Self {
        Self(Arc::from(s))
    }
}

impl From<String> for ArcStr {
    fn from(s: String) -> Self {
        Self(Arc::from(s))
    }
}

impl<'de> serde::Deserialize<'de> for ArcStr {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(ArcStr::new(s))
    }
}

impl serde::Serialize for ArcStr {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}
