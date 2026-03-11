use std::io::{self, ErrorKind};

pub fn serialize<T: serde::Serialize>(value: &T) -> io::Result<Vec<u8>> {
    bincode::serialize(value).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
}

pub fn deserialize<T: serde::de::DeserializeOwned>(data: &[u8]) -> io::Result<T> {
    bincode::deserialize(data).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
}

pub fn serialize_bincode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, bincode::Error> {
    bincode::serialize(value)
}

pub fn deserialize_bincode<T: serde::de::DeserializeOwned>(
    data: &[u8],
) -> Result<T, bincode::Error> {
    bincode::deserialize(data)
}

pub fn serialized_size<T: serde::Serialize>(value: &T) -> Result<u64, bincode::Error> {
    bincode::serialized_size(value)
}
