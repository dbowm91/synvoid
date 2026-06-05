use serde::{de::DeserializeOwned, Serialize};
use std::io;

pub fn serialize<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    postcard::to_stdvec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    postcard::from_bytes(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn serialize_bincode<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    bincode::serialize(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn deserialize_bincode<T: DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    bincode::deserialize(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn serialized_size<T: Serialize>(value: &T) -> usize {
    bincode::serialized_size(value).unwrap_or(0) as usize
}
