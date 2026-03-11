use std::io::{self, Read, Write};

use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
pub const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;

pub fn write_message_sync<W, T>(writer: &mut W, msg: &T) -> io::Result<()>
where
    W: Write,
    T: Serialize,
{
    let data = bincode::serialize(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    if data.len() > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }

    let len = data.len() as u32;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&data)?;
    writer.flush()?;
    Ok(())
}

pub fn read_message_sync<R, T>(reader: &mut R, buffer: &mut Vec<u8>) -> io::Result<Option<T>>
where
    R: Read,
    T: DeserializeOwned,
{
    if buffer.len() < 4 {
        let mut temp_buf = [0u8; 4096];
        match reader.read(&mut temp_buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed",
                ))
            }
            Ok(n) => {
                buffer.extend_from_slice(&temp_buf[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        }
    }

    if buffer.len() < 4 {
        return Ok(None);
    }

    let len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }

    let total_needed = 4 + len;
    if buffer.len() < total_needed {
        let mut temp_buf = [0u8; 4096];
        loop {
            match reader.read(&mut temp_buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed",
                    ))
                }
                Ok(n) => {
                    buffer.extend_from_slice(&temp_buf[..n]);
                    if buffer.len() >= total_needed {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            }
        }
    }

    if buffer.len() < total_needed {
        return Ok(None);
    }

    let data = buffer[4..total_needed].to_vec();
    buffer.drain(..total_needed);

    let msg: T = bincode::deserialize(&data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(Some(msg))
}

pub fn read_exact_message_sync<R, T>(reader: &mut R) -> io::Result<T>
where
    R: Read,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }

    let mut data = vec![0u8; len];
    reader.read_exact(&mut data)?;

    let msg: T = bincode::deserialize(&data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(msg)
}

pub async fn write_message<W, T>(writer: &mut W, msg: &T) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let data = bincode::serialize(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    if data.len() > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }

    let len = data.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&data).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_message<R, T>(reader: &mut R, buffer: &mut Vec<u8>) -> io::Result<Option<T>>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    if buffer.len() < 4 {
        let mut temp_buf = [0u8; 4096];
        match reader.read(&mut temp_buf).await {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed",
                ))
            }
            Ok(n) => {
                buffer.extend_from_slice(&temp_buf[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        }
    }

    if buffer.len() < 4 {
        return Ok(None);
    }

    let len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }

    let total_needed = 4 + len;
    if buffer.len() < total_needed {
        let mut temp_buf = [0u8; 4096];
        loop {
            match reader.read(&mut temp_buf).await {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed",
                    ))
                }
                Ok(n) => {
                    buffer.extend_from_slice(&temp_buf[..n]);
                    if buffer.len() >= total_needed {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            }
        }
    }

    if buffer.len() < total_needed {
        return Ok(None);
    }

    let data = buffer[4..total_needed].to_vec();
    buffer.drain(..total_needed);

    let msg: T = bincode::deserialize(&data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(Some(msg))
}

pub async fn read_message_with_timeout<R, T>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
    timeout_ms: u64,
) -> io::Result<Option<T>>
where
    R: AsyncRead + Unpin + std::marker::Unpin,
    T: DeserializeOwned,
{
    use tokio::time::{timeout, Duration};
    use rand::Rng;
    
    let result = timeout(
        Duration::from_millis(timeout_ms),
        async {
            let mut sleep_duration = 1u64;
            let max_sleep = 50u64;
            loop {
                match read_message(reader, buffer).await {
                    Ok(Some(msg)) => return Ok(Some(msg)),
                    Ok(None) => {
                        let jitter = rand::rng().random_range(0..sleep_duration / 2 + 1);
                        tokio::time::sleep(Duration::from_millis(sleep_duration + jitter)).await;
                        sleep_duration = (sleep_duration * 2).min(max_sleep);
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    ).await;

    match result {
        Ok(r) => r,
        Err(_) => Ok(None),
    }
}

pub fn encode_pipe_name(name: &str) -> Vec<u16> {
    format!("\\\\.\\pipe\\{}", name)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

pub fn endpoint_to_pipe_name(endpoint: &str) -> String {
    format!("\\\\.\\pipe\\maluwaf-{}", endpoint)
}

pub fn endpoint_to_socket_path(endpoint: &str) -> std::path::PathBuf {
    super::socket_path::get_secure_socket_path(&format!("{}.sock", endpoint))
}
