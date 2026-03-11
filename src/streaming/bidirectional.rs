use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use crate::buffer::BufferPool;

pub type ProxyResult = Result<(), ProxyError>;

#[derive(Debug)]
pub enum ProxyError {
    ReadError(String),
    WriteError(String),
    ConnectionClosed,
    Timeout,
    Other(String),
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadError(e) => write!(f, "Read error: {}", e),
            Self::WriteError(e) => write!(f, "Write error: {}", e),
            Self::ConnectionClosed => write!(f, "Connection closed"),
            Self::Timeout => write!(f, "Operation timed out"),
            Self::Other(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for ProxyError {}

const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;
const DEFAULT_WRITE_BUFFER_THRESHOLD: usize = 8 * 1024;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub buffer_size: usize,
    pub write_buffer_threshold: usize,
    pub flush_interval_bytes: usize,
    pub use_native_copy: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            buffer_size: DEFAULT_BUFFER_SIZE,
            write_buffer_threshold: DEFAULT_WRITE_BUFFER_THRESHOLD,
            flush_interval_bytes: 32 * 1024,
            use_native_copy: true,
        }
    }
}

pub async fn copy_bidirectional<R1, W1, R2, W2>(
    client_read: &mut R1,
    client_write: &mut W1,
    upstream_read: &mut R2,
    upstream_write: &mut W2,
) -> ProxyResult
where
    R1: AsyncRead + Unpin + Send,
    W1: AsyncWrite + Unpin + Send,
    R2: AsyncRead + Unpin + Send,
    W2: AsyncWrite + Unpin + Send,
{
    copy_bidirectional_with_config(client_read, client_write, upstream_read, upstream_write, ProxyConfig::default()).await
}

pub async fn copy_bidirectional_with_config<R1, W1, R2, W2>(
    client_read: &mut R1,
    client_write: &mut W1,
    upstream_read: &mut R2,
    upstream_write: &mut W2,
    config: ProxyConfig,
) -> ProxyResult
where
    R1: AsyncRead + Unpin + Send,
    W1: AsyncWrite + Unpin + Send,
    R2: AsyncRead + Unpin + Send,
    W2: AsyncWrite + Unpin + Send,
{
    let buffer_size = config.buffer_size;
    let write_threshold = config.write_buffer_threshold;
    let flush_interval = config.flush_interval_bytes;

    let client_to_upstream = async {
        let mut buf = BufferPool::acquire(buffer_size);
        let mut write_buf = BufferPool::acquire(buffer_size);
        let mut write_pending: usize = 0;
        let mut total: u64 = 0;
        let mut last_flush_at: u64 = 0;
        
        loop {
            match client_read.read(buf.as_mut_slice()).await {
                Ok(0) => {
                    if write_pending > 0 {
                        upstream_write.write_all(&write_buf.as_slice()[..write_pending]).await
                            .map_err(|e| ProxyError::WriteError(e.to_string()))?;
                        let _ = upstream_write.flush().await;
                    }
                    break Ok(total);
                }
                Ok(n) => {
                    total += n as u64;
                    
                    if n < write_threshold && write_pending + n <= buffer_size {
                        write_buf.as_mut_slice()[write_pending..write_pending + n]
                            .copy_from_slice(&buf.as_slice()[..n]);
                        write_pending += n;
                        
                        if write_pending >= flush_interval || total - last_flush_at >= flush_interval as u64 {
                            upstream_write.write_all(&write_buf.as_slice()[..write_pending]).await
                                .map_err(|e| ProxyError::WriteError(e.to_string()))?;
                            let _ = upstream_write.flush().await;
                            write_pending = 0;
                            last_flush_at = total;
                        }
                    } else {
                        if write_pending > 0 {
                            upstream_write.write_all(&write_buf.as_slice()[..write_pending]).await
                                .map_err(|e| ProxyError::WriteError(e.to_string()))?;
                            write_pending = 0;
                        }
                        
                        upstream_write.write_all(&buf.as_slice()[..n]).await
                            .map_err(|e| ProxyError::WriteError(e.to_string()))?;
                        
                        if total - last_flush_at >= flush_interval as u64 {
                            let _ = upstream_write.flush().await;
                            last_flush_at = total;
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => break Err(ProxyError::ReadError(e.to_string())),
            }
        }
    };

    let upstream_to_client = async {
        let mut buf = BufferPool::acquire(buffer_size);
        let mut write_buf = BufferPool::acquire(buffer_size);
        let mut write_pending: usize = 0;
        let mut total: u64 = 0;
        let mut last_flush_at: u64 = 0;
        
        loop {
            match upstream_read.read(buf.as_mut_slice()).await {
                Ok(0) => {
                    if write_pending > 0 {
                        client_write.write_all(&write_buf.as_slice()[..write_pending]).await
                            .map_err(|e| ProxyError::WriteError(e.to_string()))?;
                        let _ = client_write.flush().await;
                    }
                    break Ok(total);
                }
                Ok(n) => {
                    total += n as u64;
                    
                    if n < write_threshold && write_pending + n <= buffer_size {
                        write_buf.as_mut_slice()[write_pending..write_pending + n]
                            .copy_from_slice(&buf.as_slice()[..n]);
                        write_pending += n;
                        
                        if write_pending >= flush_interval || total - last_flush_at >= flush_interval as u64 {
                            client_write.write_all(&write_buf.as_slice()[..write_pending]).await
                                .map_err(|e| ProxyError::WriteError(e.to_string()))?;
                            let _ = client_write.flush().await;
                            write_pending = 0;
                            last_flush_at = total;
                        }
                    } else {
                        if write_pending > 0 {
                            client_write.write_all(&write_buf.as_slice()[..write_pending]).await
                                .map_err(|e| ProxyError::WriteError(e.to_string()))?;
                            write_pending = 0;
                        }
                        
                        client_write.write_all(&buf.as_slice()[..n]).await
                            .map_err(|e| ProxyError::WriteError(e.to_string()))?;
                        
                        if total - last_flush_at >= flush_interval as u64 {
                            let _ = client_write.flush().await;
                            last_flush_at = total;
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => break Err(ProxyError::ReadError(e.to_string())),
            }
        }
    };

    let result = tokio::try_join!(client_to_upstream, upstream_to_client);
    
    let _ = client_write.flush().await;
    let _ = upstream_write.flush().await;
    
    match result {
        Ok((_, _)) => Ok(()),
        Err(e) => Err(e),
    }
}

pub async fn copy_bidirectional_native<R1, R2>(
    client: &mut R1,
    upstream: &mut R2,
) -> Result<(u64, u64), ProxyError>
where
    R1: AsyncRead + AsyncWrite + Unpin + Send,
    R2: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (client_bytes, upstream_bytes) = tokio::io::copy_bidirectional(client, upstream)
        .await
        .map_err(|e| ProxyError::Other(e.to_string()))?;
    
    Ok((client_bytes, upstream_bytes))
}

pub async fn copy_bidirectional_auto<R1, W1, R2, W2>(
    client_read: &mut R1,
    client_write: &mut W1,
    upstream_read: &mut R2,
    upstream_write: &mut W2,
    config: ProxyConfig,
) -> ProxyResult
where
    R1: AsyncRead + Unpin + Send,
    W1: AsyncWrite + Unpin + Send,
    R2: AsyncRead + Unpin + Send,
    W2: AsyncWrite + Unpin + Send,
{
    if config.use_native_copy {
        let client = tokio::io::join(client_read, client_write);
        let upstream = tokio::io::join(upstream_read, upstream_write);
        let (mut client_combined, mut upstream_combined) = (client, upstream);
        copy_bidirectional_native(&mut client_combined, &mut upstream_combined).await?;
        Ok(())
    } else {
        copy_bidirectional_with_config(client_read, client_write, upstream_read, upstream_write, config).await
    }
}

pub async fn copy_bidirectional_zero_copy<R1, W1, R2, W2>(
    client_read: &mut R1,
    client_write: &mut W1,
    upstream_read: &mut R2,
    upstream_write: &mut W2,
    buffer_size: usize,
) -> ProxyResult
where
    R1: AsyncRead + Unpin + Send,
    W1: AsyncWrite + Unpin + Send,
    R2: AsyncRead + Unpin + Send,
    W2: AsyncWrite + Unpin + Send,
{
    let client_to_upstream = async {
        let mut buf = BufferPool::acquire(buffer_size);
        loop {
            match client_read.read(buf.as_mut_slice()).await {
                Ok(0) => break Ok(()),
                Ok(n) => {
                    upstream_write.write_all(&buf.as_slice()[..n]).await
                        .map_err(|e| ProxyError::WriteError(e.to_string()))?;
                }
                Err(e) => break Err(ProxyError::ReadError(e.to_string())),
            }
        }
    };

    let upstream_to_client = async {
        let mut buf = BufferPool::acquire(buffer_size);
        loop {
            match upstream_read.read(buf.as_mut_slice()).await {
                Ok(0) => break Ok(()),
                Ok(n) => {
                    client_write.write_all(&buf.as_slice()[..n]).await
                        .map_err(|e| ProxyError::WriteError(e.to_string()))?;
                }
                Err(e) => break Err(ProxyError::ReadError(e.to_string())),
            }
        }
    };

    let result = tokio::try_join!(client_to_upstream, upstream_to_client);
    
    match result {
        Ok((_, _)) => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_copy_bidirectional() {
        let (client_a, upstream_a) = duplex(1024);
        let (mut client_b, mut upstream_b) = duplex(1024);

        let proxy_handle = tokio::spawn(async move {
            let (mut cr, mut cw) = tokio::io::split(client_a);
            let (mut ur, mut uw) = tokio::io::split(upstream_a);
            copy_bidirectional(&mut cr, &mut uw, &mut ur, &mut cw).await
        });

        client_b.write_all(b"hello upstream").await.unwrap();
        let mut buf = vec![0u8; 20];
        let n = upstream_b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello upstream");

        upstream_b.write_all(b"hello client").await.unwrap();
        let n = client_b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello client");

        drop(client_b);
        drop(upstream_b);

        let result = proxy_handle.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_copy_bidirectional_with_config() {
        let (client_a, upstream_a) = duplex(64 * 1024);
        let (mut client_b, mut upstream_b) = duplex(64 * 1024);

        let config = ProxyConfig {
            buffer_size: 8 * 1024,
            write_buffer_threshold: 1024,
            flush_interval_bytes: 4 * 1024,
            use_native_copy: false,
        };

        let proxy_handle = tokio::spawn(async move {
            let (mut cr, mut cw) = tokio::io::split(client_a);
            let (mut ur, mut uw) = tokio::io::split(upstream_a);
            copy_bidirectional_with_config(&mut cr, &mut uw, &mut ur, &mut cw, config).await
        });

        let test_data = vec![0xABu8; 16 * 1024];
        client_b.write_all(&test_data).await.unwrap();
        
        let mut buf = vec![0u8; 16 * 1024];
        let mut total_read = 0;
        while total_read < 16 * 1024 {
            let n = upstream_b.read(&mut buf[total_read..]).await.unwrap();
            total_read += n;
        }
        assert_eq!(&buf[..], &test_data[..]);

        drop(client_b);
        drop(upstream_b);

        let result = proxy_handle.await.unwrap();
        assert!(result.is_ok());
    }
}
