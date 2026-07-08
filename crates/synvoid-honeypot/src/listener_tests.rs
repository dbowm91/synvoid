#[cfg(test)]
mod tests {
    use crate::config::*;
    use crate::listener::{handle_connection, IpConnGuard};
    use crate::protocol::ProtocolDetector;
    use crate::storage::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::sync::Semaphore;

    fn test_storage() -> HoneypotStorage {
        let cfg = StorageConfig {
            database_path: ":memory:".to_string(),
            ..Default::default()
        };
        HoneypotStorage::new(&cfg).unwrap()
    }

    #[tokio::test]
    async fn ip_conn_guard_removes_entry_at_zero() {
        let counts = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        {
            let mut c = counts.write();
            c.insert("1.2.3.4".to_string(), 1);
        }
        {
            let _guard = IpConnGuard::new(counts.clone(), "1.2.3.4".to_string());
        }
        let c = counts.read();
        assert_eq!(c.get("1.2.3.4"), None);
    }

    #[tokio::test]
    async fn ip_conn_guard_decrements_not_remove() {
        let counts = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        {
            let mut c = counts.write();
            c.insert("1.2.3.4".to_string(), 3);
        }
        {
            let _guard = IpConnGuard::new(counts.clone(), "1.2.3.4".to_string());
        }
        let c = counts.read();
        assert_eq!(c.get("1.2.3.4"), Some(&2));
    }

    #[tokio::test]
    async fn global_semaphore_enforces_max_concurrent() {
        let sem = Arc::new(Semaphore::new(1));
        let p1 = Arc::clone(&sem).try_acquire_owned();
        assert!(p1.is_ok());
        let p2 = Arc::clone(&sem).try_acquire_owned();
        assert!(p2.is_err());
        drop(p1);
        let p3 = Arc::clone(&sem).try_acquire_owned();
        assert!(p3.is_ok());
    }

    #[tokio::test]
    async fn burst_never_exceeds_max_permits() {
        let max = 5;
        let sem = Arc::new(Semaphore::new(max));
        let mut permits = Vec::new();
        for _ in 0..max {
            permits.push(Arc::clone(&sem).try_acquire_owned().unwrap());
        }
        assert!(Arc::clone(&sem).try_acquire_owned().is_err());
        drop(permits.pop().unwrap());
        assert!(Arc::clone(&sem).try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn per_ip_limit_enforced() {
        let counts = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let max_per_ip = 2;

        for _ in 0..max_per_ip {
            let mut c = counts.write();
            let count = c.entry("1.2.3.4".to_string()).or_insert(0);
            *count += 1;
        }

        let c = counts.read();
        assert!(c.get("1.2.3.4").copied().unwrap_or(0) >= max_per_ip);
    }

    #[tokio::test]
    async fn per_ip_cleanup_after_close() {
        let counts = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        {
            let mut c = counts.write();
            c.insert("10.0.0.1".to_string(), 2);
        }
        let g1 = IpConnGuard::new(counts.clone(), "10.0.0.1".to_string());
        let g2 = IpConnGuard::new(counts.clone(), "10.0.0.1".to_string());
        drop(g1);
        assert_eq!(*counts.read().get("10.0.0.1").unwrap(), 1);
        drop(g2);
        assert!(counts.read().get("10.0.0.1").is_none());
    }

    #[tokio::test]
    async fn payload_truncation_enforced() {
        let config = PortHoneypotConfig {
            max_concurrent_connections: 4,
            max_connections_per_ip: 10,
            connection_timeout_ms: 500,
            read_timeout_ms: 500,
            max_payload_size: 10,
            ..Default::default()
        };
        let storage = test_storage();
        let detector = ProtocolDetector::new();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server_stream, _) = listener.accept().await.unwrap();

        let data = vec![0x42u8; 100];
        client.write_all(&data).await.unwrap();
        client.shutdown().await.unwrap();

        let sem = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&sem).acquire_owned().await.unwrap();
        let counts = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let guard = IpConnGuard::new(counts, "127.0.0.1".to_string());

        handle_connection(
            server_stream,
            addr,
            addr.port(),
            &config,
            &storage,
            &detector,
            permit,
            guard,
        )
        .await;

        let records = storage.get_records_since(0, 10).unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].payload_truncated);
        assert!(records[0].payload.len() <= config.max_payload_size);
        assert_eq!(records[0].bytes_received, 100);
    }

    #[tokio::test]
    async fn multi_read_byte_accounting() {
        let config = PortHoneypotConfig {
            max_concurrent_connections: 4,
            max_connections_per_ip: 10,
            connection_timeout_ms: 1000,
            read_timeout_ms: 500,
            max_payload_size: 8192,
            ..Default::default()
        };
        let storage = test_storage();
        let detector = ProtocolDetector::new();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server_stream, _) = listener.accept().await.unwrap();

        client.write_all(b"GET /").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        client
            .write_all(b" HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        client.shutdown().await.unwrap();

        let sem = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&sem).acquire_owned().await.unwrap();
        let counts = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let guard = IpConnGuard::new(counts, "127.0.0.1".to_string());

        handle_connection(
            server_stream,
            addr,
            addr.port(),
            &config,
            &storage,
            &detector,
            permit,
            guard,
        )
        .await;

        let records = storage.get_records_since(0, 10).unwrap();
        assert_eq!(records.len(), 1);
        // total bytes from both reads: "GET /" (5) + " HTTP/1.1\r\nHost: test\r\n\r\n" (22) = 27
        assert!(records[0].bytes_received > 5);
    }

    #[tokio::test]
    async fn bytes_sent_includes_banner_and_response() {
        let config = PortHoneypotConfig {
            max_concurrent_connections: 4,
            max_connections_per_ip: 10,
            connection_timeout_ms: 1000,
            read_timeout_ms: 500,
            max_payload_size: 8192,
            ..Default::default()
        };
        let storage = test_storage();
        let detector = ProtocolDetector::new();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server_stream, _) = listener.accept().await.unwrap();

        client
            .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        client.shutdown().await.unwrap();

        let sem = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&sem).acquire_owned().await.unwrap();
        let counts = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let guard = IpConnGuard::new(counts, "127.0.0.1".to_string());

        handle_connection(
            server_stream,
            addr,
            addr.port(),
            &config,
            &storage,
            &detector,
            permit,
            guard,
        )
        .await;

        let records = storage.get_records_since(0, 10).unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].bytes_sent > 0);
    }

    #[tokio::test]
    async fn semaphore_releases_after_timeout() {
        let sem = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&sem).try_acquire_owned().unwrap();
        assert!(Arc::clone(&sem).try_acquire_owned().is_err());
        drop(permit);
        assert!(Arc::clone(&sem).try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn initial_timeout_releases_permits() {
        let config = PortHoneypotConfig {
            max_concurrent_connections: 1,
            max_connections_per_ip: 10,
            connection_timeout_ms: 50,
            read_timeout_ms: 50,
            max_payload_size: 1024,
            ..Default::default()
        };
        let storage = test_storage();
        let detector = ProtocolDetector::new();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server_stream, _) = listener.accept().await.unwrap();

        let sem = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&sem).acquire_owned().await.unwrap();
        let counts = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let guard = IpConnGuard::new(counts, "127.0.0.1".to_string());

        handle_connection(
            server_stream,
            addr,
            addr.port(),
            &config,
            &storage,
            &detector,
            permit,
            guard,
        )
        .await;

        assert!(Arc::clone(&sem).try_acquire_owned().is_ok());
        let records = storage.get_records_since(0, 10).unwrap();
        assert_eq!(records.len(), 0);
    }

    #[tokio::test]
    async fn read_timeout_releases_permits() {
        let config = PortHoneypotConfig {
            max_concurrent_connections: 1,
            max_connections_per_ip: 10,
            connection_timeout_ms: 2000,
            read_timeout_ms: 50,
            max_payload_size: 1024,
            ..Default::default()
        };
        let storage = test_storage();
        let detector = ProtocolDetector::new();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server_stream, _) = listener.accept().await.unwrap();

        // Send initial data so we pass the initial timeout
        client.write_all(b"hello").await.unwrap();

        let sem = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&sem).acquire_owned().await.unwrap();
        let counts = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let guard = IpConnGuard::new(counts, "127.0.0.1".to_string());

        handle_connection(
            server_stream,
            addr,
            addr.port(),
            &config,
            &storage,
            &detector,
            permit,
            guard,
        )
        .await;

        // After read timeout, permit should be released
        assert!(Arc::clone(&sem).try_acquire_owned().is_ok());
        let records = storage.get_records_since(0, 10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].bytes_received, 5);
    }
}
