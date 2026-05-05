#[cfg(unix)]
mod drain_e2e_tests {
    use synvoid::process::{IpcEndpoint, IpcListener, Message, WorkerId};
    use tempfile::TempDir;

    fn temp_endpoint(temp_dir: &TempDir, name: &str) -> IpcEndpoint {
        let socket_path = temp_dir.path().join(format!("{}.sock", name));
        let endpoint_str = socket_path.to_string_lossy().to_string();
        IpcEndpoint::new(&endpoint_str)
    }

    #[tokio::test]
    async fn test_worker_drain_protocol_basic() {
        let temp_dir = TempDir::new().unwrap();
        let endpoint = temp_endpoint(&temp_dir, "drain-basic");

        let listener = IpcListener::bind(&endpoint).await.unwrap();

        let worker_handle = tokio::spawn(async move {
            let mut stream = endpoint.connect().await.unwrap();

            let started = Message::WorkerStarted {
                id: WorkerId(1),
                pid: std::process::id(),
                port: 9000,
                timestamp: 0,
            };
            stream.send(&started).await.unwrap();

            let _ack: Message = stream.recv().await.unwrap().unwrap();

            let ready = Message::WorkerReady { id: WorkerId(1) };
            stream.send(&ready).await.unwrap();

            let drain: Message = stream.recv().await.unwrap().unwrap();
            match drain {
                Message::WorkerDrain { id, timeout_secs } => {
                    assert_eq!(id, WorkerId(1));
                    assert_eq!(timeout_secs, 60);
                }
                other => panic!("expected WorkerDrain, got {:?}", other),
            }

            let drained = Message::WorkerDrained {
                id: WorkerId(1),
                remaining_connections: 0,
            };
            stream.send(&drained).await.unwrap();
        });

        let mut master_stream = listener.accept().await.unwrap();

        let _: Message = master_stream.recv().await.unwrap().unwrap();
        master_stream
            .send(&Message::HealthCheckAck { timestamp: 0 })
            .await
            .unwrap();
        let _: Message = master_stream.recv().await.unwrap().unwrap();

        let drain = Message::WorkerDrain {
            id: WorkerId(1),
            timeout_secs: 60,
        };
        master_stream.send(&drain).await.unwrap();

        let drained_msg: Message = master_stream.recv().await.unwrap().unwrap();
        match drained_msg {
            Message::WorkerDrained {
                id,
                remaining_connections,
            } => {
                assert_eq!(id, WorkerId(1));
                assert_eq!(remaining_connections, 0);
            }
            _ => panic!("expected WorkerDrained"),
        }

        worker_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_worker_drain_protocol_with_connections() {
        let temp_dir = TempDir::new().unwrap();
        let endpoint = temp_endpoint(&temp_dir, "drain-with-conns");

        let listener = IpcListener::bind(&endpoint).await.unwrap();

        let worker_handle = tokio::spawn(async move {
            let mut stream = endpoint.connect().await.unwrap();

            stream
                .send(&Message::WorkerStarted {
                    id: WorkerId(2),
                    pid: std::process::id(),
                    port: 9001,
                    timestamp: 0,
                })
                .await
                .unwrap();

            let _ack: Message = stream.recv().await.unwrap().unwrap();

            stream
                .send(&Message::WorkerReady { id: WorkerId(2) })
                .await
                .unwrap();

            let drain: Message = stream.recv().await.unwrap().unwrap();
            match drain {
                Message::WorkerDrain { id, .. } => {
                    assert_eq!(id, WorkerId(2));
                }
                other => panic!("expected WorkerDrain, got {:?}", other),
            }

            let drained = Message::WorkerDrained {
                id: WorkerId(2),
                remaining_connections: 5,
            };
            stream.send(&drained).await.unwrap();
        });

        let mut master_stream = listener.accept().await.unwrap();

        let _: Message = master_stream.recv().await.unwrap().unwrap();
        master_stream
            .send(&Message::HealthCheckAck { timestamp: 0 })
            .await
            .unwrap();
        let _: Message = master_stream.recv().await.unwrap().unwrap();

        master_stream
            .send(&Message::WorkerDrain {
                id: WorkerId(2),
                timeout_secs: 30,
            })
            .await
            .unwrap();

        let drained_msg: Message = master_stream.recv().await.unwrap().unwrap();
        match drained_msg {
            Message::WorkerDrained {
                id,
                remaining_connections,
            } => {
                assert_eq!(id, WorkerId(2));
                assert_eq!(remaining_connections, 5);
            }
            _ => panic!("expected WorkerDrained"),
        }

        worker_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_worker_drain_protocol_timeout() {
        let temp_dir = TempDir::new().unwrap();
        let endpoint = temp_endpoint(&temp_dir, "drain-timeout");

        let listener = IpcListener::bind(&endpoint).await.unwrap();

        let worker_handle = tokio::spawn(async move {
            let mut stream = endpoint.connect().await.unwrap();

            stream
                .send(&Message::WorkerStarted {
                    id: WorkerId(3),
                    pid: std::process::id(),
                    port: 9002,
                    timestamp: 0,
                })
                .await
                .unwrap();

            let _ack: Message = stream.recv().await.unwrap().unwrap();

            stream
                .send(&Message::WorkerReady { id: WorkerId(3) })
                .await
                .unwrap();

            let drain: Message = stream.recv().await.unwrap().unwrap();
            match drain {
                Message::WorkerDrain { id, timeout_secs } => {
                    assert_eq!(id, WorkerId(3));
                    assert_eq!(timeout_secs, 120);
                }
                other => panic!("expected WorkerDrain with timeout 120, got {:?}", other),
            }

            let drained = Message::WorkerDrained {
                id: WorkerId(3),
                remaining_connections: 0,
            };
            stream.send(&drained).await.unwrap();
        });

        let mut master_stream = listener.accept().await.unwrap();

        let _: Message = master_stream.recv().await.unwrap().unwrap();
        master_stream
            .send(&Message::HealthCheckAck { timestamp: 0 })
            .await
            .unwrap();
        let _: Message = master_stream.recv().await.unwrap().unwrap();

        master_stream
            .send(&Message::WorkerDrain {
                id: WorkerId(3),
                timeout_secs: 120,
            })
            .await
            .unwrap();

        let drained_msg: Message = master_stream.recv().await.unwrap().unwrap();
        match drained_msg {
            Message::WorkerDrained { id, .. } => {
                assert_eq!(id, WorkerId(3));
            }
            _ => panic!("expected WorkerDrained"),
        }

        worker_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_multiple_workers_drain_sequence() {
        let temp_dir = TempDir::new().unwrap();
        let endpoint = temp_endpoint(&temp_dir, "multi-drain");

        let listener = IpcListener::bind(&endpoint).await.unwrap();

        let worker_count = 3;
        let mut worker_handles = Vec::new();

        for i in 0..worker_count {
            let endpoint_clone = IpcEndpoint::new(&endpoint.name().to_string());
            let handle = tokio::spawn(async move {
                let mut stream = endpoint_clone.connect().await.unwrap();

                stream
                    .send(&Message::WorkerStarted {
                        id: WorkerId(i),
                        pid: std::process::id(),
                        port: 9000 + i as u16,
                        timestamp: 0,
                    })
                    .await
                    .unwrap();

                let _ack: Message = stream.recv().await.unwrap().unwrap();

                stream
                    .send(&Message::WorkerReady { id: WorkerId(i) })
                    .await
                    .unwrap();

                let drain: Message = stream.recv().await.unwrap().unwrap();
                match drain {
                    Message::WorkerDrain { id, .. } => {
                        assert_eq!(id, WorkerId(i));
                    }
                    other => panic!("expected WorkerDrain, got {:?}", other),
                }

                stream
                    .send(&Message::WorkerDrained {
                        id: WorkerId(i),
                        remaining_connections: 0,
                    })
                    .await
                    .unwrap();
            });
            worker_handles.push(handle);
        }

        let mut master_streams = Vec::new();
        for _ in 0..worker_count {
            let stream = listener.accept().await.unwrap();
            master_streams.push(stream);
        }

        for stream in master_streams.iter_mut() {
            let _: Message = stream.recv().await.unwrap().unwrap();
            stream
                .send(&Message::HealthCheckAck { timestamp: 0 })
                .await
                .unwrap();
            let _: Message = stream.recv().await.unwrap().unwrap();
        }

        for i in 0..worker_count {
            let stream = &mut master_streams[i];

            stream
                .send(&Message::WorkerDrain {
                    id: WorkerId(i),
                    timeout_secs: 45,
                })
                .await
                .unwrap();

            let drained_msg: Message = stream.recv().await.unwrap().unwrap();
            match drained_msg {
                Message::WorkerDrained { id, .. } => {
                    assert_eq!(id, WorkerId(i));
                }
                _ => panic!("expected WorkerDrained"),
            }
        }

        for handle in worker_handles {
            handle.await.unwrap();
        }
    }
}
