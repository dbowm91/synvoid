use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;

pub async fn start_prometheus_exporter(
    metrics_config: &crate::config::admin::MetricsConfig,
    mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
) {
    if !metrics_config.enabled {
        tracing::debug!("Prometheus metrics exporter disabled by config");
        return;
    }

    let port = metrics_config.port;
    tracing::info!("Starting Prometheus metrics exporter on port {}", port);

    let addr: SocketAddr = match format!("127.0.0.1:{}", port).parse() {
        Ok(addr) => addr,
        Err(e) => {
            tracing::error!("Invalid metrics bind address 127.0.0.1:{}: {}", port, e);
            return;
        }
    };

    match PrometheusBuilder::new()
        .with_http_listener(addr)
        .build()
    {
        Ok((_layer, exporter)) => {
            tokio::spawn(async move {
                match exporter.await {
                    Ok(_) => {
                        tracing::info!("Prometheus exporter task completed");
                    }
                    Err(e) => {
                        tracing::error!("Prometheus exporter task error: {:?}", e);
                    }
                }
            });
            tracing::info!("Prometheus metrics endpoint listening on http://{}", addr);
        }
        Err(e) => {
            tracing::error!("Failed to build Prometheus exporter: {:?}", e);
            return;
        }
    }

    tokio::select! {
        _ = shutdown_rx.recv() => {
            tracing::info!("Prometheus exporter shutdown signal received");
        }
    }
}