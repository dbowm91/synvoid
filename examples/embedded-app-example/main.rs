use myapp::create_app;

#[tokio::main]
async fn main() {
    let app = create_app();
    
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await.unwrap();
    tracing::info!("Starting embedded app on {}", listener.local_addr().unwrap());
    
    axum::serve(listener, app).await.unwrap();
}
