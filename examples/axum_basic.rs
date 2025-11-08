//! Basic Axum example with security headers middleware.
//!
//! Run with:
//! ```
//! cargo run --example axum_basic --features middleware
//! ```

#[cfg(feature = "middleware")]
use axum::{routing::get, Router};
#[cfg(feature = "middleware")]
use http_security_headers::{add_security_headers, Preset};
#[cfg(feature = "middleware")]
use std::net::SocketAddr;
#[cfg(feature = "middleware")]
use std::sync::Arc;

#[cfg(not(feature = "middleware"))]
fn main() {
    panic!("This example requires the `middleware` feature. Run with `--features middleware`.");
}

#[cfg(feature = "middleware")]
#[tokio::main]
async fn main() {
    // Create security headers configuration using the Strict preset
    let headers = Arc::new(Preset::Strict.build());

    // Create a simple Axum router
    let app = Router::new()
        .route("/", get(handler))
        .route("/health", get(health_check))
        // Add security headers middleware using map_response
        .layer(tower::ServiceBuilder::new().map_response(move |mut response| {
            add_security_headers(&mut response, &headers);
            response
        }));

    // Run the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Server running on http://{}", addr);
    println!("Try:");
    println!("  curl -I http://{}/", addr);
    println!("  curl -I http://{}/health", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[cfg(feature = "middleware")]
async fn handler() -> &'static str {
    "Hello, World! Check the response headers for security headers."
}

#[cfg(feature = "middleware")]
async fn health_check() -> &'static str {
    "OK"
}
