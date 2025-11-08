//! Axum example with custom security headers configuration.
//!
//! Run with:
//! ```
//! cargo run --example axum_custom --features middleware
//! ```

#[cfg(feature = "middleware")]
use axum::{routing::get, Router};
#[cfg(feature = "middleware")]
use http_security_headers::{add_security_headers, ContentSecurityPolicy, SecurityHeaders};
#[cfg(feature = "middleware")]
use std::net::SocketAddr;
#[cfg(feature = "middleware")]
use std::sync::Arc;
#[cfg(feature = "middleware")]
use std::time::Duration;

#[cfg(not(feature = "middleware"))]
fn main() {
    panic!("This example requires the `middleware` feature. Run with `--features middleware`.");
}

#[cfg(feature = "middleware")]
#[tokio::main]
async fn main() {
    // Create a custom CSP policy
    let csp = ContentSecurityPolicy::new()
        .default_src(vec!["'self'"])
        .script_src(vec!["'self'", "https://cdn.jsdelivr.net"])
        .style_src(vec!["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"])
        .font_src(vec!["'self'", "https://fonts.gstatic.com"])
        .img_src(vec!["'self'", "data:", "https:"])
        .connect_src(vec!["'self'", "https://api.example.com"])
        .frame_ancestors(vec!["'none'"])
        .base_uri(vec!["'self'"])
        .form_action(vec!["'self'"]);

    // Build custom security headers configuration
    let headers = Arc::new(
        SecurityHeaders::builder()
            .content_security_policy(csp)
            .strict_transport_security(Duration::from_secs(63072000), true, true) // 2 years with preload
            .x_frame_options_deny()
            .x_content_type_options_nosniff()
            .referrer_policy_strict_origin_when_cross_origin()
            .build()
            .expect("Failed to build security headers"),
    );

    // Create a simple Axum router
    let app = Router::new()
        .route("/", get(handler))
        .route("/api/data", get(api_handler))
        // Add security headers middleware
        .layer(tower::ServiceBuilder::new().map_response(move |mut response| {
            add_security_headers(&mut response, &headers);
            response
        }));

    // Run the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Server running on http://{}", addr);
    println!("Custom security configuration:");
    println!("  - Custom CSP with multiple trusted sources");
    println!("  - HSTS with 2-year max-age and preload");
    println!("  - X-Frame-Options: DENY");
    println!("  - Referrer-Policy: strict-origin-when-cross-origin");
    println!("\nTry:");
    println!("  curl -I http://{}/", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[cfg(feature = "middleware")]
async fn handler() -> &'static str {
    "Hello! This response has custom security headers configured."
}

#[cfg(feature = "middleware")]
async fn api_handler() -> &'static str {
    r#"{"message": "API response with security headers"}"#
}
