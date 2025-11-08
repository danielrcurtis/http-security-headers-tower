//! Basic Actix-Web example using the security headers middleware.
//!
//! Run with:
//! ```
//! cargo run --example actix_basic --features actix
//! ```

#[cfg(feature = "actix")]
use actix_web::{web, App, HttpResponse, HttpServer};
#[cfg(feature = "actix")]
use http_security_headers::{Preset, SecurityHeadersMiddleware};
#[cfg(feature = "actix")]
use std::sync::Arc;

#[cfg(not(feature = "actix"))]
fn main() {
    panic!("This example requires the `actix` feature. Run with `--features actix`.");
}

#[cfg(feature = "actix")]
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let headers = Arc::new(Preset::Strict.build());

    HttpServer::new(move || {
        App::new()
            .wrap(SecurityHeadersMiddleware::new(headers.clone()))
            .route("/", web::get().to(|| async { HttpResponse::Ok().body("Hello, World!") }))
            .route("/health", web::get().to(|| async { HttpResponse::Ok().finish() }))
    })
    .bind(("127.0.0.1", 3000))?
    .run()
    .await
}

