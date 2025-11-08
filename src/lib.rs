//! # http-security-headers
//!
//! Type-safe, framework-agnostic HTTP security headers with Tower middleware support.
//!
//! ## Features
//!
//! - **Type-safe configuration**: Compile-time guarantees for header values
//! - **Builder pattern**: Ergonomic, fluent API
//! - **Preset configurations**: Strict, Balanced, and Relaxed security levels
//! - **Tower middleware**: Framework-agnostic (works with Axum, Actix, Tonic, etc.)
//! - **Zero dependencies**: Core library has minimal dependencies (only `thiserror`)
//!
//! ## Quick Start
//!
//! ```rust
//! use http_security_headers::{SecurityHeaders, Preset};
//! use std::time::Duration;
//!
//! // Use a preset configuration
//! let headers = Preset::Strict.build();
//!
//! // Or build a custom configuration
//! let headers = SecurityHeaders::builder()
//!     .strict_transport_security(Duration::from_secs(31536000), true, false)
//!     .x_frame_options_deny()
//!     .referrer_policy_no_referrer()
//!     .build()
//!     .unwrap();
//! ```
//!
//! ## Using with Axum
//!
//! Enable the `middleware` feature in your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! http-security-headers = { version = "0.1", features = ["middleware"] }
//! ```
//!
//! Then use the middleware layer:
//!
//! ```rust,ignore
//! use axum::{Router, routing::get};
//! use http_security_headers::{Preset, SecurityHeadersLayer};
//! use std::sync::Arc;
//!
//! let headers = Arc::new(Preset::Strict.build());
//!
//! let app = Router::new()
//!     .route("/", get(|| async { "Hello, World!" }))
//!     .layer(SecurityHeadersLayer::new(headers));
//! ```
//!
//! ## Security Headers Supported
//!
//! - **Content-Security-Policy (CSP)**: Prevents XSS and code injection attacks
//! - **Strict-Transport-Security (HSTS)**: Forces HTTPS connections
//! - **X-Frame-Options**: Prevents clickjacking attacks
//! - **X-Content-Type-Options**: Prevents MIME type sniffing
//! - **Referrer-Policy**: Controls referrer information
//! - **Cross-Origin-Opener-Policy (COOP)**: Isolates browsing contexts
//! - **Cross-Origin-Embedder-Policy (COEP)**: Controls cross-origin resource loading
//! - **Cross-Origin-Resource-Policy (CORP)**: Controls resource sharing

#![warn(missing_docs, rust_2021_compatibility)]
#![deny(unsafe_code)]

mod config;
mod error;
pub mod policy;
pub mod preset;

#[cfg(feature = "middleware")]
pub mod middleware;

#[cfg(feature = "actix")]
pub mod actix;

pub use config::{SecurityHeaders, SecurityHeadersBuilder};
pub use error::{Error, Result};
pub use policy::{
    ContentSecurityPolicy, CrossOriginEmbedderPolicy, CrossOriginOpenerPolicy,
    CrossOriginResourcePolicy, ReferrerPolicy, StrictTransportSecurity, XFrameOptions,
};
pub use preset::Preset;

#[cfg(feature = "middleware")]
pub use middleware::{add_security_headers, SecurityHeadersLayer};

#[cfg(feature = "actix")]
pub use actix::SecurityHeadersMiddleware;
