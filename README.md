# http-security-headers

[![Crates.io](https://img.shields.io/crates/v/http-security-headers.svg)](https://crates.io/crates/http-security-headers)
[![Documentation](https://docs.rs/http-security-headers/badge.svg)](https://docs.rs/http-security-headers)
[![License](https://img.shields.io/crates/l/http-security-headers.svg)](https://github.com/danielrcurtis/http-security-headers)

Type-safe, framework-agnostic HTTP security headers for Rust with Tower and Actix-Web integration.

## Features

- **🔒 Type-safe configuration**: Compile-time guarantees for header values
- **🏗️ Builder pattern**: Ergonomic, fluent API for configuration
- **📦 Preset configurations**: Strict, Balanced, and Relaxed security levels
- **🔌 Framework integrations**: Tower middleware (Axum, Tonic, etc.) and Actix-Web support
- **⚡ Minimal core deps**: Core crate only depends on `thiserror`; middleware feature adds Tower + pin-project-lite
- **📝 Well-documented**: Comprehensive docs with examples

## Security Headers Supported

| Header | Description |
|--------|-------------|
| **Content-Security-Policy (CSP)** | Prevents XSS and code injection attacks |
| **Strict-Transport-Security (HSTS)** | Forces HTTPS connections |
| **X-Frame-Options** | Prevents clickjacking attacks |
| **X-Content-Type-Options** | Prevents MIME type sniffing |
| **Referrer-Policy** | Controls referrer information |
| **Cross-Origin-Opener-Policy (COOP)** | Isolates browsing contexts |
| **Cross-Origin-Embedder-Policy (COEP)** | Controls cross-origin resource loading |
| **Cross-Origin-Resource-Policy (CORP)** | Controls resource sharing |

## Installation

Add to your `Cargo.toml`:

Core only:

```toml
[dependencies]
http-security-headers = "0.2"
```

With Tower/Axum middleware:

```toml
[dependencies]
http-security-headers = { version = "0.2", features = ["middleware"] }
```

With Actix-Web integration:

```toml
[dependencies]
http-security-headers = { version = "0.2", features = ["actix"] }
```

## Quick Start

### Using Presets

```rust
use http_security_headers::Preset;

// Use a preset configuration
let headers = Preset::Strict.build();
```

### Custom Configuration

```rust
use http_security_headers::{SecurityHeaders, ContentSecurityPolicy};
use std::time::Duration;

let csp = ContentSecurityPolicy::new()
    .default_src(vec!["'self'"])
    .script_src(vec!["'self'", "'unsafe-inline'"])
    .style_src(vec!["'self'", "https://fonts.googleapis.com"]);

let headers = SecurityHeaders::builder()
    .content_security_policy(csp)
    .strict_transport_security(Duration::from_secs(31536000), true, false)
    .x_frame_options_deny()
    .x_content_type_options_nosniff()
    .referrer_policy_no_referrer()
    .build()
    .unwrap();
```

### With Axum

```rust
use axum::{Router, routing::get};
use http_security_headers::{Preset, SecurityHeadersLayer};
use std::sync::Arc;

let headers = Arc::new(Preset::Strict.build());

let app = Router::new()
    .route("/", get(|| async { "Hello, World!" }))
    .layer(SecurityHeadersLayer::new(headers));
```

### With Actix-Web

```rust
use actix_web::{web, App, HttpResponse, HttpServer};
use http_security_headers::{Preset, SecurityHeadersMiddleware};
use std::sync::Arc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let headers = Arc::new(Preset::Strict.build());

    HttpServer::new(move || {
        App::new()
            .wrap(SecurityHeadersMiddleware::new(headers.clone()))
            .route("/", web::get().to(|| async { HttpResponse::Ok().body("Hello, World!") }))
    })
    .bind(("127.0.0.1", 3000))?
    .run()
    .await
}
```

## Presets

### Strict

Recommended for applications that can enforce strict security policies.

```rust
let headers = Preset::Strict.build();
```

**Includes:**
- CSP: `default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`
- HSTS: 1 year, includeSubDomains
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: no-referrer
- COOP: same-origin
- COEP: require-corp
- CORP: same-origin

### Balanced

Provides good security while maintaining compatibility.

```rust
let headers = Preset::Balanced.build();
```

**Includes:**
- CSP: `default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'`
- HSTS: 1 year, includeSubDomains
- X-Frame-Options: SAMEORIGIN
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin
- COOP: same-origin-allow-popups

### Relaxed

Baseline security with minimal restrictions.

```rust
let headers = Preset::Relaxed.build();
```

**Includes:**
- HSTS: 6 months
- X-Frame-Options: SAMEORIGIN
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin

## Examples

Check out the [examples](examples/) directory:

- **[axum_basic.rs](examples/axum_basic.rs)**: Basic Axum integration with preset
- **[axum_custom.rs](examples/axum_custom.rs)**: Custom security headers configuration
- **[actix_basic.rs](examples/actix_basic.rs)**: Simple Actix-Web integration

Run examples:

```bash
cargo run --example axum_basic --features middleware
cargo run --example axum_custom --features middleware
cargo run --example actix_basic --features actix
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `middleware` | Enables Tower middleware support |
| `axum` | Enables Axum-specific helpers (requires `middleware`) |
| `actix` | Enables Actix-Web middleware integration (includes `actix-web`) |
| `observability` | Enables tracing support |
| `metrics` | Enables metrics collection |
| `validation` | Enables CSP/Permissions-Policy validation |

## Documentation

Full documentation is available on [docs.rs](https://docs.rs/http-security-headers).

## Comparison with Other Crates

| Feature | http-security-headers | secure-headers | tower-http |
|---------|---------------------|----------------|------------|
| Type-safe configuration | ✅ | ❌ | Partial |
| Builder pattern | ✅ | ❌ | ❌ |
| Preset configurations | ✅ | ❌ | ❌ |
| Framework-agnostic | ✅ | ❌ | ✅ |
| CSP builder | ✅ | ❌ | ❌ |
| Full header support | ✅ | Partial | Partial |

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Acknowledgments

Inspired by:
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
