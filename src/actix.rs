//! Actix-Web middleware integration.
//!
//! Enable the `actix` feature to use the provided middleware that applies
//! `http-security-headers` to every outgoing response.

use crate::SecurityHeaders;
use actix_web::body::MessageBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::Error;
use actix_web::http::header::HeaderName;
use futures_util::future::{ready, LocalBoxFuture, Ready};
use std::sync::Arc;

/// Actix-Web middleware that applies configured security headers to responses.
///
/// # Examples
///
/// ```rust,ignore
/// use actix_web::{web, App, HttpResponse, HttpServer};
/// use http_security_headers::{Preset, SecurityHeadersMiddleware};
/// use std::sync::Arc;
///
/// #[actix_web::main]
/// async fn main() -> std::io::Result<()> {
///     let headers = Arc::new(Preset::Strict.build());
///
///     HttpServer::new(move || {
///         App::new()
///             .wrap(SecurityHeadersMiddleware::new(headers.clone()))
///             .route("/", web::get().to(|| async { HttpResponse::Ok().body("Hello") }))
///     })
///     .bind(("127.0.0.1", 3000))?
///     .run()
///     .await
/// }
/// ```
#[derive(Clone)]
pub struct SecurityHeadersMiddleware {
    headers: Arc<SecurityHeaders>,
}

impl SecurityHeadersMiddleware {
    /// Creates a new Actix middleware from the provided configuration.
    pub fn new(headers: Arc<SecurityHeaders>) -> Self {
        Self { headers }
    }
}

impl<S, B> Transform<S, ServiceRequest> for SecurityHeadersMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SecurityHeadersMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityHeadersMiddlewareService {
            service,
            headers: self.headers.clone(),
        }))
    }
}

/// Inner service that applies headers after the wrapped service completes.
pub struct SecurityHeadersMiddlewareService<S> {
    service: S,
    headers: Arc<SecurityHeaders>,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let headers = self.headers.clone();
        let fut = self.service.call(req);

        Box::pin(async move {
            let mut res = fut.await?;
            apply_headers(res.response_mut().headers_mut(), &headers);
            Ok(res)
        })
    }
}

fn apply_headers(
    headers: &mut actix_web::http::header::HeaderMap,
    config: &SecurityHeaders,
) {
    // Content-Security-Policy
    if let Some(csp) = config.content_security_policy() {
        if let Ok(value) = csp.to_header_value() {
            if let Ok(header_value) = value.parse() {
                headers.insert(actix_web::http::header::CONTENT_SECURITY_POLICY, header_value);
            }
        }
    }

    // Strict-Transport-Security
    if let Some(hsts) = config.strict_transport_security() {
        if let Ok(value) = hsts.to_header_value() {
            if let Ok(header_value) = value.parse() {
                headers.insert(actix_web::http::header::STRICT_TRANSPORT_SECURITY, header_value);
            }
        }
    }

    // X-Frame-Options
    if let Some(xfo) = config.x_frame_options() {
        if let Ok(header_value) = xfo.as_str().parse() {
            headers.insert(actix_web::http::header::X_FRAME_OPTIONS, header_value);
        }
    }

    // X-Content-Type-Options
    if config.x_content_type_options_enabled() {
        if let Ok(header_value) = "nosniff".parse() {
            headers.insert(actix_web::http::header::X_CONTENT_TYPE_OPTIONS, header_value);
        }
    }

    // Referrer-Policy
    if let Some(rp) = config.referrer_policy() {
        if let Ok(header_value) = rp.as_str().parse() {
            headers.insert(actix_web::http::header::REFERRER_POLICY, header_value);
        }
    }

    // Cross-Origin-Opener-Policy
    if let Some(coop) = config.cross_origin_opener_policy() {
        const COOP: HeaderName = HeaderName::from_static("cross-origin-opener-policy");
        if let Ok(header_value) = coop.as_str().parse() {
            headers.insert(COOP, header_value);
        }
    }

    // Cross-Origin-Embedder-Policy
    if let Some(coep) = config.cross_origin_embedder_policy() {
        const COEP: HeaderName = HeaderName::from_static("cross-origin-embedder-policy");
        if let Ok(header_value) = coep.as_str().parse() {
            headers.insert(COEP, header_value);
        }
    }

    // Cross-Origin-Resource-Policy
    if let Some(corp) = config.cross_origin_resource_policy() {
        const CORP: HeaderName = HeaderName::from_static("cross-origin-resource-policy");
        if let Ok(header_value) = corp.as_str().parse() {
            headers.insert(CORP, header_value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Preset;
    use actix_web::{test, web, App, HttpResponse};

    #[actix_web::test]
    async fn middleware_adds_headers() {
        let headers = Arc::new(Preset::Balanced.build());

        let app = test::init_service(
            App::new()
                .wrap(SecurityHeadersMiddleware::new(headers))
                .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
        )
        .await;

        let req = test::TestRequest::get().uri("/").to_request();
        let res = test::call_service(&app, req).await;
        let headers = res.headers();

        use actix_web::http::header;

        assert!(headers.contains_key(header::STRICT_TRANSPORT_SECURITY));
        assert!(headers.contains_key(header::X_FRAME_OPTIONS));
        assert!(headers.contains_key(header::X_CONTENT_TYPE_OPTIONS));
    }
}

