//! Tower middleware for adding security headers.
//!
//! This module provides Tower Layer and Service implementations for adding
//! security headers to HTTP responses.

use crate::SecurityHeaders;
use http::{header::HeaderName, Request, Response};
use http_body::Body;
use pin_project_lite::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};

#[cfg(feature = "observability")]
use tracing::{debug, trace};

/// Tower layer for adding security headers.
///
/// # Examples
///
/// ```rust,ignore
/// use axum::{Router, routing::get};
/// use http_security_headers::{Preset, SecurityHeadersLayer};
/// use std::sync::Arc;
///
/// let headers = Arc::new(Preset::Strict.build());
///
/// let app = Router::new()
///     .route("/", get(|| async { "Hello, World!" }))
///     .layer(SecurityHeadersLayer::new(headers));
/// ```
#[derive(Clone)]
pub struct SecurityHeadersLayer {
    headers: Arc<SecurityHeaders>,
}

impl SecurityHeadersLayer {
    /// Creates a new SecurityHeadersLayer with the given configuration.
    pub fn new(headers: Arc<SecurityHeaders>) -> Self {
        Self { headers }
    }
}

impl<S> Layer<S> for SecurityHeadersLayer {
    type Service = SecurityHeadersService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersService {
            inner,
            headers: self.headers.clone(),
        }
    }
}

/// Tower service for adding security headers.
#[derive(Clone)]
pub struct SecurityHeadersService<S> {
    inner: S,
    headers: Arc<SecurityHeaders>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SecurityHeadersService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: Body,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = SecurityHeadersFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        #[cfg(feature = "observability")]
        trace!("Security headers middleware: processing request");

        SecurityHeadersFuture {
            future: self.inner.call(req),
            headers: self.headers.clone(),
        }
    }
}

pin_project! {
    /// Future returned by [`SecurityHeadersService`].
    pub struct SecurityHeadersFuture<F> {
        #[pin]
        future: F,
        headers: Arc<SecurityHeaders>,
    }
}

impl<F, ResBody, E> Future for SecurityHeadersFuture<F>
where
    F: Future<Output = Result<Response<ResBody>, E>>,
    ResBody: Body,
{
    type Output = Result<Response<ResBody>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        match this.future.poll(cx) {
            Poll::Ready(Ok(mut response)) => {
                add_security_headers(&mut response, this.headers);
                #[cfg(feature = "observability")]
                trace!("Security headers middleware: applied headers to response");
                Poll::Ready(Ok(response))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub(crate) fn apply_security_headers(headers: &mut http::HeaderMap, config: &SecurityHeaders) {
    // Content-Security-Policy
    if let Some(csp) = config.content_security_policy() {
        if let Ok(value) = csp.to_header_value() {
            if let Ok(header_value) = value.parse() {
                headers.insert(http::header::CONTENT_SECURITY_POLICY, header_value);
                #[cfg(feature = "observability")]
                debug!("Added Content-Security-Policy header");
            }
        }
    }

    // Strict-Transport-Security
    if let Some(hsts) = config.strict_transport_security() {
        if let Ok(value) = hsts.to_header_value() {
            if let Ok(header_value) = value.parse() {
                headers.insert(http::header::STRICT_TRANSPORT_SECURITY, header_value);
                #[cfg(feature = "observability")]
                debug!("Added Strict-Transport-Security header");
            }
        }
    }

    // X-Frame-Options
    if let Some(xfo) = config.x_frame_options() {
        if let Ok(header_value) = xfo.as_str().parse() {
            headers.insert(http::header::X_FRAME_OPTIONS, header_value);
            #[cfg(feature = "observability")]
            debug!("Added X-Frame-Options header");
        }
    }

    // X-Content-Type-Options
    if config.x_content_type_options_enabled() {
        if let Ok(header_value) = "nosniff".parse() {
            headers.insert(http::header::X_CONTENT_TYPE_OPTIONS, header_value);
            #[cfg(feature = "observability")]
            debug!("Added X-Content-Type-Options header");
        }
    }

    // Referrer-Policy
    if let Some(rp) = config.referrer_policy() {
        if let Ok(header_value) = rp.as_str().parse() {
            headers.insert(http::header::REFERRER_POLICY, header_value);
            #[cfg(feature = "observability")]
            debug!("Added Referrer-Policy header");
        }
    }

    // Cross-Origin-Opener-Policy
    if let Some(coop) = config.cross_origin_opener_policy() {
        const COOP: HeaderName = HeaderName::from_static("cross-origin-opener-policy");
        if let Ok(header_value) = coop.as_str().parse() {
            headers.insert(COOP, header_value);
            #[cfg(feature = "observability")]
            debug!("Added Cross-Origin-Opener-Policy header");
        }
    }

    // Cross-Origin-Embedder-Policy
    if let Some(coep) = config.cross_origin_embedder_policy() {
        const COEP: HeaderName = HeaderName::from_static("cross-origin-embedder-policy");
        if let Ok(header_value) = coep.as_str().parse() {
            headers.insert(COEP, header_value);
            #[cfg(feature = "observability")]
            debug!("Added Cross-Origin-Embedder-Policy header");
        }
    }

    // Cross-Origin-Resource-Policy
    if let Some(corp) = config.cross_origin_resource_policy() {
        const CORP: HeaderName = HeaderName::from_static("cross-origin-resource-policy");
        if let Ok(header_value) = corp.as_str().parse() {
            headers.insert(CORP, header_value);
            #[cfg(feature = "observability")]
            debug!("Added Cross-Origin-Resource-Policy header");
        }
    }
}

/// Helper function to add security headers to a response.
///
/// This function is used internally by the middleware but can also be used
/// directly if you need more control.
///
/// # Examples
///
/// ```rust,ignore
/// use http_security_headers::{Preset, add_security_headers};
/// use http::Response;
///
/// let headers = Preset::Strict.build();
/// let mut response = Response::new("Hello, World!");
/// add_security_headers(&mut response, &headers);
/// ```
pub fn add_security_headers<B>(response: &mut Response<B>, config: &SecurityHeaders) {
    #[cfg(feature = "observability")]
    trace!("Adding security headers to response");

    apply_security_headers(response.headers_mut(), config);

    #[cfg(feature = "observability")]
    trace!("Finished adding security headers");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Preset;
    use bytes::Bytes;
    use http::Response;
    use http_body_util::Full;
    use std::convert::Infallible;
    use std::sync::Arc;
    use tower::service_fn;
    use tower::ServiceExt;

    #[test]
    fn test_add_security_headers_strict() {
        let config = Preset::Strict.build();
        let mut response = Response::new("test body");

        add_security_headers(&mut response, &config);

        let headers = response.headers();
        assert!(headers.contains_key(http::header::CONTENT_SECURITY_POLICY));
        assert!(headers.contains_key(http::header::STRICT_TRANSPORT_SECURITY));
        assert!(headers.contains_key(http::header::X_FRAME_OPTIONS));
        assert!(headers.contains_key(http::header::X_CONTENT_TYPE_OPTIONS));
        assert!(headers.contains_key(http::header::REFERRER_POLICY));
        assert!(headers.contains_key("cross-origin-opener-policy"));
        assert!(headers.contains_key("cross-origin-embedder-policy"));
        assert!(headers.contains_key("cross-origin-resource-policy"));
    }

    #[test]
    fn test_add_security_headers_balanced() {
        let config = Preset::Balanced.build();
        let mut response = Response::new("test body");

        add_security_headers(&mut response, &config);

        let headers = response.headers();
        assert!(headers.contains_key(http::header::CONTENT_SECURITY_POLICY));
        assert!(headers.contains_key(http::header::STRICT_TRANSPORT_SECURITY));
        assert!(headers.contains_key(http::header::X_FRAME_OPTIONS));
        assert_eq!(
            headers.get(http::header::X_FRAME_OPTIONS).unwrap(),
            "SAMEORIGIN"
        );
    }

    #[test]
    fn test_add_security_headers_relaxed() {
        let config = Preset::Relaxed.build();
        let mut response = Response::new("test body");

        add_security_headers(&mut response, &config);

        let headers = response.headers();
        assert!(headers.contains_key(http::header::STRICT_TRANSPORT_SECURITY));
        assert!(headers.contains_key(http::header::X_FRAME_OPTIONS));
        assert!(headers.contains_key(http::header::X_CONTENT_TYPE_OPTIONS));
        assert!(headers.contains_key(http::header::REFERRER_POLICY));

        // Relaxed doesn't include CSP
        assert!(!headers.contains_key(http::header::CONTENT_SECURITY_POLICY));
    }

    #[tokio::test]
    async fn test_security_headers_layer_applies_headers() {
        let config = Arc::new(Preset::Balanced.build());
        let layer = SecurityHeadersLayer::new(config);

        let service = layer.layer(service_fn(|_req: Request<()>| async {
            let body = Full::new(Bytes::from_static(b"ok"));
            Ok::<_, Infallible>(Response::new(body))
        }));

        let response = service.oneshot(Request::new(())).await.unwrap();
        let headers = response.headers();

        assert!(headers.contains_key(http::header::STRICT_TRANSPORT_SECURITY));
        assert!(headers.contains_key(http::header::X_FRAME_OPTIONS));
    }
}
