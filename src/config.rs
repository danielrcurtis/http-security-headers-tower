//! Security headers configuration.
//!
//! This module provides the main configuration type and builder for security headers.

use crate::error::{Error, Result};
use crate::policy::*;

/// Main security headers configuration.
///
/// This struct holds all configured security headers and provides a builder pattern
/// for ergonomic construction.
///
/// # Examples
///
/// ```
/// use http_security_headers::SecurityHeaders;
/// use std::time::Duration;
///
/// let headers = SecurityHeaders::builder()
///     .strict_transport_security(Duration::from_secs(31536000), true, false)
///     .x_frame_options_deny()
///     .referrer_policy_no_referrer()
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct SecurityHeaders {
    pub(crate) content_security_policy: Option<ContentSecurityPolicy>,
    pub(crate) strict_transport_security: Option<StrictTransportSecurity>,
    pub(crate) x_frame_options: Option<XFrameOptions>,
    pub(crate) x_content_type_options: bool,
    pub(crate) referrer_policy: Option<ReferrerPolicy>,
    pub(crate) cross_origin_opener_policy: Option<CrossOriginOpenerPolicy>,
    pub(crate) cross_origin_embedder_policy: Option<CrossOriginEmbedderPolicy>,
    pub(crate) cross_origin_resource_policy: Option<CrossOriginResourcePolicy>,
}

impl SecurityHeaders {
    /// Creates a new builder for SecurityHeaders.
    pub fn builder() -> SecurityHeadersBuilder {
        SecurityHeadersBuilder::default()
    }

    /// Returns the Content-Security-Policy if configured.
    pub fn content_security_policy(&self) -> Option<&ContentSecurityPolicy> {
        self.content_security_policy.as_ref()
    }

    /// Returns the Strict-Transport-Security policy if configured.
    pub fn strict_transport_security(&self) -> Option<&StrictTransportSecurity> {
        self.strict_transport_security.as_ref()
    }

    /// Returns the X-Frame-Options policy if configured.
    pub fn x_frame_options(&self) -> Option<XFrameOptions> {
        self.x_frame_options
    }

    /// Returns whether X-Content-Type-Options: nosniff is enabled.
    pub fn x_content_type_options_enabled(&self) -> bool {
        self.x_content_type_options
    }

    /// Returns the Referrer-Policy if configured.
    pub fn referrer_policy(&self) -> Option<ReferrerPolicy> {
        self.referrer_policy
    }

    /// Returns the Cross-Origin-Opener-Policy if configured.
    pub fn cross_origin_opener_policy(&self) -> Option<CrossOriginOpenerPolicy> {
        self.cross_origin_opener_policy
    }

    /// Returns the Cross-Origin-Embedder-Policy if configured.
    pub fn cross_origin_embedder_policy(&self) -> Option<CrossOriginEmbedderPolicy> {
        self.cross_origin_embedder_policy
    }

    /// Returns the Cross-Origin-Resource-Policy if configured.
    pub fn cross_origin_resource_policy(&self) -> Option<CrossOriginResourcePolicy> {
        self.cross_origin_resource_policy
    }
}

/// Builder for SecurityHeaders.
///
/// Provides a fluent interface for configuring security headers.
#[derive(Debug, Default)]
pub struct SecurityHeadersBuilder {
    content_security_policy: Option<ContentSecurityPolicy>,
    strict_transport_security: Option<StrictTransportSecurity>,
    x_frame_options: Option<XFrameOptions>,
    x_content_type_options: bool,
    referrer_policy: Option<ReferrerPolicy>,
    cross_origin_opener_policy: Option<CrossOriginOpenerPolicy>,
    cross_origin_embedder_policy: Option<CrossOriginEmbedderPolicy>,
    cross_origin_resource_policy: Option<CrossOriginResourcePolicy>,
}

impl SecurityHeadersBuilder {
    /// Sets the Content-Security-Policy.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::{SecurityHeaders, ContentSecurityPolicy};
    ///
    /// let csp = ContentSecurityPolicy::new()
    ///     .default_src(vec!["'self'"])
    ///     .script_src(vec!["'self'", "'unsafe-inline'"]);
    ///
    /// let headers = SecurityHeaders::builder()
    ///     .content_security_policy(csp)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn content_security_policy(mut self, policy: ContentSecurityPolicy) -> Self {
        self.content_security_policy = Some(policy);
        self
    }

    /// Sets the Strict-Transport-Security header.
    ///
    /// # Arguments
    ///
    /// * `max_age` - Duration for the max-age directive
    /// * `include_subdomains` - Whether to include the includeSubDomains directive
    /// * `preload` - Whether to include the preload directive
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::SecurityHeaders;
    /// use std::time::Duration;
    ///
    /// let headers = SecurityHeaders::builder()
    ///     .strict_transport_security(Duration::from_secs(31536000), true, false)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn strict_transport_security(
        mut self,
        max_age: std::time::Duration,
        include_subdomains: bool,
        preload: bool,
    ) -> Self {
        let mut hsts = StrictTransportSecurity::new(max_age);
        if include_subdomains {
            hsts = hsts.include_subdomains(true);
        }
        if preload {
            hsts = hsts.preload(true);
        }
        self.strict_transport_security = Some(hsts);
        self
    }

    /// Sets the Strict-Transport-Security header with a custom policy.
    pub fn strict_transport_security_policy(mut self, policy: StrictTransportSecurity) -> Self {
        self.strict_transport_security = Some(policy);
        self
    }

    /// Sets X-Frame-Options to DENY.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::SecurityHeaders;
    ///
    /// let headers = SecurityHeaders::builder()
    ///     .x_frame_options_deny()
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn x_frame_options_deny(mut self) -> Self {
        self.x_frame_options = Some(XFrameOptions::Deny);
        self
    }

    /// Sets X-Frame-Options to SAMEORIGIN.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::SecurityHeaders;
    ///
    /// let headers = SecurityHeaders::builder()
    ///     .x_frame_options_sameorigin()
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn x_frame_options_sameorigin(mut self) -> Self {
        self.x_frame_options = Some(XFrameOptions::SameOrigin);
        self
    }

    /// Sets the X-Frame-Options header with a custom value.
    pub fn x_frame_options(mut self, policy: XFrameOptions) -> Self {
        self.x_frame_options = Some(policy);
        self
    }

    /// Enables X-Content-Type-Options: nosniff.
    ///
    /// This is enabled by default in preset configurations.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::SecurityHeaders;
    ///
    /// let headers = SecurityHeaders::builder()
    ///     .x_content_type_options_nosniff()
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn x_content_type_options_nosniff(mut self) -> Self {
        self.x_content_type_options = true;
        self
    }

    /// Sets the Referrer-Policy header.
    pub fn referrer_policy(mut self, policy: ReferrerPolicy) -> Self {
        self.referrer_policy = Some(policy);
        self
    }

    /// Sets Referrer-Policy to no-referrer.
    pub fn referrer_policy_no_referrer(mut self) -> Self {
        self.referrer_policy = Some(ReferrerPolicy::NoReferrer);
        self
    }

    /// Sets Referrer-Policy to strict-origin-when-cross-origin.
    pub fn referrer_policy_strict_origin_when_cross_origin(mut self) -> Self {
        self.referrer_policy = Some(ReferrerPolicy::StrictOriginWhenCrossOrigin);
        self
    }

    /// Sets the Cross-Origin-Opener-Policy header.
    pub fn cross_origin_opener_policy(mut self, policy: CrossOriginOpenerPolicy) -> Self {
        self.cross_origin_opener_policy = Some(policy);
        self
    }

    /// Sets the Cross-Origin-Embedder-Policy header.
    pub fn cross_origin_embedder_policy(mut self, policy: CrossOriginEmbedderPolicy) -> Self {
        self.cross_origin_embedder_policy = Some(policy);
        self
    }

    /// Sets the Cross-Origin-Resource-Policy header.
    pub fn cross_origin_resource_policy(mut self, policy: CrossOriginResourcePolicy) -> Self {
        self.cross_origin_resource_policy = Some(policy);
        self
    }

    /// Builds the SecurityHeaders configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    pub fn build(self) -> Result<SecurityHeaders> {
        if let Some(csp) = &self.content_security_policy {
            csp.to_header_value()?;
        }

        // Validate that at least one header is configured
        if self.content_security_policy.is_none()
            && self.strict_transport_security.is_none()
            && self.x_frame_options.is_none()
            && !self.x_content_type_options
            && self.referrer_policy.is_none()
            && self.cross_origin_opener_policy.is_none()
            && self.cross_origin_embedder_policy.is_none()
            && self.cross_origin_resource_policy.is_none()
        {
            return Err(Error::ValidationFailed(
                "At least one security header must be configured".to_string(),
            ));
        }

        Ok(SecurityHeaders {
            content_security_policy: self.content_security_policy,
            strict_transport_security: self.strict_transport_security,
            x_frame_options: self.x_frame_options,
            x_content_type_options: self.x_content_type_options,
            referrer_policy: self.referrer_policy,
            cross_origin_opener_policy: self.cross_origin_opener_policy,
            cross_origin_embedder_policy: self.cross_origin_embedder_policy,
            cross_origin_resource_policy: self.cross_origin_resource_policy,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_builder_empty_fails() {
        let result = SecurityHeaders::builder().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_with_hsts() {
        let headers = SecurityHeaders::builder()
            .strict_transport_security(Duration::from_secs(31536000), true, false)
            .build()
            .unwrap();

        assert!(headers.strict_transport_security().is_some());
        let hsts = headers.strict_transport_security().unwrap();
        assert_eq!(hsts.max_age(), Duration::from_secs(31536000));
        assert!(hsts.includes_subdomains());
        assert!(!hsts.is_preload());
    }

    #[test]
    fn test_builder_with_frame_options() {
        let headers = SecurityHeaders::builder()
            .x_frame_options_deny()
            .build()
            .unwrap();

        assert_eq!(headers.x_frame_options(), Some(XFrameOptions::Deny));
    }

    #[test]
    fn test_builder_with_referrer_policy() {
        let headers = SecurityHeaders::builder()
            .referrer_policy_no_referrer()
            .build()
            .unwrap();

        assert_eq!(headers.referrer_policy(), Some(ReferrerPolicy::NoReferrer));
    }

    #[test]
    fn test_builder_with_multiple_headers() {
        let csp = ContentSecurityPolicy::new().default_src(vec!["'self'"]);

        let headers = SecurityHeaders::builder()
            .content_security_policy(csp)
            .strict_transport_security(Duration::from_secs(31536000), true, false)
            .x_frame_options_deny()
            .x_content_type_options_nosniff()
            .referrer_policy_no_referrer()
            .cross_origin_opener_policy(CrossOriginOpenerPolicy::SameOrigin)
            .cross_origin_embedder_policy(CrossOriginEmbedderPolicy::RequireCorp)
            .cross_origin_resource_policy(CrossOriginResourcePolicy::SameOrigin)
            .build()
            .unwrap();

        assert!(headers.content_security_policy().is_some());
        assert!(headers.strict_transport_security().is_some());
        assert!(headers.x_frame_options().is_some());
        assert!(headers.x_content_type_options_enabled());
        assert!(headers.referrer_policy().is_some());
        assert!(headers.cross_origin_opener_policy().is_some());
        assert!(headers.cross_origin_embedder_policy().is_some());
        assert!(headers.cross_origin_resource_policy().is_some());
    }

    #[test]
    fn test_builder_with_empty_csp_fails() {
        let result = SecurityHeaders::builder()
            .content_security_policy(ContentSecurityPolicy::new())
            .build();

        assert!(result.is_err());
    }
}
