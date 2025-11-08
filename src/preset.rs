//! Preset security header configurations.
//!
//! This module provides pre-configured security header sets for common use cases.

use crate::config::SecurityHeaders;
use crate::policy::*;
use std::time::Duration;

/// Security preset levels.
///
/// # Examples
///
/// ```
/// use http_security_headers::Preset;
///
/// let headers = Preset::Strict.build();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    /// Strict security configuration.
    ///
    /// Recommended for applications that can enforce strict security policies.
    /// May break functionality if not properly configured.
    ///
    /// Includes:
    /// - CSP: `default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`
    /// - HSTS: 1 year, includeSubDomains
    /// - X-Frame-Options: DENY
    /// - X-Content-Type-Options: nosniff
    /// - Referrer-Policy: no-referrer
    /// - COOP: same-origin
    /// - COEP: require-corp
    /// - CORP: same-origin
    Strict,

    /// Balanced security configuration.
    ///
    /// Provides good security while maintaining compatibility with most applications.
    ///
    /// Includes:
    /// - CSP: `default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'`
    /// - HSTS: 1 year, includeSubDomains
    /// - X-Frame-Options: SAMEORIGIN
    /// - X-Content-Type-Options: nosniff
    /// - Referrer-Policy: strict-origin-when-cross-origin
    /// - COOP: same-origin-allow-popups
    Balanced,

    /// Relaxed security configuration.
    ///
    /// Provides baseline security with minimal restrictions.
    /// Suitable for applications that need maximum compatibility.
    ///
    /// Includes:
    /// - HSTS: 6 months
    /// - X-Frame-Options: SAMEORIGIN
    /// - X-Content-Type-Options: nosniff
    /// - Referrer-Policy: strict-origin-when-cross-origin
    Relaxed,
}

impl Preset {
    /// Builds the SecurityHeaders for this preset.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::Preset;
    ///
    /// let headers = Preset::Strict.build();
    /// ```
    pub fn build(self) -> SecurityHeaders {
        match self {
            Self::Strict => self.build_strict(),
            Self::Balanced => self.build_balanced(),
            Self::Relaxed => self.build_relaxed(),
        }
    }

    fn build_strict(self) -> SecurityHeaders {
        let csp = ContentSecurityPolicy::new()
            .default_src(vec!["'self'"])
            .object_src(vec!["'none'"])
            .base_uri(vec!["'self'"])
            .frame_ancestors(vec!["'none'"]);

        SecurityHeaders::builder()
            .content_security_policy(csp)
            .strict_transport_security(Duration::from_secs(31536000), true, false)
            .x_frame_options_deny()
            .x_content_type_options_nosniff()
            .referrer_policy_no_referrer()
            .cross_origin_opener_policy(CrossOriginOpenerPolicy::SameOrigin)
            .cross_origin_embedder_policy(CrossOriginEmbedderPolicy::RequireCorp)
            .cross_origin_resource_policy(CrossOriginResourcePolicy::SameOrigin)
            .build()
            .expect("strict preset should always be valid")
    }

    fn build_balanced(self) -> SecurityHeaders {
        let csp = ContentSecurityPolicy::new()
            .default_src(vec!["'self'"])
            .script_src(vec!["'self'", "'unsafe-inline'"])
            .object_src(vec!["'none'"]);

        SecurityHeaders::builder()
            .content_security_policy(csp)
            .strict_transport_security(Duration::from_secs(31536000), true, false)
            .x_frame_options_sameorigin()
            .x_content_type_options_nosniff()
            .referrer_policy_strict_origin_when_cross_origin()
            .cross_origin_opener_policy(CrossOriginOpenerPolicy::SameOriginAllowPopups)
            .build()
            .expect("balanced preset should always be valid")
    }

    fn build_relaxed(self) -> SecurityHeaders {
        SecurityHeaders::builder()
            .strict_transport_security(Duration::from_secs(15552000), false, false) // 6 months
            .x_frame_options_sameorigin()
            .x_content_type_options_nosniff()
            .referrer_policy_strict_origin_when_cross_origin()
            .build()
            .expect("relaxed preset should always be valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_preset() {
        let headers = Preset::Strict.build();

        assert!(headers.content_security_policy().is_some());
        assert!(headers.strict_transport_security().is_some());
        assert_eq!(headers.x_frame_options(), Some(XFrameOptions::Deny));
        assert!(headers.x_content_type_options_enabled());
        assert_eq!(headers.referrer_policy(), Some(ReferrerPolicy::NoReferrer));
        assert_eq!(
            headers.cross_origin_opener_policy(),
            Some(CrossOriginOpenerPolicy::SameOrigin)
        );
        assert_eq!(
            headers.cross_origin_embedder_policy(),
            Some(CrossOriginEmbedderPolicy::RequireCorp)
        );
        assert_eq!(
            headers.cross_origin_resource_policy(),
            Some(CrossOriginResourcePolicy::SameOrigin)
        );
    }

    #[test]
    fn test_balanced_preset() {
        let headers = Preset::Balanced.build();

        assert!(headers.content_security_policy().is_some());
        assert!(headers.strict_transport_security().is_some());
        assert_eq!(headers.x_frame_options(), Some(XFrameOptions::SameOrigin));
        assert!(headers.x_content_type_options_enabled());
        assert_eq!(
            headers.referrer_policy(),
            Some(ReferrerPolicy::StrictOriginWhenCrossOrigin)
        );
        assert_eq!(
            headers.cross_origin_opener_policy(),
            Some(CrossOriginOpenerPolicy::SameOriginAllowPopups)
        );
    }

    #[test]
    fn test_relaxed_preset() {
        let headers = Preset::Relaxed.build();

        assert!(headers.content_security_policy().is_none());
        assert!(headers.strict_transport_security().is_some());
        assert_eq!(headers.x_frame_options(), Some(XFrameOptions::SameOrigin));
        assert!(headers.x_content_type_options_enabled());
        assert_eq!(
            headers.referrer_policy(),
            Some(ReferrerPolicy::StrictOriginWhenCrossOrigin)
        );

        let hsts = headers.strict_transport_security().unwrap();
        assert_eq!(hsts.max_age(), Duration::from_secs(15552000)); // 6 months
    }
}
