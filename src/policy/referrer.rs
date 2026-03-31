//! Referrer-Policy header configuration.
//!
//! The Referrer-Policy header controls how much referrer information should be
//! included with requests.

use crate::error::{Error, Result};

/// Referrer-Policy header value.
///
/// # Examples
///
/// ```
/// use http_security_headers::ReferrerPolicy;
///
/// let policy = ReferrerPolicy::NoReferrer;
/// let policy = ReferrerPolicy::StrictOriginWhenCrossOrigin;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferrerPolicy {
    /// No referrer information is sent.
    NoReferrer,
    /// Only send the origin when the protocol security level stays the same (HTTPS→HTTPS).
    NoReferrerWhenDowngrade,
    /// Only send the origin, not the full URL.
    Origin,
    /// Send the full URL when performing a same-origin request, but only the origin for other cases.
    OriginWhenCrossOrigin,
    /// Send the full URL for same-origin requests, and no referrer for cross-origin requests.
    SameOrigin,
    /// Only send the origin when the protocol security level stays the same (HTTPS→HTTPS),
    /// and send no referrer to a less secure destination (HTTPS→HTTP).
    StrictOrigin,
    /// Send the full URL for same-origin requests, only the origin for cross-origin requests
    /// on the same protocol level, and no referrer to less secure destinations.
    StrictOriginWhenCrossOrigin,
    /// Send the full URL for all requests.
    UnsafeUrl,
}

impl ReferrerPolicy {
    /// Converts the policy to its header value string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoReferrer => "no-referrer",
            Self::NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
            Self::Origin => "origin",
            Self::OriginWhenCrossOrigin => "origin-when-cross-origin",
            Self::SameOrigin => "same-origin",
            Self::StrictOrigin => "strict-origin",
            Self::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
            Self::UnsafeUrl => "unsafe-url",
        }
    }
}

impl std::str::FromStr for ReferrerPolicy {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "no-referrer" => Ok(Self::NoReferrer),
            "no-referrer-when-downgrade" => Ok(Self::NoReferrerWhenDowngrade),
            "origin" => Ok(Self::Origin),
            "origin-when-cross-origin" => Ok(Self::OriginWhenCrossOrigin),
            "same-origin" => Ok(Self::SameOrigin),
            "strict-origin" => Ok(Self::StrictOrigin),
            "strict-origin-when-cross-origin" => Ok(Self::StrictOriginWhenCrossOrigin),
            "unsafe-url" => Ok(Self::UnsafeUrl),
            _ => Err(Error::InvalidReferrerPolicy(format!(
                "Unknown referrer policy: '{}'",
                s
            ))),
        }
    }
}

impl std::fmt::Display for ReferrerPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_as_str() {
        assert_eq!(ReferrerPolicy::NoReferrer.as_str(), "no-referrer");
        assert_eq!(
            ReferrerPolicy::NoReferrerWhenDowngrade.as_str(),
            "no-referrer-when-downgrade"
        );
        assert_eq!(ReferrerPolicy::Origin.as_str(), "origin");
        assert_eq!(
            ReferrerPolicy::OriginWhenCrossOrigin.as_str(),
            "origin-when-cross-origin"
        );
        assert_eq!(ReferrerPolicy::SameOrigin.as_str(), "same-origin");
        assert_eq!(ReferrerPolicy::StrictOrigin.as_str(), "strict-origin");
        assert_eq!(
            ReferrerPolicy::StrictOriginWhenCrossOrigin.as_str(),
            "strict-origin-when-cross-origin"
        );
        assert_eq!(ReferrerPolicy::UnsafeUrl.as_str(), "unsafe-url");
    }

    #[test]
    fn test_from_str() {
        assert_eq!(
            ReferrerPolicy::from_str("no-referrer").unwrap(),
            ReferrerPolicy::NoReferrer
        );
        assert_eq!(
            ReferrerPolicy::from_str("NO-REFERRER").unwrap(),
            ReferrerPolicy::NoReferrer
        );
        assert_eq!(
            ReferrerPolicy::from_str("strict-origin-when-cross-origin").unwrap(),
            ReferrerPolicy::StrictOriginWhenCrossOrigin
        );

        assert!(ReferrerPolicy::from_str("invalid").is_err());
    }

    #[test]
    fn test_display() {
        assert_eq!(ReferrerPolicy::NoReferrer.to_string(), "no-referrer");
        assert_eq!(
            ReferrerPolicy::StrictOriginWhenCrossOrigin.to_string(),
            "strict-origin-when-cross-origin"
        );
    }
}
