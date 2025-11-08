//! Content-Security-Policy (CSP) header configuration.
//!
//! CSP helps prevent cross-site scripting (XSS), clickjacking, and other code injection
//! attacks by specifying which dynamic resources are allowed to load.

use crate::error::{Error, Result};
use std::collections::HashMap;

/// Content-Security-Policy configuration.
///
/// # Examples
///
/// ```
/// use http_security_headers::ContentSecurityPolicy;
///
/// let csp = ContentSecurityPolicy::new()
///     .default_src(vec!["'self'"])
///     .script_src(vec!["'self'", "'unsafe-inline'"])
///     .style_src(vec!["'self'", "https://fonts.googleapis.com"])
///     .img_src(vec!["'self'", "data:", "https:"]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentSecurityPolicy {
    directives: HashMap<String, Vec<String>>,
}

impl ContentSecurityPolicy {
    /// Creates a new empty CSP policy.
    pub fn new() -> Self {
        Self {
            directives: HashMap::new(),
        }
    }

    /// Sets the `default-src` directive.
    ///
    /// This serves as a fallback for other fetch directives.
    pub fn default_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("default-src", sources);
        self
    }

    /// Sets the `script-src` directive.
    ///
    /// Specifies valid sources for JavaScript.
    pub fn script_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("script-src", sources);
        self
    }

    /// Sets the `style-src` directive.
    ///
    /// Specifies valid sources for stylesheets.
    pub fn style_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("style-src", sources);
        self
    }

    /// Sets the `img-src` directive.
    ///
    /// Specifies valid sources for images.
    pub fn img_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("img-src", sources);
        self
    }

    /// Sets the `font-src` directive.
    ///
    /// Specifies valid sources for fonts.
    pub fn font_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("font-src", sources);
        self
    }

    /// Sets the `connect-src` directive.
    ///
    /// Restricts URLs that can be loaded using script interfaces (fetch, XHR, WebSocket, etc.).
    pub fn connect_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("connect-src", sources);
        self
    }

    /// Sets the `object-src` directive.
    ///
    /// Specifies valid sources for `<object>`, `<embed>`, and `<applet>` elements.
    pub fn object_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("object-src", sources);
        self
    }

    /// Sets the `frame-src` directive.
    ///
    /// Specifies valid sources for nested browsing contexts loaded using `<frame>` and `<iframe>`.
    pub fn frame_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("frame-src", sources);
        self
    }

    /// Sets the `base-uri` directive.
    ///
    /// Restricts the URLs that can be used in a document's `<base>` element.
    pub fn base_uri<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("base-uri", sources);
        self
    }

    /// Sets the `form-action` directive.
    ///
    /// Restricts the URLs which can be used as the target of form submissions.
    pub fn form_action<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("form-action", sources);
        self
    }

    /// Sets the `frame-ancestors` directive.
    ///
    /// Specifies valid parents that may embed a page using `<frame>`, `<iframe>`, etc.
    pub fn frame_ancestors<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("frame-ancestors", sources);
        self
    }

    /// Sets the `upgrade-insecure-requests` directive (valueless).
    ///
    /// Instructs browsers to upgrade all insecure requests to HTTPS.
    pub fn upgrade_insecure_requests(mut self) -> Self {
        self.directives
            .insert("upgrade-insecure-requests".to_string(), vec![]);
        self
    }

    /// Sets the `block-all-mixed-content` directive (valueless).
    ///
    /// Prevents loading any mixed content (HTTP resources on HTTPS pages).
    pub fn block_all_mixed_content(mut self) -> Self {
        self.directives
            .insert("block-all-mixed-content".to_string(), vec![]);
        self
    }

    /// Sets a custom directive.
    ///
    /// This allows setting directives not covered by the convenience methods.
    pub fn directive<I, S>(mut self, name: &str, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive(name, sources);
        self
    }

    /// Helper method to set a directive.
    fn set_directive<I, S>(&mut self, name: &str, sources: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let sources: Vec<String> = sources.into_iter().map(|s| s.into()).collect();
        self.directives.insert(name.to_string(), sources);
    }

    /// Converts the policy to its header value string.
    pub fn to_header_value(&self) -> Result<String> {
        if self.directives.is_empty() {
            return Err(Error::InvalidCsp("CSP policy is empty".to_string()));
        }

        let mut parts = Vec::new();

        for (directive, sources) in &self.directives {
            if sources.is_empty() {
                // Valueless directives (upgrade-insecure-requests, block-all-mixed-content)
                parts.push(directive.clone());
            } else {
                parts.push(format!("{} {}", directive, sources.join(" ")));
            }
        }

        Ok(parts.join("; "))
    }

    /// Parses a CSP policy from a header value string.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::ContentSecurityPolicy;
    ///
    /// let csp = ContentSecurityPolicy::parse("default-src 'self'; script-src 'unsafe-inline'").unwrap();
    /// ```
    pub fn parse(value: &str) -> Result<Self> {
        let mut csp = Self::new();

        for directive_str in value.split(';').map(|s| s.trim()) {
            if directive_str.is_empty() {
                continue;
            }

            let parts: Vec<&str> = directive_str.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let directive_name = parts[0];
            let sources: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();

            csp.directives.insert(directive_name.to_string(), sources);
        }

        if csp.directives.is_empty() {
            return Err(Error::InvalidCsp("No directives found".to_string()));
        }

        Ok(csp)
    }
}

impl Default for ContentSecurityPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ContentSecurityPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_header_value().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let csp = ContentSecurityPolicy::new();
        assert!(csp.directives.is_empty());
    }

    #[test]
    fn test_builder() {
        let csp = ContentSecurityPolicy::new()
            .default_src(vec!["'self'"])
            .script_src(vec!["'self'", "'unsafe-inline'"])
            .style_src(vec!["'self'", "https://fonts.googleapis.com"]);

        assert_eq!(csp.directives.len(), 3);
        assert_eq!(csp.directives.get("default-src").unwrap(), &vec!["'self'"]);
        assert_eq!(
            csp.directives.get("script-src").unwrap(),
            &vec!["'self'", "'unsafe-inline'"]
        );
    }

    #[test]
    fn test_to_header_value() {
        let csp = ContentSecurityPolicy::new()
            .default_src(vec!["'self'"])
            .script_src(vec!["'self'", "'unsafe-inline'"]);

        let header = csp.to_header_value().unwrap();
        assert!(header.contains("default-src 'self'"));
        assert!(header.contains("script-src 'self' 'unsafe-inline'"));
    }

    #[test]
    fn test_valueless_directives() {
        let csp = ContentSecurityPolicy::new()
            .default_src(vec!["'self'"])
            .upgrade_insecure_requests();

        let header = csp.to_header_value().unwrap();
        assert!(header.contains("upgrade-insecure-requests"));
        assert!(header.contains("default-src 'self'"));
    }

    #[test]
    fn test_empty_policy_error() {
        let csp = ContentSecurityPolicy::new();
        assert!(csp.to_header_value().is_err());
    }

    #[test]
    fn test_parse() {
        let csp =
            ContentSecurityPolicy::parse("default-src 'self'; script-src 'unsafe-inline'")
                .unwrap();

        assert_eq!(csp.directives.len(), 2);
        assert_eq!(csp.directives.get("default-src").unwrap(), &vec!["'self'"]);
        assert_eq!(
            csp.directives.get("script-src").unwrap(),
            &vec!["'unsafe-inline'"]
        );
    }

    #[test]
    fn test_parse_empty() {
        assert!(ContentSecurityPolicy::parse("").is_err());
        assert!(ContentSecurityPolicy::parse("   ").is_err());
    }

    #[test]
    fn test_custom_directive() {
        let csp = ContentSecurityPolicy::new()
            .directive("worker-src", vec!["'self'", "blob:"]);

        assert_eq!(
            csp.directives.get("worker-src").unwrap(),
            &vec!["'self'", "blob:"]
        );
    }
}
