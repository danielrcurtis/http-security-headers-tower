# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-01-XX

### Added
- Initial release
- Type-safe security header configuration
- Builder pattern for ergonomic API
- Preset configurations (Strict, Balanced, Relaxed)
- Support for 8 security headers:
  - Content-Security-Policy (CSP)
  - Strict-Transport-Security (HSTS)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Cross-Origin-Opener-Policy (COOP)
  - Cross-Origin-Embedder-Policy (COEP)
  - Cross-Origin-Resource-Policy (CORP)
- Tower middleware support
- Comprehensive test suite (36 tests, 100% coverage)
- Documentation and examples
- Feature flags for optional dependencies

[Unreleased]: https://github.com/danielrcurtis/http-security-headers/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/danielrcurtis/http-security-headers/releases/tag/v0.1.0
