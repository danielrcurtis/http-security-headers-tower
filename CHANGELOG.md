# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-03-30

### Changed
- Bump dependency versions: tower 0.5.2, http-body 1.0.1, pin-project-lite 0.2.16, actix-web 4.11, futures-util 0.3.31, tracing 0.1.41, metrics 0.24.2, regex 1.12.2
- Bump dev-dependency versions: tower 0.5.2, http 1.3.1, http-body-util 0.1.3, bytes 1.10.1, hyper 1.7

### Fixed
- CSP `to_header_value()` now produces deterministic directive ordering (sorted alphabetically)
- HSTS validation now runs at `build()` time — invalid preload configurations are caught immediately instead of being silently dropped at request time
- Populate LICENSE-MIT with full license text

## [0.1.0] - 2025-11-08

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

[Unreleased]: https://github.com/danielrcurtis/http-security-headers/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/danielrcurtis/http-security-headers/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/danielrcurtis/http-security-headers/releases/tag/v0.1.0
