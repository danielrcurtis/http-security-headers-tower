//! Security policy types.
//!
//! This module contains all the policy types for various security headers.

pub mod csp;
pub mod cross_origin;
pub mod frame_options;
pub mod hsts;
pub mod referrer;

pub use csp::ContentSecurityPolicy;
pub use cross_origin::{
    CrossOriginEmbedderPolicy, CrossOriginOpenerPolicy, CrossOriginResourcePolicy,
};
pub use frame_options::XFrameOptions;
pub use hsts::StrictTransportSecurity;
pub use referrer::ReferrerPolicy;
