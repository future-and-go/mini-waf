//! Challenge page module for bot mitigation via Proof-of-Work.
//!
//! Renders a minimal (<5KB) HTML page that auto-solves a `PoW` challenge
//! and sets a cookie to allow the request through on retry.

mod config;
mod page_template;
mod pow;
mod reload;
mod renderer;

pub use config::{
    BrandingConfig, ChallengeConfig, ChallengeDocument, DifficultyConfig, DifficultyTierConfig, NonceStoreConfig,
    TokenConfig,
};
pub use page_template::render_challenge_page;
pub use pow::{DifficultyMap, DifficultyTier, PowSolution, PowVerifyResult, verify_pow};
pub use reload::{ChallengeReloader, DEFAULT_DEBOUNCE_MS};
pub use renderer::{ChallengeContext, ChallengeError, ChallengeRenderer, ChallengeResponse, JsChallengeRenderer};
