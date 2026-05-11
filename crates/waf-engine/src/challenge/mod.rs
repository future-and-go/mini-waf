//! Challenge page module for bot mitigation via Proof-of-Work.
//!
//! Renders a minimal (<5KB) HTML page that auto-solves a PoW challenge
//! and sets a cookie to allow the request through on retry.

mod page_template;
mod renderer;

pub use page_template::render_challenge_page;
pub use renderer::{ChallengeContext, ChallengeError, ChallengeRenderer, ChallengeResponse, JsChallengeRenderer};
