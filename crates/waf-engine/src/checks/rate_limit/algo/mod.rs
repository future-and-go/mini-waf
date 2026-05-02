//! Rate-limit algorithms (token bucket + sliding window).
//!
//! Pure logic only — no I/O, no locking. Backends compose these on top
//! of their own state-storage primitive (`DashMap` entry, Redis Lua, …).

pub mod sliding_window;
pub mod token_bucket;

pub use sliding_window::SlidingWindowState;
pub use token_bucket::TokenBucketState;
