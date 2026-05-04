//! FR-011 behavior classifiers — `SignalProvider` impls that read from a
//! per-actor `Recorder` snapshot.
//!
//! Behavior providers differ from `device_fp/providers/*` in one way: they
//! key off `ctx.key` to fetch a `Recorder` snapshot rather than computing
//! over `ctx`'s in-band fields. Otherwise they implement the same trait so
//! the existing `ProviderRegistry::dispatch` fan-out covers them.

pub mod burst_interval;

pub use burst_interval::BurstIntervalProvider;
