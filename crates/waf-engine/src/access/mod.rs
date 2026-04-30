//! FR-008 — IP/Host whitelist + blacklist subsystem.
//!
//! Phase-01 wires only the public data model and YAML parser. The IP trie
//! (`ip_table`), host gate (`host_gate`), and runtime evaluator (`evaluator`)
//! are filled by phases 02-04.

pub mod config;
pub mod evaluator;
pub mod host_gate;
pub mod ip_table;
pub mod reload;

pub use config::{AccessConfig, AccessLists, WhitelistMode};
pub use evaluator::{AccessDecision, AccessRequestView, BlockReason, evaluate};
pub use host_gate::HostGate;
pub use ip_table::IpCidrTable;
pub use reload::{AccessReloader, DEFAULT_DEBOUNCE_MS, WatcherError};
