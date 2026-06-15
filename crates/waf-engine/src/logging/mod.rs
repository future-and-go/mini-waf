//! Logging subsystems for the WAF engine.
//!
//! * [`audit_sender`] — structured WAF security-event sink invoked from
//!   `WafEngine::inspect` for every non-Allow decision. Writes to the JSONL
//!   audit file sink (`audit_file_sink`). Used for audit/compliance.
//! * [`db_batch_writer`] — batched writer for `attack_logs` and
//!   `security_events` database tables.
//!
//! Both sinks fail open: if the buffer is saturated or the sink is
//! unavailable, entries are dropped and the WAF request path stays unblocked.

pub mod audit_file_sink;
pub mod audit_sender;
pub mod db_batch_writer;

pub use audit_file_sink::AuditFileSink;
pub use audit_sender::{AuditEvent, AuditEventType, AuditSender};
pub use db_batch_writer::{DbBatchWriter, DbLogEvent};
