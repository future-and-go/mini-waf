use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use waf_engine::WafEngine;
use waf_storage::Database;
use gateway::HostRouter;

/// Shared application state for the API server
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub engine: Arc<WafEngine>,
    pub router: Arc<HostRouter>,
    pub request_counter: Arc<AtomicU64>,
}

impl AppState {
    pub fn new(db: Arc<Database>, engine: Arc<WafEngine>, router: Arc<HostRouter>) -> Self {
        Self {
            db,
            engine,
            router,
            request_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn increment_requests(&self) {
        self.request_counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn total_requests(&self) -> u64 {
        self.request_counter.load(Ordering::Relaxed)
    }
}
