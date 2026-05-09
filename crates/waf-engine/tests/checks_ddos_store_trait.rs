//! Coverage for `checks::ddos::store::CounterStore` default
//! `incr_get_blocking` bridge. Uses a tiny in-test impl that does NOT override
//! the default to actually exercise the trait body.

use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use waf_engine::checks::ddos::store::CounterStore;

struct CountingStore {
    n: AtomicU64,
}

#[async_trait]
impl CounterStore for CountingStore {
    async fn incr_get(&self, _key: &str, _ttl_ms: i64, _now_ms: i64) -> anyhow::Result<u64> {
        Ok(self.n.fetch_add(1, Ordering::SeqCst) + 1)
    }
    async fn purge_expired(&self, _now_ms: i64) -> anyhow::Result<usize> {
        Ok(0)
    }
    // NOTE: do not override `incr_get_blocking`; default impl is what we test.
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t_incr_get_blocking_default_bridge_works() {
    let store: Arc<dyn CounterStore> = Arc::new(CountingStore { n: AtomicU64::new(0) });
    let s2 = Arc::clone(&store);
    let n = tokio::task::spawn_blocking(move || s2.incr_get_blocking("k", 1000, 0))
        .await
        .expect("join")
        .expect("incr ok");
    assert_eq!(n, 1, "first increment returns 1");

    let s3 = Arc::clone(&store);
    let n2 = tokio::task::spawn_blocking(move || s3.incr_get_blocking("k", 1000, 0))
        .await
        .expect("join")
        .expect("incr ok");
    assert_eq!(n2, 2, "second increment returns 2");
}

#[tokio::test]
async fn t_purge_expired_via_dyn_dispatch() {
    let store: Arc<dyn CounterStore> = Arc::new(CountingStore { n: AtomicU64::new(0) });
    let purged = store.purge_expired(0).await.expect("purge");
    assert_eq!(purged, 0);
}
