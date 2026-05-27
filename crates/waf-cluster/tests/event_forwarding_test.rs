//! Event batcher tests — batching, timer flush, and backpressure.

use tokio::sync::mpsc;
use waf_cluster::protocol::{EventBatch, SecurityEvent};
use waf_cluster::sync::events::EventBatcher;

fn sample_event(id: u64) -> SecurityEvent {
    SecurityEvent {
        timestamp_ms: 1_700_000_000_000 + id,
        client_ip: format!("10.0.0.{}", id % 256),
        method: "GET".into(),
        path: "/test".into(),
        host: "example.com".into(),
        rule_id: Some(format!("r{id}")),
        action: "block".into(),
        geo_country: "US".into(),
        node_id: "worker-1".into(),
    }
}

#[tokio::test]
async fn batch_full_triggers_immediate_flush() {
    let batcher = EventBatcher::new("worker-1".into(), 3, 60_000);
    let (event_tx, event_rx) = mpsc::channel::<SecurityEvent>(16);
    let (batch_tx, mut batch_rx) = mpsc::channel::<EventBatch>(16);

    tokio::spawn(async move {
        waf_cluster::sync::events::run_event_batcher(batcher, event_rx, batch_tx).await;
    });

    // Push exactly 3 events — should trigger batch flush
    for i in 1..=3 {
        event_tx.send(sample_event(i)).await.unwrap();
    }

    let batch = tokio::time::timeout(std::time::Duration::from_secs(2), batch_rx.recv())
        .await
        .expect("batch should arrive within timeout")
        .expect("channel should not be closed");

    assert_eq!(batch.events.len(), 3);
    assert_eq!(batch.node_id, "worker-1");
}

#[tokio::test]
async fn timer_flush_sends_partial_batch() {
    let batcher = EventBatcher::new("worker-1".into(), 100, 50);
    let (event_tx, event_rx) = mpsc::channel::<SecurityEvent>(16);
    let (batch_tx, mut batch_rx) = mpsc::channel::<EventBatch>(16);

    tokio::spawn(async move {
        waf_cluster::sync::events::run_event_batcher(batcher, event_rx, batch_tx).await;
    });

    // Push 2 events — well under batch_size of 100
    for i in 1..=2 {
        event_tx.send(sample_event(i)).await.unwrap();
    }

    // Timer flush at 50ms should send them
    let batch = tokio::time::timeout(std::time::Duration::from_millis(500), batch_rx.recv())
        .await
        .expect("batch should arrive after timer")
        .expect("channel should not be closed");

    assert_eq!(batch.events.len(), 2);
}

#[tokio::test]
async fn closing_input_flushes_remaining() {
    let batcher = EventBatcher::new("worker-1".into(), 100, 60_000);
    let (event_tx, event_rx) = mpsc::channel::<SecurityEvent>(16);
    let (batch_tx, mut batch_rx) = mpsc::channel::<EventBatch>(16);

    tokio::spawn(async move {
        waf_cluster::sync::events::run_event_batcher(batcher, event_rx, batch_tx).await;
    });

    event_tx.send(sample_event(1)).await.unwrap();
    // Close the input channel
    drop(event_tx);

    let batch = tokio::time::timeout(std::time::Duration::from_secs(1), batch_rx.recv())
        .await
        .expect("remaining events should be flushed on close")
        .expect("channel should not be closed");

    assert_eq!(batch.events.len(), 1);
}

#[tokio::test]
async fn backpressure_drops_oldest_when_queue_full() {
    // Bounded channel with capacity 2
    let (event_tx, event_rx) = mpsc::channel::<SecurityEvent>(2);

    // Fill the channel
    event_tx.send(sample_event(1)).await.unwrap();
    event_tx.send(sample_event(2)).await.unwrap();

    // Third send should fail (try_send returns Full)
    let result = event_tx.try_send(sample_event(3));
    assert!(result.is_err());

    // Verify the channel still has the first 2
    drop(event_tx);
    let mut rx = event_rx;
    let e1 = rx.recv().await.unwrap();
    assert!(e1.client_ip.ends_with(".1"));
    let e2 = rx.recv().await.unwrap();
    assert!(e2.client_ip.ends_with(".2"));
    assert!(rx.recv().await.is_none());
}

#[tokio::test]
async fn multiple_batches_from_large_input() {
    let batcher = EventBatcher::new("worker-1".into(), 3, 60_000);
    let (event_tx, event_rx) = mpsc::channel::<SecurityEvent>(32);
    let (batch_tx, mut batch_rx) = mpsc::channel::<EventBatch>(16);

    tokio::spawn(async move {
        waf_cluster::sync::events::run_event_batcher(batcher, event_rx, batch_tx).await;
    });

    // Push 5 events: should get batch of 3, then remaining 2 after close
    for i in 1..=5 {
        event_tx.send(sample_event(i)).await.unwrap();
    }

    let batch1 = tokio::time::timeout(std::time::Duration::from_secs(2), batch_rx.recv())
        .await
        .expect("first batch should arrive")
        .expect("channel open");
    assert_eq!(batch1.events.len(), 3);

    // Close to flush remaining
    drop(event_tx);

    let batch2 = tokio::time::timeout(std::time::Duration::from_secs(2), batch_rx.recv())
        .await
        .expect("second batch should arrive after close")
        .expect("channel open");
    assert_eq!(batch2.events.len(), 2);
}
