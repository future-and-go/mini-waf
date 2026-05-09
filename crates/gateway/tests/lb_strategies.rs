//! Phase 05: load-balancer strategy edge cases.

use std::collections::HashMap;
use std::net::IpAddr;

use gateway::{Backend, LoadBalancer, LoadBalancerRegistry};
use waf_common::LoadBalanceStrategy;

fn ip() -> IpAddr {
    "127.0.0.1".parse().expect("static ip")
}

#[test]
fn empty_pool_returns_none() {
    let lb = LoadBalancer::new(LoadBalanceStrategy::RoundRobin);
    assert!(lb.next_backend(ip()).is_none(), "no backends → None");
}

#[test]
fn single_backend_always_picked() {
    let lb = LoadBalancer::new(LoadBalanceStrategy::RoundRobin);
    lb.add_backend(Backend::new("only", "10.0.0.1", 8080, 1));
    for _ in 0..20 {
        assert_eq!(lb.next_backend(ip()).expect("hit"), "10.0.0.1:8080");
    }
}

#[test]
fn all_unhealthy_falls_back_to_all_backends() {
    let lb = LoadBalancer::new(LoadBalanceStrategy::RoundRobin);
    lb.add_backend(Backend::new("a", "10.0.0.1", 80, 1));
    lb.add_backend(Backend::new("b", "10.0.0.2", 80, 1));
    for b in lb.all_backends() {
        b.set_healthy(false);
    }
    // Fallback to "all backends" branch.
    let picked = lb.next_backend(ip()).expect("fallback to all-backends");
    assert!(picked == "10.0.0.1:80" || picked == "10.0.0.2:80");
}

#[test]
fn add_backend_replaces_existing_by_id() {
    let lb = LoadBalancer::new(LoadBalanceStrategy::RoundRobin);
    lb.add_backend(Backend::new("dup", "10.0.0.1", 80, 1));
    lb.add_backend(Backend::new("dup", "10.0.0.99", 80, 1));
    assert_eq!(lb.all_backends().len(), 1);
    assert_eq!(lb.all_backends()[0].host, "10.0.0.99");
}

#[test]
fn remove_backend_drops_entry() {
    let lb = LoadBalancer::new(LoadBalanceStrategy::RoundRobin);
    lb.add_backend(Backend::new("x", "10.0.0.1", 80, 1));
    lb.add_backend(Backend::new("y", "10.0.0.2", 80, 1));
    lb.remove_backend("x");
    let remain = lb.all_backends();
    assert_eq!(remain.len(), 1);
    assert_eq!(remain[0].id, "y");
}

#[test]
fn set_backends_replaces_pool() {
    let lb = LoadBalancer::new(LoadBalanceStrategy::RoundRobin);
    lb.add_backend(Backend::new("old", "10.0.0.1", 80, 1));
    lb.set_backends(vec![
        Backend::new("new1", "10.0.0.2", 80, 1),
        Backend::new("new2", "10.0.0.3", 80, 1),
    ]);
    let names: Vec<_> = lb.all_backends().iter().map(|b| b.id.clone()).collect();
    assert_eq!(names, vec!["new1", "new2"]);
}

#[test]
fn weighted_distribution_skews_to_higher_weight() {
    let lb = LoadBalancer::new(LoadBalanceStrategy::WeightedRoundRobin);
    lb.add_backend(Backend::new("low", "10.0.0.1", 80, 1));
    lb.add_backend(Backend::new("high", "10.0.0.2", 80, 9));
    let mut counts: HashMap<String, usize> = HashMap::new();
    for _ in 0..1000 {
        let addr = lb.next_backend(ip()).expect("hit");
        *counts.entry(addr).or_insert(0) += 1;
    }
    let high = counts.get("10.0.0.2:80").copied().unwrap_or(0);
    let low = counts.get("10.0.0.1:80").copied().unwrap_or(0);
    // High should be ~9× low; allow wide tolerance.
    assert!(high > low * 4, "weighted: {high} vs {low}");
}

#[test]
fn weighted_with_zero_weight_uses_min_weight_one() {
    let lb = LoadBalancer::new(LoadBalanceStrategy::WeightedRoundRobin);
    // weight=0 path gets max(1) → still selectable.
    lb.add_backend(Backend::new("a", "10.0.0.1", 80, 0));
    lb.add_backend(Backend::new("b", "10.0.0.2", 80, 0));
    let mut hit = false;
    for _ in 0..50 {
        if lb.next_backend(ip()).is_some() {
            hit = true;
        }
    }
    assert!(hit, "weight=0 backends still selected via max(1)");
}

#[test]
fn least_connections_picks_fewest() {
    let lb = LoadBalancer::new(LoadBalanceStrategy::LeastConnections);
    lb.add_backend(Backend::new("loaded", "10.0.0.1", 80, 1));
    lb.add_backend(Backend::new("idle", "10.0.0.2", 80, 1));
    let bs = lb.all_backends();
    for _ in 0..5 {
        bs[0].acquire_connection();
    }
    assert_eq!(lb.next_backend(ip()).expect("hit"), "10.0.0.2:80");
}

#[test]
fn release_connection_underflow_protected() {
    let b = Backend::new("u", "10.0.0.1", 80, 1);
    b.release_connection(); // never acquired
    b.release_connection();
    // Defensive: should not panic; counter clamped.
    b.acquire_connection();
    assert!(b.is_healthy());
}

#[test]
fn ip_hash_distributes_across_distinct_ips() {
    let lb = LoadBalancer::new(LoadBalanceStrategy::IpHash);
    lb.add_backend(Backend::new("a", "10.0.0.1", 80, 1));
    lb.add_backend(Backend::new("b", "10.0.0.2", 80, 1));
    let mut seen = std::collections::HashSet::new();
    for octet in 1..=50u8 {
        let ip: IpAddr = format!("192.168.0.{octet}").parse().expect("ip");
        if let Some(addr) = lb.next_backend(ip) {
            seen.insert(addr);
        }
    }
    assert!(seen.len() >= 2, "ip-hash should hit >1 backend across 50 IPs");
}

#[test]
fn registry_register_get_remove() {
    let reg = LoadBalancerRegistry::new();
    assert!(reg.is_empty());
    let lb = LoadBalancer::new(LoadBalanceStrategy::RoundRobin);
    lb.add_backend(Backend::new("a", "1.1.1.1", 80, 1));
    reg.register("host1", lb);
    assert_eq!(reg.len(), 1);
    assert!(reg.get("host1").is_some());
    assert!(reg.get("missing").is_none());
    reg.remove("host1");
    assert!(reg.get("host1").is_none());
    assert!(reg.is_empty());
}

#[test]
fn registry_default_is_empty() {
    let reg = LoadBalancerRegistry::default();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
}

#[test]
fn backend_addr_format() {
    let b = Backend::new("id", "host.example", 1234, 5);
    assert_eq!(b.addr(), "host.example:1234");
}

#[test]
fn backend_health_toggle() {
    let b = Backend::new("id", "h", 80, 1);
    assert!(b.is_healthy());
    b.set_healthy(false);
    assert!(!b.is_healthy());
    b.set_healthy(true);
    assert!(b.is_healthy());
}

#[tokio::test]
async fn tcp_health_check_unreachable_port_returns_false() {
    use std::time::Duration;
    // 127.0.0.1:1 is conventionally closed.
    let ok = gateway::lb::tcp_health_check("127.0.0.1", 1, Duration::from_millis(100)).await;
    assert!(!ok, "closed port → unhealthy");
}
