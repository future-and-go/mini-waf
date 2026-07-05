# 2026-07-05 — GH-202: RiskBump actor-keyed sync submit

## What

Three latent `RiskBumpAction` defects fixed on branch
`fix/gh-202-riskbump-actor-keyed-submit` (stacked on
`fix/gh-204-risk-delta-cap-decay-config`). All were latent because the engine
wires ban-only actions today; they would fire the moment `ban_and_risk` is
enabled:

1. **`block_in_place` panic** on `current_thread` runtimes (prx-waf main uses
   `new_current_thread`). Replaced by a sync `RiskAggregator::submit_ip(ip,
   signals)` trait method — `try_send` is already sync, so no bridge is needed.
   `ScoringAggregator` shares one private `enqueue` between both seams.
2. **Phantom actor.** The IP was smuggled as `FpKey { ja3: "ddos:{ip}" }` and
   hashed to an fp axis the request-path scorer (`RiskKey::from_ip`) never
   joins. Ingest `Job` now carries `fp_key: Option<FpKey>` + `actor_ip:
   Option<IpAddr>` (`Job::for_fp` / `Job::for_ip`); the worker builds
   `RiskKey { ip, fp_hash, session: None }` and drops with the unresolved-key
   metric only when both axes are None.
3. **Severity flattening.** The 0-100 detector delta went through
   `Signal::BurstInterval { count }` and the weight table (flat 20/30). New
   `Signal::DdosBurst { risk_delta: u8 }` maps passthrough to the contributor
   delta — deliberately not weight-table routed.

Non-goals kept: `ban_and_risk` stays unwired in `engine.rs`; no SoftAnomaly
action-policy change; no redis store changes.

## Verified

- New acceptance suite `tests/ddos_risk_bump_acceptance.rs`, deliberately on
  the default current_thread test runtime: HardBurst → state readable at
  `RiskKey::from_ip` with `ddos_burst` delta 100; SoftAnomaly(37) → delta 37
  end-to-end; phantom-key regression (no state under the smuggled shape).
- `risk.rs` action unit tests converted from `#[tokio::test(multi_thread)]`
  to plain `#[test]` — itself the unit-level panic-regression proof.
- waf-engine lib (redis-store): 1453 passed + the known 6 docker-gated
  `engine::tests` failures (environmental). Workspace tests, clippy (both
  feature sets), fmt clean.

## Gotchas

- `LoggingAggregator::submit_ip` records `key: FpKey::default()` +
  `actor_ip: Some(ip)` — assertions should check `actor_ip`, not the key.
- `DdosBurst` bypasses `SignalWeights` overrides by design; severity is
  operator-controlled at the DDoS detector config instead.
- The worker's drop-on-unresolvable branch is now "both axes None"; an empty
  `FpKey` alone no longer drops if an IP is present.
