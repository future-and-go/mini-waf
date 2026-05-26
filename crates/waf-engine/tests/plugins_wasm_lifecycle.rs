//! Integration tests for `plugins::manager` — WASM plugin lifecycle.
//!
//! Covers: load valid WAT→WASM, run_request, disable/enable, unload,
//! hot-reload (load v2 over v1), rejection of invalid bytes,
//! isolation (one plugin error does not crash others), list/get.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::redundant_clone,
    clippy::significant_drop_tightening,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::needless_raw_string_hashes,
    clippy::default_trait_access
)]

use uuid::Uuid;
use waf_engine::plugins::manager::{LoadPluginParams, PluginAction, PluginManager, WasmPlugin};

// ── WAT fixtures ─────────────────────────────────────────────────────────────

/// Minimal WASM module that always returns Allow (0) from `on_request`.
fn wat_allow() -> Vec<u8> {
    wat::parse_str(
        r#"(module
             (func (export "on_request") (result i32) i32.const 0)
           )"#,
    )
    .expect("valid WAT")
}

/// WASM module that always returns Block (1) from `on_request`.
fn wat_block() -> Vec<u8> {
    wat::parse_str(
        r#"(module
             (func (export "on_request") (result i32) i32.const 1)
           )"#,
    )
    .expect("valid WAT")
}

/// WASM module that always returns Log (2) from `on_request`.
fn wat_log() -> Vec<u8> {
    wat::parse_str(
        r#"(module
             (func (export "on_request") (result i32) i32.const 2)
           )"#,
    )
    .expect("valid WAT")
}

/// WASM module that exposes `get_action` (legacy export name) returning Block.
fn wat_get_action_block() -> Vec<u8> {
    wat::parse_str(
        r#"(module
             (func (export "get_action") (result i32) i32.const 1)
           )"#,
    )
    .expect("valid WAT")
}

/// WASM module with no `on_request` or `get_action` → defaults to Allow.
fn wat_no_export() -> Vec<u8> {
    wat::parse_str(r#"(module (func (export "noop")))"#).expect("valid WAT")
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn params<'a>(id: Uuid, name: &str, wasm: &'a [u8]) -> LoadPluginParams<'a> {
    LoadPluginParams {
        id,
        name: name.to_string(),
        version: "1.0".to_string(),
        description: String::new(),
        author: "test".to_string(),
        enabled: true,
        wasm_bytes: wasm,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn load_allow_plugin_returns_allow_on_request() {
    let mgr = PluginManager::new();
    let id = Uuid::new_v4();
    mgr.load(params(id, "allow-plugin", &wat_allow())).await.expect("load");

    let action = mgr.run_request("GET", "/", "1.2.3.4").await;
    assert_eq!(action, PluginAction::Allow);
}

#[tokio::test]
async fn load_block_plugin_short_circuits_on_block() {
    let mgr = PluginManager::new();
    let id = Uuid::new_v4();
    mgr.load(params(id, "block-plugin", &wat_block())).await.expect("load");

    let action = mgr.run_request("GET", "/admin", "9.9.9.9").await;
    assert_eq!(action, PluginAction::Block);
}

#[tokio::test]
async fn load_log_plugin_upgrades_allow_to_log() {
    let mgr = PluginManager::new();
    let id = Uuid::new_v4();
    mgr.load(params(id, "log-plugin", &wat_log())).await.expect("load");

    let action = mgr.run_request("GET", "/api", "2.2.2.2").await;
    assert_eq!(action, PluginAction::Log);
}

#[tokio::test]
async fn get_action_export_name_works_as_fallback() {
    let mgr = PluginManager::new();
    let id = Uuid::new_v4();
    mgr.load(params(id, "legacy", &wat_get_action_block()))
        .await
        .expect("load");

    let action = mgr.run_request("POST", "/", "3.3.3.3").await;
    assert_eq!(action, PluginAction::Block);
}

#[tokio::test]
async fn no_export_defaults_to_allow() {
    let mgr = PluginManager::new();
    let id = Uuid::new_v4();
    mgr.load(params(id, "noop", &wat_no_export())).await.expect("load");

    let action = mgr.run_request("GET", "/", "4.4.4.4").await;
    assert_eq!(action, PluginAction::Allow);
}

#[tokio::test]
async fn invalid_wasm_bytes_rejected_by_load() {
    let mgr = PluginManager::new();
    let id = Uuid::new_v4();
    let res = mgr.load(params(id, "bad", b"not-wasm-bytes")).await;
    assert!(res.is_err());
    // Plugin must not appear in list.
    assert!(mgr.list().await.is_empty());
}

#[tokio::test]
async fn disabled_plugin_returns_allow_regardless() {
    let mgr = PluginManager::new();
    let id = Uuid::new_v4();
    let wasm = wat_block();
    let mut p = params(id, "disabled-block", &wasm);
    p.enabled = false;
    mgr.load(p).await.expect("load");

    // Even though the WASM returns Block, the plugin is disabled.
    let action = mgr.run_request("GET", "/", "5.5.5.5").await;
    assert_eq!(action, PluginAction::Allow);
}

#[tokio::test]
async fn set_enabled_false_then_true_toggles_behaviour() {
    let mgr = PluginManager::new();
    let id = Uuid::new_v4();
    mgr.load(params(id, "toggle", &wat_block())).await.expect("load");

    // Initially enabled → Block.
    assert_eq!(mgr.run_request("GET", "/", "1.1.1.1").await, PluginAction::Block);

    // Disable → Allow.
    assert!(mgr.set_enabled(id, false).await);
    assert_eq!(mgr.run_request("GET", "/", "1.1.1.1").await, PluginAction::Allow);

    // Re-enable → Block again.
    assert!(mgr.set_enabled(id, true).await);
    assert_eq!(mgr.run_request("GET", "/", "1.1.1.1").await, PluginAction::Block);
}

#[tokio::test]
async fn unload_removes_plugin() {
    let mgr = PluginManager::new();
    let id = Uuid::new_v4();
    mgr.load(params(id, "to-remove", &wat_block())).await.expect("load");

    assert!(mgr.unload(id).await);
    // After removal manager is empty.
    assert!(mgr.list().await.is_empty());
    // run_request with no plugins → Allow.
    assert_eq!(mgr.run_request("GET", "/", "6.6.6.6").await, PluginAction::Allow);
}

#[tokio::test]
async fn hot_reload_replaces_plugin_in_place() {
    let mgr = PluginManager::new();
    let id = Uuid::new_v4();

    // v1: Allow plugin.
    mgr.load(params(id, "hot-reload-v1", &wat_allow()))
        .await
        .expect("load v1");
    assert_eq!(mgr.run_request("GET", "/", "7.7.7.7").await, PluginAction::Allow);

    // v2: Block plugin (same id).
    mgr.load(params(id, "hot-reload-v2", &wat_block()))
        .await
        .expect("load v2");
    assert_eq!(mgr.run_request("GET", "/", "7.7.7.7").await, PluginAction::Block);

    // Only one entry in the registry.
    assert_eq!(mgr.list().await.len(), 1);
}

#[tokio::test]
async fn block_plugin_short_circuits_before_log_plugin() {
    let mgr = PluginManager::new();
    let block_id = Uuid::new_v4();
    let log_id = Uuid::new_v4();

    mgr.load(params(block_id, "blocker", &wat_block()))
        .await
        .expect("load block");
    mgr.load(params(log_id, "logger", &wat_log())).await.expect("load log");

    // Block is returned immediately — Log plugin is never reached.
    let action = mgr.run_request("GET", "/", "8.8.8.8").await;
    assert_eq!(action, PluginAction::Block);
}

#[tokio::test]
async fn get_returns_plugin_by_id() {
    let mgr = PluginManager::new();
    let id = Uuid::new_v4();
    mgr.load(params(id, "find-me", &wat_allow())).await.expect("load");

    let found = mgr.get(id).await;
    assert!(found.is_some());
    assert_eq!(found.expect("some").name, "find-me");

    // Non-existent id → None.
    assert!(mgr.get(Uuid::new_v4()).await.is_none());
}

#[tokio::test]
async fn list_returns_info_for_all_plugins() {
    let mgr = PluginManager::new();
    let id1 = Uuid::new_v4();
    let id2 = Uuid::new_v4();
    mgr.load(params(id1, "p1", &wat_allow())).await.expect("p1");
    mgr.load(params(id2, "p2", &wat_log())).await.expect("p2");

    let list = mgr.list().await;
    assert_eq!(list.len(), 2);
    let names: Vec<_> = list.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"p1"));
    assert!(names.contains(&"p2"));
}

#[tokio::test]
async fn wasm_plugin_new_direct_rejects_malformed_bytes() {
    let res = WasmPlugin::new(
        Uuid::new_v4(),
        "bad".to_string(),
        "0".to_string(),
        String::new(),
        String::new(),
        true,
        b"\x00asm-but-garbage",
    );
    assert!(res.is_err());
}

#[tokio::test]
async fn plugin_manager_default_equals_new() {
    let mgr: PluginManager = Default::default();
    assert!(mgr.list().await.is_empty());
}

#[tokio::test]
async fn set_enabled_on_missing_id_returns_false() {
    let mgr = PluginManager::new();
    assert!(!mgr.set_enabled(Uuid::new_v4(), true).await);
}

// ── Memory limiter (#78) ─────────────────────────────────────────────────────
//
// `MAX_MEMORY_BYTES` is 64 MiB = 1024 WASM pages. A hostile plugin declaring
// `(memory N)` for large N would otherwise allocate `N * 64 KiB` at
// instantiation and OOM the host (fuel meters instructions only). The
// `ResourceLimiter` wired onto every `Store` caps `memory_growing` at
// `MAX_MEMORY_BYTES`. Instantiation that would exceed the cap fails inside
// `run_request`, which then swallows the error and returns the safe-default
// `Allow` — so a Block-returning plugin with oversized memory ends up Allowing.

fn wat_memory_pages_block(pages: u32) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(module
             (memory (export "memory") {pages})
             (func (export "on_request") (result i32) i32.const 1)
           )"#,
    ))
    .expect("valid WAT")
}

#[tokio::test]
async fn memory_within_cap_block_plugin_still_blocks() {
    let mgr = PluginManager::new();
    let id = Uuid::new_v4();
    // 1024 pages × 64 KiB = exactly 64 MiB; limiter permits `desired <= cap`.
    mgr.load(params(id, "within-cap", &wat_memory_pages_block(1024)))
        .await
        .expect("load");

    let action = mgr.run_request("GET", "/", "1.2.3.4").await;
    assert_eq!(action, PluginAction::Block, "plugin at the cap must still run");
}

#[tokio::test]
async fn memory_over_cap_blocks_instantiation_and_returns_allow() {
    let mgr = PluginManager::new();
    let id = Uuid::new_v4();
    // 2048 pages × 64 KiB = 128 MiB, double the cap. WasmPlugin::new only
    // compiles the module, so `load` succeeds. The limiter rejects the
    // memory growth at instantiation inside `run_request`, the error
    // propagates, `on_request` swallows it and returns Allow — so the
    // module's i32.const 1 (Block) is never observed.
    mgr.load(params(id, "over-cap", &wat_memory_pages_block(2048)))
        .await
        .expect("load (compile only)");

    let action = mgr.run_request("GET", "/", "1.2.3.4").await;
    assert_eq!(
        action,
        PluginAction::Allow,
        "memory cap must reject instantiation; safe-default to Allow"
    );
}
