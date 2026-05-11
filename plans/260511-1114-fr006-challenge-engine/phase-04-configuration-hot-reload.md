---
phase: 4
title: "Configuration Hot-Reload"
status: complete
priority: P2
effort: "0.5d"
dependencies: [1, 2, 3]
---

# Phase 4: Configuration Hot-Reload

## Overview

Add YAML configuration for challenge settings with hot-reload support. Follow existing patterns from `risk/config.rs` and other hot-reload modules.

## Requirements

**Functional:**
- Load challenge config from `configs/challenge.yaml`
- Support difficulty mapping configuration
- Support branding customization
- Hot-reload on file change

**Non-functional:**
- Use ArcSwap for atomic config updates
- No service restart required

## Architecture

```yaml
# configs/challenge.yaml
challenge:
  enabled: true
  type: js_challenge
  
  difficulty:
    default: 16
    tiers:
      - min_risk: 30
        max_risk: 40
        difficulty: 14
      - min_risk: 40
        max_risk: 55
        difficulty: 16
      - min_risk: 55
        max_risk: 70
        difficulty: 18
  
  token:
    ttl_secs: 300
    cookie_name: __waf_cc
    cookie_max_age: 300
    same_site: Strict
    http_only: false  # Must be readable by JS for redirect
  
  branding:
    title: "Security Check"
    message: "Please wait while we verify your browser..."
  
  nonce_store:
    capacity: 100000
    # Redis backend disabled (in-memory only per design decision)
```

## Related Code Files

**Create:**
- `configs/challenge.yaml`
- `crates/waf-engine/src/challenge/config.rs`

**Modify:**
- `crates/waf-engine/src/challenge/mod.rs` — add config module
- `crates/waf-engine/src/risk/config.rs` — extend ChallengeConfig if needed

## Implementation Steps

### Step 1: Create config structs

```rust
// crates/waf-engine/src/challenge/config.rs
use serde::{Deserialize, Serialize};
use crate::challenge::pow::DifficultyMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChallengeYamlConfig {
    pub challenge: ChallengeSettings,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChallengeSettings {
    #[serde(default = "default_true")]
    pub enabled: bool,
    
    #[serde(default = "default_challenge_type")]
    pub r#type: String,
    
    pub difficulty: DifficultySettings,
    pub token: TokenSettings,
    pub branding: BrandingSettings,
    pub nonce_store: NonceStoreSettings,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DifficultySettings {
    #[serde(default = "default_difficulty")]
    pub default: u8,
    pub tiers: Vec<DifficultyTierConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DifficultyTierConfig {
    pub min_risk: u8,
    pub max_risk: u8,
    pub difficulty: u8,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenSettings {
    #[serde(default = "default_ttl")]
    pub ttl_secs: u32,
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,
    #[serde(default = "default_cookie_max_age")]
    pub cookie_max_age: u32,
    #[serde(default = "default_same_site")]
    pub same_site: String,
    #[serde(default)]
    pub http_only: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BrandingSettings {
    #[serde(default = "default_title")]
    pub title: String,
    #[serde(default = "default_message")]
    pub message: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NonceStoreSettings {
    #[serde(default = "default_capacity")]
    pub capacity: usize,
}

// Default functions
fn default_true() -> bool { true }
fn default_challenge_type() -> String { "js_challenge".into() }
fn default_difficulty() -> u8 { 16 }
fn default_ttl() -> u32 { 300 }
fn default_cookie_name() -> String { "__waf_cc".into() }
fn default_cookie_max_age() -> u32 { 300 }
fn default_same_site() -> String { "Strict".into() }
fn default_title() -> String { "Security Check".into() }
fn default_message() -> String { "Please wait while we verify your browser...".into() }
fn default_capacity() -> usize { 100_000 }
```

### Step 2: Add config loading and hot-reload

```rust
// crates/waf-engine/src/challenge/config.rs (continued)
use arc_swap::ArcSwap;
use std::sync::Arc;
use notify::{Watcher, RecursiveMode, Event};
use std::path::Path;

pub struct ChallengeConfigLoader {
    config: Arc<ArcSwap<ChallengeSettings>>,
}

impl ChallengeConfigLoader {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let yaml_config: ChallengeYamlConfig = serde_yaml::from_str(&content)?;
        
        Ok(Self {
            config: Arc::new(ArcSwap::from_pointee(yaml_config.challenge)),
        })
    }
    
    pub fn config(&self) -> arc_swap::Guard<Arc<ChallengeSettings>> {
        self.config.load()
    }
    
    pub fn start_watcher(&self, path: &Path) -> anyhow::Result<()> {
        let config = Arc::clone(&self.config);
        let path = path.to_path_buf();
        
        std::thread::spawn(move || {
            let (tx, rx) = std::sync::mpsc::channel();
            let mut watcher = notify::recommended_watcher(move |res: Result<Event, _>| {
                if let Ok(event) = res {
                    if event.kind.is_modify() {
                        let _ = tx.send(());
                    }
                }
            }).expect("Failed to create watcher");
            
            watcher.watch(&path, RecursiveMode::NonRecursive)
                .expect("Failed to watch config file");
            
            for () in rx {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(yaml_config) = serde_yaml::from_str::<ChallengeYamlConfig>(&content) {
                        config.store(Arc::new(yaml_config.challenge));
                        tracing::info!("Challenge config reloaded");
                    }
                }
            }
        });
        
        Ok(())
    }
}
```

### Step 3: Convert config to runtime types

```rust
impl From<&DifficultySettings> for DifficultyMap {
    fn from(settings: &DifficultySettings) -> Self {
        DifficultyMap {
            default: settings.default,
            tiers: settings.tiers.iter().map(|t| DifficultyTier {
                min_risk: t.min_risk,
                max_risk: t.max_risk,
                difficulty: t.difficulty,
            }).collect(),
        }
    }
}
```

### Step 4: Create default config file

```yaml
# configs/challenge.yaml
challenge:
  enabled: true
  type: js_challenge
  
  difficulty:
    default: 16
    tiers:
      - min_risk: 30
        max_risk: 40
        difficulty: 14
      - min_risk: 40
        max_risk: 55
        difficulty: 16
      - min_risk: 55
        max_risk: 70
        difficulty: 18
  
  token:
    ttl_secs: 300
    cookie_name: __waf_cc
    cookie_max_age: 300
    same_site: Strict
    http_only: false
  
  branding:
    title: "Security Check"
    message: "Please wait while we verify your browser..."
  
  nonce_store:
    capacity: 100000
```

### Step 5: Export from mod.rs

```rust
// crates/waf-engine/src/challenge/mod.rs
mod config;
pub use config::{ChallengeConfigLoader, ChallengeSettings, DifficultySettings};
```

## Success Criteria

- [x] `configs/challenge.yaml` exists with default values
- [x] `ChallengeConfigLoader::load()` parses YAML correctly
- [x] Hot-reload updates config without restart
- [x] `DifficultyMap` constructs from config
- [x] `cargo check --package waf-engine` passes

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Invalid YAML on reload | Validate before swap; keep old config on error |
| File watcher resource leak | Single watcher thread, bounded channel |
| Config race during update | ArcSwap provides atomic swap |
