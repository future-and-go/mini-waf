use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteropMode {
    Enforce,
    LogOnly,
}

impl InteropMode {
    pub const fn as_contract_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::LogOnly => "log_only",
        }
    }

    pub fn from_contract_str(s: &str) -> Option<Self> {
        match s {
            "enforce" => Some(Self::Enforce),
            "log_only" => Some(Self::LogOnly),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModeState {
    pub default_mode: InteropMode,
    pub feature_overrides: HashMap<String, InteropMode>,
    pub policy_overrides: HashMap<String, InteropMode>,
}

impl Default for ModeState {
    fn default() -> Self {
        Self {
            default_mode: InteropMode::Enforce,
            feature_overrides: HashMap::new(),
            policy_overrides: HashMap::new(),
        }
    }
}

#[derive(Clone)]
pub struct ModeRegistry {
    inner: Arc<ArcSwap<ModeState>>,
}

impl ModeRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(ModeState::default())),
        }
    }

    /// Hot-path resolution: policy override > feature override > default.
    /// Lock-free via `ArcSwap::load`.
    pub fn resolve(&self, feature: &str, policy: Option<&str>) -> InteropMode {
        let guard = self.inner.load();

        if let Some(policy_name) = policy {
            let key = format!("{feature}.{policy_name}");
            if let Some(&mode) = guard.policy_overrides.get(&key) {
                return mode;
            }
        }

        if let Some(&mode) = guard.feature_overrides.get(feature) {
            return mode;
        }

        guard.default_mode
    }

    /// Set default mode and clear all overrides.
    pub fn set_all(&self, mode: InteropMode) {
        self.inner.store(Arc::new(ModeState {
            default_mode: mode,
            feature_overrides: HashMap::new(),
            policy_overrides: HashMap::new(),
        }));
    }

    pub fn set_feature(&self, feature: &str, mode: InteropMode) {
        let feature = feature.to_owned();
        self.inner.rcu(|current| {
            let mut next = (**current).clone();
            next.feature_overrides.insert(feature.clone(), mode);
            next
        });
    }

    pub fn set_features(&self, features: &[&str], mode: InteropMode) {
        let owned: Vec<String> = features.iter().map(|s| (*s).to_owned()).collect();
        self.inner.rcu(|current| {
            let mut next = (**current).clone();
            for f in &owned {
                next.feature_overrides.insert(f.clone(), mode);
            }
            next
        });
    }

    pub fn set_policy(&self, feature: &str, policy: &str, mode: InteropMode) {
        let key = format!("{feature}.{policy}");
        self.inner.rcu(|current| {
            let mut next = (**current).clone();
            next.policy_overrides.insert(key.clone(), mode);
            next
        });
    }

    pub fn set_policies(&self, feature: &str, policies: &[&str], mode: InteropMode) {
        let keys: Vec<String> = policies.iter().map(|p| format!("{feature}.{p}")).collect();
        self.inner.rcu(|current| {
            let mut next = (**current).clone();
            for key in &keys {
                next.policy_overrides.insert(key.clone(), mode);
            }
            next
        });
    }

    pub fn snapshot(&self) -> ModeState {
        let guard = self.inner.load();
        ModeState::clone(&guard)
    }

    pub fn reset(&self) {
        self.inner.store(Arc::new(ModeState::default()));
    }
}

impl Default for ModeRegistry {
    fn default() -> Self {
        Self::new()
    }
}
