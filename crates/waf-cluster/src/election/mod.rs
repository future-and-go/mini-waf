use anyhow::Result;
use tokio::sync::RwLock;
use tracing::info;
use waf_common::config::NodeRole;

use rand::Rng;

use crate::protocol::{ElectionResult, ElectionVote};

/// Raft-lite election state machine.
///
/// Handles term tracking, vote granting, and role transitions.
/// Full state machine (random timeout, candidate promotion, split-vote
/// backoff) is implemented in P3.
pub struct ElectionManager {
    node_id: String,
    term: RwLock<u64>,
    voted_for: RwLock<Option<String>>,
    timeout_min_ms: u64,
    timeout_max_ms: u64,
}

impl ElectionManager {
    pub fn new(node_id: String, timeout_min_ms: u64, timeout_max_ms: u64) -> Self {
        Self {
            node_id,
            term: RwLock::new(0),
            voted_for: RwLock::new(None),
            timeout_min_ms,
            timeout_max_ms,
        }
    }

    pub async fn current_term(&self) -> u64 {
        *self.term.read().await
    }

    /// Returns a random election timeout within the configured range (ms).
    pub fn election_timeout_ms(&self) -> u64 {
        let mut rng = rand::thread_rng();
        rng.gen_range(self.timeout_min_ms..=self.timeout_max_ms)
    }

    /// Decide whether to grant a vote.
    /// Grants if `vote.term > current_term` or if this node hasn't voted yet.
    pub async fn process_vote(&self, vote: &ElectionVote) -> Result<bool> {
        let current_term = *self.term.read().await;
        if vote.term < current_term {
            return Ok(false);
        }
        if vote.term > current_term {
            *self.term.write().await = vote.term;
            *self.voted_for.write().await = None;
        }
        let mut voted_for = self.voted_for.write().await;
        let can_vote =
            voted_for.is_none() || voted_for.as_deref() == Some(&vote.candidate_id);
        if can_vote {
            *voted_for = Some(vote.candidate_id.clone());
            info!(
                node_id = %self.node_id,
                candidate = %vote.candidate_id,
                term = vote.term,
                "Granted election vote"
            );
            return Ok(true);
        }
        Ok(false)
    }

    /// Process an election result and return the new role for this node.
    pub async fn process_result(&self, result: &ElectionResult) -> Result<NodeRole> {
        let mut term = self.term.write().await;
        if result.term > *term {
            *term = result.term;
        }
        if result.elected_id == self.node_id {
            info!(
                node_id = %self.node_id,
                term = result.term,
                "Elected as cluster main"
            );
            Ok(NodeRole::Main)
        } else {
            Ok(NodeRole::Worker)
        }
    }
}
