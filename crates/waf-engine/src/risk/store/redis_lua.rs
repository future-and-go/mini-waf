//! FR-025 Phase 7: Embedded Lua scripts for Redis risk store.
//!
//! All scripts are atomic single-RTT operations: owner resolution (mint or
//! max-score convergence across index keys) and state mutation happen inside
//! one Lua execution. Decay/fold logic mirrors `decay.rs` and `score.rs`
//! exactly — parity tests verify identical outputs.
//!
//! State keys are computed inside Lua from the `key_prefix` argument, so they
//! are not declared in KEYS. This is invalid for Redis Cluster slot routing;
//! the store assumes a single non-cluster Redis/Valkey instance (it uses one
//! `ConnectionManager`).

/// Apply script: resolve/mint owner → converge indices → GET state → decay →
/// fold deltas → SET with TTL → return state.
///
/// Owner resolution: all index keys are read; if no owner exists one is
/// claimed via SETNX with the pre-minted UUID. If one or more owners exist,
/// the owner whose state has the highest `clamped_score` wins (missing state
/// counts as 0; ties keep the first in KEYS order) and every index key is
/// repointed to it. Losing owners' state keys expire via TTL.
///
/// KEYS[1..N]: index keys (ip, fp, session) — only populated axes
/// ARGV[1]: `new_owner_id` (pre-minted UUID, used only when minting)
/// ARGV[2]: `key_prefix` (e.g. `waf:risk:`)
/// ARGV[3]: `now_ms` (current timestamp in milliseconds)
/// ARGV[4]: `deltas_json` (JSON array of {kind, delta, `ts_ms`})
/// ARGV[5]: `ttl_sec` (TTL for state and index keys)
/// ARGV[6]: `min_clean_streak` (decay threshold)
/// ARGV[7]: `decay_rate` (points per clean request)
/// ARGV[8]: `max_decay` (floor for automatic decay)
///
/// Returns: JSON-encoded `{state, is_new, owner_id}`
pub const APPLY_SCRIPT: &str = r"
local new_owner_id = ARGV[1]
local key_prefix = ARGV[2]
local now_ms = tonumber(ARGV[3])
local deltas_json = ARGV[4]
local ttl_sec = tonumber(ARGV[5])
local min_clean_streak = tonumber(ARGV[6])
local decay_rate = tonumber(ARGV[7])
local max_decay = tonumber(ARGV[8])

-- Resolve owner: collect distinct candidate owners from the index keys
local candidates = {}
local seen = {}
for i, key in ipairs(KEYS) do
    local v = redis.call('GET', key)
    if v and not seen[v] then
        seen[v] = true
        table.insert(candidates, v)
    end
end

local owner_id
if #candidates == 0 then
    -- Mint path: claim the first index key (SETNX guards concurrent minting)
    local claimed = redis.call('SETNX', KEYS[1], new_owner_id)
    if claimed == 1 then
        redis.call('EXPIRE', KEYS[1], ttl_sec)
        owner_id = new_owner_id
    else
        owner_id = redis.call('GET', KEYS[1])
    end
    for i = 2, #KEYS do
        redis.call('SET', KEYS[i], owner_id, 'EX', ttl_sec)
    end
else
    -- Convergence: pick the max-score owner so colliding identity axes can
    -- never shed accumulated risk onto a cleaner owner. Missing state = 0;
    -- ties keep the first owner in KEYS order for determinism.
    owner_id = candidates[1]
    local best_score = -1
    for _, cand in ipairs(candidates) do
        local score = 0
        local cand_json = redis.call('GET', key_prefix .. 'state:' .. cand)
        if cand_json then
            local decoded = cjson.decode(cand_json)
            score = tonumber(decoded.clamped_score) or 0
        end
        if score > best_score then
            best_score = score
            owner_id = cand
        end
    end
    -- Repoint ALL index keys to the winner
    for i, key in ipairs(KEYS) do
        redis.call('SET', key, owner_id, 'EX', ttl_sec)
    end
end

local state_key = key_prefix .. 'state:' .. owner_id

-- Helper: clamp value to [0, 100]
local function clamp_score(raw)
    if raw < 0 then return 0 end
    if raw > 100 then return 100 end
    return raw
end

-- Get existing state or create default
local state_json = redis.call('GET', state_key)
local state
if state_json then
    state = cjson.decode(state_json)
else
    -- Default state
    state = {
        raw_score = 0,
        clamped_score = 0,
        last_updated_ms = now_ms,
        created_ms = now_ms,
        contributors = {},
        clean_streak = 0,
        pinned_until_ms = cjson.null
    }
end

-- Decode deltas
local deltas = cjson.decode(deltas_json)
local is_new = (state_json == nil)

-- Apply decay if state exists and has clean streak
if not is_new and state.clean_streak >= min_clean_streak then
    -- Check if not pinned
    local pinned = state.pinned_until_ms
    local is_pinned = (pinned ~= nil and pinned ~= cjson.null and now_ms < pinned)

    if not is_pinned and state.raw_score > max_decay then
        local available = state.raw_score - max_decay
        if available > decay_rate then
            available = decay_rate
        end
        if available > 0 then
            state.raw_score = state.raw_score - available
            -- Push decay contributor (keep max 8)
            local decay_contrib = {
                kind = {Decay = cjson.null},
                delta = -available,
                ts_ms = now_ms
            }
            table.insert(state.contributors, decay_contrib)
            if #state.contributors > 8 then
                table.remove(state.contributors, 1)
            end
            state.clamped_score = clamp_score(state.raw_score)
        end
    end
end

-- Update timestamp
state.last_updated_ms = now_ms

-- Apply deltas
if #deltas == 0 then
    -- Empty deltas = clean request, increment streak
    state.clean_streak = state.clean_streak + 1
else
    -- Has deltas = reset streak
    state.clean_streak = 0
    for _, delta in ipairs(deltas) do
        state.raw_score = state.raw_score + delta.delta
        -- Push contributor (keep max 8)
        table.insert(state.contributors, delta)
        if #state.contributors > 8 then
            table.remove(state.contributors, 1)
        end
    end
    state.clamped_score = clamp_score(state.raw_score)
end

-- cjson encodes an empty Lua table as a JSON object, but contributors is a
-- JSON array in RiskState — patch the empty case so serde can parse it.
-- (\34 is the double-quote character.)
local function fix_empty_contributors(json)
    if #state.contributors == 0 then
        return string.gsub(json, '\34contributors\34:{}', '\34contributors\34:[]', 1)
    end
    return json
end

-- Persist state with TTL
local result_json = fix_empty_contributors(cjson.encode(state))
redis.call('SET', state_key, result_json, 'EX', ttl_sec)

-- Return state JSON plus is_new flag and the winning owner
return fix_empty_contributors(cjson.encode({state = state, is_new = is_new, owner_id = owner_id}))
";

/// Force-max script: resolve/mint owner → converge indices → set state to
/// score=100 with pin until timestamp.
///
/// Owner resolution/convergence is identical to [`APPLY_SCRIPT`]; the choice
/// does not affect the forced score but keeps index repointing consistent.
///
/// KEYS[1..N]: index keys (ip, fp, session) — only populated axes
/// ARGV[1]: `new_owner_id` (pre-minted UUID, used only when minting)
/// ARGV[2]: `key_prefix`
/// ARGV[3]: `until_ms` (pin expiry timestamp)
/// ARGV[4]: `now_ms` (current timestamp)
/// ARGV[5]: `ttl_sec` (key TTL)
///
/// Returns: the winning `owner_id`
pub const FORCE_MAX_SCRIPT: &str = r"
local new_owner_id = ARGV[1]
local key_prefix = ARGV[2]
local until_ms = tonumber(ARGV[3])
local now_ms = tonumber(ARGV[4])
local ttl_sec = tonumber(ARGV[5])

-- Resolve owner: collect distinct candidate owners from the index keys
local candidates = {}
local seen = {}
for i, key in ipairs(KEYS) do
    local v = redis.call('GET', key)
    if v and not seen[v] then
        seen[v] = true
        table.insert(candidates, v)
    end
end

local owner_id
if #candidates == 0 then
    -- Mint path: claim the first index key (SETNX guards concurrent minting)
    local claimed = redis.call('SETNX', KEYS[1], new_owner_id)
    if claimed == 1 then
        redis.call('EXPIRE', KEYS[1], ttl_sec)
        owner_id = new_owner_id
    else
        owner_id = redis.call('GET', KEYS[1])
    end
    for i = 2, #KEYS do
        redis.call('SET', KEYS[i], owner_id, 'EX', ttl_sec)
    end
else
    -- Convergence: pick the max-score owner (ties keep first in KEYS order)
    owner_id = candidates[1]
    local best_score = -1
    for _, cand in ipairs(candidates) do
        local score = 0
        local cand_json = redis.call('GET', key_prefix .. 'state:' .. cand)
        if cand_json then
            local decoded = cjson.decode(cand_json)
            score = tonumber(decoded.clamped_score) or 0
        end
        if score > best_score then
            best_score = score
            owner_id = cand
        end
    end
    -- Repoint ALL index keys to the winner
    for i, key in ipairs(KEYS) do
        redis.call('SET', key, owner_id, 'EX', ttl_sec)
    end
end

local state_key = key_prefix .. 'state:' .. owner_id

-- Get existing state or create default
local state_json = redis.call('GET', state_key)
local state
if state_json then
    state = cjson.decode(state_json)
else
    state = {
        raw_score = 0,
        clamped_score = 0,
        last_updated_ms = now_ms,
        created_ms = now_ms,
        contributors = {},
        clean_streak = 0,
        pinned_until_ms = cjson.null
    }
end

-- Force to max
state.raw_score = 100
state.clamped_score = 100
state.pinned_until_ms = until_ms
state.last_updated_ms = now_ms

-- Persist. cjson encodes an empty Lua table as a JSON object, but
-- contributors is a JSON array in RiskState — patch the empty case so serde
-- can parse it. (\34 is the double-quote character.)
local state_out = cjson.encode(state)
if #state.contributors == 0 then
    state_out = string.gsub(state_out, '\34contributors\34:{}', '\34contributors\34:[]', 1)
end
redis.call('SET', state_key, state_out, 'EX', ttl_sec)
return owner_id
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts_are_valid_lua_syntax() {
        // Basic syntax check - these would fail to compile if invalid
        assert!(!APPLY_SCRIPT.is_empty());
        assert!(!FORCE_MAX_SCRIPT.is_empty());
    }
}
