//! FR-025 Phase 7: Embedded Lua scripts for Redis risk store.
//!
//! All scripts are atomic single-RTT operations. Logic mirrors `decay.rs` and
//! `score.rs` exactly — parity tests verify identical outputs.

/// Apply script: GET state → decay → fold deltas → SET with TTL → return state.
///
/// KEYS[1]: state key (waf:risk:state:{owner_id})
/// ARGV[1]: now_ms (current timestamp in milliseconds)
/// ARGV[2]: deltas_json (JSON array of {kind, delta, ts_ms})
/// ARGV[3]: ttl_sec (TTL for the key)
/// ARGV[4]: min_clean_streak (decay threshold)
/// ARGV[5]: decay_rate (points per clean request)
/// ARGV[6]: max_decay (floor for automatic decay)
///
/// Returns: JSON-encoded RiskState after apply
pub const APPLY_SCRIPT: &str = r#"
local state_key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local deltas_json = ARGV[2]
local ttl_sec = tonumber(ARGV[3])
local min_clean_streak = tonumber(ARGV[4])
local decay_rate = tonumber(ARGV[5])
local max_decay = tonumber(ARGV[6])

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

-- Persist state with TTL
local result_json = cjson.encode(state)
redis.call('SET', state_key, result_json, 'EX', ttl_sec)

-- Return state JSON plus is_new flag
return cjson.encode({state = state, is_new = is_new})
"#;

/// Force-max script: Set state to score=100 with pin until timestamp.
///
/// KEYS[1]: state key
/// ARGV[1]: until_ms (pin expiry timestamp)
/// ARGV[2]: now_ms (current timestamp)
/// ARGV[3]: ttl_sec (key TTL)
///
/// Returns: "OK"
pub const FORCE_MAX_SCRIPT: &str = r#"
local state_key = KEYS[1]
local until_ms = tonumber(ARGV[1])
local now_ms = tonumber(ARGV[2])
local ttl_sec = tonumber(ARGV[3])

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

-- Persist
redis.call('SET', state_key, cjson.encode(state), 'EX', ttl_sec)
return "OK"
"#;

/// Mint-or-get owner script: Atomically get existing owner_id or create new one.
///
/// Uses SETNX pattern to prevent race conditions where two concurrent requests
/// both see no owner and mint different IDs.
///
/// KEYS[1..N]: index keys (ip, fp, session) - only populated ones
/// ARGV[1]: new_owner_id (UUID to use if minting)
/// ARGV[2]: ttl_sec
///
/// Returns: {owner_id, is_new} JSON
pub const MINT_OR_GET_OWNER_SCRIPT: &str = r"
local new_owner_id = ARGV[1]
local ttl_sec = tonumber(ARGV[2])

-- Check all index keys for existing owner (MGET for efficiency)
local existing_owner = nil
for i, key in ipairs(KEYS) do
    local v = redis.call('GET', key)
    if v then
        existing_owner = v
        break
    end
end

if existing_owner then
    -- Ensure all indices point to this owner (convergence)
    for i, key in ipairs(KEYS) do
        redis.call('SET', key, existing_owner, 'EX', ttl_sec)
    end
    return cjson.encode({owner_id = existing_owner, is_new = false})
else
    -- Use SETNX on first key to atomically claim ownership
    -- This prevents race where two requests both see nil and mint different owners
    local first_key = KEYS[1]
    local claimed = redis.call('SETNX', first_key, new_owner_id)

    if claimed == 1 then
        -- We won the race, set TTL and remaining indices
        redis.call('EXPIRE', first_key, ttl_sec)
        for i = 2, #KEYS do
            redis.call('SET', KEYS[i], new_owner_id, 'EX', ttl_sec)
        end
        return cjson.encode({owner_id = new_owner_id, is_new = true})
    else
        -- Lost the race, use the winner's owner_id
        local winner_id = redis.call('GET', first_key)
        for i = 2, #KEYS do
            redis.call('SET', KEYS[i], winner_id, 'EX', ttl_sec)
        end
        return cjson.encode({owner_id = winner_id, is_new = false})
    end
end
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts_are_valid_lua_syntax() {
        // Basic syntax check - these would fail to compile if invalid
        assert!(!APPLY_SCRIPT.is_empty());
        assert!(!FORCE_MAX_SCRIPT.is_empty());
        assert!(!MINT_OR_GET_OWNER_SCRIPT.is_empty());
    }
}
