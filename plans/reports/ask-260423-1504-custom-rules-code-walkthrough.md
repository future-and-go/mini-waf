# Custom Rules — Code Walkthrough

## Big Picture
The WAF has **two parallel rule systems** that work together:
1. **YAML file rules** (like `rules/custom/example.yaml`) → loaded by a file-based engine
2. **Database-stored custom rules** (from PostgreSQL, created via the Admin UI) → handled by a separate "Custom Rules Engine"

## Real-World Analogy
Factory assembly line:
1. **Loader** grabs rule papers from folders
2. **Parser** reads each paper and fills a form
3. **Engine** holds all forms in a binder
4. **Evaluator** checks every incoming request against every form

---

## Step 1: Where Rules Get Loaded (the "source")

**File:** `crates/waf-engine/src/rules/sources.rs:13-37`

```rust
// This enum means: a rule source can be ONE of these 4 kinds
pub enum RuleSource {
    // A single YAML file on disk
    LocalFile  { name, path, format },
    // A whole folder (matches files like "*.yaml")
    LocalDir   { name, path, glob },
    // A URL fetched from the internet
    RemoteUrl  { name, url, format, update_interval_secs },
    // Rules compiled into the program itself
    Builtin    { name },
}
```

**Translation:** `rules/custom/` folder is a `LocalDir` source. The loader walks it and reads every `.yaml` file.

---

## Step 2: The Fields a Rule Can Inspect

**File:** `crates/waf-engine/src/rules/engine.rs:22-46`

```rust
// These are the "parts of the request" a rule can look at
pub enum ConditionField {
    Ip,            // client IP address
    Path,          // the URL path — /login, /api/*, etc.
    Query,         // the ?foo=bar part
    Method,        // GET, POST, etc.
    Body,          // the request body
    Cookie,        // cookies
    UserAgent,     // browser info
    Header(String),// any specific header
    // GeoIP fields
    GeoCountry, GeoIso, GeoCity, ...
}
```

**Translation:** For tiered routing (`/login`, `/game/*`, etc.), the relevant field is `Path`.

---

## Step 3: The Comparison Operators

**File:** `crates/waf-engine/src/rules/engine.rs:52-67`

```rust
pub enum Operator {
    Eq, Ne,                    // equals / not equals
    Contains, NotContains,     // substring check
    StartsWith, EndsWith,      // prefix/suffix match
    Regex,                     // pattern match (for /game/*)
    InList, NotInList,         // whitelist/blacklist
    CidrMatch,                 // IP range
    Gt, Lt, Gte, Lte,          // numbers
}
```

---

## Step 4: The Actual Matching Logic (THE HEART)

**File:** `crates/waf-engine/src/rules/engine.rs:287-311`

```rust
// For one condition, grab the field's value, then apply the operator
fn eval_one(&self, ctx: &RequestCtx, cond: &Condition) -> bool {
    // Pull the value out of the request (e.g., the path "/login")
    let fval = self.field_value(ctx, &cond.field);
    let fstr = fval.as_deref().unwrap_or("");

    // Match operator + value together
    match (&cond.operator, &cond.value) {
        (Operator::StartsWith, ConditionValue::Str(v)) => fstr.starts_with(v.as_str()),
        (Operator::Regex, ConditionValue::Str(v)) =>
            Regex::new(v).ok().is_some_and(|r| r.is_match(fstr)),
        // ...more operators...
    }
}
```

**Plain English flow:**
1. Look at the request (e.g. someone visiting `/login`)
2. Extract the path → `"/login"`
3. If rule says `operator: regex, value: "^/(login|otp)$"`, compile the regex and test
4. Return `true` if matched → rule fires → action taken

---

## Step 5: AND/OR Combination

**File:** `crates/waf-engine/src/rules/engine.rs:277-285`

```rust
fn eval_conditions(&self, ctx, conditions, op) -> bool {
    match op {
        ConditionOp::And => conditions.iter().all(|c| self.eval_one(ctx, c)),
        ConditionOp::Or  => conditions.iter().any(|c| self.eval_one(ctx, c)),
    }
}
```

**Example:** "path starts with `/deposit` AND method is `POST`" = AND combination.

---

## Step 6: The Actions

**File:** `crates/waf-engine/src/rules/engine.rs:110-117`

```rust
pub enum RuleAction {
    Block,      // reject the request
    Allow,      // explicit whitelist (skip other checks)
    Log,        // just record it
    Challenge,  // show a CAPTCHA-like challenge
}
```

---

## Brutal Honest Truth

Two rule systems in this codebase, different vocabularies:

| YAML file rules (`rules/custom/*.yaml`) | DB custom rules engine (`engine.rs`) |
|---|---|
| `field: "path"` | `ConditionField::Path` |
| `operator: "regex"` | `Operator::Regex` |
| `action: "block"` | `RuleAction::Block` |
| Single condition per rule | Multiple conditions w/ AND/OR |
| No GeoIP, no Rhai scripts | Has GeoIP + Rhai scripting |

DB engine is more powerful (combos, GeoIP, custom scripts). YAML format simpler. They converge in the registry, but DB-backed one is what the Admin UI uses for tiered routing.

## What This Means For Tiered Routing
For `/login`, `/deposit`, `/game/*`, `/api/*`, etc., either system works:
- **Simple → YAML** in `rules/custom/` (one rule per path, one condition)
- **Advanced → DB custom rules** via Admin UI (combine path + method + GeoIP + AND/OR)

## Key Code Hotspot
`crates/waf-engine/src/rules/engine.rs:298` — the `Regex` match arm. That single line decides whether `^/(login|otp)$` fires against a real request path. The core of the engine.

## Unresolved Questions
- Does the YAML loader support **bypass/exclusion rules** (skip SQLi on `/static/*`)? Not yet verified.
- Are YAML rules and DB rules evaluated in one pass, or separately? Ordering semantics unclear.
