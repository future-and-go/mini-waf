//! Built-in rules compiled into the binary.

pub mod bot;
pub mod owasp;
pub mod scanner;

use super::registry::Rule;

/// Load all built-in rules into a combined list.
pub fn all_builtin_rules(enable_owasp: bool, enable_bot: bool, enable_scanner: bool) -> Vec<Rule> {
    let mut rules = Vec::new();
    if enable_owasp {
        rules.extend(owasp::rules());
    }
    if enable_bot {
        rules.extend(bot::rules());
    }
    if enable_scanner {
        rules.extend(scanner::rules());
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_disabled_yields_empty() {
        assert!(all_builtin_rules(false, false, false).is_empty());
    }

    #[test]
    fn each_set_loads_independently() {
        let owasp_only = all_builtin_rules(true, false, false);
        let bot_only = all_builtin_rules(false, true, false);
        let scanner_only = all_builtin_rules(false, false, true);

        assert!(!owasp_only.is_empty(), "owasp rule set must not be empty");
        assert!(!bot_only.is_empty(), "bot rule set must not be empty");
        assert!(!scanner_only.is_empty(), "scanner rule set must not be empty");

        for r in &owasp_only {
            assert_eq!(r.source, "builtin-owasp");
        }
        for r in &bot_only {
            assert_eq!(r.source, "builtin-bot");
        }
        for r in &scanner_only {
            assert_eq!(r.source, "builtin-scanner");
        }
    }

    #[test]
    fn all_enabled_combines_all_sets() {
        let owasp = owasp::rules().len();
        let bot = bot::rules().len();
        let scanner = scanner::rules().len();
        let combined = all_builtin_rules(true, true, true);
        assert_eq!(combined.len(), owasp + bot + scanner);

        // Every rule must have a non-empty id and a recognised source tag.
        for r in &combined {
            assert!(!r.id.is_empty());
            assert!(r.source.starts_with("builtin-"));
        }
    }
}
