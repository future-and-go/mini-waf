//! SQL injection detection patterns and descriptions.
//!
//! This module contains the `RegexSet` patterns and aligned description slice
//! used by `SqlInjectionCheck`. Patterns are organized by category:
//! - SQLI-001..012: Classic injection patterns
//! - SQLI-013..019: Blind and error-based patterns

use std::sync::LazyLock;

use regex::RegexSet;

/// Pattern descriptions aligned by index with `SQLI_SET` patterns.
///
/// Each description corresponds to the pattern at the same index.
/// When adding patterns, add a matching description at the same position.
pub static SQLI_DESCS: &[&str] = &[
    // Classic patterns (001-012)
    "UNION SELECT injection",
    "comment-based injection (-- / #)",
    "stacked query injection (;DROP/DELETE/...)",
    "time-based blind injection (SLEEP/BENCHMARK/WAITFOR)",
    "xp_cmdshell execution",
    "INFORMATION_SCHEMA enumeration",
    "OR/AND always-true tautology",
    "LOAD_FILE() read",
    "INTO OUTFILE/DUMPFILE write",
    "hex-encoded string injection (0x...)",
    "quoted string escape (')",
    "MySQL/MSSQL system table enumeration",
    // Blind + error-based patterns (013-019)
    "numeric tautology (AND 1=1, OR 2>1)",
    "blind data-extraction function (SUBSTRING/ASCII/LENGTH)",
    "conditional blind IF(x,y,z)",
    "database fingerprint (@@version/@@datadir)",
    "error-based CAST injection",
    "error-based CONVERT injection (MySQL)",
    "error-based DOUBLE overflow (MySQL exp(~()))",
];

// Compile-time assertion: descriptions must match pattern count
const _: () = assert!(SQLI_DESCS.len() == 19);

/// Compiled SQL injection pattern set.
///
/// SAFETY: All patterns are compile-time string literals. If any pattern fails
/// to compile it is a code bug that must be caught in development, not at runtime.
pub static SQLI_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        // === Classic patterns (SQLI-001 to SQLI-012) ===
        // SQLI-001: UNION … SELECT
        r"(?i)\bunion\b[\s/\*]+select\b",
        // SQLI-002: Comment sequences followed by DML keywords
        r"(?i)(--|#|/\*[\s\S]*?\*/)[\s]*?(select|union|drop|insert|update|delete|exec|xp_)",
        // SQLI-003: Stacked queries: '; <keyword>
        r"(?i)'[\s]*;[\s]*(drop|delete|insert|update|exec|select|truncate)\b",
        // SQLI-004: Time-based blind (bounded \s{0,10} to prevent ReDoS)
        r"(?i)\b(sleep|benchmark|waitfor[\s]+delay|pg_sleep)\s{0,10}\(",
        // SQLI-005: xp_cmdshell
        r"(?i)\bxp_cmdshell\b",
        // SQLI-006: INFORMATION_SCHEMA / sys.tables / sysobjects
        r"(?i)\b(information_schema|sys\.(tables|columns|databases)|sysobjects|sysusers)\b",
        // SQLI-007: OR/AND tautologies (quoted strings)
        r"(?i)\b(or|and)\b[\s]+'[^']*'[\s]*=[\s]*'[^']*'",
        // SQLI-008: LOAD_FILE() (bounded \s{0,10})
        r"(?i)\bload_file\s{0,10}\(",
        // SQLI-009: INTO OUTFILE / DUMPFILE
        r"(?i)\binto[\s]+(outfile|dumpfile)\b",
        // SQLI-010: Hex literals 0x41…
        r"(?i)0x[0-9a-f]{4,}",
        // SQLI-011: Single-quote escapes common in error-based injection
        r"'[\s]*(or|and|union|select|drop|insert|update|delete)\b",
        // SQLI-012: MySQL/MSSQL catalog tables
        r"(?i)\b(mysql\.(user|db)|master\.\.(sysdatabases|sysobjects))\b",
        // === Blind + error-based patterns (SQLI-013 to SQLI-019) ===
        // SQLI-013: Numeric tautology (AND 1=1, OR 2>1)
        r"(?i)\b(and|or)\s+\d+\s*(=|<|>)\s*\d+\b",
        // SQLI-014: Blind data-extraction functions (bounded \s{0,10})
        r"(?i)\b(substring|substr|mid|ascii|length|hex|bin)\s{0,10}\(",
        // SQLI-015: Conditional blind IF(x,y,z) - bounded to prevent ReDoS
        r"(?i)\bif\s{0,10}\([^)]{1,128}?,[^)]{1,128}?,[^)]{1,128}?\)",
        // SQLI-016: Database fingerprint variables
        r"(?i)@@(version|datadir|hostname|tmpdir|servername)\b",
        // SQLI-017: Error-based CAST injection (bounded \s{0,10}, .{1,64}? for nested parens)
        r"(?i)\bcast\s{0,10}\(.{1,64}?\s+as\s+",
        // SQLI-018: Error-based CONVERT injection (MySQL, bounded \s{0,10})
        r"(?i)\bconvert\s{0,10}\([^)]{1,64}?using\s+",
        // SQLI-019: Error-based DOUBLE overflow (MySQL, bounded \s{0,10})
        r"(?i)\bexp\s{0,10}\(\s{0,10}~\s{0,10}\(",
    ])
    .expect("BUG: SQL injection regex patterns must compile - these are compile-time literals")
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_and_description_count_match() {
        assert_eq!(SQLI_SET.len(), SQLI_DESCS.len());
    }

    // === New pattern tests (SQLI-013 to SQLI-019) ===

    #[test]
    fn detects_numeric_tautology_sqli_013() {
        assert!(SQLI_SET.is_match("id=1 AND 1=1"));
        assert!(SQLI_SET.is_match("id=1 OR 2>1"));
        assert!(SQLI_SET.is_match("x=1 and 5=5"));
    }

    #[test]
    fn detects_blind_extraction_sqli_014() {
        assert!(SQLI_SET.is_match("SUBSTRING(password,1,1)"));
        assert!(SQLI_SET.is_match("ascii(substr(username,1,1))"));
        assert!(SQLI_SET.is_match("length(password)"));
        assert!(SQLI_SET.is_match("hex(password)"));
    }

    #[test]
    fn detects_conditional_blind_sqli_015() {
        assert!(SQLI_SET.is_match("IF(1=1,SLEEP(5),0)"));
        assert!(SQLI_SET.is_match("if(ascii(substr(x,1,1))>97,1,0)"));
    }

    #[test]
    fn detects_fingerprint_sqli_016() {
        assert!(SQLI_SET.is_match("SELECT @@version"));
        assert!(SQLI_SET.is_match("@@datadir"));
        assert!(SQLI_SET.is_match("@@hostname"));
    }

    #[test]
    fn detects_error_cast_sqli_017() {
        assert!(SQLI_SET.is_match("CAST(username AS int)"));
        assert!(SQLI_SET.is_match("cast((select password) as int)"));
    }

    #[test]
    fn detects_error_convert_sqli_018() {
        assert!(SQLI_SET.is_match("CONVERT(password using utf8)"));
        assert!(SQLI_SET.is_match("convert(x using latin1)"));
    }

    #[test]
    fn detects_double_overflow_sqli_019() {
        assert!(SQLI_SET.is_match("exp(~(select * from users))"));
        assert!(SQLI_SET.is_match("EXP( ~ ( select 1 ))"));
    }
}
