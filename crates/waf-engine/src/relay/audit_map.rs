//! Mapping from `relay::Signal` variants to stable `security_events.rule_id`
//! strings consumed by the admin panel.
//!
//! Every `rule_id` is a `&'static str` — no per-request allocation. Detail
//! payloads are pre-formatted compact JSON to keep the hot path single-pass
//! (issue #60 I1: previous API built a `serde_json::Value` twice per signal
//! when callers needed both the tuple and the stringified detail).

use super::signal::Signal;

/// Stable rule name shared by all XFF-flavored relay signals.
pub const RULE_NAME_XFF_VALIDATOR: &str = "xff_validator";
/// Stable rule name for proxy-chain depth signals.
pub const RULE_NAME_PROXY_CHAIN: &str = "proxy_chain";
/// Stable rule name for ASN classifier signals.
pub const RULE_NAME_ASN_CLASSIFIER: &str = "asn_classifier";
/// Stable rule name for Tor-exit signals.
pub const RULE_NAME_TOR_EXIT: &str = "tor_exit";

/// Map a relay signal to its `(rule_id, rule_name, detail-json)` triple.
///
/// Exhaustive over `Signal` so adding a new variant trips a compile error
/// here rather than silently emitting an `UNKNOWN` `rule_id`. The detail
/// payload is built only once per call — callers receive the ready-to-use
/// `Option<String>` directly (avoids the previous double-allocation pattern
/// where `signal_to_audit` returned a `Value` and `detail_json_string`
/// re-built the same `Value` to stringify it).
#[must_use]
pub fn signal_to_audit(sig: &Signal) -> (&'static str, &'static str, Option<String>) {
    match sig {
        Signal::XffSpoofPrivate => ("BOT-XFF-SPOOF-PRIVATE-001", RULE_NAME_XFF_VALIDATOR, None),
        Signal::XffMalformed => ("BOT-XFF-MALFORMED-001", RULE_NAME_XFF_VALIDATOR, None),
        Signal::XffTooLong => ("BOT-XFF-TOOLONG-001", RULE_NAME_XFF_VALIDATOR, None),
        Signal::ExcessiveHopDepth(depth) => (
            "BOT-RELAY-HOPDEPTH-001",
            RULE_NAME_PROXY_CHAIN,
            Some(format!(r#"{{"depth":{depth}}}"#)),
        ),
        Signal::AsnDatacenter { asn, org } => (
            "BOT-RELAY-ASN-DC-001",
            RULE_NAME_ASN_CLASSIFIER,
            Some(asn_dc_detail(*asn, org)),
        ),
        Signal::AsnResidential => ("BOT-RELAY-ASN-RESI-001", RULE_NAME_ASN_CLASSIFIER, None),
        Signal::AsnUnknown => ("BOT-RELAY-ASN-UNKNOWN-001", RULE_NAME_ASN_CLASSIFIER, None),
        Signal::TorExit => ("BOT-RELAY-TOR-001", RULE_NAME_TOR_EXIT, None),
    }
}

/// Build the datacenter detail JSON with escape-safe `org` field. Uses
/// `serde_json` purely for the org string escape; the wrapper structure is
/// templated to keep allocations to a single `String`.
///
/// `serde_json::to_string` over a `&str` is effectively infallible (the only
/// failure mode is allocator OOM, in which case the surrounding `format!`
/// would also fail). We log a warning rather than swallow silently because
/// observing this branch should always be a bug worth investigating.
fn asn_dc_detail(asn: u32, org: &str) -> String {
    let escaped_org = serde_json::to_string(org).unwrap_or_else(|err| {
        tracing::warn!(
            error = %err,
            org_len = org.len(),
            "relay::audit_map: serde_json::to_string on org failed; emitting empty string",
        );
        "\"\"".to_string()
    });
    format!(r#"{{"asn":{asn},"org":{escaped_org}}}"#)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn xff_variants_carry_xff_validator_name() {
        let cases = [Signal::XffSpoofPrivate, Signal::XffMalformed, Signal::XffTooLong];
        for sig in &cases {
            let (rule_id, name, detail) = signal_to_audit(sig);
            assert!(rule_id.starts_with("BOT-XFF-"), "got rule_id {rule_id}");
            assert_eq!(name, RULE_NAME_XFF_VALIDATOR);
            assert!(detail.is_none());
        }
    }

    #[test]
    fn excessive_hop_depth_includes_depth_in_detail() {
        let (rule_id, name, detail) = signal_to_audit(&Signal::ExcessiveHopDepth(7));
        assert_eq!(rule_id, "BOT-RELAY-HOPDEPTH-001");
        assert_eq!(name, RULE_NAME_PROXY_CHAIN);
        assert_eq!(detail.as_deref(), Some(r#"{"depth":7}"#));
    }

    #[test]
    fn datacenter_includes_asn_and_org() {
        let sig = Signal::AsnDatacenter {
            asn: 64512,
            org: "AcmeCloud".into(),
        };
        let (rule_id, name, detail) = signal_to_audit(&sig);
        assert_eq!(rule_id, "BOT-RELAY-ASN-DC-001");
        assert_eq!(name, RULE_NAME_ASN_CLASSIFIER);
        let detail = detail.expect("detail");
        assert!(detail.contains("\"asn\":64512"), "got {detail}");
        assert!(detail.contains("\"org\":\"AcmeCloud\""), "got {detail}");
    }

    #[test]
    fn datacenter_escapes_org_with_quotes() {
        // Org with embedded quotes must produce valid JSON, not corrupted output.
        let sig = Signal::AsnDatacenter {
            asn: 1,
            org: r#"Hack"er"#.into(),
        };
        let (_, _, detail) = signal_to_audit(&sig);
        let detail = detail.expect("detail");
        // Parse back to verify it's valid JSON.
        let parsed: serde_json::Value = serde_json::from_str(&detail).expect("valid json");
        assert_eq!(parsed["asn"], 1);
        assert_eq!(parsed["org"], r#"Hack"er"#);
    }

    #[test]
    fn asn_residential_unknown_have_distinct_rule_ids() {
        let (r1, _, _) = signal_to_audit(&Signal::AsnResidential);
        let (r2, _, _) = signal_to_audit(&Signal::AsnUnknown);
        assert_eq!(r1, "BOT-RELAY-ASN-RESI-001");
        assert_eq!(r2, "BOT-RELAY-ASN-UNKNOWN-001");
        assert_ne!(r1, r2);
    }

    #[test]
    fn tor_exit_maps_correctly() {
        let (rule_id, name, detail) = signal_to_audit(&Signal::TorExit);
        assert_eq!(rule_id, "BOT-RELAY-TOR-001");
        assert_eq!(name, RULE_NAME_TOR_EXIT);
        assert!(detail.is_none());
    }

    #[test]
    fn variants_without_data_emit_no_detail() {
        for sig in [
            Signal::XffSpoofPrivate,
            Signal::XffMalformed,
            Signal::XffTooLong,
            Signal::AsnResidential,
            Signal::AsnUnknown,
            Signal::TorExit,
        ] {
            let (_, _, detail) = signal_to_audit(&sig);
            assert!(detail.is_none(), "{sig:?} should have no detail payload");
        }
    }

    #[test]
    fn all_rule_ids_are_unique_static_strings() {
        let all = [
            Signal::XffSpoofPrivate,
            Signal::XffMalformed,
            Signal::XffTooLong,
            Signal::ExcessiveHopDepth(0),
            Signal::AsnDatacenter {
                asn: 1,
                org: "x".into(),
            },
            Signal::AsnResidential,
            Signal::AsnUnknown,
            Signal::TorExit,
        ];
        let mut ids: Vec<&'static str> = all.iter().map(|s| signal_to_audit(s).0).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), count, "every variant must map to a distinct rule_id");
    }
}
