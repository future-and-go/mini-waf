//! FR-007 phase-03 — ASN classifier.
//!
//! Combines an `AsnDb` (mmdb / TSV) lookup with the `DatacenterSet` to emit
//! one of `AsnDatacenter`, `AsnResidential`, or `AsnUnknown` per request.
//! Operator allow-override wins over every other source; operator deny +
//! built-in DC ASN/CIDR sets convert any record to `AsnDatacenter`.
//!
//! `db` and `dc` sit behind `ArcSwap` so the phase-04 refresh task can swap
//! them atomically without touching the registry itself.

use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::relay::intel::{AsnDb, DatacenterSet};
use crate::relay::signal::{RelayCtx, Signal, SignalProvider};

/// Hot-swappable trait-object holder. We box the trait object so the inner
/// type is `Sized` (Box is a fat pointer); `ArcSwap` requires a `Sized`
/// payload via the `RefCnt` impl on `Arc<T>`.
pub type SwapAsnDb = ArcSwap<Box<dyn AsnDb>>;
pub type SwapDatacenterSet = ArcSwap<DatacenterSet>;

pub struct AsnClassifier {
    db: Arc<SwapAsnDb>,
    dc: Arc<SwapDatacenterSet>,
}

impl AsnClassifier {
    #[must_use]
    pub fn new(db: Box<dyn AsnDb>, dc: Arc<DatacenterSet>) -> Self {
        Self {
            db: Arc::new(ArcSwap::from_pointee(db)),
            dc: Arc::new(ArcSwap::from(dc)),
        }
    }

    /// Atomic refresh hook for phase-04 intel refresh task.
    pub fn swap_db(&self, db: Box<dyn AsnDb>) {
        self.db.store(Arc::new(db));
    }

    /// Atomic refresh hook for phase-04 intel refresh task.
    pub fn swap_dc(&self, dc: Arc<DatacenterSet>) {
        self.dc.store(dc);
    }
}

impl SignalProvider for AsnClassifier {
    fn name(&self) -> &'static str {
        "asn_classifier"
    }

    fn evaluate(&self, ctx: &RelayCtx<'_>) -> Vec<Signal> {
        // `Derived` is populated by xff/proxy_chain providers; if neither
        // ran (e.g. asn_classifier listed alone in `signals.enabled`),
        // fall back to the raw peer IP per phase-03 spec.
        let real_ip = ctx.derived().map_or(ctx.peer_ip, |d| d.real_ip);
        let db = self.db.load();
        let dc = self.dc.load();
        let signal = match db.lookup(real_ip) {
            None => Signal::AsnUnknown,
            Some(rec) => {
                if dc.operator_allow.contains(&rec.asn) {
                    // Operator allow ALWAYS WINS — even if the IP is in a
                    // hyperscaler ASN range. Keeps legit cloud-hosted
                    // tenants out of the DC bucket per brainstorm §4.5.
                    Signal::AsnResidential
                } else if dc.operator_deny.contains(&rec.asn)
                    || dc.asn_ids.contains(&rec.asn)
                    || dc.contains_ip(real_ip)
                {
                    Signal::AsnDatacenter {
                        asn: rec.asn,
                        org: rec.org,
                    }
                } else {
                    Signal::AsnResidential
                }
            }
        };
        vec![signal]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::intel::{AsnRecord, EmptyAsnDb};
    use http::HeaderMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    struct StaticDb(Option<AsnRecord>);
    impl AsnDb for StaticDb {
        fn lookup(&self, _ip: IpAddr) -> Option<AsnRecord> {
            self.0.clone()
        }
        fn name(&self) -> &'static str {
            "static_test"
        }
    }

    fn ctx(headers: &HeaderMap, ip: IpAddr) -> RelayCtx<'_> {
        RelayCtx::new(ip, headers, Instant::now())
    }

    #[test]
    fn unknown_when_db_misses() {
        let h = HeaderMap::new();
        let c = AsnClassifier::new(Box::new(EmptyAsnDb), Arc::new(DatacenterSet::default()));
        let out = c.evaluate(&ctx(&h, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert_eq!(out, vec![Signal::AsnUnknown]);
    }

    #[test]
    fn datacenter_when_asn_in_dc_set() {
        let h = HeaderMap::new();
        let mut dc = DatacenterSet::default();
        dc.asn_ids.insert(15169);
        let db: Box<dyn AsnDb> = Box::new(StaticDb(Some(AsnRecord {
            asn: 15169,
            org: "GOOGLE".into(),
        })));
        let c = AsnClassifier::new(db, Arc::new(dc));
        let out = c.evaluate(&ctx(&h, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert_eq!(
            out,
            vec![Signal::AsnDatacenter {
                asn: 15169,
                org: "GOOGLE".into(),
            }]
        );
    }

    #[test]
    fn residential_when_asn_unmatched() {
        let h = HeaderMap::new();
        let db: Box<dyn AsnDb> = Box::new(StaticDb(Some(AsnRecord {
            asn: 7922,
            org: "COMCAST".into(),
        })));
        let c = AsnClassifier::new(db, Arc::new(DatacenterSet::default()));
        let out = c.evaluate(&ctx(&h, IpAddr::V4(Ipv4Addr::new(73, 1, 2, 3))));
        assert_eq!(out, vec![Signal::AsnResidential]);
    }

    #[test]
    fn operator_allow_overrides_dc_classification() {
        let h = HeaderMap::new();
        let mut dc = DatacenterSet::default();
        dc.asn_ids.insert(15169);
        dc.operator_allow.insert(15169);
        let db: Box<dyn AsnDb> = Box::new(StaticDb(Some(AsnRecord {
            asn: 15169,
            org: "GOOGLE".into(),
        })));
        let c = AsnClassifier::new(db, Arc::new(dc));
        let out = c.evaluate(&ctx(&h, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert_eq!(out, vec![Signal::AsnResidential]);
    }

    #[test]
    fn operator_deny_forces_dc_classification() {
        let h = HeaderMap::new();
        let mut dc = DatacenterSet::default();
        dc.operator_deny.insert(7922);
        let db: Box<dyn AsnDb> = Box::new(StaticDb(Some(AsnRecord {
            asn: 7922,
            org: "COMCAST".into(),
        })));
        let c = AsnClassifier::new(db, Arc::new(dc));
        let out = c.evaluate(&ctx(&h, IpAddr::V4(Ipv4Addr::new(73, 1, 2, 3))));
        assert_eq!(
            out,
            vec![Signal::AsnDatacenter {
                asn: 7922,
                org: "COMCAST".into(),
            }]
        );
    }

    #[test]
    fn cidr_match_marks_datacenter_when_asn_unknown() {
        let h = HeaderMap::new();
        let mut dc = DatacenterSet::default();
        dc.cidrs
            .insert("203.0.113.0/24".parse::<ip_network::IpNetwork>().expect("cidr"), ());
        let c = AsnClassifier::new(
            Box::new(StaticDb(Some(AsnRecord {
                asn: 64500,
                org: "VENDOR".into(),
            }))),
            Arc::new(dc),
        );
        let out = c.evaluate(&ctx(&h, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))));
        assert!(matches!(out.first(), Some(Signal::AsnDatacenter { asn: 64500, .. })));
    }
}
