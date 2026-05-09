// Certificates CRUD + status + PEM update + due-renewal coverage.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/mod.rs"]
mod common;

use chrono::{Duration, Utc};
use common::start_postgres;
use waf_storage::models::{CreateCertificate, UpdateCertificatePem};

fn sample(domain: &str) -> CreateCertificate {
    CreateCertificate {
        host_code: "h1".into(),
        domain: domain.into(),
        cert_pem: None,
        key_pem: None,
        chain_pem: None,
        auto_renew: Some(true),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn certificate_create_get_list_by_domain_delete() {
    let fx = start_postgres().await;
    let cert = fx.db.create_certificate(sample("a.example.com")).await.unwrap();
    assert_eq!(cert.status, "pending");
    assert!(cert.auto_renew);

    let by_id = fx.db.get_certificate(cert.id).await.unwrap().unwrap();
    assert_eq!(by_id.id, cert.id);

    let by_domain = fx.db.get_certificate_by_domain("a.example.com").await.unwrap().unwrap();
    assert_eq!(by_domain.id, cert.id);

    let none = fx.db.get_certificate_by_domain("missing").await.unwrap();
    assert!(none.is_none());

    let listed_all = fx.db.list_certificates(None).await.unwrap();
    assert_eq!(listed_all.len(), 1);
    let listed_h1 = fx.db.list_certificates(Some("h1")).await.unwrap();
    assert_eq!(listed_h1.len(), 1);
    let listed_other = fx.db.list_certificates(Some("nope")).await.unwrap();
    assert!(listed_other.is_empty());

    assert!(fx.db.delete_certificate(cert.id).await.unwrap());
    assert!(!fx.db.delete_certificate(cert.id).await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn update_status_and_pem_round_trip() {
    let fx = start_postgres().await;
    let cert = fx.db.create_certificate(sample("b.example.com")).await.unwrap();

    fx.db
        .update_certificate_status(cert.id, "error", Some("acme failed"))
        .await
        .unwrap();
    let after_err = fx.db.get_certificate(cert.id).await.unwrap().unwrap();
    assert_eq!(after_err.status, "error");
    assert_eq!(after_err.error_msg.as_deref(), Some("acme failed"));

    let now = Utc::now();
    let later = now + Duration::days(90);
    fx.db
        .update_certificate_pem(&UpdateCertificatePem {
            id: cert.id,
            cert_pem: "CERT",
            key_pem: "KEY",
            chain_pem: Some("CHAIN"),
            not_before: now,
            not_after: later,
            issuer: "Test CA",
            subject: "CN=b.example.com",
        })
        .await
        .unwrap();

    let after = fx.db.get_certificate(cert.id).await.unwrap().unwrap();
    assert_eq!(after.status, "active");
    assert_eq!(after.cert_pem.as_deref(), Some("CERT"));
    assert_eq!(after.key_pem.as_deref(), Some("KEY"));
    assert_eq!(after.chain_pem.as_deref(), Some("CHAIN"));
    assert_eq!(after.issuer.as_deref(), Some("Test CA"));
    assert!(after.error_msg.is_none(), "PEM update clears error_msg");
}

#[tokio::test(flavor = "multi_thread")]
async fn list_certificates_due_renewal_filters_by_window() {
    let fx = start_postgres().await;
    // Cert expiring in 5 days → due if window=10
    let due = fx.db.create_certificate(sample("due.example.com")).await.unwrap();
    fx.db
        .update_certificate_pem(&UpdateCertificatePem {
            id: due.id,
            cert_pem: "C",
            key_pem: "K",
            chain_pem: None,
            not_before: Utc::now() - Duration::days(60),
            not_after: Utc::now() + Duration::days(5),
            issuer: "I",
            subject: "S",
        })
        .await
        .unwrap();

    // Cert expiring in 60 days → not due
    let safe = fx.db.create_certificate(sample("safe.example.com")).await.unwrap();
    fx.db
        .update_certificate_pem(&UpdateCertificatePem {
            id: safe.id,
            cert_pem: "C",
            key_pem: "K",
            chain_pem: None,
            not_before: Utc::now() - Duration::days(1),
            not_after: Utc::now() + Duration::days(60),
            issuer: "I",
            subject: "S",
        })
        .await
        .unwrap();

    let renewals = fx.db.list_certificates_due_renewal(10).await.unwrap();
    assert_eq!(renewals.len(), 1);
    assert_eq!(renewals[0].id, due.id);
}
