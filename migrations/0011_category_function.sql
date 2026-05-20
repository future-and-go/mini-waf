-- 0011_category_function.sql
-- Centralized category derivation for security_events.rule_id.
-- DRY: replaces inline CASE expressions duplicated at repo.rs:987-1027 and
-- repo.rs:1062-1108. The new endpoint heatmap (repo.rs::get_endpoint_heatmap)
-- is the 3rd consumer.
-- LANGUAGE SQL IMMUTABLE: planner inlines the CASE body into the calling
-- query, zero per-row function-call overhead.

CREATE OR REPLACE FUNCTION category_of(rule_id TEXT) RETURNS TEXT AS $$
  SELECT CASE
    WHEN rule_id LIKE 'SQLI-%'        THEN 'sqli'
    WHEN rule_id LIKE 'XSS-%'         THEN 'xss'
    WHEN rule_id LIKE 'RCE-%'         THEN 'rce'
    WHEN rule_id LIKE 'TRAV-%'        THEN 'path-traversal'
    WHEN rule_id LIKE 'SCAN-%'        THEN 'scanner'
    WHEN rule_id LIKE 'BOT-%'         THEN 'bot'
    WHEN rule_id LIKE 'CC-%'          THEN 'cc-ddos'
    WHEN rule_id LIKE 'SSRF-%'        THEN 'ssrf'
    WHEN rule_id LIKE 'ADV-SSRF%'     THEN 'ssrf'
    WHEN rule_id LIKE 'ADV-SSTI%'     THEN 'ssti'
    WHEN rule_id LIKE 'ADV-%'         THEN 'advanced'
    WHEN rule_id LIKE 'CRS-RESP%'     THEN 'data-leakage'
    WHEN rule_id LIKE 'CRS-%'         THEN 'owasp-crs'
    WHEN rule_id LIKE 'API-MASS%'     THEN 'mass-assignment'
    WHEN rule_id LIKE 'API-%'         THEN 'api-security'
    WHEN rule_id LIKE 'MODSEC-RESP%'  THEN 'web-shell'
    WHEN rule_id LIKE 'MODSEC-%'      THEN 'modsecurity'
    WHEN rule_id LIKE 'CVE-%'         THEN 'cve'
    WHEN rule_id LIKE 'GEO-%'         THEN 'geo-blocking'
    WHEN rule_id LIKE 'CUSTOM-%'      THEN 'custom'
    WHEN rule_id LIKE 'IP-%'          THEN 'ip-rule'
    WHEN rule_id LIKE 'URL-%'         THEN 'url-rule'
    WHEN rule_id LIKE 'SENS-%'        THEN 'sensitive-data'
    WHEN rule_id LIKE 'HOTLINK-%'     THEN 'anti-hotlink'
    WHEN rule_id LIKE 'OWASP-942%'    THEN 'sqli'
    WHEN rule_id LIKE 'OWASP-941%'    THEN 'xss'
    WHEN rule_id LIKE 'OWASP-930%'    THEN 'lfi'
    WHEN rule_id LIKE 'OWASP-931%'    THEN 'rfi'
    WHEN rule_id LIKE 'OWASP-932%'    THEN 'rce'
    WHEN rule_id LIKE 'OWASP-933%'    THEN 'php-injection'
    WHEN rule_id LIKE 'OWASP-913%'    THEN 'scanner'
    ELSE 'other'
  END;
$$ LANGUAGE SQL IMMUTABLE;
