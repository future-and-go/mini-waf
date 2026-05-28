use sqlx::QueryBuilder;
use tracing::debug;
use uuid::Uuid;

use crate::db::Database;
use crate::error::StorageError;
use crate::models::{
    AdminUser, AllowIp, AllowUrl, AttackLog, AttackLogQuery, AuditLogEntry, AuditLogQuery, BlockIp, BlockUrl,
    CategoryTimeSeriesPoint, Certificate, CreateAdminUser, CreateCertificate, CreateCrowdSecEvent, CreateCustomRule,
    CreateHost, CreateIpRule, CreateLbBackend, CreateNotificationConfig, CreateSecurityEvent, CreateSensitivePattern,
    CreateTunnel, CreateUrlRule, CreateWasmPlugin, CrowdSecConfigRow, CrowdSecEventQuery, CrowdSecEventRow, CustomRule,
    EndpointHeatmap, GeoDistEntry, GeoStats, HeatmapCell, HeatmapFilter, Host, HotlinkConfig, LbBackend,
    NotificationConfig, NotificationLog, RecentEvent, RefreshToken, SecurityEvent, SecurityEventQuery,
    SensitivePattern, StatsFilter, StatsOverview, TimeSeriesPoint, TopEntry, TunnelRow, UpdateCertificatePem,
    UpdateCustomRule, UpdateHost, UpsertCrowdSecConfig, UpsertHotlinkConfig, WasmPluginRow,
};

impl Database {
    // ─── Hosts ───────────────────────────────────────────────────────────────

    pub async fn list_hosts(&self) -> Result<Vec<Host>, StorageError> {
        let rows = sqlx::query_as::<_, Host>("SELECT * FROM hosts ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows)
    }

    pub async fn get_host(&self, id: Uuid) -> Result<Option<Host>, StorageError> {
        let row = sqlx::query_as::<_, Host>("SELECT * FROM hosts WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    pub async fn get_host_by_code(&self, code: &str) -> Result<Option<Host>, StorageError> {
        let row = sqlx::query_as::<_, Host>("SELECT * FROM hosts WHERE code = $1")
            .bind(code)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    pub async fn create_host(&self, req: CreateHost) -> Result<Host, StorageError> {
        let id = Uuid::new_v4();
        let code = Uuid::new_v4().to_string().replace('-', "")[..16].to_string();
        let now = chrono::Utc::now();

        let row = sqlx::query_as::<_, Host>(
            r"INSERT INTO hosts (
                id, code, host, port, ssl, guard_status,
                remote_host, remote_port, remote_ip, cert_file, key_file,
                remarks, start_status, log_only_mode, upstream_alpn, upstream_skip_ssl_verify,
                http_redirect, defense_json,
                is_enable_load_balance, load_balance_stage,
                created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6,
                $7, $8, $9, $10, $11,
                $12, $13, $14, $15, $16,
                $17, $18,
                false, 0,
                $19, $19
            ) RETURNING *",
        )
        .bind(id)
        .bind(&code)
        .bind(&req.host)
        .bind(req.port)
        .bind(req.ssl)
        .bind(req.guard_status)
        .bind(&req.remote_host)
        .bind(req.remote_port)
        .bind(&req.remote_ip)
        .bind(&req.cert_file)
        .bind(&req.key_file)
        .bind(&req.remarks)
        .bind(req.start_status)
        .bind(req.log_only_mode)
        .bind(&req.upstream_alpn)
        .bind(req.upstream_skip_ssl_verify)
        .bind(req.http_redirect)  // $17
        .bind(&req.defense_json)  // $18
        .bind(now)                // $19
        .fetch_one(&self.pool)
        .await?;

        debug!("Created host: {} (code={})", req.host, code);
        Ok(row)
    }

    pub async fn update_host(&self, id: Uuid, req: UpdateHost) -> Result<Option<Host>, StorageError> {
        let now = chrono::Utc::now();

        let row = sqlx::query_as::<_, Host>(
            r"UPDATE hosts SET
                host = COALESCE($2, host),
                port = COALESCE($3, port),
                ssl = COALESCE($4, ssl),
                guard_status = COALESCE($5, guard_status),
                remote_host = COALESCE($6, remote_host),
                remote_port = COALESCE($7, remote_port),
                remote_ip = COALESCE($8, remote_ip),
                cert_file = COALESCE($9, cert_file),
                key_file = COALESCE($10, key_file),
                remarks = COALESCE($11, remarks),
                start_status = COALESCE($12, start_status),
                log_only_mode = COALESCE($13, log_only_mode),
                upstream_alpn = COALESCE($14, upstream_alpn),
                upstream_skip_ssl_verify = COALESCE($15, upstream_skip_ssl_verify),
                http_redirect = COALESCE($16, http_redirect),
                defense_json = COALESCE($17, defense_json),
                updated_at = $18
            WHERE id = $1
            RETURNING *",
        )
        .bind(id)
        .bind(req.host)
        .bind(req.port)
        .bind(req.ssl)
        .bind(req.guard_status)
        .bind(req.remote_host)
        .bind(req.remote_port)
        .bind(req.remote_ip)
        .bind(req.cert_file)
        .bind(req.key_file)
        .bind(req.remarks)
        .bind(req.start_status)
        .bind(req.log_only_mode)
        .bind(req.upstream_alpn)
        .bind(req.upstream_skip_ssl_verify)
        .bind(req.http_redirect) // $16
        .bind(req.defense_json)  // $17
        .bind(now)               // $18
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn delete_host(&self, id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM hosts WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // ─── Allow IPs ───────────────────────────────────────────────────────────

    pub async fn list_allow_ips(&self, host_code: Option<&str>) -> Result<Vec<AllowIp>, StorageError> {
        let rows = match host_code {
            Some(code) => {
                sqlx::query_as::<_, AllowIp>("SELECT * FROM allow_ips WHERE host_code = $1 ORDER BY created_at DESC")
                    .bind(code)
                    .fetch_all(&self.pool)
                    .await?
            }
            None => {
                sqlx::query_as::<_, AllowIp>("SELECT * FROM allow_ips ORDER BY created_at DESC")
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(rows)
    }

    pub async fn create_allow_ip(&self, req: CreateIpRule) -> Result<AllowIp, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = sqlx::query_as::<_, AllowIp>(
            r"INSERT INTO allow_ips (id, host_code, ip_cidr, remarks, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $5)
               RETURNING *",
        )
        .bind(id)
        .bind(&req.host_code)
        .bind(&req.ip_cidr)
        .bind(&req.remarks)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn delete_allow_ip(&self, id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM allow_ips WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // ─── Block IPs ───────────────────────────────────────────────────────────

    pub async fn list_block_ips(&self, host_code: Option<&str>) -> Result<Vec<BlockIp>, StorageError> {
        let rows = match host_code {
            Some(code) => {
                sqlx::query_as::<_, BlockIp>("SELECT * FROM block_ips WHERE host_code = $1 ORDER BY created_at DESC")
                    .bind(code)
                    .fetch_all(&self.pool)
                    .await?
            }
            None => {
                sqlx::query_as::<_, BlockIp>("SELECT * FROM block_ips ORDER BY created_at DESC")
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(rows)
    }

    pub async fn create_block_ip(&self, req: CreateIpRule) -> Result<BlockIp, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = sqlx::query_as::<_, BlockIp>(
            r"INSERT INTO block_ips (id, host_code, ip_cidr, remarks, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $5)
               RETURNING *",
        )
        .bind(id)
        .bind(&req.host_code)
        .bind(&req.ip_cidr)
        .bind(&req.remarks)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn delete_block_ip(&self, id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM block_ips WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // ─── Allow URLs ──────────────────────────────────────────────────────────

    pub async fn list_allow_urls(&self, host_code: Option<&str>) -> Result<Vec<AllowUrl>, StorageError> {
        let rows = match host_code {
            Some(code) => {
                sqlx::query_as::<_, AllowUrl>("SELECT * FROM allow_urls WHERE host_code = $1 ORDER BY created_at DESC")
                    .bind(code)
                    .fetch_all(&self.pool)
                    .await?
            }
            None => {
                sqlx::query_as::<_, AllowUrl>("SELECT * FROM allow_urls ORDER BY created_at DESC")
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(rows)
    }

    pub async fn create_allow_url(&self, req: CreateUrlRule) -> Result<AllowUrl, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = sqlx::query_as::<_, AllowUrl>(
            r"INSERT INTO allow_urls (id, host_code, url_pattern, match_type, remarks, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $6)
               RETURNING *",
        )
        .bind(id)
        .bind(&req.host_code)
        .bind(&req.url_pattern)
        .bind(&req.match_type)
        .bind(&req.remarks)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn delete_allow_url(&self, id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM allow_urls WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // ─── Block URLs ──────────────────────────────────────────────────────────

    pub async fn list_block_urls(&self, host_code: Option<&str>) -> Result<Vec<BlockUrl>, StorageError> {
        let rows = match host_code {
            Some(code) => {
                sqlx::query_as::<_, BlockUrl>("SELECT * FROM block_urls WHERE host_code = $1 ORDER BY created_at DESC")
                    .bind(code)
                    .fetch_all(&self.pool)
                    .await?
            }
            None => {
                sqlx::query_as::<_, BlockUrl>("SELECT * FROM block_urls ORDER BY created_at DESC")
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(rows)
    }

    pub async fn create_block_url(&self, req: CreateUrlRule) -> Result<BlockUrl, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = sqlx::query_as::<_, BlockUrl>(
            r"INSERT INTO block_urls (id, host_code, url_pattern, match_type, remarks, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $6)
               RETURNING *",
        )
        .bind(id)
        .bind(&req.host_code)
        .bind(&req.url_pattern)
        .bind(&req.match_type)
        .bind(&req.remarks)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn delete_block_url(&self, id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM block_urls WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // ─── Attack Logs ─────────────────────────────────────────────────────────

    pub async fn create_attack_log(&self, log: AttackLog) -> Result<(), StorageError> {
        sqlx::query(
            r"INSERT INTO attack_logs (
                id, host_code, host, client_ip, method, path, query,
                rule_id, rule_name, action, phase, detail,
                request_headers, geo_info, created_at
            ) VALUES ($1,$2,$3,$4::inet,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
        )
        .bind(log.id)
        .bind(&log.host_code)
        .bind(&log.host)
        .bind(&log.client_ip)
        .bind(&log.method)
        .bind(&log.path)
        .bind(&log.query)
        .bind(&log.rule_id)
        .bind(&log.rule_name)
        .bind(&log.action)
        .bind(&log.phase)
        .bind(&log.detail)
        .bind(&log.request_headers)
        .bind(&log.geo_info)
        .bind(log.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_attack_logs(&self, query: &AttackLogQuery) -> Result<(Vec<AttackLog>, i64), StorageError> {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(20).clamp(1, 100);
        let offset = (page - 1) * page_size;

        // Count query — same INET caveat as the list query below: avoid
        // comparing the INET column directly with a TEXT bind parameter by
        // wrapping in `host()` which returns the address as plain TEXT.
        let total: i64 = sqlx::query_scalar(
            r"SELECT COUNT(*) FROM attack_logs
               WHERE ($1::text IS NULL OR host_code = $1)
                 AND ($2::text IS NULL OR host(client_ip) = $2)
                 AND ($3::text IS NULL OR action = $3)
                 AND ($4::text IS NULL OR geo_info->>'iso_code' = $4)
                 AND ($5::text IS NULL OR geo_info->>'country' ILIKE '%' || $5 || '%')",
        )
        .bind(&query.host_code)
        .bind(&query.client_ip)
        .bind(&query.action)
        .bind(&query.iso_code)
        .bind(&query.country)
        .fetch_one(&self.pool)
        .await?;

        // NOTE: `attack_logs.client_ip` is INET in the schema but `AttackLog.client_ip`
        // is `String` in Rust — sqlx validates the column->Rust mapping at prepare
        // time and errors with "unsupported type" if we just `SELECT *`. Cast to
        // TEXT here so the prepared-statement type check sees a textual column.
        // Use postgres `host(inet)` so the result column is plain TEXT
        // ("192.168.1.1") without any subnet-mask suffix. The `::TEXT` cast
        // alone preserves the slash-form (e.g. "192.168.1.1/32") and some
        // sqlx versions still trip the prepared-statement type validation
        // because the underlying column type advertised in the result
        // metadata is INET (the alias only renames the column, not its
        // type). `host()` returns a real text expression so sqlx maps it
        // straight into String with no INET deserialiser involved.
        let rows = sqlx::query_as::<_, AttackLog>(
            r"SELECT id, host_code, host, host(client_ip) AS client_ip, method, path,
                      query, rule_id, rule_name, action, phase, detail,
                      request_headers, geo_info, created_at
               FROM attack_logs
               WHERE ($1::text IS NULL OR host_code = $1)
                 AND ($2::text IS NULL OR host(client_ip) = $2)
                 AND ($3::text IS NULL OR action = $3)
                 AND ($4::text IS NULL OR geo_info->>'iso_code' = $4)
                 AND ($5::text IS NULL OR geo_info->>'country' ILIKE '%' || $5 || '%')
               ORDER BY created_at DESC
               LIMIT $6 OFFSET $7",
        )
        .bind(&query.host_code)
        .bind(&query.client_ip)
        .bind(&query.action)
        .bind(&query.iso_code)
        .bind(&query.country)
        .bind(page_size)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok((rows, total))
    }

    // ─── Security Events ─────────────────────────────────────────────────────

    pub async fn create_security_event(&self, req: CreateSecurityEvent) -> Result<(), StorageError> {
        sqlx::query(
            r"INSERT INTO security_events
               (host_code, client_ip, method, path, rule_id, rule_name, action, detail, geo_info)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(&req.host_code)
        .bind(&req.client_ip)
        .bind(&req.method)
        .bind(&req.path)
        .bind(&req.rule_id)
        .bind(&req.rule_name)
        .bind(&req.action)
        .bind(&req.detail)
        .bind(&req.geo_info)
        .execute(&self.pool)
        .await?;

        // Broadcast to WebSocket subscribers
        if let Ok(event_json) = serde_json::to_value(&req) {
            self.broadcast_event(event_json);
        }

        Ok(())
    }

    // ─── Batch Inserts (used by DbBatchWriter for high-throughput logging) ────

    pub async fn create_attack_log_batch(&self, logs: &[AttackLog]) -> Result<(), StorageError> {
        if logs.is_empty() {
            return Ok(());
        }
        for chunk in logs.chunks(1000) {
            let mut qb: QueryBuilder<sqlx::Postgres> = QueryBuilder::new(
                "INSERT INTO attack_logs (id, host_code, host, client_ip, method, path, query, \
                 rule_id, rule_name, action, phase, detail, request_headers, geo_info, created_at) ",
            );
            qb.push_values(chunk, |mut b, log| {
                b.push_bind(log.id)
                    .push_bind(&log.host_code)
                    .push_bind(&log.host)
                    .push_bind(&log.client_ip)
                    .push_bind(&log.method)
                    .push_bind(&log.path)
                    .push_bind(&log.query)
                    .push_bind(&log.rule_id)
                    .push_bind(&log.rule_name)
                    .push_bind(&log.action)
                    .push_bind(&log.phase)
                    .push_bind(&log.detail)
                    .push_bind(&log.request_headers)
                    .push_bind(&log.geo_info)
                    .push_bind(log.created_at);
            });
            qb.push(" ON CONFLICT DO NOTHING");
            qb.build().execute(&self.pool).await?;
        }
        Ok(())
    }

    pub async fn create_security_event_batch(&self, events: &[CreateSecurityEvent]) -> Result<(), StorageError> {
        if events.is_empty() {
            return Ok(());
        }
        for chunk in events.chunks(1000) {
            let mut qb: QueryBuilder<sqlx::Postgres> = QueryBuilder::new(
                "INSERT INTO security_events (host_code, client_ip, method, path, \
                 rule_id, rule_name, action, detail, geo_info) ",
            );
            qb.push_values(chunk, |mut b, ev| {
                b.push_bind(&ev.host_code)
                    .push_bind(&ev.client_ip)
                    .push_bind(&ev.method)
                    .push_bind(&ev.path)
                    .push_bind(&ev.rule_id)
                    .push_bind(&ev.rule_name)
                    .push_bind(&ev.action)
                    .push_bind(&ev.detail)
                    .push_bind(&ev.geo_info);
            });
            qb.push(" ON CONFLICT DO NOTHING");
            qb.build().execute(&self.pool).await?;
        }
        Ok(())
    }

    // ─── Certificates ─────────────────────────────────────────────────────────

    pub async fn list_certificates(&self, host_code: Option<&str>) -> Result<Vec<Certificate>, StorageError> {
        let rows = match host_code {
            Some(code) => {
                sqlx::query_as::<_, Certificate>(
                    "SELECT * FROM certificates WHERE host_code = $1 ORDER BY created_at DESC",
                )
                .bind(code)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, Certificate>("SELECT * FROM certificates ORDER BY created_at DESC")
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(rows)
    }

    pub async fn get_certificate(&self, id: Uuid) -> Result<Option<Certificate>, StorageError> {
        Ok(
            sqlx::query_as::<_, Certificate>("SELECT * FROM certificates WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn get_certificate_by_domain(&self, domain: &str) -> Result<Option<Certificate>, StorageError> {
        Ok(sqlx::query_as::<_, Certificate>(
            "SELECT * FROM certificates WHERE domain = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(domain)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn create_certificate(&self, req: CreateCertificate) -> Result<Certificate, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = sqlx::query_as::<_, Certificate>(
            r"INSERT INTO certificates (id, host_code, domain, cert_pem, key_pem, chain_pem, auto_renew, status, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8,$8) RETURNING *"
        )
        .bind(id).bind(&req.host_code).bind(&req.domain)
        .bind(&req.cert_pem).bind(&req.key_pem).bind(&req.chain_pem)
        .bind(req.auto_renew.unwrap_or(true)).bind(now)
        .fetch_one(&self.pool).await?;
        Ok(row)
    }

    pub async fn update_certificate_status(
        &self,
        id: Uuid,
        status: &str,
        error_msg: Option<&str>,
    ) -> Result<(), StorageError> {
        sqlx::query("UPDATE certificates SET status=$2, error_msg=$3, updated_at=NOW() WHERE id=$1")
            .bind(id)
            .bind(status)
            .bind(error_msg)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_certificate_pem(&self, params: &UpdateCertificatePem<'_>) -> Result<(), StorageError> {
        sqlx::query(
            r"UPDATE certificates SET cert_pem=$2, key_pem=$3, chain_pem=$4,
               not_before=$5, not_after=$6, issuer=$7, subject=$8,
               status='active', error_msg=NULL, updated_at=NOW() WHERE id=$1",
        )
        .bind(params.id)
        .bind(params.cert_pem)
        .bind(params.key_pem)
        .bind(params.chain_pem)
        .bind(params.not_before)
        .bind(params.not_after)
        .bind(params.issuer)
        .bind(params.subject)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_certificates_due_renewal(&self, days_before: i64) -> Result<Vec<Certificate>, StorageError> {
        let threshold = chrono::Utc::now() + chrono::Duration::days(days_before);
        let rows = sqlx::query_as::<_, Certificate>(
            r"SELECT * FROM certificates
               WHERE auto_renew = TRUE AND status = 'active'
                 AND not_after IS NOT NULL AND not_after < $1",
        )
        .bind(threshold)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn delete_certificate(&self, id: Uuid) -> Result<bool, StorageError> {
        let r = sqlx::query("DELETE FROM certificates WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    // ─── Custom Rules ─────────────────────────────────────────────────────────

    pub async fn list_custom_rules(&self, host_code: Option<&str>) -> Result<Vec<CustomRule>, StorageError> {
        let rows = match host_code {
            Some(code) => {
                sqlx::query_as::<_, CustomRule>(
                    "SELECT * FROM custom_rules WHERE host_code = $1 ORDER BY priority, created_at",
                )
                .bind(code)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, CustomRule>("SELECT * FROM custom_rules ORDER BY priority, created_at")
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(rows)
    }

    pub async fn get_custom_rule(&self, id: Uuid) -> Result<Option<CustomRule>, StorageError> {
        Ok(
            sqlx::query_as::<_, CustomRule>("SELECT * FROM custom_rules WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn create_custom_rule(&self, req: CreateCustomRule) -> Result<CustomRule, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();

        // match_tree takes priority: pack it into the conditions JSON column,
        // same convention as update_custom_rule.
        let conditions_val = if let Some(tree) = req.match_tree {
            serde_json::json!({ "match_tree": tree })
        } else {
            req.conditions
        };

        let row = sqlx::query_as::<_, CustomRule>(
            r"INSERT INTO custom_rules
               (id, host_code, name, description, priority, enabled, condition_op, conditions,
                action, action_status, action_msg, script, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13) RETURNING *",
        )
        .bind(id)
        .bind(&req.host_code)
        .bind(&req.name)
        .bind(&req.description)
        .bind(req.priority.unwrap_or(100))
        .bind(req.enabled.unwrap_or(true))
        .bind(req.condition_op.as_deref().unwrap_or("and"))
        .bind(&conditions_val)
        .bind(req.action.as_deref().unwrap_or("block"))
        .bind(req.action_status.unwrap_or(403))
        .bind(&req.action_msg)
        .bind(&req.script)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn delete_custom_rule(&self, id: Uuid) -> Result<bool, StorageError> {
        let r = sqlx::query("DELETE FROM custom_rules WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn set_custom_rule_enabled(&self, id: Uuid, enabled: bool) -> Result<bool, StorageError> {
        let r = sqlx::query("UPDATE custom_rules SET enabled=$2, updated_at=NOW() WHERE id=$1")
            .bind(id)
            .bind(enabled)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn update_custom_rule(
        &self,
        id: Uuid,
        req: UpdateCustomRule,
    ) -> Result<Option<CustomRule>, StorageError> {
        // Fetch current row so absent fields fall back to existing values.
        let Some(current) = self.get_custom_rule(id).await? else {
            return Ok(None);
        };

        // match_tree takes priority: pack it into the conditions JSON column.
        // Otherwise use the explicitly provided conditions, else keep existing.
        let conditions_val = if let Some(tree) = req.match_tree {
            serde_json::json!({ "match_tree": tree })
        } else if let Some(c) = req.conditions {
            c
        } else {
            current.conditions.clone()
        };

        // Double-option fields: None = keep old, Some(v) = write v (may be NULL).
        let description = match req.description {
            None => current.description,
            Some(v) => v,
        };
        let action_msg = match req.action_msg {
            None => current.action_msg,
            Some(v) => v,
        };
        let script = match req.script {
            None => current.script,
            Some(v) => v,
        };

        let row = sqlx::query_as::<_, CustomRule>(
            r"UPDATE custom_rules SET
                host_code    = $2,
                name         = $3,
                description  = $4,
                priority     = $5,
                enabled      = $6,
                condition_op = $7,
                conditions   = $8,
                action       = $9,
                action_status= $10,
                action_msg   = $11,
                script       = $12,
                updated_at   = NOW()
              WHERE id = $1
              RETURNING *",
        )
        .bind(id)
        // Simple Option fields: None falls back to current value.
        .bind(req.host_code.unwrap_or(current.host_code))
        .bind(req.name.unwrap_or(current.name))
        .bind(description)
        .bind(req.priority.unwrap_or(current.priority))
        .bind(req.enabled.unwrap_or(current.enabled))
        .bind(req.condition_op.unwrap_or(current.condition_op))
        .bind(conditions_val)
        .bind(req.action.unwrap_or(current.action))
        .bind(req.action_status.unwrap_or(current.action_status))
        .bind(action_msg)
        .bind(script)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    // ─── Sensitive Patterns ───────────────────────────────────────────────────

    pub async fn list_sensitive_patterns(
        &self,
        host_code: Option<&str>,
    ) -> Result<Vec<SensitivePattern>, StorageError> {
        let rows = match host_code {
            Some(code) => {
                sqlx::query_as::<_, SensitivePattern>(
                    "SELECT * FROM sensitive_patterns WHERE host_code = $1 AND enabled = TRUE ORDER BY created_at",
                )
                .bind(code)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, SensitivePattern>(
                    "SELECT * FROM sensitive_patterns WHERE enabled = TRUE ORDER BY created_at",
                )
                .fetch_all(&self.pool)
                .await?
            }
        };
        Ok(rows)
    }

    pub async fn create_sensitive_pattern(
        &self,
        req: CreateSensitivePattern,
    ) -> Result<SensitivePattern, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = sqlx::query_as::<_, SensitivePattern>(
            r"INSERT INTO sensitive_patterns
               (id, host_code, pattern, pattern_type, check_request, check_response, action, remarks, enabled, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,true,$9,$9) RETURNING *"
        )
        .bind(id).bind(&req.host_code).bind(&req.pattern)
        .bind(req.pattern_type.as_deref().unwrap_or("word"))
        .bind(req.check_request.unwrap_or(true))
        .bind(req.check_response.unwrap_or(false))
        .bind(req.action.as_deref().unwrap_or("block"))
        .bind(&req.remarks).bind(now)
        .fetch_one(&self.pool).await?;
        Ok(row)
    }

    pub async fn delete_sensitive_pattern(&self, id: Uuid) -> Result<bool, StorageError> {
        let r = sqlx::query("DELETE FROM sensitive_patterns WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn toggle_sensitive_pattern(&self, id: Uuid, enabled: bool) -> Result<bool, StorageError> {
        let r = sqlx::query("UPDATE sensitive_patterns SET enabled=$2, updated_at=NOW() WHERE id=$1")
            .bind(id)
            .bind(enabled)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn update_sensitive_pattern(
        &self,
        id: Uuid,
        pattern: Option<&str>,
        pattern_type: Option<&str>,
        check_request: Option<bool>,
        check_response: Option<bool>,
        action: Option<&str>,
        remarks: Option<&str>,
        enabled: Option<bool>,
    ) -> Result<Option<SensitivePattern>, StorageError> {
        let row = sqlx::query_as::<_, SensitivePattern>(
            r"UPDATE sensitive_patterns SET
                pattern       = COALESCE($2, pattern),
                pattern_type  = COALESCE($3, pattern_type),
                check_request = COALESCE($4, check_request),
                check_response = COALESCE($5, check_response),
                action        = COALESCE($6, action),
                remarks       = COALESCE($7, remarks),
                enabled       = COALESCE($8, enabled),
                updated_at    = NOW()
              WHERE id = $1
              RETURNING *",
        )
        .bind(id)
        .bind(pattern)
        .bind(pattern_type)
        .bind(check_request)
        .bind(check_response)
        .bind(action)
        .bind(remarks)
        .bind(enabled)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    // ─── Hotlink Configs ──────────────────────────────────────────────────────

    pub async fn get_hotlink_config(&self, host_code: &str) -> Result<Option<HotlinkConfig>, StorageError> {
        Ok(
            sqlx::query_as::<_, HotlinkConfig>("SELECT * FROM hotlink_configs WHERE host_code = $1")
                .bind(host_code)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn list_hotlink_configs(&self) -> Result<Vec<HotlinkConfig>, StorageError> {
        Ok(
            sqlx::query_as::<_, HotlinkConfig>("SELECT * FROM hotlink_configs ORDER BY created_at")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn upsert_hotlink_config(&self, req: UpsertHotlinkConfig) -> Result<HotlinkConfig, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let domains = serde_json::to_value(req.allowed_domains.unwrap_or_default())
            .unwrap_or_else(|_| serde_json::Value::Array(vec![]));
        let row = sqlx::query_as::<_, HotlinkConfig>(
            r"INSERT INTO hotlink_configs (id, host_code, enabled, allow_empty_referer, allowed_domains, redirect_url, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
               ON CONFLICT (host_code) DO UPDATE SET
                 enabled=EXCLUDED.enabled, allow_empty_referer=EXCLUDED.allow_empty_referer,
                 allowed_domains=EXCLUDED.allowed_domains, redirect_url=EXCLUDED.redirect_url,
                 updated_at=NOW()
               RETURNING *"
        )
        .bind(id).bind(&req.host_code).bind(req.enabled.unwrap_or(true))
        .bind(req.allow_empty_referer.unwrap_or(true))
        .bind(domains).bind(&req.redirect_url).bind(now)
        .fetch_one(&self.pool).await?;
        Ok(row)
    }

    // ─── LB Backends ─────────────────────────────────────────────────────────

    pub async fn list_lb_backends(&self, host_code: Option<&str>) -> Result<Vec<LbBackend>, StorageError> {
        let rows = match host_code {
            Some(code) => {
                sqlx::query_as::<_, LbBackend>(
                    "SELECT * FROM lb_backends WHERE host_code = $1 ORDER BY weight DESC, created_at",
                )
                .bind(code)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, LbBackend>("SELECT * FROM lb_backends ORDER BY created_at")
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(rows)
    }

    pub async fn create_lb_backend(&self, req: CreateLbBackend) -> Result<LbBackend, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = sqlx::query_as::<_, LbBackend>(
            r"INSERT INTO lb_backends
               (id, host_code, backend_host, backend_port, weight, enabled, health_check_url, health_check_interval_secs, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9) RETURNING *"
        )
        .bind(id).bind(&req.host_code).bind(&req.backend_host).bind(req.backend_port)
        .bind(req.weight.unwrap_or(1)).bind(req.enabled.unwrap_or(true))
        .bind(&req.health_check_url)
        .bind(req.health_check_interval_secs.unwrap_or(30))
        .bind(now)
        .fetch_one(&self.pool).await?;
        Ok(row)
    }

    pub async fn delete_lb_backend(&self, id: Uuid) -> Result<bool, StorageError> {
        let r = sqlx::query("DELETE FROM lb_backends WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn update_lb_backend_health(&self, id: Uuid, is_healthy: bool) -> Result<(), StorageError> {
        sqlx::query("UPDATE lb_backends SET is_healthy=$2, last_health_check=NOW(), updated_at=NOW() WHERE id=$1")
            .bind(id)
            .bind(is_healthy)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ─── Phase 4: Admin Users ─────────────────────────────────────────────────

    pub async fn list_admin_users(&self) -> Result<Vec<AdminUser>, StorageError> {
        Ok(
            sqlx::query_as::<_, AdminUser>("SELECT * FROM admin_users ORDER BY created_at")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn get_admin_user_by_id(&self, id: Uuid) -> Result<Option<AdminUser>, StorageError> {
        Ok(
            sqlx::query_as::<_, AdminUser>("SELECT * FROM admin_users WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn get_admin_user_by_username(&self, username: &str) -> Result<Option<AdminUser>, StorageError> {
        Ok(
            sqlx::query_as::<_, AdminUser>("SELECT * FROM admin_users WHERE username = $1")
                .bind(username)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn create_admin_user(
        &self,
        req: CreateAdminUser,
        password_hash: &str,
    ) -> Result<AdminUser, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        Ok(sqlx::query_as::<_, AdminUser>(
            r"INSERT INTO admin_users
               (id, username, email, password_hash, role, is_active, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,true,$6,$6) RETURNING *",
        )
        .bind(id)
        .bind(&req.username)
        .bind(&req.email)
        .bind(password_hash)
        .bind(req.role.as_deref().unwrap_or("admin"))
        .bind(now)
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn update_admin_user_last_login(&self, id: Uuid) -> Result<(), StorageError> {
        sqlx::query("UPDATE admin_users SET last_login = NOW(), updated_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn admin_users_count(&self) -> Result<i64, StorageError> {
        Ok(sqlx::query_scalar("SELECT COUNT(*) FROM admin_users")
            .fetch_one(&self.pool)
            .await?)
    }

    // ─── Phase 4: Refresh Tokens ──────────────────────────────────────────────

    pub async fn create_refresh_token(
        &self,
        user_id: Uuid,
        token_hash: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<RefreshToken, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        Ok(sqlx::query_as::<_, RefreshToken>(
            r"INSERT INTO refresh_tokens
               (id, user_id, token_hash, expires_at, revoked, created_at)
               VALUES ($1,$2,$3,$4,false,$5) RETURNING *",
        )
        .bind(id)
        .bind(user_id)
        .bind(token_hash)
        .bind(expires_at)
        .bind(now)
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn get_refresh_token_by_hash(&self, token_hash: &str) -> Result<Option<RefreshToken>, StorageError> {
        Ok(sqlx::query_as::<_, RefreshToken>(
            "SELECT * FROM refresh_tokens WHERE token_hash = $1 AND revoked = false AND expires_at > NOW()",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn revoke_refresh_token(&self, token_hash: &str) -> Result<(), StorageError> {
        sqlx::query("UPDATE refresh_tokens SET revoked = true WHERE token_hash = $1")
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn revoke_all_user_tokens(&self, user_id: Uuid) -> Result<(), StorageError> {
        sqlx::query("UPDATE refresh_tokens SET revoked = true WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ─── Phase 4: Statistics ──────────────────────────────────────────────────

    /// Returns aggregated WAF statistics for the dashboard.
    ///
    /// `filter` is fully optional: `StatsFilter::default()` (all `None`) produces
    /// byte-equivalent output to the pre-filter implementation — guaranteed
    /// backward compatibility.
    ///
    /// Per-subquery filter matrix (see phase-02 spec §Step 4):
    /// - Subqueries #1,#2 (`total_blocked_*`): hours + `host_code`. Row action
    ///   is always `'block'`; the optional action filter only acts as a gate —
    ///   when user passes `action=X` and `X != 'block'`, the count returns 0
    ///   (asking for non-block traffic ⇒ 0 blocked by definition).
    /// - Subquery  #3 (`total_allowed`):      hours + `host_code`. Same gate
    ///   semantics: row action is always `'allow'`; non-allow filter ⇒ 0.
    /// - Subquery  #4 (`hosts_count`):         NO filters (`hosts` has neither
    ///   `created_at` nor `host_code` nor `action` columns applicable here).
    /// - Subqueries #5-#9:                     hours + `host_code` + action.
    /// - Subquery  #10 (`category_breakdown`): hours + `host_code` + action;
    ///   inline CASE replaced by `category_of(rule_id)`.
    /// - Subquery  #11 (`action_breakdown`):   hours + `host_code` ONLY (applying
    ///   action filter here would always return 1 row, defeating the chart).
    /// - Subquery  #12 (`recent_events`):      hours + `host_code` + action;
    ///   inline CASE replaced by `category_of(rule_id)`.
    pub async fn get_stats_overview(&self, filter: &StatsFilter) -> Result<StatsOverview, StorageError> {
        // Bind helpers — computed once, reused across subqueries.
        // hours_bind: Option<i32> so $N::int IS NULL check is a no-op when None.
        let hours_bind = filter.hours.map(|h| i32::try_from(h).unwrap_or(i32::MAX));
        let host_bind = filter.host_code.as_deref();
        let action_bind = filter.action.as_deref();

        // ── Subquery #1: total blocked via attack_logs ────────────────────────
        // Row action is hardcoded 'block'. The optional $3 acts as a GATE: when
        // user filters by an action that isn't 'block', return 0 (preserves
        // the semantic meaning of `total_blocked`).
        let total_blocked_logs: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM attack_logs \
             WHERE action = 'block' \
               AND ($3::text IS NULL OR $3 = 'block') \
               AND ($1::int IS NULL OR created_at >= NOW() - make_interval(hours => $1)) \
               AND ($2::text IS NULL OR host_code = $2)",
        )
        .bind(hours_bind)
        .bind(host_bind)
        .bind(action_bind)
        .fetch_one(&self.pool)
        .await?;

        // ── Subquery #2: total blocked via security_events ────────────────────
        let total_blocked_events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM security_events \
             WHERE action = 'block' \
               AND ($3::text IS NULL OR $3 = 'block') \
               AND ($1::int IS NULL OR created_at >= NOW() - make_interval(hours => $1)) \
               AND ($2::text IS NULL OR host_code = $2)",
        )
        .bind(hours_bind)
        .bind(host_bind)
        .bind(action_bind)
        .fetch_one(&self.pool)
        .await?;

        let total_blocked = total_blocked_logs + total_blocked_events;

        // ── Subquery #3: total allowed via attack_logs ────────────────────────
        // Same gate semantics as #1/#2: row action is 'allow', non-allow filter ⇒ 0.
        let total_allowed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM attack_logs \
             WHERE action = 'allow' \
               AND ($3::text IS NULL OR $3 = 'allow') \
               AND ($1::int IS NULL OR created_at >= NOW() - make_interval(hours => $1)) \
               AND ($2::text IS NULL OR host_code = $2)",
        )
        .bind(hours_bind)
        .bind(host_bind)
        .bind(action_bind)
        .fetch_one(&self.pool)
        .await?;

        let total_requests = total_blocked + total_allowed;

        // ── Subquery #4: hosts count — no filters apply ───────────────────────
        let hosts_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM hosts")
            .fetch_one(&self.pool)
            .await?;

        // ── Subquery #5: top attacking IPs ────────────────────────────────────
        let top_ips: Vec<TopEntry> = sqlx::query(
            "SELECT client_ip AS entry_key, COUNT(*)::bigint AS cnt \
             FROM security_events \
             WHERE ($1::int IS NULL OR created_at >= NOW() - make_interval(hours => $1)) \
               AND ($2::text IS NULL OR host_code = $2) \
               AND ($3::text IS NULL OR action    = $3) \
             GROUP BY client_ip \
             ORDER BY cnt DESC \
             LIMIT 10",
        )
        .bind(hours_bind)
        .bind(host_bind)
        .bind(action_bind)
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            TopEntry {
                key: row.get("entry_key"),
                count: row.get("cnt"),
            }
        })
        .fetch_all(&self.pool)
        .await?;

        // ── Subquery #6: top triggered rules ─────────────────────────────────
        let top_rules: Vec<TopEntry> = sqlx::query(
            "SELECT rule_name AS entry_key, COUNT(*)::bigint AS cnt \
             FROM security_events \
             WHERE ($1::int IS NULL OR created_at >= NOW() - make_interval(hours => $1)) \
               AND ($2::text IS NULL OR host_code = $2) \
               AND ($3::text IS NULL OR action    = $3) \
             GROUP BY rule_name \
             ORDER BY cnt DESC \
             LIMIT 10",
        )
        .bind(hours_bind)
        .bind(host_bind)
        .bind(action_bind)
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            TopEntry {
                key: row.get("entry_key"),
                count: row.get("cnt"),
            }
        })
        .fetch_all(&self.pool)
        .await?;

        // ── Subquery #7: top attacking countries ──────────────────────────────
        let top_countries: Vec<TopEntry> = sqlx::query(
            "SELECT geo_info->>'country' AS entry_key, COUNT(*)::bigint AS cnt \
             FROM security_events \
             WHERE geo_info->>'country' IS NOT NULL AND geo_info->>'country' != '' \
               AND ($1::int IS NULL OR created_at >= NOW() - make_interval(hours => $1)) \
               AND ($2::text IS NULL OR host_code = $2) \
               AND ($3::text IS NULL OR action    = $3) \
             GROUP BY entry_key \
             ORDER BY cnt DESC \
             LIMIT 10",
        )
        .bind(hours_bind)
        .bind(host_bind)
        .bind(action_bind)
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            TopEntry {
                key: row.get("entry_key"),
                count: row.get("cnt"),
            }
        })
        .fetch_all(&self.pool)
        .await?;

        // ── Subquery #8: top ISPs ─────────────────────────────────────────────
        let top_isp_list: Vec<TopEntry> = sqlx::query(
            "SELECT geo_info->>'isp' AS entry_key, COUNT(*)::bigint AS cnt \
             FROM security_events \
             WHERE geo_info->>'isp' IS NOT NULL AND geo_info->>'isp' != '' \
               AND ($1::int IS NULL OR created_at >= NOW() - make_interval(hours => $1)) \
               AND ($2::text IS NULL OR host_code = $2) \
               AND ($3::text IS NULL OR action    = $3) \
             GROUP BY entry_key \
             ORDER BY cnt DESC \
             LIMIT 10",
        )
        .bind(hours_bind)
        .bind(host_bind)
        .bind(action_bind)
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            TopEntry {
                key: row.get("entry_key"),
                count: row.get("cnt"),
            }
        })
        .fetch_all(&self.pool)
        .await?;

        // ── Subquery #9: distinct attackers ───────────────────────────────────
        let unique_attackers: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT client_ip)::bigint FROM security_events \
             WHERE ($1::int IS NULL OR created_at >= NOW() - make_interval(hours => $1)) \
               AND ($2::text IS NULL OR host_code = $2) \
               AND ($3::text IS NULL OR action    = $3)",
        )
        .bind(hours_bind)
        .bind(host_bind)
        .bind(action_bind)
        .fetch_one(&self.pool)
        .await
        .unwrap_or(0);

        // ── Subquery #10: category breakdown ─────────────────────────────────
        // Inline CASE replaced by category_of(rule_id) (DRY refactor).
        // Covers built-in checker prefixes (SQLI-, XSS-, …) and YAML rule
        // prefixes (CRS-, ADV-, API-, MODSEC-, CVE-, GEO-, CUSTOM-) via the
        // category_of() Postgres function defined in 0011_category_function.sql.
        let category_breakdown: Vec<TopEntry> = sqlx::query(
            "SELECT category_of(rule_id) AS entry_key, COUNT(*)::bigint AS cnt \
             FROM security_events \
             WHERE rule_id IS NOT NULL \
               AND ($1::int IS NULL OR created_at >= NOW() - make_interval(hours => $1)) \
               AND ($2::text IS NULL OR host_code = $2) \
               AND ($3::text IS NULL OR action    = $3) \
             GROUP BY category_of(rule_id) \
             ORDER BY cnt DESC \
             LIMIT 20",
        )
        .bind(hours_bind)
        .bind(host_bind)
        .bind(action_bind)
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            TopEntry {
                key: row.get("entry_key"),
                count: row.get("cnt"),
            }
        })
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        // ── Subquery #11: action breakdown ────────────────────────────────────
        // action filter intentionally NOT applied here: the purpose of this
        // subquery IS to show the mix of all actions. Applying action=$3 would
        // collapse the chart to a single bar. hours + host_code filters apply.
        let mut action_breakdown: Vec<TopEntry> = sqlx::query(
            "SELECT action AS entry_key, COUNT(*)::bigint AS cnt \
             FROM security_events \
             WHERE ($1::int IS NULL OR created_at >= NOW() - make_interval(hours => $1)) \
               AND ($2::text IS NULL OR host_code = $2) \
             GROUP BY action \
             ORDER BY cnt DESC",
        )
        .bind(hours_bind)
        .bind(host_bind)
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            TopEntry {
                key: row.get("entry_key"),
                count: row.get("cnt"),
            }
        })
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        // PATCH 3: if HONEY-prefixed events exist but action is stored as 'block',
        // inject a synthetic 'honeypot' entry so the frontend can distinguish them.
        if !action_breakdown.iter().any(|e| e.key == "honeypot") {
            let honeypot_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*)::bigint FROM security_events \
                 WHERE rule_id ILIKE 'HONEY%' \
                   AND ($1::int IS NULL OR created_at >= NOW() - make_interval(hours => $1)) \
                   AND ($2::text IS NULL OR host_code = $2)",
            )
            .bind(hours_bind)
            .bind(host_bind)
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);

            if honeypot_count > 0 {
                action_breakdown.push(TopEntry {
                    key: "honeypot".to_string(),
                    count: honeypot_count,
                });
            }
        }

        // ── Subquery #12: recent events activity feed ─────────────────────────
        // Inline CASE replaced by category_of(rule_id) (DRY refactor).
        let recent_events: Vec<RecentEvent> = sqlx::query(
            "SELECT \
                created_at AS ts, \
                client_ip, \
                host_code, \
                method, \
                path, \
                rule_id, \
                rule_name, \
                action, \
                COALESCE(geo_info->>'country', '') AS country, \
                category_of(rule_id) AS category \
             FROM security_events \
             WHERE ($1::int IS NULL OR created_at >= NOW() - make_interval(hours => $1)) \
               AND ($2::text IS NULL OR host_code = $2) \
               AND ($3::text IS NULL OR action    = $3) \
             ORDER BY created_at DESC \
             LIMIT 20",
        )
        .bind(hours_bind)
        .bind(host_bind)
        .bind(action_bind)
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            let country_str: String = row.get("country");
            RecentEvent {
                ts: row.get("ts"),
                client_ip: row.get("client_ip"),
                host_code: row.get("host_code"),
                method: row.get("method"),
                path: row.get("path"),
                rule_id: row.get("rule_id"),
                rule_name: row.get("rule_name"),
                action: row.get("action"),
                category: row.get("category"),
                country: if country_str.is_empty() {
                    None
                } else {
                    Some(country_str)
                },
            }
        })
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        Ok(StatsOverview {
            total_requests,
            total_blocked,
            total_allowed,
            hosts_count,
            top_ips,
            top_rules,
            top_countries,
            top_isps: top_isp_list,
            unique_attackers,
            category_breakdown,
            action_breakdown,
            recent_events,
        })
    }

    pub async fn get_stats_timeseries(
        &self,
        host_code: Option<&str>,
        hours: i64,
    ) -> Result<Vec<TimeSeriesPoint>, StorageError> {
        let rows: Vec<TimeSeriesPoint> = sqlx::query(
            "SELECT \
                date_trunc('hour', created_at) AS ts, \
                COUNT(*)::bigint AS total, \
                COUNT(*) FILTER (WHERE action = 'block')::bigint AS blocked \
             FROM security_events \
             WHERE created_at >= NOW() - make_interval(hours => $1::int) \
               AND ($2::text IS NULL OR host_code = $2) \
             GROUP BY date_trunc('hour', created_at) \
             ORDER BY ts ASC",
        )
        .bind(i32::try_from(hours).unwrap_or(i32::MAX))
        .bind(host_code)
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            TimeSeriesPoint {
                ts: row.get("ts"),
                total: row.get("total"),
                blocked: row.get("blocked"),
            }
        })
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    /// Return per-category hourly bucket counts for the last `hours` hours.
    ///
    /// The CASE expression mirrors the one in `get_stats_overview` — keep both
    /// in sync when adding a new `rule_id` prefix.
    pub async fn get_stats_timeseries_by_category(
        &self,
        host_code: Option<&str>,
        hours: i64,
    ) -> Result<Vec<CategoryTimeSeriesPoint>, StorageError> {
        let rows: Vec<CategoryTimeSeriesPoint> = sqlx::query(
            "SELECT \
                date_trunc('hour', created_at) AS ts, \
                CASE \
                    WHEN rule_id LIKE 'SQLI-%'        THEN 'sqli' \
                    WHEN rule_id LIKE 'XSS-%'         THEN 'xss' \
                    WHEN rule_id LIKE 'RCE-%'         THEN 'rce' \
                    WHEN rule_id LIKE 'TRAV-%'        THEN 'path-traversal' \
                    WHEN rule_id LIKE 'SCAN-%'        THEN 'scanner' \
                    WHEN rule_id LIKE 'BOT-%'         THEN 'bot' \
                    WHEN rule_id LIKE 'CC-%'          THEN 'cc-ddos' \
                    WHEN rule_id LIKE 'SSRF-%'        THEN 'ssrf' \
                    WHEN rule_id LIKE 'ADV-SSRF%'     THEN 'ssrf' \
                    WHEN rule_id LIKE 'ADV-SSTI%'     THEN 'ssti' \
                    WHEN rule_id LIKE 'ADV-%'         THEN 'advanced' \
                    WHEN rule_id LIKE 'CRS-RESP%'     THEN 'data-leakage' \
                    WHEN rule_id LIKE 'CRS-%'         THEN 'owasp-crs' \
                    WHEN rule_id LIKE 'API-MASS%'     THEN 'mass-assignment' \
                    WHEN rule_id LIKE 'API-%'         THEN 'api-security' \
                    WHEN rule_id LIKE 'MODSEC-RESP%'  THEN 'web-shell' \
                    WHEN rule_id LIKE 'MODSEC-%'      THEN 'modsecurity' \
                    WHEN rule_id LIKE 'CVE-%'         THEN 'cve' \
                    WHEN rule_id LIKE 'GEO-%'         THEN 'geo-blocking' \
                    WHEN rule_id LIKE 'CUSTOM-%'      THEN 'custom' \
                    WHEN rule_id LIKE 'IP-%'          THEN 'ip-rule' \
                    WHEN rule_id LIKE 'URL-%'         THEN 'url-rule' \
                    WHEN rule_id LIKE 'SENS-%'        THEN 'sensitive-data' \
                    WHEN rule_id LIKE 'HOTLINK-%'     THEN 'anti-hotlink' \
                    WHEN rule_id LIKE 'OWASP-942%'    THEN 'sqli' \
                    WHEN rule_id LIKE 'OWASP-941%'    THEN 'xss' \
                    WHEN rule_id LIKE 'OWASP-930%'    THEN 'lfi' \
                    WHEN rule_id LIKE 'OWASP-931%'    THEN 'rfi' \
                    WHEN rule_id LIKE 'OWASP-932%'    THEN 'rce' \
                    WHEN rule_id LIKE 'OWASP-933%'    THEN 'php-injection' \
                    WHEN rule_id LIKE 'OWASP-913%'    THEN 'scanner' \
                    ELSE 'other' \
                END AS category, \
                COUNT(*)::bigint AS cnt \
             FROM security_events \
             WHERE created_at >= NOW() - make_interval(hours => $1::int) \
               AND ($2::text IS NULL OR host_code = $2) \
               AND rule_id IS NOT NULL \
             GROUP BY date_trunc('hour', created_at), category \
             ORDER BY ts ASC, category ASC",
        )
        .bind(i32::try_from(hours).unwrap_or(i32::MAX))
        .bind(host_code)
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            CategoryTimeSeriesPoint {
                ts: row.get("ts"),
                category: row.get("category"),
                count: row.get("cnt"),
            }
        })
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    pub async fn get_geo_stats(&self) -> Result<GeoStats, StorageError> {
        // Top 20 countries by security event count
        let top_countries: Vec<TopEntry> = sqlx::query(
            "SELECT geo_info->>'country' AS entry_key, COUNT(*)::bigint AS cnt \
             FROM security_events \
             WHERE geo_info->>'country' IS NOT NULL AND geo_info->>'country' != '' \
             GROUP BY entry_key \
             ORDER BY cnt DESC \
             LIMIT 20",
        )
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            TopEntry {
                key: row.get("entry_key"),
                count: row.get("cnt"),
            }
        })
        .fetch_all(&self.pool)
        .await?;

        // Top 20 cities
        let top_cities: Vec<TopEntry> = sqlx::query(
            "SELECT geo_info->>'city' AS entry_key, COUNT(*)::bigint AS cnt \
             FROM security_events \
             WHERE geo_info->>'city' IS NOT NULL AND geo_info->>'city' != '' \
             GROUP BY entry_key \
             ORDER BY cnt DESC \
             LIMIT 20",
        )
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            TopEntry {
                key: row.get("entry_key"),
                count: row.get("cnt"),
            }
        })
        .fetch_all(&self.pool)
        .await?;

        // Top 20 ISPs
        let top_isps: Vec<TopEntry> = sqlx::query(
            "SELECT geo_info->>'isp' AS entry_key, COUNT(*)::bigint AS cnt \
             FROM security_events \
             WHERE geo_info->>'isp' IS NOT NULL AND geo_info->>'isp' != '' \
             GROUP BY entry_key \
             ORDER BY cnt DESC \
             LIMIT 20",
        )
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            TopEntry {
                key: row.get("entry_key"),
                count: row.get("cnt"),
            }
        })
        .fetch_all(&self.pool)
        .await?;

        // Country distribution with iso_code (for world map visualization)
        let country_distribution: Vec<GeoDistEntry> = sqlx::query(
            "SELECT \
                COALESCE(geo_info->>'iso_code', '') AS iso_code, \
                geo_info->>'country' AS country, \
                COUNT(*)::bigint AS cnt \
             FROM security_events \
             WHERE geo_info->>'country' IS NOT NULL AND geo_info->>'country' != '' \
             GROUP BY iso_code, country \
             ORDER BY cnt DESC \
             LIMIT 200",
        )
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            GeoDistEntry {
                iso_code: row.get("iso_code"),
                country: row.get("country"),
                count: row.get("cnt"),
            }
        })
        .fetch_all(&self.pool)
        .await?;

        Ok(GeoStats {
            top_countries,
            top_cities,
            top_isps,
            country_distribution,
        })
    }

    /// Returns a sparse path × category heatmap for the endpoint attack view.
    ///
    /// Three-stage CTE:
    ///   `path_ranks`   — top 20 paths by event count in the window.
    ///   `category_top` — top 12 categories in the window.
    ///   final SELECT   — pivot restricted to top paths; categories outside the
    ///                    top-12 list are rolled into `'other'` (F3 compliance).
    ///
    /// `total_events` in the returned struct equals `cells.iter().map(|c| c.count).sum()`
    /// (computed client-side from the returned cells — no extra COUNT(*) query).
    pub async fn get_endpoint_heatmap(&self, filter: &HeatmapFilter) -> Result<EndpointHeatmap, StorageError> {
        use sqlx::Row;

        // Clamp hours to i32 for make_interval; caller already enforces 1..=720
        // but we defend in depth.
        let hours_i32 = i32::try_from(filter.hours).unwrap_or(i32::MAX);
        let host = filter.host_code.as_deref();
        let action = filter.action.as_deref();

        // Filter rows FIRST in a derived table, THEN compute category_of in
        // its projection. WHERE evaluates before SELECT, so category_of runs
        // only on rows that survive the predicates (rule_id IS NOT NULL,
        // window, host/action filters, top-paths set). Avoids the wasted
        // per-row compute of the previous CROSS JOIN LATERAL form, which
        // evaluated the function before the WHERE clause excluded null rows.
        //
        // GROUP BY / ORDER BY use SELECT positions (1, 2, 3) — fully
        // unambiguous between column aliases and underlying table columns.
        let rows = sqlx::query(
            r"
            WITH path_ranks AS (
              SELECT LEFT(path, 256) AS path, COUNT(*)::bigint AS total_events
              FROM security_events
              WHERE created_at >= NOW() - make_interval(hours => $1::int)
                AND ($2::text IS NULL OR host_code = $2)
                AND ($3::text IS NULL OR action    = $3)
              GROUP BY LEFT(path, 256)
              ORDER BY total_events DESC
              LIMIT 20
            ),
            category_top AS (
              SELECT category_of(rule_id) AS category, COUNT(*)::bigint AS total
              FROM security_events
              WHERE created_at >= NOW() - make_interval(hours => $1::int)
                AND ($2::text IS NULL OR host_code = $2)
                AND ($3::text IS NULL OR action    = $3)
                AND rule_id IS NOT NULL
              GROUP BY category_of(rule_id)
              ORDER BY total DESC
              LIMIT 12
            ),
            scoped AS (
              SELECT LEFT(path, 256) AS path, category_of(rule_id) AS cat
              FROM security_events
              WHERE created_at >= NOW() - make_interval(hours => $1::int)
                AND ($2::text IS NULL OR host_code = $2)
                AND ($3::text IS NULL OR action    = $3)
                AND rule_id IS NOT NULL
                AND LEFT(path, 256) IN (SELECT path FROM path_ranks)
            )
            SELECT
              s.path AS path,
              CASE
                WHEN s.cat IN (SELECT category FROM category_top) THEN s.cat
                ELSE 'other'
              END AS category,
              COUNT(*)::bigint AS count
            FROM scoped s
            GROUP BY 1, 2
            ORDER BY 1, 3 DESC
            ",
        )
        .bind(hours_i32)
        .bind(host)
        .bind(action)
        .fetch_all(&self.pool)
        .await?;

        let mut cells: Vec<HeatmapCell> = Vec::with_capacity(rows.len());
        let mut total: i64 = 0;

        for r in rows {
            let path: String = r.try_get("path")?;
            let category: String = r.try_get("category")?;
            let count: i64 = r.try_get("count")?;
            total = total.saturating_add(count);
            cells.push(HeatmapCell { path, category, count });
        }

        // SQL already GROUP BY (path, category) so each pair appears exactly
        // once. Distinct counts derive cheaply from the materialized cells
        // using borrowed string slices — no per-row clone needed.
        let paths_sampled: i64 = cells
            .iter()
            .map(|c| c.path.as_str())
            .collect::<std::collections::HashSet<&str>>()
            .len()
            .try_into()
            .unwrap_or(i64::MAX);
        let categories_total: i64 = cells
            .iter()
            .map(|c| c.category.as_str())
            .collect::<std::collections::HashSet<&str>>()
            .len()
            .try_into()
            .unwrap_or(i64::MAX);

        Ok(EndpointHeatmap {
            cells,
            total_events: total,
            paths_sampled,
            categories_total,
            window_hours: filter.hours,
            generated_at: chrono::Utc::now(),
        })
    }

    pub async fn delete_old_stats(&self, days: i64) -> Result<u64, StorageError> {
        let r = sqlx::query("DELETE FROM request_stats WHERE period_start < NOW() - make_interval(days => $1::int)")
            .bind(i32::try_from(days).unwrap_or(i32::MAX))
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected())
    }

    // ─── Phase 4: Notifications ───────────────────────────────────────────────

    pub async fn list_notification_configs(
        &self,
        host_code: Option<&str>,
    ) -> Result<Vec<NotificationConfig>, StorageError> {
        Ok(match host_code {
            Some(code) => {
                sqlx::query_as::<_, NotificationConfig>(
                    "SELECT * FROM notification_configs WHERE host_code = $1 ORDER BY created_at",
                )
                .bind(code)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, NotificationConfig>("SELECT * FROM notification_configs ORDER BY created_at")
                    .fetch_all(&self.pool)
                    .await?
            }
        })
    }

    pub async fn get_notification_config(&self, id: Uuid) -> Result<Option<NotificationConfig>, StorageError> {
        Ok(
            sqlx::query_as::<_, NotificationConfig>("SELECT * FROM notification_configs WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn create_notification_config(
        &self,
        req: CreateNotificationConfig,
    ) -> Result<NotificationConfig, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        Ok(sqlx::query_as::<_, NotificationConfig>(
            r"INSERT INTO notification_configs
               (id, name, host_code, event_type, channel_type, config_json, enabled, rate_limit_secs, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9) RETURNING *",
        )
        .bind(id)
        .bind(&req.name)
        .bind(&req.host_code)
        .bind(&req.event_type)
        .bind(&req.channel_type)
        .bind(&req.config_json)
        .bind(req.enabled.unwrap_or(true))
        .bind(req.rate_limit_secs.unwrap_or(300))
        .bind(now)
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn delete_notification_config(&self, id: Uuid) -> Result<bool, StorageError> {
        let r = sqlx::query("DELETE FROM notification_configs WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn update_notification_last_triggered(&self, id: Uuid) -> Result<(), StorageError> {
        sqlx::query("UPDATE notification_configs SET last_triggered = NOW(), updated_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn get_enabled_notification_configs(
        &self,
        event_type: &str,
    ) -> Result<Vec<NotificationConfig>, StorageError> {
        Ok(sqlx::query_as::<_, NotificationConfig>(
            "SELECT * FROM notification_configs WHERE event_type = $1 AND enabled = true",
        )
        .bind(event_type)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn create_notification_log(
        &self,
        config_id: Option<Uuid>,
        event_type: &str,
        channel_type: &str,
        status: &str,
        message: Option<&str>,
        error_msg: Option<&str>,
    ) -> Result<(), StorageError> {
        sqlx::query(
            r"INSERT INTO notification_log
               (id, config_id, event_type, channel_type, status, message, error_msg)
               VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6)",
        )
        .bind(config_id)
        .bind(event_type)
        .bind(channel_type)
        .bind(status)
        .bind(message)
        .bind(error_msg)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_notification_log(&self, limit: i64) -> Result<Vec<NotificationLog>, StorageError> {
        Ok(
            sqlx::query_as::<_, NotificationLog>("SELECT * FROM notification_log ORDER BY created_at DESC LIMIT $1")
                .bind(limit)
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn list_security_events(
        &self,
        query: &SecurityEventQuery,
    ) -> Result<(Vec<SecurityEvent>, i64), StorageError> {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(20).clamp(1, 100);
        let offset = (page - 1) * page_size;

        // PATCH 1: pre-format prefix pattern so the SQL check remains a simple equality
        let rule_id_prefix_pattern: Option<String> = query.rule_id_prefix.as_ref().map(|p| format!("{p}%"));

        let total: i64 = sqlx::query_scalar(
            r"SELECT COUNT(*) FROM security_events
               WHERE ($1::text IS NULL OR host_code = $1)
                 AND ($2::text IS NULL OR client_ip = $2)
                 AND ($3::text IS NULL OR rule_name = $3)
                 AND ($4::text IS NULL OR action = $4)
                 AND ($5::text IS NULL OR geo_info->>'iso_code' = $5)
                 AND ($6::text IS NULL OR geo_info->>'country' ILIKE '%' || $6 || '%')
                 AND ($7::text IS NULL OR rule_id = $7)
                 AND ($8::text IS NULL OR path ILIKE '%' || $8 || '%')
                 AND ($9::text IS NULL OR rule_id ILIKE $9)",
        )
        .bind(&query.host_code)
        .bind(&query.client_ip)
        .bind(&query.rule_name)
        .bind(&query.action)
        .bind(&query.iso_code)
        .bind(&query.country)
        .bind(&query.rule_id)
        .bind(&query.path)
        .bind(&rule_id_prefix_pattern)
        .fetch_one(&self.pool)
        .await?;

        let rows = sqlx::query_as::<_, SecurityEvent>(
            r"SELECT * FROM security_events
               WHERE ($1::text IS NULL OR host_code = $1)
                 AND ($2::text IS NULL OR client_ip = $2)
                 AND ($3::text IS NULL OR rule_name = $3)
                 AND ($4::text IS NULL OR action = $4)
                 AND ($5::text IS NULL OR geo_info->>'iso_code' = $5)
                 AND ($6::text IS NULL OR geo_info->>'country' ILIKE '%' || $6 || '%')
                 AND ($7::text IS NULL OR rule_id = $7)
                 AND ($8::text IS NULL OR path ILIKE '%' || $8 || '%')
                 AND ($9::text IS NULL OR rule_id ILIKE $9)
               ORDER BY created_at DESC
               LIMIT $10 OFFSET $11",
        )
        .bind(&query.host_code)
        .bind(&query.client_ip)
        .bind(&query.rule_name)
        .bind(&query.action)
        .bind(&query.iso_code)
        .bind(&query.country)
        .bind(&query.rule_id)
        .bind(&query.path)
        .bind(&rule_id_prefix_pattern)
        .bind(page_size)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok((rows, total))
    }

    pub async fn get_security_event(&self, id: Uuid) -> Result<Option<SecurityEvent>, StorageError> {
        Ok(
            sqlx::query_as::<_, SecurityEvent>("SELECT * FROM security_events WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    // ─── Phase 5: WASM Plugins ────────────────────────────────────────────────

    pub async fn list_wasm_plugins(&self) -> Result<Vec<WasmPluginRow>, StorageError> {
        Ok(
            sqlx::query_as::<_, WasmPluginRow>("SELECT * FROM wasm_plugins ORDER BY created_at DESC")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn get_wasm_plugin(&self, id: Uuid) -> Result<Option<WasmPluginRow>, StorageError> {
        Ok(
            sqlx::query_as::<_, WasmPluginRow>("SELECT * FROM wasm_plugins WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn create_wasm_plugin(&self, req: CreateWasmPlugin) -> Result<WasmPluginRow, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        Ok(sqlx::query_as::<_, WasmPluginRow>(
            r"INSERT INTO wasm_plugins
               (id, name, version, description, author, wasm_binary, enabled, config_json, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9) RETURNING *",
        )
        .bind(id)
        .bind(&req.name)
        .bind(req.version.as_deref().unwrap_or("1.0.0"))
        .bind(&req.description)
        .bind(&req.author)
        .bind(&req.wasm_binary)
        .bind(req.enabled.unwrap_or(true))
        .bind(
            req.config_json
                .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::default())),
        )
        .bind(now)
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn set_wasm_plugin_enabled(&self, id: Uuid, enabled: bool) -> Result<bool, StorageError> {
        let r = sqlx::query("UPDATE wasm_plugins SET enabled=$2, updated_at=NOW() WHERE id=$1")
            .bind(id)
            .bind(enabled)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn delete_wasm_plugin(&self, id: Uuid) -> Result<bool, StorageError> {
        let r = sqlx::query("DELETE FROM wasm_plugins WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    // ─── Phase 5: Tunnels ─────────────────────────────────────────────────────

    pub async fn list_tunnels(&self) -> Result<Vec<TunnelRow>, StorageError> {
        Ok(
            sqlx::query_as::<_, TunnelRow>("SELECT * FROM tunnels ORDER BY created_at DESC")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn get_tunnel(&self, id: Uuid) -> Result<Option<TunnelRow>, StorageError> {
        Ok(sqlx::query_as::<_, TunnelRow>("SELECT * FROM tunnels WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub async fn get_tunnel_by_token_hash(&self, token_hash: &str) -> Result<Option<TunnelRow>, StorageError> {
        Ok(
            sqlx::query_as::<_, TunnelRow>("SELECT * FROM tunnels WHERE token_hash = $1 AND enabled = true")
                .bind(token_hash)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn create_tunnel(&self, req: &CreateTunnel, token_hash: &str) -> Result<TunnelRow, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let protocol = req.protocol.as_deref().unwrap_or("tcp");
        Ok(sqlx::query_as::<_, TunnelRow>(
            r"INSERT INTO tunnels
               (id, name, token_hash, target_host, target_port, enabled, status, protocol, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,'disconnected',$7,$8,$8) RETURNING *",
        )
        .bind(id)
        .bind(&req.name)
        .bind(token_hash)
        .bind(&req.target_host)
        .bind(req.target_port)
        .bind(req.enabled.unwrap_or(true))
        .bind(protocol)
        .bind(now)
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn delete_tunnel(&self, id: Uuid) -> Result<bool, StorageError> {
        let r = sqlx::query("DELETE FROM tunnels WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn update_tunnel_status(&self, id: Uuid, status: &str) -> Result<(), StorageError> {
        let last_seen: Option<chrono::DateTime<chrono::Utc>> = if status == "connected" {
            Some(chrono::Utc::now())
        } else {
            None
        };
        sqlx::query("UPDATE tunnels SET status=$2, last_seen=COALESCE($3, last_seen), updated_at=NOW() WHERE id=$1")
            .bind(id)
            .bind(status)
            .bind(last_seen)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ─── Phase 5: Audit Log ───────────────────────────────────────────────────

    pub async fn create_audit_log(
        &self,
        admin_username: Option<&str>,
        action: &str,
        resource_type: Option<&str>,
        resource_id: Option<&str>,
        detail: Option<serde_json::Value>,
        ip_addr: Option<&str>,
    ) -> Result<(), StorageError> {
        sqlx::query(
            r"INSERT INTO audit_log
               (admin_username, action, resource_type, resource_id, detail, ip_addr)
               VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(admin_username)
        .bind(action)
        .bind(resource_type)
        .bind(resource_id)
        .bind(detail)
        .bind(ip_addr)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_audit_log(&self, query: &AuditLogQuery) -> Result<(Vec<AuditLogEntry>, i64), StorageError> {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(50).clamp(1, 200);
        let offset = (page - 1) * page_size;

        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log
             WHERE ($1::text IS NULL OR admin_username = $1)
               AND ($2::text IS NULL OR action = $2)",
        )
        .bind(&query.admin_username)
        .bind(&query.action)
        .fetch_one(&self.pool)
        .await?;

        let rows = sqlx::query_as::<_, AuditLogEntry>(
            "SELECT * FROM audit_log
             WHERE ($1::text IS NULL OR admin_username = $1)
               AND ($2::text IS NULL OR action = $2)
             ORDER BY created_at DESC
             LIMIT $3 OFFSET $4",
        )
        .bind(&query.admin_username)
        .bind(&query.action)
        .bind(page_size)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok((rows, total))
    }

    // ─── Phase 6: CrowdSec ───────────────────────────────────────────────────

    pub async fn get_crowdsec_config(&self) -> Result<Option<CrowdSecConfigRow>, StorageError> {
        Ok(
            sqlx::query_as::<_, CrowdSecConfigRow>("SELECT * FROM crowdsec_config ORDER BY id LIMIT 1")
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn upsert_crowdsec_config(
        &self,
        req: &UpsertCrowdSecConfig,
        api_key_enc: Option<String>,
        appsec_key_enc: Option<String>,
    ) -> Result<CrowdSecConfigRow, StorageError> {
        let now = chrono::Utc::now();
        let freq = req.update_frequency_secs.unwrap_or(10);
        let fallback = req.fallback_action.clone().unwrap_or_else(|| "allow".to_string());

        let row = sqlx::query_as::<_, CrowdSecConfigRow>(
            r"INSERT INTO crowdsec_config
               (host_id, enabled, mode, lapi_url, api_key_encrypted,
                appsec_endpoint, appsec_key_encrypted,
                update_frequency_secs, fallback_action, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
               ON CONFLICT (id) DO UPDATE SET
                 enabled = EXCLUDED.enabled,
                 mode = EXCLUDED.mode,
                 lapi_url = EXCLUDED.lapi_url,
                 api_key_encrypted = COALESCE(EXCLUDED.api_key_encrypted, crowdsec_config.api_key_encrypted),
                 appsec_endpoint = EXCLUDED.appsec_endpoint,
                 appsec_key_encrypted = COALESCE(EXCLUDED.appsec_key_encrypted, crowdsec_config.appsec_key_encrypted),
                 update_frequency_secs = EXCLUDED.update_frequency_secs,
                 fallback_action = EXCLUDED.fallback_action,
                 updated_at = EXCLUDED.updated_at
               RETURNING *",
        )
        .bind(req.host_id)
        .bind(req.enabled)
        .bind(&req.mode)
        .bind(&req.lapi_url)
        .bind(&api_key_enc)
        .bind(&req.appsec_endpoint)
        .bind(&appsec_key_enc)
        .bind(freq)
        .bind(&fallback)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn log_crowdsec_event(&self, req: &CreateCrowdSecEvent) -> Result<(), StorageError> {
        sqlx::query(
            r"INSERT INTO crowdsec_events
               (host_id, client_ip, decision_type, scenario, action_taken, request_path)
               VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(req.host_id)
        .bind(&req.client_ip)
        .bind(&req.decision_type)
        .bind(&req.scenario)
        .bind(&req.action_taken)
        .bind(&req.request_path)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_crowdsec_events(
        &self,
        query: &CrowdSecEventQuery,
    ) -> Result<(Vec<CrowdSecEventRow>, i64), StorageError> {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(50).clamp(1, 200);
        let offset = (page - 1) * page_size;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM crowdsec_events")
            .fetch_one(&self.pool)
            .await?;

        let rows = sqlx::query_as::<_, CrowdSecEventRow>(
            "SELECT * FROM crowdsec_events ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(page_size)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok((rows, total))
    }
}
