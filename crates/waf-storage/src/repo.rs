use uuid::Uuid;
use tracing::debug;

use crate::db::Database;
use crate::error::StorageError;
use crate::models::*;

impl Database {
    // ─── Hosts ───────────────────────────────────────────────────────────────

    pub async fn list_hosts(&self) -> Result<Vec<Host>, StorageError> {
        let rows = sqlx::query_as::<_, Host>(
            "SELECT * FROM hosts ORDER BY created_at DESC"
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn get_host(&self, id: Uuid) -> Result<Option<Host>, StorageError> {
        let row = sqlx::query_as::<_, Host>(
            "SELECT * FROM hosts WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get_host_by_code(&self, code: &str) -> Result<Option<Host>, StorageError> {
        let row = sqlx::query_as::<_, Host>(
            "SELECT * FROM hosts WHERE code = $1"
        )
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
            r#"INSERT INTO hosts (
                id, code, host, port, ssl, guard_status,
                remote_host, remote_port, remote_ip, cert_file, key_file,
                remarks, start_status, log_only_mode,
                is_enable_load_balance, load_balance_stage,
                created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6,
                $7, $8, $9, $10, $11,
                $12, $13, $14,
                false, 0,
                $15, $15
            ) RETURNING *"#
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
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        debug!("Created host: {} (code={})", req.host, code);
        Ok(row)
    }

    pub async fn update_host(&self, id: Uuid, req: UpdateHost) -> Result<Option<Host>, StorageError> {
        let now = chrono::Utc::now();

        let row = sqlx::query_as::<_, Host>(
            r#"UPDATE hosts SET
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
                updated_at = $14
            WHERE id = $1
            RETURNING *"#
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
        .bind(now)
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
            Some(code) => sqlx::query_as::<_, AllowIp>(
                "SELECT * FROM allow_ips WHERE host_code = $1 ORDER BY created_at DESC"
            )
            .bind(code)
            .fetch_all(&self.pool)
            .await?,
            None => sqlx::query_as::<_, AllowIp>(
                "SELECT * FROM allow_ips ORDER BY created_at DESC"
            )
            .fetch_all(&self.pool)
            .await?,
        };
        Ok(rows)
    }

    pub async fn create_allow_ip(&self, req: CreateIpRule) -> Result<AllowIp, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = sqlx::query_as::<_, AllowIp>(
            r#"INSERT INTO allow_ips (id, host_code, ip_cidr, remarks, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $5)
               RETURNING *"#
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
            Some(code) => sqlx::query_as::<_, BlockIp>(
                "SELECT * FROM block_ips WHERE host_code = $1 ORDER BY created_at DESC"
            )
            .bind(code)
            .fetch_all(&self.pool)
            .await?,
            None => sqlx::query_as::<_, BlockIp>(
                "SELECT * FROM block_ips ORDER BY created_at DESC"
            )
            .fetch_all(&self.pool)
            .await?,
        };
        Ok(rows)
    }

    pub async fn create_block_ip(&self, req: CreateIpRule) -> Result<BlockIp, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = sqlx::query_as::<_, BlockIp>(
            r#"INSERT INTO block_ips (id, host_code, ip_cidr, remarks, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $5)
               RETURNING *"#
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
            Some(code) => sqlx::query_as::<_, AllowUrl>(
                "SELECT * FROM allow_urls WHERE host_code = $1 ORDER BY created_at DESC"
            )
            .bind(code)
            .fetch_all(&self.pool)
            .await?,
            None => sqlx::query_as::<_, AllowUrl>(
                "SELECT * FROM allow_urls ORDER BY created_at DESC"
            )
            .fetch_all(&self.pool)
            .await?,
        };
        Ok(rows)
    }

    pub async fn create_allow_url(&self, req: CreateUrlRule) -> Result<AllowUrl, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = sqlx::query_as::<_, AllowUrl>(
            r#"INSERT INTO allow_urls (id, host_code, url_pattern, match_type, remarks, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $6)
               RETURNING *"#
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
            Some(code) => sqlx::query_as::<_, BlockUrl>(
                "SELECT * FROM block_urls WHERE host_code = $1 ORDER BY created_at DESC"
            )
            .bind(code)
            .fetch_all(&self.pool)
            .await?,
            None => sqlx::query_as::<_, BlockUrl>(
                "SELECT * FROM block_urls ORDER BY created_at DESC"
            )
            .fetch_all(&self.pool)
            .await?,
        };
        Ok(rows)
    }

    pub async fn create_block_url(&self, req: CreateUrlRule) -> Result<BlockUrl, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = sqlx::query_as::<_, BlockUrl>(
            r#"INSERT INTO block_urls (id, host_code, url_pattern, match_type, remarks, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $6)
               RETURNING *"#
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
            r#"INSERT INTO attack_logs (
                id, host_code, host, client_ip, method, path, query,
                rule_id, rule_name, action, phase, detail,
                request_headers, created_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)"#
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
        .bind(log.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_attack_logs(&self, query: &AttackLogQuery) -> Result<(Vec<AttackLog>, i64), StorageError> {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(20).min(100).max(1);
        let offset = (page - 1) * page_size;

        // Count query
        let total: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM attack_logs
               WHERE ($1::text IS NULL OR host_code = $1)
                 AND ($2::text IS NULL OR client_ip = $2)
                 AND ($3::text IS NULL OR action = $3)"#
        )
        .bind(&query.host_code)
        .bind(&query.client_ip)
        .bind(&query.action)
        .fetch_one(&self.pool)
        .await?;

        let rows = sqlx::query_as::<_, AttackLog>(
            r#"SELECT * FROM attack_logs
               WHERE ($1::text IS NULL OR host_code = $1)
                 AND ($2::text IS NULL OR client_ip = $2)
                 AND ($3::text IS NULL OR action = $3)
               ORDER BY created_at DESC
               LIMIT $4 OFFSET $5"#
        )
        .bind(&query.host_code)
        .bind(&query.client_ip)
        .bind(&query.action)
        .bind(page_size)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok((rows, total))
    }
}
