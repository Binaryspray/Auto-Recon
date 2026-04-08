use anyhow::Result;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;

use crate::api::models::{ProgramAttributes, ProgramData, ScopeAttributes, ScopeData};

pub struct Cache {
    pool: SqlitePool,
}

impl Cache {
    pub async fn new(db_path: &str) -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&format!("sqlite:{}?mode=rwc", db_path))
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS programs (
                id TEXT PRIMARY KEY,
                handle TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                offers_bounties INTEGER NOT NULL,
                submission_state TEXT NOT NULL,
                fast_payments INTEGER NOT NULL,
                open_scope INTEGER NOT NULL,
                fetched_at INTEGER NOT NULL DEFAULT (unixepoch())
            )",
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS scopes (
                id TEXT PRIMARY KEY,
                handle TEXT NOT NULL,
                asset_type TEXT NOT NULL,
                asset_identifier TEXT NOT NULL,
                eligible_for_bounty INTEGER NOT NULL,
                eligible_for_submission INTEGER NOT NULL,
                max_severity TEXT,
                instruction TEXT,
                fetched_at INTEGER NOT NULL DEFAULT (unixepoch())
            )",
        )
        .execute(&pool)
        .await?;

        Ok(Self { pool })
    }

    pub async fn upsert_programs(&self, programs: &[ProgramData]) -> Result<()> {
        for p in programs {
            sqlx::query(
                "INSERT INTO programs (id, handle, name, offers_bounties, submission_state, fast_payments, open_scope, fetched_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, unixepoch())
                 ON CONFLICT(id) DO UPDATE SET
                    handle=excluded.handle, name=excluded.name,
                    offers_bounties=excluded.offers_bounties, submission_state=excluded.submission_state,
                    fast_payments=excluded.fast_payments, open_scope=excluded.open_scope,
                    fetched_at=excluded.fetched_at",
            )
            .bind(&p.id)
            .bind(&p.attributes.handle)
            .bind(&p.attributes.name)
            .bind(p.attributes.offers_bounties)
            .bind(&p.attributes.submission_state)
            .bind(p.attributes.fast_payments)
            .bind(p.attributes.open_scope)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    pub async fn upsert_scopes(&self, handle: &str, scopes: &[ScopeData]) -> Result<()> {
        for s in scopes {
            sqlx::query(
                "INSERT INTO scopes (id, handle, asset_type, asset_identifier, eligible_for_bounty, eligible_for_submission, max_severity, instruction, fetched_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, unixepoch())
                 ON CONFLICT(id) DO UPDATE SET
                    handle=excluded.handle, asset_type=excluded.asset_type,
                    asset_identifier=excluded.asset_identifier,
                    eligible_for_bounty=excluded.eligible_for_bounty,
                    eligible_for_submission=excluded.eligible_for_submission,
                    max_severity=excluded.max_severity,
                    instruction=excluded.instruction,
                    fetched_at=excluded.fetched_at",
            )
            .bind(&s.id)
            .bind(handle)
            .bind(&s.attributes.asset_type)
            .bind(&s.attributes.asset_identifier)
            .bind(s.attributes.eligible_for_bounty)
            .bind(s.attributes.eligible_for_submission)
            .bind(&s.attributes.max_severity)
            .bind(&s.attributes.instruction)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    pub async fn is_stale(&self, ttl_secs: u64) -> bool {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT MIN(fetched_at) FROM programs",
        )
        .fetch_optional(&self.pool)
        .await
        .unwrap_or(None);

        match row {
            Some((ts,)) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                (now - ts) > ttl_secs as i64
            }
            None => true,
        }
    }

    pub async fn get_all_programs(&self) -> Result<Vec<ProgramData>> {
        let rows: Vec<(String, String, String, bool, String, bool, bool)> = sqlx::query_as(
            "SELECT id, handle, name, offers_bounties, submission_state, fast_payments, open_scope FROM programs",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(id, handle, name, offers_bounties, submission_state, fast_payments, open_scope)| {
                ProgramData {
                    id,
                    data_type: "program".to_string(),
                    attributes: ProgramAttributes {
                        handle,
                        name,
                        offers_bounties,
                        submission_state,
                        fast_payments,
                        open_scope,
                    },
                }
            })
            .collect())
    }

    pub async fn get_scopes_for(&self, handle: &str) -> Result<Vec<ScopeData>> {
        #[allow(clippy::type_complexity)]
        let rows: Vec<(String, String, String, bool, bool, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT id, asset_type, asset_identifier, eligible_for_bounty, eligible_for_submission, max_severity, instruction FROM scopes WHERE handle = ?1",
        )
        .bind(handle)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(id, asset_type, asset_identifier, eligible_for_bounty, eligible_for_submission, max_severity, instruction)| {
                ScopeData {
                    id,
                    data_type: "structured-scope".to_string(),
                    attributes: ScopeAttributes {
                        asset_type,
                        asset_identifier,
                        eligible_for_bounty,
                        eligible_for_submission,
                        max_severity,
                        instruction,
                    },
                }
            })
            .collect())
    }

    pub async fn set_fetched_at(&self, table: &str, seconds_ago: i64) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ts = now - seconds_ago;
        let query = format!("UPDATE {} SET fetched_at = ?1", table);
        sqlx::query(&query).bind(ts).execute(&self.pool).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_program(id: &str, handle: &str) -> ProgramData {
        ProgramData {
            id: id.to_string(),
            data_type: "program".to_string(),
            attributes: ProgramAttributes {
                handle: handle.to_string(),
                name: handle.to_string(),
                offers_bounties: true,
                submission_state: "open".to_string(),
                fast_payments: true,
                open_scope: false,
            },
        }
    }

    #[tokio::test]
    async fn test_ttl_expired() {
        let cache = Cache::new(":memory:").await.unwrap();
        let programs = vec![make_program("1", "test")];
        cache.upsert_programs(&programs).await.unwrap();
        cache.set_fetched_at("programs", 90000).await.unwrap();
        assert!(cache.is_stale(86400).await);
    }

    #[tokio::test]
    async fn test_ttl_fresh() {
        let cache = Cache::new(":memory:").await.unwrap();
        let programs = vec![make_program("1", "test")];
        cache.upsert_programs(&programs).await.unwrap();
        cache.set_fetched_at("programs", 3600).await.unwrap();
        assert!(!cache.is_stale(86400).await);
    }

    #[tokio::test]
    async fn test_upsert_idempotent() {
        let cache = Cache::new(":memory:").await.unwrap();
        let programs = vec![make_program("1", "test")];
        cache.upsert_programs(&programs).await.unwrap();
        cache.upsert_programs(&programs).await.unwrap();
        let all = cache.get_all_programs().await.unwrap();
        assert_eq!(all.len(), 1);
    }
}
