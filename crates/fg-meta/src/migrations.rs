//! Preserve installed migration history when accepting reviewed byte-only predecessors.

mod fingerprints;

use fingerprints::FINGERPRINTS;
use sqlx::{
    PgConnection, PgPool,
    migrate::{AppliedMigration, Migrate, MigrateError, Migration, Migrator},
};
use std::{future::Future, pin::Pin, time::Duration};

use crate::MetaError;

type MigrationFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, MigrateError>> + Send + 'a>>;

pub(super) async fn run(pool: &PgPool) -> Result<(), MetaError> {
    let migrator = sqlx::migrate!("./migrations");
    let mut connection = pool.acquire().await?;
    // A failed/cancelled SQLx migrator can still hold a session advisory lock.
    // Close this checked-out connection on every outcome; never recycle it.
    connection.close_on_drop();
    let result = migrator
        .run_direct(&mut CompatibleMigrations {
            connection: &mut connection,
            migrator: &migrator,
        })
        .await;
    let closed = connection.close().await;
    result?;
    closed?;
    Ok(())
}

struct CompatibleMigrations<'a> {
    connection: &'a mut PgConnection,
    migrator: &'a Migrator,
}

impl Migrate for CompatibleMigrations<'_> {
    fn ensure_migrations_table(&mut self) -> MigrationFuture<'_, ()> {
        self.connection.ensure_migrations_table()
    }

    fn dirty_version(&mut self) -> MigrationFuture<'_, Option<i64>> {
        self.connection.dirty_version()
    }

    fn list_applied_migrations(&mut self) -> MigrationFuture<'_, Vec<AppliedMigration>> {
        Box::pin(async {
            let mut applied = self.connection.list_applied_migrations().await?;
            for installed in &mut applied {
                if let Some(canonical) = self
                    .migrator
                    .iter()
                    .find(|m| m.version == installed.version)
                    && accepts_predecessor(canonical, installed.checksum.as_ref())
                {
                    installed.checksum = canonical.checksum.clone();
                }
            }
            Ok(applied)
        })
    }

    fn lock(&mut self) -> MigrationFuture<'_, ()> {
        self.connection.lock()
    }

    fn unlock(&mut self) -> MigrationFuture<'_, ()> {
        self.connection.unlock()
    }

    fn apply<'e: 'm, 'm>(&'e mut self, migration: &'m Migration) -> MigrationFuture<'m, Duration> {
        self.connection.apply(migration)
    }

    fn revert<'e: 'm, 'm>(&'e mut self, migration: &'m Migration) -> MigrationFuture<'m, Duration> {
        self.connection.revert(migration)
    }
}

fn accepts_predecessor(canonical: &Migration, installed: &[u8]) -> bool {
    FINGERPRINTS.iter().any(|known| {
        known.version == canonical.version
            && matches_hex(&canonical.checksum, known.canonical)
            && known
                .predecessors
                .iter()
                .any(|old| matches_hex(installed, old))
    })
}

fn matches_hex(checksum: &[u8], expected: &str) -> bool {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    checksum
        .iter()
        .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]])
        .eq(expected.bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn decode(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let mut bytes = Vec::new();
        for pair in value.as_bytes().chunks_exact(2) {
            bytes.push(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?);
        }
        Ok(bytes)
    }

    #[test]
    fn aliases_are_version_bound_and_anchor_exact_canonical_bytes() -> TestResult {
        let migrator = sqlx::migrate!("./migrations");
        assert_eq!(migrator.iter().count(), FINGERPRINTS.len() + 1);
        for migration in migrator.iter() {
            let known = FINGERPRINTS
                .iter()
                .find(|known| known.version == migration.version);
            let Some(known) = known else {
                assert_eq!(migration.version, 20);
                assert!(!accepts_predecessor(migration, &migration.checksum));
                assert!(!accepts_predecessor(migration, &[0; 48]));
                continue;
            };
            assert!(matches_hex(&migration.checksum, known.canonical));
            for old in known.predecessors {
                let old = decode(old)?;
                assert!(accepts_predecessor(migration, &old));
                let mut edited = migration.clone();
                edited.checksum.to_mut()[0] ^= 1;
                assert!(!accepts_predecessor(&edited, &old));
                edited = migration.clone();
                edited.version = i64::MAX;
                assert!(!accepts_predecessor(&edited, &old));
            }
            assert!(!accepts_predecessor(migration, &[0; 48]));
        }
        Ok(())
    }

    async fn ledger(pool: &PgPool) -> Result<Vec<(i64, Vec<u8>)>, sqlx::Error> {
        sqlx::query_as("SELECT version,checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(pool)
            .await
    }

    async fn install_predecessors(pool: &PgPool, encoding: usize, before: i64) -> TestResult {
        let mut connection = pool.acquire().await?;
        connection.ensure_migrations_table().await?;
        for migration in sqlx::migrate!("./migrations")
            .iter()
            .filter(|m| m.version < before)
        {
            connection.apply(migration).await?;
            let known = FINGERPRINTS
                .iter()
                .find(|known| known.version == migration.version);
            let Some(known) = known else {
                assert_eq!(migration.version, 20);
                continue;
            };
            sqlx::query("UPDATE _sqlx_migrations SET checksum=decode($1,'hex') WHERE version=$2")
                .bind(known.predecessors[encoding])
                .bind(migration.version)
                .execute(&mut *connection)
                .await?;
        }
        Ok(())
    }

    async fn legacy_access_upgrade(pool: PgPool, encoding: usize) -> TestResult {
        install_predecessors(&pool, encoding, 14).await?;
        sqlx::raw_sql("INSERT INTO generation(engine,status,snapshot,native_claimed,activated_at)
            VALUES('mongodb','active','v1',true,now());
            INSERT INTO branch(name,class,generation_id,created_by,expires_at,status)
            VALUES('legacy-mongo','dev',1,'upgrade-owner',now()+interval '1 hour','active'),
                ('legacy-stage','staging',1,'upgrade-owner',now()+interval '1 hour','active');
            INSERT INTO policy_version(class,version,max_transaction_rows,table_limit_bps,approval_after_rows)
            VALUES('agent',2,17,500,6);
            INSERT INTO audit_event(actor,branch_id,event_type,payload)
            VALUES('upgrade-owner',1,'upgrade_witness','{\"keep\":true}');")
            .execute(&pool).await?;
        let before = ledger(&pool).await?;
        run(&pool).await?;
        assert_eq!(before, ledger(&pool).await?[..before.len()]);
        let branches: Vec<(i64, String, String, String, String)> =
            sqlx::query_as("SELECT id,name,access,layout,read_strategy FROM branch ORDER BY id")
                .fetch_all(&pool)
                .await?;
        assert_eq!(
            branches,
            vec![
                (
                    1,
                    "legacy-mongo".into(),
                    "read_write".into(),
                    "sparse_delta".into(),
                    "merge".into()
                ),
                (
                    2,
                    "legacy-stage".into(),
                    "read_only".into(),
                    "sparse_delta".into(),
                    "merge".into()
                ),
            ]
        );
        let policy: (i64, i64, Option<i64>, i64) = sqlx::query_as(
            "SELECT version,max_transaction_rows,approval_after_rows,small_table_floor
            FROM policy_version WHERE class='agent' ORDER BY version DESC LIMIT 1",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(policy, (2, 17, Some(6), 1));
        let witness: serde_json::Value =
            sqlx::query_scalar("SELECT payload FROM audit_event WHERE id=1")
                .fetch_one(&pool)
                .await?;
        assert_eq!(witness, serde_json::json!({"keep":true}));
        let upgraded = ledger(&pool).await?;
        run(&pool).await?;
        assert_eq!(upgraded, ledger(&pool).await?);
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires DATABASE_URL for isolated migration PostgreSQL"]
    async fn legacy_lf_preserves_access_policy_data_and_history(pool: PgPool) -> TestResult {
        legacy_access_upgrade(pool, 0).await
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires DATABASE_URL for isolated migration PostgreSQL"]
    async fn legacy_crlf_preserves_access_policy_data_and_history(pool: PgPool) -> TestResult {
        legacy_access_upgrade(pool, 1).await
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires DATABASE_URL for isolated migration PostgreSQL"]
    async fn all_versions_accept_only_known_bytes_without_rewriting_history(
        pool: PgPool,
    ) -> TestResult {
        install_predecessors(&pool, 1, i64::MAX).await?;
        for encoding in 0..2 {
            for known in FINGERPRINTS {
                sqlx::query(
                    "UPDATE _sqlx_migrations SET checksum=decode($1,'hex') WHERE version=$2",
                )
                .bind(known.predecessors[encoding])
                .bind(known.version)
                .execute(&pool)
                .await?;
            }
            let before = ledger(&pool).await?;
            run(&pool).await?;
            assert_eq!(before, ledger(&pool).await?);
        }
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires DATABASE_URL for isolated migration PostgreSQL"]
    async fn corrupt_dirty_and_unknown_history_fail_and_release_the_lock(
        pool: PgPool,
    ) -> TestResult {
        run(&pool).await?;
        let original = ledger(&pool).await?;
        sqlx::query("UPDATE _sqlx_migrations SET checksum=$1 WHERE version=1")
            .bind(vec![0u8; 48])
            .execute(&pool)
            .await?;
        assert!(matches!(
            run(&pool).await,
            Err(MetaError::Migration(MigrateError::VersionMismatch(1)))
        ));
        sqlx::query("UPDATE _sqlx_migrations SET checksum=$1,success=false WHERE version=1")
            .bind(&original[0].1)
            .execute(&pool)
            .await?;
        assert!(matches!(
            run(&pool).await,
            Err(MetaError::Migration(MigrateError::Dirty(1)))
        ));
        sqlx::query("UPDATE _sqlx_migrations SET success=true WHERE version=1")
            .execute(&pool)
            .await?;
        sqlx::query(
            "INSERT INTO _sqlx_migrations(version,description,success,checksum,execution_time)
            VALUES(999,'unknown fixture',true,$1,0)",
        )
        .bind(vec![1u8; 48])
        .execute(&pool)
        .await?;
        assert!(matches!(
            run(&pool).await,
            Err(MetaError::Migration(MigrateError::VersionMissing(999)))
        ));
        sqlx::query("DELETE FROM _sqlx_migrations WHERE version=999")
            .execute(&pool)
            .await?;
        tokio::time::timeout(Duration::from_secs(3), run(&pool)).await??;
        assert_eq!(original, ledger(&pool).await?);
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires DATABASE_URL for isolated migration PostgreSQL"]
    async fn concurrent_fresh_migrators_serialize_and_repeat(pool: PgPool) -> TestResult {
        let (first, second) = tokio::join!(run(&pool), run(&pool));
        first?;
        second?;
        let before = ledger(&pool).await?;
        assert_eq!(before.len(), FINGERPRINTS.len() + 1);
        run(&pool).await?;
        assert_eq!(before, ledger(&pool).await?);
        let limited = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with(pool.connect_options().as_ref().clone())
            .await?;
        let (first, second) = tokio::join!(run(&limited), run(&limited));
        first?;
        second?;
        limited.close().await;
        Ok(())
    }
}
