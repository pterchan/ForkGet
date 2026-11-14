use fg_protocol_common::{GENERATED_ID_MAX, GENERATED_ID_START, MAX_GENERATED_ROWS};

use crate::{MetaError, Metadata};

impl Metadata {
    pub async fn allocate_ids(
        &self,
        principal: &str,
        branch_id: i64,
        table_id: i64,
        count: u16,
        engine: &str,
    ) -> Result<i64, MetaError> {
        if !(1..=MAX_GENERATED_ROWS).contains(&count) {
            return Err(MetaError::InvalidAllocation);
        }
        let mut tx = self.pool.begin().await?;
        // The branch row lock orders allocation against the transition to dropping.
        sqlx::query_scalar::<_, i64>(
            "SELECT b.id FROM branch b JOIN generation g ON g.id = b.generation_id
             JOIN catalog_table c ON c.generation_id = g.id
             WHERE b.id = $1 AND b.created_by = $2 AND c.id = $3 AND g.engine = $4
               AND b.status = 'active' AND b.layout = 'native_copy' AND b.access = 'read_write'
               AND b.expires_at > clock_timestamp() AND c.generated_key IS NOT NULL
               AND g.status IN ('active', 'retiring')
             FOR SHARE OF b",
        )
        .bind(branch_id)
        .bind(principal)
        .bind(table_id)
        .bind(engine)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(MetaError::BranchUnavailable)?;

        sqlx::query(
            "INSERT INTO generated_id_cursor (branch_id, table_id, next_id)
             VALUES ($1, $2, $3) ON CONFLICT (branch_id, table_id) DO NOTHING",
        )
        .bind(branch_id)
        .bind(table_id)
        .bind(GENERATED_ID_START)
        .execute(&mut *tx)
        .await?;

        let count = i64::from(count);
        let first = sqlx::query_scalar(
            "UPDATE generated_id_cursor SET next_id = next_id + $3
             WHERE branch_id = $1 AND table_id = $2 AND next_id <= $4
             RETURNING next_id - $3",
        )
        .bind(branch_id)
        .bind(table_id)
        .bind(count)
        .bind(GENERATED_ID_MAX - count + 1)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(MetaError::IdsExhausted)?;
        tx.commit().await?;
        Ok(first)
    }
}
