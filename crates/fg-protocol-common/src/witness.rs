use crate::{AUDIT_WITNESS_VERSION, AuditAttempt, BranchBinding, WireError, WriteTarget};

pub const TXN_WITNESS_TABLE: &str = "_fg_txn_witness";
pub const TXN_WITNESS_FORMAT: u16 = AUDIT_WITNESS_VERSION;

/// Only controller-issued identities enter this SQL. Application identifiers,
/// statements and values never participate in the internal commit marker.
pub fn witness_insert_sql(
    binding: &BranchBinding,
    attempt: &AuditAttempt,
) -> Result<String, WireError> {
    let witness = attempt.witness().ok_or(WireError::Backend)?;
    let context = attempt.context();
    let schema = binding.write_schema.as_deref().ok_or(WireError::Backend)?;
    let target = WriteTarget::new(&binding.engine, binding.id, schema).ok_or(WireError::Backend)?;
    if witness.format_version != TXN_WITNESS_FORMAT
        || witness.branch_id != binding.id
        || witness.generation_id != binding.generation_id
        || context.generation_id != binding.generation_id
        || !valid_witness_identity(&witness.deployment_id, &witness.storage_incarnation)
        || !valid_attempt_id(&context.attempt_id)
    {
        return Err(WireError::Backend);
    }
    let relation = match binding.engine.as_str() {
        "mysql" | "tidb" => format!(
            "`{}`.`{}`",
            target.schema(),
            target.table(TXN_WITNESS_TABLE)
        ),
        "postgresql" => format!(
            "\"{}\".\"{}\"",
            target.schema(),
            target.table(TXN_WITNESS_TABLE)
        ),
        _ => return Err(WireError::Backend),
    };
    Ok(format!(
        "INSERT INTO {relation} (format_version, deployment_id, branch_id, generation_id, storage_incarnation, attempt_id, native_session) VALUES ({}, '{}', {}, {}, '{}', '{}', '{}')",
        witness.format_version,
        witness.deployment_id,
        witness.branch_id,
        witness.generation_id,
        witness.storage_incarnation,
        context.attempt_id,
        context.native_session_id,
    ))
}

fn valid_attempt_id(value: &str) -> bool {
    let mut fields = value.split(':');
    let Some(epoch) = fields.next() else {
        return false;
    };
    let valid_epoch = epoch.len() == 32
        && epoch
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    let valid_serial = |serial: &str| {
        !serial.starts_with('0') && serial.parse::<u64>().is_ok_and(|value| value > 0)
    };
    valid_epoch
        && fields.next().is_some_and(valid_serial)
        && fields.next().is_some_and(valid_serial)
        && fields.next().is_none()
}

pub fn valid_witness_identity(deployment: &str, incarnation: &str) -> bool {
    deployment.len() == 36
        && deployment.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
        && incarnation.len() == 32
        && incarnation
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{valid_attempt_id, valid_witness_identity};

    #[test]
    fn rejects_noncanonical_identity_before_internal_sql() {
        let deployment = "00000000-0000-0000-0000-000000000001";
        let storage = "0123456789abcdef0123456789abcdef";
        assert!(valid_witness_identity(deployment, storage));
        for invalid in [
            "'",
            "00000000-0000-0000-0000-00000000000'",
            "00000000-0000-0000-0000-00000000000A",
        ] {
            assert!(!valid_witness_identity(invalid, storage));
        }
        assert!(!valid_witness_identity(
            deployment,
            "0123456789abcdef0123456789abcde'"
        ));
    }

    #[test]
    fn accepts_only_canonical_monotone_attempt_serials() {
        let epoch = "0123456789abcdef0123456789abcdef";
        assert!(valid_attempt_id(&format!("{epoch}:1:18446744073709551615")));
        for suffix in [
            "0:1",
            "01:1",
            "1:0",
            "1:18446744073709551616",
            "1:2:3",
            "1:'",
        ] {
            assert!(!valid_attempt_id(&format!("{epoch}:{suffix}")));
        }
    }
}
