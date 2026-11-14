//! Native storage estimates and explicit evidence limits, without paths.

use std::{
    env,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::native::Native;

#[derive(Debug, thiserror::Error)]
pub(crate) enum CapacityError {
    #[error("Storage preflight setting refused: {0}")]
    Setting(&'static str),
    #[error("Storage preflight could not read native allocation statistics")]
    NativeStatistics,
    #[error("Storage preflight could not measure local available space")]
    LocalStatistics,
    #[error(
        "Storage preflight refused {resource}: estimated required {required} bytes exceeds available {available} bytes"
    )]
    Insufficient {
        resource: &'static str,
        required: u64,
        available: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoragePreflight {
    pub estimate_basis: String,
    pub estimated_native_bytes: u64,
    pub native_copies: u64,
    pub estimated_native_required_bytes: u64,
    pub native_available_bytes: Option<u64>,
    pub native_assurance: String,
    pub estimated_local_required_bytes: u64,
    pub local_available_bytes: u64,
    pub assessed_at: u64,
    pub limitations: Vec<String>,
}

impl StoragePreflight {
    pub fn ensure_capacity(&self) -> Result<(), CapacityError> {
        if self.local_available_bytes < self.estimated_local_required_bytes {
            return Err(CapacityError::Insufficient {
                resource: "local_storage",
                required: self.estimated_local_required_bytes,
                available: self.local_available_bytes,
            });
        }
        if let Some(available) = self.native_available_bytes
            && available < self.estimated_native_required_bytes
        {
            return Err(CapacityError::Insufficient {
                resource: "native_storage",
                required: self.estimated_native_required_bytes,
                available,
            });
        }
        Ok(())
    }
}

pub(crate) fn native_available() -> Result<Option<u64>, CapacityError> {
    match env::var("FG_NATIVE_FREE_BYTES") {
        Ok(value) if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
            value.parse().map(Some).map_err(|_| {
                CapacityError::Setting("FG_NATIVE_FREE_BYTES_must_be_an_unsigned_byte_count")
            })
        }
        Ok(_) | Err(env::VarError::NotUnicode(_)) => Err(CapacityError::Setting(
            "FG_NATIVE_FREE_BYTES_must_be_an_unsigned_byte_count",
        )),
        Err(env::VarError::NotPresent) => Ok(None),
    }
}

pub(crate) fn assurance() -> serde_json::Value {
    match native_available() {
        Ok(Some(bytes)) => {
            json!({"native_assurance":"operator_attested","native_available_bytes":bytes,"native_space_guaranteed":false,"hint":"refresh FG_NATIVE_FREE_BYTES before storage changes; this value is an operator attestation, not a live measurement or reservation"})
        }
        Ok(None) => {
            json!({"native_assurance":"estimated_only","native_available_bytes":null,"native_space_guaranteed":false,"hint":"remote native free space is unknown; set FG_NATIVE_FREE_BYTES to a current operator-attested byte count to refuse a known shortage"})
        }
        Err(_) => {
            json!({"native_assurance":"invalid_attestation","native_available_bytes":null,"native_space_guaranteed":false,"hint":"FG_NATIVE_FREE_BYTES must be an unsigned byte count"})
        }
    }
}

pub(crate) fn assess(
    bytes: u64,
    basis: &str,
    native_copies: u64,
    local_copies: u64,
    path: &Path,
) -> Result<StoragePreflight, CapacityError> {
    let required = bytes
        .checked_mul(native_copies)
        .ok_or(CapacityError::Setting("storage_estimate_overflow"))?;
    let local = bytes
        .checked_mul(local_copies)
        .ok_or(CapacityError::Setting("storage_estimate_overflow"))?;
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        env::current_dir()
            .map_err(|_| CapacityError::LocalStatistics)?
            .join(path)
    };
    let existing = absolute
        .ancestors()
        .find(|path| path.is_dir())
        .ok_or(CapacityError::LocalStatistics)?;
    let output = Command::new("df")
        .env("LC_ALL", "C")
        .args(["-P", "-B1", "--"])
        .arg(existing)
        .output()
        .map_err(|_| CapacityError::LocalStatistics)?;
    if !output.status.success() {
        return Err(CapacityError::LocalStatistics);
    }
    let text = String::from_utf8(output.stdout).map_err(|_| CapacityError::LocalStatistics)?;
    let available = text
        .lines()
        .nth(1)
        .and_then(|line| line.split_whitespace().nth(3))
        .and_then(|value| value.parse().ok())
        .ok_or(CapacityError::LocalStatistics)?;
    let native_available = if native_copies == 0 {
        None
    } else {
        native_available()?
    };
    Ok(StoragePreflight{estimate_basis:basis.into(),estimated_native_bytes:bytes,native_copies,estimated_native_required_bytes:required,native_available_bytes:native_available,
        native_assurance:if native_copies==0{"not_requested"}else if native_available.is_some(){"operator_attested"}else{"estimated_only"}.into(),estimated_local_required_bytes:local,local_available_bytes:available,
        assessed_at:SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_|CapacityError::Setting("clock"))?.as_secs(),limitations:vec!["native table allocation statistics are estimates and may be stale or underestimate output, indexes and transient work".into(),"available space can change after this check; no capacity is reserved".into(),"FG_NATIVE_FREE_BYTES is an operator attestation and must be refreshed when native storage changes".into()]})
}

pub(crate) async fn estimate(
    native: &mut Native,
    relations: &[(String, String)],
) -> Result<u64, CapacityError> {
    let mut total = 0u64;
    for (schema, table) in relations {
        let bytes=match native {
            Native::Postgres(connection)=>{
                let value:i64=sqlx::query_scalar("SELECT pg_total_relation_size(format('%I.%I',$1::text,$2::text)::regclass)::bigint").bind(schema).bind(table).fetch_one(&mut *connection).await.map_err(|_|CapacityError::NativeStatistics)?;
                u64::try_from(value).map_err(|_|CapacityError::NativeStatistics)?
            },
            Native::MySql(connection)|Native::TiDB(connection)=>{
                sqlx::query_scalar::<_,u64>("SELECT CAST(COALESCE(DATA_LENGTH,0)+COALESCE(INDEX_LENGTH,0) AS UNSIGNED) FROM information_schema.tables WHERE table_schema=? AND table_name=?").bind(schema).bind(table).fetch_one(&mut *connection).await.map_err(|_|CapacityError::NativeStatistics)?
            },
            Native::Mongo(client)=>{
                let reply=client.database(schema).run_command(bson::doc!{"collStats":table}).await.map_err(|_|CapacityError::NativeStatistics)?;
                let number=|name|reply.get(name).and_then(|value|match value {bson::Bson::Int64(value)=>u64::try_from(*value).ok(),bson::Bson::Int32(value)=>u64::try_from(*value).ok(),bson::Bson::Double(value) if value.is_finite() && *value>=0.0 && *value<(u64::MAX as f64)=>Some(value.ceil() as u64),_=>None}).ok_or(CapacityError::NativeStatistics);
                number("storageSize")?.checked_add(number("totalIndexSize")?).ok_or(CapacityError::Setting("storage_estimate_overflow"))?
            },
        };
        // Empty or not-yet-analyzed relations can report zero bytes. Keep an
        // explicit allocation allowance rather than treating DDL as free.
        total = total
            .checked_add(bytes.max(64 * 1024))
            .ok_or(CapacityError::Setting("storage_estimate_overflow"))?;
    }
    Ok(total)
}

pub(crate) async fn manifest_estimate(
    native: &mut Native,
    manifest: &fg_protocol_common::SnapshotManifest,
    physical: &str,
) -> Result<u64, CapacityError> {
    let names = if let Some(document) = &manifest.document {
        document
            .collections
            .iter()
            .map(|c| c.name.clone())
            .collect::<Vec<_>>()
    } else {
        manifest.tables.iter().map(|t| t.name.clone()).collect()
    };
    let relations = names
        .into_iter()
        .map(|name| (physical.to_owned(), name))
        .collect::<Vec<_>>();
    estimate(native, &relations).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measured_and_attested_shortages_are_refused_but_unknown_is_explicit() {
        let mut check = StoragePreflight {
            estimate_basis: "native_allocation_statistics".into(),
            estimated_native_bytes: 200,
            native_copies: 2,
            estimated_native_required_bytes: 400,
            native_available_bytes: None,
            native_assurance: "estimated_only".into(),
            estimated_local_required_bytes: 200,
            local_available_bytes: 300,
            assessed_at: 0,
            limitations: Vec::new(),
        };
        assert!(check.ensure_capacity().is_ok());
        assert_eq!(check.native_assurance, "estimated_only");
        check.native_available_bytes = Some(399);
        assert!(matches!(
            check.ensure_capacity(),
            Err(CapacityError::Insufficient {
                resource: "native_storage",
                ..
            })
        ));
        check.native_available_bytes = Some(400);
        check.local_available_bytes = 199;
        assert!(matches!(
            check.ensure_capacity(),
            Err(CapacityError::Insufficient {
                resource: "local_storage",
                ..
            })
        ));
    }

    #[test]
    fn actual_local_probe_refuses_an_unavailable_estimate_without_allocating_files()
    -> Result<(), CapacityError> {
        let result = assess(
            u64::MAX,
            "native_allocation_statistics",
            0,
            1,
            &env::temp_dir(),
        )?;
        assert!(result.local_available_bytes > 0);
        assert!(matches!(
            result.ensure_capacity(),
            Err(CapacityError::Insufficient {
                resource: "local_storage",
                ..
            })
        ));
        Ok(())
    }
}
