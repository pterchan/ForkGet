//! Safe observations of acknowledged standalone write commands. No document
//! keys, error messages or application values cross the audit boundary.

use std::collections::HashSet;

use bson::{Bson, Document};
use fg_protocol_common::{MongoObservationState, MongoWriteObservation, WriteKind};

use crate::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeWriteCategory {
    Acknowledged,
    AcknowledgedWithErrors,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeWriteObservation {
    pub category: NativeWriteCategory,
    pub n: Option<u64>,
    pub modified: Option<u64>,
    pub upserted: u64,
    pub write_errors: u64,
    pub code: Option<i32>,
}

impl NativeWriteObservation {
    pub fn audit(self, kind: WriteKind) -> MongoWriteObservation {
        MongoWriteObservation {
            state: match self.category {
                NativeWriteCategory::Acknowledged => MongoObservationState::Acknowledged,
                NativeWriteCategory::AcknowledgedWithErrors => {
                    MongoObservationState::AcknowledgedWithErrors
                }
                NativeWriteCategory::Unknown => MongoObservationState::Unknown,
            },
            matched: if kind == WriteKind::Update {
                self.n.and_then(|n| n.checked_sub(self.upserted))
            } else {
                None
            },
            modified: self.modified,
            inserted: (kind == WriteKind::Insert).then_some(self.n).flatten(),
            deleted: (kind == WriteKind::Delete).then_some(self.n).flatten(),
            upserted: (kind == WriteKind::Update && self.n.is_some()).then_some(self.upserted),
            error_count: self.n.map(|_| self.write_errors),
            native_code: self.code,
        }
    }
}

/// Parse the whole write result, including partial errors and write concern.
/// `n` is native matched/inserted/deleted, never a generic modified-row count.
pub fn observe_write(
    document: &Document,
    kind: WriteKind,
    planned: u64,
) -> Result<NativeWriteObservation, Error> {
    let ok = match document.get("ok") {
        Some(Bson::Int32(value)) if matches!(value, 0 | 1) => *value == 1,
        Some(Bson::Int64(value)) if matches!(value, 0 | 1) => *value == 1,
        Some(Bson::Double(value)) if *value == 0.0 || *value == 1.0 => *value == 1.0,
        _ => return Err(Error::Invalid),
    };
    if !ok {
        return Ok(NativeWriteObservation {
            category: NativeWriteCategory::Unknown,
            n: None,
            modified: None,
            upserted: 0,
            write_errors: 0,
            code: optional_code(document)?,
        });
    }
    let n = count(document.get("n"))?;
    if n > planned {
        return Err(Error::Invalid);
    }
    let modified = if kind == WriteKind::Update {
        Some(count(document.get("nModified"))?)
    } else {
        None
    };
    let (upserted_indices, _) = result_indices(document, "upserted", planned, false)?;
    let upserted = upserted_indices.len() as u64;
    if upserted > n || modified.is_some_and(|value| value > n - upserted) {
        return Err(Error::Invalid);
    }
    let (error_indices, code) = result_indices(document, "writeErrors", planned, true)?;
    let write_errors = error_indices.len() as u64;
    if write_errors > planned - n
        || (kind != WriteKind::Update && upserted > 0)
        || !upserted_indices.is_disjoint(&error_indices)
    {
        return Err(Error::Invalid);
    }
    let concern_code = match document.get("writeConcernError") {
        None => None,
        Some(Bson::Document(concern)) => Some(required_code(concern)?),
        _ => return Err(Error::Invalid),
    };
    Ok(NativeWriteObservation {
        category: if concern_code.is_some() {
            NativeWriteCategory::Unknown
        } else if write_errors > 0 {
            NativeWriteCategory::AcknowledgedWithErrors
        } else {
            NativeWriteCategory::Acknowledged
        },
        n: Some(n),
        modified,
        upserted,
        write_errors,
        code: concern_code.or(code),
    })
}

fn count(value: Option<&Bson>) -> Result<u64, Error> {
    let integer = match value {
        Some(Bson::Int32(value)) => i64::from(*value),
        Some(Bson::Int64(value)) => *value,
        _ => return Err(Error::Invalid),
    };
    u64::try_from(integer).map_err(|_| Error::Invalid)
}

fn optional_code(document: &Document) -> Result<Option<i32>, Error> {
    document
        .get("code")
        .map(|_| required_code(document))
        .transpose()
}

fn required_code(document: &Document) -> Result<i32, Error> {
    let value = count(document.get("code"))?;
    i32::try_from(value).map_err(|_| Error::Invalid)
}

fn result_indices(
    document: &Document,
    field: &str,
    planned: u64,
    errors: bool,
) -> Result<(HashSet<u64>, Option<i32>), Error> {
    let Some(value) = document.get(field) else {
        return Ok((HashSet::new(), None));
    };
    let values = value.as_array().ok_or(Error::Invalid)?;
    if values.len() as u64 > planned {
        return Err(Error::Invalid);
    }
    let mut indices = HashSet::with_capacity(values.len());
    let mut first_code = None;
    for value in values {
        let value = value.as_document().ok_or(Error::Invalid)?;
        let index = count(value.get("index"))?;
        if index >= planned || !indices.insert(index) {
            return Err(Error::Invalid);
        }
        if errors {
            let code = required_code(value)?;
            first_code = first_code.or(Some(code));
        } else if !value.contains_key("_id") {
            return Err(Error::Invalid);
        }
    }
    Ok((indices, first_code))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::doc;

    #[test]
    fn partial_success_keeps_safe_native_counts() -> Result<(), Error> {
        let observation = observe_write(
            &doc! {"ok":1.0,"n":1,"writeErrors":[{"index":1,"code":11000,"errmsg":"secret", "keyValue":{"secret":42}}]},
            WriteKind::Insert,
            3,
        )?;
        assert_eq!(
            observation.category,
            NativeWriteCategory::AcknowledgedWithErrors
        );
        assert_eq!(
            (observation.n, observation.write_errors, observation.code),
            (Some(1), 1, Some(11000))
        );
        assert!(!format!("{observation:?}").contains("secret"));
        Ok(())
    }

    #[test]
    fn concern_or_command_error_is_not_committed_or_rolled_back() -> Result<(), Error> {
        let concern = observe_write(
            &doc! {"ok":1,"n":1,"writeConcernError":{"code":64}},
            WriteKind::Insert,
            1,
        )?;
        assert_eq!(concern.category, NativeWriteCategory::Unknown);
        assert_eq!(concern.n, Some(1));
        let rejected = observe_write(&doc! {"ok":0,"code":13}, WriteKind::Delete, 1)?;
        assert_eq!(rejected.category, NativeWriteCategory::Unknown);
        assert_eq!(rejected.audit(WriteKind::Delete).deleted, None);
        Ok(())
    }

    #[test]
    fn updates_preserve_matched_modified_and_upserted_distinction() -> Result<(), Error> {
        let unchanged = observe_write(&doc! {"ok":1,"n":1,"nModified":0}, WriteKind::Update, 1)?;
        assert_eq!(unchanged.modified, Some(0));
        let upsert = observe_write(
            &doc! {"ok":1,"n":1,"nModified":0,"upserted":[{"index":0,"_id":"private"}]},
            WriteKind::Update,
            1,
        )?;
        assert_eq!(
            (upsert.n, upsert.modified, upsert.upserted),
            (Some(1), Some(0), 1)
        );
        Ok(())
    }

    #[test]
    fn malformed_and_incomplete_acknowledgments_are_rejected() {
        for reply in [
            doc! {"ok":1},
            doc! {"ok":1,"n":-1},
            doc! {"ok":1,"n":2},
            doc! {"ok":1,"n":1,"writeErrors":[{"index":1,"code":11000}]},
            doc! {"ok":1,"n":1,"writeConcernError":{}},
            doc! {"ok":1,"n":0,"writeErrors":[{"index":0,"code":11000},{"index":0,"code":11000}]},
        ] {
            assert!(observe_write(&reply, WriteKind::Insert, 1).is_err());
        }
        assert!(observe_write(&doc! {"ok":1,"n":1}, WriteKind::Update, 1).is_err());
        assert!(
            observe_write(
                &doc! {"ok":1,"n":1,"nModified":0,
                "upserted":[{"index":0,"_id":7}],
                "writeErrors":[{"index":0,"code":11000}]},
                WriteKind::Update,
                2
            )
            .is_err()
        );
    }
}
