//! Write capture into the branch delta:
//! a branch write never touches the base collection; the full document
//! image lands in the delta under `_fg_branch` / `_fg_op` / `_doc`, and
//! merged reads apply it delta-wins by `_doc._id`. Every capture goes
//! through the same policy pipeline as the SQL guarded writes.

use bson::{Document, doc};
use fg_protocol_common::{CatalogEntry, TransactionBudget, WireError, WriteKind, WriteOperation};

/// Standalone audit recovery requires an acknowledged native response. Never
/// rewrite the application's write concern to manufacture that guarantee.
pub(crate) fn require_acknowledged(command: &Document) -> Result<(), WireError> {
    let Some(concern) = command.get("writeConcern") else {
        return Ok(());
    };
    let concern = concern.as_document().ok_or(WireError::InvalidValue)?;
    match concern.get("w") {
        None => Ok(()),
        Some(bson::Bson::Int32(0) | bson::Bson::Int64(0)) => Err(WireError::Unsupported),
        Some(bson::Bson::Int32(value)) if *value > 0 => Ok(()),
        Some(bson::Bson::Int64(value)) if *value > 0 => Ok(()),
        Some(bson::Bson::String(value)) if !value.is_empty() => Ok(()),
        _ => Err(WireError::InvalidValue),
    }
}

pub(crate) fn optional_bool(
    document: &Document,
    field: &str,
    default: bool,
) -> Result<bool, WireError> {
    match document.get(field) {
        None => Ok(default),
        Some(bson::Bson::Boolean(value)) => Ok(*value),
        _ => Err(WireError::InvalidValue),
    }
}

pub(crate) fn require_single_delete(statement: &Document) -> Result<(), WireError> {
    match statement.get("limit") {
        Some(bson::Bson::Int32(1) | bson::Bson::Int64(1)) => Ok(()),
        Some(bson::Bson::Int32(0) | bson::Bson::Int64(0)) => Err(WireError::Unsupported),
        _ => Err(WireError::InvalidValue),
    }
}

/// One capture decision already resolved: which branch table, and how many
/// documents the command will write once the policy admits it.
pub(crate) struct Capture<'a> {
    pub entry: &'a CatalogEntry,
    pub branch_id: i64,
}

impl Capture<'_> {
    /// The delta document for a captured operation: full image under `_doc`,
    /// tombstones keep only the natural key.
    pub(crate) fn delta_document(&self, operation: &str, image: &Document) -> Document {
        let payload = if operation == "D" {
            let mut tombstone = Document::new();
            if let Some(id) = image.get("_id") {
                tombstone.insert("_id", id.clone());
            }
            tombstone
        } else {
            image.clone()
        };
        doc! {
            "_fg_branch": self.branch_id,
            "_fg_op": operation,
            "_doc": payload,
        }
    }

    /// The delta replace filter: per-branch last write wins by `_doc._id`.
    pub(crate) fn delta_filter(&self, id: &bson::Bson) -> Document {
        doc! { "_fg_branch": self.branch_id, "_doc._id": id }
    }

    /// Run the same admission ladder as the SQL guard: liveness, policy,
    /// then the transaction budget (rows, table share, approval flow).
    pub(crate) async fn admit(
        &self,
        session: &mut fg_protocol_common::BranchSession,
        budget: &mut TransactionBudget,
        kind: WriteKind,
        rows: u64,
    ) -> Result<fg_protocol_common::Policy, WireError> {
        session.binding().require_write_access()?;
        session.authorize().await?;
        let policy = session.policy().await?;
        // TransactionBudget::evaluate records the decision, runs the
        // approval flow, and re-checks branch liveness, exactly like the
        // SQL guard's write admission.
        budget
            .evaluate(
                session,
                &policy,
                WriteOperation {
                    table_id: self.entry.id,
                    kind,
                },
                rows,
            )
            .await?;
        Ok(policy)
    }
}

/// Apply an update-operator document ($set / $unset / $inc) onto a captured
/// image. Anything outside the admitted operator subset is a typed refusal.
pub(crate) fn apply_operators(image: &mut Document, operators: &Document) -> Result<(), WireError> {
    for (name, body) in operators {
        match name.as_str() {
            "$set" => {
                let fields = body.as_document().ok_or(WireError::InvalidValue)?;
                for (key, value) in fields {
                    image.insert(key, value.clone());
                }
            }
            "$unset" => {
                let fields = body.as_document().ok_or(WireError::InvalidValue)?;
                for (key, _) in fields {
                    image.remove(key);
                }
            }
            "$inc" => {
                let fields = body.as_document().ok_or(WireError::InvalidValue)?;
                for (key, amount) in fields {
                    let current = image.get(key).cloned().unwrap_or(bson::Bson::Int32(0));
                    image.insert(key, increment(&current, amount)?);
                }
            }
            _ => return Err(WireError::Unsupported),
        }
    }
    Ok(())
}

fn increment(current: &bson::Bson, amount: &bson::Bson) -> Result<bson::Bson, WireError> {
    match (current, amount) {
        (bson::Bson::Int32(value), bson::Bson::Int32(step)) => value
            .checked_add(*step)
            .map(bson::Bson::Int32)
            .ok_or(WireError::InvalidValue),
        (bson::Bson::Int64(value), bson::Bson::Int64(step)) => value
            .checked_add(*step)
            .map(bson::Bson::Int64)
            .ok_or(WireError::InvalidValue),
        (bson::Bson::Double(value), bson::Bson::Double(step)) => {
            Ok(bson::Bson::Double(value + step))
        }
        // MongoDB type-brackets mixed numeric increments to double; keep the
        // integer forms exact and refuse silent widening.
        (bson::Bson::Int32(value), bson::Bson::Int64(step)) => {
            i64::checked_add(i64::from(*value), *step)
                .map(bson::Bson::Int64)
                .ok_or(WireError::InvalidValue)
        }
        (bson::Bson::Int64(value), bson::Bson::Int32(step)) => value
            .checked_add(i64::from(*step))
            .map(bson::Bson::Int64)
            .ok_or(WireError::InvalidValue),
        _ => Err(WireError::InvalidValue),
    }
}

/// Whether an update body is operator form (every key starts with `$`).
pub(crate) fn is_operator_form(body: &Document) -> bool {
    !body.is_empty() && body.keys().all(|key| key.starts_with('$'))
}

/// Replacement documents must preserve the document identity.
pub(crate) fn replacement_keeps_id(body: &Document, current: &Document) -> bool {
    match body.get("_id") {
        Some(id) => current.get("_id") == Some(id),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unacknowledged_writes_are_refused_without_changing_write_concern() {
        for w in [bson::Bson::Int32(0), bson::Bson::Int64(0)] {
            let command = doc! {"writeConcern":{"w":w}};
            let unchanged = command.clone();
            assert_eq!(require_acknowledged(&command), Err(WireError::Unsupported));
            assert_eq!(command, unchanged);
        }
        assert!(require_acknowledged(&doc! {}).is_ok());
        assert!(require_acknowledged(&doc! {"writeConcern":{"w":1,"j":false}}).is_ok());
        assert!(require_acknowledged(&doc! {"writeConcern":{"w":-1}}).is_err());
    }

    #[test]
    fn numeric_width_or_truthy_fields_cannot_bypass_single_document_bounds() {
        for limit in [bson::Bson::Int32(0), bson::Bson::Int64(0)] {
            assert_eq!(
                require_single_delete(&doc! {"limit":limit}),
                Err(WireError::Unsupported)
            );
        }
        for limit in [bson::Bson::Int32(1), bson::Bson::Int64(1)] {
            assert!(require_single_delete(&doc! {"limit":limit}).is_ok());
        }
        assert!(require_single_delete(&doc! {}).is_err());
        assert!(optional_bool(&doc! {"multi":1}, "multi", false).is_err());
        assert_eq!(
            optional_bool(&doc! {"multi":true}, "multi", false),
            Ok(true)
        );
    }

    #[test]
    fn tombstones_keep_only_the_natural_key() {
        let entry = CatalogEntry {
            id: 3,
            baseline_rows: 0,
            logical_schema: "app".into(),
            logical_table: "orders".into(),
            base_schema: "fg_g7".into(),
            base_table: "orders".into(),
            delta_schema: "fg_g7".into(),
            delta_table: "_d_g7_t3".into(),
            generated_key: None,
            columns: Vec::new(),
        };
        let capture = Capture {
            entry: &entry,
            branch_id: 21,
        };
        let image = doc! { "_id": 7, "note": "gone" };
        assert_eq!(
            capture.delta_document("D", &image),
            doc! { "_fg_branch": 21i64, "_fg_op": "D", "_doc": { "_id": 7 } }
        );
        assert_eq!(
            capture.delta_document("U", &image),
            doc! { "_fg_branch": 21i64, "_fg_op": "U", "_doc": image }
        );
    }

    #[test]
    fn update_operators_cover_set_unset_and_inc_only() -> Result<(), WireError> {
        let mut image = doc! { "_id": 1, "note": "a", "amount": 10.0 };
        apply_operators(
            &mut image,
            &doc! { "$set": { "note": "b" }, "$inc": { "amount": 5.0 }, "$unset": { "gone": 1i32 } },
        )?;
        assert_eq!(image.get_str("note"), Ok("b"));
        assert_eq!(image.get_f64("amount"), Ok(15.0));
        assert!(!image.contains_key("gone"));
        assert_eq!(
            apply_operators(&mut image, &doc! { "$push": { "tags": 1i32 } }),
            Err(WireError::Unsupported)
        );
        assert!(is_operator_form(&doc! { "$set": {} }));
        assert!(!is_operator_form(&doc! { "note": "replacement" }));
        assert!(replacement_keeps_id(
            &doc! { "_id": 1, "note": "b" },
            &doc! { "_id": 1 }
        ));
        assert!(!replacement_keeps_id(
            &doc! { "_id": 2, "note": "b" },
            &doc! { "_id": 1 }
        ));
        Ok(())
    }
}
