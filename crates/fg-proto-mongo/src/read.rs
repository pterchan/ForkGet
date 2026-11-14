//! Branch reads merge immutable base documents with branch-local changes:
//! every branch read is one aggregation over the base collection — an
//! anti-join against the branch delta hides replaced or deleted documents,
//! `$unionWith` appends the branch's live delta images, and the driver's
//! stages run on the merged view. Delta collections share the generation
//! database precisely so these same-database stages exist (migration 0013).

use bson::{Bson, Document, doc};
use fg_protocol_common::{CatalogEntry, WireError};

/// Aggregate stages a driver may run on the merged view.
/// `$group` is admitted only in the exact count_documents
/// shape so aggregations cannot escape the merged view.
const ADMITTED_STAGES: [&str; 7] = [
    "$match", "$sort", "$skip", "$limit", "$project", "$count", "$group",
];

/// The merge prefix run against the base collection: hide every document
/// the branch has captured in its delta, whatever the operation is.
fn merge_prefix(entry: &CatalogEntry, branch_id: i64) -> Vec<Document> {
    vec![
        doc! {
            "$lookup": {
                "from": entry.delta_table.as_str(),
                "let": { "fg_id": "$_id" },
                "pipeline": [
                    { "$match": { "$expr": { "$and": [
                        { "$eq": ["$_fg_branch", branch_id] },
                        { "$eq": ["$_doc._id", "$$fg_id"] },
                    ] } } },
                    { "$limit": 1i32 },
                ],
                "as": "_fg_shadow",
            }
        },
        doc! { "$match": { "_fg_shadow.0": { "$exists": false } } },
        doc! { "$unset": "_fg_shadow" },
    ]
}

/// The delta arm appended by `$unionWith`: live insert and update images
/// with the wrapper stripped, so the merged stream holds plain documents.
fn delta_arm(entry: &CatalogEntry, branch_id: i64) -> Document {
    doc! {
        "$unionWith": {
            "coll": entry.delta_table.as_str(),
            "pipeline": [
                { "$match": { "_fg_branch": branch_id, "_fg_op": { "$in": ["I", "U"] } } },
                { "$replaceRoot": { "newRoot": "$_doc" } },
            ],
        }
    }
}

/// The full pipeline for one merged read. Without a driver sort the merged
/// stream gets an `_id` sort so cursor re-runs partition deterministically
/// across getMore batches.
pub fn merged_pipeline(
    entry: &CatalogEntry,
    branch_id: i64,
    mut stages: Vec<Document>,
    needs_order: bool,
) -> Vec<Document> {
    let mut pipeline = merge_prefix(entry, branch_id);
    pipeline.push(delta_arm(entry, branch_id));
    if needs_order && !stages.iter().any(|stage| stage.contains_key("$sort")) {
        pipeline.push(doc! { "$sort": { "_id": 1i32 } });
    }
    pipeline.append(&mut stages);
    pipeline
}

/// For materialized write branches, the copy answers directly,
/// so no delta stages join the pipeline.
pub(crate) fn step_pipeline(
    entry: &CatalogEntry,
    branch_id: i64,
    mut stages: Vec<Document>,
    needs_order: bool,
    native: bool,
) -> Vec<Document> {
    let mut pipeline = Vec::new();
    if !native {
        pipeline = merge_prefix(entry, branch_id);
        pipeline.push(delta_arm(entry, branch_id));
    }
    if needs_order && !stages.iter().any(|stage| stage.contains_key("$sort")) {
        pipeline.push(doc! { "$sort": { "_id": 1i32 } });
    }
    pipeline.append(&mut stages);
    pipeline
}

/// The `aggregate` command running one merged pipeline against the base.
pub(crate) fn aggregate_command(
    entry: &CatalogEntry,
    pipeline: Vec<Document>,
    batch_size: Option<i64>,
) -> Document {
    let mut cursor = doc! {};
    if let Some(size) = batch_size {
        cursor.insert("batchSize", size);
    }
    doc! {
        "aggregate": entry.base_table.as_str(),
        "pipeline": pipeline,
        "cursor": cursor,
    }
}

/// Validate the driver's aggregate stages against the admitted subset.
pub(crate) fn admitted_stages(pipeline: &[Document]) -> Result<Vec<Document>, WireError> {
    for stage in pipeline {
        let name = stage.keys().next().ok_or(WireError::InvalidValue)?;
        if !ADMITTED_STAGES.contains(&name.as_str()) {
            return Err(WireError::Unsupported);
        }
        if name == "$group" {
            let shape = stage
                .get_document(name)
                .map_err(|_| WireError::InvalidValue)?;
            let counts = shape
                .get("n")
                .and_then(Bson::as_document)
                .is_some_and(|spec| spec.get("$sum") == Some(&Bson::Int32(1)));
            if shape.get("_id") != Some(&Bson::Int32(1)) || !counts {
                return Err(WireError::Unsupported);
            }
        }
    }
    Ok(pipeline.to_vec())
}

/// Drivers encode counts as Int32 or Int64; accept either.
pub(crate) fn positive_int(value: Option<&Bson>) -> Option<i64> {
    match value? {
        Bson::Int32(count) if *count > 0 => Some(i64::from(*count)),
        Bson::Int64(count) if *count > 0 => Some(*count),
        _ => None,
    }
}

/// Driver `find` options translated into merged-view stages.
pub(crate) fn find_stages(command: &Document) -> Vec<Document> {
    let mut stages = Vec::new();
    let empty = Document::new();
    let filter = command.get_document("filter").unwrap_or(&empty);
    if !filter.is_empty() {
        stages.push(doc! { "$match": filter.clone() });
    }
    if let Some(sort) = sort_stage(command.get("sort")) {
        stages.push(sort);
    }
    if let Some(skip) = positive_int(command.get("skip")) {
        stages.push(doc! { "$skip": skip });
    }
    if let Some(limit) = positive_int(command.get("limit")) {
        stages.push(doc! { "$limit": limit });
    }
    if let Ok(projection) = command.get_document("projection")
        && !projection.is_empty()
    {
        stages.push(doc! { "$project": projection.clone() });
    }
    stages
}

/// `sort` arrives as a document; drivers may also send key/value pairs.
fn sort_stage(sort: Option<&bson::Bson>) -> Option<Document> {
    match sort? {
        bson::Bson::Document(document) => {
            (!document.is_empty()).then(|| doc! { "$sort": document.clone() })
        }
        bson::Bson::Array(pairs) => {
            let mut stage = Document::new();
            for pair in pairs {
                let fields = pair.as_document()?;
                let (key, direction) = fields.iter().next()?;
                stage.insert(key, direction.clone());
            }
            (!stage.is_empty()).then_some(doc! { "$sort": stage })
        }
        _ => None,
    }
}

/// Driver `count` options translated into merged-view stages.
pub(crate) fn count_stages(command: &Document) -> Vec<Document> {
    let mut stages = Vec::new();
    let empty = Document::new();
    let query = command.get_document("query").unwrap_or(&empty);
    if !query.is_empty() {
        stages.push(doc! { "$match": query.clone() });
    }
    if let Some(skip) = positive_int(command.get("skip")) {
        stages.push(doc! { "$skip": skip });
    }
    if let Some(limit) = positive_int(command.get("limit")) {
        stages.push(doc! { "$limit": limit });
    }
    stages.push(doc! { "$count": "n" });
    stages
}

/// Driver `distinct` options translated into merged-view stages.
pub(crate) fn distinct_stages(key: &str, command: &Document) -> Vec<Document> {
    let mut stages = Vec::new();
    let empty = Document::new();
    let query = command.get_document("query").unwrap_or(&empty);
    if !query.is_empty() {
        stages.push(doc! { "$match": query.clone() });
    }
    stages.push(doc! { "$group": { "_id": format!("${key}") } });
    stages.push(doc! { "$sort": { "_id": 1i32 } });
    stages
}

/// The single merged document a capture path needs (update/delete target
/// resolution): merged prefix + filter + first hit.
pub(crate) fn resolve_pipeline(
    entry: &CatalogEntry,
    branch_id: i64,
    filter: &Document,
) -> Vec<Document> {
    merged_pipeline(
        entry,
        branch_id,
        vec![doc! { "$match": filter.clone() }, doc! { "$limit": 1i32 }],
        false,
    )
}

/// Rewrite a mongod aggregate reply for the driver: the cursor namespace
/// names the branch view, and a live mongod cursor id becomes the proxy's
/// synthetic id (the pipeline is replayed with skips, never continued).
pub(crate) fn rewrite_reply(
    reply: &mut Document,
    driver_db: &str,
    driver_coll: &str,
    synthetic_id: Option<i64>,
) -> Result<(), WireError> {
    let cursor = reply
        .get_document_mut("cursor")
        .map_err(|_| WireError::Backend)?;
    cursor.insert("ns", format!("{driver_db}.{driver_coll}"));
    let live = cursor.get_i64("id").map(|id| id != 0).unwrap_or(false);
    match synthetic_id {
        Some(id) => cursor.insert("id", id),
        None if live => return Err(WireError::Backend),
        None => cursor.insert("id", 0i64),
    };
    Ok(())
}

/// A registered branch cursor: the merged pipeline to replay plus how much
/// of the stream the driver has already received.
pub(crate) struct CursorState {
    pub pipeline: Vec<Document>,
    pub base_db: String,
    pub base_coll: String,
    pub driver_db: String,
    pub driver_coll: String,
    pub fetched: i64,
}

impl CursorState {
    /// The next getMore command: the same merged pipeline with a skip over
    /// the already-delivered documents. Base images are pinned per branch
    /// and delta writes come only from this branch, so replay order holds.
    pub(crate) fn continuation(&self, batch_size: Option<i64>) -> Document {
        let mut pipeline = self.pipeline.clone();
        pipeline.push(doc! { "$skip": self.fetched });
        aggregate_command(
            &CatalogEntry {
                id: 0,
                baseline_rows: 0,
                logical_schema: String::new(),
                logical_table: String::new(),
                base_schema: self.base_db.clone(),
                base_table: self.base_coll.clone(),
                delta_schema: String::new(),
                delta_table: String::new(),
                generated_key: None,
                columns: Vec::new(),
            },
            pipeline,
            batch_size,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> CatalogEntry {
        CatalogEntry {
            id: 9,
            baseline_rows: 4,
            logical_schema: "app".into(),
            logical_table: "orders".into(),
            base_schema: "fg_g7".into(),
            base_table: "orders".into(),
            delta_schema: "fg_g7".into(),
            delta_table: "_d_g7_t9".into(),
            generated_key: None,
            columns: Vec::new(),
        }
    }

    #[test]
    fn merged_pipeline_anti_joins_delta_and_appends_live_images() -> Result<(), &'static str> {
        let pipeline = merged_pipeline(&entry(), 12, vec![doc! { "$count": "n" }], false);
        let lookup = pipeline[0].get_document("$lookup").map_err(|_| "lookup")?;
        assert_eq!(lookup.get_str("from"), Ok("_d_g7_t9"));
        assert_eq!(
            lookup
                .get_document("let")
                .map_err(|_| "let")?
                .get_str("fg_id"),
            Ok("$_id")
        );
        // merge_prefix (lookup, hide, unset) then the delta arm.
        assert!(pipeline[3].contains_key("$unionWith"));
        let last = pipeline.last().ok_or("last")?;
        assert_eq!(last, &doc! { "$count": "n" });
        // No driver sort and needs_order=false (single reply, no cursor).
        assert!(!pipeline.iter().any(|stage| stage.contains_key("$sort")));
        Ok(())
    }

    #[test]
    fn cursor_reads_get_a_deterministic_order_stage() -> Result<(), &'static str> {
        let pipeline = merged_pipeline(&entry(), 1, Vec::new(), true);
        assert_eq!(
            pipeline.get(4).ok_or("stage 4")?,
            &doc! { "$sort": { "_id": 1i32 } },
            "the appended _id sort precedes driver stages"
        );
        Ok(())
    }

    #[test]
    fn aggregate_stages_admit_only_the_merged_subset() -> Result<(), WireError> {
        assert!(admitted_stages(&[doc! { "$match": {} }, doc! { "$limit": 3i32 }]).is_ok());
        assert_eq!(
            admitted_stages(&[doc! { "$out": "elsewhere" }]),
            Err(WireError::Unsupported)
        );
        assert_eq!(
            admitted_stages(&[doc! { "$group": { "_id": "$tenant_id" } }]),
            Err(WireError::Unsupported)
        );
        admitted_stages(&[doc! { "$group": { "_id": 1, "n": { "$sum": 1 } } }])?;
        Ok(())
    }

    #[test]
    fn find_stages_translate_driver_options() {
        let command = doc! {
            "find": "orders",
            "filter": { "tenant_id": 1 },
            "sort": { "amount": -1i32 },
            "skip": 2i64,
            "limit": 5i64,
            "projection": { "note": 1i32 },
        };
        let stages = find_stages(&command);
        assert_eq!(
            stages,
            vec![
                doc! { "$match": { "tenant_id": 1 } },
                doc! { "$sort": { "amount": -1i32 } },
                doc! { "$skip": 2i64 },
                doc! { "$limit": 5i64 },
                doc! { "$project": { "note": 1i32 } },
            ]
        );
    }
}
