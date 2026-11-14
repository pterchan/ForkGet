use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use bson::{Document, RawDocumentBuf, doc};

/// Base64 encodes raw BSON, including numeric widths, binary subtypes and
/// document field order. It never passes through Extended JSON.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentChange {
    pub collection_id: i64,
    pub operation: ChangeOperation,
    pub key_bson: String,
    pub before_bson: Option<String>,
    pub after_bson: Option<String>,
}

pub fn encode_bson(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn bson_document(encoded: &str) -> io::Result<RawDocumentBuf> {
    let bytes = STANDARD.decode(encoded).map_err(invalid)?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(invalid("bson_document_limit_exceeded"));
    }
    let raw = RawDocumentBuf::from_bytes(bytes).map_err(invalid)?;
    // Fully traverse the image, rather than validating only the BSON envelope.
    let _: Document = bson::from_slice(raw.as_bytes()).map_err(invalid)?;
    Ok(raw)
}

pub fn bson_key(document: &RawDocumentBuf) -> io::Result<String> {
    let document: Document = bson::from_slice(document.as_bytes()).map_err(invalid)?;
    let id = document
        .get("_id")
        .ok_or_else(|| invalid("bson_id_required"))?;
    Ok(encode_bson(
        &bson::to_vec(&doc! {"_id":id.clone()}).map_err(invalid)?,
    ))
}

pub fn validate_document_change(
    header: &ArtifactHeader,
    change: &DocumentChange,
) -> io::Result<()> {
    if header.engine != "mongodb"
        || !header
            .tables
            .iter()
            .any(|table| table.id == change.collection_id)
    {
        return Err(invalid("document_catalog_mismatch"));
    }
    let key = bson_document(&change.key_bson)?;
    let key: Document = bson::from_slice(key.as_bytes()).map_err(invalid)?;
    if key.len() != 1 || !key.contains_key("_id") {
        return Err(invalid("invalid_bson_key"));
    }
    match (&change.operation, &change.before_bson, &change.after_bson) {
        (ChangeOperation::Insert, None, Some(_)) | (ChangeOperation::Delete, Some(_), None) => (),
        (ChangeOperation::Update, Some(before), Some(after)) if before != after => (),
        _ => return Err(invalid("invalid_document_images")),
    }
    for image in [change.before_bson.as_ref(), change.after_bson.as_ref()]
        .into_iter()
        .flatten()
    {
        if bson_key(&bson_document(image)?)? != change.key_bson {
            return Err(invalid("bson_identity_changed"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Cursor, str::FromStr};
    #[test]
    fn raw_bson_round_trip_preserves_types_order_and_identity() -> io::Result<()> {
        let document = doc! {"_id":bson::oid::ObjectId::from_bytes([7;12]),
        "i32":7i32,"i64":7i64,"decimal":bson::Decimal128::from_str("1.2300").map_err(invalid)?,
        "date":bson::DateTime::from_millis(1735689600123),"binary":bson::Binary {subtype:bson::spec::BinarySubtype::Uuid,bytes:vec![9;16]},
        "nested":{"z":1i32,"a":2i64},"array":[true,bson::Bson::Null]};
        let bytes = bson::to_vec(&document).map_err(invalid)?;
        let raw = bson_document(&encode_bson(&bytes))?;
        assert_eq!(raw.as_bytes(), bytes);
        let header = ArtifactHeader {
            format_version: 2,
            engine: "mongodb".into(),
            source_branch_id: 1,
            origin: ReplayOrigin {
                deployment_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
                generation_id: 1,
                snapshot: "v2".into(),
            },
            native_write: true,
            manifest: None,
            tables: vec![ArtifactTable {
                id: 3,
                schema: "app".into(),
                table: "events".into(),
                generated_key: None,
                columns: Vec::new(),
            }],
        };
        let change = DocumentChange {
            collection_id: 3,
            operation: ChangeOperation::Insert,
            key_bson: bson_key(&raw)?,
            before_bson: None,
            after_bson: Some(encode_bson(&bytes)),
        };
        let mut writer = ArtifactWriter::new(Vec::new(), header.clone())?;
        writer.document(change.clone())?;
        let mut reader = ArtifactReader::new(Cursor::new(writer.finish(Vec::new())?))?;
        assert_eq!(
            reader.next_entry()?,
            Some(ArtifactEntry::Document(change.clone()))
        );
        assert!(reader.next_entry()?.is_none());
        assert!(
            reader
                .end()
                .is_some_and(|end| end.replayable && end.changes == 1)
        );
        let mut changed = change;
        changed.key_bson = encode_bson(&bson::to_vec(&doc! {"_id":7}).map_err(invalid)?);
        assert!(validate_document_change(&header, &changed).is_err());
        assert!(
            header
                .validate_change(&TypedChange {
                    table_id: 3,
                    operation: ChangeOperation::Insert,
                    key: vec!["7".into()],
                    before: None,
                    after: Some(Vec::new())
                })
                .is_err()
        );
        Ok(())
    }
}
