//! Message framing: the 4-field header plus the OP_MSG body layout.

use crate::{Error, MAX_MESSAGE_SIZE};

pub const HEADER_LEN: usize = 16;

/// A whole wire message: the 16-byte header followed by the body.
pub struct Message {
    pub request_id: i32,
    pub response_to: i32,
    pub opcode: i32,
    pub body: Vec<u8>,
}

impl Message {
    pub fn into_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.body.len());
        out.extend_from_slice(&((HEADER_LEN + self.body.len()) as i32).to_le_bytes());
        out.extend_from_slice(&self.request_id.to_le_bytes());
        out.extend_from_slice(&self.response_to.to_le_bytes());
        out.extend_from_slice(&self.opcode.to_le_bytes());
        out.extend_from_slice(&self.body);
        out
    }
}

/// Parse header plus body from one complete message buffer.
pub fn parse(frame: &[u8]) -> Result<Message, Error> {
    if frame.len() < HEADER_LEN {
        return Err(Error::Invalid);
    }
    let length = i32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
    if (length as usize) != frame.len() || (length as usize) < HEADER_LEN {
        return Err(Error::Invalid);
    }
    if (length as usize) > MAX_MESSAGE_SIZE {
        return Err(Error::Oversize(length as usize));
    }
    Ok(Message {
        request_id: i32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]),
        response_to: i32::from_le_bytes([frame[8], frame[9], frame[10], frame[11]]),
        opcode: i32::from_le_bytes([frame[12], frame[13], frame[14], frame[15]]),
        body: frame[HEADER_LEN..].to_vec(),
    })
}

/// The OP_MSG body: flag bits, sections, optional checksum.
pub struct OpMsg {
    /// Request flag bits with the checksum-present bit cleared; optional
    /// flags are cleared so the proxy never forwards unknown contract bits.
    pub flags: u32,
    /// Every section verbatim (kind byte + payload). Command inspection uses
    /// the kind-0 document; passthrough keeps the raw layout byte-exact.
    pub sections: Vec<u8>,
    /// True when the driver set moreToCome and expects no reply.
    pub more_to_come: bool,
}

pub const FLAG_CHECKSUM: u32 = 1;
pub const FLAG_MORE_TO_COME: u32 = 2;
pub const FLAG_EXHAUST_ALLOWED: u32 = 1 << 16;

pub fn parse_op_msg(body: &[u8]) -> Result<OpMsg, Error> {
    if body.len() < 4 {
        return Err(Error::Invalid);
    }
    let mut flags = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    let more_to_come = flags & FLAG_MORE_TO_COME != 0;
    if flags & FLAG_CHECKSUM != 0 {
        if body.len() < 8 {
            return Err(Error::Invalid);
        }
        flags &= !FLAG_CHECKSUM;
        // Trailing CRC-32C checksum section is dropped; this proxy never
        // emits checksums and mongod does not require them.
        let sections_end = body.len() - 4;
        Ok(OpMsg {
            flags,
            sections: body[4..sections_end].to_vec(),
            more_to_come,
        })
    } else {
        Ok(OpMsg {
            flags,
            sections: body[4..].to_vec(),
            more_to_come,
        })
    }
}

/// Serialize an OP_MSG body from flag bits plus one kind-0 BSON document.
pub fn op_msg_body(flags: u32, document: &bson::Document) -> Result<Vec<u8>, Error> {
    let encoded = bson::to_vec(document).map_err(|_| Error::Invalid)?;
    let mut body = Vec::with_capacity(4 + encoded.len());
    body.extend_from_slice(&flags.to_le_bytes());
    body.push(0);
    body.extend_from_slice(&encoded);
    Ok(body)
}

/// Extract the kind-0 command document, refusing sequences-only bodies.
pub fn kind_zero_document(sections: &[u8]) -> Result<bson::Document, Error> {
    let mut cursor = std::io::Cursor::new(sections);
    let kind = read_byte(&mut cursor)?;
    if kind != 0 {
        return Err(Error::Invalid);
    }
    bson::Document::from_reader(&mut cursor).map_err(|_| Error::Invalid)
}

/// The command name is the first key of the kind-0 document.
/// Materialize OP_MSG kind-1 document sequences (driver bulk writes carry
/// `documents`/`updates`/`deletes` outside the kind-0 body) into the
/// command document as ordinary arrays, so inspection sees the whole
/// command.
pub fn document_sequences(op_msg: &OpMsg) -> Result<Vec<(String, Vec<bson::Document>)>, Error> {
    let sections = &op_msg.sections;
    // Section layout: kind byte, then either a body (kind 0: BSON length +
    // document) or a sequence (kind 1: length, NUL-terminated identifier,
    // concatenated documents).
    if sections.first() != Some(&0u8) {
        return Err(Error::Invalid);
    }
    let body_len =
        i32::from_le_bytes(sections[1..5].try_into().map_err(|_| Error::Invalid)?) as usize;
    // The BSON length is self-inclusive; the kind byte adds one.
    let mut position = 1 + body_len;
    let mut sequences = Vec::new();
    while position < sections.len() {
        // Trailing garbage (a malformed frame) is a protocol error, never a
        // slice panic: every read is bounds-checked against the section end.
        // One kind byte plus at least the four length bytes.
        if sections.len() < position + 5 {
            return Err(Error::Invalid);
        }
        let kind = sections[position];
        position += 1;
        if kind != 1 {
            return Err(Error::Invalid);
        }
        // The sequence length covers its own four bytes plus the identifier
        // and the documents; the kind byte stays outside.
        let length = i32::from_le_bytes(
            sections[position..position + 4]
                .try_into()
                .map_err(|_| Error::Invalid)?,
        ) as usize;
        if length < 14 || sections.len() < position + length {
            return Err(Error::Invalid);
        }
        let sequence_end = position + length;
        let Some(identifier_offset) = sections[position + 4..sequence_end]
            .iter()
            .position(|byte| *byte == 0)
        else {
            return Err(Error::Invalid);
        };
        // The identifier starts after the length field and runs to its NUL.
        let identifier_start = position + 4;
        let identifier =
            std::str::from_utf8(&sections[identifier_start..identifier_start + identifier_offset])
                .map_err(|_| Error::Invalid)?
                .to_owned();
        let mut documents = Vec::new();
        // Documents follow the identifier's NUL terminator.
        let mut cursor = identifier_start + identifier_offset + 1;
        while cursor + 5 <= sequence_end {
            let doc_len = i32::from_le_bytes(
                sections[cursor..cursor + 4]
                    .try_into()
                    .map_err(|_| Error::Invalid)?,
            ) as usize;
            if doc_len < 5 || cursor + doc_len > sequence_end {
                return Err(Error::Invalid);
            }
            documents.push(
                bson::Document::from_reader(&sections[cursor..cursor + doc_len])
                    .map_err(|_| Error::Invalid)?,
            );
            cursor += doc_len;
        }
        if cursor != sequence_end {
            return Err(Error::Invalid);
        }
        position = sequence_end;
        sequences.push((identifier, documents));
    }
    Ok(sequences)
}

/// Legacy `OP_QUERY` request: flags, `namespace.$cmd`, skip, return, and the
/// query document. Drivers still use it for the initial handshake against
/// servers that may predate OP_MSG; mongod accepts both, so the proxy must.
pub struct OpQuery {
    pub document: bson::Document,
}

/// `body` is the OP_QUERY payload after the message header: flags, the
/// `database.$cmd` namespace (NUL-terminated), skip and return counts, then
/// the query document.
pub fn parse_op_query(body: &[u8]) -> Result<OpQuery, Error> {
    if body.len() < 13 {
        return Err(Error::Invalid);
    }
    // flags(4) | namespace NUL-terminated | skip(4) | return(4) | query doc
    let nul = body[4..]
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Error::Invalid)?;
    let cursor_start = 4 + nul + 1 + 8;
    let namespace = std::str::from_utf8(&body[4..4 + nul]).map_err(|_| Error::Invalid)?;
    if !namespace.ends_with(".$cmd") {
        return Err(Error::Invalid);
    }
    if body.len() < cursor_start + 5 {
        return Err(Error::Invalid);
    }
    let document =
        bson::Document::from_reader(&body[cursor_start..]).map_err(|_| Error::Invalid)?;
    Ok(OpQuery { document })
}

/// Legacy `OP_REPLY` carrying one document: response flags (0), cursor id 0,
/// starting-from 0, one returned document.
pub fn op_reply_body(document: &bson::Document) -> Result<Vec<u8>, Error> {
    let mut body = Vec::with_capacity(20 + 5);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0i64.to_le_bytes());
    body.extend_from_slice(&0i32.to_le_bytes());
    body.extend_from_slice(&1i32.to_le_bytes());
    body.extend_from_slice(&bson::to_vec(document).map_err(|_| Error::Invalid)?);
    Ok(body)
}

pub fn command_name(document: &bson::Document) -> Option<&str> {
    document
        .iter()
        .next()
        .map(|(key, _)| key.as_str())
        .or_else(|| document.get_str("$db").ok())
}

fn read_byte(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u8, Error> {
    use std::io::Read;
    let mut byte = [0u8; 1];
    cursor.read_exact(&mut byte).map_err(|_| Error::Invalid)?;
    Ok(byte[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OPCODE_MSG;

    type Outcome = Result<(), Error>;

    fn sample_document() -> bson::Document {
        bson::doc! {
            "insert": "orders",
            "documents": { "0": { "x": 1i32 } },
            "$db": "app",
        }
    }

    #[test]
    fn op_msg_roundtrip_without_checksum() -> Outcome {
        let body = op_msg_body(0, &sample_document())?;
        let parsed = parse_op_msg(&body)?;
        assert_eq!(parsed.flags, 0);
        assert!(!parsed.more_to_come);
        assert_eq!(kind_zero_document(&parsed.sections)?, sample_document());
        Ok(())
    }

    #[test]
    fn document_sequences_materialize_into_inline_arrays() -> Outcome {
        let payload = sample_document();
        let identifier = b"documents\0";
        let mut body = op_msg_body(0, &payload)?;
        let encoded = bson::to_vec(&payload).map_err(|_| Error::Invalid)?;
        let mut sequence = Vec::new();
        // The length covers itself, the identifier and the documents.
        let sequence_length = (4 + identifier.len() + encoded.len()) as i32;
        sequence.push(1u8);
        sequence.extend_from_slice(&sequence_length.to_le_bytes());
        sequence.extend_from_slice(identifier);
        sequence.extend_from_slice(&encoded);
        body.extend_from_slice(&sequence);
        let parsed = parse_op_msg(&body)?;
        let sequences = document_sequences(&parsed)?;
        assert_eq!(sequences.len(), 1);
        assert_eq!(sequences[0].0, "documents");
        assert_eq!(sequences[0].1, vec![payload]);
        Ok(())
    }

    #[test]
    fn checksum_section_is_stripped_and_flag_cleared() -> Outcome {
        let mut body = op_msg_body(FLAG_CHECKSUM, &sample_document())?;
        body.extend_from_slice(&[1, 2, 3, 4]);
        let parsed = parse_op_msg(&body)?;
        assert_eq!(parsed.flags & FLAG_CHECKSUM, 0);
        assert_eq!(kind_zero_document(&parsed.sections)?, sample_document());
        Ok(())
    }

    #[test]
    fn more_to_come_flag_is_reported() -> Outcome {
        let body = op_msg_body(FLAG_MORE_TO_COME, &sample_document())?;
        assert!(parse_op_msg(&body)?.more_to_come);
        Ok(())
    }

    #[test]
    fn message_roundtrip_preserves_header_fields() -> Outcome {
        let message = Message {
            request_id: 7,
            response_to: 9,
            opcode: OPCODE_MSG,
            body: op_msg_body(0, &sample_document())?,
        };
        let parsed = parse(&message.into_bytes())?;
        assert_eq!(parsed.request_id, 7);
        assert_eq!(parsed.response_to, 9);
        assert_eq!(parsed.opcode, OPCODE_MSG);
        Ok(())
    }

    #[test]
    fn legacy_reply_has_a_single_wire_header_and_twenty_byte_prefix() -> Outcome {
        let document = sample_document();
        let body = op_reply_body(&document)?;
        assert_eq!(&body[..16], &[0u8; 16]);
        assert_eq!(&body[16..20], &1i32.to_le_bytes());
        assert_eq!(
            bson::Document::from_reader(&body[20..]).map_err(|_| Error::Invalid)?,
            document
        );
        let frame = Message {
            request_id: 7,
            response_to: 9,
            opcode: crate::OPCODE_REPLY,
            body,
        }
        .into_bytes();
        assert_eq!(
            frame.len(),
            HEADER_LEN + 20 + bson::to_vec(&document).map_err(|_| Error::Invalid)?.len()
        );
        Ok(())
    }

    #[test]
    fn short_frame_is_rejected() {
        assert!(matches!(parse(&[0u8; 8]), Err(Error::Invalid)));
    }
}
