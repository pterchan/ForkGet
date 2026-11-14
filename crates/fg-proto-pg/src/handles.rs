//! Keep frontend handle names out of the private backend namespace.

use std::{collections::HashMap, io};

use crate::wire::{Frame, backend_error, cstring, take_string};

#[derive(Default)]
pub(super) struct Handles {
    statements: HashMap<String, String>,
    portals: HashMap<String, String>,
    serial: u64,
}

pub(super) enum Change {
    Statement(String, String),
    Portal(String, String),
    CloseStatement(String),
    ClosePortal(String),
}

impl Handles {
    /// Allocate names before sending, but publish them only after native success.
    pub(super) fn prepare(&mut self, frame: &mut Frame) -> io::Result<Option<Change>> {
        let mut rest = frame.body.as_slice();
        let mut body = Vec::new();
        let change = match frame.tag {
            b'P' => {
                let name = take_string(&mut rest)?;
                let native = self.statement(name, true)?;
                cstring(&mut body, &native);
                Some(Change::Statement(name.to_owned(), native))
            }
            b'B' => {
                let name = take_string(&mut rest)?;
                let statement = take_string(&mut rest)?;
                let native = self.portal(name, true)?;
                let native_statement = self.statement(statement, false)?;
                cstring(&mut body, &native);
                cstring(&mut body, &native_statement);
                Some(Change::Portal(name.to_owned(), native))
            }
            b'E' => {
                let name = take_string(&mut rest)?;
                cstring(&mut body, &self.portal(name, false)?);
                None
            }
            b'C' | b'D' => {
                let (&kind, remaining) = rest.split_first().ok_or_else(backend_error)?;
                rest = remaining;
                let name = take_string(&mut rest)?;
                body.push(kind);
                let native = match kind {
                    b'S' => self.statement(name, false)?,
                    b'P' => self.portal(name, false)?,
                    _ => return Err(backend_error()),
                };
                cstring(&mut body, &native);
                match (frame.tag, kind) {
                    (b'C', b'S') => Some(Change::CloseStatement(name.to_owned())),
                    (b'C', b'P') => Some(Change::ClosePortal(name.to_owned())),
                    _ => None,
                }
            }
            _ => return Ok(None),
        };
        body.extend_from_slice(rest);
        frame.body = body;
        Ok(change)
    }

    pub(super) fn complete(&mut self, change: Option<Change>) {
        match change {
            Some(Change::Statement(name, native)) => {
                if !name.is_empty() {
                    self.statements.insert(name, native);
                }
            }
            Some(Change::Portal(name, native)) => {
                if !name.is_empty() {
                    self.portals.insert(name, native);
                }
            }
            Some(Change::CloseStatement(name)) => {
                self.statements.remove(&name);
            }
            Some(Change::ClosePortal(name)) => {
                self.portals.remove(&name);
            }
            None => (),
        }
    }

    pub(super) fn clear_portals(&mut self) {
        self.portals.clear();
    }

    pub(super) fn clear_statements(&mut self) {
        self.statements.clear();
    }

    fn statement(&mut self, name: &str, creating: bool) -> io::Result<String> {
        if name.is_empty() {
            return Ok(String::new());
        }
        if let Some(native) = self.statements.get(name) {
            return Ok(native.clone());
        }
        self.allocate(if creating { "s" } else { "missing" })
    }

    fn portal(&mut self, name: &str, creating: bool) -> io::Result<String> {
        if name.is_empty() {
            return Ok(String::new());
        }
        if let Some(native) = self.portals.get(name) {
            return Ok(native.clone());
        }
        self.allocate(if creating { "p" } else { "missing" })
    }

    fn allocate(&mut self, kind: &str) -> io::Result<String> {
        self.serial = self.serial.checked_add(1).ok_or_else(backend_error)?;
        Ok(format!("_fg_user_{kind}_{}", self.serial))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(tag: u8, names: &[&str], suffix: &[u8]) -> Frame {
        let mut body = Vec::new();
        for name in names {
            cstring(&mut body, name);
        }
        body.extend_from_slice(suffix);
        Frame { tag, body }
    }

    #[test]
    fn client_private_names_and_unknown_references_never_reach_private_handles() -> io::Result<()> {
        let mut handles = Handles::default();
        let mut parse = frame(b'P', &["_fg_witness_s", "SELECT 1"], &[0, 0]);
        let change = handles.prepare(&mut parse)?;
        let native = take_string(&mut parse.body.as_slice())?.to_owned();
        assert_ne!(native, "_fg_witness_s");
        assert!(native.len() < 63);
        handles.complete(change);
        let mut bind = frame(b'B', &["_fg_witness_p", "_fg_witness_s"], &[0; 6]);
        let change = handles.prepare(&mut bind)?;
        let mut rest = bind.body.as_slice();
        assert_ne!(take_string(&mut rest)?, "_fg_witness_p");
        assert_eq!(take_string(&mut rest)?, native);
        handles.complete(change);
        let mut close = frame(b'C', &["_fg_witness_s"], &[]);
        close.body.insert(0, b'S');
        let change = handles.prepare(&mut close)?;
        handles.complete(change);
        let mut describe = frame(b'D', &["_fg_witness_s"], &[]);
        describe.body.insert(0, b'S');
        handles.prepare(&mut describe)?;
        assert!(take_string(&mut &describe.body[1..])?.starts_with("_fg_user_missing_"));
        Ok(())
    }

    #[test]
    fn failed_parse_does_not_consume_capacity_and_unnamed_handles_are_preserved() -> io::Result<()>
    {
        let mut handles = Handles::default();
        for index in 0..1000 {
            let mut rejected = frame(b'P', &[&format!("rejected_{index}"), "SELECT )"], &[0, 0]);
            handles.prepare(&mut rejected)?;
        }
        assert!(handles.statements.is_empty());
        let mut unnamed = frame(b'B', &["", ""], &[0; 6]);
        let before = unnamed.body.clone();
        let change = handles.prepare(&mut unnamed)?;
        handles.complete(change);
        assert_eq!(unnamed.body, before);
        assert!(handles.portals.is_empty());
        handles.serial = u64::MAX;
        let mut parse = frame(b'P', &["next", "SELECT 1"], &[0, 0]);
        assert!(handles.prepare(&mut parse).is_err());
        Ok(())
    }
}
