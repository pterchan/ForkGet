//! Render the legacy four-table catalog and its supported net row changes.

use std::collections::HashSet;

use fg_protocol_common::GENERATED_ID_START;
use fg_rewrite::{Dialect, validate_dryrun_statement};
use serde::{Deserialize, Serialize};

use crate::{Error, dryrun::Engine};

const LOGICAL_SCHEMA: &str = "app";
const TABLES: [&str; 4] = ["orders", "customers", "parents", "children"];
const MAX_STATEMENTS: usize = 1_024;

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Table {
    pub(super) id: i64,
    schema: String,
    table: String,
    generated_key: Option<String>,
    columns: Vec<Column>,
    pub(super) changes: Vec<Change>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Column {
    name: String,
    type_name: String,
    nullable: bool,
    primary_key_ordinal: Option<u16>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Insert,
    Update,
    Delete,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Change {
    operation: Operation,
    key: Vec<String>,
    before: Option<Vec<Option<String>>>,
    after: Option<Vec<Option<String>>>,
}

impl Table {
    fn position(&self, name: &str) -> Result<usize, Error> {
        self.columns
            .iter()
            .position(|column| column.name == name)
            .ok_or(Error::ReplayArtifact)
    }
}

pub(super) fn statements(engine: Engine, tables: &[Table]) -> Result<Vec<String>, Error> {
    if tables.len() != TABLES.len() || !tables.windows(2).all(|pair| pair[0].id < pair[1].id) {
        return Err(Error::ReplayArtifact);
    }
    let mut reviewed = Vec::with_capacity(TABLES.len());
    for name in TABLES {
        let table = tables
            .iter()
            .find(|table| table.table == name)
            .ok_or(Error::ReplayArtifact)?;
        reviewed.push(ReviewedTable::new(engine, table)?);
    }
    let [orders, customers, parents, children] = reviewed.as_slice() else {
        return Err(Error::ReplayArtifact);
    };
    let mut sql = Vec::new();
    for table in [orders, customers] {
        for change in &table.table.changes {
            sql.push(table.render(change)?);
        }
    }
    render_family(parents, children, &mut sql)?;
    if sql.len() > MAX_STATEMENTS {
        return Err(Error::ReplayArtifact);
    }
    for statement in &sql {
        validate_dryrun_statement(engine.dialect(), statement, true)
            .map_err(|_| Error::ReplayArtifact)?;
    }
    Ok(sql)
}

struct ReviewedTable<'a> {
    engine: Engine,
    table: &'a Table,
    keys: Vec<usize>,
    relation: String,
}

impl<'a> ReviewedTable<'a> {
    fn new(engine: Engine, table: &'a Table) -> Result<Self, Error> {
        let mut names = HashSet::new();
        if table.id <= 0
            || table.schema != LOGICAL_SCHEMA
            || table.columns.is_empty()
            || table.columns.iter().any(|column| {
                !valid_identifier(&column.name)
                    || !names.insert(&column.name)
                    || !known_type(engine, &column.type_name)
            })
        {
            return Err(Error::ReplayArtifact);
        }
        let keys = ordered_keys(table)?;
        let dialect = engine.dialect();
        let relation = format!(
            "{}.{}",
            quote(dialect, &table.schema),
            quote(dialect, &table.table)
        );
        let reviewed = Self {
            engine,
            table,
            keys,
            relation,
        };
        reviewed.validate_changes()?;
        Ok(reviewed)
    }

    fn validate_changes(&self) -> Result<(), Error> {
        let generated = match (
            self.table.table.as_str(),
            self.table.generated_key.as_deref(),
        ) {
            ("parents", Some("id")) if self.keys.len() == 1 => {
                let index = self.table.position("id")?;
                if self.keys != [index] || self.table.columns[index].type_name != "bigint" {
                    return Err(Error::ReplayArtifact);
                }
                Some(index)
            }
            ("parents", _) | (_, Some(_)) => return Err(Error::ReplayArtifact),
            (_, None) => None,
        };
        let mut previous_key = None;
        for change in &self.table.changes {
            let key = self.validate_change(change)?;
            if previous_key
                .as_ref()
                .is_some_and(|previous| previous >= &key)
            {
                return Err(Error::ReplayArtifact);
            }
            if generated.is_some()
                && change.operation == Operation::Insert
                && !(1..GENERATED_ID_START).contains(&key[0])
            {
                return Err(Error::ReplayUnsupported);
            }
            previous_key = Some(key);
        }
        Ok(())
    }

    fn validate_change(&self, change: &Change) -> Result<Vec<i64>, Error> {
        match (change.operation, &change.before, &change.after) {
            (Operation::Insert, None, Some(_)) | (Operation::Delete, Some(_), None) => (),
            (Operation::Update, Some(before), Some(after)) if before != after => (),
            _ => return Err(Error::ReplayArtifact),
        }
        if change.key.len() != self.keys.len() {
            return Err(Error::ReplayArtifact);
        }
        for row in [change.before.as_ref(), change.after.as_ref()]
            .into_iter()
            .flatten()
        {
            if row.len() != self.table.columns.len()
                || self
                    .keys
                    .iter()
                    .zip(&change.key)
                    .any(|(&index, key)| row[index].as_ref() != Some(key))
            {
                return Err(Error::ReplayArtifact);
            }
            for (column, value) in self.table.columns.iter().zip(row) {
                literal(self.engine, column, value.as_deref())?;
            }
        }
        change
            .key
            .iter()
            .map(|key| key.parse().map_err(|_| Error::ReplayArtifact))
            .collect()
    }

    fn render(&self, change: &Change) -> Result<String, Error> {
        match (&change.before, &change.after) {
            (None, Some(after)) => self.insert(after, None),
            (Some(before), Some(after)) => self.update(
                change,
                before
                    .iter()
                    .zip(after)
                    .enumerate()
                    .filter_map(|(index, (old, new))| {
                        (old != new).then_some((index, new.as_deref()))
                    }),
            ),
            (Some(_), None) => Ok(format!(
                "DELETE FROM {} WHERE {}",
                self.relation,
                self.where_key(change)?
            )),
            _ => Err(Error::ReplayArtifact),
        }
    }

    fn insert(&self, after: &[Option<String>], force_null: Option<usize>) -> Result<String, Error> {
        let mut columns = Vec::new();
        let mut values = Vec::new();
        for (index, (column, value)) in self.table.columns.iter().zip(after).enumerate() {
            columns.push(quote(self.engine.dialect(), &column.name));
            let value = if force_null == Some(index) {
                None
            } else {
                value.as_deref()
            };
            values.push(literal(self.engine, column, value)?);
        }
        Ok(format!(
            "INSERT INTO {} ({}) VALUES ({})",
            self.relation,
            columns.join(", "),
            values.join(", ")
        ))
    }

    fn update<'b>(
        &self,
        change: &Change,
        values: impl Iterator<Item = (usize, Option<&'b str>)>,
    ) -> Result<String, Error> {
        let mut assignments = Vec::new();
        for (index, value) in values {
            let column = &self.table.columns[index];
            if column.primary_key_ordinal.is_some() {
                return Err(Error::ReplayArtifact);
            }
            assignments.push(format!(
                "{} = {}",
                quote(self.engine.dialect(), &column.name),
                literal(self.engine, column, value)?
            ));
        }
        if assignments.is_empty() {
            return Err(Error::ReplayArtifact);
        }
        Ok(format!(
            "UPDATE {} SET {} WHERE {}",
            self.relation,
            assignments.join(", "),
            self.where_key(change)?
        ))
    }

    fn where_key(&self, change: &Change) -> Result<String, Error> {
        self.keys
            .iter()
            .zip(&change.key)
            .map(|(&index, key)| {
                let column = &self.table.columns[index];
                Ok(format!(
                    "{} = {}",
                    quote(self.engine.dialect(), &column.name),
                    literal(self.engine, column, Some(key))?
                ))
            })
            .collect::<Result<Vec<_>, Error>>()
            .map(|terms| terms.join(" AND "))
    }
}

fn render_family(
    parents: &ReviewedTable<'_>,
    children: &ReviewedTable<'_>,
    sql: &mut Vec<String>,
) -> Result<(), Error> {
    let tenant = parents.table.position("tenant_id")?;
    let code = parents.table.position("code")?;
    let link = parents.table.position("parent_code")?;
    let mut inserts = Vec::new();
    let mut updates = Vec::new();
    let mut deletes = Vec::new();
    for change in &parents.table.changes {
        match (&change.before, &change.after) {
            (None, Some(after)) => inserts.push((change, after)),
            (Some(before), Some(after))
                if [tenant, code].iter().all(|&i| before[i] == after[i]) =>
            {
                updates.push(change)
            }
            (Some(_), Some(_)) => return Err(Error::ReplayUnsupported),
            (Some(before), None) => deletes.push((change, before)),
            _ => return Err(Error::ReplayArtifact),
        }
    }
    if !inserts.is_empty() && !deletes.is_empty() {
        return Err(Error::ReplayUnsupported);
    }
    // Install every new locator before connecting its nullable self-reference.
    for (_, row) in &inserts {
        sql.push(parents.insert(row, Some(link))?);
    }
    for change in updates {
        sql.push(parents.render(change)?);
    }
    for (change, row) in inserts {
        if let Some(target) = row[link].as_deref() {
            sql.push(parents.update(change, std::iter::once((link, Some(target))))?);
        }
    }
    // Resolve child moves and deletes before any native delete cascade.
    for change in &children.table.changes {
        sql.push(children.render(change)?);
    }
    for (change, row) in &deletes {
        if row[link].is_some() {
            sql.push(parents.update(change, std::iter::once((link, None)))?);
        }
    }
    for (change, _) in deletes {
        sql.push(parents.render(change)?);
    }
    Ok(())
}

fn ordered_keys(table: &Table) -> Result<Vec<usize>, Error> {
    let mut keys = table
        .columns
        .iter()
        .enumerate()
        .filter_map(|(index, column)| Some((column.primary_key_ordinal?, index)))
        .collect::<Vec<_>>();
    keys.sort_unstable();
    if keys.is_empty()
        || keys.iter().enumerate().any(|(offset, &(ordinal, index))| {
            let column = &table.columns[index];
            usize::from(ordinal) != offset + 1
                || column.nullable
                || !matches!(column.type_name.as_str(), "int" | "integer" | "bigint")
        })
    {
        return Err(Error::ReplayArtifact);
    }
    Ok(keys.into_iter().map(|(_, index)| index).collect())
}

fn valid_identifier(identifier: &str) -> bool {
    let mut bytes = identifier.bytes();
    identifier.len() <= 63
        && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn quote(dialect: Dialect, identifier: &str) -> String {
    match dialect {
        Dialect::MySql => format!("`{identifier}`"),
        Dialect::PostgreSql => format!("\"{identifier}\""),
    }
}

fn known_type(engine: Engine, kind: &str) -> bool {
    match engine {
        Engine::Mysql | Engine::Tidb => matches!(
            kind,
            "int" | "bigint" | "decimal(12,2)" | "varchar(64)" | "varbinary(16)"
        ),
        Engine::Postgresql => matches!(
            kind,
            "integer" | "bigint" | "numeric(12,2)" | "character varying(64)" | "bytea"
        ),
    }
}

fn literal(engine: Engine, column: &Column, value: Option<&str>) -> Result<String, Error> {
    let Some(value) = value else {
        return column
            .nullable
            .then_some("NULL".to_owned())
            .ok_or(Error::ReplayArtifact);
    };
    match column.type_name.as_str() {
        "int" | "integer"
            if value
                .parse::<i32>()
                .is_ok_and(|number| number.to_string() == value) =>
        {
            Ok(value.to_owned())
        }
        "bigint"
            if value
                .parse::<i64>()
                .is_ok_and(|number| number.to_string() == value) =>
        {
            Ok(value.to_owned())
        }
        "decimal(12,2)" | "numeric(12,2)" if decimal(value) => Ok(value.to_owned()),
        "varchar(64)" | "character varying(64)" if value.chars().count() <= 64 => {
            string_literal(engine, value)
        }
        "varbinary(16)" if value.len() <= 32 && hex(value) => Ok(format!("X'{value}'")),
        "bytea" if hex(value) => Ok(format!("'\\x{value}'")),
        _ => Err(Error::ReplayArtifact),
    }
}

fn decimal(value: &str) -> bool {
    let value = value.strip_prefix('-').unwrap_or(value);
    let Some((whole, fraction)) = value.split_once('.') else {
        return false;
    };
    (1..=10).contains(&whole.len())
        && whole.bytes().all(|byte| byte.is_ascii_digit())
        && fraction.len() == 2
        && fraction.bytes().all(|byte| byte.is_ascii_digit())
}

fn hex(value: &str) -> bool {
    value.len().is_multiple_of(2)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn string_literal(engine: Engine, value: &str) -> Result<String, Error> {
    let mut sql = String::from("'");
    for character in value.chars() {
        match (engine, character) {
            (_, '\'') => sql.push_str("''"),
            (Engine::Mysql | Engine::Tidb, '\\') => sql.push_str(r"\\"),
            (Engine::Mysql | Engine::Tidb, '\0') => sql.push_str(r"\0"),
            (Engine::Mysql | Engine::Tidb, '\n') => sql.push_str(r"\n"),
            (Engine::Mysql | Engine::Tidb, '\r') => sql.push_str(r"\r"),
            (Engine::Mysql | Engine::Tidb, '\t') => sql.push_str(r"\t"),
            (Engine::Mysql | Engine::Tidb, '\u{001a}') => sql.push_str(r"\Z"),
            (Engine::Postgresql, '\0') => return Err(Error::ReplayArtifact),
            (_, character) => sql.push(character),
        }
    }
    sql.push('\'');
    Ok(sql)
}
