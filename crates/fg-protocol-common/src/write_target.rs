/// The operator-owned database for newly provisioned write branches on
/// engines that speak the MySQL wire protocol (MySQL and TiDB).
pub const MYSQL_WRITE_SCHEMA: &str = "fgwrite";

#[derive(Debug)]
pub struct WriteTarget {
    branch_id: i64,
    schema: String,
    prefix: Option<String>,
}

impl WriteTarget {
    /// Validate a physical binding obtained from the authenticated controller.
    /// MongoDB owns a whole per-branch database (`fg_b<id>`), so shared stays
    /// false and collections keep their logical names.
    pub fn new(engine: &str, id: i64, schema: &str) -> Option<Self> {
        if id <= 0 || !matches!(engine, "mysql" | "postgresql" | "tidb" | "mongodb") {
            return None;
        }
        let target = Self::for_branch(
            id,
            matches!(engine, "mysql" | "tidb") && schema == MYSQL_WRITE_SCHEMA,
        );
        (schema == target.schema).then_some(target)
    }

    pub fn for_branch(id: i64, uses_mysql_shared_schema: bool) -> Self {
        let namespace = format!("fg_b{id}");
        if uses_mysql_shared_schema {
            Self {
                branch_id: id,
                schema: MYSQL_WRITE_SCHEMA.to_owned(),
                prefix: Some(format!("{namespace}_")),
            }
        } else {
            Self {
                branch_id: id,
                schema: namespace,
                prefix: None,
            }
        }
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn branch_id(&self) -> i64 {
        self.branch_id
    }

    pub fn table(&self, logical: &str) -> String {
        match &self.prefix {
            Some(prefix) => format!("{prefix}{logical}"),
            None => logical.to_owned(),
        }
    }

    pub fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_only_the_registered_layout_and_branch_namespace() -> Result<(), &'static str> {
        for shared_engine in ["mysql", "tidb"] {
            let shared = WriteTarget::new(shared_engine, 17, MYSQL_WRITE_SCHEMA).ok_or("shared")?;
            assert_eq!(shared.table("parents"), "fg_b17_parents");
            assert_eq!(shared.prefix(), Some("fg_b17_"));
        }
        for engine in ["mysql", "postgresql", "tidb"] {
            let legacy = WriteTarget::new(engine, 17, "fg_b17").ok_or("branch schema")?;
            assert_eq!(legacy.table("parents"), "parents");
            assert_eq!(legacy.prefix(), None);
            assert!(WriteTarget::new(engine, 18, "fg_b17").is_none());
        }
        assert!(WriteTarget::new("postgresql", 17, MYSQL_WRITE_SCHEMA).is_none());
        // MongoDB owns the whole branch database.
        let mongo = WriteTarget::new("mongodb", 17, "fg_b17").ok_or("mongo branch db")?;
        assert_eq!(mongo.table("orders"), "orders");
        assert_eq!(mongo.prefix(), None);
        assert!(WriteTarget::new("mongodb", 17, MYSQL_WRITE_SCHEMA).is_none());
        assert!(WriteTarget::new("mongodb", 17, "fg_b18").is_none());
        assert!(WriteTarget::new("unknown", 17, MYSQL_WRITE_SCHEMA).is_none());
        assert!(WriteTarget::new("mysql", 0, MYSQL_WRITE_SCHEMA).is_none());
        Ok(())
    }
}
