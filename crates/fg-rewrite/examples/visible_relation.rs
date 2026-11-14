use fg_rewrite::{BranchId, Dialect, TableRef, TableShape, render_visible_relation};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let dialect = match arguments.as_slice() {
        [engine] if engine == "mysql" => Dialect::MySql,
        [engine] if engine == "postgres" => Dialect::PostgreSql,
        _ => {
            return Err(
                "Usage: cargo run -p fg-rewrite --example visible_relation -- mysql|postgres"
                    .into(),
            );
        }
    };
    let table = TableShape {
        base: TableRef {
            schema: "fg_g1",
            table: "orders",
        },
        delta: TableRef {
            schema: "forkget_delta",
            table: "_d_g1_t1",
        },
        columns: &["tenant_id", "id", "amount", "note"],
        primary_key: &["tenant_id", "id"],
    };
    println!(
        "{}",
        render_visible_relation(dialect, BranchId::new(7)?, &table)?
    );
    Ok(())
}
