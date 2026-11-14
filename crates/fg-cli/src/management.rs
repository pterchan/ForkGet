//! Owner management commands keep every mutation on the authenticated control API.

use clap::Subcommand;
use reqwest::Method;
use serde_json::{Value, json};

use crate::{Control, Error};

#[derive(Subcommand)]
pub(super) enum GitHubCommand {
    List {
        #[arg(long)]
        after: Option<String>,
    },
    Recreate {
        #[arg(long)]
        repository_id: i64,
        #[arg(long)]
        kind: String,
        #[arg(long)]
        source_key: String,
        #[arg(long)]
        expected_branch_id: i64,
    },
}

pub(super) async fn github(control: &Control, command: GitHubCommand) -> Result<Value, Error> {
    match command {
        GitHubCommand::List{after} => {
            let query=after.map(|value|vec![("after",value)]).unwrap_or_default();
            control.request_with_query(Method::GET,"v1/github/bindings",None,&query).await
        }
        GitHubCommand::Recreate{repository_id,kind,source_key,expected_branch_id} => {
            control.request(Method::POST,"v1/github/recreate",Some(json!({"repository_id":repository_id,
                "source_kind":kind,"source_key":source_key,"expected_branch_id":expected_branch_id}))).await
        }
    }
}

#[derive(Subcommand)]
pub(super) enum BudgetCommand {
    Request {
        #[arg(long)]
        id: i64,
        #[arg(long)]
        max_transaction_rows: u64,
        #[arg(long)]
        table_limit_bps: Option<u16>,
        #[arg(long, default_value_t = 10)]
        small_table_floor: u64,
        #[arg(long, default_value_t = 900)]
        for_seconds: u32,
        #[arg(long)]
        reason: String,
    },
    Inbox {
        #[arg(long, default_value = "pending")]
        state: String,
        #[arg(long)]
        after: Option<i64>,
    },
    Approve {
        #[arg(long)]
        id: i64,
        #[arg(long)]
        request_id: i64,
    },
    Deny {
        #[arg(long)]
        id: i64,
        #[arg(long)]
        request_id: i64,
    },
    Revoke {
        #[arg(long)]
        id: i64,
        #[arg(long)]
        grant_id: i64,
    },
}

pub(super) async fn budget(control: &Control, command: BudgetCommand) -> Result<Value, Error> {
    match command {
        BudgetCommand::Request {
            id,
            max_transaction_rows,
            table_limit_bps,
            small_table_floor,
            for_seconds,
            reason,
        } => control
            .request(
                Method::POST,
                &format!("v1/branches/{id}/budget-requests"),
                Some(json!({
                    "max_transaction_rows":max_transaction_rows,"table_limit_bps":table_limit_bps,
                    "small_table_floor":small_table_floor,"ttl_seconds":for_seconds,"reason":reason
                })),
            )
            .await,
        BudgetCommand::Inbox { state, after } => {
            let mut query = vec![("state", state)];
            if let Some(after) = after {
                query.push(("after", after.to_string()));
            }
            control
                .request_with_query(Method::GET, "v1/budget-requests", None, &query)
                .await
        }
        BudgetCommand::Approve { id, request_id } => review(control, id, request_id, true).await,
        BudgetCommand::Deny { id, request_id } => review(control, id, request_id, false).await,
        BudgetCommand::Revoke { id, grant_id } => {
            control
                .request(
                    Method::POST,
                    &format!("v1/branches/{id}/budget-grants/{grant_id}/revoke"),
                    Some(json!({})),
                )
                .await
        }
    }
}

async fn review(control: &Control, id: i64, request: i64, approve: bool) -> Result<Value, Error> {
    control
        .request(
            Method::POST,
            &format!("v1/branches/{id}/budget-requests/{request}/review"),
            Some(json!({"approve":approve})),
        )
        .await
}
