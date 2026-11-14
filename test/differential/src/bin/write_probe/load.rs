//! Timed workloads over verified native or proxy SQL connections.

use std::{
    collections::BTreeSet,
    io::{self, Read},
    thread,
    time::{Duration, Instant},
};

use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Connection;
use tokio::{runtime::Builder, time::timeout};

use super::{Client, Operation, Request};

const MAX_PLAN_BYTES: u64 = 2 * 1024 * 1024;
const MAX_WORKERS: usize = 16;
const MAX_MEASUREMENT_SECONDS: u64 = 1_800;
const MAX_STATEMENTS_PER_SESSION: u32 = 512;
const LEASE: Duration = Duration::from_secs(1);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const INTERVAL: u64 = 60;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    warmup_seconds: u64,
    measure_seconds: u64,
    ca_pem: String,
    order_rows: u32,
    workers: Vec<Worker>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Worker {
    workload: Workload,
    targets: Vec<Target>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Workload {
    Point,
    Range,
    Insert,
    Update,
    Mixed,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    url: String,
    branch_id: Option<i64>,
    setup: Option<String>,
}

struct Measurement {
    elapsed_us: Vec<u32>,
    errors: u64,
    timeouts: u64,
    connection_errors: u64,
    warmup_errors: u64,
    writes: u64,
    failure: Option<String>,
    intervals: Vec<u64>,
    covered: BTreeSet<i64>,
}

impl Measurement {
    fn new(measure_seconds: u64) -> Self {
        Self {
            elapsed_us: Vec::new(),
            errors: 0,
            timeouts: 0,
            connection_errors: 0,
            warmup_errors: 0,
            writes: 0,
            failure: None,
            intervals: vec![0; measure_seconds.div_ceil(INTERVAL) as usize],
            covered: BTreeSet::new(),
        }
    }

    fn merge(&mut self, other: Self) {
        self.elapsed_us.extend(other.elapsed_us);
        self.errors += other.errors;
        self.timeouts += other.timeouts;
        self.connection_errors += other.connection_errors;
        self.warmup_errors += other.warmup_errors;
        self.writes += other.writes;
        if self.failure.is_none() {
            self.failure = other.failure;
        }
        for (total, count) in self.intervals.iter_mut().zip(other.intervals) {
            *total += count;
        }
        self.covered.extend(other.covered);
    }

    fn report(mut self, measure_seconds: u64) -> Value {
        self.elapsed_us.sort_unstable();
        let count = self.elapsed_us.len();
        let quantile = |percentile: usize| {
            let index = (count * percentile).div_ceil(100).checked_sub(1)?;
            Some(f64::from(*self.elapsed_us.get(index)?) / 1_000.0)
        };
        json!({
            "measure_seconds": measure_seconds, "successful": count,
            "qps": count as f64 / measure_seconds as f64,
            "p95_ms": quantile(95), "p99_ms": quantile(99),
            "errors": self.errors, "timeouts": self.timeouts,
            "connection_errors": self.connection_errors, "warmup_errors": self.warmup_errors,
            "first_failure": self.failure,
            "reads": count as u64 - self.writes, "writes": self.writes,
            "successful_per_interval": self.intervals, "interval_seconds": INTERVAL,
            "covered_branch_ids": self.covered,
        })
    }
}

pub(super) fn run() -> Result<Value, Box<dyn std::error::Error>> {
    let mut body = Vec::new();
    io::stdin()
        .lock()
        .take(MAX_PLAN_BYTES + 1)
        .read_to_end(&mut body)?;
    if body.len() as u64 > MAX_PLAN_BYTES {
        return Err("load plan exceeds its input limit".into());
    }
    let plan: Plan = serde_json::from_slice(&body).map_err(|_| "invalid timed load plan")?;
    if !plan.is_valid() {
        return Err("timed load plan is outside the workload limits".into());
    }
    let start = Instant::now();
    let warm_end = start + Duration::from_secs(plan.warmup_seconds);
    let end = warm_end + Duration::from_secs(plan.measure_seconds);
    let ca = plan.ca_pem.as_bytes();
    let measurement = thread::scope(|scope| -> Result<_, Box<dyn std::error::Error>> {
        let mut measurement = Measurement::new(plan.measure_seconds);
        let mut tasks = Vec::with_capacity(plan.workers.len());
        for (index, worker) in plan.workers.into_iter().enumerate() {
            let window = Window {
                index: index as u64,
                order_rows: plan.order_rows,
                warm_end,
                end,
                measure_seconds: plan.measure_seconds,
            };
            tasks.push(scope.spawn(move || {
                let runtime = Builder::new_current_thread().enable_all().build()?;
                Ok::<_, io::Error>(runtime.block_on(work(worker, window, ca)))
            }));
        }
        for task in tasks {
            measurement.merge(task.join().map_err(|_| "load worker did not complete")??);
        }
        Ok(measurement)
    })?;
    Ok(measurement.report(plan.measure_seconds))
}

impl Plan {
    fn is_valid(&self) -> bool {
        self.warmup_seconds <= 60
            && (1..=MAX_MEASUREMENT_SECONDS).contains(&self.measure_seconds)
            && !self.ca_pem.is_empty()
            && (1..=20_000_000).contains(&self.order_rows)
            && (1..=MAX_WORKERS).contains(&self.workers.len())
            && self.workers.iter().all(|worker| {
                (1..=1_000).contains(&worker.targets.len())
                    && worker.targets.iter().all(|target| {
                        target.branch_id.is_none_or(|id| id > 0)
                            && ["mysql://", "postgres://", "postgresql://"]
                                .iter()
                                .any(|scheme| target.url.starts_with(scheme))
                    })
            })
    }
}

struct Window {
    index: u64,
    order_rows: u32,
    warm_end: Instant,
    end: Instant,
    measure_seconds: u64,
}

async fn work(worker: Worker, window: Window, ca: &[u8]) -> Measurement {
    let mut measurement = Measurement::new(window.measure_seconds);
    let mut index = 0;
    for target in worker.targets.iter().cycle() {
        if Instant::now() >= window.end {
            break;
        }
        let mut client = match timeout(REQUEST_TIMEOUT, connect(target, ca)).await {
            Ok(Ok(client)) => client,
            _ => {
                measurement.connection_errors += 1;
                measurement.failure = Some("TLS connection or setup failed".to_owned());
                break;
            }
        };
        let now = Instant::now();
        let end = if worker.targets.len() > 1 {
            (now + LEASE).min(window.end)
        } else {
            window.end
        };
        if !session(
            &mut client,
            &window,
            &worker,
            target,
            end,
            &mut index,
            &mut measurement,
        )
        .await
        {
            break;
        }
        let _ = timeout(REQUEST_TIMEOUT, close(client)).await;
    }
    measurement
}

async fn connect(target: &Target, ca: &[u8]) -> Result<Client, sqlx::Error> {
    let mut client = Client::connect_with_pem(&target.url, ca.to_vec()).await?;
    if let Some(setup) = &target.setup {
        client
            .query(Request {
                op: Operation::Text,
                sql: setup.clone(),
                params: Vec::new(),
            })
            .await?;
    }
    Ok(client)
}

async fn close(client: Client) -> Result<(), sqlx::Error> {
    match client {
        Client::MySql(connection) => connection.close().await,
        Client::Postgres(connection) => connection.close().await,
    }
}

async fn session(
    client: &mut Client,
    window: &Window,
    worker: &Worker,
    target: &Target,
    end: Instant,
    index: &mut u64,
    measurement: &mut Measurement,
) -> bool {
    for _ in 0..MAX_STATEMENTS_PER_SESSION {
        let start = Instant::now();
        if start >= end {
            break;
        }
        let request = worker
            .workload
            .statement(*index, window.index, window.order_rows);
        let is_write = matches!(request.op, Operation::Text);
        *index += 1;
        let result = timeout(REQUEST_TIMEOUT, client.query(request)).await;
        let finished = Instant::now();
        match result {
            Ok(Ok(_)) if start >= window.warm_end && finished < window.end => {
                let elapsed = u32::try_from((finished - start).as_micros()).unwrap_or(u32::MAX);
                measurement.elapsed_us.push(elapsed);
                measurement.writes += u64::from(is_write);
                let interval = (finished - window.warm_end).as_secs() / INTERVAL;
                measurement.intervals[interval as usize] += 1;
                measurement.covered.extend(target.branch_id);
            }
            Ok(Ok(_)) => (),
            _ => {
                measurement.failure = Some(match &result {
                    Ok(Err(error)) => error
                        .as_database_error()
                        .and_then(|error| error.code())
                        .map_or_else(|| "transport".to_owned(), |code| code.into_owned()),
                    _ => "timeout".to_owned(),
                });
                if start < window.warm_end {
                    measurement.warmup_errors += 1;
                } else if result.is_err() {
                    measurement.timeouts += 1;
                } else {
                    measurement.errors += 1;
                }
                return false;
            }
        }
    }
    true
}

impl Workload {
    fn statement(self, index: u64, worker: u64, order_rows: u32) -> Request {
        let workload = match (self, index % 10) {
            (Self::Mixed, 7) => Self::Range,
            (Self::Mixed, 8) => Self::Insert,
            (Self::Mixed, 9) => Self::Update,
            (Self::Mixed, _) => Self::Point,
            _ => self,
        };
        let key = 1 + (index.wrapping_mul(104_729) + worker * 7919) % u64::from(order_rows);
        let (op, sql) = match workload {
            Self::Point | Self::Mixed => (
                Operation::Read,
                format!("SELECT tenant_id,id,note FROM orders WHERE tenant_id=7 AND id={key}"),
            ),
            Self::Range => (
                Operation::Read,
                format!(
                    "SELECT tenant_id,id,note FROM orders WHERE tenant_id=7 AND id>={key} ORDER BY tenant_id,id LIMIT 20"
                ),
            ),
            Self::Insert => {
                let new_key = (worker + 1) * 1_000_000_000 + index;
                (
                    Operation::Text,
                    format!(
                        "INSERT INTO orders (tenant_id,id,customer_id,amount,note) VALUES (9,{new_key},10,12.34,'gate-load')"
                    ),
                )
            }
            Self::Update => (
                Operation::Text,
                format!(
                    "UPDATE orders SET note='gate-load-{}' WHERE tenant_id=7 AND id={key}",
                    index % 2
                ),
            ),
        };
        Request {
            op,
            sql,
            params: Vec::new(),
        }
    }
}
