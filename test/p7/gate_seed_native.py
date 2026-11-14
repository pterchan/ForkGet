#!/usr/bin/env python3
"""Run the actual gate-seed Rust module against disposable native SQL engines.

Run under Linux/WSL with Docker and Cargo. No retained database volumes or
Forkget services are used. The small harness compiles the production seed
module directly instead of reimplementing its loading and validation logic.
"""

import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
from urllib.parse import quote
import uuid

ROOT = Path(__file__).resolve().parents[2]
IMAGES = {"mysql": "mysql:8.0.43", "postgresql": "postgres:16.14", "tidb": "pingcap/tidb:v8.5.8"}


def call(args, **kwargs):
    return subprocess.run(args, text=True, capture_output=True, check=True, **kwargs)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def harness(directory):
    # Compile the unmodified module from the selected source checkout.
    # Only the crate-private native connection/error glue is supplied here.
    source = json.dumps(str(ROOT / "crates/fg-control/src/gate_seed.rs"))
    (directory / "src").mkdir()
    (directory / "Cargo.toml").write_text('''[package]
name = "fg-gate-seed-native-check"
version = "0.0.0"
edition = "2024"
[dependencies]
sqlx = { version = "=0.8.6", default-features = false, features = ["runtime-tokio", "mysql", "postgres", "macros", "tls-rustls-ring-native-roots"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
thiserror = "2.0.18"
tracing = "0.1"
tracing-subscriber = { version = "0.3", default-features = false, features = ["fmt", "json"] }
''', encoding="utf-8")
    (directory / "src/lib.rs").write_text('''#![allow(dead_code)]
#[derive(Debug, thiserror::Error)]
enum ControlError {
    #[error("Seed bootstrap refused: {0}")] Seed(&'static str),
    #[error("Native operation failed")] Native(#[from] sqlx::Error),
}
mod native {
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Engine { MySql, Postgres, TiDB, MongoDb }
    impl Engine {
        pub(crate) fn name(self) -> &'static str { match self {
            Self::MySql => "mysql", Self::Postgres => "postgresql",
            Self::TiDB => "tidb", Self::MongoDb => "mongodb",
        }}
    }
    pub(crate) enum Native {
        MySql(sqlx::MySqlConnection), Postgres(sqlx::PgConnection),
        TiDB(sqlx::MySqlConnection), Mongo(()),
    }
    impl Native {
        pub(crate) fn engine(&self) -> Engine { match self {
            Self::MySql(_) => Engine::MySql, Self::Postgres(_) => Engine::Postgres,
            Self::TiDB(_) => Engine::TiDB, Self::Mongo(_) => Engine::MongoDb,
        }}
    }
}
''' + f"#[path = {source}]\nmod gate_seed;\n", encoding="utf-8")
    shutil.copyfile(ROOT / "Cargo.lock", directory / "Cargo.lock")


def start(engine, name, password):
    environment = os.environ.copy()
    if engine == "mysql":
        environment["MYSQL_ROOT_PASSWORD"] = password
        options = ["--env", "MYSQL_ROOT_PASSWORD"]
        port, tail = 3306, []
    elif engine == "postgresql":
        environment.update(POSTGRES_PASSWORD=password, POSTGRES_DB="gate_seed", POSTGRES_USER="fg_seed")
        options = ["--env", "POSTGRES_PASSWORD", "--env", "POSTGRES_DB", "--env", "POSTGRES_USER"]
        port, tail = 5432, []
    else:
        options, port = [], 4000
        tail = ["--store=unistore", "--path=", "-P", "4000", "--status=10080"]
    call(["docker", "run", "-d", "--name", name, "-p", f"127.0.0.1::{port}", *options, IMAGES[engine], *tail], env=environment)
    host_port = call(["docker", "port", name, f"{port}/tcp"]).stdout.strip().rsplit(":", 1)[1]
    return host_port


def ready(engine, name, password):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if engine == "tidb":
            command = ["curl", "-sf", "http://127.0.0.1:10080/status"]
            arguments = ["docker", "exec", name, *command]
            environment = None
        elif engine == "postgresql":
            arguments = ["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "fg_seed", "-d", "gate_seed"]
            environment = None
        else:
            environment = os.environ | {"MYSQL_PWD": password}
            arguments = ["docker", "exec", "--env", "MYSQL_PWD", name, "mysql", "--no-defaults", "--protocol=TCP", "-h127.0.0.1", "-uroot", "-Nse", "SELECT 1"]
        if subprocess.run(arguments, env=environment, capture_output=True).returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError(f"{engine} did not become ready")


def run_engine(engine, directory, report):
    name = f"fg-t10-seed-{engine}-{uuid.uuid4().hex[:10]}"
    password = secrets.token_urlsafe(24)
    result = {"engine": engine, "image": IMAGES[engine], "status": "failed", "container": name}
    try:
        port = start(engine, name, password)
        ready(engine, name, password)
        if engine == "mysql":
            environment = os.environ | {"MYSQL_PWD": password}
            call(["docker", "exec", "--env", "MYSQL_PWD", name, "mysql", "--no-defaults", "-uroot", "-e", "CREATE DATABASE gate_seed CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci"], env=environment)
        elif engine == "tidb":
            # TiDB's built-in `test` database is private to this disposable container.
            pass
        user = "fg_seed" if engine == "postgresql" else "root"
        database = "test" if engine == "tidb" else "gate_seed"
        scheme = "postgresql" if engine == "postgresql" else "mysql"
        secret = "" if engine == "tidb" else quote(password, safe="")
        environment = os.environ | {"FG_GATE_SEED_NATIVE_ENGINE": engine,
                                   "FG_GATE_SEED_NATIVE_DSN": f"{scheme}://{user}:{secret}@127.0.0.1:{port}/{database}"}
        command = ["cargo", "test", "--offline", "--manifest-path", str(directory / "Cargo.toml"),
                   "gate_seed::tests::native_boundaries_and_corruption", "--", "--ignored", "--nocapture"]
        executed = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=900)
        (report / f"{engine}.log").write_text(executed.stdout + executed.stderr, encoding="utf-8")
        result.update(exit_code=executed.returncode, status="passed" if executed.returncode == 0 else "failed")
        if executed.returncode == 0 and engine in {"mysql", "tidb"}:
            test_name = "verify::tests::namespace_emptiness_uses_exact_schema_and_literal_prefix"
            namespace = subprocess.run(
                ["cargo", "test", "--offline", "--locked", "-p", "fg-control", "--bin", "fg-control",
                 test_name, "--", "--ignored", "--exact", "--nocapture"],
                cwd=ROOT, env=environment, text=True, capture_output=True, timeout=900,
            )
            output = namespace.stdout + namespace.stderr
            for value in [environment["FG_GATE_SEED_NATIVE_DSN"], password, secret]:
                if value:
                    output = output.replace(value, "[redacted]")
            (report / f"{engine}-namespace.log").write_text(output, encoding="utf-8")
            one_test = ("running 1 test" in namespace.stdout
                        and test_name in namespace.stdout
                        and "test result: ok. 1 passed; 0 failed; 0 ignored;" in namespace.stdout)
            result.update(namespace_exit_code=namespace.returncode, namespace_one_test_executed=one_test)
            result["status"] = "passed" if namespace.returncode == 0 and one_test else "failed"
    except Exception as error:
        # Never persist DSNs, credentials, or a subprocess argument dump.
        result["status"] = "failed"
        result["failure_category"] = type(error).__name__
    finally:
        removed = subprocess.run(["docker", "rm", "-f", "-v", name], text=True, capture_output=True)
        result["cleaned_up"] = removed.returncode == 0
    write_json(report / f"{engine}.json", result)
    print(json.dumps(result), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=[*IMAGES, "all"], default="all")
    parser.add_argument("--report-dir", type=Path, required=True)
    arguments = parser.parse_args()
    report = arguments.report_dir.resolve()
    report.mkdir(parents=True, exist_ok=False)
    write_json(report / "source.json", {"source_revision": call(["git", "rev-parse", "HEAD"], cwd=ROOT).stdout.strip(),
                                       "source_state": call(["git", "status", "--short"], cwd=ROOT).stdout.splitlines(),
                                       "started_at": datetime.now(UTC).isoformat(),
                                       "scope": "Actual Rust gate_seed load/verify, native boundaries and corruption; not a complete P7 gate"})
    (report / "gate-seed-source.rs").write_text((ROOT / "crates/fg-control/src/gate_seed.rs").read_text(), encoding="utf-8")
    (report / "gate-seed.patch").write_text(call(["git", "diff", "--", "crates/fg-control/src/gate_seed.rs", "test/p7/gate_fixture.py"], cwd=ROOT).stdout, encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="fg-gate-seed-harness-") as temporary:
        directory = Path(temporary)
        harness(directory)
        build = subprocess.run(["cargo", "test", "--offline", "--manifest-path", str(directory / "Cargo.toml"), "--no-run"],
                               text=True, capture_output=True, timeout=900)
        (report / "build.log").write_text(build.stdout + build.stderr, encoding="utf-8")
        if build.returncode:
            write_json(report / "report.json", {"status": "failed", "failure_category": "harness_build", "engines": []})
            raise SystemExit(1)
        results = [run_engine(engine, directory, report) for engine in (IMAGES if arguments.engine == "all" else [arguments.engine])]
    passed = all(result["status"] == "passed" and result["cleaned_up"] for result in results)
    write_json(report / "report.json", {"status": "passed" if passed else "failed", "engines": results})
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
