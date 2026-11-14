#!/usr/bin/env python3
"""Execute generated visibility SQL against a local MySQL 8 test server.

Two transports are supported:
- By default, `docker compose exec` into the `mysql` service managed by
  test/local/docker-compose.yml (start it with `make local-up`).
- With FG_TEST_MYSQL_HOST set, a TCP connection through a local `mysql`
  client; this is the GitHub Actions service-container path. The password is
  taken from FG_TEST_MYSQL_PASSWORD (or FG_TEST_MYSQL_ROOT_PASSWORD) and
  passed via MYSQL_PWD so it never appears on the command line.
"""

import os
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "test/local/docker-compose.yml"


def run(arguments, **kwargs):
    return subprocess.run(
        arguments, check=True, text=True, capture_output=True, cwd=ROOT, **kwargs
    ).stdout


def mysql_tcp_command():
    host = os.environ.get("FG_TEST_MYSQL_HOST")
    if host is None:
        return None
    if shutil.which("mysql") is None:
        raise SystemExit("FG_TEST_MYSQL_HOST is set but the mysql client is not on PATH")
    password = os.environ.get("FG_TEST_MYSQL_PASSWORD") or os.environ.get(
        "FG_TEST_MYSQL_ROOT_PASSWORD"
    )
    if not password:
        raise SystemExit("Set FG_TEST_MYSQL_PASSWORD or FG_TEST_MYSQL_ROOT_PASSWORD")
    return [
        "mysql",
        "--default-character-set=utf8mb4",
        "-h", host,
        "-P", os.environ.get("FG_TEST_MYSQL_PORT", "3306"),
        "-u", os.environ.get("FG_TEST_MYSQL_USER", "root"),
    ], {"MYSQL_PWD": password}


def mysql_exec_command():
    for executable in ["docker"]:
        if shutil.which(executable) is None:
            raise SystemExit("Missing docker; start the local environment with `make local-up`")
    inner = (
        'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql --default-character-set=utf8mb4 -uroot'
    )
    return ["docker", "compose", "-f", str(COMPOSE_FILE), "exec", "-T", "mysql", "sh", "-c", inner], None


def main():
    for executable in ["cargo"]:
        if shutil.which(executable) is None:
            raise SystemExit(f"Missing {executable}; Rust 1.94.1 is pinned by rust-toolchain.toml")

    relation = run([
        "cargo", "run", "--locked", "--quiet", "-p", "fg-rewrite",
        "--example", "visible_relation", "--", "mysql",
    ]).strip()
    # Replace only the marker site; the header comment must not spell the
    # marker literal, or the generated SQL would be injected into the comment.
    sql = (ROOT / "test/rewrite/mysql.sql").read_text().replace(
        "-- GENERATED_VISIBLE_RELATION", relation, 1
    )

    command, extra_env = mysql_tcp_command() or mysql_exec_command()
    environment = None if extra_env is None else {**os.environ, **extra_env}
    output = run(command + ["--table"], input=sql, env=environment)
    version = run(command + ["-N", "-e", "SELECT VERSION()"], env=environment).strip()
    print(version)
    print(output, end="")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.stderr or error.stdout or str(error)) from error
