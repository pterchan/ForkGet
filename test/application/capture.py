#!/usr/bin/env python3
"""Capture the pinned dialect's real SQL on disposable native engines."""

import argparse
from contextlib import contextmanager
import json
from importlib.metadata import version
import pathlib
import secrets
import subprocess
import time
import uuid

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import URL

from business import Base, constraint_checks, exercise, observe, reflect, seed_source, typed_json


@contextmanager
def native(engine):
    name = "fg-orm-capture-" + uuid.uuid4().hex[:12]
    password = secrets.token_hex(16)
    port = 3306 if engine == "mysql" else 5432
    environment = (["MYSQL_ROOT_PASSWORD=" + password, "MYSQL_DATABASE=business"] if engine == "mysql"
                   else ["POSTGRES_PASSWORD=" + password, "POSTGRES_DB=business"])
    command = ["docker", "run", "--detach", "--rm", "--name", name, "-p", f"127.0.0.1::{port}"]
    for value in environment:
        command.extend(["-e", value])
    command.append("mysql:8.0.43" if engine == "mysql" else "postgres:16.14")
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
    try:
        mapping = json.loads(subprocess.check_output(["docker", "inspect", name]))[0]["NetworkSettings"]["Ports"]
        host_port = int(mapping[f"{port}/tcp"][0]["HostPort"])
        url = URL.create("mysql+pymysql" if engine == "mysql" else "postgresql+psycopg",
                         username="root" if engine == "mysql" else "postgres", password=password,
                         host="127.0.0.1", port=host_port, database="business")
        deadline = time.monotonic() + 100
        while True:
            db = create_engine(url)
            try:
                with db.connect() as connection:
                    connection.execute(text("SELECT 1"))
                break
            except Exception:
                db.dispose()
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.3)
        db.dispose()
        yield url
    finally:
        subprocess.run(["docker", "rm", "--force", name], check=True, stdout=subprocess.DEVNULL)


def capture(engine, output):
    with native(engine) as url:
        setup = create_engine(url)
        if engine == "postgresql":
            with setup.begin() as connection:
                connection.execute(text("CREATE SCHEMA business"))
                connection.execute(text("ALTER DATABASE business SET search_path TO business"))
        setup.dispose()
        setup = create_engine(url)
        Base.metadata.create_all(setup)
        seed_source(setup)
        setup.dispose()
        db = create_engine(url)
        statements = []

        @event.listens_for(db, "before_cursor_execute")
        def record(connection, cursor, statement, parameters, context, executemany):
            statements.append({"sql": statement, "executemany": executemany,
                               "parameter_names": sorted(parameters) if isinstance(parameters, dict) and len(parameters) < 100 else None,
                               "parameter_count": len(parameters)})

        @event.listens_for(db, "after_cursor_execute")
        def columns(connection, cursor, statement, parameters, context, executemany):
            statements[-1]["columns"] = [(item[0], item[1]) for item in cursor.description] if cursor.description else []

        try:
            result = exercise(db)
            state = observe(db)
            constraints = constraint_checks(db, state)
            schema = reflect(db)
        finally:
            db.dispose()
        unique = list({item["sql"]: item for item in statements}.values())
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps({"engine": engine,"versions":{name:version(name) for name in ("SQLAlchemy","PyMySQL","psycopg")},
                                     "result": result, "schema": schema,
                                     "constraints": constraints,"state":typed_json(state),"statements": unique}, indent=2))
        print(json.dumps({"engine": engine, "passed": True, "statements": len(statements),
                          "unique_sql": len(unique), "output": str(output)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("engine", choices=["mysql", "postgresql"])
    parser.add_argument("--output", type=pathlib.Path, required=True)
    options = parser.parse_args()
    capture(options.engine, options.output)
