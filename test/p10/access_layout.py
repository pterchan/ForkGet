#!/usr/bin/env python3
"""Exercise the real pre-0014 upgrade and immutable storage contract on PostgreSQL."""

import json
import pathlib
import subprocess
import time
import uuid


ROOT = pathlib.Path(__file__).resolve().parents[2]


def run(*arguments, sql=None):
    return subprocess.run(arguments, input=sql, text=True, capture_output=True, check=True).stdout.strip()


def main():
    container = "fg-p10-access-" + uuid.uuid4().hex[:12]
    run("docker", "run", "--detach", "--rm", "--name", container, "--network", "none",
        "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "postgres:16.14")

    def execute(sql):
        return run("docker", "exec", "-i", container, "psql", "-X", "-qAt",
                   "-v", "ON_ERROR_STOP=1", "-h", "127.0.0.1", "-U", "postgres", sql=sql)

    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                execute("SELECT 1;")
                break
            except subprocess.CalledProcessError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.2)
        migrations = sorted((ROOT / "crates/fg-meta/migrations").glob("*.sql"))
        for path in migrations:
            if int(path.name.split("_", 1)[0]) >= 14:
                break
            execute(path.read_text())
        execute("""
            INSERT INTO generation (engine,status,snapshot) VALUES
                ('mysql','failed','v2'), ('postgresql','failed','v2'),
                ('tidb','failed','v2'), ('mongodb','failed','v2');
            INSERT INTO branch (name,class,generation_id,created_by,expires_at,status,mode,native_claimed)
            VALUES ('old-sql-read','dev',2,'alice',now()+interval '1 hour','active','read_only',false),
                ('old-mongo-read','dev',4,'alice',now()+interval '1 hour','active','read_only',false),
                ('old-mongo-stage','staging',4,'alice',now()+interval '1 hour','active','read_only',false),
                ('old-native-copy','dev',1,'alice',now()+interval '1 hour','active','native_write',true),
                ('old-copy-pending','ci',3,'alice',now()+interval '1 hour','provisioning','native_write',false);
        """)
        execute((ROOT / "crates/fg-meta/migrations/0014_branch_access_layout.sql").read_text())
        observed = execute("SELECT name,access,layout,read_strategy,native_claimed FROM branch ORDER BY name;")
        assert observed.splitlines() == [
            "old-copy-pending|read_write|native_copy|merge|f",
            "old-mongo-read|read_write|sparse_delta|merge|f",
            "old-mongo-stage|read_only|sparse_delta|merge|f",
            "old-native-copy|read_write|native_copy|merge|t",
            "old-sql-read|read_only|sparse_delta|merge|f",
        ], observed
        execute("""
            INSERT INTO branch (name,class,generation_id,created_by,expires_at,status)
            SELECT 'new-read-'||engine,'dev',id,'alice',now()+interval '1 hour','active' FROM generation;
            INSERT INTO branch (name,class,generation_id,created_by,expires_at,status,read_strategy)
            SELECT 'new-base-'||engine,'dev',id,'alice',now()+interval '1 hour','active','base_only'
            FROM generation WHERE engine <> 'mongodb';
            INSERT INTO branch (name,class,generation_id,created_by,expires_at,status,mode)
            VALUES ('new-native-copy','dev',1,'alice',now()+interval '1 hour','provisioning','native_write');
        """)
        assert execute("SELECT count(*) FROM branch WHERE name LIKE 'new-read-%' AND access='read_only' AND layout='sparse_delta' AND read_strategy='merge';") == "4"
        assert execute("SELECT count(*) FROM branch WHERE read_strategy='base_only';") == "3"
        assert execute("SELECT access||':'||layout FROM branch WHERE name='new-native-copy';") == "read_write:native_copy"
        for invalid in [
            "UPDATE branch SET access='read_write' WHERE name='old-sql-read'",
            "UPDATE branch SET read_strategy='base_only' WHERE name='old-sql-read'",
            "UPDATE branch SET layout='native_copy' WHERE name='old-mongo-read'",
            "INSERT INTO branch(name,class,generation_id,created_by,expires_at,status,read_strategy) VALUES('invalid-mongo','dev',4,'alice',now()+interval '1 hour','active','base_only')",
            "INSERT INTO branch(name,class,generation_id,created_by,expires_at,status,access) VALUES('invalid-sql','dev',2,'alice',now()+interval '1 hour','active','read_write')",
            "INSERT INTO branch(name,class,generation_id,created_by,expires_at,status,access) VALUES('invalid-stage','staging',4,'alice',now()+interval '1 hour','active','read_write')",
        ]:
            execute("DO $$ BEGIN BEGIN " + invalid + "; RAISE EXCEPTION 'invalid contract was accepted'; EXCEPTION WHEN check_violation THEN NULL; END; END $$;")
        # Storage invariants do not interfere with TTL/drop recovery updates.
        execute("UPDATE branch SET status='dropping' WHERE name='old-mongo-read'; UPDATE branch SET status='dropped' WHERE name='old-mongo-read';")
        print(json.dumps({"suite": "p10-access-layout-migration", "passed": True,
                          "cases": ["legacy_access_backfill", "legacy_storage_and_pending_state", "four_engine_defaults", "sql_base_only", "immutable_contract", "invalid_combinations", "drop_transition"]}))
    except subprocess.CalledProcessError as error:
        # This isolated fixture contains only synthetic DDL/test rows. Preserve
        # native diagnostics instead of losing a startup interruption cause.
        raise RuntimeError("Disposable migration fixture failed: " + error.stderr.strip()) from error
    finally:
        run("docker", "rm", "--force", container)


if __name__ == "__main__":
    main()
