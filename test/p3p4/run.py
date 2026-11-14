"""Run the native-write and snapshot lifecycle suite on disposable deployments."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
import importlib.util
import json
import os
from pathlib import Path
import platform
import secrets
import select
import socket
import subprocess
import sys
import tempfile
from threading import Event, Thread
import time

P2 = Path(__file__).resolve().parents[1] / "p2"
sys.path.append(str(P2))
spec = importlib.util.spec_from_file_location("run_p2", P2 / "run.py")
p2 = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = p2
spec.loader.exec_module(p2)
from run_p2 import OWNER_A, OWNER_B, ROOT, Failure, require, wait_until

from write_cases import Probe, begin, check_count, differential, disconnect_rollback, generated_cases, int64, seed_reference

ADMIN = "p34_branch_admin"
GENERATION_LOCK = 0x4647000000000001
MYSQL_WRITE_SCHEMA = "fgwrite"
TIDB_BRANCH_ADMIN_RIGHTS = "CREATE, DROP, ALTER, INDEX, REFERENCES, SELECT, INSERT, UPDATE, DELETE"
MYSQL_BRANCH_ADMIN_RIGHTS = TIDB_BRANCH_ADMIN_RIGHTS + ", TRIGGER"


class EngineRun(p2.EngineRun):
    def __init__(self, *args):
        super().__init__(*args)
        self.secret["branch_admin"] = secrets.token_hex(24)
        self.base_env["FG_BRANCH_ADMIN_USER"] = ADMIN
        self.layout = {}
        self.metadata_version = None

    def policy_account(self, user):
        return {"policy_admin": True} if user == OWNER_A else {}

    def set_policy(self, branch_class, max_rows, bps=None, approval=None, floor=None):
        path = f"/v1/policies/{branch_class}"
        token = self.owner_tokens[OWNER_A]
        status, body = self.request("GET", path, token)
        require(status == 200, "Could not read the current policy version")
        version = json.loads(body)["version"]
        status, body = self.request("PUT", path, token, {
            "expected_version": version, "max_transaction_rows": max_rows,
            "table_limit_bps": bps, "approval_after_rows": approval, "small_table_floor": floor,
        })
        require(status == 200, f"Could not configure test policy: {status} {body}")
        return json.loads(body)

    def native_roles(self):
        super().native_roles()
        if self.family == "mysql":
            self.native("SET GLOBAL partial_revokes = ON;")
            self.create_mysql_branch_admin()
            self.prepare_mysql_write_schema()
            require(self.native("SELECT @@GLOBAL.partial_revokes;") == "1",
                    "MySQL test requires the managed partial-revokes behavior")
        elif self.family == "tidb":
            # TiDB has no partial_revokes; the branch-admin recipe is the same
            # shared fgwrite layout without MySQL's partial-revoke assertion.
            self.create_mysql_branch_admin()
            self.prepare_mysql_write_schema()
        else:
            self.use_branch_admin_database(self.backend_database)
            self.native(f"CREATE ROLE {ADMIN} LOGIN PASSWORD '{self.secret['branch_admin']}'; "
                        f"GRANT CREATE ON DATABASE {self.backend_database} TO {ADMIN};")

    def use_branch_admin_database(self, database):
        self.base_env["FG_BRANCH_ADMIN_DSN"] = self.dsn(
            ADMIN, self.secret["branch_admin"], self.native_port, database)

    def create_mysql_branch_admin(self):
        self.native(f"CREATE USER '{ADMIN}'@'%' IDENTIFIED WITH caching_sha2_password "
                    f"BY '{self.secret['branch_admin']}' REQUIRE SSL;")

    def prepare_mysql_write_schema(self):
        rights = MYSQL_BRANCH_ADMIN_RIGHTS if self.family == "mysql" else TIDB_BRANCH_ADMIN_RIGHTS
        self.native(f"""
            CREATE SCHEMA {MYSQL_WRITE_SCHEMA} CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
            GRANT {rights} ON {MYSQL_WRITE_SCHEMA}.* TO '{ADMIN}'@'%' WITH GRANT OPTION;
        """)
        self.use_branch_admin_database(MYSQL_WRITE_SCHEMA)

    def metadata_role(self):
        super().metadata_role()
        self.metadata("""
            GRANT UPDATE (native_claimed) ON branch TO p2_meta_control;
            GRANT SELECT, INSERT, UPDATE ON generated_id_cursor TO p2_meta_control;
        """)

    def generation_command(self, label, *args, succeeds=True, timeout=45, cooldown=None):
        account = "postgres" if self.family == "postgresql" else "root"
        env = self.base_env | {
            "FG_BACKEND_CA": str(self.certs / "backend-ca.pem"), "FG_META_CA": str(self.certs / "backend-ca.pem"),
            "FG_META_DSN": self.dsn("postgres", self.secret["meta"], self.metadata_port, "forkget_meta", "postgresql"),
            "FG_BACKEND_ADMIN_DSN": self.dsn(account, self.secret["native"], self.native_port, "p2_native"),
        }
        if cooldown is not None:
            env["FG_REFRESH_COOLDOWN_SECONDS"] = str(cooldown)
        self.call(label, [self.executable("fg-control"), *args], env=env, log=True, succeeds=succeeds, timeout=timeout)

    def active(self):
        return int(self.metadata("SELECT id FROM generation WHERE status='active';"))

    def legacy_migration(self):
        if self.family == "tidb":
            # TiDB deployments have no pre-migration history; the legacy rows
            # this test replays predate the TiDB engine registration entirely.
            return
        migrations = sorted((ROOT / "crates/fg-meta/migrations").glob("*.sql"))
        initial = "\n".join(path.read_text(encoding="utf-8") for path in migrations[:2])
        upgrade = "\n".join(path.read_text(encoding="utf-8") for path in migrations[2:])
        migrated = self.metadata(f"""
            BEGIN;
            CREATE SCHEMA legacy_upgrade;
            SET LOCAL search_path TO legacy_upgrade;
            {initial}
            INSERT INTO generation (engine,status,native_claimed,activated_at)
                VALUES ('{self.engine}','active',true,now());
            INSERT INTO branch (name,class,generation_id,created_by,status,expires_at)
                VALUES ('legacy-read','dev',1,'{OWNER_A}','active',now()+INTERVAL '1 hour');
            {upgrade}
            SELECT b.id,b.mode,b.status,b.native_claimed,g.snapshot
                FROM branch b JOIN generation g ON g.id=b.generation_id WHERE b.name='legacy-read';
            ROLLBACK;
        """)
        require(migrated == "1|read_only|active|f|v1", "Forward migrations changed a persisted P2 branch")
        self.record("Forward migrations preserve an existing P2 branch ID, mode and active status")
        if self.family == "mysql":
            prior = "\n".join(path.read_text(encoding="utf-8") for path in migrations
                              if path.name < "0010_mysql_write_layout.sql")
            layout = (ROOT / "crates/fg-meta/migrations/0010_mysql_write_layout.sql").read_text(encoding="utf-8")
            migrated = self.metadata(f"""
                BEGIN;
                CREATE SCHEMA legacy_upgrade;
                SET LOCAL search_path TO legacy_upgrade;
                {prior}
                INSERT INTO generation (engine,status,native_claimed,activated_at,snapshot)
                    VALUES ('mysql','active',true,now(),'v2');
                INSERT INTO branch (name,class,generation_id,created_by,status,expires_at,mode,native_claimed)
                    SELECT 'legacy-' || state,'dev',1,'{OWNER_A}',state,now()+INTERVAL '1 hour','native_write',true
                    FROM unnest(ARRAY['active','provisioning','dropping']) AS state;
                {layout}
                SELECT id,status,uses_mysql_shared_schema FROM branch ORDER BY id;
                ROLLBACK;
            """)
            require(migrated == "1|active|f\n2|provisioning|f\n3|dropping|f",
                    "MySQL layout migration repinned an existing branch")
            self.record("Forward layout migration preserves existing MySQL writable branch IDs and states")

    def branch_status(self, branch):
        status, body = self.request("GET", f"/v1/branches/{branch['id']}", self.owner_tokens[OWNER_A])
        return json.loads(body)["status"] if status == 200 else None

    def fork(self, name, write=False, ttl=None, wait=True):
        args = ["--write"] if write else []
        if ttl is not None:
            args.extend(("--ttl-seconds", str(ttl)))
        started = time.monotonic()
        branch = self.cli(OWNER_A, "fork", name, *args)
        require(branch["mode"] == ("native_write" if write else "read_only"), "Branch mode was not persisted")
        if wait:
            wait_until(f"{name} activation", lambda: self.branch_status(branch) == "active")
        return branch, round((time.monotonic() - started) * 1000, 2)

    def note(self, probe, expected):
        placeholders = ("$1", "$2") if self.family == "postgresql" else ("?", "?")
        sql = f"SELECT note FROM app.orders WHERE tenant_id={placeholders[0]} AND id={placeholders[1]}"
        result = probe.sql(sql, "fetch", ({"i32": 1}, int64(1)))
        require(result.get("rows") == [[expected]], f"Wrong pinned snapshot rows: {result}")

    def schema_exists(self, schema):
        return self.native(f"SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='{schema}';") == "1"

    def branch_namespace(self, branch_id, *, legacy=False):
        namespace = f"fg_b{int(branch_id)}"
        if self.family in ("mysql", "tidb") and not legacy:
            return MYSQL_WRITE_SCHEMA, f"{namespace}_"
        return namespace, ""

    def branch_relation(self, branch_id, table, *, legacy=False):
        schema, prefix = self.branch_namespace(branch_id, legacy=legacy)
        return f"{schema}.{prefix}{table}"

    def branch_storage_exists(self, branch_id, *, legacy=False):
        schema, prefix = self.branch_namespace(branch_id, legacy=legacy)
        if prefix:
            return self.native("SELECT EXISTS (SELECT 1 FROM information_schema.tables "
                               f"WHERE table_schema='{schema}' AND LEFT(table_name,{len(prefix)})='{prefix}');") == "1"
        return self.schema_exists(schema)

    def snapshot_constraints(self, generation):
        count = self.native(f"""
            SELECT count(*) FROM information_schema.table_constraints
            WHERE table_schema='fg_g{generation}'
              AND constraint_name IN ('parents_code_key','parents_parent_fkey','children_parent_fkey','parents_label_key');
        """)
        require(count == ("4" if self.family == "postgresql" else "3"),
                "Activated snapshot lacks its registered native constraints")

    def stale_refresh(self):
        stale = int(self.metadata(f"""
            INSERT INTO generation (engine,status,snapshot,native_claimed)
                VALUES ('{self.engine}','importing','v2',true) RETURNING id;
        """))
        self.metadata(f"INSERT INTO refresh_job (target_generation_id,status,started_at) VALUES ({stale},'running',now());")
        table = int(self.metadata(f"""
            INSERT INTO catalog_table (generation_id,logical_schema,logical_table,base_table)
                VALUES ({stale},'app','unfinished','unfinished') RETURNING id;
        """))
        self.metadata(f"""
            INSERT INTO catalog_column (table_id,ordinal,name,data_type,is_nullable,key_ordinal)
                VALUES ({table},1,'id','bigint',false,1);
        """)
        self.native(f"CREATE SCHEMA fg_g{stale}; CREATE TABLE fg_g{stale}.unfinished (id BIGINT PRIMARY KEY); "
                    f"CREATE TABLE forkget_delta._d_g{stale}_t{table} (id BIGINT PRIMARY KEY);")
        return stale, table

    def refresh_to_v2(self):
        v1 = self.active()
        old, _ = self.fork("old-read")
        too_early, _ = self.request("POST", "/v1/branches", self.owner_tokens[OWNER_A],
                                    {"name": "too-early", "mode": "native_write"})
        require(too_early == 409, "The v1 baseline accepted native writable provisioning")
        stale, table = self.stale_refresh()
        with Probe(self, "old-read-across-refresh", (OWNER_A, old["name"])) as pinned:
            self.note(pinned, "base-one")
            before, _ = self.fork("during-import")
            require(before["generation_id"] == v1, "An importing generation admitted a fork")
            with ThreadPoolExecutor(max_workers=5) as pool:
                refreshing = pool.submit(self.generation_command, "refresh-v2", "refresh", "--snapshot", "v2")
                racing = [pool.submit(self.fork, f"refresh-race-{index}") for index in range(4)]
                refreshing.result()
                raced = [request.result()[0] for request in racing]
            v2 = self.active()
            require(v2 > stale > v1, "Refresh did not activate a new generation after interrupted import")
            self.snapshot_constraints(v2)
            require(all(branch["generation_id"] in {v1, v2} for branch in raced), "Racing fork pinned an importing generation")
            for branch in raced:
                with Probe(self, branch["name"], (OWNER_A, branch["name"])) as probe:
                    self.note(probe, "base-one" if branch["generation_id"] == v1 else "base-v2-one")
                self.drop(OWNER_A, branch["id"])
            self.note(pinned, "base-one")
            self.generation_command("retire-pinned-v1", "retire", "--generation", str(v1), succeeds=False)
        self.drop(OWNER_A, before["id"])
        require(self.metadata(f"SELECT status FROM refresh_job WHERE target_generation_id={stale};") == "failed"
                and not self.schema_exists(f"fg_g{stale}") and self.native(
                    "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='forkget_delta' "
                    f"AND table_name='_d_g{stale}_t{table}';") == "0", "Interrupted refresh left registered objects")
        self.record("v1 upgrade baseline, failed import recovery, fork/refresh race and old prepared handle")
        return old, v1, v2

    def witness(self, branch):
        binding = self.binding(OWNER_A, branch)
        chunks = []
        for table in binding["tables"]:
            cols = [column["name"] for column in sorted(table["columns"], key=lambda column: column["primary_key_ordinal"] or 999)
                    if column["primary_key_ordinal"]]
            order = ",".join(cols)
            base = f"{table['base_schema']}.{table['base_table']}"
            delta = f"{table['delta_schema']}.{table['delta_table']}"
            chunks.append(self.native(f"SELECT * FROM {base} ORDER BY {order}; SELECT * FROM {delta} ORDER BY _fg_branch,{order};"))
        return chunks

    def measure_layouts(self, sparse, write, sparse_ms, write_ms):
        schema, prefix = self.branch_namespace(write["id"])
        if self.family == "tidb":
            # TiDB reports DATA_LENGTH=0 until statistics are collected; take
            # real measurements after ANALYZE.
            tables = self.native("SELECT CONVERT(table_name USING utf8mb4) FROM information_schema.tables "
                                 f"WHERE table_schema='{schema}' "
                                 f"AND LEFT(table_name,{len(prefix)})='{prefix}';").splitlines()
            require(bool(tables), "Writable branch left no physical tables")
            # information_schema already lists physical names (prefix included).
            qualified = ", ".join(f"{schema}.`{name.strip()}`" for name in tables)
            self.native(f"ANALYZE TABLE {qualified};")
            statement = (f"SELECT COALESCE(SUM(data_length+index_length),0) "
                         f"FROM information_schema.tables WHERE table_schema='{schema}' "
                         f"AND LEFT(table_name,{len(prefix)})='{prefix}';")
        elif self.family == "mysql":
            statement = ("SET SESSION information_schema_stats_expiry=0; SELECT COALESCE(SUM(data_length+index_length),0) "
                         f"FROM information_schema.tables WHERE table_schema='{schema}' "
                         f"AND LEFT(table_name,{len(prefix)})='{prefix}';")
        else:
            statement = ("SELECT COALESCE(sum(pg_total_relation_size(c.oid)),0) FROM pg_class c JOIN pg_namespace n "
                         f"ON n.oid=c.relnamespace WHERE n.nspname='{schema}' AND c.relkind='r';")
        native_bytes = int(self.native(statement))
        require(native_bytes > 0 and not self.branch_storage_exists(sparse["id"]), "Fork layout accounting differs")
        self.layout = {"read_only": {"creation_ms": sparse_ms, "native_copy_bytes": 0},
                       "native_write": {"creation_ms": write_ms, "native_copy_bytes": native_bytes}}
        self.record("Measured sparse and native fork time and physical copy size")

    def provision_after_interruption(self):
        with Probe(self, "hold-native-admin-lock", metadata=True) as guard:
            guard.sql(f"SELECT pg_advisory_lock({GENERATION_LOCK})")
            branch, _ = self.fork("interrupted-write", True, wait=False)
            require(self.branch_status(branch) == "provisioning", "Writable fork activated before native verification")
            self.stop("control")
            branch_id = branch["id"]
            schema, _ = self.branch_namespace(branch_id)
            orders = self.branch_relation(branch_id, "orders")
            self.metadata(f"UPDATE branch SET native_claimed=true WHERE id={branch_id};")
            if self.family in ("mysql", "tidb"):
                self.native(f"CREATE TABLE {orders} (incomplete INT PRIMARY KEY); "
                            f"GRANT SELECT, INSERT, UPDATE, DELETE ON {orders} TO 'p2_service'@'%';")
            else:
                self.native(f"CREATE SCHEMA {schema} AUTHORIZATION {ADMIN}; SET ROLE {ADMIN}; "
                            f"CREATE TABLE {orders} (incomplete INT PRIMARY KEY);")
        self.start_control()
        wait_until("resumed writable provision", lambda: self.branch_status(branch) == "active")
        with Probe(self, "resumed-write", (OWNER_A, branch["name"])) as probe:
            self.note(probe, "base-v2-one")
        self.stop("proxy")
        status, _ = self.request("DELETE", f"/v1/branches/{branch['id']}", self.owner_tokens[OWNER_A])
        require(status in (200, 202) and self.branch_status(branch) == "dropping"
                and self.branch_storage_exists(branch_id),
                "Writable cleanup ran before proxy drain confirmation")
        self.stop("control")
        self.start_control()
        self.start_proxy()
        self.wait_dropped(OWNER_A, branch["id"])
        require(not self.branch_storage_exists(branch_id), "Resumed write cleanup left branch storage")
        replacement, _ = self.fork(branch["name"], True)
        require(replacement["id"] != branch["id"], "Same-name creation reused a branch ID")
        self.drop(OWNER_A, replacement["id"])
        self.record("Interrupted writable provisioning, native table and grant cleanup, and name reuse")

    def capacity(self, live_write):
        with Probe(self, "hold-capacity-lock", metadata=True) as guard:
            guard.sql(f"SELECT pg_advisory_lock({GENERATION_LOCK})")
            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = [pool.submit(self.request, "POST", "/v1/branches", self.owner_tokens[OWNER_A],
                                       {"name": f"capacity-{index}", "mode": "native_write"}) for index in range(16)]
                results = [task.result() for task in futures]
            accepted = [json.loads(body) for status, body in results if status == 202]
            require(len(accepted) == 16 - live_write and sum(status == 409 for status, _ in results) == live_write,
                    "Concurrent provisioning did not enforce the 16-slot limit")
            for branch in accepted:
                status, _ = self.request("DELETE", f"/v1/branches/{branch['id']}", self.owner_tokens[OWNER_A])
                require(status in (200, 202), "Could not release a provisioning slot")
        for branch in accepted:
            self.wait_dropped(OWNER_A, branch["id"])
        self.record("Concurrent native branch provisioning enforces 16 uncleaned slots")

    def write_isolation(self, branch):
        other, _ = self.fork("native-peer", True)
        with Probe(self, "isolated-peer", (OWNER_A, other["name"])) as peer:
            require(peer.sql("SELECT id FROM parents WHERE tenant_id=8", "read").get("rows") == [],
                    "Writable peer saw generated rows from another branch")
            check_count(peer, "UPDATE parents SET label='isolated-peer' WHERE id=100", 1)
            with Probe(self, "isolated-primary", branch) as primary:
                require(primary.sql("SELECT label FROM parents WHERE id=100", "read").get("rows") == [["v2-root"]],
                        "Writable peer changed another branch")
                physical = self.branch_relation(other["id"], "parents")
                require(primary.sql(f"SELECT id FROM {physical}", "read").get("fg") == "FG-2003",
                        "A physical writable table became addressable through the SQL frontend")
        other_login, _ = self.request("POST", "/internal/v1/resolve", self.secret["internal"],
                                     {"principal": OWNER_B, "branch": other["name"]})
        require(other_login == 404, "Writable branch resolved for another owner")
        self.drop(OWNER_A, other["id"])
        if self.family in ("mysql", "tidb"):
            _, prefix = self.branch_namespace(other["id"])
            grants = self.native("SHOW GRANTS FOR 'p2_service'@'%';")
            require(self.schema_exists(MYSQL_WRITE_SCHEMA) and not self.branch_storage_exists(other["id"])
                    and prefix not in grants, "Dropping a shared branch left its tables or grants")
            with Probe(self, "isolated-primary-after-peer-drop", branch) as primary:
                self.note(primary, "base-v2-one")
        self.record("Same-generation writable copies and owners stay isolated")

    def mysql_legacy_branch(self):
        self.grant_mysql_legacy_storage()
        with Probe(self, "hold-legacy-layout", metadata=True) as guard:
            guard.sql(f"SELECT pg_advisory_lock({GENERATION_LOCK})")
            branch, _ = self.fork("native-legacy-upgrade", True, wait=False)
            self.metadata(f"UPDATE branch SET uses_mysql_shared_schema=false WHERE id={branch['id']};")
        wait_until("legacy native activation", lambda: self.branch_status(branch) == "active")
        target = (OWNER_A, branch["name"])
        with Probe(self, "legacy-native-write", target) as probe:
            check_count(probe, "UPDATE parents SET label='legacy-witness' WHERE id=100", 1)
        self.stop("proxy")
        self.stop("control")
        self.start_control()
        self.start_proxy()
        require(self.branch_storage_exists(branch["id"], legacy=True)
                and not self.branch_storage_exists(branch["id"]), "Legacy branch moved during restart")
        with Probe(self, "legacy-native-restarted", target) as probe:
            require(probe.sql("SELECT label FROM parents WHERE id=100", "read").get("rows")
                    == [["legacy-witness"]], "Legacy branch lost its writable image")
        self.drop(OWNER_A, branch["id"])
        require(not self.branch_storage_exists(branch["id"], legacy=True), "Legacy branch cleanup left its database")
        self.revoke_mysql_legacy_storage()
        self.record("Legacy writable data survives restart and drains alongside shared MySQL branches")

    def grant_mysql_legacy_storage(self):
        # The original binary validates its original privilege contract. Add
        # trigger visibility only at the coordinated new-version upgrade.
        rights = TIDB_BRANCH_ADMIN_RIGHTS if getattr(self, "uses_legacy_binaries", False) else MYSQL_BRANCH_ADMIN_RIGHTS
        self.native(f"""
            SET GLOBAL partial_revokes = OFF;
            GRANT SELECT ON `fg\\_g%`.* TO '{ADMIN}'@'%';
            GRANT {rights} ON `fg\\_b%`.* TO '{ADMIN}'@'%' WITH GRANT OPTION;
        """)

    def revoke_mysql_legacy_storage(self):
        self.native(f"""
            REVOKE SELECT ON `fg\\_g%`.* FROM '{ADMIN}'@'%';
            REVOKE {MYSQL_BRANCH_ADMIN_RIGHTS}, GRANT OPTION ON `fg\\_b%`.* FROM '{ADMIN}'@'%';
            SET GLOBAL partial_revokes = ON;
        """)

    def reject_overprivileged_admin(self):
        self.stop("control")
        if self.family in ("mysql", "tidb"):
            self.native(f"GRANT SELECT ON *.* TO '{ADMIN}'@'%';")
        else:
            self.native(f"ALTER ROLE {ADMIN} CREATEROLE;")
        try:
            self.start_control()
        except Failure:
            log = (self.report / "control.log").read_text()
            require("native role privileges differ" in log,
                    "Writable startup failed for a reason other than the unexpected grant")
            diagnostics = [json.loads(line).get("fields", {})
                           for line in log.splitlines() if line.startswith("{")]
            grants = [entry for entry in diagnostics
                      if entry.get("component") == "grants" and entry.get("role") == ADMIN]
            require(grants and all(entry.get("detail") for entry in grants),
                    "Writable startup did not identify the failing native role and grant detail")
            if self.family in ("mysql", "tidb"):
                require(any("SELECT on *.*" in entry["detail"] for entry in grants),
                        "Startup did not identify the unexpected global SELECT privilege")
            require(self.secret["branch_admin"] not in log,
                    "Writable startup diagnostics exposed the branch administrator credential")
        else:
            raise Failure("Writable startup accepted a global branch administrator privilege")
        finally:
            self.stop("control")
            if self.family in ("mysql", "tidb"):
                self.native(f"REVOKE SELECT ON *.* FROM '{ADMIN}'@'%';")
            else:
                self.native(f"ALTER ROLE {ADMIN} NOCREATEROLE;")
        self.start_control()
        self.record("Writable service startup rejects an overprivileged branch administrator")

    def refuse_extra_branch_grant(self):
        if self.family in ("mysql", "tidb"):
            grant = "GRANT SELECT ON *.* TO 'p2_service'@'%';"
            revoke = "REVOKE SELECT ON *.* FROM 'p2_service'@'%';"
        else:
            prefix = f"ALTER DEFAULT PRIVILEGES FOR ROLE {ADMIN}"
            grant = f"{prefix} GRANT TRIGGER ON TABLES TO p2_service;"
            revoke = f"{prefix} REVOKE TRIGGER ON TABLES FROM p2_service;"
        self.native(grant)
        try:
            branch, _ = self.fork("extra-native-grant", True, wait=False)
            self.wait_dropped(OWNER_A, branch["id"])
            require(not self.branch_storage_exists(branch["id"]), "Refused branch left physical storage")
            require(self.metadata(f"SELECT count(*) FROM audit_event WHERE branch_id={branch['id']} "
                                  "AND event_type='branch_active';") == "0",
                    "Writable branch activated with an extra effective grant")
        finally:
            self.native(revoke)
        self.record("Unexpected native service grant prevents writable activation")

    def refresh_to_v3(self, v1, v2, old, sparse, write):
        self.generation_command("refresh-third-generation", "refresh", "--snapshot", "v3", succeeds=False,
                                cooldown=0)
        require(self.active() == v2, "Third generation overrode the active snapshot")
        self.drop(OWNER_A, old["id"])
        self.generation_command("retire-v1", "retire", "--generation", str(v1))
        self.generation_command("refresh-daily-cap", "refresh", "--snapshot", "v3", succeeds=False)
        details = (self.report / "refresh-daily-cap.log").read_text(encoding="utf-8")
        require("86400 seconds" in details, "Default refresh cooldown did not report its interval")
        self.generation_command("refresh-explicit-cap", "refresh", "--snapshot", "v3", succeeds=False,
                                cooldown=3600)
        details = (self.report / "refresh-explicit-cap.log").read_text(encoding="utf-8")
        require("3600 seconds" in details, "Explicit refresh cooldown did not reach metadata admission")
        require(not self.schema_exists(f"fg_g{v1}") and self.active() == v2, "Retirement or daily refresh cap failed")
        with Probe(self, "v2-write-pinned", (OWNER_A, write["name"])) as writable:
            self.note(writable, "base-v2-one")
            self.generation_command("refresh-v3", "refresh", "--snapshot", "v3", cooldown=0)
            v3 = self.active()
            self.snapshot_constraints(v3)
            self.note(writable, "base-v2-one")
            check_count(writable, "UPDATE parents SET label='old-generation' WHERE id=100", 1)
            fresh, _ = self.fork("fresh-v3", True)
            require(fresh["generation_id"] == v3 > v2, "Writable fork did not pin v3")
            with Probe(self, "v3-write", (OWNER_A, fresh["name"])) as probe:
                self.note(probe, "base-v3-one")
                require(probe.sql("SELECT label FROM parents WHERE id=100", "read").get("rows") == [["v3-root"]],
                        "Old native write escaped into the new generation")
            self.drop(OWNER_A, fresh["id"])
        self.drop(OWNER_A, sparse["id"])
        self.drop(OWNER_A, write["id"])
        self.generation_command("retire-v2", "retire", "--generation", str(v2))
        self.generation_command("retire-v2-repeat", "retire", "--generation", str(v2))
        if self.family in ("mysql", "tidb"):
            grants = self.native(f"SHOW GRANTS FOR '{ADMIN}'@'%';")
            require(f"`fg_g{v2}`" not in grants and f"`fg_g{v3}`" in grants,
                    "Generation retirement left the old native administrator's grants")
        self.record("Default and explicit cooldown, zero-interval retention limits, pinned writes and safe retirement")

    def start_databases(self):
        self.compose_started = True
        self.compose("compose-up", "up", "--detach", "--wait", "--wait-timeout", "120", timeout=150, log=True)
        self.native_port = int(self.compose("native-port", "port", "native", str(self.internal_port)).rpartition(":")[2])
        self.metadata_port = int(self.compose("metadata-port", "port", "metadata", "5432").rpartition(":")[2])
        self.prepare_native_engine()
        self.engine_version = self.native("SELECT VERSION();")
        self.metadata_version = self.metadata("SELECT VERSION();")
        require(self.settings["version"] in self.engine_version, "Unexpected native engine version")

    def start_deployment(self):
        self.start_databases()
        self.legacy_migration()
        self.migrations_and_bootstrap()
        self.start_control()
        self.start_proxy()

    def dump_native_state(self):
        """Persist backend-side state on failure: branch table rows, pending
        sessions and a direct-connection replay of the last witness query."""
        try:
            lines = ["-- native state dump"]
            if self.family=="postgresql":
                lines.append(self.native("SELECT pid,usename,state,wait_event_type,wait_event FROM pg_stat_activity WHERE datname=current_database();"))
                lines.append(self.native("SELECT schemaname,relname,n_live_tup FROM pg_stat_user_tables ORDER BY schemaname,relname;"))
                (self.report/"native-state.log").write_text("\n".join(lines)+"\n",encoding="utf-8")
                return
            # TiDB's processlist lacks MySQL's TXN_START column.
            lines.append(self.native("SELECT ID, USER, COMMAND, TIME, STATE FROM information_schema.PROCESSLIST "
                                     "WHERE COMMAND <> 'Sleep';"))
            schema = MYSQL_WRITE_SCHEMA
            lines.append(self.native(f"SELECT table_name, table_rows FROM information_schema.tables "
                                     f"WHERE table_schema='{schema}';"))
            (self.report / "native-state.log").write_text(
                "\n".join(lines) + "\n", encoding="utf-8", errors="backslashreplace")
        except Exception as dump_error:
            print(f"[WARN] {self.engine}: native state dump failed: {dump_error}", flush=True)

    def execute(self):
        self.start_deployment()
        self.reject_overprivileged_admin()
        self.set_policy("dev", 50_000)
        self.record("P3/P4 regression budget configured through the administrator API")
        old, v1, v2 = self.refresh_to_v2()
        self.refuse_extra_branch_grant()
        sparse, sparse_ms = self.fork("sparse-v2")
        write, write_ms = self.fork("native-v2", True)
        branch = (OWNER_A, write["name"])
        baseline = self.witness(sparse)
        self.measure_layouts(sparse, write, sparse_ms, write_ms)
        seed_reference(self)
        for ordinal, isolation in enumerate(("READ COMMITTED", "REPEATABLE READ"), 2):
            differential(self, branch, isolation, ordinal)
        table = next(table for table in self.binding(OWNER_A, write)["tables"] if table["logical_table"] == "parents")
        generated_cases(self, branch, write["id"], table["id"])
        disconnect_rollback(self, branch)
        lost_commit_response(self, branch)
        self.write_isolation(branch)
        if self.family == "mysql":
            self.mysql_legacy_branch()
        require(self.witness(sparse) == baseline, "Proxy writes modified immutable base or sparse deltas")
        self.record("Immutable base tables and sparse deltas unchanged by native writes")
        self.provision_after_interruption()
        self.capacity(1)
        self.ttl_write()
        self.ttl_startup()
        self.refresh_to_v3(v1, v2, old, sparse, write)

    def ttl_write(self):
        branch, _ = self.fork("ttl-writer", True, ttl=8)
        with Probe(self, "ttl-held-native-write", (OWNER_A, branch["name"])) as held:
            begin(held, self.engine, "REPEATABLE READ")
            check_count(held, "INSERT INTO parents (id,tenant_id,code) VALUES (9888,8,'uncommitted-ttl')", 1)
            wait_until("scheduled TTL native drain and cleanup", lambda: self.branch_status(branch) == "dropped", seconds=70)
            require("transport" in held.sql("COMMIT"), "Expired write transaction remained able to commit")
        require(not self.branch_storage_exists(branch["id"]) and self.metadata(f"""
            SELECT count(*) FROM audit_event WHERE branch_id={branch['id']}
                AND actor='system:ttl' AND event_type='branch_dropping';
        """) == "1", "TTL did not record a system transition and remove the native schema")
        self.record("Periodic metadata-clock TTL drains an idle uncommitted native writer")

    def ttl_startup(self):
        branch, _ = self.fork("ttl-startup")
        self.stop("control")
        self.metadata(f"UPDATE branch SET created_at=now()-INTERVAL '2 seconds', "
                      f"expires_at=now()-INTERVAL '1 second' WHERE id={branch['id']};")
        self.start_control()
        self.wait_dropped(OWNER_A, branch["id"])
        self.record("Startup TTL sweep reclaims an expired sparse branch")




def preserve_binding(original, upgraded):
    def same(old, new, path):
        if isinstance(old, dict):
            require(isinstance(new, dict), "Upgrade changed binding object: " + path)
            for key, value in old.items():
                require(key in new, "Upgrade removed binding field: " + path + "." + key)
                same(value, new[key], path + "." + key)
        elif isinstance(old, list):
            require(isinstance(new, list) and len(new) == len(old), "Upgrade changed binding list: " + path)
            for index, (before, after) in enumerate(zip(old, new)):
                same(before, after, f"{path}[{index}]")
        else:
            require(type(new) is type(old) and new == old, "Upgrade changed binding value: " + path)
    # Readiness is the one intentional additive/transitioning field. Every
    # original business, physical, generation and principal field stays exact.
    same({key: value for key, value in original.items() if key != "audit_witness_ready"}, upgraded, "binding")
    expected = (upgraded.get("engine") in ("mysql", "postgresql", "tidb")
                and upgraded.get("layout") == "native_copy" and upgraded.get("access") == "read_write")
    require(upgraded.get("audit_witness_ready") is expected, "Upgrade has the wrong engine/access-specific witness readiness")


class DropReply:
    """Forward TLS opaquely until armed, then discard server replies."""

    def __init__(self, target):
        self.target = target
        self.armed = Event()
        self.done = Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(3)
        self.port = self.listener.getsockname()[1]
        self.thread = Thread(target=self.relay, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.disconnect()
        self.listener.close()

    def disconnect(self):
        self.done.set()
        self.thread.join(timeout=5)

    def relay(self):
        try:
            client, _ = self.listener.accept()
            with client, socket.create_connection(("127.0.0.1", self.target), timeout=3) as server:
                while not self.done.is_set():
                    readable, _, _ = select.select([client, server], [], [], 0.05)
                    for source in readable:
                        message = source.recv(65536)
                        if not message:
                            return
                        if source == client:
                            server.sendall(message)
                        elif not self.armed.is_set():
                            client.sendall(message)
        except OSError:
            return


def lost_commit_response(run, branch):
    with DropReply(run.proxy_port) as relay:
        with Probe(run, "unknown-commit", branch, port=relay.port) as client:
            begin(client, run.engine, "READ COMMITTED")
            check_count(client, "INSERT INTO parents (id,tenant_id,code) VALUES (9899,8,'lost-ack')", 1)
            relay.armed.set()
            client.send("COMMIT")
            with Probe(run, "observe-commit", branch) as observer:
                select_sql = "SELECT id FROM parents WHERE id=9899"
                wait_until("commit reached native server", lambda: observer.sql(select_sql, "read").get("rows") == [[9899]])
                relay.disconnect()
                require("transport" in client.receive(), "Client unexpectedly observed the withheld COMMIT reply")
                check_count(observer, "DELETE FROM parents WHERE id=9899", 1)
    run.record("Lost COMMIT response gives client transport failure while committed data survives")


def run_engine(engine, report, run_id, runner=EngineRun):
    directory = report / engine
    directory.mkdir()
    with tempfile.TemporaryDirectory(prefix=f"{run_id}-") as temporary:
        workspace = Path(temporary)
        certs = workspace / "certs"
        run = runner(engine, directory, workspace, certs, run_id)
        errors = []
        try:
            p2.build_certs(certs)
            run.execute()
        except Exception as error:
            errors.append(run.safe(str(error)))
            run.dump_native_state()
        finally:
            try:
                run.cleanup()
            except (Failure, OSError, subprocess.TimeoutExpired) as error:
                errors.append(run.safe(str(error)))
        for error in errors:
            print(f"[FAIL] {engine}: {error}", flush=True)
        return {"status": "failed" if errors else "passed", "image": run.image, "version": run.engine_version,
                "metadata_version": run.metadata_version,
                "driver": "SQLx 0.8.6", "checks": run.cases, "fork_layout": run.layout,
                "errors": errors, "cleaned_up": not run.compose_started}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engine", nargs="?", choices=("mysql", "postgresql", "tidb", "all"), default="all")
    selected = parser.parse_args().engine
    engines = ("mysql", "postgresql", "tidb") if selected == "all" else (selected,)
    started = datetime.now(UTC)
    run_id = f"fgp34-{started:%H%M%S}-{os.getpid()}"
    root = Path(os.environ.get("FG_P3P4_REPORT_ROOT", ROOT / "test/reports")).resolve()
    report = root / f"{started:%Y%m%d}-p3p4-{started:%H%M%S}-{os.getpid()}"
    report.mkdir(parents=True)
    print(f"P3/P4 report: {report}", flush=True)
    with ThreadPoolExecutor(max_workers=len(engines)) as workers:
        tasks = {engine: workers.submit(run_engine, engine, report, run_id) for engine in engines}
        results = {engine: task.result() for engine, task in tasks.items()}
    checks = dict(results)
    evidence = {"mode": "native_write_reference_vs_proxy", "engines": results, "started_at": started.isoformat()}
    status = "passed" if all(result["status"] == "passed" for result in checks.values()) else "failed"
    p2.json_file(report / "report.json", evidence | {"status": status, "finished_at": datetime.now(UTC).isoformat()})
    revision, source_state = p2.git_state()
    rust = subprocess.check_output(["rustc", "--version"], cwd=ROOT, text=True).strip()
    docker = subprocess.check_output(["docker", "--version"], cwd=ROOT, text=True).strip()
    p2.json_file(report / "env.json", {"run_kind": "local", "source_revision": revision, "source_state": source_state,
                                       "host": platform.system(), "architecture": platform.machine(),
                                       "rust": rust, "docker": docker,
                                       "metadata_image": "postgres:16.14"})
    summary = ["# P3/P4 local native writes and lifecycle", "", f"Overall result: {status}.", ""]
    for engine, result in checks.items():
        summary.append(f"- {engine}: {result['status']}, {len(result['checks'])} checks ({result['version']}).")
        summary.extend(f"  - {check}" for check in result["checks"])
        summary.extend(f"  - {error}" for error in result["errors"])
        for layout, numbers in result["fork_layout"].items():
            summary.append(f"  - {layout}: {numbers['creation_ms']} ms, {numbers['native_copy_bytes']} native copy bytes.")
    (report / "summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
