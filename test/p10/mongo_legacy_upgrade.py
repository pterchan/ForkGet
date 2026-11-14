#!/usr/bin/env python3
"""Upgrade actual pre-0014 metadata and sparse BSON images, then use the new proxy."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import urllib.request
import uuid

import pymongo
from bson import BSON, Decimal128, Int64, SON
from bson.codec_options import CodecOptions
from bson.raw_bson import RawBSONDocument

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "p7"))
from mongo_snapshot import ROOT, BINS, command, require, wait


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", required=True, type=Path)
    parser.add_argument("--migration-directory", type=Path,
                        help="Explicit predecessor SQL fixtures for byte-accurate upgrade qualification")
    options = parser.parse_args()
    report = options.report_dir.resolve()
    migration_directory = options.migration_directory or ROOT / "crates/fg-meta/migrations"
    report.mkdir(parents=True, exist_ok=False)
    suffix = uuid.uuid4().hex[:12]
    containers = ["fg-legacy-meta-" + suffix, "fg-legacy-mongo-" + suffix]
    processes, clients, errors, checks = [], [], [], []
    password, token, internal = secrets.token_hex(24), secrets.token_hex(24), secrets.token_hex(24)
    with tempfile.TemporaryDirectory(prefix="fg-mongo-legacy-", dir=Path.home()) as temporary:
        state = Path(temporary)
        try:
            command("docker", "run", "--detach", "--rm", "--name", containers[0], "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "-p", "127.0.0.1::5432", "postgres:16.14")
            command("docker", "run", "--detach", "--rm", "--name", containers[1], "-e", "MONGO_INITDB_ROOT_USERNAME=root", "-e", "MONGO_INITDB_ROOT_PASSWORD=" + password, "-p", "127.0.0.1::27017", "mongo:7.0.48")
            def port(name, native):
                return command("docker", "inspect", "--format", '{{(index (index .NetworkSettings.Ports "' + str(native) + '/tcp") 0).HostPort}}', name).stdout.strip()
            pg_port, mongo_port = port(containers[0], 5432), port(containers[1], 27017)
            wait("metadata readiness", lambda: command("docker", "exec", containers[0], "pg_isready", "-h", "127.0.0.1", "-U", "postgres", check=False).returncode == 0)
            native = pymongo.MongoClient(f"mongodb://root:{password}@127.0.0.1:{mongo_port}/admin?directConnection=true", serverSelectionTimeoutMS=500)
            clients.append(native)
            wait("MongoDB readiness", lambda: native.admin.command("ping"))
            def sql(text):
                result = subprocess.run(["docker", "exec", "-i", containers[0], "psql", "-XqAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres"], input=text, text=True, capture_output=True, timeout=60)
                require(result.returncode == 0, "Metadata fixture operation failed")
                return result.stdout.strip()
            sql("CREATE TABLE _sqlx_migrations(version BIGINT PRIMARY KEY,description TEXT NOT NULL,installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),success BOOLEAN NOT NULL,checksum BYTEA NOT NULL,execution_time BIGINT NOT NULL)")
            for migration in sorted(migration_directory.glob("*.sql")):
                version = int(migration.name.split("_", 1)[0])
                if version >= 14:
                    break
                # SQLx's migration ledger uses SHA-384 over the original SQL
                # source bytes. This hashes metadata scripts, never user data.
                checksum = hashlib.sha384(migration.read_bytes()).hexdigest()
                description = migration.stem.split("_", 1)[1].replace("_", " ")
                sql(migration.read_text() + f"\nINSERT INTO _sqlx_migrations(version,description,success,checksum,execution_time) VALUES({version},'{description}',true,decode('{checksum}','hex'),0);")
            require(sql("SELECT count(*) FROM information_schema.columns WHERE table_name='branch' AND column_name IN ('access','layout','read_strategy')") == "0", "Fixture was not pre-0014")
            generation = int(sql("INSERT INTO generation(engine,status,snapshot,native_claimed,activated_at) VALUES('mongodb','active','v1',true,now()) RETURNING id"))
            table = int(sql(f"INSERT INTO catalog_table(generation_id,logical_schema,logical_table,base_table,delta_schema,baseline_rows) VALUES({generation},'app','orders','orders','fg_g{generation}',2) RETURNING id"))
            legacy = int(sql(f"INSERT INTO branch(name,class,generation_id,created_by,expires_at,status,mode) VALUES('legacy-mongo','dev',{generation},'alice',now()+interval '1 hour','active','read_only') RETURNING id"))
            staging = int(sql(f"INSERT INTO branch(name,class,generation_id,created_by,expires_at,status,mode) VALUES('legacy-stage','staging',{generation},'alice',now()+interval '1 hour','active','read_only') RETURNING id"))
            database = f"fg_g{generation}"
            delta_name = f"_d_g{generation}_t{table}"
            base = native[database].orders
            base.insert_many([SON([("_id", Int64(1)), ("note", "base-one")]), SON([("_id", Int64(2)), ("note", "base-two")])])
            image = SON([("_id", Int64(1)), ("note", "legacy-change"), ("wide", Int64(7)), ("amount", Decimal128("1.2300")), ("nested", SON([("z", 1), ("a", Int64(2))]))])
            native[database][delta_name].insert_many([
                {"_fg_branch": Int64(legacy), "_fg_op": "U", "_doc": image},
                {"_fg_branch": Int64(legacy), "_fg_op": "I", "_doc": {"_id": Int64(99), "note": "legacy-insert"}},
                {"_fg_branch": Int64(legacy), "_fg_op": "D", "_doc": {"_id": Int64(2)}},
                {"_fg_branch": Int64(staging), "_fg_op": "I", "_doc": {"_id": Int64(88), "note": "stage-existing"}},
            ])
            native[database][delta_name].create_index([("_fg_branch", 1), ("_doc._id", 1)], unique=True, name="_fg_branch_document")
            service = [{"resource": {"cluster": True}, "actions": ["inprog"]}, {"resource": {"db": database, "collection": "orders"}, "actions": ["find"]}, {"resource": {"db": database, "collection": delta_name}, "actions": ["find", "insert", "update", "remove"]}]
            collector = [{"resource": {"db": database, "collection": delta_name}, "actions": ["find", "remove"]}]
            for user, privileges in (("fg_service", service), ("fg_gc", collector)):
                native.admin.command("createRole", user, privileges=privileges, roles=[])
                native.admin.command("createUser", user, pwd="legacy-fixture-service", roles=[{"role": user, "db": "admin"}])
            listeners = []
            for _ in range(3):
                listener = socket.socket()
                listener.bind(("127.0.0.1", 0))
                listeners.append(listener)
            control_port, proxy_port, internal_port = [listener.getsockname()[1] for listener in listeners]
            for listener in listeners:
                listener.close()
            base_url = f"http://127.0.0.1:{control_port}"
            environment = {key: value for key, value in os.environ.items() if not key.startswith("FG_")}
            environment.update(FG_META_DSN=f"postgresql://postgres@127.0.0.1:{pg_port}/postgres", FG_BACKEND_ADMIN_DSN=f"mongodb://root:{password}@127.0.0.1:{mongo_port}/admin", FG_BACKEND_GC_DSN=f"mongodb://fg_gc:legacy-fixture-service@127.0.0.1:{mongo_port}/admin", FG_BACKEND_DSN=f"mongodb://fg_service:legacy-fixture-service@127.0.0.1:{mongo_port}/admin", FG_BACKEND_SERVICE_USER="fg_service", FG_BACKEND_GC_USER="fg_gc", FG_INTERNAL_TOKEN=internal, FG_CONTROL_ACCOUNTS=json.dumps([{"user": "alice", "token": token, "expires_at": 9999999999, "policy_admin": True}]), FG_CONTROL_LISTEN=f"127.0.0.1:{control_port}", FG_PROXY_CONTROL_URL=f"http://127.0.0.1:{internal_port}", FG_PROXY_CONTROL_LISTEN=f"127.0.0.1:{internal_port}", FG_LISTEN_MONGO=f"127.0.0.1:{proxy_port}", FG_FRONTEND_ACCOUNTS=json.dumps([{"user": "alice", "password": "legacy-fixture-client", "expires_at": 9999999999}]), FG_CONTROL_URL=base_url, FG_OWNER_TOKEN=token, FG_STATE_DIR=str(state / "private-state"))
            def binary(label, executable, *args, succeeds=True):
                result = command(BINS / executable, *args, env=environment, check=False)
                (report / (label + ".log")).write_text((result.stdout + result.stderr).replace(password, "[redacted]").replace(token, "[redacted]").replace(internal, "[redacted]"))
                require((result.returncode == 0) == succeeds, label + " returned an unexpected result")
                return json.loads(result.stdout) if succeeds and result.stdout else None
            binary("forward-migrate", "fg-control", "migrate")
            require(sql(f"SELECT access||':'||layout||':'||read_strategy FROM branch WHERE id={legacy}") == "read_write:sparse_delta:merge", "Legacy Mongo access/storage was not preserved")
            require(sql(f"SELECT access FROM branch WHERE id={staging}") == "read_only", "Legacy staging gained write permission")
            checks.append("Actual pre-0014 metadata and legacy U/I/D BSON delta images forward-migrate without repinning or changing storage")
            for label, args in (("control", [BINS / "fg-control", "serve"]), ("proxy", [BINS / "fg-proxy"])):
                with (report / (label + ".log")).open("w") as output:
                    processes.append(subprocess.Popen([str(value) for value in args], cwd=ROOT, env=environment, stdout=output, stderr=subprocess.STDOUT))
            def http(path):
                request = urllib.request.Request(base_url + path, headers={"Authorization": "Bearer " + token})
                with urllib.request.urlopen(request, timeout=5) as response:
                    return json.load(response)
            wait("new control readiness", lambda: http("/v1/branches"))
            wait("new proxy readiness", lambda: urllib.request.urlopen(f"http://127.0.0.1:{internal_port}/healthz", timeout=1).status == 204)
            def connect(branch):
                client = pymongo.MongoClient(f"mongodb://alice:legacy-fixture-client@127.0.0.1:{proxy_port}/{branch}?authSource=admin&directConnection=true", serverSelectionTimeoutMS=3000, retryReads=False, retryWrites=False)
                clients.append(client)
                return client[branch].orders
            merged = connect("legacy-mongo")
            observed = list(merged.find().sort("_id", 1))
            require([row["_id"] for row in observed] == [1, 99] and BSON.encode(SON(observed[0])) == BSON.encode(image), "New proxy lost or normalized a legacy delta image")
            stage = connect("legacy-stage")
            require([row["_id"] for row in stage.find().sort("_id", 1)] == [1, 2, 88], "New proxy lost existing staging delta or mixed branch data")
            for client in clients[1:]:
                client.close()
            artifact = state / "legacy-v1.ndjson"
            binary("export-v1", "forkget", "export", "--id", str(legacy), "--output", str(artifact))
            records = [json.loads(line) for line in artifact.read_text().splitlines()]
            footer = records[-1]["value"]
            images = [record["value"].get("after_bson") for record in records if record["record"] == "document_change"]
            require(footer["complete"] and not footer["replayable"] and "source_snapshot_not_writable" in footer["reasons"] and base64.b64encode(BSON.encode(image)).decode() in images, "Legacy v1 export lost its raw image or replay boundary")
            counts = sql("SELECT (SELECT count(*) FROM branch)||':'||(SELECT count(*) FROM replay_job)")
            binary("v1-replay-refused", "forkget", "replay", "--engine", "mongodb", "--input", str(artifact), "--check", succeeds=False)
            require(sql("SELECT (SELECT count(*) FROM branch)||':'||(SELECT count(*) FROM replay_job)") == counts, "Non-replayable v1 preflight created a target")
            checks.append("Legacy v1 export saves complete typed BSON and explicitly refuses replay without allocating any target")
            raw_options = CodecOptions(document_class=RawBSONDocument)
            raw_before = [row.raw for row in base.with_options(codec_options=raw_options).find().sort("_id", 1)]
            merged = connect("legacy-mongo")
            require(merged.update_one({"_id": Int64(1)}, {"$set": {"note": "new-proxy-write"}}).modified_count == 1, "Migrated legacy Mongo branch lost write permission")
            require(merged.find_one({"_id": Int64(1)})["note"] == "new-proxy-write", "New proxy did not retain its sparse write")
            stage = connect("legacy-stage")
            default = binary("new-default", "forkget", "fork", "new-default")
            new_status = http(f"/v1/branches/{default['id']}/status")
            require(new_status["access"] == "read_only" and new_status["layout"] == "sparse_delta", "New Mongo branch did not default to read-only")
            for collection in (stage, connect("new-default")):
                refused = False
                try:
                    collection.insert_one({"_id": "must-refuse"})
                except pymongo.errors.PyMongoError:
                    refused = True
                require(refused, "Read-only branch accepted a Mongo write")
            require(raw_before == [row.raw for row in base.with_options(codec_options=raw_options).find().sort("_id", 1)], "Sparse legacy writes changed immutable native base BSON")
            require(sql(f"SELECT id||':'||generation_id||':'||mode||':'||layout||':'||access FROM branch WHERE id={legacy}") == f"{legacy}:{generation}:read_only:sparse_delta:read_write", "Legacy upgrade changed identity or storage contract")
            checks.append("New proxy preserves migrated legacy read/write, staging and new-default read-only, branch isolation and immutable base BSON")
        except Exception as error:
            errors.append(str(error).replace(password, "[redacted]").replace(token, "[redacted]").replace(internal, "[redacted]"))
        finally:
            for client in clients:
                client.close()
            for process in processes:
                process.terminate()
            for process in processes:
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            for container in containers:
                command("docker", "rm", "-f", "-v", container, check=False)
    cleaned = all(command("docker", "inspect", container, check=False).returncode != 0 for container in containers)
    result = {"status": "failed" if errors or not cleaned else "passed", "checks": checks, "errors": errors, "cleaned_up": cleaned}
    (report / "report.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result), flush=True)
    return 1 if errors or not cleaned else 0


if __name__ == "__main__":
    raise SystemExit(main())
