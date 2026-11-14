#!/usr/bin/env python3
"""Prove native frozen-source snapshots on isolated MongoDB/metadata services."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid

import pymongo
from bson import Binary, Decimal128, Int64, ObjectId, SON
from bson.codec_options import CodecOptions
from bson.raw_bson import RawBSONDocument

ROOT = Path(__file__).resolve().parents[2]
BINS = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")) / "debug"


def require(value, label):
    if not value:
        raise RuntimeError(label)


def command(*args, env=None, check=True):
    result = subprocess.run([str(arg) for arg in args], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=240)
    if check and result.returncode:
        raise RuntimeError("Native fixture operation failed")
    return result


def wait(label, predicate):
    until = time.monotonic() + 60
    while time.monotonic() < until:
        try:
            if predicate():
                return
        except (OSError, pymongo.errors.PyMongoError):
            pass
        time.sleep(.1)
    raise RuntimeError("Timed out: " + label)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", required=True, type=Path)
    report = parser.parse_args().report_dir.resolve()
    report.mkdir(parents=True, exist_ok=False)
    suffix = uuid.uuid4().hex[:12]
    containers = ["fg-snapshot-meta-" + suffix, "fg-snapshot-mongo-" + suffix]
    checks, errors = [], []
    mongo_password = secrets.token_hex(24)
    with tempfile.TemporaryDirectory(prefix="forkget-mongo-snapshot-", dir=Path.home()) as temporary:
        state = Path(temporary)
        try:
            command("docker", "run", "--detach", "--rm", "--name", containers[0], "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "-p", "127.0.0.1::5432", "postgres:16.14")
            command("docker", "run", "--detach", "--rm", "--name", containers[1], "-e", "MONGO_INITDB_ROOT_USERNAME=root", "-e", "MONGO_INITDB_ROOT_PASSWORD=" + mongo_password, "-p", "127.0.0.1::27017", "mongo:7.0.48")
            def port(name, internal):
                return command("docker", "inspect", "--format", '{{(index (index .NetworkSettings.Ports "' + str(internal) + '/tcp") 0).HostPort}}', name).stdout.strip()
            pg_port, mongo_port = port(containers[0], 5432), port(containers[1], 27017)
            wait("metadata", lambda: command("docker", "exec", containers[0], "pg_isready", "-U", "postgres", check=False).returncode == 0)
            native = pymongo.MongoClient(f"mongodb://root:{mongo_password}@127.0.0.1:{mongo_port}/admin?directConnection=true", serverSelectionTimeoutMS=500)
            wait("MongoDB", lambda: native.admin.command("ping"))
            for user in ("fg_service", "fg_gc"):
                native.admin.command("createUser", user, pwd="fixture-service", roles=[])
            source = native.native_app
            source.create_collection("invoices", validator={"$jsonSchema": {"bsonType": "object", "required": ["account"], "properties": {"account": {"bsonType": "string"}}}}, validationLevel="strict", validationAction="error")
            source.create_collection("empty_notes")
            source.invoices.create_index([("account", 1), ("sequence", -1)], unique=True, name="account_sequence")
            source.invoices.insert_many([SON([("_id", ObjectId()), ("account", "Unicode 雪🛠"), ("sequence", i), ("i64", Int64(i)), ("decimal", Decimal128("123.4500")), ("payload", Binary(bytes(range(16)), subtype=4)), ("at", datetime(2026, 11, 12, 0, 0, 0, 123000, tzinfo=timezone.utc)), ("nested", SON([("z", i), ("a", Int64(i))]))]) for i in range(7)])
            environment = {key: value for key, value in os.environ.items() if not key.startswith("FG_")}
            environment.update(FG_META_DSN=f"postgresql://postgres@127.0.0.1:{pg_port}/postgres", FG_BACKEND_ADMIN_DSN=f"mongodb://root:{mongo_password}@127.0.0.1:{mongo_port}/admin", FG_SOURCE_DSN=f"mongodb://root:{mongo_password}@127.0.0.1:{mongo_port}/admin", FG_BACKEND_SERVICE_USER="fg_service", FG_BACKEND_GC_USER="fg_gc", FG_REFRESH_COOLDOWN_SECONDS="0")
            def binary(label, *args, succeeds=True):
                result = command(BINS / "fg-control", *args, env=environment, check=False)
                details = (result.stdout + result.stderr).replace(mongo_password, "[redacted]")
                (report / (label + ".log")).write_text(details)
                require((result.returncode == 0) == succeeds, label + " unexpected result; see sanitized log")
                return json.loads(result.stdout) if succeeds and result.stdout else None
            def metadata(sql):
                return command("docker", "exec", containers[0], "psql", "-U", "postgres", "-At", "-c", sql).stdout.strip()
            binary("migrate", "migrate")
            flags = ["--source-env", "FG_SOURCE_DSN", "--schema", "native_app", "--name", "native-mongo", "--consistency", "frozen_source"]
            binary("unfrozen-rejected", "snapshot", "inspect", *flags, "--output", str(state / "unfrozen.json"), succeeds=False)
            source.invoices.create_index("at", expireAfterSeconds=3600, name="expires")
            native.admin.command({"fsync": 1, "lock": True})
            try:
                binary("ttl-rejected", "snapshot", "inspect", *flags, "--output", str(state / "ttl.json"), succeeds=False)
            finally:
                native.admin.command({"fsyncUnlock": 1})
            source.invoices.drop_index("expires")
            native.admin.command({"fsync": 1, "lock": True})
            try:
                binary("inspect", "snapshot", "inspect", *flags, "--output", str(state / "plan.json"))
                bundle = state / "bundle"
                binary("capture", "snapshot", "capture", *flags, "--output", str(bundle))
            finally:
                native.admin.command({"fsyncUnlock": 1})
            checks.append("Unfrozen sources and native TTL indexes are explicitly refused")
            environment["FG_NATIVE_FREE_BYTES"] = "0"
            try:
                binary("capacity-refusal", "snapshot", "import", "--input", str(bundle), succeeds=False)
                require(metadata("SELECT count(*) FROM generation") == "0", "Capacity refusal allocated a native generation")
            finally:
                environment.pop("FG_NATIVE_FREE_BYTES", None)
            result = binary("import", "snapshot", "import", "--input", str(bundle))
            require(result["storage_preflight"]["native_assurance"] == "estimated_only", "Unknown native free space was reported as guaranteed")
            generation = result["generation_id"]
            checks.append("Actual native allocation estimates and measured local free space are reported; zero attested native space refuses before allocation")
            restored = native[f"fg_g{generation}"]
            options = CodecOptions(document_class=RawBSONDocument)
            expected = list(source.get_collection("invoices", codec_options=options).find().sort("_id", 1))
            observed = list(restored.get_collection("invoices", codec_options=options).find().sort("_id", 1))
            require([row.raw for row in expected] == [row.raw for row in observed], "Native import changed BSON bytes/types/order")
            require(restored.empty_notes.count_documents({}) == 0 and "empty_notes" in restored.list_collection_names(), "Native import lost empty collection")
            require(source.invoices.options() == restored.invoices.options(), "Native import changed validator/options")
            require(list(source.invoices.list_indexes()) == list(restored.invoices.list_indexes()), "Native import changed indexes/order")
            require(metadata(f"SELECT count(*) FROM catalog_table WHERE generation_id={generation}") == "2", "Owned catalog lost document collections")
            checks.append("Genuine mongodump/mongorestore preserves raw typed BSON, validators, compound unique indexes and empty collections")
            bad = state / "bad-bundle"
            shutil.copytree(bundle, bad)
            manifest = json.loads((bad / "manifest.json").read_text())
            manifest["document"]["collections"][0]["rows"] += 1
            (bad / "manifest.json").write_text(json.dumps(manifest))
            binary("corrupt-import", "snapshot", "import", "--input", str(bad), succeeds=False)
            require(metadata("SELECT id FROM generation WHERE status='active'") == str(generation), "Failed native import replaced active generation")
            failed = int(metadata("SELECT max(generation_id) FROM snapshot_job WHERE phase='failed'"))
            require(f"fg_g{failed}" not in native.list_database_names(), "Failed native import left owned native database")
            require(metadata(f"SELECT native_claimed FROM generation WHERE id={failed}") == "f", "Failed native import left claimed objects")
            checks.append("Corrupt manifest is refused and compensated without replacing the previous active snapshot")
            changed = state / "changed-bson-bundle"
            shutil.copytree(bundle, changed)
            witness = changed / "witness" / "invoices.bson"
            original = witness.read_bytes()
            require(b"Unicode" in original, "Fixture witness did not contain its typed source data")
            witness.write_bytes(original.replace(b"Unicode", b"Changed", 1))
            binary("changed-bson", "snapshot", "import", "--input", str(changed), succeeds=False)
            require(metadata("SELECT id FROM generation WHERE status='active'") == str(generation), "BSON mismatch replaced active generation")
            failed = int(metadata("SELECT max(generation_id) FROM snapshot_job WHERE phase='failed'"))
            require(f"fg_g{failed}" not in native.list_database_names(), "BSON mismatch left owned native database")
            checks.append("A changed BSON value is detected byte-for-byte and the failed generation is removed")
            binary("status", "snapshot", "status")
        except Exception as error:
            errors.append(str(error).replace(mongo_password, "[redacted]"))
        finally:
            for container in reversed(containers):
                command("docker", "rm", "-f", "-v", container, check=False)
    result = {"status": "failed" if errors else "passed", "checks": checks, "errors": errors, "cleaned_up": True}
    (report / "report.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result), flush=True)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
