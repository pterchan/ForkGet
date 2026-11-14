"""Prepare and measure the staged dataset and an independent reference."""

import json
from hashlib import sha256
from math import ceil
from pathlib import Path
import tempfile
import time

from run_p2 import OWNER_A, json_file, require, wait_until
from write_cases import REFERENCE

TENANT = 7
PAYLOAD = "00017F80FF00017F80FF00017F80FF00"
LOCAL_ROWS = 25_001
GIB = 1 << 30
DRYRUN_CHANGES = 1_000
DRYRUN_TRIALS = 20


def refresh_gate(run, count=LOCAL_ROWS):
    previous = run.active()
    # Disposable local profiles intentionally refresh immediately after their
    # bootstrap. Managed deployments retain the production daily cooldown.
    cooldown = 0 if run.profile in ("local", "nightly") else None
    run.generation_command("refresh-gate", "refresh", "--gate-orders", str(count), timeout=900,
                           cooldown=cooldown)
    generation = run.active()
    require(generation != previous, "The verified gate generation did not activate")
    require(run.metadata(f"SELECT snapshot FROM generation WHERE id={generation};")
            == f"gate-v2-{count}", "The activated gate snapshot identity differs")
    require(run.metadata(f"SELECT baseline_rows FROM catalog_table WHERE generation_id={generation} "
                         "AND logical_table='orders';") == str(count + 4),
            "The gate order count differs from the pinned catalog")
    run.generation_command("retire-gate-previous", "retire", "--generation", str(previous))
    return generation


def populate_reference(run, count):
    """Generate the same fixture independently of the production snapshot loader."""
    if run.mysql:
        digits = "(SELECT 0 AS digit UNION ALL " + " UNION ALL ".join(
            f"SELECT {value}" for value in range(1, 10)) + ")"
        aliases = ("ones", "tens", "hundreds", "thousands", "tenthousands")
        number = "+".join(f"{10 ** index}*{alias}.digit" for index, alias in enumerate(aliases))
        sources = " CROSS JOIN ".join(f"{digits} {alias}" for alias in aliases)
        note = "REPEAT(CONVERT(X'F09F9BA0' USING utf8mb4),64)"
        payload = f"X'{PAYLOAD}'"
    else:
        note = "repeat(chr(128736),64)"
        payload = f"decode('{PAYLOAD}','hex')"
    for first in range(1, count + 1, 100_000):
        run.check_deadline(330)
        last = min(count, first + 99_999)
        if run.mysql:
            selection = f"SELECT {first}+{number} AS id FROM {sources} WHERE {number}<={last - first}"
        else:
            selection = f"SELECT generate_series({first},{last}) AS id"
        run.native(f"""
            INSERT INTO {REFERENCE}.orders (tenant_id,id,customer_id,amount,note,payload)
            SELECT {TENANT}, ids.id, 10, 50.00, {note}, {payload}
            FROM ({selection}) AS ids ORDER BY ids.id;
        """, timeout=300)


def dataset(run, generation, count):
    baseline = f"fg_g{generation}"
    result = {}
    for label, schema in (("baseline", baseline), ("reference", REFERENCE)):
        rows = int(run.native(f"SELECT COUNT(*) FROM {schema}.orders WHERE tenant_id={TENANT};",
                              timeout=180))
        require(rows == count, f"{label} gate order count differs")
        if run.mysql:
            if run.family == "tidb":
                tables = run.native(f"SELECT table_name FROM information_schema.tables WHERE table_schema='{schema}';").splitlines()
                for table in tables:
                    run.native(f"ANALYZE TABLE {schema}.`{table}`;", timeout=180)
            else:
                run.native(f"ANALYZE TABLE {schema}.orders;", timeout=180)
            prepare = "SET SESSION information_schema_stats_expiry=0; " if run.family == "mysql" else ""
            size = run.native(prepare +
                              "SELECT CAST(SUM(data_length + index_length) AS SIGNED) "
                              f"FROM information_schema.tables WHERE table_schema='{schema}';")
        else:
            size = run.native("SELECT SUM(pg_total_relation_size(c.oid)) FROM pg_class c "
                              "JOIN pg_namespace n ON n.oid=c.relnamespace "
                              f"WHERE n.nspname='{schema}' AND c.relkind='r';")
        result[label] = {"gate_order_rows": rows, "total_bytes_including_indexes": int(size),
                         "measurement_method": "tidb_statistics_estimate" if run.family == "tidb" else "engine_relation_size"}
    return result


def baseline_witness(run, generation, count):
    """Verify the large fixture without exporting millions of row values."""
    schema = f"fg_g{generation}"
    if run.mysql:
        # TiDB 8.5.8 infers 64 bytes for CAST(VARCHAR(64) AS BINARY),
        # truncating the valid 256-byte value. HEX preserves every byte.
        note = f"HEX(note) <=> '{'F09F9BA0' * 64}' AND CHAR_LENGTH(note)=64 AND OCTET_LENGTH(note)=256"
        same_values = f"amount <=> 50.00 AND ({note}) AND payload <=> X'{PAYLOAD}'"
        string_value = "HEX(payload)"
        json_array = "JSON_ARRAY"
    else:
        note = "convert_to(note,'UTF8') IS NOT DISTINCT FROM convert_to(repeat(chr(128736),64),'UTF8')"
        same_values = f"amount IS NOT DISTINCT FROM 50.00 AND ({note}) AND payload IS NOT DISTINCT FROM decode('{PAYLOAD}','hex')"
        string_value = "encode(payload,'hex')"
        json_array = "json_build_array"
    sql = (f"SELECT COUNT(*) FROM {schema}.orders WHERE tenant_id={TENANT} "
           f"AND id BETWEEN 1 AND {count} AND customer_id=10 AND ({same_values});")
    require(int(run.native(sql, timeout=180)) == count,
            "The immutable staged orders differ from the typed seed")
    require(int(run.native(f"SELECT COUNT(*) FROM {schema}.orders;", timeout=180)) == count + 4,
            "The immutable order key set changed")
    parts = {}
    for table, columns, where, order in (
        ("orders", f"tenant_id,id,customer_id,amount,note,{string_value}",
         f"WHERE tenant_id<>{TENANT}", "tenant_id,id"),
        ("customers", "id,name", "", "id"),
        ("parents", "id,tenant_id,code,parent_code,label", "", "id"),
        ("children", "id,tenant_id,parent_code,label", "", "id"),
    ):
        rows = run.native(f"SELECT {json_array}({columns}) FROM {schema}.{table} {where} ORDER BY {order};")
        parts[table] = sha256(rows.encode()).hexdigest()
    return {"verified_gate_rows": count, "fixed_typed_json_rows_sha256": parts}


def dryrun_trials(run, trials, *, require_target):
    environment = run.gate_dryrun_env()
    measurements = []
    with tempfile.TemporaryDirectory(prefix="forkget-gate-dryrun-") as workspace:
        directory = Path(workspace)
        manifest = directory / "changes.json"
        json_file(manifest, {
            "changes": [f"UPDATE orders SET note='gate-{key}' WHERE tenant_id={TENANT} AND id={key}"
                        for key in range(1, DRYRUN_CHANGES + 1)],
            "checks": [f"SELECT COUNT(*) = {DRYRUN_CHANGES} FROM orders "
                       f"WHERE tenant_id={TENANT} AND id <= {DRYRUN_CHANGES} AND note LIKE 'gate-%'"],
        })
        for index in range(trials):
            run.check_deadline(300)
            output = directory / f"trial-{index}.json"
            started = time.monotonic()
            try:
                run.call("gate-dryrun", [run.executable("forkget"), "dryrun", "--engine", run.engine,
                         "--manifest", str(manifest), "--output", str(output)],
                         env=environment, timeout=300)
                report = json.loads(output.read_text())
                order_diff = next(table for table in report["rowdiff"]["tables"] if table["table"] == "orders")
                require(report["transaction"] == "committed" and report["cleanup"] == "dropped"
                        and len(order_diff["changes"]) == DRYRUN_CHANGES
                        and output.stat().st_mode & 0o777 == 0o600,
                        "Dry-run lost its typed diff, private report or confirmed cleanup")
                elapsed = (time.monotonic() - started) * 1_000
                measurements.append({"trial": index + 1, "elapsed_ms": elapsed,
                                     "branch_id": report["branch_id"], "status": "passed"})
            except Exception:
                failure = {"trial": index + 1, "status": "failed"}
                if output.exists():
                    report = json.loads(output.read_text())
                    for key in ("failure", "branch_id", "transaction", "cleanup"):
                        failure[key] = report.get(key)
                    failed = [item for item in report.get("statements", []) if not item.get("success", True)]
                    if failed:
                        failure["first_failed_statement"] = failed[0]
                measurements.append(failure)
                raise
            finally:
                json_file(run.report / "dryrun-gate.json", {"changes_per_trial": DRYRUN_CHANGES,
                          "trials": measurements, "p95_ms": percentile(measurements, "elapsed_ms", 95)})
    if require_target:
        require(percentile(measurements, "elapsed_ms", 95) < 30_000,
                "The formal dry-run p95 missed 30 seconds")
    run.record(f"{trials} dry-run trials with {DRYRUN_CHANGES} typed changes and confirmed cleanup")


def percentile(samples, field, percent):
    values = sorted(sample[field] for sample in samples if field in sample)
    return values[ceil(len(values) * percent / 100) - 1] if values else None
