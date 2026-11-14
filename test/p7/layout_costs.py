#!/usr/bin/env python3
"""Measure local SQL branch provisioning, native allocation and confirmed cleanup.

These serial samples describe native-copy cost at two finite dataset sizes;
they are not device free-space reclamation or formal managed Gate evidence.
"""

from functools import partial
import json
import statistics
import time

import run as smoke
from gate import LocalGate
from gate_fixture import refresh_gate
from run_p2 import OWNER_A, json_file, require

ROW_COUNTS = (1, 25_001)
REPETITIONS = 3


class LayoutCosts(LocalGate):
    def allocation(self, schema, prefix=""):
        if self.mysql:
            names = self.native(
                "SELECT table_name FROM information_schema.tables "
                f"WHERE table_schema='{schema}' "
                f"AND LEFT(table_name,{len(prefix)})='{prefix}' ORDER BY table_name;"
            ).splitlines()
            for name in names:
                self.native(f"ANALYZE TABLE {schema}.`{name}`;", timeout=180)
            prepare = "SET SESSION information_schema_stats_expiry=0; " if self.family == "mysql" else ""
            sql = (prepare + "SELECT CAST(COALESCE(SUM(data_length+index_length),0) AS SIGNED) "
                   "FROM information_schema.tables "
                   f"WHERE table_schema='{schema}' AND LEFT(table_name,{len(prefix)})='{prefix}';")
        else:
            sql = ("SELECT COALESCE(SUM(pg_total_relation_size(c.oid)),0) "
                   "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                   f"WHERE n.nspname='{schema}' AND c.relkind='r';")
        return int(self.native(sql))

    def sample(self, count, repetition, writable):
        started = time.monotonic()
        branch, _ = self.create(f"layout-{count}-{repetition}-{'rw' if writable else 'ro'}",
                                write=writable)
        sample = {"branch_id": branch["id"], "writable": writable,
                  "provision_ms": (time.monotonic() - started) * 1000}
        schema, prefix = self.branch_namespace(branch["id"])
        try:
            status, body = self.request("GET", f"/v1/branches/{branch['id']}", self.owner_tokens[OWNER_A])
            require(status == 200, "Measured branch status is unavailable")
            state = json.loads(body)
            for key in ("access", "layout", "read_strategy"):
                sample[key] = state.get(key)
            sample["allocated_native_relation_bytes"] = self.allocation(schema, prefix)
            sample["physical_objects_present"] = self.branch_storage_exists(branch["id"])
            require(sample["physical_objects_present"] == writable,
                    "Read-only/native-copy physical layouts differ from their contract")
            require((sample["allocated_native_relation_bytes"] > 0) == writable,
                    "Native allocation was not observed for the expected layout")
        finally:
            started = time.monotonic()
            self.drop(OWNER_A, branch["id"])
            sample["confirmed_cleanup_ms"] = (time.monotonic() - started) * 1000
            sample["remaining_native_relation_bytes"] = self.allocation(schema, prefix)
            sample["physical_objects_removed"] = not self.branch_storage_exists(branch["id"])
        require(sample["physical_objects_removed"] and sample["remaining_native_relation_bytes"] == 0,
                "Confirmed branch cleanup left native objects")
        return sample

    def execute(self):
        self.start_deployment()
        evidence = {"kind": "local_indicative", "rows": [], "repetitions": REPETITIONS,
                    "allocation_method": "tidb_statistics_estimate" if self.family == "tidb" else "engine_relation_allocation",
                    "allocation_scope": "branch-owned native table/index bytes; excludes shared metadata, baseline and spool storage",
                    "timing_scope": "owner CLI through active/dropped confirmation, including polling",
                    "cleanup_scope": "native objects absent; not device free bytes or background storage compaction"}
        for count in ROW_COUNTS:
            self.gate_generation = refresh_gate(self, count)
            result = {"seeded_order_rows": count, "total_order_rows": count + 4,
                      "baseline_relation_bytes": self.allocation(f"fg_g{self.gate_generation}"),
                      "samples": []}
            evidence["rows"].append(result)
            try:
                for repetition in range(REPETITIONS):
                    for writable in (False, True):
                        result["samples"].append(self.sample(count, repetition, writable))
                        json_file(self.report / "layout-costs.json", evidence)
                result["medians"] = {
                    label: {field: statistics.median(sample[field] for sample in result["samples"]
                                                    if sample["writable"] == writable)
                            for field in ("provision_ms", "allocated_native_relation_bytes", "confirmed_cleanup_ms")}
                    for label, writable in (("read_only", False), ("native_copy", True))}
            finally:
                json_file(self.report / "layout-costs.json", evidence)
        self.record("Two dataset sizes, three repetitions per layout: provisioning, native allocation and confirmed cleanup")


def main():
    # Keep engine stacks serial for meaningful local cost observations.
    for engine in ("mysql", "postgresql", "tidb"):
        status = smoke.p6.run_profile("p7layout", f"P7 native layout costs ({engine})",
                                      partial(LayoutCosts, profile="local"), [engine])
        if status:
            return status
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
