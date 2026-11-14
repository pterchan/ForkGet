"""Verify complete typed artifacts and exclusive generated-key replay locally."""

import importlib.util
import json
import os
import shutil
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
P6 = Path(__file__).resolve().parents[1] / "p6"
sys.path.insert(0, str(P6))
spec = importlib.util.spec_from_file_location("p10_p6", P6 / "run.py")
p6 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p6)
from run_p2 import OWNER_A, OWNER_B, require
from write_cases import Probe, check_count


def artifact(path):
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    require(records[0]["record"] == "header" and records[-1]["record"] == "end", "Incomplete artifact")
    changes = [record["value"] for record in records if record["record"] == "change"]
    require(records[-1]["value"]["complete"] and records[-1]["value"]["changes"] == len(changes), "Artifact footer differs")
    return records, changes


class EngineRun(p6.p5.EngineRun):
    def __init__(self, *args):
        super().__init__(*args)
        self.base_env["FG_STATE_DIR"] = str(self.certs.parent / "private-replay-state")

    def legacy_migration(self):
        # Policy upgrade semantics have a dedicated migrated-PostgreSQL test.
        # This profile starts a fresh native deployment for artifact behavior.
        pass

    def artifact_cli(self, label, *arguments, succeeds=True):
        environment = self.base_env | {"FG_CONTROL_URL": self.control_url, "FG_OWNER_TOKEN": self.owner_tokens[OWNER_A]}
        result = self.call(label, [self.executable("forkget"), *arguments], env=environment,
                           timeout=350, log=True, succeeds=succeeds)
        return json.loads(result) if result else None

    def execute(self):
        self.start_deployment()
        old, _, _ = self.refresh_to_v2()
        self.drop(OWNER_A, old["id"])
        self.set_policy("dev", 50000)
        source, credentials = self.create("artifact-source")
        with Probe(self, "artifact-source-writes", credentials) as probe:
            for start in range(1, 5001, 100):
                note = "é雪" * 32
                payload = ("X'" + "00ff" * 8 + "'") if self.family in ("mysql", "tidb") else (r"'\x" + "00ff" * 8 + "'")
                rows = ",".join(f"(88,{key},10,12.34,'{note}',{payload})" for key in range(start, start + 100))
                check_count(probe, "INSERT INTO orders (tenant_id,id,customer_id,amount,note,payload) VALUES " + rows, 100)
            check_count(probe, "INSERT INTO parents (tenant_id,code,label) VALUES (8,'generated-artifact','generated-parent')", 1)
            generated = probe.sql("SELECT id FROM parents WHERE tenant_id=8 AND code='generated-artifact'", "read")["rows"][0][0]
            require(generated >= 1 << 62, "Generated key lost signed BIGINT precision")
        path = self.certs.parent / "complete.ndjson"
        exported = self.artifact_cli("complete-export", "export", "--id", str(source["id"]), "--output", str(path))
        records, changes = artifact(path)
        require(len(changes) == 5001 and exported["changes"] == 5001 and exported["complete"], "Export inherited a legacy row cap")
        require(exported["replayable"] and stat.S_IMODE(path.stat().st_mode) == 0o600, "Complete export lost replayability or privacy")
        require(path.stat().st_size > 1024 * 1024, "Fixture did not cross the old report byte cap")
        before = len(self.cli(OWNER_A, "list"))
        checked = self.artifact_cli("complete-preflight", "replay", "--engine", self.engine, "--input", str(path), "--check")
        require(checked["checked"] and len(self.cli(OWNER_A, "list")) == before, "Preflight created a target")
        self.record("Complete 5001-change artifact crosses legacy 1024/4096/1MiB limits; preflight has no side effects")
        replayed = self.artifact_cli("complete-replay", "replay", "--engine", self.engine,
                                     "--input", str(path), "--name", "artifact-target")
        require(replayed["verified"] and replayed["transaction"] == "committed", f"Replay did not verify: {replayed}")
        target = replayed["branch_id"]
        for table, order in (("orders", "tenant_id,id"), ("parents", "id"), ("children", "id")):
            left = self.native(f"SELECT * FROM {self.branch_relation(source['id'], table)} ORDER BY {order};")
            right = self.native(f"SELECT * FROM {self.branch_relation(target, table)} ORDER BY {order};")
            require(left == right, f"Replay changed native {table} rows")
        with Probe(self, "artifact-next-generated", (OWNER_A, "artifact-target")) as probe:
            check_count(probe, "INSERT INTO parents (tenant_id,code) VALUES (8,'after-replay')", 1)
            next_key = probe.sql("SELECT id FROM parents WHERE tenant_id=8 AND code='after-replay'", "read")["rows"][0][0]
            require(next_key > generated, "Ordinary generated insert collided with replayed IDs")
            rejected = probe.sql(f"INSERT INTO parents (id,tenant_id,code) VALUES ({generated+100},8,'forbidden-generated')")
            require("fg" in rejected, "The internal permit escaped into ordinary frontend SQL")
        self.record("Exclusive internal replay preserves generated IDs/native rows and advances the next ordinary allocation")
        # Simulate the metadata boundary after a successful native COMMIT but
        # before its completion reached control. Verification must observe the
        # existing 5001 inserts, never attempt to apply them a second time.
        job = replayed["job_id"]
        self.metadata(f"UPDATE replay_job SET state='unknown',artifact_cleaned=FALSE WHERE id={job};")
        shutil.copyfile(path, Path(self.base_env["FG_STATE_DIR"]) / f"replay-{job}.ndjson")
        status, _ = self.request("POST", f"/v1/replays/{job}/apply", self.owner_tokens[OWNER_A])
        require(status == 409, "An uncertain commit could apply the plan again")
        # Remove the later allocation from this target so its exact net changes
        # again match the committed artifact before recovery observation.
        self.native(f"DELETE FROM {self.branch_relation(target,'parents')} WHERE code='after-replay';")
        recovered = self.artifact_cli("unknown-verify-only", "replay", "--engine", self.engine, "--verify-job", str(job))
        require(recovered["verified"] and recovered["result"]["applied"] is False,
                "Unknown COMMIT recovery did not use observation only")
        self.record("Simulated lost-COMMIT completion rejects reapply and verifies existing native changes without executing the plan again")
        truncated = self.certs.parent / "incomplete.ndjson"
        truncated.write_bytes(b"\n".join(path.read_bytes().splitlines()[:-1]) + b"\n")
        self.artifact_cli("incomplete-refused", "replay", "--engine", self.engine, "--input", str(truncated), "--check", succeeds=False)
        require(len(self.cli(OWNER_A, "list")) == before + 1, "An incomplete artifact created a target")
        self.artifact_cli("existing-output-refused", "export", "--id", str(source["id"]), "--output", str(path), succeeds=False)
        artifact(path)
        self.record("Truncated transfers cannot create replay targets; atomic export never overwrites an existing artifact")
        self.v1_compatibility()
        self.drop(OWNER_A, source["id"])
        self.drop(OWNER_A, target)

    def v1_compatibility(self):
        source, credentials = self.create("v1-artifact-source")
        with Probe(self, "v1-artifact-write", credentials) as probe:
            check_count(probe,"INSERT INTO orders (tenant_id,id,customer_id,amount,note,payload) VALUES (91,901,10,12.34,'legacy',NULL)",1)
        path=self.certs.parent / "v1-capture.ndjson"
        self.artifact_cli("v1-source-export","export","--id",str(source["id"]),"--output",str(path))
        records,changes=artifact(path)
        header=records[0]["value"]
        tables=[]
        for table in header["tables"]:
            table=dict(table)
            table["changes"]=[{key:value for key,value in change.items() if key!="table_id"}
                              for change in changes if change["table_id"]==table["id"]]
            tables.append(table)
        quote='"' if self.family=='postgresql' else '`'
        names=["tenant_id","id","customer_id","amount","note","payload"]
        columns=", ".join(quote+name+quote for name in names)
        sql=f"INSERT INTO {quote}app{quote}.{quote}orders{quote} ({columns}) VALUES (91, 901, 10, 12.34, 'legacy', NULL)"
        old=self.certs.parent / "v1-artifact.json"
        old.write_text(json.dumps({"format_version":1,"engine":self.engine,"source_branch_id":source["id"],
                                   "origin":header["origin"],"tables":tables,"sql":[sql]}))
        replayed=self.artifact_cli("v1-replay","replay","--engine",self.engine,"--input",str(old),"--name","v1-artifact-target")
        require(replayed["verified"],"V1 artifact compatibility did not verify")
        left=self.native(f"SELECT * FROM {self.branch_relation(source['id'],'orders')} ORDER BY tenant_id,id;")
        right=self.native(f"SELECT * FROM {self.branch_relation(replayed['branch_id'],'orders')} ORDER BY tenant_id,id;")
        require(left==right,"V1 artifact lost native values")
        self.drop(OWNER_A,source["id"])
        self.drop(OWNER_A,replayed["branch_id"])
        self.record("The historical V1 typed artifact and exact canonical SQL remain readable and replayable")


if __name__ == "__main__":
    raise SystemExit(p6.run_profile("p10-artifacts", "P10 complete artifacts and generated replay", EngineRun))
