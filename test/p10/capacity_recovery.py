#!/usr/bin/env python3
"""Prove native-copy capacity refusal and restart recovery on disposable SQL services."""

import argparse
from datetime import datetime, UTC
import json
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "p7"))
import snapshot_import as fixture

p34 = fixture.p34
ROOT = fixture.ROOT
require = fixture.require


class CapacityRun(fixture.SnapshotRun):
    def status(self, branch):
        status, body = self.request("GET", f"/v1/branches/{branch['id']}/status", self.owner_tokens[p34.OWNER_A])
        require(status == 200, "Could not read safe owner branch status")
        return json.loads(body)

    def execute(self):
        self.start_databases()
        self.native_roles()
        if self.family == "mysql":
            self.native("SET GLOBAL local_infile=ON;")
        self.call("migrate", [self.executable("fg-control"), "migrate"], env=self.environment(), log=True)
        self.source()
        bundle = self.workspace / "bundle"
        self.snapshot("capture", "capture", "--source-env", "FG_SOURCE_DSN", "--schema", "shop", "--name", "capacity-source", "--output", str(bundle))
        self.snapshot("import", "import", "--input", str(bundle))
        self.metadata_role()
        self.base_env["FG_NATIVE_FREE_BYTES"] = "0"
        self.start_control()
        self.start_proxy()
        unrelated, _ = self.fork("capacity-unrelated")
        original = self.status(unrelated)
        blocked, _ = self.fork("capacity-resume", write=True, wait=False)
        p34.wait_until("visible native capacity refusal", lambda: self.status(blocked).get("reason") == "capacity_preflight_refused", seconds=45)
        status = self.status(blocked)
        require(status["status"] == "provisioning", "Capacity shortage changed the branch's recoverable state")
        require(self.metadata(f"SELECT native_claimed FROM branch WHERE id={blocked['id']};") == "f", "Capacity shortage claimed native objects")
        require(not self.branch_storage_exists(blocked["id"]), "Capacity shortage created native branch tables")
        space = status["storage_preflight"]
        require(space["native_assurance"] == "operator_attested" and space["native_available_bytes"] == 0 and space["estimated_native_required_bytes"] > 0, "Capacity refusal did not expose its safe evidence")
        public = json.dumps(status)
        require("fg_g" not in public and "fgwrite" not in public and not any(secret in public for secret in self.secret.values()), "Owner capacity status exposed private native facts or credentials")
        fixture.json_file(self.report / "blocked-status.json", status)
        self.record("Zero attested capacity leaves the same native-copy branch provisioning, unclaimed, with safe owner-visible estimates and reason")
        self.stop("control")
        self.base_env.pop("FG_NATIVE_FREE_BYTES")
        self.start_control()
        p34.wait_until("same branch resumes after capacity configuration recovery", lambda: self.branch_status(blocked) == "active", seconds=60)
        resumed = self.status(blocked)
        require(resumed["id"] == blocked["id"] and resumed["generation_id"] == blocked["generation_id"], "Recovery replaced or repinned the branch")
        require(resumed["storage_preflight"]["native_assurance"] == "estimated_only" and self.branch_storage_exists(blocked["id"]), "Recovery did not complete native provisioning")
        after = self.status(unrelated)
        require(all(after[key] == original[key] for key in ("id", "generation_id", "status", "access", "layout", "read_strategy", "expires_at", "lease_version")), "Capacity recovery changed an unrelated branch")
        require(after["status"] == "active", "An unrelated branch became unavailable")
        self.binding(p34.OWNER_A, unrelated)
        fixture.json_file(self.report / "resumed-status.json", resumed)
        self.record("Restart without the attestation resumes the original branch while an unrelated read-only branch retains its identity, lease and binding")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=["all", "mysql", "postgresql", "tidb"], default="all")
    parser.add_argument("--report-dir", type=Path, required=True)
    arguments = parser.parse_args()
    report = arguments.report_dir.resolve()
    report.mkdir(parents=True, exist_ok=False)
    started = datetime.now(UTC)
    results = {}
    for engine in (["mysql", "postgresql", "tidb"] if arguments.engine == "all" else [arguments.engine]):
        detail = report / engine
        detail.mkdir()
        with tempfile.TemporaryDirectory(prefix="fg-capacity-recovery-", dir=Path.home()) as temporary:
            workspace = Path(temporary)
            certs = workspace / "certs"
            p34.p2.build_certs(certs)
            runner = CapacityRun(engine, detail, workspace, certs, f"fgcapacity-{started:%H%M%S}-{os.getpid()}")
            errors = []
            try:
                runner.execute()
            except Exception as error:
                errors.append(runner.safe(str(error)))
            finally:
                try:
                    runner.cleanup()
                except Exception as error:
                    errors.append(runner.safe(str(error)))
            results[engine] = {"status": "failed" if errors else "passed", "checks": runner.cases, "errors": errors, "cleaned_up": not runner.compose_started}
            print(json.dumps({engine: results[engine]}), flush=True)
    passed = all(result["status"] == "passed" for result in results.values())
    fixture.json_file(report / "report.json", {"status": "passed" if passed else "failed", "engines": results})
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
