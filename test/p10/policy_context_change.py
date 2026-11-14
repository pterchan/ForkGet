#!/usr/bin/env python3
"""Prove a transaction cannot replace its first policy context by switching tables."""

import argparse
from datetime import UTC, datetime
import http.client
import json
import os
from pathlib import Path
import sys
import tempfile
import secrets
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "p7"))
import snapshot_import as fixture

p34 = fixture.p34
require = fixture.require


class PolicyRun(fixture.SnapshotRun):
    def start(self, label, binary, arguments, env):
        if label == "control":
            self.secret["upload_token"] = secrets.token_hex(24)
            self.upload_expiry = int(time.time()) + 5
            accounts = json.loads(env["FG_CONTROL_ACCOUNTS"])
            accounts.append({"user": "upload-owner", "token": self.secret["upload_token"], "expires_at": self.upload_expiry})
            env = env | {"FG_CONTROL_ACCOUNTS": json.dumps(accounts)}
        return super().start(label, binary, arguments, env)

    def policy_account(self, user):
        return {"policy_admin": True, "approver_for": [p34.OWNER_A] if user == p34.OWNER_B else []}

    def api(self, method, path, body=None, owner=p34.OWNER_A):
        status, response = self.request(method, path, self.owner_tokens[owner], body)
        require(status in (200, 201, 204), f"Policy fixture API refused {method} {path}: {status}")
        return json.loads(response) if response else None

    def grant(self, branch):
        request = self.api("POST", f"/v1/branches/{branch['id']}/budget-requests", {"max_transaction_rows": 100, "table_limit_bps": 10000, "small_table_floor": 10, "ttl_seconds": 900, "reason": "Cross-table transaction context regression"})
        self.api("POST", f"/v1/branches/{branch['id']}/budget-requests/{request['id']}/review", {"approve": True}, p34.OWNER_B)
        grants = self.api("GET", f"/v1/branches/{branch['id']}/budget-grants")["grants"]
        return next(grant for grant in grants if grant["state"] == "active")

    def revisions(self, branch):
        return [int(self.native(f"SELECT revision FROM {self.branch_relation(branch['id'], table)} WHERE id=1;")) for table in ("stock_card", "purchase_log")]

    def writes(self, probe):
        p34.check_count(probe, "BEGIN", 0)
        for revision in range(1, 4):
            p34.check_count(probe, f"UPDATE shop.stock_card SET revision={revision} WHERE id=1", 1)

    def credential_expiry(self):
        branch, _ = self.fork("credential-source")
        path = self.workspace / "credential.ndjson"
        self.cli(p34.OWNER_A, "export", "--id", str(branch["id"]), "--output", str(path))
        data = path.read_bytes()
        before = self.metadata("SELECT (SELECT count(*) FROM branch)||':'||(SELECT count(*) FROM replay_job);")
        require(int(time.time()) < self.upload_expiry, "Upload fixture credential expired before request admission")
        connection = http.client.HTTPConnection("127.0.0.1", self.control_port, timeout=30)
        connection.putrequest("POST", "/v1/replays")
        connection.putheader("Authorization", "Bearer " + self.secret["upload_token"])
        connection.putheader("X-Forkget-Replay-Name", "must-not-create")
        connection.putheader("Content-Type", "application/x-ndjson")
        connection.putheader("Content-Length", str(len(data)))
        connection.endheaders()
        midpoint = len(data) // 2
        connection.send(data[:midpoint])
        while int(time.time()) <= self.upload_expiry:
            time.sleep(.1)
        connection.send(data[midpoint:])
        response = connection.getresponse()
        status = response.status
        response.read()
        connection.close()
        after = self.metadata("SELECT (SELECT count(*) FROM branch)||':'||(SELECT count(*) FROM replay_job);")
        fixture.json_file(self.report / "expired-upload-witness.json", {"http_status": status, "before_counts": before, "after_counts": after})
        require(status == 401 and before == after, "A credential that expired during upload allocated a replay target")
        self.record("Owner credential expiry during an admitted HTTP upload returns 401 without allocating a replay target or job")

    def changing_context(self, name, change):
        branch, _ = self.fork(name, write=True)
        if change == "revoke":
            grant = self.grant(branch)
        else:
            self.set_policy("dev", 100, bps=10000, floor=10)
        with p34.Probe(self, name, (p34.OWNER_A, name)) as probe:
            self.writes(probe)
            before = self.api("GET", f"/v1/branches/{branch['id']}/policy")
            if change == "revoke":
                self.api("POST", f"/v1/branches/{branch['id']}/budget-grants/{grant['id']}/revoke")
            else:
                self.set_policy("dev", 100, bps=10000, floor=1)
            after = self.api("GET", f"/v1/branches/{branch['id']}/policy")
            changed = probe.sql("UPDATE shop.purchase_log SET revision=1 WHERE id=1")
            # Preserve the actual bad commit before asserting. On an unfixed
            # binary this proves table A's old allowance survived revocation.
            completion = probe.sql("ROLLBACK" if "fg" in changed else "COMMIT")
            observed = self.revisions(branch)
            fixture.json_file(self.report / (change + "-witness.json"), {"before": before, "after": after, "second_table_result": changed, "completion": completion, "native_revisions": observed})
            require(changed.get("fg") == "FG-5001", "A second table replaced the first statement's revoked or changed policy context")
            require(observed == [0, 0], "Policy context change committed previously admitted work")
            # ROLLBACK must recover the driver connection and fresh budget.
            p34.check_count(probe, "UPDATE shop.purchase_log SET revision=1 WHERE id=1", 1)
            require(self.revisions(branch) == [0, 1], "Driver rollback did not recover a fresh transaction")
        self.record("Cross-table " + change + " refuses and rolls back the complete transaction; explicit driver rollback restores ordinary writes")

    def execute(self):
        self.start_databases()
        self.native_roles()
        if self.family == "mysql":
            self.native("SET GLOBAL local_infile=ON;")
        self.call("migrate", [self.executable("fg-control"), "migrate"], env=self.environment(), log=True)
        self.source()
        bundle = self.workspace / "bundle"
        self.snapshot("capture", "capture", "--source-env", "FG_SOURCE_DSN", "--schema", "shop", "--name", "policy-source", "--output", str(bundle))
        self.snapshot("import", "import", "--input", str(bundle))
        self.metadata_role()
        self.start_control()
        self.start_proxy()
        self.credential_expiry()
        self.set_policy("dev", 100, bps=10000, floor=1)
        stable, _ = self.fork("stable-context", write=True)
        self.grant(stable)
        with p34.Probe(self, "stable-context", (p34.OWNER_A, "stable-context")) as probe:
            self.writes(probe)
            p34.check_count(probe, "UPDATE shop.purchase_log SET revision=1 WHERE id=1", 1)
            p34.check_count(probe, "COMMIT", 0)
        require(self.revisions(stable) == [3, 1], "An unchanged temporary grant failed a valid cross-table transaction")
        self.record("An unchanged grant admits and commits a valid cross-table transaction")
        self.changing_context("revoked-context", "revoke")
        self.changing_context("version-context", "class_policy")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=["all", "mysql", "postgresql", "tidb"], default="all")
    parser.add_argument("--report-dir", required=True, type=Path)
    arguments = parser.parse_args()
    report = arguments.report_dir.resolve()
    report.mkdir(parents=True, exist_ok=False)
    results = {}
    started = datetime.now(UTC)
    revision, source_state = p34.p2.git_state()
    for engine in (["mysql", "postgresql", "tidb"] if arguments.engine == "all" else [arguments.engine]):
        detail = report / engine
        detail.mkdir()
        with tempfile.TemporaryDirectory(prefix="fg-policy-context-", dir=Path.home()) as temporary:
            workspace = Path(temporary)
            certs = workspace / "certs"
            p34.p2.build_certs(certs)
            runner = PolicyRun(engine, detail, workspace, certs, f"fgpolicycontext-{started:%H%M%S}-{os.getpid()}")
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
    environment = {"source_revision": revision, "source_state": source_state, "started_at": started.isoformat(), "finished_at": datetime.now(UTC).isoformat(), "run_kind": "focused_native_acceptance"}
    fixture.json_file(report / "env.json", environment)
    fixture.json_file(report / "report.json", environment | {"status": "passed" if passed else "failed", "engines": results})
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
