#!/usr/bin/env python3
"""Exercise the owner CLI's independent target-budget review before replay."""

import json

from artifacts import EngineRun as ArtifactRun, artifact, p6
from run_p2 import OWNER_A, OWNER_B, require
from write_cases import Probe, check_count


class EngineRun(ArtifactRun):
    def policy_account(self, user):
        account = super().policy_account(user)
        if user == OWNER_B:
            account["policy_admin"] = True
        return account

    def grant(self, branch):
        request = self.cli(OWNER_A, "budget", "request", "--id", str(branch),
                           "--max-transaction-rows", "100", "--table-limit-bps", "10000",
                           "--small-table-floor", "20", "--reason", "Review eleven exact typed inserts")
        reviewed = self.cli(OWNER_B, "budget", "approve", "--id", str(branch),
                            "--request-id", str(request["id"]))
        require(reviewed["state"] == "approved", "An independent reviewer did not approve the target budget")
        return request

    def job(self, job):
        status, response = self.request("GET", f"/v1/replays/{job}", self.owner_tokens[OWNER_A])
        require(status == 200, "Owner could not inspect the staged job")
        return json.loads(response)

    def execute(self):
        self.start_deployment()
        old, _, _ = self.refresh_to_v2()
        self.drop(OWNER_A, old["id"])
        source, credentials = self.create("review-source")
        self.grant(source["id"])
        with Probe(self, "review-source-writes", credentials) as probe:
            values = ",".join(f"(73,{key},10,12.34,'reviewed-{key}',NULL)" for key in range(1, 12))
            check_count(probe, "INSERT INTO orders (tenant_id,id,customer_id,amount,note,payload) VALUES " + values, 11)
        path = self.certs.parent / "review.ndjson"
        self.artifact_cli("review-export", "export", "--id", str(source["id"]), "--output", str(path))
        _, changes = artifact(path)
        require(len(changes) == 11, "The reviewed source artifact is incomplete")
        staged = self.artifact_cli("review-stage-only", "replay", "--engine", self.engine,
                                    "--input", str(path), "--name", "review-target", "--stage-only")
        job, branch = staged["job_id"], staged["branch_id"]
        require(staged["staged"] and not staged["verified"] and staged["transaction"] == "not_started"
                and staged["branch"]["status"] == "active" and self.job(job)["state"] == "staged",
                "Stage-only applied the artifact or failed to provision a reviewable target")
        relation = self.branch_relation(branch, "orders")
        require(self.native(f"SELECT count(*) FROM {relation} WHERE tenant_id=73;") == "0",
                "Staging executed the source changes before independent review")
        status, _ = self.request("POST", "/internal/v1/resolve", self.secret["internal"],
                                 {"principal": OWNER_A, "branch": "review-target"})
        require(status == 404, "A staged replay target accepted ordinary connections")
        other_env = self.base_env | {"FG_CONTROL_URL": self.control_url, "FG_OWNER_TOKEN": self.owner_tokens[OWNER_B]}
        self.call("other-owner-cannot-apply", [self.executable("forkget"), "replay", "--engine", self.engine,
                  "--apply-job", str(job)], env=other_env, succeeds=False, log=True)
        require(self.job(job)["state"] == "staged", "An unauthorized apply changed the job state")
        self.record("CLI stage-only creates an active private target with no DML; another owner cannot apply it")
        request = self.grant(branch)
        applied = self.artifact_cli("review-apply-job", "replay", "--engine", self.engine, "--apply-job", str(job))
        require(applied["verified"] and applied["job_id"] == job and applied["branch_id"] == branch,
                "Applying the reviewed job replaced the target or failed verification")
        for table, order in (("orders", "tenant_id,id"), ("parents", "id"), ("children", "id")):
            left = self.native(f"SELECT * FROM {self.branch_relation(source['id'], table)} ORDER BY {order};")
            right = self.native(f"SELECT * FROM {self.branch_relation(branch, table)} ORDER BY {order};")
            require(left == right, "Reviewed replay changed exact typed native rows")
        witness = {"staged": staged, "target_request": request, "applied": applied}
        events = self.metadata(f"SELECT count(*) FROM audit_event WHERE branch_id={branch};")
        for state in ("verified", "unknown", "failed"):
            # Real unknown-COMMIT faults are covered by P6. This state-boundary
            # regression proves the CLI never sends apply for a non-staged job.
            self.metadata(f"UPDATE replay_job SET state='{state}' WHERE id={job};")
            self.artifact_cli("review-refuse-" + state, "replay", "--engine", self.engine,
                              "--apply-job", str(job), succeeds=False)
            require(self.job(job)["state"] == state
                    and self.metadata(f"SELECT count(*) FROM audit_event WHERE branch_id={branch};") == events
                    and self.native(f"SELECT count(*) FROM {relation} WHERE tenant_id=73;") == "11",
                    "The CLI reapplied or changed a completed, uncertain, or failed job")
        self.metadata(f"UPDATE replay_job SET state='verified' WHERE id={job};")
        (self.report / "reviewed-cli-receipt.json").write_text(json.dumps(witness, indent=2) + "\n")
        self.record("Independent target grant and apply-job retain the same IDs and exact typed results; verified/unknown/failed states never reapply")
        self.drop(OWNER_A, source["id"])
        self.drop(OWNER_A, branch)


if __name__ == "__main__":
    raise SystemExit(p6.run_profile("p10-staged-replay", "P10 independently reviewed staged CLI replay", EngineRun))
