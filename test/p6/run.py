"""Run GitHub App, CI lifecycle, and row replay against both pinned engines."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from decimal import Decimal
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import time
import tomllib

P5 = Path(__file__).resolve().parents[1] / "p5" / "run.py"
spec = importlib.util.spec_from_file_location("run_p5", P5)
p5 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p5)
from run_p2 import OWNER_A, ROOT, require, wait_until


ALL_SQL_ENGINES = ("mysql", "postgresql", "tidb")


def qualification_sql_engines(revision="HEAD"):
    manifest = subprocess.check_output(
        ["git", "show", f"{revision}:Cargo.toml"], cwd=ROOT, text=True)
    dependencies = tomllib.loads(manifest)["workspace"].get("dependencies", {})
    protocol = dependencies.get("fg-protocol-common")
    if isinstance(protocol, dict) and "no-tidb" in protocol.get("features", []):
        return ("mysql", "postgresql")
    return ALL_SQL_ENGINES


class EngineRun(p5.EngineRun):
    def execute(self):
        from github import github_cases
        from negative import negative_cases
        from replay import replay_cases

        self.start_deployment()
        old, _, _ = self.refresh_to_v2()
        self.drop(OWNER_A, old["id"])
        github_cases(self, p5.OUTSIDER)
        self.ci_cases()
        self.set_policy("dev", 50_000)
        replay_cases(self)
        negative_cases(self, p5.p34.ADMIN, p5.p34.GENERATION_LOCK)

    def ci_lease_witness(self, branch_id):
        return json.loads(self.metadata(f"""
            SELECT jsonb_build_object(
                'id', b.id, 'status', b.status, 'lease_version', b.lease_version,
                'expires_at_epoch', extract(epoch FROM b.expires_at)::text,
                'observed_clock', clock_timestamp(),
                'renewal_events', (SELECT count(*) FROM audit_event e
                    WHERE e.branch_id=b.id AND e.event_type='branch_renewed'))::text
            FROM branch b WHERE b.id={branch_id};
        """))

    def ci_cases(self):
        from negative import ci

        output = self.certs.parent / "github-output"
        expected_faults = {
            "sql-failure": "SQL duplicate-key failure FG-3001 observed and rollback verified.",
            "wrong-ca": "Verified TLS rejected the deliberately unrelated CA.",
        }
        for case in ("success", *expected_faults, "abandoned"):
            name = f"ci-{case}"
            output.unlink(missing_ok=True)
            args = ["--ttl", "2", "--read-only"] if case == "abandoned" else []
            ci(self, output, "fork", "--name", name, *args)
            fields = dict(line.split("=", 1) for line in output.read_text().splitlines())
            require(fields.keys() == {"branch_id", "branch_name", "endpoint"} and fields["branch_name"] == name,
                    "CI leaked a credential or changed branch output")
            id_arg = ["--id", fields["branch_id"]]
            branch_id = int(fields["branch_id"])
            if case!="abandoned":
                status=self.cli(OWNER_A,"status","--id",str(branch_id))
                require(86300 <= status["expires_at"]-time.time() <= 86400,
                        "A CI runner loss lacks its default 24-hour fallback lease")
            if case == "abandoned":
                wait_until("CI TTL reached", lambda: self.metadata(
                    f"SELECT (expires_at <= clock_timestamp())::int FROM branch WHERE id={branch_id};") == "1", seconds=10)
                self.stop("control")
                self.start_control()
                self.wait_dropped(OWNER_A, branch_id)
                continue
            try:
                ci(self, output, "wait", *id_arg)
                expected = expected_faults.get(case)
                result = ci(self, output, "smoke", "--engine", self.engine, "--name", name,
                            "--scenario", case, succeeds=expected is None)
                if expected:
                    require(result.stderr.strip() == f"Forkget CI fault observed. {expected}",
                            f"CI did not observe the deliberate {case} fault")
                    before = self.ci_lease_witness(branch_id)
                    callback = json.loads(ci(self, output, "retain", *id_arg).stdout)
                    retained = self.cli(OWNER_A, "status", "--id", str(branch_id))
                    after = self.ci_lease_witness(branch_id)
                    status_keys = ("id", "status", "expired", "lease_version", "expires_at")
                    callback_keys = ("branch_id", "status", "lease_version", "expires_at")
                    p5.p34.p2.json_file(self.report / f"ci-retention-{case}.json", {
                        "case": case, "branch_id": branch_id,
                        "before": before, "after": after,
                        "api_before": {key: status[key] for key in status_keys},
                        "api_retained": {key: retained[key] for key in status_keys},
                        "callback": {key: callback[key] for key in callback_keys},
                    })
                    require(retained["id"] == branch_id and retained["status"] == "active"
                            and not retained["expired"] and retained["lease_version"] == 2
                            and retained["expires_at"] >= status["expires_at"],
                            "The CI failure callback did not retain and renew its environment")
                    require(before["id"] == after["id"] == branch_id
                            and before["status"] == after["status"] == "active"
                            and before["lease_version"] == 1 and after["lease_version"] == 2
                            and after["renewal_events"] == before["renewal_events"] + 1,
                            "CI retention did not commit exactly one authoritative CAS renewal")
                    require(Decimal(after["expires_at_epoch"]) > Decimal(before["expires_at_epoch"]),
                            "CI retention did not strictly extend the exact metadata deadline")
                    require(callback["branch_id"] == branch_id
                            and callback["status"] == "retained_after_failure"
                            and callback["lease_version"] == retained["lease_version"]
                            and callback["expires_at"] == retained["expires_at"],
                            "CI retention output did not match the renewed environment")
            finally:
                # Disposable-suite cleanup follows the retention assertions;
                # the example workflow only drops successful jobs.
                ci(self, output, "drop", *id_arg)
                self.wait_dropped(OWNER_A, branch_id)
        self.record("CI 24-hour fallback, success cleanup, deliberate SQL/TLS failure retention with CAS renewal, and runner-loss TTL")


def run_profile(tag, title, runner, argv=None, *, all_engines=ALL_SQL_ENGINES):
    parser = argparse.ArgumentParser(description=title)
    parser.add_argument("engine", nargs="?", choices=(*all_engines, "all"), default="all")
    selected = parser.parse_args(argv).engine
    engines = all_engines if selected == "all" else (selected,)
    started = datetime.now(UTC)
    run_id = f"fg{tag}-{started:%H%M%S}-{os.getpid()}"
    report_env = f"FG_{tag.upper().replace('-', '_')}_REPORT_ROOT"
    root = Path(os.environ.get(report_env, ROOT / "test/reports")).resolve()
    report = root / f"{started:%Y%m%d}-{tag}-{started:%H%M%S}-{os.getpid()}"
    report.mkdir(parents=True)
    print(f"{title}: {report}", flush=True)
    with ThreadPoolExecutor(max_workers=len(engines)) as workers:
        tasks = {engine: workers.submit(p5.p34.run_engine, engine, report, run_id, runner) for engine in engines}
        results = {engine: task.result() for engine, task in tasks.items()}
    status = "passed" if all(result["status"] == "passed" for result in results.values()) else "failed"
    p5.p34.p2.json_file(report / "report.json", {"schema_version": 1, "status": status, "engines": results,
        "started_at": started.isoformat(), "finished_at": datetime.now(UTC).isoformat()})
    revision, state = p5.p34.p2.git_state()
    p5.p34.p2.json_file(report / "env.json", {"run_kind": "local", "source_revision": revision,
        "source_state": state, "host": platform.system(), "architecture": platform.machine(),
        "rust": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "docker": subprocess.check_output(["docker", "--version"], text=True).strip(),
        "metadata_image": "postgres:16.14"})
    summary = [f"# {title}", "", f"Overall result: {status}.", ""]
    for engine, result in results.items():
        summary.append(f"- {engine}: {result['status']}, {len(result['checks'])} checks ({result['version']}).")
        summary.extend(f"  - {check}" for check in result["checks"])
        summary.extend(f"  - {error}" for error in result["errors"])
        if (report / engine / "benchmark.json").is_file():
            summary.append(f"  - [Individual benchmark runs]({engine}/benchmark.json)")
    (report / "summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(run_profile("p6", "P6 local GitHub App, CI, and replay", EngineRun))
