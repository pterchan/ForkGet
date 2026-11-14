"""Run local and nightly native-engine verification profiles."""

import argparse
from datetime import UTC, datetime, timedelta
from functools import partial
import json
import os
from pathlib import Path

import run as smoke
from gate_compatibility import compatibility_trials
from gate_differential import FAMILIES, SEED, run_differential
from gate_fixture import LOCAL_ROWS, baseline_witness, dataset, dryrun_trials, populate_reference, refresh_gate
from gate_workloads import benchmarks, scale
from run_p2 import OWNER_A, ROOT, json_file, require, wait_until
from write_cases import REFERENCE

LOCAL_CASES = 250
NIGHTLY_CASES = 5_000
NIGHTS = 14


class WorkloadDeployment:
    """Methods shared by the same corpus and workloads on both topologies."""

    def load_target(self, branch):
        if branch is None:
            database = REFERENCE if self.mysql else self.backend_database
            url = self.dsn("p2_ref", self.secret["reference"], self.native_port, database)
            setup = None if self.mysql else f"SET search_path TO {REFERENCE}"
            ca = self.certs / "backend-ca.pem"
        else:
            url = self.dsn(OWNER_A, self.frontend_passwords[OWNER_A], self.proxy_port, branch["name"])
            setup = None
            ca = self.certs / "frontend-ca.pem"
        return {"url": url, "branch_id": branch["id"] if branch else None, "setup": setup}, ca

    def gate_dryrun_env(self):
        target, ca = self.load_target({"id": 1, "name": "placeholder"})
        return self.base_env | {
            "FG_CONTROL_URL": self.control_url, "FG_OWNER_TOKEN": self.owner_tokens[OWNER_A],
            "FG_DRYRUN_PROXY_DSN": target["url"], "FG_DRYRUN_PROXY_CA": str(ca),
        }

    def timed_load(self, workers, ca, order_rows, warmup, duration):
        plan = {"warmup_seconds": warmup, "measure_seconds": duration,
                "ca_pem": ca.read_text(), "order_rows": order_rows, "workers": workers}
        result = self.run_load(plan, warmup + duration + 20)
        return json.loads(result)

    def drop_many(self, branches):
        failures = []
        for branch in reversed(branches):
            try:
                self.drop(OWNER_A, branch["id"])
            except Exception:
                failures.append(branch["id"])
        if failures:
            json_file(self.report / "pending-branch-cleanup.json", {"branch_ids": failures})
            require(False, f"{len(failures)} test branch cleanups are unconfirmed")


class LocalGate(WorkloadDeployment, smoke.EngineRun):
    def __init__(self, *args, profile):
        super().__init__(*args)
        self.profile = profile

    def create(self, name, branch_class="dev", write=True, ttl=None):
        args = ["fork", name, "--class", branch_class]
        if write:
            args.append("--write")
        if ttl is not None:
            args.extend(("--ttl-seconds", str(ttl)))
        branch = self.cli(OWNER_A, *args)
        try:
            require(branch["generation_id"] == self.gate_generation, "The test branch pinned another generation")
            wait_until(f"{name} activation", lambda: self.branch_status(branch) == "active",
                       seconds=60 if write else 30)
        except Exception:
            self.drop_many([branch])
            raise
        return branch, (OWNER_A, name)

    def check_deadline(self, _reserve):
        pass

    def run_load(self, plan, timeout):
        return self.call("gate-load", [self.executable("fg-write-probe"), "timed-load"],
                         stdin=json.dumps(plan), timeout=timeout)

    def execute(self):
        self.start_deployment()
        generation = refresh_gate(self)
        self.gate_generation = generation
        self.reference_data()
        populate_reference(self, LOCAL_ROWS)
        json_file(self.report / "dataset.json", dataset(self, generation, LOCAL_ROWS))
        before = baseline_witness(self, generation, LOCAL_ROWS)
        cases = NIGHTLY_CASES if self.profile == "nightly" else LOCAL_CASES
        run_differential(self, cases, LOCAL_ROWS)
        if self.profile == "local":
            from rowdiff_cases import rowdiff_cases
            rowdiff_cases(self, LOCAL_ROWS)
            compatibility_trials(self)
            dryrun_trials(self, 1, require_target=False)
            benchmarks(self, LOCAL_ROWS, formal=False)
            scale(self, LOCAL_ROWS, formal=False)
        after = baseline_witness(self, generation, LOCAL_ROWS)
        json_file(self.report / "immutable-baseline.json", {"before": before, "after": after})
        require(before == after, "The immutable gate baseline changed")
        self.record("The typed staged baseline is unchanged")


def exact_revision():
    revision, state = smoke.p6.p5.p34.p2.git_state()
    require(state == "clean", "Nightly verification requires a clean, committed checkout")
    return revision


def verify_nights(directory, revision):
    """Require fourteen consecutive UTC dates for this exact product SHA."""
    dates = set()
    for candidate in directory.glob("*-p7gate-*"):
        try:
            summary = json.loads((candidate / "report.json").read_text())
            environment = json.loads((candidate / "env.json").read_text())
            if summary["status"] != "passed" or environment["source_revision"] != revision:
                continue
            if environment["source_state"] != "clean" or set(summary["engines"]) != {"mysql", "postgresql", "tidb"}:
                continue
            if all(valid_night(candidate, engine, result) for engine, result in summary["engines"].items()):
                started = datetime.fromisoformat(summary["started_at"])
                if started.tzinfo is not None:
                    day = started.astimezone(UTC).date()
                    if day <= datetime.now(UTC).date():
                        dates.add(day)
        except (KeyError, OSError, TypeError, ValueError):
            continue
    for latest in sorted(dates, reverse=True):
        streak = [latest - timedelta(days=offset) for offset in range(NIGHTS)]
        if all(day in dates for day in streak):
            return [day.isoformat() for day in reversed(streak)]
    require(False, f"Nightly evidence needs {NIGHTS} consecutive nightly dates for this SHA ({len(dates)} available)")


def valid_night(candidate, engine, result):
    diff = json.loads((candidate / engine / "differential.json").read_text())
    return (result["status"] == "passed" and diff["requested"] == NIGHTLY_CASES
            and diff["executed"] == NIGHTLY_CASES and diff["seed"] == SEED and not diff["skipped"]
            and set(diff["families"]) == set(FAMILIES) and all(
                count == NIGHTLY_CASES // len(FAMILIES) for count in diff["families"].values()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=("local", "nightly"))
    parser.add_argument("engine", nargs="?", choices=("mysql", "postgresql", "tidb", "all"), default="all")
    selected = parser.parse_args()
    if selected.profile != "local":
        revision = exact_revision()
    os.environ.setdefault("FG_P7GATE_REPORT_ROOT", str(ROOT / "target" / "p7-evidence"))
    status = smoke.p6.run_profile("p7gate", f"P7 {selected.profile} verification", partial(
        LocalGate, profile=selected.profile), [selected.engine])
    if selected.profile == "nightly":
        require(exact_revision() == revision, "The source revision changed during the nightly run")
    return status


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except smoke.p6.p5.p34.p2.Failure as error:
        raise SystemExit(str(error)) from None
