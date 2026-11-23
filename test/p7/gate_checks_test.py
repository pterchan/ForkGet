"""Safety checks for local performance policy and nightly evidence."""

from datetime import UTC, datetime, timedelta
import copy
import math
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import gate_seed_native

from gate import FAMILIES, NIGHTLY_CASES, SEED, smoke, verify_nights
from gate_workloads import BENCHMARK_POLICY, BENCHMARK_TARGETS, benchmark_ok, check_ratios
from compare_perf_runs import recorded_target
from run_p2 import Failure, json_file

REVISION = "a" * 40


def benchmark_evidence(**changes):
    ratios = {"point_p95_ratio": 1.15, "point_qps_ratio": 0.701105086213417,
              "insert_p95_ratio": 3.406140007821666} | changes
    runs = []
    for _ in range(3):
        runs.extend([
            {"workload": "point", "reference": {"p95_ms": 1, "qps": 1},
             "proxy": {"p95_ms": ratios["point_p95_ratio"], "qps": ratios["point_qps_ratio"]}},
            {"workload": "insert", "reference": {"p95_ms": 1},
             "proxy": {"p95_ms": ratios["insert_p95_ratio"]}},
        ])
    return {"runs": runs, "performance_policy": BENCHMARK_POLICY,
            "performance_targets": dict(BENCHMARK_TARGETS)}


def night(root, index, started, *, revision, selected, skipped=None):
    evidence = root / f"fixture-p7gate-{index}"
    engines = {engine: {"status": "passed"} for engine in selected}
    evidence.mkdir()
    json_file(evidence / "report.json", {"status": "passed", "started_at": started.isoformat(),
              "engines": engines})
    json_file(evidence / "env.json", {"source_revision": revision, "source_state": "clean"})
    for engine in engines:
        (evidence / engine).mkdir()
        json_file(evidence / engine / "differential.json",
                  {"requested": NIGHTLY_CASES, "executed": NIGHTLY_CASES, "seed": SEED,
                   "families": {family: NIGHTLY_CASES // len(FAMILIES) for family in FAMILIES},
                   "skipped": skipped or []})


class PerformancePolicyChecks(unittest.TestCase):
    def test_exact_authorized_boundary_passes_with_recorded_identity(self):
        evidence = benchmark_evidence()
        check_ratios(evidence)
        decision = evidence["gate_1"]
        self.assertTrue(decision["passed"])
        self.assertEqual(decision["policy"], "gate1-mysql-v2")
        self.assertEqual(decision["targets"], {
            "point_p95_max": 1.15, "point_qps_min": 0.701105086213417,
            "insert_p95_max": 3.406140007821666})

    def test_adjacent_failing_values_get_no_tolerance(self):
        for change in (
            {"point_qps_ratio": math.nextafter(0.701105086213417, -math.inf)},
            {"insert_p95_ratio": math.nextafter(3.406140007821666, math.inf)},
            {"point_p95_ratio": math.nextafter(1.15, math.inf)},
        ):
            with self.subTest(change=change):
                evidence = benchmark_evidence(**change)
                check_ratios(evidence)
                self.assertFalse(evidence["gate_1"]["passed"])

    def test_old_evidence_cannot_be_silently_reclassified(self):
        evidence = benchmark_evidence()
        evidence.pop("performance_policy")
        original = copy.deepcopy(evidence)
        with self.assertRaises(Failure):
            check_ratios(evidence)
        self.assertEqual(evidence, original)
        self.assertEqual(recorded_target({}, "point_qps_min", ">="), "unrecorded")
        self.assertEqual(recorded_target({"gate_1": {"targets": {"point_qps_min": 0.8}}},
                                         "point_qps_min", ">="), ">= 0.8")

    def test_workload_errors_still_refuse_an_otherwise_successful_run(self):
        clean = {"successful": 1, "errors": 0, "timeouts": 0, "connection_errors": 0, "warmup_errors": 0}
        self.assertTrue(benchmark_ok(clean))
        for key in ("errors", "timeouts", "connection_errors", "warmup_errors"):
            with self.subTest(key=key):
                self.assertFalse(benchmark_ok(clean | {key: 1}))
        self.assertFalse(benchmark_ok(clean | {"successful": 0}))




class NativeRegressionEvidenceChecks(unittest.TestCase):
    def test_namespace_launch_errors_cannot_preserve_seed_success(self):
        failures = [subprocess.TimeoutExpired("namespace-test", 900), OSError("fixture launch failed")]
        for failure in failures:
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                succeeded = subprocess.CompletedProcess([], 0, "", "")
                with (patch.object(gate_seed_native, "start", return_value="31000"),
                      patch.object(gate_seed_native, "ready"),
                      patch.object(gate_seed_native.subprocess, "run", side_effect=[succeeded, failure, succeeded])):
                    result = gate_seed_native.run_engine("tidb", directory, directory)
                self.assertEqual(result["exit_code"], 0)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["failure_category"], type(failure).__name__)
                self.assertTrue(result["cleaned_up"])


class EvidenceChecks(unittest.TestCase):
    def setUp(self):
        self.revision, _ = smoke.p6.p5.p34.p2.git_state()
        self.engines = smoke.p6.qualification_sql_engines(self.revision)

    def test_nightly_scope_reads_the_requested_commit(self):
        dependency = '[workspace.dependencies]\nfg-protocol-common = { path = "crates/fg-protocol-common"'
        for features, expected in (
            ("", ("mysql", "postgresql", "tidb")),
            (', features = ["no-tidb"]', ("mysql", "postgresql")),
        ):
            with self.subTest(features=features):
                with patch.object(smoke.p6.subprocess, "check_output", return_value=dependency + features + " }") as git:
                    self.assertEqual(smoke.p6.qualification_sql_engines(self.revision), expected)
                git.assert_called_once_with(["git", "show", f"{self.revision}:Cargo.toml"], cwd=smoke.p6.ROOT, text=True)

    def test_nightly_proof_rejects_missing_or_extra_engines(self):
        invalid_scopes = [self.engines[:-1], (*self.engines, "mongodb")]
        if "tidb" not in self.engines:
            invalid_scopes.append((*self.engines, "tidb"))
        for engines in invalid_scopes:
            with self.subTest(engines=engines), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                first = datetime.now(UTC) - timedelta(days=14)
                for offset in range(14):
                    night(directory, offset, first + timedelta(days=offset), selected=engines, revision=self.revision)
                with self.assertRaises(Failure):
                    verify_nights(directory, self.revision)

    def test_nightly_proof_requires_fourteen_consecutive_dates(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            first = datetime.now(UTC) - timedelta(days=14)
            for offset in range(13):
                night(directory, offset, first + timedelta(days=offset), selected=self.engines, revision=self.revision)
            night(directory, "duplicate", first, selected=self.engines, revision=self.revision)
            night(directory, "future", datetime.now(UTC) + timedelta(days=7), selected=self.engines, revision=self.revision)
            night(directory, "skipped", first + timedelta(days=13), selected=self.engines, revision=self.revision,
                  skipped=["unsupported"])
            night(directory, "foreign", first + timedelta(days=13), selected=self.engines, revision="b" * 40)
            with self.assertRaises(Failure):
                verify_nights(directory, self.revision)
            night(directory, "fourteenth", first + timedelta(days=13), selected=self.engines, revision=self.revision)
            self.assertEqual(len(verify_nights(directory, self.revision)), 14)

if __name__ == "__main__":
    unittest.main()
