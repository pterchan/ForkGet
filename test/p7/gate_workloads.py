"""Paired latency benchmarks and single-proxy branch capacity runs."""

import json
import math
import os
import time

from gate_fixture import TENANT, percentile
from run_p2 import Failure, OWNER_A, json_file, require
from write_cases import REFERENCE

WORKLOADS = ("point", "range", "insert", "update", "mixed")
REPETITIONS = 3
SCALE_POINTS = ((100, 300), (500, 1_800), (1_000, 300))
WRITERS = 4
SESSIONS = 16
BENCHMARK_POLICY = "gate1-mysql-v2"
BENCHMARK_TARGETS = {"point_p95_max": 1.15, "point_qps_min": 0.701105086213417,
                     "insert_p95_max": 3.406140007821666}


def benchmark_ok(result):
    return result["successful"] > 0 and all(result[key] == 0 for key in
        ("errors", "timeouts", "connection_errors", "warmup_errors"))


def current_benchmark_policy(evidence):
    return (evidence.get("performance_policy") == BENCHMARK_POLICY
            and evidence.get("performance_targets") == BENCHMARK_TARGETS)


def current_gate_one_policy(evidence):
    decision = evidence.get("gate_1", {})
    return (current_benchmark_policy(evidence) and isinstance(decision, dict)
            and decision.get("policy") == BENCHMARK_POLICY
            and decision.get("targets") == BENCHMARK_TARGETS)


def ratios_meet_targets(ratios):
    if not isinstance(ratios, dict):
        return False
    values = [ratios.get(key) for key in ("point_p95_ratio", "point_qps_ratio", "insert_p95_ratio")]
    if not all(type(value) in (int, float) and math.isfinite(value) and value > 0 for value in values):
        return False
    return (ratios["point_p95_ratio"] <= BENCHMARK_TARGETS["point_p95_max"]
            and ratios["point_qps_ratio"] >= BENCHMARK_TARGETS["point_qps_min"]
            and ratios["insert_p95_ratio"] <= BENCHMARK_TARGETS["insert_p95_max"])


def reset_reference(run):
    note = "REPEAT(CONVERT(X'F09F9BA0' USING utf8mb4),64)" if run.mysql else "repeat(chr(128736),64)"
    run.native(f"DELETE FROM {REFERENCE}.orders WHERE tenant_id=9; "
               f"UPDATE {REFERENCE}.orders SET note={note} "
               f"WHERE tenant_id={TENANT} AND note IN ('gate-load-0','gate-load-1');",
               timeout=300)


def worker(workload, targets):
    return {"workload": workload, "targets": targets}


def benchmarks(run, order_rows, *, formal):
    # The informal profile defaults to the 1s/2s/concurrency-2 smoke shape;
    # FG_GATE_BENCH_WARMUP/MEASURE/CONCURRENCY extend it for local
    # before/after performance comparisons (never a substitute for the
    # formal managed profile).
    warmup, measure, concurrency = (30, 120, SESSIONS) if formal else (
        int(os.environ.get("FG_GATE_BENCH_WARMUP", "1")),
        int(os.environ.get("FG_GATE_BENCH_MEASURE", "2")),
        int(os.environ.get("FG_GATE_BENCH_CONCURRENCY", "2")))
    evidence = {"warmup_seconds": warmup, "measure_seconds": measure, "repetitions": REPETITIONS,
                "concurrency": concurrency, "dataset_rows": order_rows, "runs": [],
                "performance_policy": BENCHMARK_POLICY, "performance_targets": dict(BENCHMARK_TARGETS)}
    for workload in WORKLOADS:
        for repetition in range(REPETITIONS):
            run.check_deadline(2 * (warmup + measure) + 120)
            is_write = workload in ("insert", "update", "mixed")
            branch, _ = run.create(f"gate-bench-{workload}-{repetition}", write=is_write)
            order = ("reference", "proxy") if repetition % 2 == 0 else ("proxy", "reference")
            result = {"workload": workload, "repetition": repetition + 1, "order": order,
                      "proxy_mode": "native_write" if is_write else "sparse"}
            evidence["runs"].append(result)
            try:
                status, body = run.request("GET", f"/v1/branches/{branch['id']}", run.owner_tokens[OWNER_A])
                require(status == 200, "Benchmark branch status is unavailable")
                actual = json.loads(body)
                result["proxy_storage"] = {key: actual[key] for key in ("access", "layout", "read_strategy")}
                result["proxy_read_path"] = "native_copy" if actual["layout"] == "native_copy" else actual["read_strategy"]
                for side in order:
                    reference = side == "reference"
                    if reference and is_write:
                        reset_reference(run)
                    target, ca = run.load_target(None if reference else branch)
                    threads = [worker(workload, [target])] * concurrency
                    result[side] = run.timed_load(threads, ca, order_rows, warmup, measure)
                    require(benchmark_ok(result[side]), "Timed SQL workload returned an error")
            finally:
                json_file(run.report / "benchmark-gate.json", evidence)
                run.drop(OWNER_A, branch["id"])
    if formal and run.mysql:
        check_ratios(evidence)
        json_file(run.report / "benchmark-gate.json", evidence)
        require(evidence["gate_1"]["passed"], "MySQL Gate 1 performance targets were not met")
    run.record("Five paired timed workloads with independent reference and three reset repetitions")


def check_ratios(evidence):
    require(current_benchmark_policy(evidence), "Benchmark evidence must record the current performance policy")
    pairs = evidence["runs"]
    point = [entry for entry in pairs if entry["workload"] == "point"]
    insert = [entry for entry in pairs if entry["workload"] == "insert"]

    def ratio(entries, metric):
        values = sorted(entry["proxy"][metric] / entry["reference"][metric] for entry in entries)
        return values[len(values) // 2]

    ratios = {"point_p95_ratio": ratio(point, "p95_ms"), "point_qps_ratio": ratio(point, "qps"),
              "insert_p95_ratio": ratio(insert, "p95_ms")}
    evidence["gate_1"] = {"policy": BENCHMARK_POLICY, "ratios": ratios,
                          "targets": dict(BENCHMARK_TARGETS), "passed": ratios_meet_targets(ratios)}


def scale(run, order_rows, *, formal):
    scenarios = SCALE_POINTS if formal else ((20, 5),)
    evidence = {"runs": []}
    failures = []
    for size, duration in scenarios:
        branches = []
        writable, readonly = [], []
        fork_samples = []
        warmup = 30 if formal else 1
        result = {"branch_count": size, "seconds": duration, "forks": fork_samples,
                  "observed_boundary": formal and size == 1_000}
        evidence["runs"].append(result)
        try:
            run.check_deadline(duration + 300)
            for index in range(size):
                if index % 25 == 0:
                    run.check_deadline(duration + 180)
                is_write = index < WRITERS
                started = time.monotonic()
                branch, _ = run.create(f"gate-scale-{size}-{index}", write=is_write)
                branches.append(branch)
                fork_samples.append({"branch_id": branch["id"], "writable": is_write,
                                     "elapsed_ms": (time.monotonic() - started) * 1_000})
                (writable if is_write else readonly).append(run.load_target(branch)[0])
            ca = run.load_target(branches[0])[1]
            readers = min(len(readonly), SESSIONS - WRITERS)
            threads = [worker("update", [target]) for target in writable]
            threads.extend(worker("point", readonly[index::readers]) for index in range(readers))
            result["concurrency"] = len(threads)
            if formal:
                for index in range(2):
                    canary, _ = run.create(f"gate-ttl-{size}-{index}", write=False, ttl=45)
                    branches.append(canary)
                result["ttl_canaries"] = [branch["id"] for branch in branches[size:]]
            load = run.timed_load(threads, ca, order_rows, warmup, duration)
            result["load"] = load
            result["sparse_fork_p99_ms"] = percentile(
                [sample for sample in fork_samples if not sample["writable"]], "elapsed_ms", 99)
            covered = set(load["covered_branch_ids"])
            result["all_branches_covered"] = covered == {branch["id"] for branch in branches[:size]}
            require(benchmark_ok(load) and result["all_branches_covered"],
                    "Scale workload had an error or missed a branch")
            if formal:
                for branch in branches[size:]:
                    run.wait_dropped(OWNER_A, branch["id"])
                result["ttl_cleanup_confirmed"] = True
                if not result["observed_boundary"]:
                    require(result["sparse_fork_p99_ms"] < 1_000, "Sparse fork p99 missed one second")
                if size == 500:
                    result["gate_2_qps_passed"] = len(load["successful_per_interval"]) == 30 and all(
                        successes >= 2_500 * 60 for successes in load["successful_per_interval"])
                    require(result["gate_2_qps_passed"], "At least one scale minute missed 2,500 successful QPS")
            result["status"] = "passed"
        except Failure as error:
            result.update(status="failed", error=str(error))
            if not result["observed_boundary"] or not load_was_observed(result):
                failures.append(f"{size} branches: {error}")
        finally:
            json_file(run.report / "scale-gate.json", evidence)
            run.drop_many(branches)
    require(not failures, ". ".join(failures))
    run.record("Single-proxy measured branch coverage, write and read activity, and fork latency")


def load_was_observed(result):
    return "load" in result or bool(result["forks"])
