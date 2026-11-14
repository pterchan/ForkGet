"""Extended-parameter local benchmark runs for proxy performance work.

Runs only the paired workload benchmarks (no differential, compatibility
or scale stages) through the same fixtures and evidence schema as the
p7gate profiles, so before/after comparisons of proxy hot-path changes
are cheap and comparable. This is indicative local evidence only — it
never substitutes for the formal managed Gate 1 profile.

Benchmark shape comes from FG_GATE_BENCH_WARMUP / FG_GATE_BENCH_MEASURE
/ FG_GATE_BENCH_CONCURRENCY (see gate_workloads.benchmarks); run them
per engine serially so concurrent engine stacks do not contend for CPU
and skew the paired ratios.
"""

from functools import partial
import argparse
import json

import run as smoke
from gate import LocalGate
from gate_fixture import LOCAL_ROWS, populate_reference, refresh_gate
from gate_workloads import benchmarks


class BenchGate(LocalGate):
    def execute(self):
        self.start_deployment()
        generation = refresh_gate(self)
        self.gate_generation = generation
        self.reference_data()
        populate_reference(self, LOCAL_ROWS)
        benchmarks(self, LOCAL_ROWS, formal=False)
        indicative_ratios(self)


def indicative_ratios(run):
    """Record local proxy/reference medians under an explicit non-formal key."""
    evidence = json.loads((run.report / "benchmark-gate.json").read_text())
    point = [entry for entry in evidence["runs"] if entry["workload"] == "point"]
    insert = [entry for entry in evidence["runs"] if entry["workload"] == "insert"]

    def ratio(entries, metric):
        values = sorted(entry["proxy"][metric] / entry["reference"][metric] for entry in entries)
        return values[len(values) // 2]

    evidence["local_indicative_ratios"] = {
        "point_p95_ratio": ratio(point, "p95_ms"),
        "point_qps_ratio": ratio(point, "qps"),
        "insert_p95_ratio": ratio(insert, "p95_ms"),
        "note": "Local extended-shape sample, not formal Gate 1 evidence",
    }
    (run.report / "benchmark-gate.json").write_text(json.dumps(evidence, indent=2) + "\n")
    run.record("Extended paired workloads with local indicative ratios")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("mysql", "postgresql", "all"), default="all")
    args = parser.parse_args()
    engines = ("mysql", "postgresql") if args.engine == "all" else (args.engine,)
    for engine in engines:
        status = smoke.p6.run_profile("p7bench", f"P7 extended local benchmark ({engine})",
                                      partial(BenchGate, profile="local"), [engine])
        if status:
            return status
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except smoke.p6.p5.p34.p2.Failure as error:
        raise SystemExit(str(error)) from None
