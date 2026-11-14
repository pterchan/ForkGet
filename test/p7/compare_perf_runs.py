"""Build the before/after comparison report for paired benchmark runs.

Reads two p7bench run directories (each holding per-engine
benchmark-gate.json with identical shape) and writes a summary.md
comparing the indicative Gate 1 ratios per engine, plus the per-repetition
pairs for the gated workloads. Run from the repository root:

    python3 test/p7/compare_perf_runs.py BEFORE_DIR AFTER_DIR
"""

import glob
import json
from pathlib import Path
import sys

GATED = ("point", "insert")


def load(directory):
    runs = {}
    for path in glob.glob(f"{directory}/*/benchmark-gate.json"):
        data = json.loads(Path(path).read_text())
        engine = Path(path).parent.name
        runs[engine] = data
    return runs


def median(values):
    values = sorted(values)
    return values[len(values) // 2]


def ratios(data, workload, metric):
    return [entry["proxy"][metric] / entry["reference"][metric]
            for entry in data["runs"] if entry["workload"] == workload]


def recorded_target(data, key, comparison):
    targets = data.get("performance_targets", data.get("gate_1", {}).get("targets", {}))
    return f"{comparison} {targets[key]}" if key in targets else "unrecorded"


def main(before_dir, after_dir):
    before, after = load(before_dir), load(after_dir)
    lines = ["# Paired benchmark comparison", "",
             f"- Before: `{before_dir}`", f"- After: `{after_dir}`",
             "- Shape: identical knobs on both sides (see each run's benchmark-gate.json).",
             "- Local indicative evidence only; the formal Gate 1 ratios come from the managed profile.",
             ""]
    for engine in sorted(set(before) & set(after)):
        old, new = before[engine], after[engine]
        lines.append(f"## {engine}")
        lines.append("")
        lines.append(f"- Recorded policy before: `{old.get('performance_policy', 'unversioned')}`.")
        lines.append(f"- Recorded policy after: `{new.get('performance_policy', 'unversioned')}`.")
        lines.append("")
        lines.append("| Indicative ratio | Before | After | Recorded target before | Recorded target after |")
        lines.append("|---|---|---|---|---|")
        for label, key, target, comparison in (("point p95", "point_p95_ratio", "point_p95_max", "<="),
                                               ("point QPS", "point_qps_ratio", "point_qps_min", ">="),
                                               ("insert p95", "insert_p95_ratio", "insert_p95_max", "<=")):
            lines.append(f"| {label} | {old['local_indicative_ratios'][key]:.2f} | "
                         f"{new['local_indicative_ratios'][key]:.2f} | "
                         f"{recorded_target(old, target, comparison)} | {recorded_target(new, target, comparison)} |")
        lines.append("")
        lines.append("Gated workload pairs (p95 ms / qps):")
        lines.append("")
        lines.append("| Workload | Rep | Reference | Proxy (before) | Proxy (after) |")
        lines.append("|---|---|---|---|---|")
        for workload in GATED:
            for index, (old_run, new_run) in enumerate(zip(
                    [r for r in old["runs"] if r["workload"] == workload],
                    [r for r in new["runs"] if r["workload"] == workload]), 1):
                reference = new_run["reference"]
                lines.append(
                    f"| {workload} | {index} | p95 {reference['p95_ms']:.2f} / qps {reference['qps']:.0f} "
                    f"| p95 {old_run['proxy']['p95_ms']:.2f} / qps {old_run['proxy']['qps']:.0f} "
                    f"| p95 {new_run['proxy']['p95_ms']:.2f} / qps {new_run['proxy']['qps']:.0f} |")
        lines.append("")
        lines.append("Ungated observations (median across repetitions):")
        lines.append("")
        lines.append("| Workload | Before p95 ratio | After p95 ratio |")
        lines.append("|---|---|---|")
        for workload in ("range", "update", "mixed"):
            old_ratio = median(ratios(old, workload, "p95_ms"))
            new_ratio = median(ratios(new, workload, "p95_ms"))
            lines.append(f"| {workload} | {old_ratio:.2f}x | {new_ratio:.2f}x |")
        lines.append("")
    print("\n".join(lines))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    main(sys.argv[1], sys.argv[2])
