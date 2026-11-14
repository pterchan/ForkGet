"""Summarize an isolated protocol fixture run without reading connection credentials."""

import json
from pathlib import Path
import re
import subprocess
import sys


def git_state():
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    )
    if revision.returncode != 0:
        return {"source_revision": None, "source_dirty": None}
    dirty = subprocess.run(
        ["git", "status", "--porcelain"], capture_output=True, text=True, check=True
    )
    return {
        "source_revision": revision.stdout.strip(),
        "source_dirty": bool(dirty.stdout.strip()),
    }


def describe(row_file, report):
    for line in row_file.read_text().splitlines():
        engine, driver, status, log = line.split("\t")
        lines = (report / log).read_text(errors="replace").splitlines()
        yield {
            "engine": engine,
            "driver": driver,
            "status": status,
            "version": next((line[8:] for line in lines if line.startswith("version ")), None),
            "passed_cases": [
                line[5:-5] for line in lines if line.startswith("case ") and line.endswith(" PASS")
            ],
            "log": log,
        }


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def contains_version(observed, expected):
    return re.search(rf"(?<![0-9.]){re.escape(expected)}(?![0-9.])", observed or "") is not None


def validate_rows(rows, engines, versions):
    manifest = json.loads(Path(__file__).with_name("drivers.json").read_text())
    actual = {}
    errors = []
    for row in rows:
        key = (row["engine"], row["driver"])
        if key in actual:
            errors.append(f"Duplicate row {key[0]}/{key[1]}")
        actual[key] = row
    for engine in engines:
        config = manifest[engine]
        if not contains_version(versions.get(engine), config["native_version"]):
            errors.append(f"{engine}: expected native version {config['native_version']}")
        for driver, requirements in config["drivers"].items():
            row = actual.pop((engine, driver), None)
            if row is None:
                errors.append(f"Missing row {engine}/{driver}")
                continue
            if row["status"] != "passed":
                continue
            missing_versions = [
                version for version in requirements["version"]
                if not contains_version(row["version"], version)
            ]
            required_cases = requirements["cases"] + ["native-independent-rollback"]
            if driver != "raw":
                required_cases += config["common_cases"]
            missing_cases = sorted(set(required_cases).difference(row["passed_cases"]))
            if missing_versions or missing_cases:
                row["status"] = "failed"
                row["missing_versions"] = missing_versions
                row["missing_cases"] = missing_cases
                errors.append(f"{engine}/{driver}: required versions or cases missing")
    errors.extend(f"Unexpected row {engine}/{driver}" for engine, driver in actual)
    return errors


def main():
    report = Path(sys.argv[1])
    started, finished, status, selected = sys.argv[2:]
    engines = selected.split()
    rows = list(describe(report / "rows.tsv", report))
    native_versions = {}
    for engine in engines:
        version_file = report / f"{engine}-native-version.txt"
        if version_file.is_file():
            native_versions[engine] = version_file.read_text().strip()
    errors = validate_rows(rows, engines, native_versions)
    counts = {
        outcome: sum(row["status"] == outcome for row in rows)
        for outcome in ("passed", "failed", "blocked")
    }
    failed = status != "0" or bool(errors) or counts["failed"] > 0 or counts["blocked"] > 0
    write_json(
        report / "env.json",
        {
            "run_kind": "local",
            "scope": "isolated_protocol_fixture",
            "native_engines": native_versions,
            "docker_version": (report / "docker-version.txt").read_text().strip(),
            "compose_version": (report / "compose-version.txt").read_text().strip(),
            **git_state(),
        },
    )
    write_json(
        report / "report.json",
        {
            "run_id": report.name,
            "scope": "isolated_protocol_fixture",
            "status": "failed" if failed else "passed",
            "started_at": started,
            "finished_at": finished,
            "engines": engines,
            "counts": counts,
            "validation_errors": errors,
            "rows": rows,
        },
    )
    table = ["| Engine | Driver | Status | Observed version |", "|---|---|---|---|"]
    for row in rows:
        table.append(
            f"| {row['engine']} | {row['driver']} | {row['status']} | {row['version'] or 'Unavailable'} |"
        )
    summary = [
        "# P1 isolated protocol fixture",
        "",
        f"{counts['passed']} passed, {counts['failed']} failed, {counts['blocked']} blocked.",
        "",
        "These results cover the isolated fixture and its seeded native engine.",
        "Production branch admission, SQL rewriting, and release Gate evidence are separate.",
        "",
        *table,
        "",
    ]
    if errors:
        summary.extend([*(f"- {error}" for error in errors), ""])
    (report / "summary.md").write_text("\n".join(summary))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
