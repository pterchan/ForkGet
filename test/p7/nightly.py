#!/usr/bin/env python3
"""Run one exact-revision nightly attempt; this command installs no scheduler."""

import argparse
from datetime import UTC, datetime
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def check_source(revision, source_root):
    top = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], cwd=source_root, text=True).strip()
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source_root, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=source_root, text=True)
    if Path(top).resolve() != source_root or not re.fullmatch(r"[0-9a-f]{40}", revision) or actual != revision or dirty:
        raise ValueError("Nightly requires the requested full SHA and a clean checkout")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--report-root", type=Path)
    parser.add_argument("--check", action="store_true", help="validate inputs without running tests")
    args = parser.parse_args()
    source_root = args.source_root.resolve()
    check_source(args.source_revision, source_root)
    root = (args.report_root or source_root / "target/p7-evidence").resolve()
    if args.check:
        print(json.dumps({"source_revision": args.source_revision, "report_root": str(root)}))
        return 0
    root.mkdir(parents=True, exist_ok=True)
    with (root / "nightly.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        started = datetime.now(UTC)
        attempt = root / "attempts" / f"{started:%Y%m%dT%H%M%S%fZ}-{os.getpid()}"
        attempt.mkdir(parents=True)
        command = ["make", "p7-gate", "PROFILE=nightly", "ENGINE=all"]
        status = {"source_revision": args.source_revision, "started_at": started.isoformat(),
                  "command": command, "status": "running"}
        record = attempt / "attempt.json"
        record.write_text(json.dumps(status, indent=2) + "\n")
        exit_code = 1
        try:
            with (attempt / "output.log").open("w") as output:
                exit_code = subprocess.call(command, cwd=source_root, stdout=output, stderr=subprocess.STDOUT,
                    env=os.environ | {"FG_P7GATE_REPORT_ROOT": str(root), "PYTHONDONTWRITEBYTECODE": "1"})
            check_source(args.source_revision, source_root)
        except (OSError, ValueError, KeyboardInterrupt) as error:
            status["error"] = str(error)
            exit_code = 1
        finally:
            status |= {"finished_at": datetime.now(UTC).isoformat(), "exit_code": exit_code,
                       "status": "passed" if exit_code == 0 else "failed"}
            record.write_text(json.dumps(status, indent=2) + "\n")
        print(record)
        return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
