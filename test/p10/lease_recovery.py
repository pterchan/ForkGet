#!/usr/bin/env python3
"""Run the real Rust lease/retirement/Git methods on disposable PostgreSQL."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]


def command(*args, **options):
    return subprocess.run(args, capture_output=True, text=True, check=True, **options)


def main():
    output = Path(os.environ.get("FG_P10_LEASE_REPORT_ROOT", ROOT / "target/p10-leases"))
    output.mkdir(parents=True, exist_ok=True)
    name = "fg-p10-leases-" + uuid.uuid4().hex[:12]
    report = {"suite": "p10-lease-recovery", "started_at": datetime.now(timezone.utc).isoformat(),
              "source_revision": command("git", "rev-parse", "HEAD", cwd=ROOT).stdout.strip(),
              "dirty": bool(command("git", "status", "--porcelain", cwd=ROOT).stdout), "passed": False}
    command("docker", "run", "--detach", "--rm", "--name", name,
            "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "-p", "127.0.0.1::5432", "postgres:16.14")
    try:
        deadline = time.monotonic() + 30
        while subprocess.run(["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"],
                             capture_output=True).returncode:
            if time.monotonic() >= deadline:
                raise RuntimeError("disposable PostgreSQL readiness timed out")
            time.sleep(0.2)
        port = command("docker", "inspect", "--format",
                       '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}', name).stdout.strip()
        dsn=f"postgresql://postgres@127.0.0.1:{port}/postgres"
        environment = os.environ | {"FG_T10_LEASE_DSN":dsn,"DATABASE_URL":dsn}
        report["suites"]=[]
        commands=[("lease-replay","fg-meta",["--test","lease_recovery","--test","replay_jobs"]),
                  ("budget","fg-meta",["--lib","budget::tests"]),
                  ("migration-history","fg-meta",["--lib","migrations::tests"]),
                  ("durable-audit","fg-meta",["--lib","audit_journal::tests"]),
                  ("batched-catalog","fg-meta",["--lib","catalog::tests"]),
                  ("native-witness-lock","fg-control",["--bin","fg-control","writable::audit::tests"])]
        for label,package,selection in commands:
            result = subprocess.run(["cargo", "test", "--locked", "-p", package, *selection, "--",
                                     "--ignored", "--test-threads=1", "--nocapture"], cwd=ROOT,
                                    env=environment, text=True, capture_output=True, timeout=300)
            (output / f"{label}.log").write_text(result.stdout + result.stderr)
            report["suites"].append({"name":label,"exit_code":result.returncode})
            if result.returncode:
                raise RuntimeError(f"metadata recovery tests failed; see {label}.log")
        report["passed"] = True
    finally:
        subprocess.run(["docker", "rm", "--force", name], capture_output=True, check=False)
        report["cleanup_verified"] = subprocess.run(["docker", "inspect", name], capture_output=True).returncode != 0
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report))


if __name__ == "__main__":
    main()
