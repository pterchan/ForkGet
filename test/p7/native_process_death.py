#!/usr/bin/env python3
"""Kill a real snapshot process helper and verify its native child disconnects."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", required=True, type=Path)
    report = parser.parse_args().report_dir.resolve()
    report.mkdir(parents=True, exist_ok=False)
    name = "fg-native-parent-death-" + uuid.uuid4().hex[:12]
    def command(*args, **kwargs):
        return subprocess.run([str(arg) for arg in args], cwd=ROOT, text=True, capture_output=True, timeout=360, **kwargs)
    errors = []
    try:
        result = command("docker", "run", "--detach", "--rm", "--name", name, "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "-p", "127.0.0.1::5432", "postgres:16.14")
        if result.returncode:
            raise RuntimeError("Isolated PostgreSQL startup failed")
        port = command("docker", "inspect", "--format", '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}', name).stdout.strip()
        for _ in range(200):
            if command("docker", "exec", name, "pg_isready", "-U", "postgres").returncode == 0:
                break
            time.sleep(.1)
        environment = os.environ.copy()
        environment["FG_SNAPSHOT_TEST_PG_DSN"] = f"postgresql://postgres@127.0.0.1:{port}/postgres"
        result = command("cargo", "test", "--offline", "-p", "fg-control", "snapshot::tools::tests::native_parent_death", "--", "--ignored", "--exact", env=environment)
        (report / "native-parent-death.log").write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError("Actual process runner failed its native parent-death test")
    except Exception as error:
        errors.append(str(error))
    finally:
        command("docker", "rm", "-f", "-v", name)
    result = {"status": "failed" if errors else "passed", "errors": errors, "cleaned_up": True,
              "checks": ["Abrupt controller SIGKILL terminates the actual supervised native child PID and PostgreSQL connection"] if not errors else []}
    (report / "report.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result), flush=True)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
