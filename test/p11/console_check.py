"""Run frontend checks with Linux Node or the Windows Node host from WSL."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", required=True, type=Path)
    parser.add_argument("--report-dir", required=True, type=Path)
    options = parser.parse_args()
    report = options.report_dir.resolve()
    report.mkdir(parents=True)
    node = options.node.resolve()
    if node.name.endswith(".exe"):
        npm = node.parent / "node_modules/npm/bin/npm-cli.js"
        argument = subprocess.check_output(["wslpath", "-w", str(npm)], text=True).strip()
        prefix = [str(node), argument]
    else:
        npm = shutil.which("npm")
        if not npm:
            raise ValueError("Install npm alongside Node.js")
        prefix = [npm]
    environment = {key: value for key, value in os.environ.items() if not key.startswith("FG_CONSOLE_")}
    stages = []
    for script in ("check", "test", "build", "test:browser"):
        with (report / (script.replace(":", "-") + ".log")).open("w") as output:
            code = subprocess.call([*prefix, "run", script], cwd=ROOT / "apps/console", env=environment,
                                   stdout=output, stderr=subprocess.STDOUT)
        stages.append({"script": script, "exit_code": code})
        if code:
            break
    results = ROOT / "apps/console/artifacts/browser-results.json"
    if stages[-1]["script"] == "test:browser" and stages[-1]["exit_code"] == 0:
        shutil.copyfile(results, report / "browser-results.json")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    status = "failed" if any(item["exit_code"] for item in stages) else "passed"
    (report / "report.json").write_text(json.dumps({"source_revision": revision, "status": status,
        "stages": stages, "live_scope": "Separate native suite must run both real-backend cases on each engine; ordinary browser run skips these two."}, indent=2) + "\n")
    return int(status == "failed")


if __name__ == "__main__":
    raise SystemExit(main())
