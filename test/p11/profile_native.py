"""Sample release proxy/control CPU without stack memory or SQL payloads."""

import argparse
from functools import partial
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/p7"))
import gate
from gate_fixture import LOCAL_ROWS, refresh_gate
from gate_workloads import benchmark_ok, worker
from run_p2 import json_file, require


class Profile(gate.LocalGate):
    perf = None

    def execute(self):
        self.start_deployment()
        self.gate_generation = refresh_gate(self)
        self.reference_data()
        self.set_policy("dev", 50000)
        observations = []
        for workload in ("point", "insert"):
            branch, _ = self.create("cpu-profile-" + workload, write=workload == "insert")
            capture = None
            try:
                target, ca = self.load_target(branch)
                data = self.report / (workload + ".perf.data")
                pids = ",".join(str(self.processes[name].pid) for name in ("proxy", "control"))
                with (self.report / (workload + ".perf.log")).open("w") as output:
                    capture = subprocess.Popen([str(self.perf), "record", "-e", "cpu-clock", "-F", "99",
                        "-p", pids, "-o", str(data), "--", "sleep", "15"], stdout=output, stderr=subprocess.STDOUT)
                    # Flat instruction-pointer samples only: no user stacks,
                    # memory dumps, function arguments or SQL text collection.
                    load = self.timed_load([worker(workload, [target])] * 16, ca, LOCAL_ROWS, 2, 10)
                    code = capture.wait(timeout=20)
                require(code == 0 and data.is_file(), "Release CPU capture failed; inspect the diagnostic log")
                data.chmod(0o600)
                require(benchmark_ok(load), "Profile workload returned native/proxy errors")
                report = subprocess.run([str(self.perf), "report", "--stdio", "--no-children", "--sort",
                    "comm,dso,symbol", "-i", str(data)], text=True, capture_output=True, timeout=30)
                require(report.returncode == 0, "CPU sample decoding failed")
                (self.report / (workload + ".cpu.txt")).write_text(self.safe(report.stdout + report.stderr))
                observations.append({"workload": workload, "load": load, "capture_exit": code,
                    "sampling": "99 Hz cpu-clock, flat instruction pointer; proxy and control processes",
                    "scope": "On-CPU samples exclude native/network wait; 2-second warmup and 10-second diagnostic load are not Gate measurements"})
            finally:
                if capture is not None and capture.poll() is None:
                    capture.terminate()
                    capture.wait(timeout=5)
                self.drop_many([branch])
        json_file(self.report / "cpu-profile.json", {"binary_profile": "release", "observations": observations,
            "payload_collection": False, "user_stack_collection": False, "formal_performance_evidence": False})
        self.record("Release read/insert CPU samples and zero-error native workloads captured without payload or stack-memory collection")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engine", choices=("mysql", "postgresql"))
    parser.add_argument("--perf", required=True, type=Path)
    options = parser.parse_args()
    require(options.perf.is_file(), "Supply the installed Linux perf executable")
    Profile.perf = options.perf
    raise SystemExit(gate.smoke.p6.run_profile("p11-cpu", "Release CPU diagnostic",
        partial(Profile, profile="local"), [options.engine]))
