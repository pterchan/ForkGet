"""Count release-path control round trips; this relay is not a performance Gate."""

from functools import partial
from contextlib import closing
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import statistics
import sys
from threading import Lock, Thread
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/p7"))
import gate
from gate_fixture import refresh_gate
from run_p2 import json_file, require
from write_cases import Probe, check_count


class Profile(gate.LocalGate):
    def start_proxy(self):
        destination = urlsplit(self.control_url)
        self.observations = []
        self.observation_lock = Lock()
        self.phase = "setup"
        runner = self

        class Relay(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_arguments):
                pass

            def do_POST(self):
                self.forward()

            def do_GET(self):
                self.forward()

            def forward(self):
                size = int(self.headers.get("Content-Length", "0"))
                allowed = (self.command == "POST" and self.path.startswith("/internal/v1/")) or (
                    self.command == "GET" and self.path in {"/health/ready", "/health/live"})
                if size > 8192 or not allowed:
                    self.send_error(400)
                    return
                body = self.rfile.read(size)
                started = time.perf_counter()
                with closing(HTTPConnection(destination.hostname, destination.port, timeout=25)) as connection:
                    connection.request(self.command, self.path, body, {"Authorization": self.headers.get("Authorization", ""),
                        "Content-Type": "application/json"})
                    response = connection.getresponse()
                    payload = response.read()
                    status, content_type = response.status, response.getheader("Content-Type", "application/json")
                elapsed = time.perf_counter() - started
                # Neither request/response payloads, credentials nor raw URLs are retained.
                parts = self.path.split("/")
                route = "/".join("{id}" if part.isdecimal() else part for part in parts)
                with runner.observation_lock:
                    runner.observations.append({"phase": runner.phase, "route": route,
                                                "status": status, "elapsed_seconds": elapsed})
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.relay = ThreadingHTTPServer(("127.0.0.1", 0), Relay)
        self.relay.daemon_threads = True
        self.relay_thread = Thread(target=self.relay.serve_forever, daemon=True)
        self.relay_thread.start()
        original = self.control_url
        self.control_url = f"http://127.0.0.1:{self.relay.server_port}"
        try:
            super().start_proxy()
        finally:
            self.control_url = original

    def execute(self):
        branch = None
        try:
            self.start_deployment()
            self.gate_generation = refresh_gate(self, 250)
            self.reference_data()
            self.set_policy("dev", 50000)
            branch, credentials = self.create("profile-control")
            with Probe(self, "profile-control", credentials) as probe:
                require(probe.sql("SELECT id FROM orders WHERE tenant_id=1 AND id=1", "read").get("rows") is not None,
                        "Profile warmup failed")
                for phase, count, statement in (
                    ("point-read", 100, "SELECT id FROM orders WHERE tenant_id=1 AND id=1"),
                    ("autocommit-update", 10, "UPDATE orders SET note='profile-value' WHERE tenant_id=1 AND id=1"),
                    ("explicit-transaction-update", 10, "UPDATE orders SET note='profile-next' WHERE tenant_id=1 AND id=1"),
                ):
                    self.phase = phase
                    started = time.perf_counter()
                    if phase.startswith("explicit"):
                        check_count(probe, "BEGIN", 0)
                    for index in range(count):
                        current = statement.replace("profile-value", f"profile-value-{index}").replace("profile-next", f"profile-next-{index}")
                        result = probe.sql(current, "read" if phase == "point-read" else "text")
                        require("rows" in result if phase == "point-read" else result.get("affected") in {0, 1},
                                "Release profiling statement failed")
                    if phase.startswith("explicit"):
                        check_count(probe, "COMMIT", 0)
                    phase_elapsed = time.perf_counter() - started
                    with self.observation_lock:
                        values = [item for item in self.observations if item["phase"] == phase]
                    grouped = {}
                    for item in values:
                        grouped.setdefault(item["route"], []).append(item["elapsed_seconds"])
                    json_file(self.report / (phase + ".json"), {
                        "binary_profile": "release", "statements": count, "wall_seconds_with_relay": phase_elapsed,
                        "control_calls": len(values), "control_seconds": sum(item["elapsed_seconds"] for item in values),
                        "routes": {route: {"count": len(timings), "total_seconds": sum(timings),
                            "median_seconds": statistics.median(timings)} for route, timings in grouped.items()},
                        "non_success_statuses": sorted({item["status"] for item in values if item["status"] >= 400}),
                        "scope": "Loopback relay adds overhead; counts identify control boundaries, timings include HTTP and metadata. Not a paired benchmark or a native/encoding CPU profile."})
            self.record("Release-path point/autocommit/explicit-transaction control round trips observed without payload logging")
        finally:
            self.phase = "cleanup"
            if branch:
                self.drop_many([branch])
            if hasattr(self, "relay"):
                self.relay.shutdown()
                self.relay.server_close()
                self.relay_thread.join(timeout=5)


if __name__ == "__main__":
    raise SystemExit(gate.smoke.p6.run_profile("p11-profile", "Release control round-trip diagnostic",
        partial(Profile, profile="local")))
