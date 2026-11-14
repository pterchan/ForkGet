#!/usr/bin/env python3
"""Observe 100 real SQL transactions; this diagnostic is not a timed Gate load."""

import argparse
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import UTC, datetime
import json
import math
import os
from pathlib import Path
import socket
import statistics
import sys
from threading import local
import time
from types import SimpleNamespace

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import sql_audit
from run_p2 import OWNER_A, json_file, require, wait_until
from write_cases import Probe

TRANSACTIONS = 100
FIRST_KEY = 10_000
META_MESSAGE = "metadata write operation"
CLEANUP_MESSAGE = "Completed witness cleanup batch"
META_PHASES = {
    "pool_acquire_including_health_and_connect", "transaction_begin", "transaction_commit", "policy_lock",
    "branch_lock", "attempt_lock", "witness", "intent", "fresh_scope", "effective_policy", "admission",
    "approval", "audit_event", "persist_attempt", "mongo_step",
}
COUNTERS = ("started", "completed", "failed", "cancelled")


def distribution(values):
    ordered = sorted(values)
    return {"count": len(ordered), "total": sum(ordered), "mean": statistics.mean(ordered) if ordered else 0,
            "p50": statistics.median(ordered) if ordered else 0,
            "p95": ordered[max(0, math.ceil(len(ordered) * .95) - 1)] if ordered else 0,
            "max": ordered[-1] if ordered else 0, "samples": list(values)}


def route_class(path):
    path = path.split("?", 1)[0]
    for suffix, name in (("/audit/decisions", "decision"), ("/write-fence", "fence"),
                         ("/audit/outcome", "outcome"), ("/audit/status", "audit_status"),
                         ("/policy/validate", "policy_validate"), ("/lease", "lease"),
                         ("/policy", "policy_fetch"), ("/allocate", "allocation"),
                         ("/resolve", "resolve"), ("/proxy/start", "proxy_registration")):
        if path.endswith(suffix):
            return name
    return "approval" if "/approvals/" in path else "other"


class HttpProfile(sql_audit.ControlRelay):
    def __init__(self, run):
        self.phase, self.samples, self.current = "setup", [], local()
        super().__init__(SimpleNamespace(control_url=run.control_url), self.observe_response)

    def observe_response(self, _method, _path, status, _body):
        self.current.status = status
        self.current.upstream_reply = time.perf_counter_ns()
        return False

    def forward(self, handler):
        started, phase = time.perf_counter_ns(), self.phase
        self.current.status = None
        self.current.upstream_reply = None
        try:
            super().forward(handler)
        finally:
            ended = time.perf_counter_ns()
            self.samples.append({"phase": phase, "route": route_class(handler.path), "status": self.current.status,
                "elapsed_ms": (ended - started) / 1_000_000,
                "upstream_reply_ms": ((self.current.upstream_reply - started) / 1_000_000
                                      if self.current.upstream_reply is not None else None)})


class TappedStream:
    def __init__(self, stream, observe):
        self.stream, self.observe = stream, observe

    def fileno(self):
        return self.stream.fileno()

    def pending(self):
        return self.stream.pending()

    def recv(self, size):
        return self.stream.recv(size)

    def sendall(self, frame):
        self.observe(frame)
        self.stream.sendall(frame)


class WitnessTiming:
    def __init__(self, relay):
        self.relay = relay
        self.commands = sql_audit.CommandFrames(relay.run.family)
        self.pending = None

    def request(self, frame):
        _commits, _business, witnesses = self.commands.scan(frame)
        if witnesses:
            require(witnesses == 1 and self.pending is None, "The witness observer saw overlapping internal writes")
            self.pending = (time.perf_counter_ns(), self.relay.phase)

    def response(self, frame):
        if self.pending is None:
            return
        if self.relay.run.family == "postgresql":
            complete = frame[:1] == b"C" and frame[5:] == b"INSERT 0 1\0"
            failed = frame[:1] == b"E"
        else:
            complete, failed = frame[4:5] == b"\0", frame[4:5] == b"\xff"
        if complete or failed:
            started, phase = self.pending
            self.pending = None
            with self.relay.lock:
                self.relay.timings.append({"phase": phase, "completed": complete,
                    "elapsed_ms": (time.perf_counter_ns() - started) / 1_000_000})


class NativeProfile(sql_audit.NativeRelay):
    def __init__(self, run):
        super().__init__(run, "observe")
        self.phase, self.timings, self.socket_options = "setup", [], []

    def forward(self, client, server):
        options = {}
        for name, stream in (("proxy_to_relay", client), ("relay_to_native", server)):
            # The product sets TCP_NODELAY on both SQL legs. Extra observer
            # sockets must preserve that contract rather than add Nagle waits.
            stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            options[name + "_tcp_nodelay"] = stream.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)
            require(options[name + "_tcp_nodelay"] == 1,
                    "The diagnostic observer did not preserve TCP_NODELAY")
        with self.lock:
            self.socket_options.append(options)
        observation = WitnessTiming(self)
        # NativeRelay already reconstructs complete original protocol frames.
        # Taps observe their send boundaries without rewriting or delaying SQL.
        super().forward(TappedStream(client, observation.response), TappedStream(server, observation.request))

    def counters(self):
        with self.lock:
            return {"business": self.business_mutations, "witness": self.witness_mutations, "commit": self.commits}


def numeric(value, integer=False):
    require(type(value) in ((int,) if integer else (int, float)) and value >= 0 and math.isfinite(value),
            "A diagnostic timing or counter is not a finite nonnegative number")
    return value


def observations(text):
    metadata, cleanup = [], []
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        fields = event.get("fields", {})
        if fields.get("message") == META_MESSAGE:
            allowed = {"message", "operation", "engine", "status", "elapsed_ns", "phases",
                       "query_calls_started", "query_calls_completed", "query_calls_failed", "query_calls_cancelled"}
            require(set(fields) <= allowed and fields["operation"] in ("decision", "fence", "outcome")
                    and fields["engine"] in ("mysql", "postgresql", "tidb", "mongodb", "unsupported")
                    and fields["status"] in ("completed", "failed", "cancelled"), "Unexpected metadata diagnostic schema")
            numeric(fields["elapsed_ns"], True)
            counts = {key: numeric(fields["query_calls_" + key], True) for key in COUNTERS}
            require(counts["started"] == counts["completed"] + counts["cancelled"]
                    and counts["failed"] <= counts["completed"], "Metadata query counters are inconsistent")
            phases = json.loads(fields["phases"])
            require(set(phases) <= META_PHASES, "Metadata diagnostic exposed an unexpected phase")
            for phase in phases.values():
                require(set(phase) == {*COUNTERS, "elapsed_ns"}, "Unexpected metadata phase counters")
                for value in phase.values():
                    numeric(value, True)
                require(phase["started"] == phase["completed"] + phase["cancelled"]
                        and phase["failed"] <= phase["completed"], "Metadata phase counters are inconsistent")
            metadata.append({**{key: value for key, value in fields.items() if key not in ("message", "phases")}, "phases": phases})
        elif fields.get("message") == CLEANUP_MESSAGE:
            require(set(fields) <= {"message", "engine", "acknowledged_attempts", "native_delete_ms", "metadata_mark_ms",
                                    "native_commit_ms", "collection_total_ms"}
                    and fields["engine"] in ("mysql", "postgresql", "tidb", "mongodb", "unsupported"),
                    "Unexpected witness cleanup diagnostic schema")
            sample = {"engine": fields["engine"], "acknowledged_attempts": numeric(fields["acknowledged_attempts"], True),
                      "native_delete_ms": numeric(fields["native_delete_ms"]),
                      "metadata_mark_ms": numeric(fields["metadata_mark_ms"])}
            for phase in ("native_commit_ms", "collection_total_ms"):
                sample[phase + "_available"] = phase in fields
                if phase in fields:
                    sample[phase] = numeric(fields[phase])
            cleanup.append(sample)
    return metadata, cleanup


def summarize_http(samples):
    groups = defaultdict(list)
    for sample in samples:
        groups[(sample["phase"], sample["route"])].append(sample)
    return {phase: {route: {"requests": len(entries), "statuses": dict(Counter(str(entry["status"]) for entry in entries)),
            "elapsed_ms": distribution([entry["elapsed_ms"] for entry in entries]),
            "upstream_reply_ms": distribution([entry["upstream_reply_ms"] for entry in entries if entry["upstream_reply_ms"] is not None])}
            for (current, route), entries in groups.items() if current == phase}
            for phase in sorted({phase for phase, _route in groups})}


def summarize_metadata(entries):
    result = {}
    for operation in sorted({entry["operation"] for entry in entries}):
        current = [entry for entry in entries if entry["operation"] == operation]
        phases = {phase for entry in current for phase in entry["phases"]}
        result[operation] = {"operations": len(current),
            "elapsed_ns": distribution([entry["elapsed_ns"] for entry in current]),
            "query_calls": {key: sum(entry["query_calls_" + key] for entry in current) for key in COUNTERS},
            "phase_totals": {phase: {key: sum(entry["phases"].get(phase, {}).get(key, 0) for entry in current)
                             for key in (*COUNTERS, "elapsed_ns")} for phase in sorted(phases)},
            "phases_not_observed": sorted(META_PHASES - phases)}
    return result


class ProfileRun(sql_audit.AuditRun):
    def __init__(self, *arguments):
        super().__init__(*arguments)
        self.base_env["RUST_LOG"] = "warn,fg_meta::write_path=debug,fg_control::audit_cleanup=debug"

    def start_proxy(self):
        if not hasattr(self, "http_profile"):
            self.http_profile = HttpProfile(self)
            self.http_profile.__enter__()
        original = self.control_url
        self.control_url = self.http_profile.url
        try:
            sql_audit.p6.p5.EngineRun.start_proxy(self)
        finally:
            self.control_url = original

    def cleanup(self):
        try:
            super().cleanup()
        finally:
            if hasattr(self, "http_profile"):
                try:
                    self.http_profile.__exit__(None, None, None)
                finally:
                    json_file(self.report / "http-profile.json", {
                        "errors": self.http_profile.errors, "requests": self.http_profile.samples,
                        "summary": summarize_http(self.http_profile.samples)})

    @contextmanager
    def profiled_native(self):
        self.stop("proxy")
        port = self.native_port
        try:
            with NativeProfile(self) as relay:
                try:
                    self.native_port = relay.port
                    self.start_proxy()
                    self.native_port = port
                    yield relay
                finally:
                    self.native_port = port
                    self.stop("proxy")
                    json_file(self.report / "native-profile.json", {
                        "errors": relay.errors, "executions": relay.counters(), "witness_timings": relay.timings,
                        "observer_socket_options": relay.socket_options})
        finally:
            self.native_port = port
            self.start_proxy()

    def autocommit(self, client, key):
        statement = self.insert(key)
        if self.family == "postgresql":
            require(b"C" in client.query(statement.encode(), b"I"), "The simple autocommit write did not complete")
        else:
            client.count(statement, 1)

    def execute(self):
        self.verify_binaries()
        self.start_deployment()
        self.generation_command("profile-refresh", "refresh", "--snapshot", "v2", cooldown=0)
        self.set_policy("dev", 50000, bps=10000, floor=200)
        branch, credentials = self.create("write-profile")
        with self.profiled_native() as relay:
            with self.wire(branch) as client:
                self.http_profile.phase = relay.phase = "warmup"
                self.autocommit(client, FIRST_KEY - 1)
                before_ids = {row["id"] for row in self.settled(branch, 1)}
                before_native = relay.counters()
                log = self.report / "control.log"
                offset = log.stat().st_size
                self.http_profile.phase = relay.phase = "measured"
                started = time.perf_counter_ns()
                for key in range(FIRST_KEY, FIRST_KEY + TRANSACTIONS):
                    self.autocommit(client, key)
                wall_ms = (time.perf_counter_ns() - started) / 1_000_000
                wait_until("all measured HTTP outcomes observed", lambda: sum(
                    sample["phase"] == "measured" and sample["route"] == "outcome" for sample in self.http_profile.samples) == TRANSACTIONS)
                self.http_profile.phase = relay.phase = "recovery"
                endpoint = log.stat().st_size
            rows = self.settled(branch, TRANSACTIONS + 1)
            measured_rows = [row for row in rows if row["id"] not in before_ids]
            require(len(measured_rows) == TRANSACTIONS and all(row["decisions"] == row["outcomes"] == 1
                    and row["outcome"] == "committed" and row["resolution"] is None for row in measured_rows),
                    "One hundred normal transactions lack unique durable decision/outcome pairs")
            after_native = relay.counters()
            delta = {key: after_native[key] - before_native[key] for key in before_native}
            require(set(delta.values()) == {TRANSACTIONS}, "Normal work retried business DML or omitted a witness/COMMIT")
            timings = [sample for sample in relay.timings if sample["phase"] == "measured"]
            require(len(timings) == TRANSACTIONS and all(sample["completed"] for sample in timings),
                    "The native observer did not see one real successful witness completion per transaction")
            if self.family == "postgresql":
                require(relay.private_frames == list("PBECCH") * (TRANSACTIONS + 1),
                        "Normal witness timing did not follow the private PostgreSQL extended-protocol boundary")
            measured_http = [sample for sample in self.http_profile.samples if sample["phase"] == "measured"]
            counts = Counter(sample["route"] for sample in measured_http)
            expected = {"decision": 100, "fence": 100, "outcome": 100,
                        "lease": 200 if self.stage == "safety" else 0,
                        "policy_validate": 200 if self.stage == "safety" else 0}
            require(all(counts[route] == count for route, count in expected.items())
                    and set(counts) <= {*expected, "policy_fetch"}
                    and all(sample["status"] in (200, 204) for sample in measured_http),
                    "The observed SQL write RPC shape differs from the selected safety/optimized stage")
            expected_rows = [[key, 8, f"audit-{key}", None, None] for key in range(FIRST_KEY, FIRST_KEY + TRANSACTIONS)]
            query = f"SELECT id,tenant_id,code,parent_code,label FROM parents WHERE id>={FIRST_KEY} AND id<{FIRST_KEY + TRANSACTIONS} ORDER BY id"
            with Probe(self, "profile-typed-observer", credentials) as probe:
                require(probe.sql(query, "read").get("rows") == expected_rows, "Typed frontend business results differ after the hundred commits")
            relation = self.branch_relation(branch["id"], "parents")
            expression = ("jsonb_agg(jsonb_build_array(id,tenant_id,code,parent_code,label) ORDER BY id)::text" if self.family == "postgresql"
                          else "JSON_ARRAYAGG(JSON_ARRAY(id,tenant_id,code,parent_code,label))")
            native_rows = json.loads(self.native(f"SELECT {expression} FROM {relation} WHERE id>={FIRST_KEY} AND id<{FIRST_KEY + TRANSACTIONS};"))
            require(sorted(native_rows) == expected_rows, "Typed native business state differs from the hundred frontend results")
            recovery_started = time.perf_counter_ns()
            self.audit_reconcile("profile-recovery")
            wait_until("normal audit delivery and witness collection complete", lambda:
                self.witness_count(branch) == 0 and self.metadata(
                    f"SELECT count(*) FROM audit_attempt a WHERE branch_id={branch['id']} AND forkget_audit_pending(a);") == "0")
            recovery_ms = (time.perf_counter_ns() - recovery_started) / 1_000_000
            metadata, measured_cleanup = observations(log.read_bytes()[offset:endpoint].decode())
            meta_counts = Counter(entry["operation"] for entry in metadata)
            complete = (meta_counts == Counter({"decision": 100, "fence": 100, "outcome": 100})
                        and all(entry["status"] == "completed" and entry["query_calls_failed"] == entry["query_calls_cancelled"] == 0 for entry in metadata))
            json_file(self.report / "metadata-observations.json", {"status": "complete" if complete else "incomplete",
                "observed_operations": dict(meta_counts), "expected_operations": {"decision": 100, "fence": 100, "outcome": 100},
                "coverage": "decision/fence/outcome only; original Stage-A lease/context metadata queries are outside these counters",
                "observations": metadata})
            require(complete,
                    "The required real metadata write-path diagnostics are missing or contain failed operations")
            _unused, cleanup = observations(log.read_bytes()[endpoint:].decode() + "\n" + (self.report / "profile-recovery.log").read_text())
            json_file(self.report / "write-profile.json", {"stage": self.stage, "transactions": TRANSACTIONS,
                "qualification": "diagnostic relay run; not paired performance or release Gate evidence",
                "measured_wall_ms": wall_ms, "mandatory_rpc_requests": sum(expected.values()),
                "all_measured_http_requests": len(measured_http), "periodic_policy_refresh_requests": counts["policy_fetch"],
                "http_by_phase_and_route": summarize_http(self.http_profile.samples), "native_executions": delta,
                "native_witness_ms": distribution([sample["elapsed_ms"] for sample in timings]),
                "native_witness_boundary": "private_Execute_to_CommandComplete" if self.family == "postgresql" else "COM_QUERY_to_OK",
                "observer_tcp_nodelay": True,
                "observer_socket_options": relay.socket_options,
                "metadata": summarize_metadata(metadata), "metadata_query_scope": "top-level SQLx commands; pool acquisition/BEGIN/COMMIT are separate phases; not native wire packets",
                "metadata_operation_coverage": "decision/fence/outcome only; original Stage-A lease/context queries are not included",
                "cleanup_during_measured_window": measured_cleanup, "cleanup_after_measured_window": cleanup,
                "cleanup_phase_scope": "native DELETE, optional native COMMIT and metadata mark are separate timings; optional collection_total_ms covers the complete collection call including metadata, connection, BEGIN/lock and admin attestation; absent historical timings are unavailable",
                "recovery_wall_ms": recovery_ms, "pending_after_recovery": 0, "witness_rows_after_recovery": 0,
                "typed_native_frontend_equality": True, "unique_decisions": 100, "unique_outcomes": 100, "business_dml_retried": False})
        self.drop(OWNER_A, branch["id"])
        self.record(f"100 {self.stage} native transactions preserve exact business/audit/witness facts with complete RPC and SQLx-command observations")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=("safety", "optimized"), required=True)
    parser.add_argument("--engine", choices=("mysql", "postgresql", "tidb", "all"), default="all")
    parser.add_argument("--report-dir", type=Path, required=True)
    args = parser.parse_args()
    args.report_dir.mkdir(parents=True, exist_ok=False)
    revision, state = sql_audit.p6.p5.p34.p2.git_state()
    ProfileRun.stage, ProfileRun.suite_source_state = args.stage, state
    started = datetime.now(UTC)
    results = {}
    for engine in (("mysql", "postgresql", "tidb") if args.engine == "all" else (args.engine,)):
        results[engine] = sql_audit.p6.p5.p34.run_engine(engine, args.report_dir,
            f"fgp12profile-{started:%H%M%S}-{os.getpid()}", ProfileRun)
    passed = all(result["status"] == "passed" for result in results.values())
    json_file(args.report_dir / "report.json", {"status": "passed" if passed else "failed", "stage": args.stage,
        "source_revision": revision, "source_state": state, "engines": results,
        "qualification": "focused diagnostic; timings are not paired qualification samples",
        "started_at": started.isoformat(), "finished_at": datetime.now(UTC).isoformat()})
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
