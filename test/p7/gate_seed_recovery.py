#!/usr/bin/env python3
"""Exercise actual control refresh validation and compensation over test TLS.

The relay forwards every protocol frame unchanged. It pauses the first native
validation PREPARE/Parse after load, lets an independent administrator corrupt
the inactive target, and pauses compensation before its first owned-table DROP
to preserve the real diagnostic while the damaged target still exists.
"""

import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
import select
import subprocess
import sys
import tempfile
from threading import Event

import snapshot_import as fixture

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "p6"))
from faults import CommitReply
from gate_fixture import baseline_witness

p34 = fixture.p34
require = fixture.require
json_file = fixture.json_file
BOUNDARIES = (1, 25_001, 99_999, 100_000, 100_001)
CORRUPT_ROWS = 25_001
FRAME_LIMIT = 2 * 1024 * 1024


class NativeFrames:
    """Keep complete original frames, including prepared native SQL commands."""

    def __init__(self, family):
        self.mysql = family != "postgresql"
        self.startup = not self.mysql
        self.buffer = bytearray()

    def feed(self, data):
        self.buffer.extend(data)
        while self.buffer:
            start = 0 if self.mysql or self.startup else 1
            if len(self.buffer) < start + 4:
                break
            size = (4 + int.from_bytes(self.buffer[:3], "little") if self.mysql
                    else start + int.from_bytes(self.buffer[start:start + 4], "big"))
            if not 4 <= size <= FRAME_LIMIT:
                raise ValueError("Unexpected native test frame length")
            if len(self.buffer) < size:
                break
            frame = bytes(self.buffer[:size])
            del self.buffer[:size]
            sql, kind = None, None
            if self.mysql:
                if size > 5 and frame[3] == 0 and frame[4] in (3, 22):
                    sql = frame[5:]
                    kind = "COM_QUERY" if frame[4] == 3 else "COM_STMT_PREPARE"
            elif not self.startup:
                if frame[0] == ord("Q"):
                    sql, kind = frame[5:-1], "Query"
                elif frame[0] == ord("P"):
                    fields = frame[5:].split(b"\0", 2)
                    if len(fields) != 3:
                        raise ValueError("Invalid native test Parse frame")
                    sql, kind = fields[1], "Parse"
            self.startup = False
            yield frame, sql, kind


class SeedValidationPause(CommitReply):
    def __init__(self, run):
        super().__init__(run, native=True)
        self.reached, self.resume = Event(), Event()
        self.cleanup_reached, self.cleanup_resume = Event(), Event()
        self.generation_id = None
        self.relation = None
        self.validation_kind = None
        self.cleanup_kind = None
        self.validation_matches = 0

    def disconnect(self):
        self.resume.set()
        self.cleanup_resume.set()
        super().disconnect()

    def pause(self, sql, kind):
        if sql is None:
            return
        markers = (b" AS row_count", b" AS invalid_ids", b" AS invalid_notes", b" WHERE tenant_id = 7")
        if all(marker in sql for marker in markers):
            match = re.search(rb'FROM ([`"]fg_g([0-9]+)[`"]\.[`"]orders[`"]) WHERE tenant_id = 7$', sql)
            if match is None:
                raise ValueError("Unexpected native seed-validation relation")
            with self.lock:
                self.validation_matches += 1
                first = self.generation_id is None
                if first:
                    self.generation_id = int(match[2])
                    self.relation = match[1].decode("ascii")
                    self.validation_kind = kind
            if first:
                self.reached.set()
                if not self.resume.wait(60):
                    raise ValueError("Seed corruption was not released")
        if (self.generation_id is not None and sql.startswith(b"DROP TABLE")
                and (f"_d_g{self.generation_id}_".encode() in sql
                     or f"fg_g{self.generation_id}".encode() in sql)):
            with self.lock:
                first_drop = self.cleanup_kind is None
                if first_drop:
                    self.cleanup_kind = kind
            if first_drop:
                self.cleanup_reached.set()
                if not self.cleanup_resume.wait(60):
                    raise ValueError("Seed compensation was not released")

    def forward(self, client, server):
        frames = NativeFrames(self.run.family)
        while not self.done.is_set():
            readable = [stream for stream in (client, server) if stream.pending()]
            if not readable:
                readable, _, _ = select.select([client, server], [], [], .05)
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                if source is client:
                    for original, sql, kind in frames.feed(data):
                        self.pause(sql, kind)
                        server.sendall(original)
                else:
                    client.sendall(data)


class GateRecovery(fixture.SnapshotRun):
    def environment(self):
        return super().environment() | {"FG_REFRESH_COOLDOWN_SECONDS": "0"}

    def control(self, label, *arguments, succeeds=True):
        return self.call(label, [self.executable("fg-control"), *arguments],
                         env=self.environment(), log=True, timeout=900, succeeds=succeeds)

    def rows(self, generation):
        snapshot = self.metadata(f"SELECT snapshot FROM generation WHERE id={generation};")
        require(snapshot.startswith("gate-v2-"), "Expected the retained real gate generation")
        return baseline_witness(self, generation, int(snapshot.rsplit("-", 1)[1]))

    def loaded(self, relation):
        json_object = "json_build_object" if self.family == "postgresql" else "JSON_OBJECT"
        note = ("encode(convert_to(note,'UTF8'),'hex')='" + "f09f9ba0" * 64 + "'" if self.family == "postgresql"
                else "HEX(note)='" + "F09F9BA0" * 64 + "'")
        statement = f"""SELECT {json_object}('rows',COUNT(*),'min_id',MIN(id),'max_id',MAX(id),
            'min_characters',MIN(CHAR_LENGTH(note)),'max_characters',MAX(CHAR_LENGTH(note)),
            'min_bytes',MIN(OCTET_LENGTH(note)),'max_bytes',MAX(OCTET_LENGTH(note)),
            'exact_notes',SUM(CASE WHEN {note} THEN 1 ELSE 0 END))
            FROM {relation} WHERE tenant_id=7;"""
        return json.loads(self.native(statement))

    def absent(self, generation):
        schema = self.native(f"SELECT count(*) FROM information_schema.schemata WHERE schema_name='fg_g{generation}';")
        deltas = self.metadata(f"SELECT delta_table FROM catalog_table WHERE generation_id={generation} ORDER BY id;").splitlines()
        remaining = [name for name in deltas if self.native(
            "SELECT count(*) FROM information_schema.tables WHERE table_schema='forkget_delta' "
            f"AND table_name='{name}';") != "0"]
        return schema == "0" and not remaining

    def positive(self, count, label):
        previous = self.active()
        self.control(label, "refresh", "--gate-orders", str(count))
        active = self.active()
        require(active != previous and self.metadata(f"SELECT snapshot FROM generation WHERE id={active};") == f"gate-v2-{count}",
                "Actual refresh did not activate the requested verified gate generation")
        require(self.metadata(f"SELECT status FROM refresh_job WHERE target_generation_id={active};") == "succeeded",
                "A successful gate refresh lacks its succeeded job")
        require(self.metadata(f"SELECT baseline_rows FROM catalog_table WHERE generation_id={active} AND logical_table='orders';") == str(count + 4),
                "Activated catalog count differs from native gate content")
        witness = baseline_witness(self, active, count)
        self.control(label + "-retire", "retire", "--generation", str(previous))
        require(self.absent(previous), "Successful refresh retirement left old owned objects")
        return {"rows": count, "generation_id": active, "previous_retired": previous, "witness": witness}

    def corrupt(self, category, relay):
        relation = relay.relation
        if category == "missing_row":
            sql = f"DELETE FROM {relation} WHERE tenant_id=7 AND id=1;"
        elif category == "out_of_range":
            sql = f"UPDATE {relation} SET id={CORRUPT_ROWS + 1} WHERE tenant_id=7 AND id={CORRUPT_ROWS};"
        else:
            note = "repeat(chr(128512),64)" if self.family == "postgresql" else "REPEAT(CONVERT(X'F09F9880' USING utf8mb4),64)"
            sql = f"UPDATE {relation} SET note={note} WHERE tenant_id=7 AND id=1;"
        self.native(sql)

    def failure(self, category):
        old = self.active()
        before = self.rows(old)
        log_path = self.report / (category + ".log")
        process = None
        result = {"category": category, "old_active": old, "requested_rows": CORRUPT_ROWS}
        with SeedValidationPause(self) as relay, log_path.open("w", encoding="utf-8") as output:
            environment = self.environment()
            account = "postgres" if self.family == "postgresql" else "root"
            environment["FG_BACKEND_ADMIN_DSN"] = self.dsn(account, self.secret["native"], relay.port, "p2_native")
            try:
                process = subprocess.Popen([self.executable("fg-control"), "refresh", "--gate-orders", str(CORRUPT_ROWS)],
                                           cwd=fixture.ROOT, env=environment, stdout=output, stderr=subprocess.STDOUT)
                require(relay.reached.wait(90), "Actual refresh did not reach the native validation pause")
                generation = relay.generation_id
                result.update(generation_id=generation, validation_frame=relay.validation_kind,
                              before_corruption=self.loaded(relay.relation))
                require(result["before_corruption"] == {"rows": CORRUPT_ROWS, "min_id": 1, "max_id": CORRUPT_ROWS,
                        "min_characters": 64, "max_characters": 64, "min_bytes": 256, "max_bytes": 256,
                        "exact_notes": CORRUPT_ROWS}, "The complete original Unicode seed was not loaded before corruption")
                require(self.active() == old and self.metadata(f"SELECT status FROM generation WHERE id={generation};") == "importing",
                        "Inactive target activated before its native validation")
                self.corrupt(category, relay)
                result["after_corruption"] = self.loaded(relay.relation)
                relay.resume.set()
                require(relay.cleanup_reached.wait(90), "Validation failure did not enter actual native compensation")
                events = []
                for line in log_path.read_text().splitlines():
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
                diagnostics = [event for event in events if event.get("fields", {}).get("message") == "gate seed validation failed before compensation"]
                require(len(diagnostics) == 1, "Actual validation did not emit its diagnostic before native cleanup")
                fields = diagnostics[0]["fields"]
                require(fields.get("component") == "gate_seed" and fields.get("engine") == self.engine
                        and fields.get("expected_rows") == CORRUPT_ROWS and "Verification" in fields.get("actual", ""),
                        "Pre-compensation diagnostic lost its safe typed validation counts")
                observation = fields["actual"]
                expected = {"missing_row": (f"rows: {CORRUPT_ROWS - 1}", "min_id: Some(2)"),
                            "out_of_range": ("invalid_ids: 1", f"max_id: Some({CORRUPT_ROWS + 1})"),
                            "content": ("invalid_notes: 1", "min_note_bytes: Some(256)")}[category]
                require(all(value in observation for value in expected), "The native diagnostic did not identify the injected corruption")
                contexts = [event for event in events if event.get("fields", {}).get("reason") == "snapshot_build_failed_before_activation"]
                require(len(contexts) == 1 and contexts[0]["fields"].get("generation_id") == generation
                        and contexts[0]["fields"].get("engine") == self.engine
                        and contexts[0]["fields"].get("message") == "generation failed; collecting only its owned objects"
                        and events.index(diagnostics[0]) < events.index(contexts[0]),
                        "Pre-cleanup counts lack their matching numeric generation context or event ordering")
                result.update(diagnostic_before_first_drop=diagnostics[0], generation_context_before_first_drop=contexts[0],
                              compensation_frame=relay.cleanup_kind,
                              target_still_present_at_diagnostic=self.native(f"SELECT count(*) FROM information_schema.schemata WHERE schema_name='fg_g{generation}';") == "1")
                require(result["target_still_present_at_diagnostic"] and self.active() == old,
                        "Diagnostic was captured only after the damaged target disappeared or replaced active")
                json_file(self.report / (category + "-before-compensation.json"), result)
                relay.cleanup_resume.set()
                result["exit_code"] = process.wait(timeout=120)
                require(result["exit_code"] != 0 and relay.validation_matches == 1,
                        "A corrupted target succeeded or validation was silently retried")
            finally:
                relay.resume.set()
                relay.cleanup_resume.set()
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)
        generation = result["generation_id"]
        result.update(generation_state=self.metadata(f"SELECT status || '|' || native_claimed::text FROM generation WHERE id={generation};"),
                      job_state=self.metadata(f"SELECT status FROM refresh_job WHERE target_generation_id={generation};"),
                      owned_objects_removed=self.absent(generation), old_active_unchanged=self.active() == old and self.rows(old) == before)
        require(result["generation_state"] == "failed|false" and result["job_state"] == "failed"
                and result["owned_objects_removed"] and result["old_active_unchanged"],
                "Actual failed refresh left native claims/objects, changed old rows, or replaced the active generation")
        json_file(self.report / (category + "-result.json"), result)
        self.record(category + ": real refresh emits pre-cleanup diagnostic, fails privately and compensates without changing active")
        return result

    def execute(self):
        self.mysql = self.family != "postgresql"
        self.start_databases()
        self.native_roles()
        self.control("migrate", "migrate")
        self.control("bootstrap", "bootstrap")
        boundaries = [self.positive(count, f"positive-{count}") for count in BOUNDARIES]
        json_file(self.report / "positive-boundaries.json", boundaries)
        self.record("All five actual control refresh boundaries activate exact Unicode data/catalog and retire their previous native generation")
        failures = [self.failure(category) for category in ("missing_row", "out_of_range", "content")]
        retry = self.positive(CORRUPT_ROWS, "recovery-retry")
        json_file(self.report / "recovery.json", {"boundaries": boundaries, "failures": failures, "successful_retry": retry})
        self.record("A real no-fault refresh succeeds after all three failed native imports and compensations")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=["mysql", "postgresql", "tidb", "all"], default="all")
    parser.add_argument("--report-dir", type=Path, required=True)
    arguments = parser.parse_args()
    report = arguments.report_dir.resolve()
    report.mkdir(parents=True, exist_ok=False)
    started = datetime.now(UTC)
    results = {}
    for engine in (["mysql", "postgresql", "tidb"] if arguments.engine == "all" else [arguments.engine]):
        detail = report / engine
        detail.mkdir()
        with tempfile.TemporaryDirectory(prefix="fg-gate-seed-recovery-") as temporary:
            workspace = Path(temporary)
            certs = workspace / "certs"
            p34.p2.build_certs(certs)
            runner = GateRecovery(engine, detail, workspace, certs, f"fgseedrecovery-{started:%H%M%S}-{os.getpid()}")
            errors = []
            try:
                runner.execute()
            except Exception as error:
                errors.append(runner.safe(str(error)))
            finally:
                try:
                    runner.cleanup()
                except Exception as error:
                    errors.append(runner.safe(str(error)))
            results[engine] = {"status": "failed" if errors else "passed", "version": runner.engine_version,
                               "checks": runner.cases, "errors": errors, "cleaned_up": not runner.compose_started}
            print(json.dumps({engine: results[engine]}), flush=True)
            json_file(report / "report.json", {"status": "running", "engines": results})
    revision, state = p34.p2.git_state()
    json_file(report / "env.json", {"source_revision": revision, "source_state": state, "started_at": started.isoformat(),
              "scope": "Actual fg-control refresh boundaries and TLS-framed native fault injection before validation; no production hooks or SQL rewrites"})
    passed = all(result["status"] == "passed" and result["cleaned_up"] for result in results.values())
    json_file(report / "report.json", {"status": "passed" if passed else "failed", "engines": results})
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
