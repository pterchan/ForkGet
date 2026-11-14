"""Check diagnostic observers and privacy boundaries without native services."""

import json
from threading import Lock
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import write_profile as profile
from faults import WITNESS_COLUMNS
from run_p2 import Failure


def pg(tag, body=b""):
    return tag + (len(body) + 4).to_bytes(4, "big") + body


def witness(relation):
    return b"INSERT INTO " + relation + WITNESS_COLUMNS + b"1)"


def relay(family):
    return SimpleNamespace(run=SimpleNamespace(family=family), phase="measured", timings=[], lock=Lock())


class WitnessObserverTests(unittest.TestCase):
    def test_pg_times_execute_completion_and_preserves_original_phase(self):
        native = relay("postgresql")
        observer = profile.WitnessTiming(native)
        observer.request((8).to_bytes(4, "big") + (196608).to_bytes(4, "big"))
        observer.request(pg(b"P", b"w\0" + witness(b'"fg_b1"."_fg_txn_witness"') + b"\0\0\0"))
        observer.request(pg(b"B", b"p\0w\0" + bytes(6)))
        observer.response(pg(b"1"))
        self.assertEqual(native.timings, [])
        with patch.object(profile.time, "perf_counter_ns", side_effect=[1_000_000, 4_000_000]):
            observer.request(pg(b"E", b"p\0" + bytes(4)))
            native.phase = "recovery"
            observer.response(pg(b"2"))
            observer.response(pg(b"C", b"INSERT 0 1\0"))
        self.assertEqual(native.timings, [{"phase": "measured", "completed": True, "elapsed_ms": 3}])

    def test_mysql_business_value_does_not_start_witness_timer(self):
        native = relay("mysql")
        observer = profile.WitnessTiming(native)
        def request(statement):
            body = b"\3" + statement
            return len(body).to_bytes(3, "little") + b"\0" + body
        observer.request(request(b"INSERT INTO customers (name) VALUES ('_fg_txn_witness')"))
        observer.response(b"\x07\0\0\1\0\1\0\2\0\0\0")
        self.assertEqual(native.timings, [])
        with patch.object(profile.time, "perf_counter_ns", side_effect=[2_000_000, 7_000_000]):
            observer.request(request(witness(b"`fgwrite`.`fg_b1__fg_txn_witness`")))
            observer.response(b"\x07\0\0\1\0\1\0\2\0\0\0")
        self.assertEqual(native.timings, [{"phase": "measured", "completed": True, "elapsed_ms": 5}])

    def test_tap_forwards_original_frame_without_mutation(self):
        sent, observed = [], []
        tap = profile.TappedStream(SimpleNamespace(sendall=sent.append), observed.append)
        original = pg(b"C", b"INSERT 0 1\0")
        tap.sendall(original)
        self.assertEqual(sent, [original])
        self.assertIs(observed[0], original)


class DiagnosticSchemaTests(unittest.TestCase):
    def metadata(self):
        return {"message": profile.META_MESSAGE, "operation": "decision", "engine": "mysql", "status": "completed",
                "elapsed_ns": 9, "query_calls_started": 4, "query_calls_completed": 4,
                "query_calls_failed": 0, "query_calls_cancelled": 0,
                "phases": json.dumps({"pool_acquire_including_health_and_connect": {
                    "started": 1, "completed": 1, "failed": 0, "cancelled": 0, "elapsed_ns": 3}})}

    def parse(self, fields):
        return profile.observations(json.dumps({"fields": fields}))

    def test_safe_numeric_schema_does_not_require_target_field(self):
        metadata, cleanup = self.parse(self.metadata())
        self.assertEqual(len(metadata), 1)
        self.assertEqual(metadata[0]["query_calls_started"], 4)
        self.assertEqual(cleanup, [])
        _metadata, cleanup = self.parse({"message": profile.CLEANUP_MESSAGE, "engine": "postgresql",
            "acknowledged_attempts": 100, "native_delete_ms": 2.5, "metadata_mark_ms": 1.25})
        self.assertEqual(cleanup[0]["acknowledged_attempts"], 100)
        self.assertFalse(cleanup[0]["native_commit_ms_available"])
        self.assertFalse(cleanup[0]["collection_total_ms_available"])
        self.assertNotIn("native_commit_ms", cleanup[0])
        self.assertNotIn("collection_total_ms", cleanup[0])

    def test_new_cleanup_phases_keep_actual_values_and_reject_private_or_invalid_data(self):
        fields = {"message": profile.CLEANUP_MESSAGE, "engine": "mysql", "acknowledged_attempts": 1,
                  "native_delete_ms": 1.5, "native_commit_ms": .5, "metadata_mark_ms": 2,
                  "collection_total_ms": 9.75}
        _metadata, cleanup = self.parse(fields)
        self.assertTrue(cleanup[0]["native_commit_ms_available"])
        self.assertTrue(cleanup[0]["collection_total_ms_available"])
        self.assertEqual(cleanup[0]["native_commit_ms"], .5)
        self.assertEqual(cleanup[0]["collection_total_ms"], 9.75)
        for key, value in (("native_commit_ms", -1), ("collection_total_ms", float("nan")),
                           ("collection_total_ms", "private SQL"), ("native_connection", "private")):
            with self.subTest(key=key, value=value), self.assertRaises(Failure):
                self.parse(fields | {key: value})

    def test_private_or_unknown_fields_and_broken_counters_fail_closed(self):
        for key, value in (("principal", "private-user"), ("query_calls_started", 5), ("elapsed_ns", "private SQL")):
            fields = self.metadata()
            fields[key] = value
            with self.subTest(key=key), self.assertRaises(Failure):
                self.parse(fields)
        fields = self.metadata()
        fields["phases"] = json.dumps({"private-table": {}})
        with self.assertRaises(Failure):
            self.parse(fields)

    def test_route_class_ignores_query_values_and_p95_handles_small_samples(self):
        self.assertEqual(profile.route_class("/internal/v1/branches/1/audit/outcome?private=value"), "outcome")
        self.assertEqual(profile.distribution([1, 4, 2])["p95"], 4)
        self.assertEqual(profile.distribution([])["count"], 0)


if __name__ == "__main__":
    unittest.main()
