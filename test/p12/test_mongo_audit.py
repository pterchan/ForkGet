"""Pure frame-boundary checks for the native Mongo audit fault relay."""

from pathlib import Path
import ast
import io
import json
from types import SimpleNamespace
from unittest.mock import patch
import struct
import ssl
import tempfile
import unittest
from urllib.parse import quote, unquote, urlsplit

from bson import BSON, SON
import mongo_audit as audit


class PhaseDiagnosticTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[1] / "p2/mongo.py"
        self.tree = ast.parse(path.read_text(), filename=str(path))
        self.context = {"json": json, "unquote": unquote, "urlsplit": urlsplit}
        helper = next(node for node in self.tree.body
                      if isinstance(node, ast.FunctionDef) and node.name == "sanitized_phase_output")
        exec(compile(ast.Module(body=[helper], type_ignores=[]), str(path), "exec"), self.context)
        self.sanitize = self.context["sanitized_phase_output"]

    def test_literal_and_json_escaped_quote_backslash_and_unicode_are_redacted(self):
        secret = 'synthetic-"quoted"\\path\n-\u6c49\u5b57'
        self.assertEqual(self.sanitize(secret, {}, [secret]), "[redacted]")
        for ascii_only in (False, True):
            with self.subTest(ascii_only=ascii_only):
                output = json.dumps({"message": "FG-2003 Config: " + secret}, ensure_ascii=ascii_only)
                safe = self.sanitize(output, {}, [secret])
                self.assertEqual(json.loads(safe), {"message": "FG-2003 Config: [redacted]"})

    def test_account_and_encoded_dsn_variants_are_redacted_inside_json(self):
        password, token = 'synthetic-"\\\u5bc6\u7801@', 'synthetic-token-"\\\u4ee4\u724c'
        encoded = quote(password, safe="")
        dsn = "postgresql://reader:" + encoded + "@fixture.invalid/database"
        environment = {"FG_META_DSN": dsn,
                       "FG_FRONTEND_ACCOUNTS": json.dumps([{"password": password}]),
                       "FG_CONTROL_ACCOUNTS": json.dumps([{"token": token}])}
        payload = {"dsn": dsn, "encoded": encoded, "password": password, "token": token}
        for ascii_only in (False, True):
            with self.subTest(ascii_only=ascii_only):
                safe = self.sanitize(json.dumps(payload, ensure_ascii=ascii_only), environment, [])
                self.assertEqual(json.loads(safe), {key: "[redacted]" for key in payload})

    def test_failed_phase_persists_only_sanitized_output_before_refusal(self):
        secret = 'synthetic-"\\\u51ed\u636e'
        output = json.dumps({"message": "FG-2003 Config: " + secret})
        phase = next(node for node in ast.walk(self.tree)
                     if isinstance(node, ast.FunctionDef) and node.name == "phase")
        with tempfile.TemporaryDirectory(prefix="mongo-diagnostics-unit-") as temporary:
            def run(command, env, check):
                self.assertEqual(command, ["fg-control", "bootstrap"])
                self.assertFalse(check)
                return SimpleNamespace(returncode=1, stdout=output, stderr="")
            context = self.context | {"artifacts": Path(temporary), "run": run,
                                      "secrets_map": {"password": secret}, "secrets_token": "synthetic-token"}
            exec(compile(ast.Module(body=[phase], type_ignores=[]), "<phase>", "exec"), context)
            with self.assertRaisesRegex(RuntimeError, r"inspect bootstrap\.log") as refused:
                context["phase"]("bootstrap", ["fg-control", "bootstrap"], {})
            self.assertNotIn(secret, str(refused.exception))
            saved = (Path(temporary) / "bootstrap.log").read_text()
            self.assertEqual(json.loads(saved), {"message": "FG-2003 Config: [redacted]"})

    def test_missing_phase_confirmations_reference_safe_logs_only(self):
        assertions = [node for node in ast.walk(self.tree) if isinstance(node, ast.Assert)
                      and any(isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name)
                              and value.value.id in ("bootstrap", "refresh")
                              for value in ast.walk(node.test))]
        self.assertEqual(len(assertions), 2)
        for assertion in assertions:
            with self.subTest(line=assertion.lineno):
                context = {"bootstrap": SimpleNamespace(stdout="synthetic-private", stderr="synthetic-private"),
                           "refresh": SimpleNamespace(stdout="synthetic-private", stderr="synthetic-private")}
                with self.assertRaises(AssertionError) as refused:
                    exec(compile(ast.Module(body=[assertion], type_ignores=[]), "<confirmation>", "exec"), context)
                self.assertIn(".log", str(refused.exception))
                self.assertNotIn("synthetic-private", str(refused.exception))


def frame(request, response, document):
    body = bytes(5) + BSON.encode(document)
    return struct.pack("<iiii", len(body) + 16, request, response, 2013) + body


class Run:
    native_port = 1
    certs = Path("/unused")


class MemoryStream:
    def __init__(self, data=b"", reply=b"", finished=None):
        self.data, self.sent = bytearray(data), []
        self.reply, self.finished = reply, finished
        self.timeout = 5

    def gettimeout(self):
        return self.timeout

    def setblocking(self, blocking):
        self.timeout = None if blocking else 0

    def settimeout(self, timeout):
        self.timeout = timeout

    def pending(self):
        return len(self.data)

    def recv(self, size):
        count = min(size, 3)
        result = bytes(self.data[:count])
        del self.data[:count]
        return result

    def sendall(self, data):
        self.sent.append(data)
        self.data.extend(self.reply)
        if self.finished:
            self.finished.set()


class MongoRelayTests(unittest.TestCase):
    def relay(self):
        relay = audit.MongoRelay(Run())
        self.addCleanup(relay.listener.close)
        relay.target = ("fg_b7", "orders")
        return relay

    def test_fragmented_original_request_and_partial_reply_are_preserved(self):
        relay = self.relay()
        request = frame(42, 0, SON([("insert", "orders"), ("documents", [{"_id": 1}]), ("$db", "fg_b7")]))
        reply = frame(100, 42, SON([("ok", 1.0), ("n", 1), ("writeErrors", [{"index": 1, "code": 11000, "errmsg": "private-native-text"}])]))
        client = MemoryStream(request, finished=relay.done)
        server = MemoryStream(reply=reply)
        relay.forward(client, server)
        self.assertEqual(server.sent, [request])
        self.assertEqual(client.sent, [reply])
        self.assertEqual(relay.last_reply, reply[21:])
        self.assertEqual(relay.native_writes, 1)
        self.assertEqual(relay.errors, [])

    def test_tls_control_readiness_cannot_block_the_client_first_command(self):
        relay = self.relay()
        request = frame(42, 0, {"insert": "orders", "documents": [{"_id": 1}], "$db": "fg_b7"})
        reply = frame(100, 42, {"ok": 1.0, "n": 1})
        class Stream(MemoryStream):
            def pending(self):
                return 0
        client = Stream(request, finished=relay.done)
        server = Stream(reply=reply)
        original_recv = server.recv
        ticket = [True]
        def server_recv(size):
            self.assertEqual(server.timeout, 0)
            if ticket[0]:
                ticket[0] = False
                raise ssl.SSLWantReadError()
            return original_recv(size)
        server.recv = server_recv
        def ready(readers, writers, _errors, _timeout):
            self.assertFalse(writers)
            source = server if ticket[0] else client if client.data else server
            self.assertIn(source, readers)
            return [source], [], []
        with patch.object(audit.select, "select", side_effect=ready):
            relay.forward(client, server)
        self.assertEqual(server.sent, [request])
        self.assertEqual(client.sent, [reply])
        self.assertEqual((client.timeout, server.timeout), (5, 5))
        self.assertEqual(relay.native_writes, 1)
        self.assertEqual(relay.errors, [])

    def test_tls_want_write_and_fragmented_frames_resume_without_resending(self):
        relay = self.relay()
        request = frame(42, 0, {"insert": "orders", "documents": [{"_id": 1}], "$db": "fg_b7"})
        reply = frame(100, 42, {"ok": 1.0, "n": 1})
        class Stream(MemoryStream):
            def pending(self):
                return 0
        client, server = Stream(request, finished=relay.done), Stream(reply=reply)
        original_recv = client.recv
        want_write, observed_write_interest = [True], []
        def client_recv(size):
            self.assertEqual(client.timeout, 0)
            if want_write[0]:
                want_write[0] = False
                raise ssl.SSLWantWriteError()
            return original_recv(size)
        client.recv = client_recv
        def ready(readers, writers, _errors, _timeout):
            if writers:
                self.assertEqual(writers, [client])
                self.assertNotIn(client, readers)
                observed_write_interest.append(True)
                return [], [client], []
            return [client if client.data else server], [], []
        with patch.object(audit.select, "select", side_effect=ready):
            relay.forward(client, server)
        self.assertEqual(observed_write_interest, [True])
        self.assertEqual(server.sent, [request])
        self.assertEqual(client.sent, [reply])
        self.assertEqual((client.timeout, server.timeout), (5, 5))
        self.assertEqual(relay.native_writes, 1)
        self.assertEqual(relay.last_reply, reply[21:])

    def test_partial_native_send_failure_does_not_resend_the_command(self):
        relay = self.relay()
        request = frame(42, 0, {"insert": "orders", "documents": [{"_id": 1}], "$db": "fg_b7"})
        client, server = MemoryStream(request), MemoryStream()
        attempts = []
        def failed_send(data):
            self.assertEqual(server.timeout, 5)
            attempts.append(data)
            server.sent.append(data[:7])
            raise BrokenPipeError()
        server.sendall = failed_send
        relay.forward(client, server)
        self.assertEqual(attempts, [request])
        self.assertEqual(server.sent, [request[:7]])
        self.assertEqual(client.sent, [])
        self.assertEqual(relay.native_writes, 1)
        self.assertIsNone(relay.last_reply)
        self.assertEqual((client.timeout, server.timeout), (5, 5))

    def test_uncorrelated_reply_cannot_trigger_the_native_ack_cut(self):
        relay = self.relay()
        relay.drop_ack.set()
        request = frame(42, 0, SON([("insert", "orders"), ("documents", [{"_id": 1}]), ("$db", "fg_b7")]))
        reply = frame(100, 41, {"ok": 1.0, "n": 1})
        client = MemoryStream(request, finished=relay.done)
        server = MemoryStream(reply=reply)
        relay.forward(client, server)
        self.assertFalse(relay.ack_seen.is_set())
        self.assertIsNone(relay.last_reply)
        self.assertEqual(client.sent, [reply])

    def test_full_correlated_reply_is_withheld_without_fabricating_driver_success(self):
        relay = self.relay()
        relay.drop_ack.set()
        relay.release_ack.set()
        request = frame(42, 0, SON([("insert", "orders"), ("documents", [{"_id": 1}]), ("$db", "fg_b7")]))
        reply = frame(100, 42, {"ok": 1.0, "n": 1})
        client, server = MemoryStream(request), MemoryStream(reply=reply)
        relay.forward(client, server)
        self.assertTrue(relay.ack_seen.is_set())
        self.assertEqual(client.sent, [])
        self.assertEqual(server.sent, [request])
        self.assertEqual(relay.last_reply, reply[21:])

    def test_wrong_database_and_trailing_document_do_not_count_as_selected_ack(self):
        relay = self.relay()
        request = frame(42, 0, SON([("insert", "orders"), ("documents", [{"_id": 1}]), ("$db", "fg_b8")]))
        reply = frame(100, 42, {"ok": 1.0, "n": 1})
        client, server = MemoryStream(request, finished=relay.done), MemoryStream(reply=reply)
        relay.forward(client, server)
        self.assertEqual(relay.native_writes, 0)
        self.assertIsNone(relay.last_reply)
        with self.assertRaises(audit.sql_audit.p6.p5.p34.p2.Failure):
            relay.document(reply + BSON.encode({"ok": 1}))


class FakeReadinessClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class ReadinessTests(unittest.TestCase):
    REVISION = "a" * 40

    def run_start(self, opener, process=None):
        clock, traces = self.clock, []
        run = audit.MongoRun.__new__(audit.MongoRun)
        run.environment, run.processes = {}, {}
        run.report, run.control_url, run.drain_url = Path("/unused"), "http://127.0.0.1:1", "http://127.0.0.1:2"
        run.secret, run.relay, run.audit = {"service": "private-password"}, SimpleNamespace(port=3), SimpleNamespace(url=run.control_url)
        run.executable, run.process_revision = lambda name: Path("/unused") / name, lambda _name: self.REVISION
        process = process or SimpleNamespace(pid=812, poll=lambda: None)
        def record(path, observations):
            traces.append((path.name, json.loads(json.dumps(observations))))
        with patch.object(audit.Path, "open", return_value=io.BytesIO()), \
                patch.object(audit.subprocess, "Popen", return_value=process), \
                patch.object(audit.urllib.request, "urlopen", side_effect=opener) as request, \
                patch.object(audit.time, "monotonic", side_effect=clock.monotonic), \
                patch.object(audit.time, "sleep", side_effect=clock.sleep), \
                patch.object(audit, "json_file", side_effect=record):
            try:
                run.start("proxy")
                return run, traces, request.call_args_list
            finally:
                self.traces, self.requests = traces, request.call_args_list

    def setUp(self):
        self.clock = FakeReadinessClock()

    @staticmethod
    def response(status=204):
        class Response:
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False
        value = Response()
        value.status = status
        return value

    def test_actual_start_retries_socket_timeout_then_requires_204_and_safe_trace(self):
        count = 0
        def opener(_url, *, timeout):
            nonlocal count
            count += 1
            self.assertLessEqual(timeout, 1)
            if count == 1:
                self.clock.now += timeout
                raise TimeoutError("private-native-error SELECT confidential private-password")
            return self.response()
        run, traces, calls = self.run_start(opener)
        self.assertEqual(len(calls), 2)
        observations = traces[-1][1]
        self.assertEqual([entry["outcome"] for entry in observations], ["pending", "ready"])
        self.assertEqual(observations[0]["exception_type"], "TimeoutError")
        self.assertEqual(observations[1]["status"], 204)
        self.assertTrue(all(isinstance(entry["elapsed_ms"], (int, float)) and entry["elapsed_ms"] >= 0 for entry in observations))
        self.assertTrue(all(entry["stage"] == "proxy" and entry["pid"] == 812
                            and entry["build_revision"] == self.REVISION for entry in observations))
        serialized = json.dumps(observations)
        for private in ("private-native-error", "SELECT confidential", "private-password", "Authorization"):
            self.assertNotIn(private, serialized)
        self.assertIn("proxy", run.processes)

    def test_repeated_timeouts_exhaust_original_thirty_second_deadline_without_later_probe(self):
        def opener(_url, *, timeout):
            self.assertLessEqual(self.clock.now + timeout, 30 + 1e-8)
            self.clock.now += timeout
            raise TimeoutError("private")
        with self.assertRaisesRegex(audit.sql_audit.p6.p5.p34.p2.Failure, "Timed out: proxy readiness"):
            self.run_start(opener)
        self.assertAlmostEqual(self.clock.now, 30)
        self.assertTrue(self.requests)
        self.assertTrue(all(call.kwargs["timeout"] <= 1 for call in self.requests))
        self.assertLess(self.requests[-1].kwargs["timeout"], 1)

    def test_exited_process_fails_before_any_health_request(self):
        with self.assertRaisesRegex(audit.sql_audit.p6.p5.p34.p2.Failure, "exited before readiness"):
            self.run_start(lambda *_args, **_kwargs: self.fail("Exited process was probed"),
                           SimpleNamespace(pid=813, poll=lambda: 7))
        self.assertEqual(self.requests, [])
        observation = self.traces[-1][1][-1]
        self.assertEqual((observation["outcome"], observation["exit_code"]), ("process_exited", 7))

    def test_non_204_and_late_204_never_satisfy_readiness(self):
        count = 0
        def opener(_url, *, timeout):
            nonlocal count
            count += 1
            if count == 1:
                return self.response(200)
            self.clock.now = 30.01
            return self.response(204)
        with self.assertRaisesRegex(audit.sql_audit.p6.p5.p34.p2.Failure, "Timed out: proxy readiness"):
            self.run_start(opener)
        observations = self.traces[-1][1]
        self.assertEqual([entry["outcome"] for entry in observations], ["pending", "deadline"])
        self.assertEqual([entry["status"] for entry in observations], [200, 204])

    def test_response_close_cannot_turn_a_past_deadline_reply_into_success(self):
        clock = self.clock
        class LateResponse:
            status = 204
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                clock.now = 30.01
        with self.assertRaisesRegex(audit.sql_audit.p6.p5.p34.p2.Failure, "Timed out: proxy readiness"):
            self.run_start(lambda *_args, **_kwargs: LateResponse())
        self.assertEqual(self.traces[-1][1][-1]["outcome"], "deadline")


    def test_revision_comes_from_selected_preflight_receipt_and_rejects_unavailable(self):
        run = audit.MongoRun.__new__(audit.MongoRun)
        run.report, run.old = Path("/unused"), False
        with patch.object(audit.Path, "read_text", return_value=json.dumps({"revisions": {"fg-proxy": self.REVISION}})):
            self.assertEqual(run.process_revision("proxy"), self.REVISION)
        run.old, run.baseline = True, SimpleNamespace(revisions={"fg-proxy": "b" * 40})
        self.assertEqual(run.process_revision("proxy"), "b" * 40)
        run.baseline.revisions["fg-proxy"] = "unavailable"
        with self.assertRaises(audit.sql_audit.p6.p5.p34.p2.Failure):
            run.process_revision("proxy")


if __name__ == "__main__":
    unittest.main()
