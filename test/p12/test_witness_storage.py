"""Pure protocol and upgrade-contract checks; no processes or native services."""

from copy import deepcopy
from pathlib import Path
import struct
from threading import Event
import unittest
from unittest.mock import patch

import witness_storage as storage


def pg_frame(tag, body):
    return tag + struct.pack("!I", len(body) + 4) + body


def mysql_frame(body, sequence=0):
    return len(body).to_bytes(3, "little") + bytes([sequence]) + body


class FakeRun:
    native_port = 1
    certs = Path("/unused")

    def __init__(self, engine):
        self.family = self.engine = engine

    def branch_namespace(self, _branch):
        return ("fg_b7", "") if self.family == "postgresql" else ("fgwrite", "fg_b7_")

    def branch_relation(self, branch, name):
        schema, prefix = self.branch_namespace(branch)
        return f"{schema}.{prefix}{name}"


class MemoryStream:
    def __init__(self, data=b"", reply=b""):
        self.data = bytearray(data)
        self.sent = []
        self.reply = reply

    def pending(self):
        return len(self.data)

    def recv(self, size):
        # Fragmented transport must still preserve the complete original frame.
        count = min(size, 3)
        result = bytes(self.data[:count])
        del self.data[:count]
        return result

    def sendall(self, data):
        self.sent.append(data)
        if b"DROP TABLE IF EXISTS" in data:
            self.data.extend(self.reply)

    def setsockopt(self, level, name, value):
        self.socket_option = (level, name, value)

    def getsockopt(self, level, name):
        stored_level, stored_name, value = self.socket_option
        if (level, name) != (stored_level, stored_name):
            raise ValueError("Unexpected socket option")
        return value


class WitnessRelayTests(unittest.TestCase):
    def test_tidb_clone_changes_only_table_and_constraint_name(self):
        predicate = "(`format_version` = 1 AND `deployment_id` = 'abc' AND `branch_id` = 7)"
        ddl = ("CREATE TABLE `fg_b7__fg_saved_witness` (\n  `attempt_id` varchar(96) NOT NULL,\n"
               "  PRIMARY KEY (`attempt_id`),\n  CONSTRAINT `fg_b7__fg_txn_witness_chk_1` CHECK "
               + predicate + "\n) ENGINE=InnoDB DEFAULT CHARSET=ascii COLLATE=ascii_bin")
        clone = storage.clone_tidb_witness(ddl, "fg_b7__fg_saved_witness", "fg_b7__fg_txn_witness", 7)
        expected = ddl.replace("CREATE TABLE `fg_b7__fg_saved_witness`", "CREATE TABLE `fg_b7__fg_txn_witness`")
        expected = expected.replace("CONSTRAINT `fg_b7__fg_txn_witness_chk_1`", "CONSTRAINT `p12_clone_7_1`")
        self.assertEqual(clone, expected)
        self.assertIn(predicate, clone)
        with self.assertRaises(storage.sql_audit.p6.p5.p34.p2.Failure):
            storage.clone_tidb_witness(ddl, "different", "fg_b7__fg_txn_witness", 7)

    def test_tidb_clustered_pk_fault_keeps_every_other_native_definition_line(self):
        primary = "  PRIMARY KEY (`attempt_id`) /*T![clustered_index] CLUSTERED */,"
        ddl = ("CREATE TABLE `witness` (\n  `attempt_id` varchar(96) NOT NULL,\n" + primary
               + "\n  CONSTRAINT `identity` CHECK (`branch_id` = 7)\n) ENGINE=InnoDB")
        self.assertEqual(storage.remove_tidb_witness_primary_key(ddl), ddl.replace(primary + "\n", ""))
        with self.assertRaises(storage.sql_audit.p6.p5.p34.p2.Failure):
            storage.remove_tidb_witness_primary_key(ddl.replace("`attempt_id`)", "`other`)"))

    def relay(self, engine):
        relay = storage.WitnessDropRelay(FakeRun(engine), {"id": 7})
        self.addCleanup(relay.listener.close)
        return relay

    def test_only_exact_registered_drop_is_armed_once(self):
        for engine in ("mysql", "postgresql", "tidb"):
            with self.subTest(engine=engine):
                relay = self.relay(engine)
                exact = b"DROP TABLE IF EXISTS " + relay.relation
                self.assertFalse(relay.observe(exact + b"_other"))
                self.assertFalse(relay.observe(b"SELECT '" + exact + b"'"))
                self.assertTrue(relay.observe(exact))
                self.assertFalse(relay.observe(exact + b";"))
                self.assertEqual(relay.drop_executions, 2)

    def test_postgres_parse_bind_do_not_execute_drop(self):
        parser = storage.ExecutedFrames("postgresql")
        parser.scan(struct.pack("!II", 8, 196608))
        sql = b'DROP TABLE IF EXISTS "fg_b7"."_fg_txn_witness"'
        parser.scan(pg_frame(b"P", b"drop_statement\0" + sql + b"\0" + struct.pack("!H", 0)))
        self.assertIsNone(parser.executed)
        parser.scan(pg_frame(b"B", b"drop_portal\0drop_statement\0" + struct.pack("!HHH", 0, 0, 0)))
        self.assertIsNone(parser.executed)
        parser.scan(pg_frame(b"E", b"drop_portal\0" + struct.pack("!I", 0)))
        self.assertEqual(parser.executed, sql)
        parser.scan(pg_frame(b"E", b"drop_portal\0" + struct.pack("!I", 0)))
        self.assertIsNone(parser.executed)

    def test_postgres_drop_requires_idle_ready_after_command_complete(self):
        relay = self.relay("postgresql")
        complete, durable = relay.drop_response(pg_frame(b"C", b"DROP TABLE\0"), False)
        self.assertTrue(complete)
        self.assertFalse(durable)
        self.assertEqual(relay.drop_response(pg_frame(b"Z", b"I"), complete), (True, True))
        for complete, status in ((False, b"I"), (True, b"T"), (True, b"E")):
            with self.subTest(complete=complete, status=status):
                with self.assertRaises(storage.sql_audit.p6.p5.p34.p2.Failure):
                    relay.drop_response(pg_frame(b"Z", status), complete)

    def test_native_error_is_never_a_successful_drop(self):
        for engine in ("mysql", "postgresql", "tidb"):
            relay = self.relay(engine)
            frame = pg_frame(b"E", b"SERROR\0\0") if engine == "postgresql" else b"\x01\0\0\x01\xff"
            with self.assertRaises(storage.sql_audit.p6.p5.p34.p2.Failure):
                relay.drop_response(frame, False)

    def test_fragmented_original_frames_forward_but_success_reply_is_lost(self):
        for engine in ("mysql", "postgresql", "tidb"):
            with self.subTest(engine=engine):
                relay = self.relay(engine)
                sql = b"DROP TABLE IF EXISTS " + relay.relation
                if engine == "postgresql":
                    request = struct.pack("!II", 8, 196608) + pg_frame(b"Q", sql + b"\0")
                    reply = pg_frame(b"C", b"DROP TABLE\0") + pg_frame(b"Z", b"I")
                else:
                    body = b"\x03" + sql
                    request = len(body).to_bytes(3, "little") + b"\0" + body
                    reply = b"\x07\0\0\x01\0\0\0\x02\0\0\0"
                client = MemoryStream(request)
                server = MemoryStream(reply=reply)
                observed = Event()

                class Finished:
                    def set(self):
                        observed.set()
                        relay.done.set()

                    def is_set(self):
                        return observed.is_set()

                relay.dropped = Finished()
                relay.forward(client, server)
                self.assertTrue(observed.is_set())
                self.assertEqual(b"".join(server.sent), request)
                self.assertEqual(client.sent, [])
                self.assertEqual(relay.drop_executions, 1)
                self.assertEqual(relay.errors, [])

    def test_recovery_counters_distinguish_business_dml_and_witness_reads(self):
        relay = self.relay("mysql")
        relay.observe(b"SELECT * FROM " + relay.relation)
        self.assertEqual(relay.missing_witness_reads, 0)
        relay.dropped.set()
        relay.observe(b"SELECT * FROM " + relay.relation)
        relay.observe(b"INSERT INTO " + relay.business[0] + b" VALUES (1)")
        self.assertEqual(relay.missing_witness_reads, 1)
        self.assertEqual(relay.business_executions, 1)


class CollectorLockRelayTests(unittest.TestCase):
    def relay(self, engine="mysql"):
        relay = storage.CollectorLockRelay(FakeRun(engine), {"id": 7})
        relay.continue_delete.set()
        self.addCleanup(relay.listener.close)
        return relay

    def test_connection_transport_entry_is_inherited_and_not_a_state_factory(self):
        self.assertIs(storage.CollectorLockRelay.connection, storage.sql_audit.CommitReply.connection)
        state = storage.CollectorLockRelay.connection_state_for(81)
        self.assertEqual(state.native_id, 81)

    def test_failed_native_diagnostic_keeps_only_safe_numeric_error_identity(self):
        from types import SimpleNamespace
        probe = SimpleNamespace(sql=lambda *_: {"errno": 1146, "sqlstate": "42S02",
            "transport": "private SQL or credentials", "physical_leak": True})
        self.assertEqual(storage.WitnessRun.diagnostic_rows(probe, "private query"),
                         {"available": False, "errno": 1146, "sqlstate": "42S02"})

    def test_exact_relation_and_lock_shape_do_not_match_a_literal_or_other_table(self):
        for engine in ("mysql", "tidb"):
            relay = self.relay(engine)
            self.assertEqual(relay.relation, b"`fgwrite`.`fg_b7__fg_txn_witness`")
            self.assertNotEqual(relay.relation.decode(), relay.run.branch_relation(7, "_fg_txn_witness"))
            delete = b"DELETE FROM " + relay.relation + b" WHERE attempt_id <> '' AND attempt_id IN (?)"
            self.assertEqual(relay.classify(delete), "delete")
            self.assertEqual(relay.classify(delete.replace(relay.relation, relay.relation + b"_other")), "business")
            self.assertIsNone(relay.classify(b"SELECT '" + delete + b"'"))
            guard = b"SELECT attempt_id FROM " + relay.relation + b" WHERE attempt_id=''"
            if engine == "mysql":
                self.assertEqual(relay.classify(guard + b" FOR UPDATE"), "lock")
                self.assertIsNone(relay.classify(guard))
            else:
                self.assertEqual(relay.classify(guard), "lock")
                self.assertIsNone(relay.classify(guard + b" FOR UPDATE"))

    def test_prepare_is_not_delete_execution_or_success_and_error_is_not_commit(self):
        relay = self.relay()
        connection = relay.connection_state_for(81)
        connection.role = "collector"
        sql = b"DELETE FROM " + relay.relation + b" WHERE attempt_id <> '' AND attempt_id IN (?)"
        prepared = mysql_frame(b"\0" + struct.pack("<IHHBH", 11, 0, 1, 0, 0), 1)
        relay.observe_client(connection, mysql_frame(b"\x16" + sql))
        relay.observe_server(connection, prepared)
        self.assertTrue(relay.at_delete.is_set())
        self.assertEqual((relay.delete_executions, relay.delete_successes), (0, 0))
        execute = mysql_frame(b"\x17" + struct.pack("<I", 11) + b"\0" * 5)
        relay.observe_client(connection, execute)
        self.assertEqual((relay.delete_executions, relay.delete_successes), (1, 0))
        relay.observe_server(connection, mysql_frame(b"\xff\x15\x04#HY000", 1))
        self.assertEqual(relay.delete_successes, 0)
        relay.observe_client(connection, mysql_frame(b"\x03COMMIT"))
        relay.observe_server(connection, mysql_frame(b"\xff\x15\x04#HY000", 1))
        self.assertEqual(relay.commit_successes, 0)
        relay.observe_server(connection, mysql_frame(b"\0\0\0\2\0\0\0", 1))
        self.assertEqual(relay.commit_successes, 1)

    def test_collector_lock_precedes_independent_admin_header(self):
        relay = self.relay()
        collector, admin = relay.connection_state_for(81), relay.connection_state_for(82)
        collector.role, admin.role = "collector", "admin"
        relay.observe_client(collector, mysql_frame(b"\x03BEGIN"))
        relay.observe_client(collector, mysql_frame(b"\x03SELECT attempt_id FROM " + relay.relation
                                                  + b" WHERE attempt_id='' FOR UPDATE"))
        relay.observe_client(admin, mysql_frame(b"\x03SELECT format_version FROM " + relay.relation
                                               + b" WHERE attempt_id = ''"))
        self.assertTrue(relay.collector_began and relay.collector_read_header)
        self.assertFalse(relay.admin_before_collector_lock)
        self.assertEqual(relay.admin_ids, {82})
        early = self.relay()
        early.observe_client(admin, mysql_frame(b"\x03SELECT format_version FROM " + early.relation
                                               + b" WHERE attempt_id = ''"))
        self.assertTrue(early.admin_before_collector_lock)

    def test_fragmented_greeting_and_tls_request_keep_original_frames_and_native_id(self):
        relay = self.relay()
        greeting = mysql_frame(b"\x0a8.0.43\0" + struct.pack("<I", 8191) + b"opaque greeting")
        request = mysql_frame(b"opaque TLS request", 1)
        server, client = MemoryStream(greeting), MemoryStream(request)
        relay.start_tls(client, server)
        self.assertEqual(client.sent, [greeting])
        self.assertEqual(server.sent, [request])
        self.assertEqual(relay.connection_state.native_id, 8191)
        self.assertEqual(relay.socket_options, [{"downstream_tcp_nodelay": 1, "upstream_tcp_nodelay": 1}])


class UpgradeBindingTests(unittest.TestCase):

    def test_every_old_field_remains_exact_with_additive_protocol_fields(self):
        old = {"id": 7, "generation_id": 3, "engine": "mysql", "write_schema": "fg_b7",
               "tables": [{"id": 2, "columns": [{"name": "id", "data_type": "bigint"}]}]}
        upgraded = deepcopy(old)
        upgraded.update(access="read_write", layout="native_copy", audit_witness_ready=True)
        upgraded["tables"][0]["columns"][0]["new_field"] = None
        preserve = storage.sql_audit.p6.p5.p34.preserve_binding
        preserve(old, upgraded)
        for field in ("id", "generation_id", "write_schema"):
            changed = deepcopy(upgraded)
            changed[field] = "changed"
            with self.subTest(field=field), self.assertRaises(storage.sql_audit.p6.p5.p34.p2.Failure):
                preserve(old, changed)
        changed = deepcopy(upgraded)
        changed["tables"][0]["columns"][0]["data_type"] = "text"
        with self.assertRaises(storage.sql_audit.p6.p5.p34.p2.Failure):
            preserve(old, changed)

    def test_mongo_and_sql_read_only_keep_unprepared_readiness(self):
        preserve = storage.sql_audit.p6.p5.p34.preserve_binding
        for engine, access, layout in (("mongodb", "read_write", "native_copy"),
                                       ("mysql", "read_only", "sparse_delta")):
            upgraded = {"engine": engine, "access": access, "layout": layout, "audit_witness_ready": False}
            preserve({"engine": engine}, upgraded)
            upgraded["audit_witness_ready"] = True
            with self.assertRaises(storage.sql_audit.p6.p5.p34.p2.Failure):
                preserve({"engine": engine}, upgraded)


if __name__ == "__main__":
    unittest.main()
