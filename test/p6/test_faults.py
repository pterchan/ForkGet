"""Protocol-only regression tests for the transparent P6 mutation observer."""

import struct
import unittest

# Initialize the same import chain as the native runner; it registers run_p2.
import run
from faults import CommandFrames, WITNESS_COLUMNS, mutation_kind


def pg_frame(tag,body=b""):
    return tag+struct.pack("!I",len(body)+4)+body


def parse(name,sql):
    return pg_frame(b"P",name+b"\0"+sql+b"\0\0\0")


def bind(portal,statement):
    return pg_frame(b"B",portal+b"\0"+statement+b"\0"+bytes(6))


def execute(portal):
    return pg_frame(b"E",portal+b"\0"+bytes(4))


def mysql_query(sql):
    body=b"\3"+sql
    return len(body).to_bytes(3,"little")+b"\0"+body


def witness(relation):
    return b"INSERT INTO "+relation+WITNESS_COLUMNS+b"1, 'deployment', 17, 2, 'storage', 'attempt', 'session')"


class CommandFrameTests(unittest.TestCase):
    def pg(self):
        parser=CommandFrames("postgresql")
        self.assertEqual(parser.scan(struct.pack("!II",8,196608)),(0,0,0))
        return parser

    def test_mysql_and_tidb_separate_exact_witness_from_business(self):
        for family in ("mysql","tidb"):
            with self.subTest(family=family):
                parser=CommandFrames(family)
                business=b"INSERT INTO `fgwrite`.`fg_b17_customers` (id,name) VALUES (1,'_fg_txn_witness')"
                payload=mysql_query(business)+mysql_query(witness(b"`fgwrite`.`fg_b17__fg_txn_witness`"))+mysql_query(b"COMMIT")
                self.assertEqual(parser.scan(payload),(1,1,1))
                self.assertEqual(parser.scan(mysql_query(witness(b"`fg_b17`.`_fg_txn_witness`"))),(0,0,1))

    def test_similar_names_literals_and_columns_remain_business(self):
        for family,relation in (("mysql",b"`other`.`fg_b17__fg_txn_witness`"),
                                ("mysql",b"`fgwrite`.`fg_b017__fg_txn_witness`"),
                                ("mysql",b"`fgwrite`.`fg_b17__fg_txn_witness_extra`"),
                                ("postgresql",b'"other"."_fg_txn_witness"'),
                                ("postgresql",b'"fg_b017"."_fg_txn_witness"')):
            with self.subTest(family=family,relation=relation):
                self.assertEqual(mutation_kind(witness(relation),family),"business")
        self.assertEqual(mutation_kind(b'INSERT INTO "fg_b17"."_fg_txn_witness" (id) VALUES (1)',"postgresql"),"business")
        self.assertEqual(mutation_kind(b'UPDATE "fg_b17"."customers" SET name=\'_fg_txn_witness\'',"postgresql"),"business")

    def test_pg_parse_bind_flush_close_do_not_execute_witness(self):
        parser=self.pg()
        statement=witness(b'"fg_b17"."_fg_txn_witness"')
        self.assertEqual(parser.scan(parse(b"w",statement)+bind(b"p",b"w")+pg_frame(b"H")),(0,0,0))
        self.assertEqual(parser.scan(execute(b"p")+pg_frame(b"C",b"Pp\0")+pg_frame(b"C",b"Sw\0")+pg_frame(b"H")),(0,0,1))
        self.assertEqual(parser.scan(execute(b"p")),(0,0,0))

    def test_pg_portals_keep_bound_statement_and_resume_does_not_reexecute(self):
        parser=self.pg()
        business=b'INSERT INTO "fg_b17"."customers" (id,name) VALUES (1,\'_fg_txn_witness\') RETURNING id'
        frames=parse(b"s",business)+bind(b"p",b"s")+parse(b"s",witness(b'"fg_b17"."_fg_txn_witness"'))
        self.assertEqual(parser.scan(frames),(0,0,0))
        self.assertEqual(parser.scan(execute(b"p")+execute(b"p")),(0,1,0))
        self.assertEqual(parser.scan(bind(b"p",b"s")+execute(b"p")),(0,0,1))

    def test_pg_unnamed_and_named_commit_execute_only(self):
        parser=self.pg()
        frames=parse(b"",b"INSERT INTO customers (id) VALUES (1)")+bind(b"",b"")
        self.assertEqual(parser.scan(frames),(0,0,0))
        self.assertEqual(parser.scan(execute(b"")),(0,1,0))
        self.assertEqual(parser.scan(parse(b"end",b"COMMIT")+bind(b"finish",b"end")),(0,0,0))
        self.assertEqual(parser.scan(execute(b"finish")+pg_frame(b"S")),(1,0,0))

    def test_pg_bind_values_and_close_cannot_change_target_classification(self):
        parser=self.pg()
        statement=b'INSERT INTO "fg_b17"."customers" (name) VALUES ($1)'
        parameter=b'_fg_txn_witness'
        bound=(b"p\0s\0"+bytes(2)+struct.pack("!H",1)
               +struct.pack("!I",len(parameter))+parameter+bytes(2))
        self.assertEqual(parser.scan(parse(b"s",statement)+pg_frame(b"S")+pg_frame(b"B",bound)),(0,0,0))
        self.assertEqual(parser.scan(pg_frame(b"C",b"Ss\0")+execute(b"p")),(0,1,0))
        self.assertEqual(parser.scan(pg_frame(b"C",b"Pp\0")+bind(b"p",b"s")+execute(b"p")),(0,0,0))
        self.assertEqual(self.pg().scan(bind(b"p",b"s")+execute(b"p")),(0,0,0))

    def test_pg_simple_query_and_fragmented_extended_frames(self):
        parser=self.pg()
        frames=(pg_frame(b"Q",b"INSERT INTO customers (id,name) VALUES (1,'_fg_txn_witness')\0")
                +parse(b"w",witness(b'"fg_b17"."_fg_txn_witness"'))+bind(b"p",b"w")+execute(b"p")
                +pg_frame(b"Q",b"COMMIT\0"))
        counts=[0,0,0]
        for value in frames:
            counts=[left+right for left,right in zip(counts,parser.scan(bytes([value])))]
        self.assertEqual(counts,[1,1,1])

    def test_mysql_fragmented_commands_count_once(self):
        parser=CommandFrames("mysql")
        frames=mysql_query(witness(b"`fgwrite`.`fg_b17__fg_txn_witness`"))+mysql_query(b"COMMIT")
        counts=[0,0,0]
        for value in frames:
            counts=[left+right for left,right in zip(counts,parser.scan(bytes([value])))]
        self.assertEqual(counts,[1,0,1])


if __name__=="__main__":
    unittest.main()
