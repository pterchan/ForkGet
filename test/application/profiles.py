#!/usr/bin/env python3
"""Extract finite catalog query shapes from an executed native ORM witness."""

import json
import pathlib
import re
import sys


def main(source, destination):
    capture = json.loads(pathlib.Path(source).read_text())
    # psycopg issues this DBAPI probe during dialect initialization, outside
    # SQLAlchemy's cursor events. Keep its finite native shape explicit.
    profiles = [{
        "kind": "types",
        "sql": "SELECT typname AS name, oid, typarray AS array_oid, oid::regtype::text AS regtype, typdelim AS delimiter FROM pg_type t WHERE t.oid = to_regtype($1) ORDER BY t.oid",
        "parameters": ["name"],
        "columns": ["name", "oid", "array_oid", "regtype", "delimiter"],
    }]
    kinds = {
        ("relname",): "tables",
        ("name", "format_type", "default", "not_null", "table_name", "comment", "generated", "identity_options", "collation"): "columns",
        ("oid", "relname"): "table_oids",
        ("conrelid", "cols", "conname", "description", "indnkeyatts", "indnullsnotdistinct"): "keys",
        ("relname", "conname", "anon_1", "nspname", "description"): "foreign_keys",
        ("oid", "amname"): "access_methods",
        ("oid", "opcname"): "opclasses",
        ("indrelid", "relname", "indisunique", "indisvalid", "has_constraint", "indoption", "reloptions", "relam", "filter_definition", "indnkeyatts", "indnullsnotdistinct", "elements", "elements_is_expr", "elements_opclass"): "indexes",
        ("relname", "conname", "anon_1", "description"): "checks",
        ("relname", "description"): "comments",
        ("oid", "relname", "reloptions", "relhasoids", "access_method_name", "tablespace_name", "parent_table_names"): "table_options",
    }
    for statement in capture["statements"]:
        if "pg_catalog." not in statement["sql"]:
            continue
        columns = tuple(item[0] for item in statement["columns"])
        names = []

        def substitute(match):
            name = match[1]
            if name not in names:
                names.append(name)
            return "$" + str(names.index(name) + 1)

        sql = re.sub(r"%\(([^)]+)\)s", substitute, statement["sql"])
        profiles.append({"kind": kinds[columns], "sql": sql, "parameters": names,
                         "columns": list(columns)})
    pathlib.Path(destination).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(destination).write_text(json.dumps(profiles, indent=2) + "\n")
    print(f"Extracted {len(profiles)} executed metadata profiles")


if __name__ == "__main__":
    main(*sys.argv[1:])
