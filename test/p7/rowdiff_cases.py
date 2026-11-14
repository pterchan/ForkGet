"""Check native diff pushdown on a staged gate generation."""

import json

from run_p2 import OWNER_A, require
from write_cases import Probe, check_count


def rowdiff_response(run, branch_id):
    return run.request("GET", f"/v1/branches/{branch_id}/diff", run.owner_tokens[OWNER_A])


def report(run, branch_id):
    status, body = rowdiff_response(run, branch_id)
    require(status == 200, f"Native row diff returned HTTP {status}")
    return json.loads(body)


def require_limit(run, branch_id):
    status, body = rowdiff_response(run, branch_id)
    require(status == 409 and json.loads(body).get("code") == "FG-2002",
            "Row diff did not refuse an oversized report")


def insert_many_customers(run, customers):
    if run.mysql:
        digits = " UNION ALL ".join(f"SELECT {digit}" for digit in range(10))
        index = "a.n + b.n * 10 + c.n * 100 + d.n * 1000"
        run.native(f"""INSERT INTO {customers} (id,name)
            WITH digits(n) AS ({digits})
            SELECT 100000 + {index}, 'limit'
            FROM digits a CROSS JOIN digits b CROSS JOIN digits c CROSS JOIN digits d
            WHERE {index} < 4097;""")
    else:
        run.native(f"""INSERT INTO {customers} (id,name)
            SELECT 100000 + n, 'limit' FROM generate_series(1,4097) AS series(n);""")


def check_limits(run, branch):
    # Limit witnesses use the disposable writable copy only. The staged
    # immutable generation is untouched.
    branch_id = branch["id"]
    orders = run.branch_relation(branch_id, "orders")
    if not run.mysql:
        run.native(f"""UPDATE {orders}
            SET payload=pg_catalog.decode(repeat('00',524289),'hex')
            WHERE tenant_id=7 AND id=3;""")
        require_limit(run, branch_id)
        run.native(f"""UPDATE {orders} AS c SET payload=b.payload
            FROM fg_g{branch["generation_id"]}.orders AS b
            WHERE c.tenant_id=7 AND c.id=3 AND b.tenant_id=c.tenant_id AND b.id=c.id;""")
    changed_note = "REPEAT(CONVERT(X'F09F9BA1' USING utf8mb4),64)" if run.mysql else "repeat(chr(128737),64)"
    baseline_note = "REPEAT(CONVERT(X'F09F9BA0' USING utf8mb4),64)" if run.mysql else "repeat(chr(128736),64)"
    run.native(f"""UPDATE {orders} SET note={changed_note}
        WHERE tenant_id=7 AND id BETWEEN 12 AND 3011;""")
    require_limit(run, branch_id)
    run.native(f"""UPDATE {orders} SET note={baseline_note}
        WHERE tenant_id=7 AND id BETWEEN 12 AND 3011;""")
    require(len(orders_changes(report(run, branch_id))) == 5,
            "The byte limit altered the native snapshot")
    insert_many_customers(run, run.branch_relation(branch_id, "customers"))
    require_limit(run, branch_id)


def orders_changes(value):
    return next(table["changes"] for table in value["tables"] if table["table"] == "orders")


def check_typed_changes(changes, last_id):
    require([change["key"] for change in changes] ==
            [["1", "1"], ["1", "2"], ["7", "2"], ["7", "10"], ["7", str(last_id)]],
            "Native diff changed composite-key order or included unchanged rows")
    first, second, third, deleted, inserted = changes
    require(first["operation"] == "update" and first["before"][-2:] == ["base-v2-one", None]
            and first["after"][-2:] == ["BASE-V2-ONE", ""],
            "Native diff equated collation-equivalent text or NULL and empty bytes")
    require(second["before"][-1] == "" and second["after"][-1] == "00ff20",
            "Native diff did not preserve exact bytes")
    require(third["before"][-2] == "🛠" * 64 and len(third["before"][-1]) == 32
            and third["after"][-2:] == [None, None],
            "Native diff lost a multibyte text value or NULL transition")
    require(deleted["operation"] == "delete" and deleted["after"] is None
            and inserted["operation"] == "insert" and inserted["before"] is None
            and inserted["after"][-3:] == ["0.00", "", ""],
            "Native diff did not preserve the inserted and deleted images")


def rowdiff_cases(run, count):
    require(count > 20_000, "Row diff fixture does not exceed the former scan limit")
    branch, credentials = run.create("p7-native-rowdiff")
    readonly, _ = run.create("p7-immutable-rowdiff", write=False)
    # Replay the legacy contract explicitly: the current fork API creates
    # immutable base-only readers, while retained sparse branches still merge.
    sparse_id=int(run.metadata(f"""INSERT INTO branch
        (name,class,generation_id,created_by,status,expires_at,access,layout,read_strategy)
        VALUES ('p7-sparse-rowdiff','dev',{branch['generation_id']},'{OWNER_A}',
                'active',clock_timestamp()+interval '1 hour','read_only','sparse_delta','merge')
        RETURNING id;"""))
    status,body=run.request("GET",f"/v1/branches/{sparse_id}",run.owner_tokens[OWNER_A])
    require(status==200,"Legacy sparse row-diff fixture was unavailable")
    sparse=json.loads(body)
    try:
        before = report(run, branch["id"])
        require(not any(table["changes"] for table in before["tables"]),
                "Untouched staged rows appear as changes")
        base = f"fg_g{branch['generation_id']}"
        require(int(run.native(f"SELECT COUNT(*) FROM {base}.orders WHERE tenant_id=7;")) == count,
                "The staged row diff baseline count differs")
        last_id = count + 1
        empty = "X''" if run.mysql else r"'\x'"
        binary = "X'00FF20'" if run.mysql else r"'\x00ff20'"
        with Probe(run, "p7-rowdiff-writer", credentials) as probe:
            for sql in (
                f"UPDATE orders SET note='BASE-V2-ONE',payload={empty} WHERE tenant_id=1 AND id=1",
                f"UPDATE orders SET payload={binary} WHERE tenant_id=1 AND id=2",
                "UPDATE orders SET note=NULL,payload=NULL WHERE tenant_id=7 AND id=2",
                "DELETE FROM orders WHERE tenant_id=7 AND id=10",
                f"INSERT INTO orders (tenant_id,id,customer_id,amount,note,payload) VALUES (7,{last_id},10,0.00,'',{empty})",
                "UPDATE orders SET amount=50.00 WHERE tenant_id=7 AND id=11",
            ):
                check_count(probe, sql, 1)
        check_typed_changes(orders_changes(report(run, branch["id"])), last_id)
        check_limits(run, branch)
        immutable=report(run,readonly["id"])
        require(not any(table["changes"] for table in immutable["tables"]),
                "New immutable read-only branch reported changes or inherited the legacy scan cap")
        require_limit(run, sparse["id"])
        run.record(f"Native diff above 20,000 staged rows preserves typed changes and both report limits ({count} rows); new immutable diff is empty and legacy sparse scan limit is unchanged")
    finally:
        run.drop(OWNER_A, sparse["id"])
        run.drop(OWNER_A, readonly["id"])
        run.drop(OWNER_A, branch["id"])
