"""Repeat release compatibility witnesses through the selected deployment."""

import json

from run_p2 import OWNER_A, OWNER_B, require
from write_cases import Probe, check_count, concurrency, constraint_cases, disconnect_rollback


def compatibility_trials(run):
    run.check_deadline(180)
    branches = []
    try:
        writable, credentials = run.create("gate-native-constraints")
        branches.append(writable)
        for ordinal, level in enumerate(("READ COMMITTED", "REPEATABLE READ"), 1):
            floor = 50_000 + ordinal * 100
            constraint_cases(run, credentials, level, floor)
            concurrency(run, credentials, level, floor)
        disconnect_rollback(run, credentials)
        other, other_credentials = run.create("gate-native-isolation")
        branches.append(other)
        with (Probe(run, "gate-native-first", credentials) as left,
              Probe(run, "gate-native-second", other_credentials) as right):
            insert = "INSERT INTO parents (id,tenant_id,code) VALUES (52000,9,'{}')"
            query = "SELECT id,code FROM parents WHERE id=52000"
            check_count(left, insert.format("isolated-first"), 1)
            require(right.sql(query, "read").get("rows") == [], "Write leaked into the other branch")
            check_count(right, insert.format("isolated-second"), 1)
            require(left.sql(query, "read").get("rows") == [[52000, "isolated-first"]] and
                    right.sql(query, "read").get("rows") == [[52000, "isolated-second"]],
                    "Equal keys did not remain branch-local")
    finally:
        run.drop_many(branches)
    run.record("Typed RC/RR constraints, native barriers, disconnect and cross-branch isolation")
    approval_trial(run)


def approval_trial(run):
    run.set_policy("agent", 10_000, approval=1)
    branch, credentials = run.create("gate-agent-approval", "agent")
    key = 52_010
    label = "gate-approval-private-value"
    try:
        with (Probe(run, "gate-agent-writer", credentials) as writer,
              Probe(run, "gate-agent-observer", credentials) as observer):
            writer.send(f"INSERT INTO parents (id,tenant_id,code) VALUES ({key},9,'{label}')")
            pending = run.pending(branch, set())
            query = f"SELECT id FROM parents WHERE id={key}"
            require(observer.sql(query, "read").get("rows") == [], "Unapproved write became visible")
            require(run.decide(branch, pending, OWNER_A) in (403, 404), "Writer approved its own change")
            require(run.decide(branch, pending, OWNER_B) == 200, "Independent approval failed")
            require(writer.receive().get("affected") == 1 and observer.sql(query, "read").get("rows") == [[key]],
                    "Approved change did not commit")
            require(run.decide(branch, pending, OWNER_B) == 409, "Consumed approval was reusable")
    finally:
        run.drop_many([branch])
    path = f"/v1/branches/{branch['id']}/audit?limit=100"
    status, result = run.request("GET", path, run.owner_tokens[OWNER_A])
    require(status == 200 and json.loads(result)["events"] and label not in result.decode(),
            "Dropped branch audit was unavailable or disclosed row values")
    require(run.request("GET", path, run.owner_tokens[OWNER_B])[0] == 404,
            "Approval delegation exposed owner audit")
    run.record("Independent one-use approval and private audit after branch cleanup")
