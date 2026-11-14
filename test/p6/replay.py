"""Exercise SQL artifacts over the ordinary authenticated writable branch path."""

import json
import stat

from run_p2 import OWNER_A, OWNER_B, require
from write_cases import Probe, check_count


def cli(run, label, *arguments, owner=OWNER_A, succeeds=True):
    environment = run.base_env | {
        "FG_CONTROL_URL": run.control_url,
        "FG_OWNER_TOKEN": run.owner_tokens[owner],
        "FG_DRYRUN_PROXY_DSN": run.dsn(owner, run.frontend_passwords[owner], run.proxy_port, "unused"),
        "FG_DRYRUN_PROXY_CA": str(run.certs / "frontend-ca.pem"),
    }
    output = run.call(label, [run.executable("forkget"), *arguments], env=environment,
                      timeout=350, succeeds=succeeds, log=not succeeds)
    return json.loads(output) if output else None


def export(run, branch, path, succeeds=True, owner=OWNER_A):
    return cli(run, "replay-export-" + path.stem, "export", "--id", str(branch["id"]),
               "--output", str(path), succeeds=succeeds, owner=owner)


def replay(run, path, name, succeeds=True, engine=None):
    return cli(run, "replay-apply-" + name, "replay", "--engine", engine or run.engine,
               "--input", str(path), "--name", name, succeeds=succeeds)


def compare(run, source, target):
    for table, order in (("orders", "tenant_id,id"), ("customers", "id"), ("parents", "id"), ("children", "id")):
        source_table = run.branch_relation(source, table)
        target_table = run.branch_relation(target, table)
        left = run.native(f"SELECT * FROM {source_table} ORDER BY {order};")
        right = run.native(f"SELECT * FROM {target_table} ORDER BY {order};")
        require(left == right, "Replay did not reproduce a complete native relation")


def finish(run, source, path, name):
    receipt = export(run, source, path)
    require(receipt["branch_id"] == source["id"] and receipt["changes"] > 0 and receipt["complete"],
            "Export lost branch or statement identity")
    require(stat.S_IMODE(path.stat().st_mode) == 0o600, "Export was not written privately")
    artifact = [json.loads(line) for line in path.read_text().splitlines()]
    header = artifact[0]["value"]
    require(header["origin"]["generation_id"] == source["generation_id"] and header["engine"] == run.engine,
            "Artifact provenance changed")
    result = replay(run, path, name)
    require(result["verified"] and result["transaction"] == "committed" and result["cleanup"] == "retained",
            "Replay did not verify its committed target")
    compare(run, source["id"], result["branch_id"])
    run.drop(OWNER_A, result["branch_id"])
    return artifact


def insertion_case(run, directory):
    source, credentials = run.create("replay-source")
    path = directory / "insertion.json"
    with Probe(run, "replay-write-source", credentials) as probe:
        payload = "X'00ff27'" if run.family != "postgresql" else r"'\x00ff27'"
        note = (r"'quote'' slash\\ newline\n é'" if run.family != "postgresql"
                else "'quote'' slash\\ newline\n é'")
        for sql in (
            f"INSERT INTO orders (tenant_id,id,customer_id,amount,note,payload) VALUES (7,8,10,-12.34,{note},{payload})",
            "UPDATE orders SET note=NULL WHERE tenant_id=1 AND id=1",
            "DELETE FROM orders WHERE tenant_id=2 AND id=1",
            "UPDATE customers SET name='replay-name' WHERE id=10",
            "INSERT INTO parents (id,tenant_id,code) VALUES (600,8,'cycle-a')",
            "INSERT INTO parents (id,tenant_id,code,parent_code) VALUES (601,8,'cycle-b','cycle-a')",
            "UPDATE parents SET parent_code='cycle-b' WHERE id=600",
            "UPDATE parents SET label='stable-change' WHERE id=100",
            "INSERT INTO children (id,tenant_id,parent_code) VALUES (602,8,'cycle-a')",
        ):
            check_count(probe, sql, 1)
    artifact = finish(run, source, path, "replay-target")
    export(run, source, directory / "forbidden.json", succeeds=False, owner=OWNER_B)
    require(not (directory / "forbidden.json").exists(), "An unauthorized export created an artifact")
    run.drop(OWNER_A, source["id"])
    run.record("Replay reproduces complete native state, composite keys, NULL, decimal, escaped text, bytes and parent insert cycles")
    return path, artifact


def deletion_case(run, directory):
    source, credentials = run.create("replay-remove-source")
    with Probe(run, "replay-delete-source", credentials) as probe:
        check_count(probe, "DELETE FROM parents WHERE id=101", 1)
        check_count(probe, "DELETE FROM parents WHERE id=100", 1)
    finish(run, source, directory / "deletion.json", "replay-remove-target")
    run.drop(OWNER_A, source["id"])
    run.record("Replay orders child deletes and nullable parent detachment before native cascades")


def sparse_case(run, directory):
    # The migrated merge layout can contain historical delta rows. New SQL
    # read-only branches use base_only and never expose such private writes.
    generation = run.active()
    branch_id = int(run.metadata(f"INSERT INTO branch (name,class,generation_id,created_by,status,expires_at,mode,read_strategy) VALUES ('replay-sparse-source','dev',{generation},'{OWNER_A}','active',now()+INTERVAL '1 hour','read_only','merge') RETURNING id;"))
    source = {"id": branch_id, "name": "replay-sparse-source", "generation_id": generation}
    binding = run.binding(OWNER_A, source)
    table = next(table for table in binding["tables"] if table["logical_table"] == "orders")
    quote = "`" if run.family != "postgresql" else '"'
    delta = f"{quote}{table['delta_schema']}{quote}.{quote}{table['delta_table']}{quote}"
    run.native(f"""INSERT INTO {delta}
        (_fg_branch,_fg_op,tenant_id,id,customer_id,amount,note,payload)
        VALUES ({source['id']},'I',7,799,10,0.00,'sparse-witness',NULL);""")
    path = directory / "sparse.json"
    export(run, source, path)
    result = replay(run, path, "replay-sparse-target")
    require(result["verified"] and result["transaction"] == "committed",
            "A supported sparse row diff did not replay")
    with Probe(run, "replay-sparse-target", (OWNER_A, "replay-sparse-target")) as probe:
        require(probe.sql("SELECT id FROM orders WHERE tenant_id=7 AND id=799", "read").get("rows") == [[799]],
                "The replayed sparse row is missing")
    run.drop(OWNER_A, result["branch_id"])
    run.drop(OWNER_A, source["id"])
    run.record("A typed sparse diff can replay into a fresh writable branch")


def unsupported_cases(run, directory):
    for label, statements in (
        ("generated", ["INSERT INTO parents (tenant_id,code) VALUES (8,'generated')"]),
        ("reference", ["UPDATE parents SET code='moved' WHERE id=102"]),
        ("mixed", ["DELETE FROM parents WHERE id=102", "INSERT INTO parents (id,tenant_id,code) VALUES (610,8,'mixed')"]),
    ):
        source, credentials = run.create("replay-" + label)
        with Probe(run, "replay-invalid-" + label, credentials) as probe:
            for sql in statements:
                check_count(probe, sql, 1)
        path = directory / (label + ".json")
        receipt = export(run, source, path)
        records = [json.loads(line) for line in path.read_text().splitlines()]
        require(receipt["complete"] and records[-1]["value"]["complete"], "A valid change lost its complete export")
        if label == "reference":
            require(not receipt["replayable"], "A referenced-key transition was falsely advertised as replayable")
            cli(run, "reference-preflight-refusal", "replay", "--engine", run.engine, "--input", str(path), "--check", succeeds=False)
        else:
            replayed = replay(run, path, "replayed-" + label)
            require(replayed["verified"], f"{label} did not replay")
            compare(run, source["id"], replayed["branch_id"])
            run.drop(OWNER_A, replayed["branch_id"])
        run.drop(OWNER_A, source["id"])
    run.record("Complete export preserves generated and unsupported changes; generated/mixed parents replay while reference transitions refuse preflight")


def refusal_cases(run, directory, path, artifact):
    replay(run, path, "replay-other-engine", succeeds=False,
           engine="postgresql" if run.family == "mysql" else "mysql")
    for label, update in (
        ("deployment", {"deployment_id": "00000000-0000-0000-0000-000000000000"}),
        ("generation", {"generation_id": artifact[0]["value"]["origin"]["generation_id"] + 1}),
    ):
        incompatible = json.loads(json.dumps(artifact))
        incompatible[0]["value"]["origin"].update(update)
        altered = directory / (label + ".json")
        altered.write_text("".join(json.dumps(record)+"\n" for record in incompatible))
        replay(run, altered, "replay-wrong-" + label, succeeds=False)

    changed = json.loads(json.dumps(artifact))
    changed[0]["value"]["sql"] = ["DELETE FROM customers WHERE id=10"]
    altered = directory / "tampered.json"
    altered.write_text("".join(json.dumps(record)+"\n" for record in changed))
    replay(run, altered, "replay-tampered", succeeds=False)

    names = {branch["name"] for branch in run.cli(OWNER_A, "list")}
    require(not names.intersection({"replay-other-engine", "replay-wrong-deployment",
                                    "replay-wrong-generation", "replay-tampered"}),
            "Invalid replay created a target")

    altered = directory / "catalog.json"
    changed = json.loads(json.dumps(artifact))
    changed[0]["value"]["tables"][-1]["id"] += 10000
    altered.write_text("".join(json.dumps(record)+"\n" for record in changed))
    replay(run, altered, "replay-wrong-catalog", succeeds=False)
    require("replay-wrong-catalog" not in {branch["name"] for branch in run.cli(OWNER_A,"list")},
            "Wrong catalog created a branch before preflight")

    run.set_policy("dev", 1)
    try:
        result = replay(run, path, "replay-policy-limit", succeeds=False)
        require(result["failure"]["code"] == "FG-5002" and result["transaction"] == "rolled_back"
                and result["cleanup"] == "retained", "Replay bypassed policy or lost its failed environment")
        run.drop(OWNER_A,result["branch_id"])
    finally:
        run.set_policy("dev", 50_000)
    run.record("Replay rejects context/catalog/tampering before target creation and retains policy failures after rollback")


def replay_cases(run):
    directory = run.certs.parent / "replay"
    directory.mkdir(mode=0o700)
    path, artifact = insertion_case(run, directory)
    deletion_case(run, directory)
    sparse_case(run, directory)
    unsupported_cases(run, directory)
    refusal_cases(run, directory, path, artifact)
