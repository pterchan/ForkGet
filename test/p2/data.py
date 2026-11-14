"""Controlled writes for test setup and an independent materialized oracle."""

import re


def identifier(engine, name):
    if re.fullmatch(r"[a-z_][a-z0-9_]*", name) is None:
        raise ValueError("unexpected fixture identifier")
    quote = "`" if engine in ("mysql", "tidb") else '"'
    return f"{quote}{name}{quote}"


def table(engine, schema, name):
    return f"{identifier(engine, schema)}.{identifier(engine, name)}"


def binary(engine, hex_value):
    if re.fullmatch(r"[0-9A-F]*", hex_value) is None:
        raise ValueError("invalid fixture bytes")
    return f"X'{hex_value}'" if engine in ("mysql", "tidb") else f"decode('{hex_value}','hex')"


def seed_delta(engine, execute, binding, alpha, beta):
    if not isinstance(alpha, int) or not isinstance(beta, int) or min(alpha, beta) <= 0 or alpha == beta:
        raise ValueError("expected separate persisted branch IDs")
    names = {entry["logical_table"]: table(engine, entry["delta_schema"], entry["delta_table"])
             for entry in binding["tables"]}
    orders = names["orders"]
    customers = names["customers"]
    alpha_bytes = binary(engine, "00FF41")
    beta_bytes = binary(engine, "FF")
    reinsert_bytes = binary(engine, "6F6B")
    execute(f"""
        INSERT INTO {orders} (_fg_branch,_fg_op,tenant_id,id,customer_id,amount,note,payload) VALUES
          ({alpha},'U',1,1,10,11.50,NULL,NULL),
          ({alpha},'D',2,1,NULL,NULL,NULL,NULL),
          ({alpha},'D',2,2,NULL,NULL,NULL,NULL),
          ({alpha},'I',3,1,20,15.00,'delta-add',{alpha_bytes}),
          ({beta},'U',1,1,10,12.50,'beta-one',{beta_bytes}),
          ({beta},'I',3,1,30,18.00,'beta-add',NULL);
        INSERT INTO {customers} (_fg_branch,_fg_op,id,name) VALUES
          ({alpha},'U',20,'Beto'),({beta},'U',30,'Cora');
    """)
    # Record a tombstone before replacing it with a distinct live image.
    execute(f"""
        UPDATE {orders} SET _fg_op='I', customer_id=30, amount=44.00,
          note='reinserted', payload={reinsert_bytes}
        WHERE _fg_branch={alpha} AND tenant_id=2 AND id=2;
    """)


def prepare_reference(engine, execute):
    if engine in ("mysql", "tidb"):
        execute("CREATE DATABASE app CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;")
    else:
        execute("CREATE SCHEMA app;")
    byte_type = "VARBINARY(16)" if engine in ("mysql", "tidb") else "BYTEA"
    execute(f"""
        CREATE TABLE app.orders (
          tenant_id INT NOT NULL, id BIGINT NOT NULL, customer_id INT NOT NULL,
          amount DECIMAL(12,2), note VARCHAR(64), payload {byte_type}, PRIMARY KEY(tenant_id,id)
        );
        CREATE TABLE app.customers (id INT NOT NULL PRIMARY KEY, name VARCHAR(64) NOT NULL);
    """)


def materialize_reference(engine, execute, branch):
    empty, bytes_with_null, text, beta_byte = (binary(engine, value) for value in ("", "00FF41", "6F6B", "FF"))
    if branch == "alpha":
        orders = f"""
          (1,1,10,11.50,NULL,NULL),(1,2,20,20.00,'base-two',{empty}),
          (2,2,30,44.00,'reinserted',{text}),(3,1,20,15.00,'delta-add',{bytes_with_null})
        """
        customers = "(10,'Ada'),(20,'Beto'),(30,'Cal')"
    elif branch == "beta":
        orders = f"""
          (1,1,10,12.50,'beta-one',{beta_byte}),(1,2,20,20.00,'base-two',{empty}),
          (2,1,10,30.00,NULL,{bytes_with_null}),(2,2,30,40.00,'base-four',{text}),
          (3,1,30,18.00,'beta-add',NULL)
        """
        customers = "(10,'Ada'),(20,'Bea'),(30,'Cora')"
    else:
        raise ValueError("unexpected branch oracle")
    execute(f"""
        DELETE FROM app.orders;
        DELETE FROM app.customers;
        INSERT INTO app.orders VALUES {orders};
        INSERT INTO app.customers VALUES {customers};
    """)


def snapshot(engine, execute, binding, branch_id=None):
    result = []
    for entry in binding["tables"]:
        keys = "tenant_id,id" if entry["logical_table"] == "orders" else "id"
        base = table(engine, entry["base_schema"], entry["base_table"])
        delta = table(engine, entry["delta_schema"], entry["delta_table"])
        result.append(execute(f"SELECT * FROM {base} ORDER BY {keys};"))
        where = "" if branch_id is None else f" WHERE _fg_branch={int(branch_id)}"
        result.append(execute(f"SELECT * FROM {delta}{where} ORDER BY _fg_branch,{keys};"))
    return result
