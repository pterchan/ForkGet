#!/usr/bin/env python3
"""Fork, wait, test, and drop a disposable branch in separate CI steps."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from urllib.parse import quote, urlsplit
from urllib.request import ProxyHandler, Request, build_opener


def control_origin():
    origin = os.environ.get("FG_CONTROL_URL", "http://127.0.0.1:8081")
    endpoint = urlsplit(origin)
    if (endpoint.scheme != "http" or endpoint.hostname not in ("127.0.0.1", "::1") or
            endpoint.username is not None or endpoint.path not in ("", "/") or
            endpoint.query or endpoint.fragment):
        raise ValueError("invalid control origin")
    return origin.rstrip("/")


def forkget(*args):
    result = subprocess.run([os.environ.get("FG_CI_FORKGET", "forkget"), *args], check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12)
    return json.loads(result.stdout)


def endpoint():
    value = os.environ["FG_CI_ENDPOINT"]
    parsed = urlsplit("//" + value)
    if (parsed.hostname not in ("127.0.0.1", "::1") or not parsed.port or parsed.path or
            parsed.username is not None or parsed.query or parsed.fragment):
        raise ValueError("invalid TLS SQL endpoint")
    host = "[::1]" if parsed.hostname == "::1" else "127.0.0.1"
    canonical = f"{host}:{parsed.port}"
    if value != canonical:
        raise ValueError("noncanonical TLS SQL endpoint")
    return canonical


def fork(args):
    sql_endpoint = endpoint()
    control_origin()
    output = os.environ["GITHUB_OUTPUT"]
    branch = forkget("fork", args.name, "--class", "ci", "--ttl-seconds", str(args.ttl),
                     *([] if args.read_only else ["--write"]))
    branch_id = branch["id"]
    if type(branch_id) is not int or branch_id <= 0 or branch["name"] != args.name or branch["class"] != "ci":
        raise ValueError("invalid fork response")
    with open(output, "a", encoding="utf-8") as stream:
        stream.write(f"branch_id={branch_id}\nbranch_name={args.name}\nendpoint={sql_endpoint}\n")


def wait(args):
    request = Request(f"{control_origin()}/v1/branches/{args.id}",
                      headers={"Authorization": "Bearer " + os.environ["FG_OWNER_TOKEN"]})
    opener = build_opener(ProxyHandler({}))
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        with opener.open(request, timeout=3) as response:
            branch = json.load(response)
        if branch["id"] != args.id or branch["class"] != "ci":
            raise ValueError("unexpected branch")
        if branch["status"] == "active":
            return
        if branch["status"] != "provisioning":
            break
        time.sleep(0.15)
    raise ValueError("branch activation failed")


def probe_environment(args):
    user = quote(os.environ["FG_CI_FRONTEND_USER"], safe="")
    password = quote(os.environ["FG_CI_FRONTEND_PASSWORD"], safe="")
    ca = os.environ["FG_CI_FRONTEND_CA"]
    database = quote(args.name, safe="")
    # TiDB speaks the MySQL wire protocol; the write probe maps the
    # tidb:// scheme itself.
    wire_scheme = "mysql" if args.engine == "tidb" else args.engine
    return os.environ | {
        "FG_WRITE_PROBE_URL": f"{wire_scheme}://{user}:{password}@{endpoint()}/{database}",
        "FG_WRITE_PROBE_CA": ca,
    }


def probe(environment, commands):
    script = "".join(json.dumps(dict(op=op, sql=sql)) + "\n" for op, sql in commands)
    return subprocess.run([os.environ.get("FG_CI_PROBE", "fg-write-probe")], input=script,
                          text=True, capture_output=True, env=environment, timeout=20)


def verified_sql(environment, commands):
    result = probe(environment, commands)
    lines = result.stdout.splitlines()
    if result.returncode or len(lines) != len(commands) + 1 or lines[0] != "ready":
        raise ValueError("TLS SQL test failed")
    return [json.loads(line) for line in lines[1:]]


def reject_wrong_ca(environment, witness):
    if verified_sql(environment, [("read", witness)])[0].get("rows") != []:
        raise ValueError("correct TLS CA could not read the disposable branch")
    with tempfile.TemporaryDirectory(prefix="forkget-ci-wrong-ca-") as directory:
        ca = Path(directory) / "wrong-ca.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
             "-subj", "/CN=Forkget CI unrelated CA", "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-keyout", Path(directory) / "unused.key", "-out", ca],
            capture_output=True, check=True, timeout=10,
        )
        result = probe(environment | {"FG_WRITE_PROBE_CA": str(ca)}, [])
    if result.returncode == 0 or result.stdout or "invalid peer certificate: UnknownIssuer" not in result.stderr:
        raise ValueError("unrelated TLS CA did not cause the expected refusal")
    return "Verified TLS rejected the deliberately unrelated CA."


def smoke(args):
    environment = probe_environment(args)
    witness = "SELECT id FROM customers WHERE id=990000"
    if args.scenario == "wrong-ca":
        return reject_wrong_ca(environment, witness)

    insertion = "INSERT INTO customers (id,name) VALUES (990000,'ci-witness')"
    commands = [
        ("text", "BEGIN"),
        ("text", insertion),
        ("read", witness),
    ]
    is_sql_failure = args.scenario == "sql-failure"
    if is_sql_failure:
        commands.append(("text", insertion))
    commands.extend([
        ("text", "ROLLBACK"),
        ("read", witness),
    ])
    observations = verified_sql(environment, commands)
    if ([observations[index].get("affected") for index in (0, 1, -2)] != [0, 1, 0] or
            observations[2].get("rows") != [[990000]] or observations[-1].get("rows") != []):
        raise ValueError("transaction test failed")
    if is_sql_failure:
        failure = observations[3]
        expected_state = "23505" if args.engine == "postgresql" else "23000"
        if failure.get("fg") != "FG-3001" or failure.get("sqlstate") != expected_state or failure.get("physical_leak"):
            raise ValueError("duplicate key did not cause the expected SQL failure")
        return "SQL duplicate-key failure FG-3001 observed and rollback verified."


def retain(args):
    control_origin()
    branch = forkget("status", "--id", str(args.id))
    if branch.get("status") not in ("active", "provisioning") or branch.get("expired"):
        raise ValueError("only a live CI environment can be retained")
    renewed = forkget("renew", "--id", str(args.id), "--ttl-seconds", "86400",
                     "--expected-lease-version", str(branch["lease_version"]))
    print(json.dumps({"branch_id": args.id, "status": "retained_after_failure",
                      "expires_at": renewed["expires_at"], "lease_version": renewed["lease_version"]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("fork")
    create.add_argument("--name", required=True)
    create.add_argument("--ttl", type=int, default=86400)
    create.add_argument("--read-only", action="store_true")
    commands.add_parser("wait").add_argument("--id", type=int, required=True)
    commands.add_parser("drop").add_argument("--id", type=int, required=True)
    commands.add_parser("retain").add_argument("--id", type=int, required=True)
    test = commands.add_parser("smoke")
    test.add_argument("--engine", choices=("mysql", "postgresql", "tidb"), required=True)
    test.add_argument("--name", required=True)
    test.add_argument("--scenario", choices=("success", "sql-failure", "wrong-ca"), default="success")
    args = parser.parse_args()
    try:
        if args.command == "fork":
            fork(args)
        elif args.command == "wait":
            wait(args)
        elif args.command == "drop":
            control_origin()
            forkget("drop", "--id", str(args.id))
        elif args.command == "retain":
            retain(args)
        else:
            fault = smoke(args)
            if fault:
                parser.exit(1, f"Forkget CI fault observed. {fault}\n")
    except (OSError, KeyError, ValueError, subprocess.SubprocessError):
        # Raw HTTP and SQL diagnostics can contain environment or fixture data.
        parser.exit(1, f"Forkget CI step failed ({args.command}).\n")


if __name__ == "__main__":
    main()
