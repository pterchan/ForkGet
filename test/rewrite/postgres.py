#!/usr/bin/env python3
"""Execute generated visibility SQL in a disposable, socket-only PostgreSQL cluster."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
PORT = "55439"


def run(arguments, **kwargs):
    return subprocess.run(
        arguments, check=True, text=True, capture_output=True, cwd=ROOT, **kwargs
    ).stdout


def main():
    for executable in ["cargo", "initdb", "pg_ctl", "psql"]:
        if shutil.which(executable) is None:
            raise SystemExit(f"Missing {executable}; install PostgreSQL 16 and add its bin directory to PATH")

    relation = run([
        "cargo", "run", "--locked", "--quiet", "-p", "fg-rewrite",
        "--example", "visible_relation", "--", "postgres",
    ]).strip()
    sql = (ROOT / "test/rewrite/postgres.sql").read_text().replace(
        "-- GENERATED_VISIBLE_RELATION", relation
    )
    # A short private socket path also fits macOS's Unix-domain socket limit.
    with tempfile.TemporaryDirectory(prefix="fg-pg-", dir="/tmp") as temporary:
        directory = Path(temporary)
        data = directory / "data"
        cluster_prefix = []
        if os.geteuid() == 0:
            # WSL commonly starts as root; only this disposable private cluster
            # needs the PostgreSQL OS account, not the build or test process.
            import pwd
            account = pwd.getpwnam("postgres")
            os.chown(directory, account.pw_uid, account.pw_gid)
            cluster_prefix = [shutil.which("runuser") or "/usr/sbin/runuser", "-u", "postgres", "--"]
        run(cluster_prefix + ["initdb", "-D", str(data), "-U", "fg_test", "--auth=trust", "--no-locale", "-E", "UTF8"])
        try:
            run(cluster_prefix + [
                "pg_ctl", "-D", str(data), "-l", str(directory / "server.log"),
                "-o", f"-h '' -k {directory} -p {PORT}", "-w", "start",
            ])
            output = run([
                "psql", "-X", "-v", "ON_ERROR_STOP=1", "-h", str(directory),
                "-p", PORT, "-U", "fg_test", "-d", "postgres", "-f", "-",
            ], input=sql, env={**os.environ, "PGPASSFILE": os.devnull})
            print(run(["psql", "--version"]).strip())
            print(output, end="")
        finally:
            if (data / "postmaster.pid").exists():
                run(cluster_prefix + ["pg_ctl", "-D", str(data), "-m", "fast", "-w", "stop"])


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.stderr or error.stdout or str(error)) from error
