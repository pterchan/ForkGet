#!/usr/bin/env python3
"""Restore a disposable metadata backup and resume service against the same native engine."""

import os
import subprocess

from run import EngineRun, OWNER_A, run_profile
from run_p2 import require
from write_cases import Probe, check_count

ORIGINAL_DB = "forkget_meta"
RESTORED_DB = "forkget_meta_recovered"
TLS_ADMIN = ('PGPASSWORD="$POSTGRES_PASSWORD" PGSSLMODE=verify-full '
             'PGSSLROOTCERT=/certs/backend-ca.pem exec')
WITNESS = 909102
WITNESS_QUERY = f"SELECT id FROM customers WHERE id={WITNESS}"


class RecoveryRun(EngineRun):
    def dsn(self, user, password, port, database, scheme=None):
        if database == ORIGINAL_DB and getattr(self, "is_restored", False):
            database = RESTORED_DB
        return super().dsn(user, password, port, database, scheme)

    def archive_command(self, label, command, **streams):
        process = subprocess.run(
            self.compose_command + ["exec", "-T", "metadata", "sh", "-c", command],
            env=self.compose_env, stderr=subprocess.PIPE, timeout=30, **streams,
        )
        if process.returncode:
            diagnostic = self.safe(process.stderr.decode("utf-8", errors="replace"))
            (self.report / f"{label}.log").write_text(diagnostic, encoding="utf-8")
        require(process.returncode == 0, f"Metadata {label} failed")

    def recover_metadata(self):
        archive = self.certs.parent / "metadata-backup.dump"
        descriptor = os.open(archive, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                self.archive_command(
                    "backup", f"{TLS_ADMIN} pg_dump -h127.0.0.1 -U postgres -Fc {ORIGINAL_DB}", stdout=stream,
                )
            self.metadata(f"CREATE DATABASE {RESTORED_DB};")
            with archive.open("rb") as stream:
                self.archive_command(
                    "restore", f"{TLS_ADMIN} pg_restore -h127.0.0.1 -U postgres "
                    f"--exit-on-error -d {RESTORED_DB}", stdin=stream, stdout=subprocess.DEVNULL,
                )
        finally:
            archive.unlink(missing_ok=True)
        self.is_restored = True

    def execute(self):
        self.start_deployment()
        self.set_policy("dev", 50_000)
        old, _, _ = self.refresh_to_v2()
        self.drop(OWNER_A, old["id"])
        surviving, credentials = self.create("recovery-active")
        pending, _ = self.create("recovery-dropping")
        with Probe(self, "recovery-write", credentials) as probe:
            check_count(probe, f"INSERT INTO customers (id,name) VALUES ({WITNESS},'recovery-witness')", 1)
        before_binding = self.binding(OWNER_A, surviving)
        self.stop("proxy")
        token = self.owner_tokens[OWNER_A]
        status, _ = self.request("DELETE", f"/v1/branches/{pending['id']}", token)
        require(status in (200, 202) and self.branch_status(pending) == "dropping"
                and self.branch_storage_exists(pending["id"]), "A pending drop was not captured at the recovery boundary")
        self.stop("control")

        self.recover_metadata()
        self.start_control()
        self.start_proxy()
        self.wait_dropped(OWNER_A, pending["id"])
        require(not self.branch_storage_exists(pending["id"]), "Restored pending drop left its native storage")
        require(self.metadata(f"SELECT status FROM branch WHERE id={pending['id']};") == "dropping",
                "Recovered service changed the original metadata database")
        after_binding = self.binding(OWNER_A, surviving)
        require(before_binding == after_binding, "Restoration changed an active immutable binding or catalog")
        with Probe(self, "recovery-read", credentials) as probe:
            require(probe.sql(WITNESS_QUERY, "read").get("rows") == [[WITNESS]],
                    "Restored metadata did not reconnect to the retained branch")
        self.record("Private metadata backup restored into an empty database and preserved an active native branch binding")
        self.record("Restored control resumed a persisted pending drop without changing the old metadata database")

        replacement, _ = self.create(pending["name"])
        require(replacement["id"] > pending["id"] and replacement["generation_id"] == surviving["generation_id"],
                "Restored sequence or active generation produced an invalid replacement")
        self.drop(OWNER_A, replacement["id"])
        self.drop(OWNER_A, surviving["id"])
        self.record("Restored sequence allocated a fresh immutable ID for a same-name replacement")


if __name__ == "__main__":
    raise SystemExit(run_profile("p6-recovery", "P6 local metadata backup and restore", RecoveryRun))
