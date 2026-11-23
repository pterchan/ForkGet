#!/usr/bin/env python3
"""Run a frozen-revision local equivalent and product-closure acceptance.

This installs no scheduler, spends no cloud money, and never pushes. Reports
must be outside tracked sources (the default target directory is ignored).
"""

import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
SQL_ENGINES=("mysql","postgresql")
RELEASE_ENGINES=(*SQL_ENGINES,"mongodb")


def source(revision):
    actual=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    dirty=subprocess.check_output(["git","status","--porcelain"],cwd=ROOT,text=True)
    if actual!=revision or len(revision)!=40 or dirty:
        raise ValueError("The acceptance run requires its exact full SHA and a clean checkout")


def free_ports():
    sockets=[]
    try:
        for _ in RELEASE_ENGINES:
            listener=socket.socket()
            listener.bind(("127.0.0.1",0))
            sockets.append(listener)
        return [listener.getsockname()[1] for listener in sockets]
    finally:
        for listener in sockets:listener.close()


def write(path,value):
    path.write_text(json.dumps(value,indent=2)+"\n",encoding="utf-8")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision",required=True)
    parser.add_argument("--report-root",type=Path,default=ROOT/"target/p10-local")
    parser.add_argument("--suite",choices=("all","product"),default="all")
    parser.add_argument("--deployment-image",help="also verify a prebuilt deployment image labeled with the source SHA")
    parser.add_argument("--paired-performance",action="store_true",
                        help="also measure native layout costs and serial 10s/30s/16-client SQL paired workloads")
    parser.add_argument("--console-node",type=Path,
                        help="also require frontend checks and packaged browser acceptance using this Node executable")
    parser.add_argument("--write-profile-stage",choices=("safety","optimized"),
                        help="also require 100-transaction native audit and control-call profiles for this stage")
    args=parser.parse_args()
    if args.console_node and str(args.console_node).endswith(".exe"):
        for label,path in (("--report-root",args.report_root),("checkout",ROOT)):
            resolved=str(path.resolve())
            if not (resolved.startswith("/mnt/") and resolved[6:7]=="/"):
                parser.error(f"Windows Node requires {label} under /mnt/<drive>/; use a Windows-mounted report directory")
    source(args.source_revision)
    started=datetime.now(UTC)
    report=args.report_root.resolve()/f"{started:%Y%m%dT%H%M%S%fZ}-{os.getpid()}"
    report.mkdir(parents=True)
    environment=os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"]="1"
    environment["FG_SUITE_PYTHON"]=sys.executable
    environment["FG_GATE_BUILD_REVISION"]=args.source_revision
    # This project owns fresh volumes and random loopback ports; retained
    # developer data and already-running services are outside its scope.
    environment["COMPOSE_PROJECT_NAME"]=f"fgp10-local-{started:%H%M%S}-{os.getpid()}"
    for name,port in zip(("MYSQL_PORT","POSTGRES_PORT","MONGO_PORT"),free_ports(),strict=True):
        environment[name]=str(port)
    for name in ("FG_TEST_MYSQL_ROOT_PASSWORD","FG_TEST_POSTGRES_PASSWORD",
                 "FG_TEST_MONGO_ROOT_PASSWORD"):
        environment[name]=secrets.token_hex(24)
    # The relation test uses this run's Compose-native MySQL CLI, independently
    # of any host CLI or developer endpoint inherited from the shell.
    environment.pop("FG_TEST_MYSQL_HOST",None)
    environment.pop("FG_TEST_MYSQL_PORT",None)
    for tag in ("PROTOCOL","P2","P2_MONGO","P3P4","P5","P6","P6_RECOVERY","TRANSPORT","P7","P7GATE","P7BENCH","P7LAYOUT",
                "P10_ARTIFACTS","P10_REPLAY_REGRESSION","P10_STAGED_REPLAY","P10_V1_EXPORT","P10LIFECYCLE","P10_MONGO"):
        environment[f"FG_{tag}_REPORT_ROOT"]=str(report/tag.lower())
    environment["FG_P10_LEASE_REPORT_ROOT"]=str(report/"metadata")
    python=sys.executable
    stages=[]
    def add(name,command,*,stage_engine=None,**extra):
        if stage_engine:
            name=f"{name}-{stage_engine}"
        stages.append((name,command,extra))

    def native_command(script,run_name,engine,*extra):
        return [python,script,"--engine",engine,"--report-dir",str(report/run_name/engine),*extra]

    add("pinned-drivers",[python,"-c","from importlib.metadata import version; assert version('SQLAlchemy')=='2.1.8'; assert version('pymongo')=='4.19.0'; print('Pinned SQLAlchemy and MongoDB drivers available')"])
    add("build-product",["cargo","build","--locked","-p","fg-control","-p","fg-proxy","-p","fg-cli","-p","fg-diff"])
    if args.suite=="all":
        add("local-up",["make","local-up"])
        for name,command in (("check",["make","check"]),("license",["make","license-audit"]),
                             ("postgres-relations",["make","test-postgres"]),("mysql-relations",["make","test-mysql"]),
                             ("differential",["make","diff-test","TAG=smoke",f"DIFF_REPORT_ROOT={report/'diff'}"]),
                             ("matrix",["make","matrix","TAG=smoke"]),("protocol",["make","protocol-test","ENGINE=all"]),
                             ("mongo-plaintext",["make","p2-mongo-test"])):add(name,command)
        add("mongo-tls",["make","p2-mongo-test"],FG_MONGO_TEST_TLS="1")
        for phase in ("p2","p3p4","p5","p6"):
            add(phase,["make",f"{phase}-test","ENGINE=all"])
        for engine in SQL_ENGINES:
            add("metadata-backup-restore",[python,"test/p6/recovery.py",engine],stage_engine=engine)
            add("private-transport",[python,"test/p7/transport_cases.py",engine],stage_engine=engine)
        add("evidence-guards",[python,"test/p7/gate_checks_test.py"])
        add("p7-smoke",["make","p7-smoke","ENGINE=all"])
        add("p7-local",["make","p7-gate","PROFILE=local","ENGINE=all"])
    add("access-migration",[python,"test/p10/access_layout.py"])
    add("build-audit-release",["cargo","build","--locked","--release","--workspace"])
    add("guard-relay-frames",[python,"test/p6/test_faults.py","-v"])
    add("witness-fault-harness",[python,"test/p12/test_witness_storage.py","-v"])
    add("write-profile-harness",[python,"test/p12/test_write_profile.py","-v"])
    add("mongo-audit-relay-frames",[python,"test/p12/test_mongo_audit.py","-v"])
    add("native-mongo-audit",[python,"test/p12/mongo_audit.py",
                              "--report-dir",str(report/"native-mongo-audit")])
    add("leases-budgets-replay-jobs",[python,"test/p10/lease_recovery.py"])
    add("source-backup-roles",[python,"test/p10/source_roles.py","--engine","all",
                               "--report-dir",str(report/"source-backup-roles")])
    add("native-tool-parent-death",[python,"test/p7/native_process_death.py","--report-dir",str(report/"native-parent-death")])
    add("mongo-legacy-upgrade",[python,"test/p10/mongo_legacy_upgrade.py","--report-dir",str(report/"mongo-legacy-upgrade")])
    for engine in SQL_ENGINES:
        add("durable-sql-audit",native_command("test/p12/sql_audit.py","durable-sql-audit",engine),stage_engine=engine)
        add("native-witness-storage",native_command("test/p12/witness_storage.py","native-witness-storage",engine),
            stage_engine=engine)
        if args.write_profile_stage:
            add("native-write-profile",native_command("test/p12/write_profile.py","native-write-profile",engine,
                "--stage",args.write_profile_stage),stage_engine=engine)
        add("cross-table-policy-revocation",native_command("test/p10/policy_context_change.py","policy-context-change",
            engine),stage_engine=engine)
        add("capacity-recovery",native_command("test/p10/capacity_recovery.py","capacity-recovery",engine),
            stage_engine=engine)
        add("seed-boundaries",native_command("test/p7/gate_seed_native.py","seed-boundaries",engine),stage_engine=engine)
        add("seed-refresh-compensation",native_command("test/p7/gate_seed_recovery.py","seed-refresh-compensation",
            engine),stage_engine=engine)
        add("snapshot",native_command("test/p7/snapshot_import.py","snapshot",engine),stage_engine=engine)
        add("application",native_command("test/application/run.py","application",engine),stage_engine=engine)
        for name,script in (
            ("live-leases","test/p10/lifecycle.py"),
            ("complete-sql-artifacts","test/p10/artifacts.py"),
            ("seed-v1-results","test/p10/seed_v1_export.py"),
            ("replay-regressions","test/p10/replay_regression.py"),
            ("staged-replay-cli","test/p10/staged_replay.py"),
        ):
            add(name,[python,script,engine],stage_engine=engine)
    add("mongo-snapshot",[python,"test/p7/mongo_snapshot.py","--report-dir",str(report/"snapshot-mongodb")])
    add("mongo-complete-artifacts",[python,"test/p10/mongo_artifacts.py"])
    if args.console_node:
        add("console-checks",[python,"test/p11/console_check.py","--node",str(args.console_node),
            "--report-dir",str(report/"console-checks")])
        for engine in RELEASE_ENGINES:
            add("console-native",[python,"test/p11/console_native.py","--node-executable",str(args.console_node),
                "--engine",engine,"--report-dir",str(report/"console-native"/engine)],stage_engine=engine)
    if args.deployment_image:
        add("persistent-deployment",[python,"test/p10/deployment.py","--image",args.deployment_image,
            "--expected-source-revision",args.source_revision,"--frontend-port","15433","--report-dir",str(report/"deployment")])
    if args.suite=="all":
        # Exercise the nightly corpus outside the scheduled evidence directory.
        add("nightly-sql-corpus",["make","p7-gate","PROFILE=nightly","ENGINE=all"],
            FG_P7GATE_REPORT_ROOT=str(report/"nightly-corpus"))
    if args.paired_performance:
        add("native-layout-costs",[python,"test/p7/layout_costs.py"])
        add("serial-paired-performance",[python,"test/p7/bench_baseline.py"],
            FG_GATE_BENCH_WARMUP="10",FG_GATE_BENCH_MEASURE="30",FG_GATE_BENCH_CONCURRENCY="16")
    result={"source_revision":args.source_revision,"source_state":"clean","suite":args.suite,
            "engines":RELEASE_ENGINES,
            "started_at":started.isoformat(),"stages":[],"status":"running"}
    try:
        for name,command,extra in stages:
            source(args.source_revision)
            stage={"name":name,"command":command,"started_at":datetime.now(UTC).isoformat()}
            print(f"Starting {name}; report: {report}",flush=True)
            result["stages"].append(stage)
            write(report/"stages.json",result)
            with (report/f"{name}.log").open("w",encoding="utf-8") as output:
                status=subprocess.call(command,cwd=ROOT,env=environment|extra,stdout=output,stderr=subprocess.STDOUT)
            stage.update(exit_code=status,finished_at=datetime.now(UTC).isoformat())
            write(report/"stages.json",result)
            if status and name in ("pinned-drivers","build-product","build-audit-release","local-up"):
                raise RuntimeError(f"{name} failed; dependent verification cannot proceed")
        source(args.source_revision)
        result["failed_stages"]=[stage["name"] for stage in result["stages"] if stage.get("exit_code")]
        result["status"]="failed" if result["failed_stages"] else "passed"
    except (OSError,ValueError,RuntimeError,KeyboardInterrupt) as error:
        result.update(status="failed",failure=str(error))
    finally:
        if args.suite=="all":
            cleanup=["docker","compose","-f","test/local/docker-compose.yml","down","--volumes"]
            with (report/"local-cleanup.log").open("w",encoding="utf-8") as output:
                result["owned_local_cleanup_exit"]=subprocess.call(cleanup,cwd=ROOT,env=environment,stdout=output,stderr=subprocess.STDOUT)
            if result["owned_local_cleanup_exit"]:result["status"]="failed"
        result["finished_at"]=datetime.now(UTC).isoformat()
        write(report/"stages.json",result)
    print(json.dumps({"status":result["status"],"report":str(report)}))
    return 0 if result["status"]=="passed" else 1


if __name__=="__main__":raise SystemExit(main())
