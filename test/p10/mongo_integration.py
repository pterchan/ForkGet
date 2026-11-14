#!/usr/bin/env python3
"""Run the existing P2 MongoDB suite on isolated plain and TLS deployments."""

import argparse
from datetime import UTC,datetime
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
COMPOSE=ROOT / "test/local/docker-compose.yml"


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir",type=Path,required=True)
    options=parser.parse_args()
    report=options.report_dir.resolve()
    report.mkdir(parents=True,exist_ok=False)
    results={}
    for transport in ("plain","tls"):
        directory=report / transport
        directory.mkdir()
        project=f"fgp10mongo-{transport}-{os.getpid()}"
        environment={key:value for key,value in os.environ.items() if not key.startswith("FG_")}
        environment["CARGO_TARGET_DIR"]=os.environ.get("CARGO_TARGET_DIR",str(ROOT / "target"))
        environment["FG_SUITE_PYTHON"]=os.environ.get("FG_SUITE_PYTHON",sys.executable)
        environment["COMPOSE_PROJECT_NAME"]=project
        passwords={name:secrets.token_hex(24) for name in ("MYSQL_ROOT","POSTGRES","MONGO_ROOT")}
        environment.update({"FG_TEST_"+name+"_PASSWORD":value for name,value in passwords.items()})
        listeners=[socket.socket() for _ in range(2)]
        try:
            for listener in listeners:listener.bind(("127.0.0.1",0))
            environment["MONGO_PORT"],environment["POSTGRES_PORT"]=[str(listener.getsockname()[1]) for listener in listeners]
        finally:
            for listener in listeners:listener.close()
        if transport=="tls":environment["FG_MONGO_TEST_TLS"]="1"
        command=["docker","compose","--project-name",project,"--file",str(COMPOSE)]
        cleaned=False
        started=datetime.now(UTC).isoformat()
        result=None
        try:
            result=subprocess.run([sys.executable,str(ROOT / "test/p2/mongo.py"),str(directory)],cwd=ROOT,
                                  env=environment,capture_output=True,text=True,timeout=900)
            details=result.stdout+result.stderr
            for password in passwords.values():details=details.replace(password,"[redacted]")
            (directory / "suite.log").write_text(details)
            print(details,flush=True)
        finally:
            cleanup=subprocess.run(command+["down","--volumes","--remove-orphans","--timeout","5"],
                                   cwd=ROOT,env=environment,capture_output=True,text=True,timeout=90)
            (directory / "cleanup.log").write_text(cleanup.stdout+cleanup.stderr)
            remaining=[]
            for listing in (["ps","-aq"],["volume","ls","--quiet"],["network","ls","--quiet"]):
                output=subprocess.check_output(["docker",*listing,"--filter",f"label=com.docker.compose.project={project}"],text=True)
                remaining.extend(output.splitlines())
            cleaned=cleanup.returncode==0 and not remaining
        results[transport]={"exit_code":result.returncode if result else None,"started_at":started,
                            "project":project,"cleaned_up":cleaned,"passed":bool(result and result.returncode==0 and cleaned)}
        (report / "report.json").write_text(json.dumps({"status":"passed" if all(item["passed"] for item in results.values()) else "failed",
            "scope":"dirty preparatory integration; exact revision must be rerun before release","transports":results},indent=2)+"\n")
    return 0 if all(item["passed"] for item in results.values()) else 1


if __name__=="__main__":
    raise SystemExit(main())
