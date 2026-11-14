"""Exercise uncertain CI and replay outcomes against real P6 deployments."""

import json
import subprocess
import sys

from faults import CommitReply, ControlRelay
from replay import export
from run_p2 import OWNER_A, ROOT, require, wait_until
from write_cases import Probe, check_count

WITNESS_ID = 909101
WITNESS_QUERY = f"SELECT id FROM customers WHERE id={WITNESS_ID}"


def assert_redacted(run, *outputs):
    credentials = (*run.secret.values(), *run.owner_tokens.values(), *run.frontend_passwords.values())
    require(all(value not in output for output in outputs for value in credentials if value),
            "CI or replay output contained a deployment credential")


def ci(run, output, *args, origin=None, succeeds=True):
    environment = run.base_env | {
        "FG_CI_ENDPOINT": f"127.0.0.1:{run.proxy_port}",
        "FG_CI_FRONTEND_CA": str(run.certs / "frontend-ca.pem"),
        "FG_CI_FRONTEND_USER": OWNER_A,
        "FG_CI_FRONTEND_PASSWORD": run.frontend_passwords[OWNER_A],
        "FG_CI_FORKGET": str(run.executable("forkget")),
        "FG_CI_PROBE": str(run.executable("fg-write-probe")),
        "FG_CONTROL_URL": origin or run.control_url,
        "FG_OWNER_TOKEN": run.owner_tokens[OWNER_A],
        "GITHUB_OUTPUT": str(output),
    }
    result = subprocess.run([sys.executable, ROOT / "test/p6/ci.py", *args], env=environment,
                            capture_output=True, text=True, timeout=55)
    assert_redacted(run, result.stdout, result.stderr, output.read_text() if output.exists() else "")
    if (result.returncode == 0) != succeeds:
        (run.report / f"ci-fault-{output.name}.log").write_text(
            f"returncode={result.returncode}\n--stdout--\n{result.stdout}\n--stderr--\n{result.stderr}",
            encoding="utf-8", errors="backslashreplace")
    require((result.returncode == 0) == succeeds, "CI fault step had an unexpected exit status")
    return result


def lost_fork_reply(run):
    accepted = []
    name = "ci-lost-reply"

    def lose_reply(method, path, status, body):
        if (method, path, status) == ("POST", "/v1/branches", 201):
            accepted.append(json.loads(body))
            return True
        return False

    output = run.certs.parent / "lost-fork-output"
    with ControlRelay(run, lose_reply) as relay:
        result = ci(run, output, "fork", "--name", name, "--ttl", "2", "--read-only",
                    origin=relay.url, succeeds=False)
    require(result.stderr.strip() == "Forkget CI step failed (fork)." and not result.stdout
            and not output.exists(), "An unanswered fork exposed output or claimed success")
    require(len(accepted) == 1 and accepted[0]["name"] == name and accepted[0]["status"] == "active",
            "The upstream fork did not commit once before its response was lost")
    branch = accepted[0]
    branch_id = branch["id"]
    require(run.branch_status(branch) == "active", "The unanswered fork was not persisted")
    wait_until("unanswered fork TTL reached", lambda: run.metadata(
        f"SELECT (expires_at <= clock_timestamp())::int FROM branch WHERE id={branch_id};") == "1", seconds=10)
    run.stop("control")
    run.start_control()
    run.wait_dropped(OWNER_A, branch_id)
    run.record("CI fork committed once before reply loss, published no credentials or ID, and expired by TTL")


def drop_partial_fork(run, admin, generation_lock):
    output = run.certs.parent / "partial-fork-output"
    name = "ci-partial-id"
    with Probe(run, "hold-ci-provisioning", metadata=True) as guard:
        guard.sql(f"SELECT pg_advisory_lock({generation_lock})")
        ci(run, output, "fork", "--name", name)
        fields = dict(line.split("=", 1) for line in output.read_text().splitlines())
        branch_id = int(fields["branch_id"])
        require(fields == {"branch_id": str(branch_id), "branch_name": name,
                           "endpoint": f"127.0.0.1:{run.proxy_port}"} and branch_id > 0,
                "CI fork did not publish the acknowledged immutable ID and safe connection fields")
        require(run.branch_status({"id": branch_id}) == "provisioning", "Native CI branch provision was not held")
        run.metadata(f"UPDATE branch SET native_claimed=true WHERE id={branch_id};")
        schema, _ = run.branch_namespace(branch_id)
        if run.family == "postgresql":
            run.native(f"CREATE SCHEMA {schema} AUTHORIZATION {admin};")
        role = f"SET ROLE {admin};" if run.family == "postgresql" else ""
        orders = run.branch_relation(branch_id, "orders")
        run.native(f"{role} CREATE TABLE {orders} (incomplete INT PRIMARY KEY);")
        ci(run, output, "wait", "--id", str(branch_id), origin=run.control_url + "/invalid", succeeds=False)
        ci(run, output, "drop", "--id", str(branch_id))
        require(run.branch_status({"id": branch_id}) == "dropping" and run.branch_storage_exists(branch_id),
                "The acknowledged partial branch did not persist its drop before cleanup")
    run.wait_dropped(OWNER_A, branch_id)
    require(not run.branch_storage_exists(branch_id), "CI cleanup left the claimed partial branch storage")
    run.record("CI acknowledged a provisioning ID, redacted credentials and removed its claimed partial storage by ID")


def replay_command(run, path, name, origin=None):
    environment = run.base_env | {
        "FG_CONTROL_URL": origin or run.control_url,
        "FG_OWNER_TOKEN": run.owner_tokens[OWNER_A],
    }
    arguments = [run.executable("forkget"), "replay", "--engine", run.engine,
                 "--input", path, "--name", name]
    return arguments, environment


def receipt(run, process):
    assert_redacted(run, process.stdout, process.stderr)
    if not process.stdout:
        (run.report / "replay-fault.log").write_text(run.safe(process.stderr), encoding="utf-8")
    require(bool(process.stdout), "Replay fault did not return its immutable job receipt")
    result=json.loads(process.stdout)
    require(result["job_id"]>0 and result["branch_id"]>0,"Replay lost its immutable job or target identity")
    (run.report/f"replay-fault-receipt-{result['job_id']}.json").write_text(json.dumps(result,indent=2)+"\n")
    return result


def replacement_replay(run, path):
    name = "replay-decoy"
    original = []
    replacement = []

    def replace_after_preflight(method, route, status, body):
        if (method, route, status) == ("POST", "/v1/replays", 200):
            original.append(json.loads(body))
        if (original and not replacement
                and (method, route, status) == ("GET", f"/v1/branches/{original[0]['branch']['id']}", 200)
                and json.loads(body)["status"]=="active"):
            run.drop(OWNER_A, original[0]["branch"]["id"])
            replacement.append(run.create(name)[0])
        return False

    with ControlRelay(run, replace_after_preflight) as relay:
        args, env = replay_command(run, path, name, origin=relay.url)
        process = subprocess.run(args, env=env, capture_output=True, text=True, timeout=350)
    result=receipt(run,process)
    require(process.returncode!=0 and not result.get("verified",False)
            and (result.get("cleanup")=="retained" or result.get("retained") is True),
            "Failed replay claimed verification or automatically discarded its job")
    require(len(original) == len(replacement) == 1 and result["branch_id"] == original[0]["branch"]["id"]
            and result["job_id"]==original[0]["job"]["id"] and replacement[0]["id"] != result["branch_id"],
            "The test did not replace the pinned ID under the same name")
    require(run.metadata(f"SELECT count(*) FROM audit_event WHERE branch_id={result['branch_id']} AND event_type='policy_decision';")=="0",
            "Replay executed a mutation against the dropped original target")
    require(run.branch_status(replacement[0]) == "active" and all(not rows for rows in run.rowdiff(replacement[0]).values()),
            "Replay touched or cleaned up the replacement branch")
    run.drop(OWNER_A, replacement[0]["id"])
    run.record("Replay job remains pinned to its original ID across real same-name replacement; no mutation or cleanup reaches the replacement")


def lost_apply_reply(run,path):
    completed=[]
    verifies=[]
    decisions=[]
    def lose_completion(method,route,status,body):
        if method=="POST" and route.startswith("/v1/replays/") and route.endswith("/verify"):
            verifies.append(route)
        if method=="POST" and route.startswith("/v1/replays/") and route.endswith("/apply") and status==200:
            result=json.loads(body)
            require(result["verified"] and result["result"]["transaction"]=="committed",
                    "The lost HTTP completion did not follow a real verified native commit")
            completed.append(result)
            decisions.append(run.metadata(f"SELECT count(*) FROM audit_event WHERE branch_id={result['job']['branch_id']} AND event_type='policy_decision';"))
            return True
        return False
    with ControlRelay(run,lose_completion) as relay:
        args,environment=replay_command(run,path,"replay-lost-apply",origin=relay.url)
        process=subprocess.run(args,env=environment,capture_output=True,text=True,timeout=350)
    result=receipt(run,process)
    require(process.returncode==0 and result["verified"] and len(completed)==1 and len(verifies)==1,
            "CLI did not recover the lost completion with exactly one verification request")
    require(result["job_id"]==completed[0]["job"]["id"] and result["branch_id"]==completed[0]["job"]["branch_id"],
            "Recovery changed the known immutable job identity")
    require(run.metadata(f"SELECT count(*) FROM audit_event WHERE branch_id={result['branch_id']} AND event_type='policy_decision';")==decisions[0],
            "Recovering a lost completion submitted another mutation decision")
    with Probe(run,"lost-apply-native-result",(OWNER_A,"replay-lost-apply")) as observer:
        require(observer.sql(WITNESS_QUERY,"read").get("rows")==[[WITNESS_ID]],"Recovery lost the committed native witness")
    expected=[json.loads(line)["value"] for line in path.read_text().splitlines() if json.loads(line)["record"]=="change"]
    target={"id":result["branch_id"]}
    observed=run.certs.parent/"lost-apply-observed.ndjson"
    export(run,target,observed)
    actual=[json.loads(line)["value"] for line in observed.read_text().splitlines() if json.loads(line)["record"]=="change"]
    require(actual==expected,"Lost-completion recovery changed the exact typed net result")
    require(run.branch_status(target)=="active","Verified recovery discarded its target")
    (run.report/"http-apply-reply-loss.json").write_text(json.dumps({"upstream_verified_completion":completed[0],
        "apply_requests":len(completed),"verify_requests":len(verifies),"policy_decisions_before_and_after":decisions[0],
        "exact_typed_result":True,"recovery":result},indent=2)+"\n")
    run.drop(OWNER_A,target["id"])
    run.record("Control relay discarded the real native verified apply completion; CLI only verified the same job, retained exact typed results and submitted no second mutation")


def committed_replay(run, path):
    name = "replay-lost-commit"
    native_port=run.native_port
    run.stop("proxy")
    with CommitReply(run,native=True) as relay:
        try:
            run.native_port=relay.port
            run.start_proxy()
        finally:
            run.native_port=native_port
        args, env = replay_command(run, path, name)
        process = subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            def commit_sent():
                require(process.poll() is None, "Replay exited before forwarding native COMMIT")
                return relay.commit.is_set()
            wait_until("replay sent native COMMIT", commit_sent, seconds=30)
            require(relay.withheld.wait(5), "The native relay did not receive the real COMMIT reply")
            branch_id=int(run.metadata("SELECT b.id FROM branch b JOIN replay_job j ON j.branch_id=b.id WHERE b.name='replay-lost-commit' ORDER BY j.id DESC LIMIT 1;"))
            customers=run.branch_relation(branch_id,"customers")
            require(run.native(f"SELECT id FROM {customers} WHERE id={WITNESS_ID};")==str(WITNESS_ID),
                    "The withheld native COMMIT was not durable")
            status,_=run.request("POST","/internal/v1/resolve",run.secret["internal"],{"principal":OWNER_A,"branch":name})
            require(status==404,"An unverified native commit target accepted ordinary sessions")
            relay.lose_commit_reply()
            stdout, stderr = process.communicate(timeout=45)
            result=receipt(run,subprocess.CompletedProcess(args,process.returncode,stdout,stderr))
            require(process.returncode==0 and result["verified"] and result["transaction"]=="unknown"
                    and result["result"]["applied_again"] is False and result["branch_id"]==branch_id,
                    "Native unknown-COMMIT recovery did not verify without reapplying")
            require(relay.commits==1 and relay.mutations==1,"Unknown native commit submitted duplicate mutations or COMMIT")
            require(relay.witness_mutations==1,"Unknown native commit did not submit exactly one audit witness")
            require(run.branch_status({"id":branch_id})=="active","Verified unknown commit discarded its target")
            (run.report/"native-commit-reply-loss.json").write_text(json.dumps({"verified_tls":True,"native_reply_withheld":relay.withheld.is_set(),
                "durable_witness":WITNESS_ID,"ordinary_access_before_verification":404,"native_mutations":relay.mutations,
                "native_witness_mutations":relay.witness_mutations,"native_commits":relay.commits,"recovery":result},indent=2)+"\n")
        finally:
            if process.poll() is None:
                process.kill();process.communicate(timeout=5)
            run.stop("proxy")
    run.start_proxy()
    run.drop(OWNER_A,branch_id)
    run.record("Verified TLS native relay withheld a durable COMMIT success packet; private target stayed inaccessible until fresh verify-only equality, with exactly one mutation and COMMIT")


def negative_cases(run, admin, generation_lock):
    lost_fork_reply(run)
    drop_partial_fork(run, admin, generation_lock)
    source, credentials = run.create("replay-fault-source")
    with Probe(run, "write-replay-fault-source", credentials) as probe:
        check_count(probe, f"INSERT INTO customers (id,name) VALUES ({WITNESS_ID},'replay-fault-witness')", 1)
    path = run.certs.parent / "fault-witness.json"
    export(run, source, path)
    replacement_replay(run, path)
    lost_apply_reply(run,path)
    committed_replay(run, path)
    run.drop(OWNER_A, source["id"])
