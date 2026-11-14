"""Exercise GitHub App reconciliation through the real control and proxy."""

import base64
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import subprocess
import tempfile
from threading import Event, Lock, Thread
from urllib.error import HTTPError
from urllib.parse import unquote
from urllib.request import ProxyHandler, Request, build_opener

from run_p2 import OWNER_A, OWNER_B, require, wait_until
from write_cases import Probe, check_count


APP_ID = 823
INSTALLATION_ID = 570
REPOSITORY_ID = 417
API_VERSION = "2026-03-10"
REPOSITORY = "example/widget"
WEBHOOK = "/v1/github/webhook"
BINDINGS = "/v1/github/bindings"
HTTP = build_opener(ProxyHandler({}))


class MockGitHub:
    def __init__(self, directory):
        self.directory = directory
        self.key = directory / "fixture-app.pem"
        self.public = directory / "fixture-app.pub"
        self.secret = secrets.token_hex(32)
        self.token = ""
        self.issued = 0
        self.rejected_token = ""
        self.status_override = None
        self.refs = set()
        self.pulls = {}
        self.observations = []
        self.lock = Lock()
        self.hold_ref = None
        self.held = Event()
        self.release = Event()
        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.http.fixture = self
        self.thread = Thread(target=self.http.serve_forever, daemon=True)

    def __enter__(self):
        for arguments in (("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", self.key),
                          ("pkey", "-in", self.key, "-pubout", "-out", self.public)):
            result = subprocess.run(["openssl", *arguments], capture_output=True, timeout=15)
            require(result.returncode == 0, "OpenSSL could not create the disposable GitHub App key")
        self.key.chmod(0o600)
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.release.set()
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(timeout=5)

    def env(self, pr_write=False, *, installation_id=INSTALLATION_ID, principal=OWNER_A):
        return {
            "FG_GITHUB_WEBHOOK_SECRET": self.secret,
            "FG_GITHUB_APP_ID": str(APP_ID),
            "FG_GITHUB_TEST_APP_PRIVATE_KEY": str(self.key),
            "FG_GITHUB_TEST_API_URL": f"http://127.0.0.1:{self.http.server_port}",
            "FG_GITHUB_REPOSITORIES": json.dumps([{
                "repository_id": REPOSITORY_ID, "installation_id": installation_id,
                "owner": "example", "repo": "widget", "principal": principal, "pr_write": pr_write,
            }]),
        }

    def verify_jwt(self, bearer):
        scheme, jwt = bearer.split(" ", 1)
        header, claims, signature = jwt.split(".")
        if scheme != "Bearer" or json.loads(unbase64(header)) != {"alg": "RS256", "typ": "JWT"}:
            return False
        body = json.loads(unbase64(claims))
        now = int(datetime.now(UTC).timestamp())
        if body.get("iss") != str(APP_ID) or not now - 75 <= body.get("iat", 0) <= now - 45:
            return False
        if not now < body.get("exp", 0) <= now + 600:
            return False
        with tempfile.NamedTemporaryFile(dir=self.directory) as signed:
            signed.write(unbase64(signature))
            signed.flush()
            result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", self.public,
                                     "-signature", signed.name], input=f"{header}.{claims}".encode(),
                                    capture_output=True, timeout=5)
        return result.returncode == 0


def unbase64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def do_POST(self):
        fixture = self.server.fixture
        if self.headers.get("X-GitHub-Api-Version") != API_VERSION or self.path != f"/app/installations/{INSTALLATION_ID}/access_tokens":
            return self.reply(404, {})
        try:
            valid_jwt = fixture.verify_jwt(self.headers.get("Authorization", ""))
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        except (OSError, ValueError, TypeError, subprocess.SubprocessError):
            return self.reply(401, {})
        permissions = {"contents": "read", "pull_requests": "read"}
        if not valid_jwt or body != {"repository_ids": [REPOSITORY_ID], "permissions": permissions}:
            return self.reply(401, {})
        with fixture.lock:
            fixture.issued += 1
            fixture.token = secrets.token_hex(24)
            token = fixture.token
        return self.reply(201, {"token": token, "permissions": permissions | {"metadata": "read"},
                                "repositories": [{"id": REPOSITORY_ID}],
                                "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat()})

    def do_GET(self):
        fixture = self.server.fixture
        path = unquote(self.path)
        repository = f"/repos/{REPOSITORY}"
        prefix = repository + "/git/matching-refs/"
        wait = False
        with fixture.lock:
            authorization = self.headers.get("Authorization", "")
            if (self.headers.get("X-GitHub-Api-Version") != API_VERSION or
                    authorization != f"Bearer {fixture.token}" or fixture.token == fixture.rejected_token):
                status, body = 401, {}
            elif fixture.status_override is not None:
                status, body = fixture.status_override, {}
            elif path == repository:
                status, body = 200, {"id": REPOSITORY_ID}
            elif path.startswith(prefix):
                ref = "refs/" + path.removeprefix(prefix)
                status, body = 200, [{"ref": name} for name in fixture.refs if name.startswith(ref)]
                fixture.observations.append({"kind": "ref", "key": ref, "present": ref in fixture.refs})
                wait = fixture.hold_ref == ref
                if wait:
                    fixture.hold_ref = None
                    fixture.held.set()
            elif path.startswith(repository + "/pulls/"):
                number = path.rsplit("/", 1)[1]
                status, body = 200, {"id": 900 + int(number), "number": int(number), "state": fixture.pulls.get(number, "closed"),
                                     "base": {"repo": {"id": REPOSITORY_ID}}}
                fixture.observations.append({"kind": "pull_request", "key": number, "present": fixture.pulls.get(number)=="open"})
            else:
                status, body = 404, {}
        if wait:
            fixture.release.wait(8)
        return self.reply(status, body)


def post(run, fixture, event, data, expected=202, signature=True):
    body = json.dumps(data, ensure_ascii=False).encode()
    digest = hmac.new(fixture.secret.encode(), body, hashlib.sha256).hexdigest()
    headers = {"X-GitHub-Event": event, "Content-Type": "application/json",
               "X-GitHub-Delivery": "a571473b-6db0-47a4-ac21-782deca008da"}
    if signature is not None:
        headers["X-Hub-Signature-256"] = "sha256=" + (digest if signature else "0" * 64)
    request = Request(run.control_url + WEBHOOK, data=body, headers=headers, method="POST")
    try:
        with HTTP.open(request, timeout=4) as response:
            status = response.status
    except HTTPError as error:
        status = error.code
    require(status == expected, f"GitHub {event} returned {status}, expected {expected}")


def push(ref, *, created=True, repository_id=REPOSITORY_ID, installation_id=INSTALLATION_ID, **extra):
    return {"repository": {"id": repository_id, "full_name": REPOSITORY}, "installation": {"id": installation_id},
            "ref": ref, "created": created, "deleted": not created, **extra}


def pull(action, number=9):
    return {"repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
            "installation": {"id": INSTALLATION_ID}, "action": action, "number": number,
            "pull_request": {"number": number, "base": {"repo": {"id": REPOSITORY_ID}},
                             "head": {"repo": {"id": REPOSITORY_ID + 1}}}}


def bindings(run, owner=OWNER_A):
    status, raw = run.request("GET", BINDINGS, run.owner_tokens[owner])
    require(status == 200, "Could not query GitHub bindings")
    return {entry["source_key"]: entry for entry in json.loads(raw)["bindings"]}


def await_binding(run, key, predicate):
    def observe():
        entry = bindings(run).get(key)
        return entry if entry is not None and predicate(entry) else None
    return wait_until(f"GitHub source {key}", observe)


def branch_detail(run, branch_id):
    status, data = run.request("GET", f"/v1/branches/{branch_id}", run.owner_tokens[OWNER_A])
    require(status == 200, "GitHub branch is unavailable to its owner")
    return json.loads(data)


def ref_cases(run, fixture):
    ref = "refs/heads/Feature/API"
    post(run, fixture, "push", push(ref), 401, signature=False)
    post(run, fixture, "push", push(ref), 401, signature=None)
    post(run, fixture, "push", push(ref, repository_id=REPOSITORY_ID + 1), 403)
    post(run, fixture, "push", push(ref, installation_id=INSTALLATION_ID + 1), 403)
    post(run, fixture, "push", {}, 400)
    post(run, fixture, "ping", {}, 204)
    post(run, fixture, "push", push(ref) | {"created": False}, 204)
    require(not bindings(run), "Rejected or ignored delivery persisted a binding")
    fixture.refs.add(ref)
    post(run, fixture, "push", push(ref, padded="é" * 5500))
    first = await_binding(run, ref, lambda row: row["state"] == "present")
    branch_id = first["branch_id"]
    original = branch_detail(run, branch_id)
    require(original["class"] == "dev" and original["mode"] == "read_only" and fixture.issued == 1,
            "Source branch or GitHub JWT/token scope did not match the contract")
    post(run, fixture, "push", push(ref))
    post(run, fixture, "push", push(ref, created=False))
    current = await_binding(run, ref, lambda row: row["state"] == "present")
    require(current["branch_id"] == branch_id and branch_detail(run, branch_id)["expires_at"] == original["expires_at"],
            "Duplicate or reordered delivery replaced the branch or renewed its TTL")
    for blocked_ref, reason in (("refs/heads/" + "x" * 70, "name_too_long"),
                                ("refs/heads/feature-api", "name_conflict")):
        for _ in range(2):
            post(run, fixture, "push", push(blocked_ref))
            blocked = bindings(run)[blocked_ref]
            require(blocked["state"] == "blocked" and blocked["last_error"] == reason
                    and blocked["branch_id"] is None, "The acknowledged naming failure did not stay blocked")
    require(bindings(run)[ref] == current and branch_detail(run, branch_id) == original,
            "A blocked naming delivery changed the existing live binding")
    require(not bindings(run, OWNER_B), "GitHub bindings were visible to another owner")
    with fixture.lock:
        fixture.rejected_token = fixture.token
    post(run, fixture, "push", push(ref))
    await_binding(run, ref, lambda row: row["state"] == "present")
    require(fixture.issued == 2, "HTTP 401 did not refresh the installation token exactly once")
    with fixture.lock:
        fixture.status_override = 404
    post(run, fixture, "push", push(ref, created=False))
    await_binding(run, ref, lambda row: row["state"] == "retrying" and row["last_error"] == "access_unavailable")
    require(branch_detail(run, branch_id)["status"] == "active" and fixture.issued == 2,
            "Ambiguous GitHub 404 removed the branch or refreshed credentials")
    with fixture.lock:
        fixture.status_override = None
    await_binding(run, ref, lambda row: row["state"] == "present")
    run.record("GitHub rejects invalid signatures and scope, ignores irrelevant events, and acknowledges durable naming blocks")
    run.record("GitHub token scope, TTL stability, and owner isolation")

    with fixture.lock:
        fixture.hold_ref = ref
        fixture.refs.remove(ref)
    post(run, fixture, "push", push(ref, created=False))
    require(fixture.held.wait(4), "The stale authoritative request did not start")
    with fixture.lock:
        fixture.refs.add(ref)
    post(run, fixture, "push", push(ref))
    fixture.release.set()
    await_binding(run, ref, lambda row: row["state"] == "present")
    require(branch_detail(run, branch_id)["status"] == "active", "A superseded GitHub lookup dropped the branch")
    run.metadata(f"UPDATE branch SET created_at=clock_timestamp()-interval '2 hours', "
                 f"expires_at=clock_timestamp()-interval '1 second' WHERE id={branch_id};")
    run.stop("control")
    run.start_control()
    run.wait_dropped(OWNER_A, branch_id)
    post(run, fixture, "push", push(ref))
    current = await_binding(run, ref, lambda row: row["state"] == "present")
    require(current["branch_id"] == branch_id and current["branch_status"] == "dropped",
            "Duplicate create recreated an expired branch")
    manual, _ = run.fork(first["name"])
    with fixture.lock:
        fixture.refs.remove(ref)
        fixture.refs.add(ref + "-sibling")
    post(run, fixture, "push", push(ref, created=False))
    await_binding(run, ref, lambda row: row["state"] == "absent")
    require(branch_detail(run, manual["id"])["status"] == "active", "Old binding deleted a newer manual branch by name")
    run.drop(OWNER_A, manual["id"])
    run.record("GitHub superseded observations, restart TTL, exact ref match and stale cleanup by immutable ID")


def stored_binding_conflicts(run, fixture, other_owner):
    ref = "refs/heads/stored-binding"
    fixture.refs.add(ref)
    post(run, fixture, "push", push(ref))
    original = await_binding(run, ref, lambda row: row["state"] == "present")
    branch_id = original["branch_id"]
    witness = f"SELECT row_to_json(source) FROM github_source AS source WHERE source_key='{ref}';"
    before = run.metadata(witness)
    try:
        for mapping in ({"installation_id": INSTALLATION_ID + 1}, {"principal": other_owner}):
            run.stop("control")
            run.base_env.update(fixture.env(**mapping))
            run.start_control()
            installation = mapping.get("installation_id", INSTALLATION_ID)
            post(run, fixture, "push", push(ref, installation_id=installation), 409)
            require(run.metadata(witness) == before and bindings(run)[ref] == original
                    and ref not in bindings(run, other_owner) and run.branch_status({"id": branch_id}) == "active",
                    "Conflicting GitHub configuration changed a stored binding")
    finally:
        run.stop("control")
        run.base_env.update(fixture.env())
        run.start_control()
    fixture.refs.remove(ref)
    post(run, fixture, "push", push(ref, created=False))
    run.wait_dropped(OWNER_A, branch_id)
    run.record("GitHub rejects a newly configured installation or owner that conflicts with an existing durable binding")


def github_cli(run, label, *arguments, owner=OWNER_A, succeeds=True):
    environment=run.base_env | {"FG_CONTROL_URL":run.control_url,"FG_OWNER_TOKEN":run.owner_tokens[owner]}
    output=run.call("github-cli-"+label,[run.executable("forkget"),"github",*arguments],env=environment,
                    log=True,succeeds=succeeds)
    return json.loads(output) if succeeds else None


def recreate_cases(run,fixture):
    ref="refs/heads/recreate-cli"
    with fixture.lock:
        fixture.refs.add(ref)
    post(run,fixture,"push",push(ref))
    original=await_binding(run,ref,lambda row:row["state"]=="present" and row["branch_status"]=="active")
    old_id=original["branch_id"]
    arguments=("recreate","--repository-id",str(REPOSITORY_ID),"--kind","ref","--source-key",ref,"--expected-branch-id")
    github_cli(run,"active-refused",*arguments,str(old_id),succeeds=False)
    run.metadata(f"UPDATE branch SET created_at=clock_timestamp()-interval '2 hours', "
                 f"expires_at=clock_timestamp()-interval '1 second' WHERE id={old_id};")
    run.stop("control")
    run.start_control()
    run.wait_dropped(OWNER_A,old_id)
    post(run,fixture,"push",push(ref))
    expired=await_binding(run,ref,lambda row:row["state"]=="present" and row["branch_status"]=="dropped")
    listed=github_cli(run,"expired-list","list")["bindings"]
    require(any(row["source_key"]==ref and row["branch_id"]==old_id and row["environment_state"]=="expired" for row in listed),
            "CLI list omitted the expired GitHub environment")
    require(not any(row["source_key"]==ref for row in github_cli(run,"other-owner-list","list",owner=OWNER_B)["bindings"]),
            "Another owner could list the expired binding")
    witness=f"SELECT row_to_json(s) FROM github_source s WHERE source_key='{ref}';"
    before=run.metadata(witness)
    before_count=run.metadata("SELECT count(*) FROM branch;")
    github_cli(run,"wrong-id",*arguments,str(old_id+100000),succeeds=False)
    github_cli(run,"other-owner",*arguments,str(old_id),owner=OWNER_B,succeeds=False)
    require(run.metadata(witness)==before and run.metadata("SELECT count(*) FROM branch;")==before_count,
            "A stale ID or another owner changed the GitHub binding")
    run.record("GitHub CLI lists expired bindings, isolates owners and refuses recreation with an active or stale branch ID")

    with fixture.lock:
        fixture.refs.remove(ref)
        fixture.refs.add(ref+"-sibling")
        observations=len(fixture.observations)
    require(github_cli(run,"closed-source",*arguments,str(old_id))["status"]=="accepted","Recreate did not queue a fresh observation")
    absent=await_binding(run,ref,lambda row:row["state"]=="absent")
    with fixture.lock:
        fresh=fixture.observations[observations:]
    require(absent["branch_id"]==old_id and run.metadata("SELECT count(*) FROM branch;")==before_count
            and any(row["key"]==ref and not row["present"] for row in fresh),
            "Recreate ignored the closed authoritative source or accepted a sibling ref")
    try:
        run.stop("control")
        run.base_env.update(fixture.env(installation_id=INSTALLATION_ID+1))
        run.start_control()
        github_cli(run,"changed-installation",*arguments,str(old_id))
        blocked=await_binding(run,ref,lambda row:row["state"]=="blocked" and row["last_error"]=="access_unavailable")
        require(blocked["branch_id"]==old_id and run.metadata("SELECT count(*) FROM branch;")==before_count,
                "Changed provider scope recreated the old environment")
    finally:
        run.stop("control")
        run.base_env.update(fixture.env())
        run.start_control()
    run.record("GitHub recreation rechecks the authoritative exact ref and refuses closed sources or changed installation scope")

    with fixture.lock:
        fixture.refs.add(ref)
        fixture.hold_ref=ref
        fixture.held.clear()
        fixture.release.clear()
        observations=len(fixture.observations)
    github_cli(run,"fresh-source",*arguments,str(old_id))
    require(fixture.held.wait(4),"Recreate did not perform a fresh GitHub provider request")
    require(run.metadata("SELECT count(*) FROM branch;")==before_count,"Recreate allocated before the provider observation completed")
    fixture.release.set()
    renewed=await_binding(run,ref,lambda row:row["state"]=="present" and row["branch_status"]=="active" and row["branch_id"]!=old_id)
    new_id=renewed["branch_id"]
    new_branch=branch_detail(run,new_id)
    with fixture.lock:
        fresh=fixture.observations[observations:]
    require(renewed["name"]==original["name"] and any(row["key"]==ref and row["present"] for row in fresh),
            "Successful recreation lost its stable logical name or fresh provider evidence")
    for created in (True,False,True):
        post(run,fixture,"push",push(ref,created=created))
        current=await_binding(run,ref,lambda row:row["state"]=="present")
        require(current["branch_id"]==new_id and branch_detail(run,new_id)["expires_at"]==new_branch["expires_at"],
                "Duplicate or reordered webhook recreated the branch or renewed its lease")
    github_cli(run,"old-id-after-success",*arguments,str(old_id),succeeds=False)
    require(run.metadata("SELECT count(*) FROM branch;")==str(int(before_count)+1),"Recreation allocated more than one new branch")
    run.record("GitHub CLI recreates a dropped ID only after fresh provider observation; duplicate and reordered deliveries preserve the new ID and lease")

    run.stop("proxy")
    try:
        with fixture.lock:
            fixture.refs.remove(ref)
        post(run,fixture,"push",push(ref,created=False))
        await_binding(run,ref,lambda row:row["state"]=="absent" and row["branch_status"]=="dropping")
        github_cli(run,"cleanup-pending",*arguments,str(new_id),succeeds=False)
        with fixture.lock:
            fixture.refs.add(ref)
        for created in (True,False,True):
            post(run,fixture,"push",push(ref,created=created))
            waiting=await_binding(run,ref,lambda row:row["state"]=="waiting_for_cleanup")
            require(waiting["branch_id"]==new_id and waiting["branch_status"]=="dropping"
                    and run.metadata("SELECT count(*) FROM branch;")==str(int(before_count)+1),
                    "Pending native cleanup changed branch identity or allocated a replacement")
        with fixture.lock:
            fixture.refs.remove(ref)
        post(run,fixture,"push",push(ref,created=False))
        await_binding(run,ref,lambda row:row["state"]=="absent" and row["branch_status"]=="dropping")
    finally:
        run.start_proxy()
    run.wait_dropped(OWNER_A,new_id)
    (run.report / "github-recreate.json").write_text(json.dumps({"old_branch_id":old_id,"new_branch_id":new_id,
        "expired_listed":True,"stale_id_and_nonowner_refused":True,"closed_and_changed_source_refused":True,
        "fresh_provider_observed":True,"duplicate_ttl_unchanged":True,"pending_cleanup_stable":True})+"\n")
    run.record("GitHub CLI refuses recreation during native cleanup and keeps closing/waiting bindings stable until drain recovers")


def pull_cases(run, fixture):
    fixture.pulls["9"] = "open"
    post(run, fixture, "pull_request", pull("opened"))
    first = await_binding(run, "9", lambda row: row["state"] == "present")
    old_id = first["branch_id"]
    branch = branch_detail(run, old_id)
    require(branch["class"] == "ci" and branch["mode"] == "read_only", "GitHub PR did not use sparse ci by default")
    run.stop("proxy")
    fixture.pulls["9"] = "closed"
    post(run, fixture, "pull_request", pull("closed"))
    await_binding(run, "9", lambda row: row["state"] == "absent" and row["branch_status"] == "dropping")
    fixture.pulls["9"] = "open"
    post(run, fixture, "pull_request", pull("reopened"))
    await_binding(run, "9", lambda row: row["state"] == "waiting_for_cleanup")
    run.stop("control")
    run.start_control()
    run.start_proxy()
    reopened = await_binding(run, "9", lambda row: row["state"] == "present" and row["branch_id"] != old_id)
    require(reopened["name"] == first["name"] and branch_detail(run, old_id)["status"] == "dropped",
            "Reopened PR did not wait for cleanup and bind a new ID")
    post(run, fixture, "pull_request", pull("closed"))
    current = await_binding(run, "9", lambda row: row["state"] == "present")
    require(current["branch_id"] == reopened["branch_id"], "Stale PR close changed the reopened binding")
    fixture.pulls["9"] = "closed"
    post(run, fixture, "pull_request", pull("closed"))
    run.wait_dropped(OWNER_A, reopened["branch_id"])
    run.record("GitHub PR reopen resumes after controller restart and waits for native drain")


def writable_pull(run, fixture):
    run.stop("control")
    run.base_env.update(fixture.env(pr_write=True))
    run.start_control()
    fixture.pulls["10"] = "open"
    post(run, fixture, "pull_request", pull("opened", 10))
    bound = await_binding(run, "10", lambda row: row["state"] == "present" and row["branch_status"] == "active")
    branch = branch_detail(run, bound["branch_id"])
    require(branch["class"] == "ci" and branch["mode"] == "native_write", "GitHub pr_write did not provision native CI")
    with Probe(run, "github-pr-write", (OWNER_A, branch["name"])) as probe:
        check_count(probe, "INSERT INTO parents (id,tenant_id,code) VALUES (7110,8,'gh-pr-write')", 1)
    fixture.pulls["10"] = "closed"
    post(run, fixture, "pull_request", pull("closed", 10))
    run.wait_dropped(OWNER_A, branch["id"])
    run.record("GitHub pr_write provisions a native CI branch and supports guarded TLS writes")


def github_cases(run, other_owner):
    with tempfile.TemporaryDirectory(prefix="github-fixture-", dir=run.certs.parent) as directory:
        with MockGitHub(Path(directory)) as fixture:
            settings = fixture.env()
            run.secret["github_webhook"] = fixture.secret
            run.base_env.update(settings)
            try:
                run.stop("control")
                run.start_control()
                ref_cases(run, fixture)
                recreate_cases(run, fixture)
                stored_binding_conflicts(run, fixture, other_owner)
                pull_cases(run, fixture)
                writable_pull(run, fixture)
            finally:
                run.stop("control")
                for key in settings:
                    run.base_env.pop(key, None)
                run.start_control()
