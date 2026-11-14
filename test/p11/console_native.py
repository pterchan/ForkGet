#!/usr/bin/env python3
"""Exercise packaged console routes and real browser journeys on owned engines."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("console_p6", ROOT / "test/p6/run.py")
p6 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p6)
from run_p2 import OWNER_A, OWNER_B, json_file, require
from write_cases import Probe, check_count


def windows_path(path):
    path = str(Path(path).resolve())
    require(path.startswith("/mnt/") and path[6:7] == "/", "Windows Node requires a mounted drive path")
    return path[5].upper() + ":" + path[6:].replace("/", "\\")



def cross_host_control_port(node):
    """Ask Windows to select a nonexcluded port, then check the Linux bind."""
    if not node or not str(node).endswith('.exe'):
        return None
    script = "const net=require('node:net'); const server=net.createServer(); server.listen(0,'127.0.0.1',()=>{process.stdout.write(String(server.address().port));server.close();});"
    for _ in range(10):
        candidate = int(subprocess.check_output([str(node), '-e', script], text=True, timeout=10))
        with socket.socket() as listener:
            try:
                listener.bind(('127.0.0.1', candidate))
            except OSError:
                continue
        return candidate
    raise ValueError('No shared Windows/WSL control port was available')


def browser(runner, branch, node):
    directory = ROOT / "target"
    directory.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="console-native-", dir=directory) as temporary:
        private = Path(temporary) / "live.json"
        config = {
            "engine": runner.engine, "control_url": runner.control_url,
            "owner_token": runner.owner_tokens[OWNER_A], "reviewer_token": runner.owner_tokens[OWNER_B],
            "branch_id": branch["id"], "proxy_port": runner.proxy_port,
            "database_username": OWNER_A, "database_password": runner.frontend_passwords[OWNER_A],
            "ca_file": str(runner.certs / "frontend-ca.pem"),
            "driver_binary": str(runner.executable("fg-write-probe")), "driver_python": sys.executable,
        }
        private.write_text(json.dumps(config), encoding="utf-8")
        private.chmod(0o600)
        report = runner.report / "browser-results.json"
        executable = str(node or shutil.which("node") or "")
        require(executable, "Install Node.js or supply --node-executable")
        cli = ROOT / "apps/console/node_modules/@playwright/test/cli.js"
        environment = os.environ.copy()
        environment.update(FG_CONSOLE_LIVE_FILE=str(private), FG_CONSOLE_LIVE_URL=runner.control_url,
                           FG_CONSOLE_BROWSER_REPORT=str(report))
        if executable.endswith(".exe"):
            environment["FG_CONSOLE_LIVE_FILE"] = windows_path(private)
            environment["FG_CONSOLE_BROWSER_REPORT"] = windows_path(report)
            environment["WSLENV"] = ":".join(filter(None, (environment.get("WSLENV"),
                "FG_CONSOLE_LIVE_FILE", "FG_CONSOLE_LIVE_URL", "FG_CONSOLE_BROWSER_REPORT")))
            cli = windows_path(cli)
        result = subprocess.run([executable, str(cli), "test", "--config", "playwright.native.config.ts"],
                                cwd=ROOT / "apps/console", env=environment, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240)
        (runner.report / "browser.log").write_text(runner.safe(result.stdout), encoding="utf-8")
        require(result.returncode == 0, "Native browser journeys failed; inspect the safe browser report")
        summary = json.loads(report.read_text())
        require(summary["stats"]["expected"] == 2 and summary["stats"]["skipped"] == 0
                and summary["stats"]["unexpected"] == 0, "Native browser cases must both execute and pass")
        runner.record("Packaged browser lifecycle, typed diff, TLS commands, policy and independent pending-write review pass without skipped cases")


class ConsoleRun(p6.p5.EngineRun):
    node = None

    def execute(self):
        shared_port = cross_host_control_port(self.node)
        if shared_port is not None:
            self.control_port = shared_port
            self.control_url = f"http://127.0.0.1:{shared_port}"
            json_file(self.report / "safe-endpoint-ports.json", {
                "host": "127.0.0.1", "control_port": self.control_port,
                "proxy_port": self.proxy_port, "proxy_control_port": self.drain_port,
                "allocation": "Windows-selected nonexcluded port, Linux bind checked"})
        self.base_env["FG_CONSOLE_DIR"] = str(ROOT / "apps/console/build")
        self.start_deployment()
        old, _, _ = self.refresh_to_v2()
        self.drop(OWNER_A, old["id"])
        self.set_policy("dev", 50000)
        status, body = self.request("GET", "/", None)
        require(status == 200 and b"content-security-policy" in body.lower(), "Controller must serve the built CSP-protected console")
        status, body = self.request("GET", "/api/v1/branches", self.owner_tokens[OWNER_A])
        require(status == 200 and isinstance(json.loads(body), list), "Public same-origin API alias failed")
        require(self.request("GET", "/api/v1/branches", "invalid")[0] == 401, "Console alias bypassed owner authentication")
        for path in ("/api/internal/v1/resolve", "/api/internal/v1/proxy/start", "/api/internal/v1/replays/1/bind"):
            require(self.request("POST", path, self.secret["internal"], {})[0] == 404,
                    "Console alias exposed an internal route")
        for path in ("/.env", "/crates/fg-control/src/main.rs", "/missing.js.map"):
            require(self.request("GET", path, None)[0] == 404, "Static delivery exposed unbundled source or private files")
        self.record("Packaged static assets and public alias preserve authentication and refuse internal/source paths")
        readonly, credentials = self.create("console-readonly", write=False)
        with Probe(self, "console-readonly", credentials) as probe:
            p6.p5.fg(probe.sql("UPDATE app.orders SET note='must-not-commit' WHERE tenant_id=1 AND id=1"), "FG-5001")
        branch, credentials = self.create("console-live")
        with Probe(self, "console-changes", credentials) as probe:
            check_count(probe, "UPDATE app.orders SET note='console-verified' WHERE tenant_id=1 AND id=1", 1)
        status, body = self.request("GET", f"/api/v1/branches/{branch['id']}/status", self.owner_tokens[OWNER_A])
        observed = json.loads(body)
        require(status == 200 and observed["access"] == "read_write" and observed["layout"] == "native_copy"
                and not observed["expired"] and observed["lease_version"] == 1, "Console status lost independent access/layout/lease fields")
        browser(self, branch, self.node)
        self.drop(OWNER_A, branch["id"])
        self.drop(OWNER_A, readonly["id"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("mysql", "postgresql", "tidb", "mongodb", "all"), default="all")
    parser.add_argument("--node-executable", type=Path)
    parser.add_argument("--report-dir", required=True, type=Path)
    options = parser.parse_args()
    node = str(options.node_executable or shutil.which("node") or "")
    require(node, "Install Node.js or supply --node-executable")
    if node.endswith(".exe"):
        for label, path in (("--report-dir", options.report_dir), ("checkout", ROOT)):
            try:
                windows_path(path)
            except RuntimeError:
                parser.error(f"Windows Node requires {label} under /mnt/<drive>/; use a Windows-mounted report directory")
    options.report_dir.mkdir(parents=True, exist_ok=True)
    os.environ["FG_P11_CONSOLE_REPORT_ROOT"] = str(options.report_dir.resolve())
    ConsoleRun.node = options.node_executable
    engines = ("mysql", "postgresql", "tidb", "mongodb") if options.engine == "all" else (options.engine,)
    results = []
    for engine in engines:
        if engine == "mongodb":
            import console_mongo
            code = console_mongo.run(options.report_dir, options.node_executable, browser, cross_host_control_port)
        else:
            code = p6.run_profile("p11-console", "Packaged console native acceptance", ConsoleRun, [engine])
        results.append({"engine": engine, "exit_code": code})
    json_file(options.report_dir / "exits.json", results)
    return int(any(result["exit_code"] for result in results))


if __name__ == "__main__":
    raise SystemExit(main())
