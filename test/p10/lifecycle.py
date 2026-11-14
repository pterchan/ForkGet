"""Verify live SQL sessions, lease renewal and independent credential deadlines."""

import importlib.util
from pathlib import Path
import time

SUITE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("live_lease_p6",SUITE.parent/"p6/run.py")
p6=importlib.util.module_from_spec(spec)
spec.loader.exec_module(p6)
from run_p2 import OWNER_A, require
from write_cases import Probe, begin, check_count


class EngineRun(p6.p5.p34.EngineRun):
    def execute(self):
        self.start_deployment()
        previous,_,_=self.refresh_to_v2()
        self.drop(OWNER_A,previous["id"])
        self.live_renewal()
        self.credential_deadline()

    def live_renewal(self):
        branch=self.cli(OWNER_A,"fork","renew-live-session","--ttl-seconds","5")
        status=self.cli(OWNER_A,"status","--id",str(branch["id"]))
        original=status["expires_at"]
        with Probe(self,"renew-live",(OWNER_A,branch["name"])) as probe:
            require(probe.sql("SELECT 1","read").get("rows")==[[1]],"Initial read failed")
            renewed=self.cli(OWNER_A,"renew","--id",str(branch["id"]),"--ttl-seconds","12",
                             "--expected-lease-version",str(status["lease_version"]))
            require(renewed["expires_at"]>original and renewed["lease_version"]==2,"Lease did not advance")
            time.sleep(max(0,original-time.time()+0.1))
            require(probe.sql("SELECT 1","read").get("rows")==[[1]],
                    "An existing native session did not inherit renewal beyond its original deadline")
            time.sleep(max(0,renewed["expires_at"]-time.time()+0.1))
            refusal=probe.sql("SELECT 1","read")
            require(refusal.get("fg")=="FG-2003" or "transport" in refusal,"Renewal bypassed its final deadline")
        p6.p5.wait_until("renewed branch TTL cleanup",lambda:self.branch_status(branch)=="dropped",seconds=90)
        self.record("Lease renewal reaches the same native session beyond its old deadline and its new deadline still closes access")

    def credential_deadline(self):
        branch=self.cli(OWNER_A,"fork","renew-credential-bound","--write","--ttl-seconds","30")
        p6.p5.wait_until("credential branch activation",lambda:self.branch_status(branch)=="active")
        old_expiry=self.expires
        self.stop("proxy")
        deadline=int(time.time())+6
        try:
            self.expires=deadline
            self.start_proxy()
            with Probe(self,"renew-short-credential",(OWNER_A,branch["name"])) as probe:
                begin(probe,self.engine,"READ COMMITTED")
                check_count(probe,"INSERT INTO customers(id,name) VALUES(970001,'lease-credential')",1)
                status=self.cli(OWNER_A,"status","--id",str(branch["id"]))
                self.cli(OWNER_A,"renew","--id",str(branch["id"]),"--ttl-seconds","3600",
                         "--expected-lease-version",str(status["lease_version"]))
                time.sleep(max(0,deadline-time.time()+0.1))
                refusal=probe.sql("COMMIT")
                require(refusal.get("fg")=="FG-1002" or "transport" in refusal,
                        "Renewal extended an independent frontend credential")
        finally:
            self.expires=old_expiry
            self.stop("proxy")
            self.start_proxy()
        with Probe(self,"renew-credential-rollback",(OWNER_A,branch["name"])) as probe:
            require(probe.sql("SELECT id FROM customers WHERE id=970001","read").get("rows")==[],
                    "Credential expiry committed its open native transaction")
        self.drop(OWNER_A,branch["id"])
        self.record("Renewal keeps credential expiration independent and rolls back native work after credential expiry")


if __name__=="__main__":
    raise SystemExit(p6.run_profile("p10lifecycle","P10 live lease and credential recovery",EngineRun))
