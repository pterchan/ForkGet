#!/usr/bin/env python3
"""Run the historical replay shapes against complete V2 artifacts."""
from artifacts import EngineRun as ArtifactRun, p6
from run_p2 import OWNER_A

class EngineRun(ArtifactRun):
    def execute(self):
        from replay import replay_cases
        self.start_deployment()
        old,_,_=self.refresh_to_v2()
        self.drop(OWNER_A,old["id"])
        self.set_policy("dev",50000)
        replay_cases(self)

if __name__=="__main__":
    raise SystemExit(p6.run_profile("p10-replay-regression","P10 historical replay compatibility",EngineRun))
