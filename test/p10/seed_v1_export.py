#!/usr/bin/env python3
"""Save seed-v1 results independently of native-copy replay availability."""
import json
from urllib.error import HTTPError
from urllib.request import Request,urlopen
from artifacts import EngineRun as ArtifactRun, artifact, p6
from run_p2 import OWNER_A,require

class EngineRun(ArtifactRun):
    def execute(self):
        self.start_deployment()
        readonly=self.cli(OWNER_A,"fork","v1-readonly")
        generation=self.active()
        legacy_id=int(self.metadata(f"INSERT INTO branch (name,class,generation_id,created_by,status,expires_at,mode,read_strategy) VALUES ('v1-legacy','dev',{generation},'{OWNER_A}','active',now()+INTERVAL '1 hour','read_only','merge') RETURNING id;"))
        legacy={"id":legacy_id,"name":"v1-legacy","generation_id":generation}
        binding=self.binding(OWNER_A,legacy)
        table=next(table for table in binding["tables"] if table["logical_table"]=="orders")
        quote='"' if self.family=='postgresql' else '`'
        relation=f"{quote}{table['delta_schema']}{quote}.{quote}{table['delta_table']}{quote}"
        binary="decode('00ff','hex')" if self.family=='postgresql' else "X'00ff'"
        self.native(f"INSERT INTO {relation} (_fg_branch,_fg_op,tenant_id,id,customer_id,amount,note,payload) VALUES ({legacy_id},'I',99,9901,10,12.34,'v1-preserved',{binary});")
        for branch,expected in [(readonly,0),(legacy,1)]:
            path=self.certs.parent/(branch["name"]+".ndjson")
            receipt=self.artifact_cli(branch["name"]+"-save","export","--id",str(branch["id"]),"--output",str(path))
            records,changes=artifact(path)
            require(receipt["complete"] and receipt["changes"]==expected and not receipt["replayable"] and "source_snapshot_not_writable" in receipt["replay_reasons"],"Seed v1 cannot save a complete explicitly unreplayable artifact")
            require(records[0]["value"]["origin"]["snapshot"]=="v1","Seed v1 provenance changed")
            if expected:
                require(changes[0]["key"]==["99","9901"] and changes[0]["after"][-2:]==["v1-preserved","00ff"],"Legacy v1 delta lost its exact typed values")
            before=self.metadata("SELECT count(*) FROM branch;")+"/"+self.metadata("SELECT count(*) FROM replay_job;")
            self.artifact_cli(branch["name"]+"-check","replay","--engine",self.engine,"--input",str(path),"--check",succeeds=False)
            request=Request(self.control_url+"/v1/replays",method="POST",data=path.read_bytes(),headers={"Authorization":"Bearer "+self.owner_tokens[OWNER_A],"Content-Type":"application/x-ndjson","x-forkget-replay-name":"v1-denied-target"})
            try:urlopen(request,timeout=10);raise RuntimeError("Seed v1 native replay was admitted")
            except HTTPError as error:require(error.code>=400,"Unexpected replay response")
            after=self.metadata("SELECT count(*) FROM branch;")+"/"+self.metadata("SELECT count(*) FROM replay_job;")
            require(before==after,"Unavailable v1 replay created a branch or job")
            self.drop(OWNER_A,branch["id"])
        self.record("Actual seed-v1 RO and populated legacy merge results save complete typed artifacts; explicit replay refusal creates no target/job")

if __name__=="__main__":
    raise SystemExit(p6.run_profile("p10-v1-export","P10 seed-v1 save/replay separation",EngineRun))
