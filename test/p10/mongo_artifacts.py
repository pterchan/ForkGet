#!/usr/bin/env python3
"""Prove private BSON artifacts/replay on unique local disposable services."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

import pymongo
from bson import BSON, Binary, Decimal128, Int64, ObjectId, SON
import base64
from bson.codec_options import CodecOptions
from bson.raw_bson import RawBSONDocument

ROOT=Path(__file__).resolve().parents[2]
BINS=Path(os.environ.get("CARGO_TARGET_DIR",ROOT/"target"))/"debug"

def require(value,label):
    if not value: raise RuntimeError(label)

def command(*arguments,env=None,check=True):
    return subprocess.run([str(argument) for argument in arguments],cwd=ROOT,env=env,
                          text=True,capture_output=True,timeout=360,check=check)

def wait(label,predicate,seconds=40):
    until=time.monotonic()+seconds
    while time.monotonic()<until:
        try:
            value=predicate()
            if value:return value
        except (OSError,pymongo.errors.PyMongoError,urllib.error.URLError):pass
        time.sleep(.1)
    raise RuntimeError("Timed out: "+label)

def main():
    started=datetime.now(timezone.utc)
    report_root=Path(os.environ.get("FG_P10_MONGO_REPORT_ROOT",ROOT/"test/reports"))
    report_dir=report_root/f"{started:%Y%m%d}-p10-mongo-artifacts-{started:%H%M%S}-{os.getpid()}"
    report_dir.mkdir(parents=True)
    suffix=uuid.uuid4().hex[:10]
    containers=["fg-p10-artifact-meta-"+suffix,"fg-p10-artifact-mongo-"+suffix]
    report={"suite":"p10-mongo-artifacts","started_at":started.isoformat(),"source_revision":command("git","rev-parse","HEAD").stdout.strip(),
            "dirty":bool(command("git","status","--porcelain").stdout),"checks":[],"passed":False}
    processes=[]
    temporary=tempfile.TemporaryDirectory(prefix="forkget-p10-mongo-artifact-",dir=Path.home())
    state=Path(temporary.name)
    token=secrets.token_hex(24)
    mongo_password=secrets.token_hex(24)
    try:
        command("docker","run","--detach","--rm","--name",containers[0],"-e","POSTGRES_HOST_AUTH_METHOD=trust","-p","127.0.0.1::5432","postgres:16.14")
        command("docker","run","--detach","--rm","--name",containers[1],"-e","MONGO_INITDB_ROOT_USERNAME=root","-e","MONGO_INITDB_ROOT_PASSWORD="+mongo_password,
                "-p","127.0.0.1::27017","mongo:7.0.48")
        def port(name,native):return command("docker","inspect","--format",'{{(index (index .NetworkSettings.Ports "'+str(native)+'/tcp") 0).HostPort}}',name).stdout.strip()
        pgport=port(containers[0],5432);mongoport=port(containers[1],27017)
        wait("metadata readiness",lambda:command("docker","exec",containers[0],"pg_isready","-U","postgres",check=False).returncode==0)
        native=pymongo.MongoClient(f"mongodb://root:{mongo_password}@127.0.0.1:{mongoport}/admin?directConnection=true",serverSelectionTimeoutMS=500)
        wait("MongoDB readiness",lambda:native.admin.command("ping"))
        for user in ["fg_service","fg_gc"]:native.admin.command("createUser",user,pwd="local-artifact-service",roles=[])
        import socket
        sockets=[]
        for _ in range(3):
            listener=socket.socket();listener.bind(("127.0.0.1",0));sockets.append(listener)
        control_port,proxy_port,internal_port=[listener.getsockname()[1] for listener in sockets]
        for listener in sockets:listener.close()
        base=f"http://127.0.0.1:{control_port}"
        environment={key:value for key,value in os.environ.items() if not key.startswith("FG_")}
        environment.update(FG_META_DSN=f"postgresql://postgres@127.0.0.1:{pgport}/postgres",
            FG_BACKEND_ADMIN_DSN=f"mongodb://root:{mongo_password}@127.0.0.1:{mongoport}/admin",
            FG_BACKEND_GC_DSN=f"mongodb://fg_gc:local-artifact-service@127.0.0.1:{mongoport}/admin",
            FG_BACKEND_SERVICE_USER="fg_service",FG_BACKEND_GC_USER="fg_gc",FG_REFRESH_COOLDOWN_SECONDS="0",
            FG_INTERNAL_TOKEN=secrets.token_hex(24),FG_CONTROL_ACCOUNTS=json.dumps([{"user":"alice","token":token,"expires_at":9999999999,"policy_admin":True}]),
            FG_CONTROL_LISTEN=f"127.0.0.1:{control_port}",FG_PROXY_CONTROL_URL=f"http://127.0.0.1:{internal_port}",
            FG_BACKEND_DSN=f"mongodb://fg_service:local-artifact-service@127.0.0.1:{mongoport}/admin",
            FG_FRONTEND_ACCOUNTS=json.dumps([{"user":"alice","password":"local-artifact-client","expires_at":9999999999}]),
            FG_CONTROL_URL=base,FG_OWNER_TOKEN=token,FG_LISTEN_MONGO=f"127.0.0.1:{proxy_port}",
            FG_PROXY_CONTROL_LISTEN=f"127.0.0.1:{internal_port}",FG_STATE_DIR=str(state/"private-state"))
        def binary(label,executable,*args,check=True):
            result=command(BINS/executable,*args,env=environment,check=False)
            (report_dir/(label+".log")).write_text(result.stdout+result.stderr)
            if check:require(result.returncode==0,label+" failed; see private-free command log")
            return json.loads(result.stdout) if result.returncode==0 and result.stdout else result
        binary("migrate","fg-control","migrate")
        binary("bootstrap","fg-control","bootstrap")
        binary("refresh","fg-control","refresh","--snapshot","v2")
        def start_process(name,args):
            output=open(report_dir/(name+".log"),"w")
            process=subprocess.Popen([str(value) for value in args],cwd=ROOT,env=environment,stdout=output,stderr=subprocess.STDOUT)
            processes.append(process)
            return process
        control_process=start_process("control",[BINS/"fg-control","serve"])
        proxy_process=start_process("proxy",[BINS/"fg-proxy"])
        def metadata(sql):return command("docker","exec",containers[0],"psql","-U","postgres","-At","-c",sql).stdout.strip()
        def http(method,path,body=None):
            request=urllib.request.Request(base+path,method=method,data=json.dumps(body).encode() if body is not None else None,
                headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"})
            with urllib.request.urlopen(request,timeout=10) as response:return json.load(response) if response.status!=204 else True
        wait("control health",lambda:http("GET","/v1/policies/dev"))
        wait("proxy health",lambda:urllib.request.urlopen(f"http://127.0.0.1:{internal_port}/healthz",timeout=1).status==204)
        policy=http("GET","/v1/policies/dev")
        http("PUT","/v1/policies/dev",{"expected_version":policy["version"],"max_transaction_rows":50000,"table_limit_bps":None,"approval_after_rows":None})
        source=binary("fork","forkget","fork","bson-source","--write")
        branch=wait("source active",lambda:next((branch for branch in http("GET","/v1/branches") if branch["name"]=="bson-source" and branch["status"]=="active"),None))
        source_id=branch["id"]
        client=pymongo.MongoClient(f"mongodb://alice:local-artifact-client@127.0.0.1:{proxy_port}/bson-source?authSource=admin&directConnection=true",serverSelectionTimeoutMS=5000)
        collection=client["bson-source"].orders
        for start in range(100,4201,50):
            documents=[SON([("_id",Int64(key)),("i32",key), ("i64",Int64(key)),("price",Decimal128("1.2300")),
                ("time",datetime(2026,11,12,0,0,0,123000,tzinfo=timezone.utc)),("blob",Binary(bytes(range(16)),subtype=4)),
                ("nested",SON([("z",1),("a",Int64(2))])),("note","é雪"*32)]) for key in range(start,min(start+50,4201))]
            collection.insert_many(documents,ordered=True)
        collection.insert_many([{"_id":ObjectId("0123456789abcdef01234567"),"note":"oid"},{"_id":"string-key","note":"string"},
                                {"_id":SON([("part",1),("other",Int64(2))]),"note":"composite BSON"}])
        collection.update_one({"_id":2},{"$set":{"note":"changed"}})
        collection.delete_one({"_id":3})
        client.close()
        path=state/"mongo.ndjson"
        exported=binary("export","forkget","export","--id",str(source_id),"--output",str(path))
        require(exported["complete"] and exported["replayable"] and exported["changes"]>4096 and path.stat().st_size>1024*1024,"BSON complete export inherited SQL legacy limits")
        require(path.stat().st_mode&0o777==0o600,"BSON artifact is not private")
        records=[json.loads(line) for line in path.read_text().splitlines()]
        require(all(record["record"]=="document_change" for record in records[1:-1]),"BSON became SQL rows")
        report["checks"].append("More than 4096 complete BSON changes cross 1MiB, preserve raw types and private mode")
        before=len(http("GET","/v1/branches"))
        binary("preflight","forkget","replay","--engine","mongodb","--input",str(path),"--check")
        require(len(http("GET","/v1/branches"))==before,"Mongo preflight created a target")
        result=binary("replay","forkget","replay","--engine","mongodb","--input",str(path),"--name","bson-target")
        require(result["verified"] and result["transaction"]=="non_transactional","Mongo replay was not explicitly verified without claiming SQL transactions")
        target_id=result["branch_id"]
        for name in ["orders","customers"]:
            def documents(branch):return [bytes(document.raw) for document in native[f"fg_b{branch}"].get_collection(name,codec_options=CodecOptions(document_class=RawBSONDocument)).find().sort("_id",1)]
            require(documents(source_id)==documents(target_id),"Raw BSON native equality differs: "+name)
            left=list(native[f"fg_b{source_id}"][name].list_indexes());right=list(native[f"fg_b{target_id}"][name].list_indexes())
            require(left==right,"Native indexes differ")
        report["checks"].append("Native raw BSON bytes/types/field order/mixed IDs and indexes equal after exclusive replay")
        require(not http("GET",f"/v1/branches/{source_id}/status")["export_in_progress"],"Capture fence remained after completed export")
        report["checks"].append("Capture fence releases and side-effect-free preflight creates no target")

        def fence():return metadata(f"SELECT capture_active FROM branch WHERE id={source_id}")=="t"
        old=pymongo.MongoClient(f"mongodb://alice:local-artifact-client@127.0.0.1:{proxy_port}/bson-source?authSource=admin&directConnection=true",serverSelectionTimeoutMS=500,socketTimeoutMS=500,retryReads=False,retryWrites=False)
        old["bson-source"].orders.find_one({"_id":1})
        # Disconnect the exporting HTTP client after the control-owned task has
        # acquired the durable fence. The server must finish and release it.
        connection=socket.create_connection(("127.0.0.1",control_port))
        connection.sendall(f"GET /v1/branches/{source_id}/export HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n".encode())
        wait("capture fence",fence)
        connection.close()
        request=urllib.request.Request(base+"/internal/v1/resolve",method="POST",data=json.dumps({"principal":"alice","branch":"bson-source"}).encode(),
            headers={"Authorization":"Bearer "+environment["FG_INTERNAL_TOKEN"],"Content-Type":"application/json"})
        try:
            urllib.request.urlopen(request,timeout=2)
            raise RuntimeError("A new named session crossed the capture fence")
        except urllib.error.HTTPError as error:require(error.code in (404,503),"Unexpected capture refusal")
        refused=False
        try:old["bson-source"].orders.insert_one({"_id":"capture-must-refuse"})
        except pymongo.errors.PyMongoError:refused=True
        require(refused,"An existing writer crossed the drained capture fence")
        old.close()
        wait("cancelled HTTP export releases its fence",lambda:not fence(),seconds=60)
        fresh=pymongo.MongoClient(f"mongodb://alice:local-artifact-client@127.0.0.1:{proxy_port}/bson-source?authSource=admin&directConnection=true",serverSelectionTimeoutMS=1000)
        require(fresh["bson-source"].orders.find_one({"_id":1}) is not None,"Fresh pool did not recover after capture")
        fresh.close()
        report["checks"].append("Capture drains connected writers, rejects new named sessions, and survives exporting HTTP client cancellation")
        for component in ("control","proxy"):
            interrupted=state/(component+"-interrupted.ndjson")
            export_process=subprocess.Popen([str(BINS/"forkget"),"export","--id",str(source_id),"--output",str(interrupted)],cwd=ROOT,env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            wait(component+" crash fence",fence)
            process=control_process if component=="control" else proxy_process
            process.kill();process.wait(timeout=10)
            output,error=export_process.communicate(timeout=30)
            (report_dir/(component+"-interrupted.log")).write_text(output+error)
            require(export_process.returncode!=0 and not interrupted.exists(),"Interrupted capture published an incomplete artifact")
            if component=="control":
                require(fence(),"Control crash silently reopened a fenced branch")
                control_process=start_process("control-restart",[BINS/"fg-control","serve"])
                wait("restarted control",lambda:http("GET","/v1/policies/dev"))
            else:
                proxy_process=start_process("proxy-restart",[BINS/"fg-proxy"])
                wait("restarted proxy",lambda:urllib.request.urlopen(f"http://127.0.0.1:{internal_port}/healthz",timeout=1).status==204)
            retry=state/(component+"-retry.ndjson")
            receipt=binary(component+"-retry","forkget","export","--id",str(source_id),"--output",str(retry))
            require(receipt["complete"] and retry.read_bytes()==path.read_bytes() and not fence(),"Restart retry produced a different or fenced artifact")
        report["checks"].append("Control/proxy crashes cannot publish partial artifacts; restart retries drain again and reproduce identical bytes")
        for branch_id in [source_id,target_id]:binary("drop-"+str(branch_id),"forkget","drop","--id",str(branch_id))
        wait("owned seed branches cleaned",lambda:metadata("SELECT count(*) FROM branch WHERE status<>'dropped'")=="0",seconds=60)
        for generation_id in metadata("SELECT id FROM generation WHERE status='retiring'").splitlines():
            binary("retire-"+generation_id,"fg-control","retire","--generation",generation_id)
        wait("retiring seed reclaimed",lambda:metadata("SELECT count(*) FROM generation WHERE status='retiring'")=="0",seconds=60)

        # Real user data, independent of the reviewed SQL/seed table names.
        application=native.native_app
        application.create_collection("invoices",validator={"$jsonSchema":{"bsonType":"object","required":["account"],"properties":{"account":{"bsonType":"string"}}}},validationLevel="strict",validationAction="error")
        application.create_collection("empty_notes")
        application.invoices.create_index([("account",1),("sequence",-1)],unique=True,name="account_sequence")
        application.invoices.insert_many([SON([("_id",ObjectId()),("account","雪"),("sequence",number),("i64",Int64(number)),("decimal",Decimal128("123.4500")),("blob",Binary(bytes(range(16)),subtype=4)),("nested",SON([("z",1),("a",Int64(2))]))]) for number in range(7)])
        environment["FG_SOURCE_DSN"]=environment["FG_BACKEND_ADMIN_DSN"]
        flags=["--source-env","FG_SOURCE_DSN","--schema","native_app","--name","native-mongo","--consistency","frozen_source"]
        native.admin.command({"fsync":1,"lock":True})
        try:
            binary("native-inspect","fg-control","snapshot","inspect",*flags,"--output",str(state/"inspect.json"))
            bundle=state/"bundle"
            binary("native-capture","fg-control","snapshot","capture",*flags,"--output",str(bundle))
        finally:native.admin.command({"fsyncUnlock":1})
        imported=binary("native-import","fg-control","snapshot","import","--input",str(bundle))
        generation=imported["generation_id"]
        bad=state/"bad-bundle";shutil.copytree(bundle,bad)
        manifest=json.loads((bad/"manifest.json").read_text());manifest["document"]["collections"][0]["rows"]+=1
        (bad/"manifest.json").write_text(json.dumps(manifest))
        failure=binary("corrupt-import","fg-control","snapshot","import","--input",str(bad),check=False)
        require(failure.returncode!=0 and metadata("SELECT id FROM generation WHERE status='active'")==str(generation),"Corrupt import replaced active generation")
        binary("native-fork","forkget","fork","native-source","--write")
        imported_source=wait("imported branch active",lambda:next((branch for branch in http("GET","/v1/branches") if branch["name"]=="native-source" and branch["status"]=="active"),None))
        source_database=native[f"fg_b{imported_source['id']}"]
        require(application.invoices.options()==source_database.invoices.options(),"Materialization changed native validator/options")
        require(list(application.invoices.list_indexes())==list(source_database.invoices.list_indexes()),"Materialization changed compound indexes")
        client=pymongo.MongoClient(f"mongodb://alice:local-artifact-client@127.0.0.1:{proxy_port}/native-source?authSource=admin&directConnection=true",serverSelectionTimeoutMS=5000)
        client["native-source"].invoices.insert_one({"_id":ObjectId(),"account":"new","sequence":100,"decimal":Decimal128("9.9900")})
        client["native-source"].invoices.update_one({"sequence":0},{"$set":{"decimal":Decimal128("7.7700")}})
        client["native-source"].empty_notes.insert_one({"_id":"first","note":"empty collection survives"})
        client.close()
        path=state/"native.ndjson"
        binary("native-export","forkget","export","--id",str(imported_source["id"]),"--output",str(path))
        result=binary("native-replay","forkget","replay","--engine","mongodb","--input",str(path),"--name","native-target")
        require(result["verified"],"Imported BSON artifact did not replay")
        target_database=native[f"fg_b{result['branch_id']}"]
        for name in ["invoices","empty_notes"]:
            raw=lambda database:[document.raw for document in database.get_collection(name,codec_options=CodecOptions(document_class=RawBSONDocument)).find().sort("_id",1)]
            require(raw(source_database)==raw(target_database),"Imported BSON replay changed native bytes")
            require(source_database[name].options()==target_database[name].options() and list(source_database[name].list_indexes())==list(target_database[name].list_indexes()),"Imported replay changed native options/indexes")
        report["checks"].append("Frozen genuine mongodump import, generic collections, validators/compound indexes/empty collection survive native fork→typed artifact→verified replay")
        retained=[]
        policy=http("GET","/v1/policies/dev")
        http("PUT","/v1/policies/dev",{"expected_version":policy["version"],"max_transaction_rows":1,"table_limit_bps":None,"approval_after_rows":None})
        refused=binary("policy-admission-refused","forkget","replay","--engine","mongodb","--input",str(path),"--name","policy-target",check=False)
        refused=json.loads(refused.stdout)
        require(not refused["verified"] and refused["transaction"]=="not_started" and refused["result"]["applied"]==0 and refused["failure"]["code"]=="FG-5002","Mongo replay applied work before the complete policy budget was admitted")
        retained.append(refused["branch_id"])
        require(native[f"fg_b{refused['branch_id']}"].empty_notes.count_documents({})==0,"Admission failure left a partial native write")
        policy=http("GET","/v1/policies/dev")
        http("PUT","/v1/policies/dev",{"expected_version":policy["version"],"max_transaction_rows":50000,"table_limit_bps":None,"approval_after_rows":None})
        records=[json.loads(line) for line in path.read_text().splitlines()]
        invoices=next(table["id"] for table in records[0]["value"]["tables"] if table["table"]=="invoices")
        change=next(record["value"] for record in records if record["record"]=="document_change" and record["value"]["collection_id"]==invoices and record["value"]["operation"]=="insert")
        image=BSON(base64.b64decode(change["after_bson"])).decode()
        image["account"]="雪";image["sequence"]=1
        change["after_bson"]=base64.b64encode(BSON.encode(image)).decode()
        conflict=state/"native-conflict.ndjson"
        conflict.write_text("".join(json.dumps(record)+"\n" for record in records))
        failed=binary("constraint-partial","forkget","replay","--engine","mongodb","--input",str(conflict),"--name","partial-target",check=False)
        failed=json.loads(failed.stdout)
        require(not failed["verified"] and failed["transaction"]=="partial" and failed["result"]["applied"]>0,"Native unique constraint did not retain an explicit non-transactional partial result")
        retained.append(failed["branch_id"])
        require(http("GET",f"/v1/replays/{failed['job_id']}")["state"]=="unknown","Partial Mongo target was not quarantined")
        request=urllib.request.Request(base+"/internal/v1/resolve",method="POST",data=json.dumps({"principal":"alice","branch":"partial-target"}).encode(),headers={"Authorization":"Bearer "+environment["FG_INTERNAL_TOKEN"],"Content-Type":"application/json"})
        try:urllib.request.urlopen(request,timeout=2);raise RuntimeError("An unverified replay target accepted ordinary named sessions")
        except urllib.error.HTTPError as error:require(error.code==404,"Unexpected quarantine refusal")
        observed_before=[document.raw for document in native[f"fg_b{failed['branch_id']}"].get_collection("invoices",codec_options=CodecOptions(document_class=RawBSONDocument)).find().sort("_id",1)]
        verified=binary("partial-verify-only","forkget","replay","--engine","mongodb","--verify-job",str(failed["job_id"]),check=False)
        verified=json.loads(verified.stdout)
        require(not verified["verified"] and verified["result"]["applied"] is False,"Unknown Mongo recovery attempted to apply the plan")
        observed_after=[document.raw for document in native[f"fg_b{failed['branch_id']}"].get_collection("invoices",codec_options=CodecOptions(document_class=RawBSONDocument)).find().sort("_id",1)]
        require(observed_before==observed_after,"Verification mutated a partial native target")
        try:http("POST",f"/v1/replays/{failed['job_id']}/apply");raise RuntimeError("A partial Mongo job could reapply")
        except urllib.error.HTTPError as error:require(error.code==409,"Unknown Mongo apply returned an unexpected status")
        report["checks"].append("Complete policy admission precedes Mongo writes; native constraint partial results stay private and verify-only never reapply or claim rollback")
        for branch_id in [imported_source["id"],result["branch_id"],*retained]:binary("drop-native-"+str(branch_id),"forkget","drop","--id",str(branch_id))
        report["engine_version"]=native.server_info()["version"]
        native.close()
        report["passed"]=True
    except Exception as error:
        report["failure"]=str(error)
        raise
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        for name in containers:command("docker","rm","--force",name,check=False)
        report["cleanup_verified"]=all(command("docker","inspect",name,check=False).returncode!=0 for name in containers)
        temporary.cleanup()
        (report_dir/"report.json").write_text(json.dumps(report,indent=2)+"\n")
        print(json.dumps(report))

if __name__=="__main__":main()
