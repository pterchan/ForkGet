"""Loopback fault relays for the disposable P6 acceptance deployments."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.client import HTTPConnection
from contextlib import closing
import select
import re
import socket
import ssl
import struct
from threading import Event, Lock, Thread
from urllib.parse import urlsplit

from run_p2 import require


class ControlRelay:
    """Apply a fault only after the real authenticated control reply arrives."""

    def __init__(self, run, fault):
        self.run = run
        self.fault = fault
        self.errors = []
        relay = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                relay.forward(self)

            def do_POST(self):
                relay.forward(self)

            def do_DELETE(self):
                relay.forward(self)

            def log_message(self, *_):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, error, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        if error is None:
            require(not self.errors, "The test control relay could not apply its fault")

    def forward(self, handler):
        phase = "request_body"
        try:
            request = self.request_body(handler)
            origin = urlsplit(self.run.control_url)
            headers = {key:value for key,value in handler.headers.items()
                       if key.lower() not in {"host","content-length","transfer-encoding","connection"}}
            headers["Content-Length"] = str(len(request))
            phase = "upstream_response"
            with closing(HTTPConnection(origin.hostname,origin.port,timeout=350)) as connection:
                connection.request(handler.command,handler.path,body=request,headers=headers)
                response=connection.getresponse()
                status,body=response.status,response.read()
                content_type=response.getheader("Content-Type","application/json")
            if self.fault(handler.command, handler.path, status, body):
                phase = "injected_disconnect"
                handler.close_connection = True
                handler.connection.shutdown(socket.SHUT_RDWR)
                return
            phase = "downstream_response"
            handler.send_response(status)
            handler.send_header("Content-Type", content_type)
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)
        except (OSError, ValueError, RuntimeError) as error:
            self.errors.append({"kind": type(error).__name__, "phase": phase,
                                "method": handler.command, "path": handler.path.split("?", 1)[0]})
            handler.close_connection = True

    @staticmethod
    def request_body(handler):
        # This fault fixture forwards one small artifact without interpreting
        # NDJSON as a JSON API object. The product's complete export has separate
        # native large-artifact coverage; this relay remains bounded to 8 MiB.
        limit=8*1024*1024
        if handler.headers.get("Transfer-Encoding","").lower()=="chunked":
            result=bytearray()
            while True:
                line=handler.rfile.readline(4096)
                length=int(line.split(b";",1)[0].strip(),16)
                if length==0:
                    while handler.rfile.readline(4096) not in (b"\r\n",b"\n",b""):
                        pass
                    return bytes(result)
                if length<0 or len(result)+length>limit:
                    raise ValueError("Unexpected test HTTP body length")
                result.extend(read_exact(handler.rfile,length))
                if read_exact(handler.rfile,2)!=b"\r\n":raise ValueError("Invalid test HTTP chunk")
        length=int(handler.headers.get("Content-Length","0"))
        if not 0<=length<=limit:raise ValueError("Unexpected test HTTP body length")
        return read_exact(handler.rfile,length)


class CommitReply:
    """Withhold the reply to an exact COMMIT over two verified test TLS legs."""

    def __init__(self, run, native=False):
        self.run = run
        self.native=native
        self.target_port=run.native_port if native else run.proxy_port
        self.commit = Event()
        self.withheld = Event()
        self.done = Event()
        self.drop_reply = Event()
        self.commits = 0
        self.mutations = 0
        self.witness_mutations = 0
        self.errors = []
        self.lock=Lock()
        self.handlers=[]
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
        self.thread = Thread(target=self.relay, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, error, *_):
        self.disconnect()
        if error is None:
            require(not self.errors, "The test SQL relay could not apply its fault")

    def disconnect(self):
        self.done.set()
        self.listener.close()
        self.thread.join(timeout=6)
        for thread in self.handlers:thread.join(timeout=6)

    def lose_commit_reply(self):
        self.drop_reply.set()

    def relay(self):
        while not self.done.is_set():
            try:
                downstream,_=self.listener.accept()
            except socket.timeout:continue
            except OSError:break
            thread=Thread(target=self.connection,args=(downstream,),daemon=True)
            self.handlers.append(thread)
            thread.start()

    def connection(self,downstream):
        try:
            with downstream, socket.create_connection(("127.0.0.1", self.target_port), timeout=5) as upstream:
                downstream.settimeout(5)
                self.start_tls(downstream, upstream)
                client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                certificate="native" if self.native else "frontend"
                authority="backend" if self.native else "frontend"
                client_context.load_cert_chain(self.run.certs / (certificate+".pem"), self.run.certs / (certificate+".key"))
                server_context = ssl.create_default_context(cafile=self.run.certs / (authority+"-ca.pem"))
                with server_context.wrap_socket(upstream, server_hostname="localhost") as server:
                    with client_context.wrap_socket(downstream, server_side=True) as client:
                        self.forward(client, server)
        except (OSError, ValueError) as error:
            if not self.done.is_set():
                self.errors.append(type(error).__name__)

    def start_tls(self, client, server):
        if self.run.family != "postgresql":
            client.sendall(mysql_packet(server))
            server.sendall(mysql_packet(client))
        else:
            request = read_exact(client, 8)
            if request != struct.pack("!II", 8, 80877103):
                raise ValueError("Unexpected PostgreSQL TLS request")
            server.sendall(request)
            response = read_exact(server, 1)
            if response != b"S":
                raise ValueError("PostgreSQL TLS was not accepted")
            client.sendall(response)

    def forward(self, client, server):
        parser=CommandFrames(self.run.family)
        withholding=False
        while not self.done.is_set():
            if withholding and self.drop_reply.is_set():return
            readable = [stream for stream in (client, server) if stream.pending()]
            if not readable:
                readable, _, _ = select.select([client, server], [], [], 0.05)
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                if source is client:
                    commits,mutations,witnesses=parser.scan(data)
                    with self.lock:
                        self.commits+=commits;self.mutations+=mutations
                        self.witness_mutations+=witnesses
                    if commits:
                        withholding=True
                        self.commit.set()
                    server.sendall(data)
                elif withholding:
                    self.withheld.set()
                else:
                    client.sendall(data)


class CommandFrames:
    """Count submitted executions, never Parse/Bind or SQL literal substrings."""
    def __init__(self,family):
        self.family=family
        self.outbound=bytearray()
        self.pg_startup=family=="postgresql"
        self.statements={}
        self.portals={}

    def scan(self, data):
        commits=mutations=witnesses=0
        self.outbound.extend(data)
        while self.outbound:
            packet = (self.mysql_command() if self.family != "postgresql"
                      else self.postgres_command())
            if packet is None:
                break
            size, sql = packet
            del self.outbound[:size]
            if sql==b"COMMIT":commits+=1
            kind=mutation_kind(sql,self.family)
            if kind=="business":mutations+=1
            if kind=="witness":witnesses+=1
        if len(self.outbound) > 1024 * 1024:
            raise ValueError("The test relay saw an oversized protocol frame")
        return commits,mutations,witnesses

    def mysql_command(self):
        if len(self.outbound) < 4:
            return None
        size = 4 + int.from_bytes(self.outbound[:3], "little")
        if len(self.outbound) < size:
            return None
        sql=bytes(self.outbound[5:size]) if size>4 and self.outbound[3]==0 and self.outbound[4]==3 else None
        return size,sql

    def postgres_command(self):
        start = 0 if self.pg_startup else 1
        if len(self.outbound) < start + 4:
            return None
        size = start + int.from_bytes(self.outbound[start:start + 4], "big")
        if size < start + 4:
            raise ValueError("Invalid PostgreSQL frame size")
        if len(self.outbound) < size:
            return None
        sql=None
        if not self.pg_startup:
            tag,body=self.outbound[0],bytes(self.outbound[5:size])
            if tag==ord("Q"):
                sql=body[:-1]
                self.statements.pop(b"",None)
                self.portals.pop(b"",None)
            elif tag==ord("P"):
                name,statement,_=pg_strings(body,2)
                self.statements[name]=statement
            elif tag==ord("B"):
                portal,statement,_=pg_strings(body,2)
                self.portals[portal]=(self.statements.get(statement),False)
            elif tag==ord("E"):
                portal,_=pg_strings(body,1)
                sql,executed=self.portals.get(portal,(None,False))
                self.portals[portal]=(sql,True)
                if executed:sql=None
            elif tag==ord("C"):
                name,_=pg_strings(body[1:],1)
                if body[:1]==b"P":self.portals.pop(name,None)
                elif body[:1]==b"S":self.statements.pop(name,None)
        self.pg_startup = False
        return size,sql


WITNESS_COLUMNS=(b" (format_version, deployment_id, branch_id, generation_id, "
                 b"storage_incarnation, attempt_id, native_session) VALUES (")
MYSQL_WITNESS=re.compile(rb"INSERT INTO (?:`fgwrite`\.`fg_b[1-9][0-9]*__fg_txn_witness`|"
                         rb"`fg_b[1-9][0-9]*`\.`_fg_txn_witness`)")
POSTGRES_WITNESS=re.compile(rb'INSERT INTO "fg_b[1-9][0-9]*"\."_fg_txn_witness"')


def mutation_kind(sql,family):
    if sql is None or not sql.startswith((b"INSERT ",b"UPDATE ",b"DELETE ")):
        return None
    # These are the exact WriteTarget + witness_insert_sql shapes. A marker in
    # an application value or a similarly named business relation stays business.
    match=(POSTGRES_WITNESS if family=="postgresql" else MYSQL_WITNESS).match(sql)
    if match is not None and sql[match.end():].startswith(WITNESS_COLUMNS):
        return "witness"
    return "business"


def pg_strings(body,count):
    fields=body.split(b"\0",count)
    if len(fields)!=count+1:
        raise ValueError("Invalid PostgreSQL test relay string")
    return fields


def read_exact(stream, size):
    buffer = bytearray()
    while len(buffer) < size:
        data = stream.recv(size - len(buffer)) if hasattr(stream,"recv") else stream.read(size-len(buffer))
        if not data:
            raise OSError("Unexpected test relay EOF")
        buffer.extend(data)
    return bytes(buffer)


def mysql_packet(stream):
    header = read_exact(stream, 4)
    return header + read_exact(stream, int.from_bytes(header[:3], "little"))
