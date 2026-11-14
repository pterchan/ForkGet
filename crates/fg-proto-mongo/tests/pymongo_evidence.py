#!/usr/bin/env python3
"""A real pymongo driver connects through the fg-proto-mongo
spike proxy (hello + SCRAM-SHA-256 termination + command passthrough) and
exercises insert/find/drop. Requires the spike mongod container and the
proxy listening on 127.0.0.1:28017; the integration test starts that proxy,
so run the Rust integration test first (or together via cargo test).

Usage: python3 pymongo_evidence.py [proxy_port]
Exits nonzero when any step fails.
"""
import sys

try:
    import pymongo
except ImportError:
    print("pymongo is not installed; evidence skipped")
    sys.exit(3)

PROXY_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 28017
URI = f"mongodb://alice:spike-alice-pw@127.0.0.1:{PROXY_PORT}/?authSource=admin&directConnection=true"


def main() -> int:
    client = pymongo.MongoClient(URI, serverSelectionTimeoutMS=5000)
    hello = client.admin.command("hello")
    assert hello["ok"] == 1, f"hello failed: {hello}"
    assert not hello.get("isWritablePrimary") is None, "hello missing topology role"
    wire = hello.get("maxWireVersion")
    assert wire is not None and wire >= 13, f"unexpected wire version {wire}"
    print(f"hello ok: wire={wire}, standalone={hello.get('msg') is None}")

    db = client["spike"]
    db.orders.drop()
    result = db.orders.insert_one({"_id": 1, "tenant_id": 1, "amount": 10.50})
    print(f"insert: _id={result.inserted_id}")
    doc = db.orders.find_one({"_id": 1})
    assert doc is not None and doc["amount"] == 10.50, f"find failed: {doc}"
    docs = list(db.orders.find({}).sort("_id", 1))
    assert len(docs) == 1, f"unexpected document count {len(docs)}"
    db.orders.drop()
    print("insert/find/drop through the spike proxy: OK (real pymongo driver)")
    client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
