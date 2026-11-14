#!/usr/bin/env python3
"""Real PyMongo driver checks against the isolated fixture proxy.

The fixture serves the spike frontend (SCRAM-SHA-256 termination, standalone
topology, mirror account) over plaintext on loopback; the probe proves the
wire path with the same assertions a driver makes against mongod.
"""
import os
import sys

import pymongo
from pymongo.errors import DuplicateKeyError

HOST = "localhost"
USER = "p1_user"
BRANCH = "p1-fixture"
PASSWORD = os.environ["FG_P1_FRONTEND_PASSWORD"]

ITEMS = [
    {"_id": 1, "payload": None},
    {"_id": 2, "payload": {"$binary": {"base64": "", "subType": "00"}}},
    {"_id": 3, "payload": {"$binary": {"base64": "AP9B", "subType": "00"}}},
]


def check(condition, case):
    if not condition:
        raise AssertionError(case)
    print(f"case {case} PASS")


def reject(operation, marker, case):
    try:
        operation()
    except Exception as error:
        if marker is not None and marker not in str(error):
            raise AssertionError(f"{case}: wrong error: {error}") from error
        check(True, case)
    else:
        raise AssertionError(f"{case}: expected a rejection")


def main() -> int:
    uri = (
        f"mongodb://{USER}:{PASSWORD}@{HOST}:28017/{BRANCH}"
        "?authSource=admin&directConnection=true"
    )
    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000)
    db = client[BRANCH]

    hello = client.admin.command("hello")
    check(hello.get("maxWireVersion", 0) >= 21, "mongo_driver_auth")
    check(hello.get("setName") is None, "standalone topology (no setName)")
    check(hello.get("msg") is None, "standalone topology (no msg)")

    seeded = list(db.fixture_items.find().sort("_id", 1))
    check(
        [document["_id"] for document in seeded] == [1, 2, 3],
        "init-seeded fixture documents are visible",
    )

    db.probe_items.insert_many(ITEMS)
    check(db.probe_items.count_documents({}) == 3, "mongo_insert_find_roundtrip")

    documents = list(db.probe_items.find().sort("_id", 1))
    check(
        [document["_id"] for document in documents] == [1, 2, 3],
        "mongo_insert_find_roundtrip",
    )

    db.probe_items.update_one({"_id": 2}, {"$set": {"payload": "changed"}})
    check(db.probe_items.find_one({"_id": 2})["payload"] == "changed", "mongo_update_applies")

    db.probe_items.delete_one({"_id": 3})
    check(db.probe_items.count_documents({}) == 2, "mongo_delete_applies")

    try:
        db.probe_items.insert_one({"_id": 1})
    except DuplicateKeyError:
        check(True, "mongo_duplicate_key_refused")
    else:
        raise AssertionError("duplicate _id was admitted")

    # $out is a native aggregation write: the standalone fixture passes it through
    # (no control plane), so the branch-side FG-2002 refusal is covered by
    # test/p2/mongo.py instead.
    db.probe_items.aggregate([{"$match": {}}, {"$out": "probe_out"}])
    check(db.probe_out.count_documents({}) == 2, "mongo_aggregate_passthrough")

    build_info = client.admin.command("buildInfo")["version"]
    client.close()
    import importlib.metadata as importlib_metadata

    print(
        f"version pymongo {importlib_metadata.version('pymongo')} "
        f"MongoDB {build_info}"
    )
    print("mongodb protocol axis complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
