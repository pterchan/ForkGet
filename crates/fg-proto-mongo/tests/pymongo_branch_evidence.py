#!/usr/bin/env python3
"""A real pymongo driver drives the branch data plane through
the proxy on a fresh branch (merge, capture, isolation semantics with
driver-level APIs: find iteration, count_documents, distinct, update_one,
delete_one). Requires the seeded stub generation from the Rust integration
test and the branch frontend listening on the given port.

Usage: pymongo_branch_evidence.py <proxy_port> [branch]
Exits 3 when pymongo is unavailable, nonzero on any failure.
"""
import sys

try:
    import pymongo
except ImportError:
    print("pymongo is not installed; evidence skipped")
    sys.exit(3)

PROXY_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 28017
BRANCH = sys.argv[2] if len(sys.argv) > 2 else "gamma"
URI = (
    f"mongodb://alice:branch-alice-pw@127.0.0.1:{PROXY_PORT}/{BRANCH}"
    "?authSource=admin&directConnection=true"
)


def main() -> int:
    client = pymongo.MongoClient(URI, serverSelectionTimeoutMS=5000)
    db = client[BRANCH]
    assert db.list_collection_names() == ["orders"], db.list_collection_names()

    # Pinned base state: four documents, branch delta empty.
    assert db.orders.count_documents({}) == 4, db.orders.count_documents({})

    # Insert capture through the driver path.
    db.orders.insert_one(
        {"_id": 20, "tenant_id": 2, "customer_id": 30, "amount": 9.5, "note": "driver"}
    )
    assert db.orders.count_documents({}) == 5

    # Cursor iteration across getMore batches.
    streamed = [document["_id"] for document in db.orders.find().batch_size(2)]
    assert streamed == [1, 2, 3, 4, 20], streamed

    # Update capture: driver-visible edit.
    db.orders.update_one({"_id": 4}, {"$set": {"note": "driver-edited"}})
    assert db.orders.find_one({"_id": 4})["note"] == "driver-edited"

    # Delete capture: tombstone hides the base document.
    db.orders.delete_one({"_id": 3})
    assert db.orders.count_documents({}) == 4
    assert db.orders.distinct("customer_id") == [10, 20, 30], db.orders.distinct("customer_id")

    # count_documents is the aggregate path; the escape hatch is refused.
    # Document 3 (tenant 2) is tombstoned; documents 4 and 20 remain.
    assert db.orders.count_documents({"tenant_id": 2}) == 2

    try:
        list(db.orders.aggregate([{"$out": "elsewhere"}]))
        raise AssertionError("$out must be refused")
    except pymongo.errors.OperationFailure as failure:
        assert "FG-2002" in str(failure), failure

    print(f"pymongo branch evidence on {BRANCH}: OK")
    client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
