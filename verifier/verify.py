#!/usr/bin/env python3
"""Independent Python verifier for RFC-EG-0010 execution lineage.

This is a deliberately separate implementation from src/lineage.js. Two
independent verifiers agreeing on a chain is a materially stronger claim than
one verifier run twice -- it catches canonicalization bugs that a single
implementation would apply consistently to both hashing and checking.

Canonical form mirrors the JavaScript stableStringify byte for byte:
  - object keys sorted, no whitespace
  - body excludes chash / chash_b / sig
  - chash   = sha3-512(body + (prev_hash    or "genesis"))
  - chash_b = blake2b-512(body + (prev_hash_b or "genesis"))

Exit codes:  0 verified   1 usage error   2 verification failed

HISTORY: the previous version of this file read three booleans that the input
document declared about itself ("authorized", "lineage_valid",
"audit_integrity") and reported them back as a verdict. It computed no hashes,
so its "tamper_detected" output was not evidence of anything. It has been
replaced outright rather than extended.
"""

import hashlib
import json
import sys

GENESIS = "genesis"

REQUIRED_FIELDS = (
    "v", "evt", "op_id", "seq", "ts", "producer", "payload",
    "prev_hash", "prev_hash_b", "chash", "chash_b",
)


class VerificationError(Exception):
    pass


def stable_stringify(value):
    """Canonical JSON matching the JS implementation's byte output."""
    if value is None or not isinstance(value, (dict, list)):
        # separators= strips the spaces json.dumps inserts by default
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(stable_stringify(v) for v in value) + "]"
    return (
        "{"
        + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + stable_stringify(value[k])
            for k in sorted(value.keys())
        )
        + "}"
    )


def hash_sha3(data):
    return "sha3-512:" + hashlib.sha3_512(data.encode("utf-8")).hexdigest()


def hash_blake(data):
    return "blake2b-512:" + hashlib.blake2b(
        data.encode("utf-8"), digest_size=64
    ).hexdigest()


def event_body(event):
    clone = {k: v for k, v in event.items() if k not in ("chash", "chash_b", "sig")}
    return stable_stringify(clone)


def verify_lineage(doc):
    if not isinstance(doc, dict) or not isinstance(doc.get("events"), list):
        raise VerificationError("Invalid lineage document: missing events array")

    prev_hash = None
    prev_hash_b = None
    prior_seq = 0
    event_types = []

    for event in doc["events"]:
        for field in REQUIRED_FIELDS:
            if field not in event:
                raise VerificationError(
                    "Event seq {} missing required field: {}".format(
                        event.get("seq", "unknown"), field
                    )
                )

        if event["seq"] != prior_seq + 1:
            raise VerificationError(
                "Sequence error: expected {}, got {}".format(prior_seq + 1, event["seq"])
            )

        if event["prev_hash"] != prev_hash:
            raise VerificationError(
                "Primary prev_hash mismatch at seq {}".format(event["seq"])
            )

        if event["prev_hash_b"] != prev_hash_b:
            raise VerificationError(
                "Redundant prev_hash_b mismatch at seq {}".format(event["seq"])
            )

        if doc.get("operation_id") and event["op_id"] != doc["operation_id"]:
            raise VerificationError(
                "Operation id mismatch at seq {}: {} != {}".format(
                    event["seq"], event["op_id"], doc["operation_id"]
                )
            )

        body = event_body(event)
        expected = hash_sha3(body + (prev_hash or GENESIS))
        expected_b = hash_blake(body + (prev_hash_b or GENESIS))

        if event["chash"] != expected:
            raise VerificationError(
                "Primary hash mismatch at seq {}".format(event["seq"])
            )

        if event["chash_b"] != expected_b:
            raise VerificationError(
                "Redundant hash mismatch at seq {}".format(event["seq"])
            )

        event_types.append(event["evt"])
        prev_hash = event["chash"]
        prev_hash_b = event["chash_b"]
        prior_seq = event["seq"]

    return {
        "verified": True,
        "events": len(doc["events"]),
        "last_hash": prev_hash,
        "last_hash_b": prev_hash_b,
        "event_types": event_types,
    }


def verify_output_provenance(doc):
    """Every source an output cites must have been retrieved earlier in the chain."""
    retrieved = {}
    problems = []
    outputs = 0

    for event in doc.get("events", []):
        if event["evt"] == "retrieval.performed":
            for source in event["payload"].get("sources", []):
                retrieved[source["source_id"]] = source["content_hash"]

        elif event["evt"] == "output.emitted":
            outputs += 1
            for ref in event["payload"].get("derived_from", []):
                source_id = ref if isinstance(ref, str) else ref.get("source_id")
                if source_id not in retrieved:
                    problems.append({
                        "seq": event["seq"],
                        "source_id": source_id,
                        "reason": "cited_source_never_retrieved",
                    })
                    continue
                pinned = ref.get("content_hash") if isinstance(ref, dict) else None
                if pinned and pinned != retrieved[source_id]:
                    problems.append({
                        "seq": event["seq"],
                        "source_id": source_id,
                        "reason": "cited_content_hash_mismatch",
                    })

    return {
        "ok": not problems,
        "outputs_checked": outputs,
        "sources_retrieved": len(retrieved),
        "problems": problems,
    }


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 verifier/verify.py <lineage.json>", file=sys.stderr)
        return 1

    with open(sys.argv[1], "r", encoding="utf-8") as handle:
        doc = json.load(handle)

    try:
        result = verify_lineage(doc)
    except VerificationError as err:
        print(json.dumps(
            {"verified": False, "tamper_detected": True, "reason": str(err)}, indent=2
        ))
        return 2

    if "output.emitted" in result["event_types"]:
        result["output_provenance"] = verify_output_provenance(doc)
        if not result["output_provenance"]["ok"]:
            result["verified"] = False
            print(json.dumps(dict(result, tamper_detected=True), indent=2))
            return 2

    print(json.dumps(dict(result, tamper_detected=False), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
