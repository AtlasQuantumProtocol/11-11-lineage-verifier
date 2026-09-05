"""Summarise a governed execution result record for display.

THIS SCRIPT PERFORMS NO CRYPTOGRAPHIC VERIFICATION.

It reads the boolean fields a record asserts about itself and reformats them.
It computes no hash, walks no chain, and checks no signature, so it cannot
detect tampering and must never be cited as evidence that a record is valid.

For actual verification, which recomputes the SHA3-512 and BLAKE2b-512 chains
from the document itself, use src/verifier.js.
"""

import json
import sys


def verify_execution(data):
    verified = (
        data.get("authorized") is True
        and data.get("lineage_valid") is True
        and data.get("audit_integrity") is True
    )

    return {
        "verified": verified,
        "authorization_valid": data.get("authorized", False),
        "policy_hash_match": bool(data.get("policy_hash")),
        "lineage_chain_valid": data.get("lineage_valid", False),
        "audit_integrity_valid": data.get("audit_integrity", False),
        "tamper_detected": not verified
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 verifier/summarize_result.py <execution_record.json>")
        sys.exit(1)

    with open(sys.argv[1], "r") as f:
        data = json.load(f)

    result = verify_execution(data)
    print(json.dumps(result, indent=2))
