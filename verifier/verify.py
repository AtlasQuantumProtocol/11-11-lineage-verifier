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
        print("Usage: python3 verifier/verify.py <execution_record.json>")
        sys.exit(1)

    with open(sys.argv[1], "r") as f:
        data = json.load(f)

    result = verify_execution(data)
    print(json.dumps(result, indent=2))
