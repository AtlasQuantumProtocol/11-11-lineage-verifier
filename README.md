# 11/11 Lineage Verifier

Reference verifier for RFC-EG-0010 Execution Lineage Specification.

This public repository verifies synthetic RFC-EG-0010 execution lineage records without exposing the private 11/11 production control plane.

## Links

RFC-EG-0010 Zenodo Record: https://zenodo.org/records/20264726

Public Proof Endpoint: https://www.11aiblockchain.com/proof

11/11 Website: https://www.11aiblockchain.com

## What It Checks

- Required lineage event fields
- Sequence continuity
- SHA3-512 primary chain linkage
- BLAKE2b-512 redundant chain linkage
- Genesis handling
- RFC-EG-0010-compatible event shape

## Quick Start

Run:

npm run verify

Or:

node src/verifier.js samples/sample-lineage.json

Expected output:

11/11 Lineage Verifier
Loaded events: 3
Verification status: PASS

## IP Boundary

This repository is verification-only.

It does not include production authorization services, runtime enforcement internals, signing keys, policy engines, enterprise infrastructure, private issuer registries, or commercial orchestration logic.

Execution Governance, Governed Execution, and related 11/11 architecture may be covered by pending patent applications.
