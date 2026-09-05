# 11/11 Lineage Verifier

Machine-verifiable execution governance verification infrastructure.

## Overview

The 11/11 Lineage Verifier is a verification and conformance layer for execution governance systems.

Traditional systems execute first and validate later.

11/11 introduces governance before execution and enables independent verification of authorization, execution lineage, immutable audit integrity, and runtime policy enforcement.

This repository provides a reference implementation for validating governed execution flows and execution lineage integrity.

## Core Doctrine

No action executes without authorization.

Execution Governance introduces pre-execution authorization, fail-closed enforcement, cryptographic verification, execution lineage, and immutable audit evidence into AI and distributed execution environments.

## Verification Flow

Request
→ Authorization
→ Verification
→ Execution
→ Audit
→ Lineage Persistence
→ Independent Validation

## Verifying a Lineage Document

The reference verifier recomputes both hash chains from the document itself. It
does not read any claim a document makes about its own validity.

```bash
node src/verifier.js examples/verified_lineage.json
```

```
11/11 Lineage Verifier
Loaded events: 3
Verification status: PASS
Last SHA3-512 hash: sha3-512:ae2d7936a802ad3b...
Last BLAKE2b-512 hash: blake2b-512:b0ad2362ea01c19e...
```

## Detecting Tampering

`examples/tampered_lineage.json` is the same document with one governed decision
altered after the fact and every hash left untouched.

```bash
node src/verifier.js examples/tampered_lineage.json
```

```
11/11 Lineage Verifier
Loaded events: 3
Verification status: FAIL
Primary hash mismatch at seq 2
```

Exit code 2. The chain names the exact event that changed.

## What the Verifier Checks

For every event, in order:

- Required fields are present: v, evt, op_id, seq, ts, producer, payload, prev_hash, prev_hash_b, chash, chash_b
- seq starts at 1 and increments by exactly 1
- prev_hash and prev_hash_b match the preceding event's chash and chash_b
- chash equals SHA3-512 over the canonical event body concatenated with prev_hash, or with the literal string "genesis" for the first event
- chash_b equals BLAKE2b-512 over the same body concatenated with prev_hash_b

The canonical body is the event with chash, chash_b and sig removed, serialised
with keys sorted recursively. The two chains are computed independently, so a
break in one cannot mask a break in the other.

The document format is specified in `schemas/lineage-event.schema.json`.

## What the Verifier Does Not Check

It does not validate signatures, resolve producer identities, or evaluate
policy. It establishes that a lineage document has not been altered since it was
written. Authorization correctness is a separate concern.

## Running the Tests

```bash
./tests/run_test.sh
```

Confirms the valid document verifies, confirms the tampered document is
rejected, and fails loudly if either outcome is wrong.
