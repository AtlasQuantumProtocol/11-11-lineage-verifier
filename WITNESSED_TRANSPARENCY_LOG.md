# Witnessed Transparency Ledger

Status: IMPLEMENTED, PARTIAL — see "What is and is not built" below.

Purpose

Prevent equivocation and split-view ledger behavior.

## Pipeline

```
Evidence Root
↓
Transparency Log          src/transparency-log.js
↓
Signed Tree Head          hybrid Ed25519 + ML-DSA-87 (FIPS 204)
↓
Witness Signatures        NOT BUILT
↓
External Anchor           src/anchor.js — RFC 3161 TSA, OpenTimestamps
↓
Independent Verification  src/lineage.js (JS) and verifier/verify.py (Python)
```

## What is and is not built

| Feature | Status | Where |
|---|---|---|
| Append-only log | Built | `TransparencyLog` |
| Merkle tree (RFC 6962) | Built | `merkleRoot` |
| Inclusion proofs | Built | `inclusionProof` / `verifyInclusionProof` |
| Consistency proofs | Built | `consistencyProof` / `verifyConsistencyProof` |
| Signed tree heads | Built | `signTreeHead` — Ed25519 + ML-DSA-87 |
| RFC 3161 timestamps | Built | `Rfc3161AnchorProvider` |
| External anchoring | Built | `OpenTimestampsAnchorProvider` (Bitcoin-backed) |
| Independent verification | Built | two implementations, JS and Python |
| **Witness signatures** | **NOT BUILT** | no witness client or quorum policy exists |
| **On-chain transaction anchor** | **NOT BUILT** | deliberately omitted — see below |

## On split-view resistance

External anchoring gives proof of existence at a point in time from a party the
log operator does not control. That is a real constraint: the operator cannot
retroactively invent a root that a TSA or a Bitcoin calendar already declined to
attest at that time.

It is not full equivocation resistance. An operator could still anchor two
divergent roots and show a different one to each verifier. Closing that requires
**witness signatures** — independent parties countersigning tree heads and
gossiping them — which is not built. Until it is, the honest claim is
"externally timestamped, single-operator", not "witnessed".

## On the absence of a blockchain provider

No provider in `src/anchor.js` broadcasts a chain transaction, and
`anchorTreeHead` always returns `on_chain_transaction: null`.

Emitting a transaction requires a funded key and a network decision. A provider
that returned a plausible-looking transaction hash without broadcasting one
would be worse than having no provider: it would make an unverifiable claim look
verified. Anyone adding one should implement the `anchor(rootHash, meta)`
interface and return a receipt whose `status` is `ANCHORED` only after the
transaction is confirmed.

`FileAnchorProvider` is included because it is what several deployments actually
do today. Its status is `LOCAL_ONLY` and its `external_proof` is `false`, by
design: a file on the operator's own disk is an integrity checkpoint, not
external proof.

## Reproducing

```
npm test                 # proofs, tree heads, anchor contracts
npm run test:conformance # both verifiers across all fixtures
npm run anchor:demo      # live RFC 3161 + OpenTimestamps anchoring (needs network)
npm run anchor:demo -- --offline
```

Execution Governance™
Governed Execution™
EA-11™
