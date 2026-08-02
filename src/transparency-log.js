// Append-only transparency log over lineage chain heads.
//
// This implements the pipeline WITNESSED_TRANSPARENCY_LOG.md specified as
// "TARGET DESIGN":
//
//   Evidence Root -> Transparency Log -> Signed Tree Head -> External Anchor
//
// Tree structure follows RFC 6962 (split at the largest power of two below n),
// which gives correct consistency proofs for non-power-of-two sizes without the
// duplicate-last-node trick.
//
// hashPair is deliberately identical to verifyEA11MerkleProof.ts in
// 11-11-execution-governance-sdk -- sha3-512(`${left}:${right}`) -- so inclusion
// proofs emitted here verify unmodified with the SDK's verifier. The end-to-end
// test relies on that.
import crypto from "node:crypto";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";

const sha3 = (input) => crypto.createHash("sha3-512").update(input).digest("hex");

export function hashPair(left, right) {
  return sha3(`${left}:${right}`);
}

// Domain-separated from hashPair: the left operand of hashPair is always a
// 128-char hex digest, so it can never begin with the literal "leaf".
export function leafHash(data) {
  return sha3(`leaf:${data}`);
}

export const EMPTY_ROOT = sha3("empty");

function largestPowerOfTwoBelow(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** Merkle tree head over a leaf-hash array (RFC 6962 MTH). */
export function merkleRoot(leaves) {
  if (leaves.length === 0) return EMPTY_ROOT;
  if (leaves.length === 1) return leaves[0];
  const k = largestPowerOfTwoBelow(leaves.length);
  return hashPair(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)));
}

/**
 * Inclusion path for a leaf, bottom-up.
 * Emitted in the {position, hash} shape the SDK's verifyMerkleProof consumes.
 */
export function inclusionPath(index, leaves) {
  if (leaves.length <= 1) return [];
  const k = largestPowerOfTwoBelow(leaves.length);
  if (index < k) {
    return [
      ...inclusionPath(index, leaves.slice(0, k)),
      { position: "right", hash: merkleRoot(leaves.slice(k)) }
    ];
  }
  return [
    ...inclusionPath(index - k, leaves.slice(k)),
    { position: "left", hash: merkleRoot(leaves.slice(0, k)) }
  ];
}

/** Verify an inclusion proof. Mirrors the SDK implementation exactly. */
export function verifyInclusionProof(proof) {
  let computed = proof.leaf;
  for (const node of proof.path) {
    computed =
      node.position === "left"
        ? hashPair(node.hash, computed)
        : hashPair(computed, node.hash);
  }
  return computed === proof.root;
}

// RFC 6962 SUBPROOF. Proves tree of size m is a prefix of the tree of size n.
function subProof(m, leaves, computeRoot) {
  if (m === leaves.length) {
    return computeRoot ? [] : [merkleRoot(leaves)];
  }
  const k = largestPowerOfTwoBelow(leaves.length);
  if (m <= k) {
    return [...subProof(m, leaves.slice(0, k), computeRoot), merkleRoot(leaves.slice(k))];
  }
  return [...subProof(m - k, leaves.slice(k), false), merkleRoot(leaves.slice(0, k))];
}

export function consistencyProof(m, leaves) {
  if (m < 1 || m > leaves.length) {
    throw new Error(`Invalid consistency range: ${m} of ${leaves.length}`);
  }
  if (m === leaves.length) return [];
  return subProof(m, leaves, true);
}

/**
 * Verify that oldRoot (size m) is a prefix of newRoot (size n).
 *
 * Recomputes both roots from the proof and requires each to match, plus full
 * consumption of the proof so trailing junk cannot be smuggled through.
 */
export function verifyConsistencyProof(m, n, oldRoot, newRoot, proof) {
  if (n < m) return false;
  if (m === n) return proof.length === 0 && oldRoot === newRoot;
  if (m === 0) return proof.length === 0;
  if (proof.length === 0) return false;

  // Strip trailing 1-bits: walks up to the highest node fully contained in the
  // old tree. If it lands on 0, m was an exact power of two and the old root
  // seeds the walk rather than appearing in the proof.
  let node = m - 1;
  let lastNode = n - 1;
  while (node % 2 === 1) {
    node = Math.floor(node / 2);
    lastNode = Math.floor(lastNode / 2);
  }

  let pi = 0;
  let hash1;
  let hash2;
  if (node > 0) {
    hash1 = proof[pi];
    hash2 = proof[pi];
    pi++;
  } else {
    hash1 = oldRoot;
    hash2 = oldRoot;
  }

  while (node > 0) {
    if (node % 2 === 1) {
      // Right child: both trees share the left sibling.
      if (pi >= proof.length) return false;
      hash1 = hashPair(proof[pi], hash1);
      hash2 = hashPair(proof[pi], hash2);
      pi++;
    } else if (node < lastNode) {
      // Left child with a right sibling that exists only in the new tree.
      if (pi >= proof.length) return false;
      hash2 = hashPair(hash2, proof[pi]);
      pi++;
    }
    // Left child with no sibling: nothing to combine at this level.
    node = Math.floor(node / 2);
    lastNode = Math.floor(lastNode / 2);
  }

  // Finish climbing to the new root.
  while (lastNode > 0) {
    if (pi >= proof.length) return false;
    hash2 = hashPair(hash2, proof[pi]);
    pi++;
    lastNode = Math.floor(lastNode / 2);
  }

  return hash1 === oldRoot && hash2 === newRoot && pi === proof.length;
}

/**
 * Append-only log of lineage chain heads.
 *
 * Each entry commits to a full lineage document: its operation id, its terminal
 * dual digests, and the count of events. Entries are never mutated or removed --
 * append is the only operation.
 */
export class TransparencyLog {
  constructor(logId = "11-11-execution-governance-log") {
    this.logId = logId;
    this.entries = [];
    this.leaves = [];
  }

  /** Append a verified lineage result. Returns the new entry with its index. */
  append(entry) {
    const record = {
      index: this.entries.length,
      operation_id: entry.operation_id,
      last_hash: entry.last_hash,
      last_hash_b: entry.last_hash_b,
      event_count: entry.event_count,
      ts: entry.ts
    };
    const canonical = [
      record.index,
      record.operation_id,
      record.last_hash,
      record.last_hash_b,
      record.event_count,
      record.ts
    ].join("|");
    record.leaf = leafHash(canonical);
    this.entries.push(record);
    this.leaves.push(record.leaf);
    return record;
  }

  get size() {
    return this.leaves.length;
  }

  root() {
    return merkleRoot(this.leaves);
  }

  /** Inclusion proof in the exact shape the SDK's verifyMerkleProof accepts. */
  inclusionProof(index) {
    if (index < 0 || index >= this.leaves.length) {
      throw new Error(`Leaf index out of range: ${index}`);
    }
    return {
      leaf: this.leaves[index],
      leaf_index: index,
      root: this.root(),
      path: inclusionPath(index, this.leaves)
    };
  }

  consistencyProof(fromSize) {
    return {
      from_size: fromSize,
      to_size: this.size,
      from_root: merkleRoot(this.leaves.slice(0, fromSize)),
      to_root: this.root(),
      path: consistencyProof(fromSize, this.leaves)
    };
  }

  /**
   * Produce a Signed Tree Head.
   *
   * Hybrid-signed: Ed25519 for today's verifiers, ML-DSA-87 (FIPS 204) so the
   * signature survives a cryptographically relevant quantum computer. A verifier
   * may require either or both; requiring both is the fail-closed posture.
   */
  signTreeHead(keys, timestamp) {
    if (!timestamp) throw new Error("signTreeHead requires an explicit timestamp");

    const head = {
      log_id: this.logId,
      tree_size: this.size,
      root_hash: this.root(),
      timestamp
    };

    const message = Buffer.from(canonicalHead(head), "utf8");
    const signatures = {};

    if (keys.ed25519PrivateKey) {
      signatures.ed25519 = {
        algorithm: "Ed25519",
        value: crypto.sign(null, message, keys.ed25519PrivateKey).toString("base64"),
        public_key: keys.ed25519PublicKey
          ? keys.ed25519PublicKey.export({ format: "der", type: "spki" }).toString("base64")
          : undefined
      };
    }

    if (keys.mlDsaSecretKey) {
      signatures.ml_dsa_87 = {
        algorithm: "ML-DSA-87",
        standard: "NIST FIPS 204",
        value: Buffer.from(ml_dsa87.sign(new Uint8Array(message), keys.mlDsaSecretKey)).toString("base64"),
        public_key: Buffer.from(keys.mlDsaPublicKey).toString("base64")
      };
    }

    if (Object.keys(signatures).length === 0) {
      throw new Error("signTreeHead requires at least one signing key");
    }

    return { ...head, signatures };
  }
}

export function canonicalHead(head) {
  return [head.log_id, head.tree_size, head.root_hash, head.timestamp].join("|");
}

/**
 * Verify a signed tree head.
 *
 * `require` selects the posture: "any" accepts a single valid signature,
 * "all" (default) demands every present algorithm verify, and "pq" demands a
 * valid post-quantum signature specifically.
 */
export function verifySignedTreeHead(sth, opts = {}) {
  const mode = opts.require || "all";
  const message = Buffer.from(canonicalHead(sth), "utf8");
  const results = {};
  const reasons = [];

  if (sth.signatures?.ed25519) {
    try {
      const pub = crypto.createPublicKey({
        key: Buffer.from(sth.signatures.ed25519.public_key, "base64"),
        format: "der",
        type: "spki"
      });
      results.ed25519 = crypto.verify(
        null,
        message,
        pub,
        Buffer.from(sth.signatures.ed25519.value, "base64")
      );
    } catch {
      results.ed25519 = false;
    }
    if (!results.ed25519) reasons.push("ed25519_invalid");
  }

  if (sth.signatures?.ml_dsa_87) {
    try {
      results.ml_dsa_87 = ml_dsa87.verify(
        new Uint8Array(Buffer.from(sth.signatures.ml_dsa_87.value, "base64")),
        new Uint8Array(message),
        new Uint8Array(Buffer.from(sth.signatures.ml_dsa_87.public_key, "base64"))
      );
    } catch {
      results.ml_dsa_87 = false;
    }
    if (!results.ml_dsa_87) reasons.push("ml_dsa_87_invalid");
  }

  const present = Object.keys(results);
  if (present.length === 0) {
    return { ok: false, results, reasons: ["no_signatures_present"] };
  }

  let ok;
  if (mode === "any") {
    ok = present.some((k) => results[k]);
    if (!ok) reasons.push("no_valid_signature");
  } else if (mode === "pq") {
    ok = results.ml_dsa_87 === true;
    if (!ok && !reasons.includes("ml_dsa_87_invalid")) reasons.push("pq_signature_required_but_missing");
  } else {
    ok = present.every((k) => results[k]);
  }

  return { ok, results, reasons: ok ? [] : reasons };
}

/** Generate a hybrid classical + post-quantum tree-head signing keypair. */
export function generateLogKeys() {
  const ed = crypto.generateKeyPairSync("ed25519");
  const pq = ml_dsa87.keygen();
  return {
    ed25519PrivateKey: ed.privateKey,
    ed25519PublicKey: ed.publicKey,
    mlDsaSecretKey: pq.secretKey,
    mlDsaPublicKey: pq.publicKey
  };
}
