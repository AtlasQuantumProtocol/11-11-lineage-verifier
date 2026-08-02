// Transparency log: Merkle proofs, signed tree heads, anchoring.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  TransparencyLog,
  merkleRoot,
  verifyInclusionProof,
  consistencyProof,
  verifyConsistencyProof,
  verifySignedTreeHead,
  generateLogKeys,
  hashPair,
  leafHash
} from "../src/transparency-log.js";
import {
  FileAnchorProvider,
  Rfc3161AnchorProvider,
  OpenTimestampsAnchorProvider,
  anchorTreeHead,
  buildTimeStampRequest,
  extractGenTime,
  ANCHOR_STATUS
} from "../src/anchor.js";

const TS = "2026-05-18T00:00:00.000Z";

function logOfSize(n) {
  const log = new TransparencyLog();
  for (let i = 0; i < n; i++) {
    log.append({
      operation_id: `op_${i}`,
      last_hash: `sha3-512:${String(i).repeat(4)}`,
      last_hash_b: `blake2b-512:${String(i).repeat(4)}`,
      event_count: 3,
      ts: TS
    });
  }
  return log;
}

describe("merkle tree", () => {
  it("is deterministic", () => {
    assert.equal(logOfSize(7).root(), logOfSize(7).root());
  });

  it("changes root when any leaf changes", () => {
    const a = logOfSize(5);
    const b = logOfSize(5);
    b.leaves[2] = leafHash("different");
    assert.notEqual(a.root(), b.root());
  });

  it("uses the same hashPair construction as the SDK's Merkle verifier", () => {
    // verifyEA11MerkleProof.ts computes sha3-512(`${left}:${right}`). Proofs are
    // only cross-repo verifiable while this stays true.
    const expected = hashPair("aa", "bb");
    assert.equal(merkleRoot(["aa", "bb"]), expected);
  });
});

describe("inclusion proofs", () => {
  it("verifies every leaf across tree sizes 1..33", () => {
    for (let n = 1; n <= 33; n++) {
      const log = logOfSize(n);
      for (let i = 0; i < n; i++) {
        assert.equal(verifyInclusionProof(log.inclusionProof(i)), true, `n=${n} i=${i}`);
      }
    }
  });

  it("rejects a corrupted leaf", () => {
    const proof = logOfSize(9).inclusionProof(4);
    assert.equal(verifyInclusionProof({ ...proof, leaf: leafHash("forged") }), false);
  });

  it("rejects a corrupted path node", () => {
    const proof = logOfSize(9).inclusionProof(4);
    const path = [...proof.path];
    path[0] = { ...path[0], hash: leafHash("forged") };
    assert.equal(verifyInclusionProof({ ...proof, path }), false);
  });

  it("rejects a flipped sibling position", () => {
    const proof = logOfSize(9).inclusionProof(4);
    const path = proof.path.map((n) => ({
      ...n,
      position: n.position === "left" ? "right" : "left"
    }));
    assert.equal(verifyInclusionProof({ ...proof, path }), false);
  });

  it("throws on an out-of-range index", () => {
    assert.throws(() => logOfSize(3).inclusionProof(7), /out of range/);
  });
});

describe("consistency proofs", () => {
  it("verifies every (m,n) pair across sizes 1..33", () => {
    for (let n = 1; n <= 33; n++) {
      const log = logOfSize(n);
      for (let m = 1; m <= n; m++) {
        const proof = consistencyProof(m, log.leaves);
        const oldRoot = merkleRoot(log.leaves.slice(0, m));
        assert.equal(
          verifyConsistencyProof(m, n, oldRoot, log.root(), proof),
          true,
          `m=${m} n=${n}`
        );
      }
    }
  });

  it("rejects a forged old root", () => {
    const log = logOfSize(11);
    const proof = consistencyProof(6, log.leaves);
    assert.equal(verifyConsistencyProof(6, 11, leafHash("forged"), log.root(), proof), false);
  });

  it("rejects a forged new root", () => {
    const log = logOfSize(11);
    const proof = consistencyProof(6, log.leaves);
    const oldRoot = merkleRoot(log.leaves.slice(0, 6));
    assert.equal(verifyConsistencyProof(6, 11, oldRoot, leafHash("forged"), proof), false);
  });

  it("rejects a proof with trailing junk appended", () => {
    const log = logOfSize(11);
    const proof = [...consistencyProof(6, log.leaves), leafHash("junk")];
    const oldRoot = merkleRoot(log.leaves.slice(0, 6));
    assert.equal(verifyConsistencyProof(6, 11, oldRoot, log.root(), proof), false);
  });

  it("detects a rewritten history (the split-view case)", () => {
    // An operator publishes size 5, then rewrites an early entry and republishes
    // at size 9. No consistency proof can bridge the two -- that is the point.
    const honest = logOfSize(5);
    const publishedRoot = honest.root();

    const rewritten = logOfSize(9);
    rewritten.leaves[1] = leafHash("rewritten-history");

    const proof = consistencyProof(5, rewritten.leaves);
    assert.equal(
      verifyConsistencyProof(5, 9, publishedRoot, rewritten.root(), proof),
      false,
      "a rewritten log must not prove consistency with what was already published"
    );
  });

  it("append-only growth does prove consistent", () => {
    const log = logOfSize(5);
    const rootAt5 = log.root();
    for (let i = 5; i < 9; i++) {
      log.append({
        operation_id: `op_${i}`,
        last_hash: `sha3-512:${String(i).repeat(4)}`,
        last_hash_b: `blake2b-512:${String(i).repeat(4)}`,
        event_count: 3,
        ts: TS
      });
    }
    const proof = consistencyProof(5, log.leaves);
    assert.equal(verifyConsistencyProof(5, 9, rootAt5, log.root(), proof), true);
  });
});

describe("signed tree heads", () => {
  it("signs with both Ed25519 and ML-DSA-87 and verifies both", () => {
    const keys = generateLogKeys();
    const sth = logOfSize(6).signTreeHead(keys, TS);
    assert.equal(sth.signatures.ed25519.algorithm, "Ed25519");
    assert.equal(sth.signatures.ml_dsa_87.algorithm, "ML-DSA-87");
    assert.equal(sth.signatures.ml_dsa_87.standard, "NIST FIPS 204");

    const result = verifySignedTreeHead(sth);
    assert.equal(result.ok, true);
    assert.equal(result.results.ed25519, true);
    assert.equal(result.results.ml_dsa_87, true);
  });

  it("rejects a tampered root hash under both algorithms", () => {
    const keys = generateLogKeys();
    const sth = logOfSize(6).signTreeHead(keys, TS);
    const forged = { ...sth, root_hash: leafHash("forged-root") };
    const result = verifySignedTreeHead(forged);
    assert.equal(result.ok, false);
    assert.equal(result.results.ed25519, false);
    assert.equal(result.results.ml_dsa_87, false);
  });

  it("rejects a tampered tree size", () => {
    const keys = generateLogKeys();
    const sth = logOfSize(6).signTreeHead(keys, TS);
    assert.equal(verifySignedTreeHead({ ...sth, tree_size: 99 }).ok, false);
  });

  it("rejects a tampered timestamp", () => {
    const keys = generateLogKeys();
    const sth = logOfSize(6).signTreeHead(keys, TS);
    assert.equal(
      verifySignedTreeHead({ ...sth, timestamp: "2030-01-01T00:00:00.000Z" }).ok,
      false
    );
  });

  it("fails closed when a PQ signature is required but absent", () => {
    const keys = generateLogKeys();
    const sth = logOfSize(6).signTreeHead(
      { ed25519PrivateKey: keys.ed25519PrivateKey, ed25519PublicKey: keys.ed25519PublicKey },
      TS
    );
    assert.equal(sth.signatures.ml_dsa_87, undefined);
    assert.equal(verifySignedTreeHead(sth, { require: "any" }).ok, true);

    const pq = verifySignedTreeHead(sth, { require: "pq" });
    assert.equal(pq.ok, false);
    assert.ok(pq.reasons.includes("pq_signature_required_but_missing"));
  });

  it("refuses to sign with no keys and refuses an implicit timestamp", () => {
    assert.throws(() => logOfSize(2).signTreeHead({}, TS), /at least one signing key/);
    assert.throws(() => logOfSize(2).signTreeHead(generateLogKeys()), /explicit timestamp/);
  });

  it("reports no_signatures_present for an unsigned head", () => {
    const result = verifySignedTreeHead({
      log_id: "x",
      tree_size: 1,
      root_hash: "abc",
      timestamp: TS,
      signatures: {}
    });
    assert.equal(result.ok, false);
    assert.ok(result.reasons.includes("no_signatures_present"));
  });
});

describe("RFC 3161 request encoding", () => {
  it("builds a DER SEQUENCE carrying the SHA-512 OID and digest", () => {
    const digest = Buffer.alloc(64, 0xab);
    const nonce = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    const tsq = buildTimeStampRequest(digest, nonce);
    assert.equal(tsq[0], 0x30, "top level must be a DER SEQUENCE");
    // sha512 OID 2.16.840.1.101.3.4.2.3
    assert.ok(
      tsq.includes(Buffer.from([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03])),
      "must carry the SHA-512 algorithm OID"
    );
    assert.ok(tsq.includes(digest), "must carry the message imprint");
  });

  it("parses a GeneralizedTime out of DER", () => {
    const time = Buffer.from("20260729180346Z", "ascii");
    const der = Buffer.concat([
      Buffer.from([0x30, 0x11, 0x18, time.length]),
      time
    ]);
    assert.equal(extractGenTime(der), "2026-07-29T18:03:46Z");
  });

  it("returns null when no timestamp is present", () => {
    assert.equal(extractGenTime(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01])), null);
  });
});

describe("anchoring", () => {
  it("file anchor reports LOCAL_ONLY and claims no external proof", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "anchor-"));
    const keys = generateLogKeys();
    const sth = logOfSize(4).signTreeHead(keys, TS);

    return anchorTreeHead(sth, [new FileAnchorProvider(dir)]).then((result) => {
      const receipt = result.receipts[0];
      assert.equal(receipt.status, ANCHOR_STATUS.LOCAL_ONLY);
      assert.equal(receipt.external_proof, false);
      assert.equal(result.external_anchor_count, 0);
      // The stack must never imply a chain transaction it did not make.
      assert.equal(result.on_chain_transaction, null);
      assert.ok(fs.existsSync(receipt.path));
      fs.rmSync(dir, { recursive: true, force: true });
    });
  });

  it("network providers fail closed rather than claiming a false anchor", async () => {
    // Unroutable endpoints: the contract under test is that a failed anchor
    // reports FAILED with external_proof false, never a fabricated receipt.
    const sth = logOfSize(4).signTreeHead(generateLogKeys(), TS);
    const result = await anchorTreeHead(sth, [
      new Rfc3161AnchorProvider("http://127.0.0.1:9/tsr", { timeoutMs: 1500 }),
      new OpenTimestampsAnchorProvider(["http://127.0.0.1:9"], { timeoutMs: 1500 })
    ]);

    for (const receipt of result.receipts) {
      assert.equal(receipt.status, ANCHOR_STATUS.FAILED);
      assert.equal(receipt.external_proof, false);
      assert.ok(receipt.error, "a failed anchor must carry an error");
    }
    assert.equal(result.external_anchor_count, 0);
    assert.equal(result.on_chain_transaction, null);
    assert.match(result.summary, /No external anchor/);
  });
});
