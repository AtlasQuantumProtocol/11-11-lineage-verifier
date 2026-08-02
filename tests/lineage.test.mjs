// Chain integrity and retrieval-provenance tests.
//
// Every negative case mutates a *valid* chain in exactly one way, so a failure
// here points at one specific defect rather than a generally malformed fixture.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  buildLineage,
  verifyLineage,
  verifyOutputProvenance,
  computeEventHashes
} from "../src/lineage.js";

const sha3 = (s) => "sha3-512:" + crypto.createHash("sha3-512").update(s).digest("hex");
const clone = (o) => JSON.parse(JSON.stringify(o));

function governanceChain() {
  return buildLineage("op_test_001", [
    {
      evt: "authorization.issued",
      payload: { artifact_id: "auth_1", subject: "agent:test", policy_ref: "policy://test" }
    },
    { evt: "admission.granted", payload: { artifact_id: "auth_1", decision: "admit" } },
    { evt: "execution.completed", payload: { result_ref: sha3("result"), status: "completed" } }
  ]);
}

function retrievalChain() {
  const a = sha3("doc-a-content");
  const b = sha3("doc-b-content");
  return buildLineage("op_test_rag", [
    {
      evt: "authorization.issued",
      payload: { artifact_id: "auth_2", subject: "agent:rag", policy_ref: "policy://rag" }
    },
    {
      evt: "retrieval.performed",
      payload: {
        query_hash: sha3("question"),
        sources: [
          { source_id: "doc://a", content_hash: a },
          { source_id: "doc://b", content_hash: b }
        ]
      }
    },
    {
      evt: "output.emitted",
      payload: {
        output_hash: sha3("answer"),
        derived_from: [
          { source_id: "doc://a", content_hash: a },
          { source_id: "doc://b", content_hash: b }
        ]
      }
    }
  ]);
}

describe("lineage chain verification", () => {
  it("verifies a well-formed governance chain", () => {
    const result = verifyLineage(governanceChain());
    assert.equal(result.ok, true);
    assert.equal(result.events, 3);
  });

  it("verifies the committed sample (regression guard on hash construction)", () => {
    const doc = JSON.parse(fs.readFileSync(new URL("../samples/sample-lineage.json", import.meta.url)));
    const result = verifyLineage(doc);
    // Pinned: if canonicalization ever changes, previously issued chains break.
    assert.equal(
      result.last_hash,
      "sha3-512:ae2d7936a802ad3be4ac789d2e608b2a219ab292e728a2ee8fa08de402d3b78e" +
        "8f33dd67a51169cbdae2a5e02f40fedd1b6288bedf17a2c6dc0244f4fee75aa2"
    );
  });

  it("rejects a document with no events array", () => {
    assert.throws(() => verifyLineage({ foo: "bar" }), /missing events array/);
  });

  it("detects an edited payload with stored digests left intact", () => {
    const doc = clone(governanceChain());
    doc.events[1].payload.decision = "deny";
    assert.throws(() => verifyLineage(doc), /Primary hash mismatch at seq 2/);
  });

  it("detects a re-hashed event whose successor no longer links", () => {
    // A more capable attacker recomputes the edited event's own digests. The
    // break then surfaces at the *next* event's prev_hash.
    const doc = clone(governanceChain());
    doc.events[1].payload.decision = "deny";
    const fixed = computeEventHashes(doc.events[1], doc.events[0].chash, doc.events[0].chash_b);
    doc.events[1].chash = fixed.chash;
    doc.events[1].chash_b = fixed.chash_b;
    assert.throws(() => verifyLineage(doc), /prev_hash mismatch at seq 3/);
  });

  it("detects a removed event", () => {
    const doc = clone(governanceChain());
    doc.events.splice(1, 1);
    assert.throws(() => verifyLineage(doc), /Sequence error/);
  });

  it("detects a duplicated event", () => {
    const doc = clone(governanceChain());
    doc.events.splice(1, 0, clone(doc.events[1]));
    assert.throws(() => verifyLineage(doc), /Sequence error/);
  });

  it("detects a backdated event", () => {
    const doc = clone(governanceChain());
    doc.events[2].ts = "2020-01-01T00:00:00.000Z";
    // Timestamp is inside the hashed body, so this trips the digest first.
    assert.throws(() => verifyLineage(doc), /hash mismatch|Timestamp regression/);
  });

  it("detects timestamp regression on an otherwise valid chain", () => {
    // Rebuild with a genuinely regressing timestamp so hashes are self-consistent.
    const doc = buildLineage("op_ts", [
      { evt: "admission.granted", ts: "2026-05-18T00:00:05.000Z", payload: { decision: "admit" } },
      { evt: "execution.completed", ts: "2026-05-18T00:00:01.000Z", payload: { status: "completed" } }
    ]);
    assert.throws(() => verifyLineage(doc), /Timestamp regression at seq 2/);
  });

  it("detects a spliced foreign event (op_id mismatch)", () => {
    const doc = clone(governanceChain());
    doc.events[1].op_id = "op_other";
    assert.throws(() => verifyLineage(doc), /hash mismatch|Operation id mismatch/);
  });

  it("rejects an event missing a required field", () => {
    const doc = clone(governanceChain());
    delete doc.events[1].producer;
    assert.throws(() => verifyLineage(doc), /missing required field: producer/);
  });
});

describe("retrieval and output provenance", () => {
  it("verifies a retrieval chain end to end", () => {
    const doc = retrievalChain();
    assert.equal(verifyLineage(doc).ok, true);
    const prov = verifyOutputProvenance(doc);
    assert.equal(prov.ok, true);
    assert.equal(prov.outputs_checked, 1);
    assert.equal(prov.sources_retrieved, 2);
  });

  it("rejects retrieval events with no sources", () => {
    assert.throws(
      () =>
        verifyLineage(
          buildLineage("op_x", [
            { evt: "retrieval.performed", payload: { query_hash: sha3("q"), sources: [] } }
          ])
        ),
      /retrieval has no sources/
    );
  });

  it("rejects a retrieval source missing its content hash", () => {
    assert.throws(
      () =>
        verifyLineage(
          buildLineage("op_x", [
            {
              evt: "retrieval.performed",
              payload: { query_hash: sha3("q"), sources: [{ source_id: "doc://a" }] }
            }
          ])
        ),
      /source\[0\] missing: content_hash/
    );
  });

  it("rejects an output with an empty derived_from", () => {
    assert.throws(
      () =>
        verifyLineage(
          buildLineage("op_x", [
            { evt: "output.emitted", payload: { output_hash: sha3("o"), derived_from: [] } }
          ])
        ),
      /empty derived_from/
    );
  });

  it("catches an output citing a source that was never retrieved", () => {
    // This is the fabricated-citation case. The chain itself is cryptographically
    // valid -- only the cross-check between retrieval and output catches it.
    const doc = retrievalChain();
    const tampered = clone(doc);
    tampered.events[2].payload.derived_from.push({ source_id: "doc://never-retrieved" });
    assert.equal(verifyOutputProvenance(tampered).ok, false);
    assert.equal(
      verifyOutputProvenance(tampered).problems[0].reason,
      "cited_source_never_retrieved"
    );
  });

  it("catches an output citing a source whose content hash does not match", () => {
    const doc = clone(retrievalChain());
    doc.events[2].payload.derived_from[0].content_hash = sha3("different-content");
    const prov = verifyOutputProvenance(doc);
    assert.equal(prov.ok, false);
    assert.equal(prov.problems[0].reason, "cited_content_hash_mismatch");
  });
});

describe("cross-language verification", () => {
  it("the Python verifier agrees with the JavaScript verifier", () => {
    // Independent implementations. Agreement here rules out a canonicalization
    // bug that a single implementation would apply consistently and never catch.
    const sample = new URL("../samples/sample-retrieval-lineage.json", import.meta.url).pathname;
    const out = execFileSync("python3", ["verifier/verify.py", sample], { encoding: "utf8" });
    const py = JSON.parse(out);
    const js = verifyLineage(JSON.parse(fs.readFileSync(sample, "utf8")));
    assert.equal(py.verified, true);
    assert.equal(py.last_hash, js.last_hash);
    assert.equal(py.last_hash_b, js.last_hash_b);
  });

  it("the Python verifier rejects the tampered example", () => {
    const file = new URL("../examples/tampered_execution.json", import.meta.url).pathname;
    let code = 0;
    try {
      execFileSync("python3", ["verifier/verify.py", file], { encoding: "utf8" });
    } catch (err) {
      code = err.status;
    }
    assert.equal(code, 2, "tampered chain must exit 2");
  });
});
