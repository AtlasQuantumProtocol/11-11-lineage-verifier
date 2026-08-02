// Core RFC-EG-0010 lineage primitives.
//
// This module is the importable half of the verifier. src/verifier.js is the CLI
// wrapper. Splitting them is what lets other repos (and the end-to-end test)
// verify a chain without shelling out to a process.
//
// Hash construction is unchanged from the original verifier.js so previously
// issued chains still verify:
//   body   = stableStringify(event minus chash/chash_b/sig)
//   chash  = sha3-512(body + (prev_hash   || "genesis"))
//   chash_b= blake2b-512(body + (prev_hash_b || "genesis"))
import crypto from "node:crypto";

export const GENESIS = "genesis";

export const REQUIRED_EVENT_FIELDS = [
  "v",
  "evt",
  "op_id",
  "seq",
  "ts",
  "producer",
  "payload",
  "prev_hash",
  "prev_hash_b",
  "chash",
  "chash_b"
];

// Event types the schema knows about. Governance events came first; the
// retrieval/output pair was added so model-output provenance rides the same chain.
export const GOVERNANCE_EVENTS = [
  "authorization.issued",
  "admission.granted",
  "admission.denied",
  "execution.completed",
  "execution.failed"
];

export const PROVENANCE_EVENTS = [
  "retrieval.performed",
  "output.emitted"
];

export const KNOWN_EVENTS = [...GOVERNANCE_EVENTS, ...PROVENANCE_EVENTS];

export function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(stableStringify).join(",") + "]";
  return (
    "{" +
    Object.keys(value)
      .sort()
      .map((k) => JSON.stringify(k) + ":" + stableStringify(value[k]))
      .join(",") +
    "}"
  );
}

export function hashSha3(input) {
  return "sha3-512:" + crypto.createHash("sha3-512").update(input).digest("hex");
}

export function hashBlake(input) {
  return "blake2b-512:" + crypto.createHash("blake2b512").update(input).digest("hex");
}

export function eventBody(event) {
  const clone = { ...event };
  delete clone.chash;
  delete clone.chash_b;
  delete clone.sig;
  return stableStringify(clone);
}

// Compute the dual digests an event must carry given its predecessor.
export function computeEventHashes(event, prevHash, prevHashB) {
  const body = eventBody(event);
  return {
    chash: hashSha3(body + (prevHash || GENESIS)),
    chash_b: hashBlake(body + (prevHashB || GENESIS))
  };
}

/**
 * Verify an RFC-EG-0010 lineage document.
 *
 * Throws on the first structural or cryptographic defect. Every digest is
 * recomputed from the canonicalized event body -- stored values are never
 * trusted, which is what makes a silent field edit detectable.
 *
 * @returns {{ok: true, events: number, last_hash: string|null, last_hash_b: string|null, event_types: string[]}}
 */
export function verifyLineage(doc) {
  if (!doc || !Array.isArray(doc.events)) {
    throw new Error("Invalid lineage document: missing events array");
  }

  let prevHash = null;
  let prevHashB = null;
  let priorSeq = 0;
  let priorTs = null;
  const eventTypes = [];

  for (const event of doc.events) {
    for (const field of REQUIRED_EVENT_FIELDS) {
      if (!(field in event)) {
        throw new Error(
          `Event seq ${event.seq || "unknown"} missing required field: ${field}`
        );
      }
    }

    if (event.seq !== priorSeq + 1) {
      throw new Error(`Sequence error: expected ${priorSeq + 1}, got ${event.seq}`);
    }

    if (event.prev_hash !== prevHash) {
      throw new Error(`Primary prev_hash mismatch at seq ${event.seq}`);
    }

    if (event.prev_hash_b !== prevHashB) {
      throw new Error(`Redundant prev_hash_b mismatch at seq ${event.seq}`);
    }

    // Timestamps must not travel backwards. The original verifier checked seq
    // ordering but not time, so a backdated event slotted into a rebuilt chain
    // would have passed.
    const ts = Date.parse(event.ts);
    if (Number.isNaN(ts)) {
      throw new Error(`Invalid timestamp at seq ${event.seq}: ${event.ts}`);
    }
    if (priorTs !== null && ts < priorTs) {
      throw new Error(`Timestamp regression at seq ${event.seq}: ${event.ts}`);
    }

    // All events in a document must belong to the same operation, otherwise two
    // unrelated chains could be spliced together and still hash-link cleanly.
    if (doc.operation_id && event.op_id !== doc.operation_id) {
      throw new Error(
        `Operation id mismatch at seq ${event.seq}: ${event.op_id} != ${doc.operation_id}`
      );
    }

    const { chash, chash_b } = computeEventHashes(event, prevHash, prevHashB);

    if (event.chash !== chash) {
      throw new Error(`Primary hash mismatch at seq ${event.seq}`);
    }

    if (event.chash_b !== chash_b) {
      throw new Error(`Redundant hash mismatch at seq ${event.seq}`);
    }

    verifyEventPayload(event);

    eventTypes.push(event.evt);
    prevHash = event.chash;
    prevHashB = event.chash_b;
    priorSeq = event.seq;
    priorTs = ts;
  }

  return {
    ok: true,
    events: doc.events.length,
    last_hash: prevHash,
    last_hash_b: prevHashB,
    event_types: eventTypes
  };
}

// Per-event-type payload requirements. Retrieval and output events carry the
// provenance fields; without these checks an "output.emitted" event with no
// source attribution would verify as a well-formed chain link.
function verifyEventPayload(event) {
  const p = event.payload;
  if (!p || typeof p !== "object") {
    throw new Error(`Event seq ${event.seq} has a non-object payload`);
  }

  const require = (fields) => {
    for (const f of fields) {
      if (p[f] === undefined || p[f] === null || p[f] === "") {
        throw new Error(
          `Event seq ${event.seq} (${event.evt}) missing payload field: ${f}`
        );
      }
    }
  };

  switch (event.evt) {
    case "retrieval.performed":
      require(["query_hash", "sources"]);
      if (!Array.isArray(p.sources) || p.sources.length === 0) {
        throw new Error(`Event seq ${event.seq} retrieval has no sources`);
      }
      p.sources.forEach((s, i) => {
        for (const f of ["source_id", "content_hash"]) {
          if (!s || !s[f]) {
            throw new Error(
              `Event seq ${event.seq} retrieval source[${i}] missing: ${f}`
            );
          }
        }
      });
      break;

    case "output.emitted":
      // derived_from binds the output to the retrieval events that produced it.
      require(["output_hash", "derived_from"]);
      if (!Array.isArray(p.derived_from) || p.derived_from.length === 0) {
        throw new Error(
          `Event seq ${event.seq} output.emitted has empty derived_from`
        );
      }
      break;

    case "authorization.issued":
      require(["artifact_id", "subject", "policy_ref"]);
      break;

    default:
      break;
  }
}

/**
 * Cross-check that every source an output claims to derive from was actually
 * retrieved earlier in the same chain.
 *
 * Chain integrity alone cannot catch this: an output citing a document that was
 * never retrieved is a perfectly valid hash link. This is the check that makes
 * retrieval lineage mean something.
 */
export function verifyOutputProvenance(doc) {
  const retrieved = new Map(); // source_id -> content_hash
  const problems = [];
  let outputs = 0;

  for (const event of doc.events) {
    if (event.evt === "retrieval.performed") {
      for (const s of event.payload.sources) {
        retrieved.set(s.source_id, s.content_hash);
      }
    }

    if (event.evt === "output.emitted") {
      outputs++;
      for (const ref of event.payload.derived_from) {
        const sourceId = typeof ref === "string" ? ref : ref.source_id;
        if (!retrieved.has(sourceId)) {
          problems.push({
            seq: event.seq,
            source_id: sourceId,
            reason: "cited_source_never_retrieved"
          });
          continue;
        }
        // If the citation pins a content hash, it must match what was retrieved.
        const pinned = typeof ref === "object" ? ref.content_hash : undefined;
        if (pinned && pinned !== retrieved.get(sourceId)) {
          problems.push({
            seq: event.seq,
            source_id: sourceId,
            reason: "cited_content_hash_mismatch"
          });
        }
      }
    }
  }

  return {
    ok: problems.length === 0,
    outputs_checked: outputs,
    sources_retrieved: retrieved.size,
    problems
  };
}

/**
 * Build a valid chain from bare event descriptors, filling in seq/prev/hashes.
 * Used by the samples, the tests, and the end-to-end harness so no fixture has
 * to carry hand-computed digests.
 */
export function buildLineage(operationId, events, opts = {}) {
  const startTs = opts.startTs ? Date.parse(opts.startTs) : Date.parse("2026-01-01T00:00:00.000Z");
  let prevHash = null;
  let prevHashB = null;

  const built = events.map((e, i) => {
    const event = {
      v: "1",
      evt: e.evt,
      op_id: operationId,
      seq: i + 1,
      ts: e.ts || new Date(startTs + i * 1000).toISOString(),
      producer: e.producer || { service: "reference", instance: "governance://11-11/reference" },
      payload: e.payload,
      prev_hash: prevHash,
      prev_hash_b: prevHashB
    };
    const { chash, chash_b } = computeEventHashes(event, prevHash, prevHashB);
    event.chash = chash;
    event.chash_b = chash_b;
    prevHash = chash;
    prevHashB = chash_b;
    return event;
  });

  return {
    rfc: "RFC-EG-0010",
    version: opts.version || "0.1.0-reference",
    operation_id: operationId,
    events: built
  };
}
