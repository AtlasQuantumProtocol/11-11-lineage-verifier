#!/usr/bin/env node
import fs from "fs";
import crypto from "crypto";

function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(stableStringify).join(",") + "]";
  return "{" + Object.keys(value).sort().map(k => JSON.stringify(k) + ":" + stableStringify(value[k])).join(",") + "}";
}

function hashSha3(input) {
  return "sha3-512:" + crypto.createHash("sha3-512").update(input).digest("hex");
}

function hashBlake(input) {
  return "blake2b-512:" + crypto.createHash("blake2b512").update(input).digest("hex");
}

function eventBody(event) {
  const clone = { ...event };
  delete clone.chash;
  delete clone.chash_b;
  delete clone.sig;
  return stableStringify(clone);
}

function verifyLineage(doc) {
  if (!doc || !Array.isArray(doc.events)) {
    throw new Error("Invalid lineage document: missing events array");
  }

  let prevHash = null;
  let prevHashB = null;
  let priorSeq = 0;

  for (const event of doc.events) {
    const required = ["v", "evt", "op_id", "seq", "ts", "producer", "payload", "prev_hash", "prev_hash_b", "chash", "chash_b"];

    for (const field of required) {
      if (!(field in event)) {
        throw new Error(`Event seq ${event.seq || "unknown"} missing required field: ${field}`);
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

    const body = eventBody(event);
    const expectedPrimary = hashSha3(body + (prevHash || "genesis"));
    const expectedRedundant = hashBlake(body + (prevHashB || "genesis"));

    if (event.chash !== expectedPrimary) {
      throw new Error(`Primary hash mismatch at seq ${event.seq}`);
    }

    if (event.chash_b !== expectedRedundant) {
      throw new Error(`Redundant hash mismatch at seq ${event.seq}`);
    }

    prevHash = event.chash;
    prevHashB = event.chash_b;
    priorSeq = event.seq;
  }

  return {
    ok: true,
    events: doc.events.length,
    last_hash: prevHash,
    last_hash_b: prevHashB
  };
}

const file = process.argv[2];

if (!file) {
  console.error("Usage: node src/verifier.js <lineage.json>");
  process.exit(1);
}

const raw = fs.readFileSync(file, "utf8");
const doc = JSON.parse(raw);

console.log("11/11 Lineage Verifier");
console.log(`Loaded events: ${doc.events?.length || 0}`);

try {
  const result = verifyLineage(doc);
  console.log("Verification status: PASS");
  console.log(`Last SHA3-512 hash: ${result.last_hash}`);
  console.log(`Last BLAKE2b-512 hash: ${result.last_hash_b}`);
} catch (err) {
  console.error("Verification status: FAIL");
  console.error(err.message);
  process.exit(2);
}
