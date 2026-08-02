#!/usr/bin/env node
// End-to-end anchoring demo against live external services.
//
//   lineage chains -> transparency log -> Merkle root -> hybrid-signed tree head
//   -> RFC 3161 TSA + OpenTimestamps calendars
//
// Requires outbound network. Run with --offline to exercise the local path only.
// Receipts are written to outputs/ so a reviewer can re-verify them independently.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyLineage } from "../src/lineage.js";
import {
  TransparencyLog,
  generateLogKeys,
  verifySignedTreeHead,
  verifyInclusionProof
} from "../src/transparency-log.js";
import {
  FileAnchorProvider,
  Rfc3161AnchorProvider,
  OpenTimestampsAnchorProvider,
  anchorTreeHead
} from "../src/anchor.js";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const offline = process.argv.includes("--offline");
const outputs = path.join(root, "outputs");
fs.mkdirSync(outputs, { recursive: true });

const samples = [
  "samples/sample-lineage.json",
  "samples/sample-retrieval-lineage.json",
  "examples/verified_execution.json"
];

console.log("== 1. verify lineage chains ==");
const log = new TransparencyLog();
for (const rel of samples) {
  const doc = JSON.parse(fs.readFileSync(path.join(root, rel), "utf8"));
  const result = verifyLineage(doc);
  const entry = log.append({
    operation_id: doc.operation_id,
    last_hash: result.last_hash,
    last_hash_b: result.last_hash_b,
    event_count: result.events,
    // The chain's own terminal event time; never wall-clock, so the log is
    // reproducible from the inputs alone.
    ts: doc.events[doc.events.length - 1].ts
  });
  console.log(`   ${rel}: ${result.events} events -> log index ${entry.index}`);
}

console.log(`\n== 2. transparency log ==`);
console.log(`   tree size : ${log.size}`);
console.log(`   root      : ${log.root()}`);

console.log(`\n== 3. inclusion proofs ==`);
for (let i = 0; i < log.size; i++) {
  const proof = log.inclusionProof(i);
  console.log(
    `   leaf ${i}: path length ${proof.path.length}, verifies ${verifyInclusionProof(proof)}`
  );
}

console.log(`\n== 4. hybrid-signed tree head ==`);
const keys = generateLogKeys();
// Timestamp derives from the newest entry, keeping the demo deterministic.
const timestamp = log.entries[log.entries.length - 1].ts;
const sth = log.signTreeHead(keys, timestamp);
const sthCheck = verifySignedTreeHead(sth, { require: "all" });
console.log(`   Ed25519    : ${sthCheck.results.ed25519}`);
console.log(`   ML-DSA-87  : ${sthCheck.results.ml_dsa_87}`);
console.log(`   overall    : ${sthCheck.ok}`);

console.log(`\n== 5. external anchoring ==`);
const providers = [new FileAnchorProvider(path.join(outputs, "anchors"))];
if (!offline) {
  providers.push(new Rfc3161AnchorProvider());
  providers.push(new OpenTimestampsAnchorProvider());
}

const anchored = await anchorTreeHead(sth, providers);
for (const receipt of anchored.receipts) {
  const detail =
    receipt.status === "ANCHORED"
      ? `attested_time=${receipt.attested_time} token=${receipt.token_bytes}B`
      : receipt.status === "PENDING"
        ? `calendars=${receipt.calendars_accepted}/${receipt.calendars_total}`
        : receipt.error || "";
  console.log(`   ${receipt.provider.padEnd(15)} ${receipt.status.padEnd(11)} ${detail}`);
}
console.log(`   external anchors : ${anchored.external_anchor_count}`);
console.log(`   on-chain tx      : ${anchored.on_chain_transaction ?? "none (no chain provider configured)"}`);

const bundle = {
  signed_tree_head: sth,
  signed_tree_head_verification: sthCheck,
  entries: log.entries,
  inclusion_proofs: log.entries.map((_, i) => log.inclusionProof(i)),
  anchors: anchored
};
const bundlePath = path.join(outputs, "transparency-bundle.json");
fs.writeFileSync(bundlePath, JSON.stringify(bundle, null, 2) + "\n");
console.log(`\n   wrote ${path.relative(root, bundlePath)}`);
