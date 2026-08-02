#!/usr/bin/env node
// CLI wrapper around src/lineage.js.
//
// The verification logic lives in lineage.js so it can be imported. This file
// only parses argv, prints, and sets an exit code:
//   0 = chain verified
//   1 = usage error
//   2 = verification failed
import fs from "node:fs";
import { verifyLineage, verifyOutputProvenance } from "./lineage.js";

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

  // Only meaningful for chains carrying retrieval/output events.
  if (result.event_types.includes("output.emitted")) {
    const prov = verifyOutputProvenance(doc);
    console.log(
      `Output provenance: ${prov.ok ? "PASS" : "FAIL"} ` +
        `(${prov.outputs_checked} output(s), ${prov.sources_retrieved} source(s))`
    );
    if (!prov.ok) {
      for (const p of prov.problems) {
        console.error(`  seq ${p.seq}: ${p.reason} (${p.source_id})`);
      }
      process.exit(2);
    }
  }
} catch (err) {
  console.error("Verification status: FAIL");
  console.error(err.message);
  process.exit(2);
}
