// External anchoring for signed tree heads.
//
// A signed tree head proves the log operator committed to a root. It does not
// prove *when*, and it does not stop a single operator from maintaining two
// divergent logs and showing a different one to each verifier (split-view /
// equivocation). Anchoring the root into a medium the operator does not control
// is what closes that gap.
//
// Providers implement: anchor(rootHash) -> Promise<AnchorReceipt>
//
//   FileAnchorProvider          local, offline. NO external proof-of-existence.
//   Rfc3161AnchorProvider       RFC 3161 TSA. Signed time attestation, seconds.
//   OpenTimestampsAnchorProvider Bitcoin-backed via OTS calendars. Free, no key.
//
// Deliberately NOT provided: any on-chain broadcast provider. Emitting a
// transaction requires a funded key and a network decision; a stub that returned
// a plausible-looking tx hash would be worse than no provider at all.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const ANCHOR_STATUS = {
  ANCHORED: "ANCHORED",
  PENDING: "PENDING",
  LOCAL_ONLY: "LOCAL_ONLY",
  FAILED: "FAILED"
};

/**
 * Local file anchor.
 *
 * Included because it is what 11-11-os-runtime's /v1/control/audit/anchor
 * actually does. Its status is LOCAL_ONLY, never ANCHORED: a file on the
 * operator's own disk is an integrity checkpoint, not external proof. Naming
 * that honestly in the type system keeps it from being cited as more.
 */
export class FileAnchorProvider {
  constructor(dir) {
    this.name = "file";
    this.dir = dir;
  }

  async anchor(rootHash, meta = {}) {
    fs.mkdirSync(this.dir, { recursive: true });
    const file = path.join(this.dir, `anchor-${rootHash.slice(0, 16)}.json`);
    const receipt = {
      provider: this.name,
      status: ANCHOR_STATUS.LOCAL_ONLY,
      root_hash: rootHash,
      tree_size: meta.tree_size,
      recorded_at: meta.timestamp,
      path: file,
      external_proof: false,
      note: "Operator-local file. Provides no external proof of existence and no split-view resistance."
    };
    fs.writeFileSync(file, JSON.stringify(receipt, null, 2));
    return receipt;
  }
}

// ---------------------------------------------------------------------------
// RFC 3161
// ---------------------------------------------------------------------------

// Minimal DER writer. Only the shapes a TimeStampReq needs.
function derLen(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function der(tag, content) {
  return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
}

const SEQUENCE = 0x30;
const INTEGER = 0x02;
const OCTET_STRING = 0x04;
const OID = 0x06;
const NULL = 0x05;
const BOOLEAN = 0x01;

function derInteger(buf) {
  // High bit set would read as negative; pad per DER rules.
  let b = buf;
  while (b.length > 1 && b[0] === 0x00 && (b[1] & 0x80) === 0) b = b.subarray(1);
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0x00]), b]);
  return der(INTEGER, b);
}

// sha512: 2.16.840.1.101.3.4.2.3
const OID_SHA512 = Buffer.from([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]);

/** Build an RFC 3161 TimeStampReq for a SHA-512 digest. */
export function buildTimeStampRequest(digest, nonce) {
  const algId = der(SEQUENCE, Buffer.concat([der(OID, OID_SHA512), der(NULL, Buffer.alloc(0))]));
  const messageImprint = der(SEQUENCE, Buffer.concat([algId, der(OCTET_STRING, digest)]));
  return der(
    SEQUENCE,
    Buffer.concat([
      derInteger(Buffer.from([0x01])), // version v1
      messageImprint,
      derInteger(nonce),
      der(BOOLEAN, Buffer.from([0xff])) // certReq = true, so the token carries the TSA cert
    ])
  );
}

/**
 * Scan DER for the TSTInfo genTime (GeneralizedTime, tag 0x18).
 *
 * This is a targeted scan, not a full CMS parse -- it reads the attested time
 * without pulling in an ASN.1 library. Cryptographic verification of the token
 * is a separate step (verifyRfc3161Token) and is NOT implied by this returning
 * a value.
 */
export function extractGenTime(der512) {
  for (let i = 0; i < der512.length - 2; i++) {
    if (der512[i] !== 0x18) continue;
    const len = der512[i + 1];
    if (len < 13 || len > 20) continue;
    const raw = der512.subarray(i + 2, i + 2 + len).toString("ascii");
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/.exec(raw);
    if (m) {
      const [, y, mo, d, h, mi, s, frac] = m;
      return `${y}-${mo}-${d}T${h}:${mi}:${s}${frac ? "." + frac : ""}Z`;
    }
  }
  return null;
}

export class Rfc3161AnchorProvider {
  /**
   * @param {string} url TSA endpoint
   * @param {object} opts { timeoutMs }
   */
  constructor(url = "https://freetsa.org/tsr", opts = {}) {
    this.name = "rfc3161";
    this.url = url;
    this.timeoutMs = opts.timeoutMs ?? 20000;
  }

  async anchor(rootHash, meta = {}) {
    // The TSA commits to a hash of our root, not the root text itself.
    const digest = crypto.createHash("sha512").update(rootHash, "utf8").digest();
    const nonce = crypto.randomBytes(8);
    const tsq = buildTimeStampRequest(digest, nonce);

    try {
      const res = await fetch(this.url, {
        method: "POST",
        headers: {
          "Content-Type": "application/timestamp-query",
          "Content-Length": String(tsq.length)
        },
        body: tsq,
        signal: AbortSignal.timeout(this.timeoutMs)
      });

      if (!res.ok) {
        return {
          provider: this.name,
          status: ANCHOR_STATUS.FAILED,
          root_hash: rootHash,
          external_proof: false,
          error: `HTTP ${res.status}`
        };
      }

      const token = Buffer.from(await res.arrayBuffer());
      const genTime = extractGenTime(token);

      return {
        provider: this.name,
        status: ANCHOR_STATUS.ANCHORED,
        root_hash: rootHash,
        tree_size: meta.tree_size,
        external_proof: true,
        tsa_url: this.url,
        digest_algorithm: "SHA-512",
        digest: digest.toString("hex"),
        attested_time: genTime,
        token_b64: token.toString("base64"),
        token_bytes: token.length,
        verification:
          "Token signature not verified in-process. Verify with: openssl ts -verify -data <root> -in <token> -CAfile <tsa-ca>"
      };
    } catch (err) {
      return {
        provider: this.name,
        status: ANCHOR_STATUS.FAILED,
        root_hash: rootHash,
        external_proof: false,
        error: String(err.message || err)
      };
    }
  }
}

// ---------------------------------------------------------------------------
// OpenTimestamps
// ---------------------------------------------------------------------------

export const DEFAULT_OTS_CALENDARS = [
  "https://a.pool.opentimestamps.org",
  "https://b.pool.opentimestamps.org",
  "https://alice.btc.calendar.opentimestamps.org"
];

/**
 * Bitcoin-backed anchoring via OpenTimestamps calendars.
 *
 * Submission is immediate; Bitcoin attestation is not. A calendar returns a
 * commitment operation right away and folds it into a block over the following
 * hours. Status is therefore PENDING on submission -- calling this ANCHORED
 * before the block exists would overstate what has been proven.
 */
export class OpenTimestampsAnchorProvider {
  constructor(calendars = DEFAULT_OTS_CALENDARS, opts = {}) {
    this.name = "opentimestamps";
    this.calendars = calendars;
    this.timeoutMs = opts.timeoutMs ?? 20000;
  }

  async anchor(rootHash, meta = {}) {
    // OTS calendars commit to a 32-byte digest.
    const digest = crypto.createHash("sha256").update(rootHash, "utf8").digest();

    const submissions = await Promise.all(
      this.calendars.map(async (cal) => {
        try {
          const res = await fetch(`${cal}/digest`, {
            method: "POST",
            headers: {
              Accept: "application/vnd.opentimestamps.v1",
              "Content-Type": "application/x-www-form-urlencoded"
            },
            body: digest,
            signal: AbortSignal.timeout(this.timeoutMs)
          });
          if (!res.ok) return { calendar: cal, ok: false, error: `HTTP ${res.status}` };
          const proof = Buffer.from(await res.arrayBuffer());
          return {
            calendar: cal,
            ok: true,
            proof_b64: proof.toString("base64"),
            proof_bytes: proof.length
          };
        } catch (err) {
          return { calendar: cal, ok: false, error: String(err.message || err) };
        }
      })
    );

    const accepted = submissions.filter((s) => s.ok);
    const failed = submissions.filter((s) => !s.ok);

    return {
      provider: this.name,
      status: accepted.length > 0 ? ANCHOR_STATUS.PENDING : ANCHOR_STATUS.FAILED,
      root_hash: rootHash,
      tree_size: meta.tree_size,
      external_proof: accepted.length > 0,
      digest_algorithm: "SHA-256",
      digest: digest.toString("hex"),
      calendars_accepted: accepted.length,
      calendars_total: this.calendars.length,
      submissions,
      // Every receipt must carry a top-level error when it obtained nothing,
      // so a caller can branch on `error` without walking per-calendar detail.
      ...(accepted.length === 0
        ? { error: `all ${this.calendars.length} calendar(s) failed: ${failed.map((f) => f.error).join("; ")}` }
        : {}),
      note:
        "Calendars have accepted the commitment. Bitcoin block attestation typically completes within hours; " +
        "until then this is a calendar commitment, not a confirmed on-chain proof.",
      upgrade: "GET <calendar>/timestamp/<commitment> to retrieve the Bitcoin attestation once mined."
    };
  }
}

/**
 * Anchor a signed tree head across every configured provider.
 * One provider failing does not abort the others -- each receipt stands alone.
 */
export async function anchorTreeHead(sth, providers) {
  const receipts = [];
  for (const provider of providers) {
    receipts.push(
      await provider.anchor(sth.root_hash, {
        tree_size: sth.tree_size,
        timestamp: sth.timestamp
      })
    );
  }

  const external = receipts.filter((r) => r.external_proof);

  return {
    log_id: sth.log_id,
    tree_size: sth.tree_size,
    root_hash: sth.root_hash,
    timestamp: sth.timestamp,
    receipts,
    external_anchor_count: external.length,
    // Explicit: no provider here broadcasts a blockchain transaction.
    on_chain_transaction: null,
    summary:
      external.length > 0
        ? `${external.length} external anchor(s) obtained`
        : "No external anchor obtained; local evidence only"
  };
}
