/**
 * R1.3 — signed checkpoints.
 *
 * A checkpoint commits to a contiguous range of events by Merkle root and
 * signs that commitment with Ed25519. This is the layer that closes the hole
 * the chain cannot: an attacker who rewrites the log and recomputes every hash
 * still cannot produce a signature over the new root without the signing key,
 * and cannot produce the old root from the new events.
 *
 * That is necessary but not sufficient. An attacker who holds the signing key
 * can re-sign a rewritten history, so a signature alone still only proves
 * "whoever holds the key asserts this". What makes a rewrite *detectable* is
 * the checkpoint leaving our control — the RFC 3161 anchor in tsa.ts. Neither
 * layer is the answer on its own and neither should be described as if it were.
 *
 * Ed25519 via node:crypto rather than sodium, deliberately: the public key
 * exports as standard SPKI PEM, so a third party verifies our signatures with
 * openssl and no code of ours. Sodium is used where the primitive is the whole
 * job (sealed boxes); node:crypto is used where interoperability with an
 * auditor's toolchain is the whole job.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from 'node:crypto';
import {
  chmodSync, closeSync, existsSync, fsyncSync, mkdirSync,
  openSync, readFileSync, statSync, writeFileSync, writeSync,
} from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';

import { canonicalJson } from './schema.js';
import { merkleRoot } from './merkle.js';

export const CHECKPOINTS_FILENAME = 'checkpoints.jsonl';
export const SIGNING_KEY_FILENAME = 'signing.key';
export const PUBLIC_KEY_FILENAME = 'signing.pub.pem';

/** Default cadence from the spec. */
export const DEFAULT_CHECKPOINT_INTERVAL = 500;

/** Genesis value for the checkpoint chain's own prev pointer. */
export const CHECKPOINT_GENESIS_PREV = '0'.repeat(64);

/**
 * The signed part of a checkpoint. Exactly these fields, canonically encoded.
 *
 * v2 added `index` and `prev_checkpoint_hash`, which make the checkpoint log a
 * chain in its own right. Without them verify could only validate the
 * checkpoints that happened to be present, and nothing established what should
 * be present — so deleting the newest checkpoint moved the log's own idea of
 * its end backwards, and a whole tail could be erased with three rm's.
 */
export interface CheckpointBody {
  v: 2;
  /** Monotonic from 0. A gap means a checkpoint was removed. */
  index: number;
  /** sha256 over the previous checkpoint's canonical body+signature. */
  prev_checkpoint_hash: string;
  seq_from: number;
  seq_to: number;
  count: number;
  merkle_root: string;
  created_at: string;
  key_id: string;
  /** Why the checkpoint was cut, for operator legibility. Signed like everything else. */
  reason: 'interval' | 'session_end' | 'manual';
}

export interface SignedCheckpoint extends CheckpointBody {
  /** base64 Ed25519 signature over canonicalJson(body). */
  signature: string;
}

export interface SigningKeyFile {
  v: 1;
  alg: 'ed25519';
  key_id: string;
  /** PKCS#8 DER, base64. */
  private_key: string;
  /** SPKI PEM — the thing an auditor needs, and safe to publish. */
  public_key_pem: string;
}

export function keyIdOf(publicKey: KeyObject): string {
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(spki).digest('hex').slice(0, 32);
}

/** Create a signing key and write it owner-only, plus the public key beside it. */
/**
 * Where the signing key should live.
 *
 * Default was inside the log directory, which made "the attacker holds the
 * key" the default configuration rather than an edge case: anyone who can
 * rewrite the events can re-sign the checkpoints over them. Callers should
 * pass an explicit path outside the log.
 */
export function signingKeyPath(dir: string, explicitPath?: string): string {
  return explicitPath ?? join(dir, SIGNING_KEY_FILENAME);
}

/** True when the key sits beside the data it authenticates. */
export function keyIsBesideData(dir: string, keyPath: string): boolean {
  return resolve(keyPath).startsWith(resolve(dir) + sep);
}

/**
 * Create a signing key.
 *
 * The PRIVATE key goes to `keyPath`, which should be OUTSIDE `logDir`. The
 * PUBLIC key always stays in the log directory: verification must never
 * require anything the operator could withhold.
 */
export function generateSigningKey(logDir: string, keyPath?: string): SigningKeyFile {
  const dir = logDir;
  const path = signingKeyPath(dir, keyPath);
  mkdirSync(dir, { recursive: true });
  mkdirSync(dirname(resolve(path)), { recursive: true });
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const kf: SigningKeyFile = {
    v: 1,
    alg: 'ed25519',
    key_id: keyIdOf(publicKey),
    private_key: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
  writeFileSync(path, `${JSON.stringify(kf, null, 2)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
  // The public key is written unencumbered on purpose: verification must never
  // require anything the operator could withhold.
  writeFileSync(join(dir, PUBLIC_KEY_FILENAME), kf.public_key_pem, { mode: 0o644 });
  return kf;
}

export function loadSigningKey(logDir: string, keyPath?: string): SigningKeyFile {
  const path = signingKeyPath(logDir, keyPath);
  if (!existsSync(path)) throw new Error(`signing key not found: ${path}`);
  if (process.platform !== 'win32') {
    const mode = statSync(path).mode & 0o777;
    if ((mode & 0o077) !== 0) {
      throw new Error(`signing key ${path} is mode ${mode.toString(8)}; must be owner-only (chmod 600)`);
    }
  }
  const kf = JSON.parse(readFileSync(path, 'utf8')) as SigningKeyFile;
  if (kf.v !== 1) throw new Error(`unsupported signing key version: ${String(kf.v)}`);
  if (kf.alg !== 'ed25519') throw new Error(`unsupported signing algorithm: ${String(kf.alg)}`);
  return kf;
}

function privateKeyOf(kf: SigningKeyFile): KeyObject {
  return createPrivateKey({ key: Buffer.from(kf.private_key, 'base64'), format: 'der', type: 'pkcs8' });
}

/** Strip the signature so the body is hashed and signed identically both ways. */
export function checkpointBody(cp: SignedCheckpoint | CheckpointBody): CheckpointBody {
  const { signature: _drop, ...body } = cp as SignedCheckpoint;
  return body;
}

/**
 * The link value a successor stores in prev_checkpoint_hash.
 *
 * Covers body AND signature — identical to anchorDigest's input — so a
 * checkpoint cannot be re-signed without breaking every link after it.
 */
export function checkpointLinkHash(cp: SignedCheckpoint): string {
  return anchorDigest(cp).toString('hex');
}

export function signCheckpoint(body: CheckpointBody, kf: SigningKeyFile): SignedCheckpoint {
  const sig = edSign(null, Buffer.from(canonicalJson(body), 'utf8'), privateKeyOf(kf));
  return { ...body, signature: sig.toString('base64') };
}

/** Verify a checkpoint signature against an SPKI PEM public key. */
export function verifyCheckpointSignature(cp: SignedCheckpoint, publicKeyPem: string): boolean {
  try {
    return edVerify(
      null,
      Buffer.from(canonicalJson(checkpointBody(cp)), 'utf8'),
      createPublicKey(publicKeyPem),
      Buffer.from(cp.signature, 'base64'),
    );
  } catch {
    return false;
  }
}

/**
 * The digest an external timestamp authority signs.
 *
 * It covers the body AND the signature, so the anchor proves that this signed
 * checkpoint — not merely this range of events — existed before time T. If it
 * covered only the root, a holder of the signing key could re-sign the same
 * root later and reuse the old anchor.
 */
export function anchorDigest(cp: SignedCheckpoint): Buffer {
  return createHash('sha256')
    .update(canonicalJson(checkpointBody(cp)), 'utf8')
    .update(Buffer.from([0]))
    .update(cp.signature, 'utf8')
    .digest();
}

export function buildCheckpoint(
  eventHashes: readonly string[],
  seqFrom: number,
  reason: CheckpointBody['reason'],
  kf: SigningKeyFile,
  prev: SignedCheckpoint | null = null,
  now: Date = new Date(),
): SignedCheckpoint {
  if (eventHashes.length === 0) throw new Error('refusing to checkpoint an empty range');
  const body: CheckpointBody = {
    v: 2,
    index: prev ? prev.index + 1 : 0,
    prev_checkpoint_hash: prev ? checkpointLinkHash(prev) : CHECKPOINT_GENESIS_PREV,
    seq_from: seqFrom,
    seq_to: seqFrom + eventHashes.length - 1,
    count: eventHashes.length,
    merkle_root: merkleRoot(eventHashes),
    created_at: now.toISOString(),
    key_id: kf.key_id,
    reason,
  };
  return signCheckpoint(body, kf);
}

export interface CheckpointChainBreak {
  index: number;
  seq_to: number;
  reason:
    | 'index_gap'
    | 'prev_hash_mismatch'
    | 'first_index_not_zero'
    | 'first_seq_not_zero'
    | 'seq_not_contiguous'
    | 'empty_count'
    | 'inverted_range'
    | 'count_mismatch'
    | 'duplicate_index'
    | 'unsupported_version';
  message: string;
}

/**
 * Structural validation of the checkpoint log as a chain.
 *
 * This is what closes tail truncation, holes, and the count:0 poison pill: it
 * checks the checkpoints tile the event log from seq 0 with no gaps, rather
 * than validating whatever the operator chose to leave on disk.
 */
export function verifyCheckpointChain(checkpoints: readonly SignedCheckpoint[]): CheckpointChainBreak[] {
  const breaks: CheckpointChainBreak[] = [];
  if (checkpoints.length === 0) return breaks;

  const seenIndex = new Set<number>();
  let prev: SignedCheckpoint | null = null;

  for (const cp of checkpoints) {
    const at = { index: cp.index, seq_to: cp.seq_to };

    if (cp.v !== 2) {
      breaks.push({ ...at, reason: 'unsupported_version', message: `checkpoint version ${String(cp.v)} is not supported` });
      continue;
    }
    if (seenIndex.has(cp.index)) {
      breaks.push({ ...at, reason: 'duplicate_index', message: `checkpoint index ${cp.index} appears more than once` });
      continue;
    }
    seenIndex.add(cp.index);

    // count:0 with a huge range was a permanent integrity kill switch: it
    // satisfied the Merkle check vacuously and pushed the "last anchored seq"
    // past every future event. An empty checkpoint is never legitimate.
    if (cp.count < 1) {
      breaks.push({ ...at, reason: 'empty_count', message: `checkpoint ${cp.index} claims count ${cp.count}; a checkpoint must cover at least one event` });
    }
    if (cp.seq_to < cp.seq_from) {
      breaks.push({ ...at, reason: 'inverted_range', message: `checkpoint ${cp.index} has seq_to ${cp.seq_to} < seq_from ${cp.seq_from}` });
    }
    if (cp.count >= 1 && cp.seq_to - cp.seq_from + 1 !== cp.count) {
      breaks.push({ ...at, reason: 'count_mismatch', message: `checkpoint ${cp.index} spans ${cp.seq_to - cp.seq_from + 1} seqs but claims count ${cp.count}` });
    }

    if (prev === null) {
      if (cp.index !== 0) {
        breaks.push({ ...at, reason: 'first_index_not_zero', message: `checkpoint log starts at index ${cp.index}; checkpoint 0 is missing` });
      }
      if (cp.seq_from !== 0) {
        breaks.push({ ...at, reason: 'first_seq_not_zero', message: `first checkpoint starts at seq ${cp.seq_from}, not 0; earlier events are uncommitted` });
      }
      if (cp.prev_checkpoint_hash !== CHECKPOINT_GENESIS_PREV) {
        breaks.push({ ...at, reason: 'prev_hash_mismatch', message: `first checkpoint does not carry the genesis prev hash` });
      }
    } else {
      if (cp.index !== prev.index + 1) {
        breaks.push({ ...at, reason: 'index_gap', message: `checkpoint index jumps from ${prev.index} to ${cp.index}; ${cp.index - prev.index - 1} checkpoint(s) removed` });
      }
      const expected = checkpointLinkHash(prev);
      if (cp.prev_checkpoint_hash !== expected) {
        breaks.push({ ...at, reason: 'prev_hash_mismatch', message: `checkpoint ${cp.index} links to ${cp.prev_checkpoint_hash.slice(0, 16)}… but its predecessor hashes to ${expected.slice(0, 16)}…` });
      }
      if (cp.seq_from !== prev.seq_to + 1) {
        breaks.push({ ...at, reason: 'seq_not_contiguous', message: `checkpoint ${cp.index} starts at seq ${cp.seq_from} but the previous ended at ${prev.seq_to}; seqs ${prev.seq_to + 1}..${cp.seq_from - 1} are uncommitted` });
      }
    }
    prev = cp;
  }
  return breaks;
}

/** Append a checkpoint durably. The checkpoint log is append-only like the events. */
export function appendCheckpoint(dir: string, cp: SignedCheckpoint): void {
  mkdirSync(dir, { recursive: true });
  const fd = openSync(join(dir, CHECKPOINTS_FILENAME), 'a');
  try {
    const line = Buffer.from(`${JSON.stringify(cp)}\n`, 'utf8');
    let w = 0;
    while (w < line.length) w += writeSync(fd, line, w, line.length - w);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

export function readCheckpoints(dir: string): SignedCheckpoint[] {
  const path = join(dir, CHECKPOINTS_FILENAME);
  if (!existsSync(path)) return [];
  const lines = readFileSync(path, 'utf8').split('\n').filter((l) => l.trim().length > 0);
  const out: SignedCheckpoint[] = [];
  const seen = new Set<string>();
  for (const [i, line] of lines.entries()) {
    let cp: SignedCheckpoint;
    try {
      cp = JSON.parse(line) as SignedCheckpoint;
    } catch {
      throw new Error(`${CHECKPOINTS_FILENAME} line ${i + 1} is not valid JSON`);
    }
    // Byte-identical repeats are not merely redundant: they let one anchor be
    // counted several times, inflating "anchors verified".
    if (seen.has(line)) throw new Error(`${CHECKPOINTS_FILENAME} line ${i + 1} is a duplicate of an earlier checkpoint`);
    seen.add(line);
    out.push(cp);
  }
  return out;
}
