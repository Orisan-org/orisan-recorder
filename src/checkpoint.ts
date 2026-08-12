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
import { join } from 'node:path';

import { canonicalJson } from './schema.js';
import { merkleRoot } from './merkle.js';

export const CHECKPOINTS_FILENAME = 'checkpoints.jsonl';
export const SIGNING_KEY_FILENAME = 'signing.key';
export const PUBLIC_KEY_FILENAME = 'signing.pub.pem';

/** Default cadence from the spec. */
export const DEFAULT_CHECKPOINT_INTERVAL = 500;

/** The signed part of a checkpoint. Exactly these fields, canonically encoded. */
export interface CheckpointBody {
  v: 1;
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
export function generateSigningKey(dir: string): SigningKeyFile {
  mkdirSync(dir, { recursive: true });
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const kf: SigningKeyFile = {
    v: 1,
    alg: 'ed25519',
    key_id: keyIdOf(publicKey),
    private_key: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
  const path = join(dir, SIGNING_KEY_FILENAME);
  writeFileSync(path, `${JSON.stringify(kf, null, 2)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
  // The public key is written unencumbered on purpose: verification must never
  // require anything the operator could withhold.
  writeFileSync(join(dir, PUBLIC_KEY_FILENAME), kf.public_key_pem, { mode: 0o644 });
  return kf;
}

export function loadSigningKey(dir: string): SigningKeyFile {
  const path = join(dir, SIGNING_KEY_FILENAME);
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
  now: Date = new Date(),
): SignedCheckpoint {
  if (eventHashes.length === 0) throw new Error('refusing to checkpoint an empty range');
  const body: CheckpointBody = {
    v: 1,
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
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as SignedCheckpoint);
}
