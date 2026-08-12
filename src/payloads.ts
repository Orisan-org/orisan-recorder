/**
 * R1.2 — encrypted payload blobs, using libsodium's crypto_box_seal.
 *
 * Why payloads live outside the event: the log is append-only, so anything
 * sealed into a record is unremovable. Prompts and tool arguments are exactly
 * the material a subject may later demand be deleted. Separate blobs mean an
 * erasure request is satisfied by destroying a blob or its key, while the chain
 * over the events stays intact and still verifies.
 *
 * Construction: sodium `crypto_box_seal` / `crypto_box_seal_open`, unmodified.
 *
 *   blob = "ORP2" || crypto_box_seal(plaintext, recipient_pk)
 *
 * sodium generates the ephemeral X25519 keypair, derives the key, and
 * authenticates, all inside the audited primitive. We add only a 4-byte format
 * tag so a future format change is distinguishable.
 *
 * This replaces a hand-rolled X25519+HKDF+AES-GCM envelope. That version was
 * sound as far as review found, but its *construction* was ours and therefore
 * the thing a reviewer had to check line by line. A named, audited primitive
 * moves that burden to libsodium, which is the correct place for it.
 *
 * One property was lost in the swap and is worth stating rather than papering
 * over: crypto_box_seal takes no associated data, so the format tag and key id
 * are no longer bound into the ciphertext's authentication. The binding that
 * matters survives elsewhere — payload_ref is sha256 over the blob bytes, and
 * that ref is a field inside a hash-chained (and, from R1.3, signed and
 * anchored) event. A blob swapped for another therefore breaks the chain, not
 * merely an AEAD tag. The chain is the stronger binding; the AAD was the
 * weaker, more bespoke one.
 *
 * Anonymity note inherited from the primitive: a sealed box does not
 * authenticate its sender. Anyone holding the recipient public key can write a
 * blob. That is acceptable only because a blob is reached through a chained
 * event and is never trusted alone.
 */

import sodium from 'sodium-native';
import { createHash, timingSafeEqual } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const MAGIC = Buffer.from('ORP2', 'utf8');

export const PAYLOAD_DIRNAME = 'payloads';
export const KEY_ALG = 'crypto_box_seal' as const;

export interface KeyFile {
  v: 1;
  /** Names the primitive so a future format is never silently misread. */
  alg: typeof KEY_ALG;
  /** sha256 of the raw public key, hex, first 32 chars. */
  kid: string;
  /** base64 raw 32-byte X25519 public key. */
  public_key: string;
  /** base64 raw 32-byte secret key. Absent in a write-only (recorder) key file. */
  private_key?: string;
}

function kidOf(rawPub: Buffer): string {
  return createHash('sha256').update(rawPub).digest('hex').slice(0, 32);
}

/** Create a keypair and write it to `path` with owner-only permissions. */
export function generateKeyFile(path: string): KeyFile {
  const pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
  const sk = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES);
  sodium.crypto_box_keypair(pk, sk);

  const kf: KeyFile = {
    v: 1,
    alg: KEY_ALG,
    kid: kidOf(pk),
    public_key: pk.toString('base64'),
    private_key: Buffer.from(sk).toString('base64'),
  };
  writeFileSync(path, `${JSON.stringify(kf, null, 2)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
  sodium.sodium_memzero(sk);
  return kf;
}

/**
 * Load a key file, refusing one readable by anyone but its owner.
 * A recorder that silently accepts mode 644 teaches operators to leave it there.
 */
export function loadKeyFile(path: string): KeyFile {
  if (!existsSync(path)) throw new Error(`key file not found: ${path}`);
  if (process.platform !== 'win32') {
    const mode = statSync(path).mode & 0o777;
    if ((mode & 0o077) !== 0) {
      throw new Error(
        `key file ${path} is mode ${mode.toString(8)}; it must not be group- or world-accessible (chmod 600)`,
      );
    }
  }
  const kf = JSON.parse(readFileSync(path, 'utf8')) as KeyFile;
  if (kf.v !== 1) throw new Error(`unsupported key file version: ${String(kf.v)}`);
  if (kf.alg !== KEY_ALG) throw new Error(`unsupported key algorithm: ${String(kf.alg)}`);
  if (typeof kf.public_key !== 'string' || typeof kf.kid !== 'string') throw new Error('malformed key file');

  const pk = Buffer.from(kf.public_key, 'base64');
  if (pk.length !== sodium.crypto_box_PUBLICKEYBYTES) throw new Error('public key has wrong length');
  if (kf.kid !== kidOf(pk)) throw new Error('key file kid does not match its public key');
  return kf;
}

/** Encrypt one payload into the store. Returns its payload_ref. */
export function sealPayload(dir: string, keyFile: KeyFile, plaintext: Buffer | string): string {
  const pt = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
  const pk = Buffer.from(keyFile.public_key, 'base64');
  if (pk.length !== sodium.crypto_box_PUBLICKEYBYTES) throw new Error('public key has wrong length');

  const sealed = Buffer.alloc(pt.length + sodium.crypto_box_SEALBYTES);
  sodium.crypto_box_seal(sealed, pt, pk);

  const blob = Buffer.concat([MAGIC, sealed]);
  const ref = createHash('sha256').update(blob).digest('hex');

  const blobDir = join(dir, PAYLOAD_DIRNAME);
  mkdirSync(blobDir, { recursive: true });
  writeFileSync(join(blobDir, `${ref}.blob`), blob, { mode: 0o600 });
  return ref;
}

/** Decrypt a payload by ref. Throws if absent, altered, or not for this key. */
export function openPayload(dir: string, keyFile: KeyFile, ref: string): Buffer {
  if (!keyFile.private_key) throw new Error('key file has no private key; cannot decrypt');
  const path = join(dir, PAYLOAD_DIRNAME, `${ref}.blob`);
  if (!existsSync(path)) throw new Error(`payload blob not found: ${ref}`);
  const blob = readFileSync(path);

  // Content addressing: the ref must actually name these bytes.
  const actual = Buffer.from(createHash('sha256').update(blob).digest('hex'), 'hex');
  const claimed = Buffer.from(ref, 'hex');
  if (actual.length !== claimed.length || !timingSafeEqual(actual, claimed)) {
    throw new Error(`payload ${ref} does not match its content hash`);
  }

  if (!blob.subarray(0, MAGIC.length).equals(MAGIC)) throw new Error('payload blob has wrong magic');
  const sealed = blob.subarray(MAGIC.length);
  if (sealed.length < sodium.crypto_box_SEALBYTES) throw new Error('payload blob truncated');

  const pk = Buffer.from(keyFile.public_key, 'base64');
  const sk = Buffer.from(keyFile.private_key, 'base64');
  if (sk.length !== sodium.crypto_box_SECRETKEYBYTES) throw new Error('secret key has wrong length');

  const out = Buffer.alloc(sealed.length - sodium.crypto_box_SEALBYTES);
  const ok = sodium.crypto_box_seal_open(out, sealed, pk, sk);
  if (!ok) throw new Error(`payload ${ref} failed authentication (wrong key, or altered)`);
  return out;
}
