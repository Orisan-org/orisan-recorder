/**
 * R1.2 — encrypted payload blobs.
 *
 * ============================ TIER C — READ EVERY LINE ======================
 * This is hand-rolled envelope encryption. It uses only primitives from
 * node:crypto and invents no cipher, but the *construction* is ours and is
 * therefore the part to review. The construction is stated in full below so it
 * can be checked against a known-good sealed-box design rather than trusted.
 * ============================================================================
 *
 * Why payloads live outside the event at all: an audit log is append-only, so
 * anything sealed into a record is unremovable. Prompts and tool arguments are
 * exactly the material a subject may later demand be deleted. Keeping them in
 * separate blobs means an erasure request is satisfied by destroying a blob (or
 * its key) while the chain over the events stays intact and still verifies.
 *
 * Construction (libsodium crypto_box_seal in shape, built from node:crypto):
 *
 *   ephemeral X25519 keypair  (fresh per blob)
 *   shared  = X25519(eph_priv, recipient_pub)
 *   key     = HKDF-SHA256(ikm = shared, salt = eph_pub || recipient_pub,
 *                         info = "orisan-recorder/payload/v1", len = 32)
 *   iv      = 12 random bytes
 *   ct||tag = AES-256-GCM(key, iv, plaintext, aad = magic || kid)
 *
 *   blob    = "ORP1" || eph_pub(32) || iv(12) || ct || tag(16)
 *
 * Properties this does and does not have:
 *  - The salt binds the derived key to both public keys, so a blob cannot be
 *    replayed against a different recipient.
 *  - The AAD binds the blob to the format version and the key id, so swapping
 *    a blob between key generations fails authentication rather than
 *    decrypting to garbage.
 *  - A fresh ephemeral key per blob means compromising one blob's session does
 *    not compromise another.
 *  - It is NOT authenticated as to origin. Anyone holding the recipient public
 *    key can write a blob. That is the same property crypto_box_seal has, and
 *    it is acceptable here because the *event* is chained and (from R1.3)
 *    signed; the blob is referenced by a chained event, not trusted alone.
 *  - Holding the key file means reading every payload. Key custody is the
 *    whole security boundary; see loadKeyFile's permission check.
 */

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPublicKey,
  createPrivateKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
  type KeyObject,
} from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const MAGIC = Buffer.from('ORP1', 'utf8');
const INFO = Buffer.from('orisan-recorder/payload/v1', 'utf8');
const EPH_LEN = 32;
const IV_LEN = 12;
const TAG_LEN = 16;

/** Fixed SPKI DER prefix for an X25519 public key; the remaining 32 bytes are the key. */
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

export const PAYLOAD_DIRNAME = 'payloads';

export interface KeyFile {
  v: 1;
  /** Key id: sha256 of the raw public key, hex, first 32 chars. Appears in the AAD. */
  kid: string;
  /** base64 raw 32-byte X25519 public key. */
  public_key: string;
  /** base64 PKCS#8 private key. Absent in a write-only (recorder) key file. */
  private_key?: string;
}

function rawPublicKey(key: KeyObject): Buffer {
  const der = key.export({ type: 'spki', format: 'der' });
  return Buffer.from(der.subarray(der.length - EPH_LEN));
}

function publicKeyFromRaw(raw: Buffer): KeyObject {
  if (raw.length !== EPH_LEN) throw new Error(`bad X25519 public key length: ${raw.length}`);
  return createPublicKey({
    key: Buffer.concat([X25519_SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
}

function kidOf(rawPub: Buffer): string {
  return createHash('sha256').update(rawPub).digest('hex').slice(0, 32);
}

/** Create a new keypair and write it to `path` with owner-only permissions. */
export function generateKeyFile(path: string): KeyFile {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const rawPub = rawPublicKey(publicKey);
  const kf: KeyFile = {
    v: 1,
    kid: kidOf(rawPub),
    public_key: rawPub.toString('base64'),
    private_key: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
  };
  writeFileSync(path, `${JSON.stringify(kf, null, 2)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
  return kf;
}

/**
 * Load a key file, refusing one that is readable by anyone but its owner.
 *
 * A recorder that silently accepts a world-readable key file trains operators
 * to leave it that way. Failing loudly is the point.
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
  if (typeof kf.public_key !== 'string' || typeof kf.kid !== 'string') {
    throw new Error('malformed key file');
  }
  const expected = kidOf(Buffer.from(kf.public_key, 'base64'));
  if (kf.kid !== expected) throw new Error('key file kid does not match its public key');
  return kf;
}

/** Encrypt one payload into the store. Returns its payload_ref. */
export function sealPayload(dir: string, keyFile: KeyFile, plaintext: Buffer | string): string {
  const pt = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
  const recipientRaw = Buffer.from(keyFile.public_key, 'base64');
  const recipient = publicKeyFromRaw(recipientRaw);

  const { publicKey: ephPub, privateKey: ephPriv } = generateKeyPairSync('x25519');
  const ephRaw = rawPublicKey(ephPub);
  const shared = diffieHellman({ privateKey: ephPriv, publicKey: recipient });

  const salt = Buffer.concat([ephRaw, recipientRaw]);
  const key = Buffer.from(hkdfSync('sha256', shared, salt, INFO, 32));
  const iv = randomBytes(IV_LEN);
  const aad = Buffer.concat([MAGIC, Buffer.from(keyFile.kid, 'utf8')]);

  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();

  const blob = Buffer.concat([MAGIC, ephRaw, iv, ct, tag]);
  const ref = createHash('sha256').update(blob).digest('hex');

  const blobDir = join(dir, PAYLOAD_DIRNAME);
  mkdirSync(blobDir, { recursive: true });
  writeFileSync(join(blobDir, `${ref}.blob`), blob, { mode: 0o600 });
  return ref;
}

/** Decrypt a payload by ref. Throws if the blob is absent, altered, or foreign. */
export function openPayload(dir: string, keyFile: KeyFile, ref: string): Buffer {
  if (!keyFile.private_key) throw new Error('key file has no private key; cannot decrypt');
  const path = join(dir, PAYLOAD_DIRNAME, `${ref}.blob`);
  if (!existsSync(path)) throw new Error(`payload blob not found: ${ref}`);
  const blob = readFileSync(path);

  // Content addressing: the ref must actually name this blob's bytes.
  const actual = createHash('sha256').update(blob).digest('hex');
  const a = Buffer.from(actual, 'hex');
  const b = Buffer.from(ref, 'hex');
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    throw new Error(`payload ${ref} does not match its content hash`);
  }

  if (blob.length < MAGIC.length + EPH_LEN + IV_LEN + TAG_LEN) throw new Error('payload blob truncated');
  if (!blob.subarray(0, MAGIC.length).equals(MAGIC)) throw new Error('payload blob has wrong magic');

  let o = MAGIC.length;
  const ephRaw = blob.subarray(o, (o += EPH_LEN));
  const iv = blob.subarray(o, (o += IV_LEN));
  const ct = blob.subarray(o, blob.length - TAG_LEN);
  const tag = blob.subarray(blob.length - TAG_LEN);

  const priv = createPrivateKey({
    key: Buffer.from(keyFile.private_key, 'base64'),
    format: 'der',
    type: 'pkcs8',
  });
  const recipientRaw = Buffer.from(keyFile.public_key, 'base64');
  const shared = diffieHellman({ privateKey: priv, publicKey: publicKeyFromRaw(Buffer.from(ephRaw)) });
  const salt = Buffer.concat([Buffer.from(ephRaw), recipientRaw]);
  const key = Buffer.from(hkdfSync('sha256', shared, salt, INFO, 32));

  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(Buffer.concat([MAGIC, Buffer.from(keyFile.kid, 'utf8')]));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}
